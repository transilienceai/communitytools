# Multi-User Desktop / Documents Flag Sweep

## When this applies

- Windows foothold with SYSTEM/admin privileges.
- Goal: locate the privileged loot/flag, which may be on a non-`Administrator` user's Desktop (any local-Admins or Domain-Admins member).

## Technique

AD environments sometimes place the privileged flag on a non-`Administrator` user's Desktop. After getting SYSTEM/admin, sweep all profiles, not just Administrator's.

## Steps

```powershell
Get-ChildItem C:\Users\*\Desktop\*.txt,C:\Users\*\Documents\*.txt -ErrorAction SilentlyContinue |
  ForEach-Object { Write-Host "==== $($_.FullName) ===="; Get-Content $_ }
```

## Verifying success

- Flag/credential text appears in the output.

## Common pitfalls

- Don't assume Administrator's Desktop is the only target. Local Admin members + DA members may have the flag.
- Service-account profiles (`C:\Users\svc_*`) sometimes hold flags too — sweep those.

## Alternate Data Streams hide the flag inside an apparently-empty file

A small file (e.g., `hm.txt`) may carry the real payload in an ADS — `<file>:<stream>:$DATA`. `Get-Content` and `type` against the bare filename return only the visible content; sweeps that just `cat` desktop files miss it.

```cmd
:: List ADS — Windows-native, no third-party tools
dir /R C:\Users\Administrator\Desktop

:: Output flags ADS as a second line under the host file:
::   12/24/2017  03:51 AM     36 hm.txt
::                            34 hm.txt:root.txt:$DATA
```

```powershell
# Read the ADS by stream name
Get-Content -Path C:\Users\Administrator\Desktop\hm.txt -Stream root.txt

# Or list all ADS programmatically:
Get-ChildItem C:\Users\*\Desktop -Recurse -Force |
  Get-Item -Stream * -ErrorAction SilentlyContinue |
  Where-Object Stream -ne ':$DATA'
```

```cmd
:: Cmd alternative:
more < C:\Users\Administrator\Desktop\hm.txt:root.txt
```

`type C:\path\file:stream` does NOT work — `type` silently strips the `:stream` suffix and prints the host file. Use `more <` (cmd) or `Get-Content -Stream` (PowerShell). If you only have a `cat`-style executor (e.g., nxc `-x`), pipe through PowerShell rather than the cmd shell.

## Tools

- PowerShell (Get-ChildItem, Get-Content, `Get-Item -Stream *`)
