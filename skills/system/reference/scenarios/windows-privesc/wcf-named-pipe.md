# WCF/SOAP/Named Pipe Service Exploitation

## When this applies

- Windows foothold; localhost-only WCF services running as SYSTEM are present.
- Goal: command-inject through SOAP method parameters to escalate.

## Steps

```powershell
# Discover localhost-only services
netstat -ano | findstr "127.0.0.1" | findstr "LISTENING"

# Identify WCF services — look for WSDL metadata
curl http://127.0.0.1:8000/?wsdl
# Or via PowerShell
Invoke-WebRequest http://127.0.0.1:8000/ -UseBasicParsing

# If a WCF method concatenates input into PowerShell/cmd:
# Use forward slashes in paths (avoids UTF-16LE XML encoding issues)
# Or base64-encode: powershell -enc <base64>
```

WCF services running as SYSTEM on localhost often lack input validation — check every method parameter for command injection.

## .NET Binary Decompilation for Credential/Vuln Discovery

```powershell
# Identify .NET services
Get-Process | ForEach-Object { $_.MainModule.FileName } 2>$null
wmic process get ProcessId,ExecutablePath

# Decompile with ILSpy (CLI: ilspycmd), dnSpy, dotPeek, or JetBrains dotTrace
# Search decompiled code for:
# - Connection strings: "Server=", "Data Source=", "Password="
# - Hardcoded credentials, API keys, encryption keys
# - Process.Start(), PowerShell invocations with string concatenation (injection points)
# - Linked server names, internal hostnames, service endpoints
```

## Verifying success

- Injected command's side effect (file write, network connection) is observable.
- Output methods reveal command output via return values or error responses.

## Common pitfalls

- XML parsing strips backslashes — use forward slashes or base64-encode the PowerShell payload.

## Tools

- curl / Invoke-WebRequest
- ILSpy / dnSpy / dotPeek (.NET decompilation)
- netstat / Get-Process
