# WCF / SOAP Service Exploitation (Post-Shell Privilege Escalation)

## When this applies

- After obtaining initial shell access, you discover localhost-only WCF/SOAP/XML-RPC services running as SYSTEM or a privileged user.
- Goal: exploit command injection in SOAP method parameters to gain higher privileges.

## Discovery

1. **Scan localhost ports** — `ss -tlnp | grep 127.0.0.1` or `netstat -tlnp | grep 127` — look for uncommon ports (8000, 8888, 9090, etc.)
2. **Identify WCF/SOAP** — `curl http://127.0.0.1:PORT/` — look for WSDL links, "Metadata publishing" pages, XML-based error responses, or `.svc` endpoints
3. **Fetch WSDL** — `curl http://127.0.0.1:PORT/?wsdl` or `curl http://127.0.0.1:PORT/service?wsdl` — reveals method names, parameter types, and SOAP action headers
4. **Read service source** — check process command line (`/proc/PID/cmdline` on Linux, `wmic process` on Windows) to find the binary, then decompile (.NET with `ilspycmd`/`dnspy`) or read source to understand method implementations

## Exploitation

5. **Command injection in SOAP parameters** — if a method passes user input to `Process.Start()`, `system()`, `exec()`, or PowerShell, inject commands in the SOAP body parameter value
6. **PowerShell path encoding** — when injecting PowerShell commands inside XML/SOAP bodies, use forward slashes (`C:/Users/file.txt`) instead of backslashes to avoid UTF-16LE encoding issues in XML parsing. Alternatively, base64-encode the entire PowerShell command: `powershell -enc <base64>`

## Verifying success

- The injected command's side effect (file write, network connection back) is observable.
- Output methods (return values logged or echoed in error responses) reveal command output.

## Common pitfalls

- XML parsing strips backslashes in some encoders — use forward slashes or base64-encoded PowerShell.
- Localhost-only services may bind only to 127.0.0.1; access via SSH port forward / SOCKS proxy from attacker box.

## Tools

- curl
- ilspycmd / dnSpy (.NET decompilation)
- ss / netstat
