# Buffer Overflow

## When this applies

- A target binary (network service, SUID program) has memory-corruption vulnerability.
- Goal: control program execution flow via stack/heap corruption to gain code execution at the binary's privilege level.

## Description

Exploiting memory corruption vulnerabilities by overwriting adjacent memory locations, potentially controlling program execution flow.

## Types

- **Stack-based Buffer Overflow**: Overwriting stack data
- **Heap-based Buffer Overflow**: Corrupting heap memory
- **Integer Overflow**: Causing unexpected behavior through integer wrapping
- **Format String Vulnerabilities**: Exploiting printf-family functions

## Tools

- GDB (GNU Debugger)
- ImmunityDebugger / WinDbg (Windows)
- pwndbg / GEF (GDB extensions)
- Metasploit pattern_create/pattern_offset
- ROPgadget
- Ropper

## Testing Methodology

1. Identify vulnerable input points
2. Determine buffer size and overflow potential
3. Find offset to EIP/RIP (instruction pointer)
4. Identify bad characters
5. Find return address or ROP gadgets
6. Craft exploit payload
7. Bypass protections (DEP, ASLR, Stack Canaries)

## Example Exploit Development

```python
#!/usr/bin/env python3
import socket

# Basic buffer overflow structure
offset = 524
eip = b"\xef\xbe\xad\xde"  # Return address
nop_sled = b"\x90" * 32
shellcode = b"\x31\xc0..."  # Shellcode bytes

payload = b"A" * offset
payload += eip
payload += nop_sled
payload += shellcode

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("target", 9999))
s.send(payload)
```

## Protection Mechanisms

- **DEP/NX**: Non-executable stack/heap
- **ASLR**: Address Space Layout Randomization
- **Stack Canaries**: Detect stack corruption
- **PIE**: Position Independent Executable
- **RELRO**: GOT protection

## Verifying success

- Crash with controlled IP (segfault at the chosen address).
- Eventually, shell connects back / file write occurs / control transfer to ROP chain.

## Common pitfalls

- Bad characters in shellcode (`\x00`, `\x0a`, etc.) terminate the payload — enumerate them first.
- ASLR randomizes addresses — leak before pivot or pick a non-randomized module.
- Stack canaries terminate before EIP overwrite — needs canary leak first.

## References

- **MITRE ATT&CK**: T1068, T1203
- **CWE**: CWE-120 (Buffer Overflow), CWE-121 (Stack-based), CWE-122 (Heap-based)
- **CVE Examples**: CVE-2021-3156 (Sudo Baron Samedit)
- **CAPEC**: CAPEC-100 (Buffer Overflow)
