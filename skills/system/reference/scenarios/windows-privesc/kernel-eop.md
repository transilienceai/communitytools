# Windows Kernel EoP (No SeImpersonatePrivilege Needed)

## When this applies

- Windows target where SeImpersonate is missing or stripped.
- Goal: identify kernel CVE based on build/patch level and exploit for SYSTEM.

## Notable Windows Kernel Exploits

- MS16-032 (CVE-2016-0099)
- MS17-010 (EternalBlue)
- HiveNightmare (CVE-2021-36934)
- CVE-2024-30088 (NtQueryInformationToken TOCTOU race → SYSTEM, Server 2022 pre-June 2024)
- CVE-2023-28252 (CLFS Driver EoP, exploited in wild, April 2023)
- CVE-2024-49138 (CLFS Driver EoP, Server 2022 pre-Dec 2024)

## Methodology

```bash
# Step 1: Identify exact build and patch level
systeminfo | findstr /B /C:"OS Version"
wmic qfe list full   # If ZERO hotfixes → kernel EoP is likely viable

# Step 2: Match build to CVE
# Server 2022 Build 20348.x: Check KB patches against CVE dates
#   Pre-June 2024 (no KB5039227): CVE-2024-30088 (TOCTOU race)
#   Pre-April 2023 (no KB5025230): CVE-2023-28252 (CLFS)
#   Pre-Dec 2024 (no KB5048654): CVE-2024-49138 (CLFS)
# Server 2025 Build 26100.x: Fewer public exploits, check newer CVEs

# Step 3: Transfer and execute exploit
# If target has no internet: base64 encode binary → transfer via echo/certutil
certutil -decode exploit.b64 C:\temp\exploit.exe
# CVE-2024-30088: TOCTOU race corrupts token → open winlogon.exe (SYSTEM) handle
#   → spawn SYSTEM cmd via PPID spoofing (CreateProcess with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)
# Post-exploit: use SYSTEM to DCSync, read flags, dump LSASS
```

## PPID Spoofing for SYSTEM Shell (after kernel exploit gives SYSTEM handle)

```csharp
// After exploit opens a SYSTEM process handle (e.g., winlogon.exe):
// CreateProcess with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS → child inherits SYSTEM token
// Compile on target: csc.exe /out:run_as_parent.exe run_as_parent.cs
// Usage: run_as_parent.exe <SYSTEM_PID> cmd.exe /c <command>
```

## CVE-2023-28252 (CLFS LPE) — Operational Gotchas

The duck-sec compiled CVE-2023-28252 PoC (`exploit.exe <token_offset> <flag> <cmd>`) is the go-to single-shot LPE for Windows 10/11/Server 2022 pre-April 2023. Token offsets: `0x4b8` (1208) for Win11 22000, `0x40` for Win10 19041, etc. Three operational pitfalls that consistently waste time:

1. **DO NOT run from `C:\Windows\Tasks\`** — even though `Tasks` is writable by all users, the directory's restrictive ACL on SYSTEM-written *output files* makes them unreadable by the original low-priv user. Use `C:\Users\Public\` or `%TEMP%` instead.

2. **SYSTEM-written output requires explicit ACL grant** — when your batch script runs as SYSTEM and writes a file (e.g., `type root.txt > out.txt`), the file inherits SYSTEM's restrictive ACL. You'll get `Access to the path is denied` when the user tries to read it. Always include in the batch script:

   ```bat
   type "C:\Users\Administrator\Desktop\root.txt" > C:\Users\Public\out.txt
   icacls C:\Users\Public\out.txt /grant Everyone:R
   ```

3. **CLFS exploit leaves stale `.blf` and `.p_N` container files** — second run with the same working directory errors `Could not create LOGfile1, error: 0x20` (ERROR_SHARING_VIOLATION). Clean up before re-running:

   ```powershell
   rm -Force C:\Users\Public\6.blf,C:\Users\Public\.p_6 -ErrorAction SilentlyContinue
   ```

   The "6" is hardcoded in the PoC's `BasicLogFileName`. If unsure, just `rm *.blf, .p_*`.

4. **Multi-shell race** — when foothold is delivered by a periodic bot (ThemeBleed, Roundcube .eps, etc.) the bot opens the trigger every few seconds, so multiple reverse shells land in parallel. They race over the CLFS files and corrupt each other. Driver MUST take ONE shell (use `threading.Event`) and ignore the rest.

## CVE-2023-38146 (ThemeBleed) — SMB DLL Fast-Swap Setup

Windows 11 < KB5030219 fetches `<theme>.msstyles_vrf.dll` from a UNC path declared in `[VisualStyles] Path=\\<host>\share\Aero.msstyles`. The verifier reads the DLL twice: once for signature check, once for load. A malicious SMB server returns the benign signed DLL on read 1 and swaps to the attacker DLL on read 2. The Jnnshschl PoC (`https://github.com/Jnnshschl/CVE-2023-38146`) is the linux-friendly impacket variant — works on Kali/macOS unlike the original gabe-k Windows-only POC.

Macos-specific gotcha: `nc -z <VPN_IP> 445` from local will time out (PF/socketfilterfw blocks the loopback path through utun), but **inbound traffic from the actual VPN peer (lab box → utun6) IS allowed** by default. Don't conclude "445 is blocked" from a local probe — fire the exploit and watch SMB server logs.

The PowerShell reverse shell baked into the evil DLL is a standard `Net.Sockets.TCPClient` loop reading bytes and `iex`-ing them. Stream stays open across multiple commands; each `c.sendall(cmd+"\n")` is consumed by the loop and output flushed back. Send short commands one at a time with timeout-based reads — large multi-line PS payloads RST the connection.

## Verifying success

- Post-exploit, `whoami` returns `nt authority\system`.
- The `Everyone:R` ACL grant lets the original low-priv user read the SYSTEM-written output file.

## Common pitfalls

- Always `icacls /grant Everyone:R` on SYSTEM-written output files — otherwise the low-priv user can't read.
- CLFS PoC leaves stale `.blf` / `.p_N` — clean before re-running.
- Multi-shell race needs a `threading.Event` to coordinate.

## Tools

- systeminfo / wmic qfe list
- certutil (-decode)
- duck-sec CVE-2023-28252 PoC
- Jnnshschl CVE-2023-38146 PoC (impacket SMB server)
