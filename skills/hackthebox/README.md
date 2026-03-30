# HackTheBox Skill

Automates HackTheBox platform interaction: login, challenge/machine selection, VPN management, solving via pentest agents, and feeding learnings back into skills.

## Prerequisites

- **OpenVPN**: `brew install openvpn` (macOS) or system package
- **Playwright**: MCP plugin installed and configured
- **HTB Account**: Active HackTheBox subscription
- **Pentest Skills**: Existing pentest skills in this repo

## Usage

```
/hackthebox
```

The skill will:
1. Ask for your HTB credentials
2. Login via Playwright browser automation
3. Help you browse and select a challenge/machine
4. Connect VPN in split-tunnel mode
5. Solve using pentester-orchestrator or pentester-spear
6. Log all proceedings to `outputs/YYYYMMDD_<challenge-name>/`
7. Extract generic learnings to improve pentest skills

## Output Structure

```
outputs/YYYYMMDD_<challenge-name>/
├── challenge-log.ndjson    # Timestamped action log
├── recon/                  # Reconnaissance findings
├── exploits/               # Exploit scripts and payloads
├── evidence/               # Screenshots, HTTP captures
├── findings/               # Vulnerability descriptions
└── flag.txt                # Captured flag
```

## VPN Notes

Uses split-tunnel: only HTB lab traffic (10.10.0.0/16) routes through VPN. Your internet connection remains unaffected.

## Skill Improvement

After solving challenges, the skill reviews logs and extracts **generic** techniques to update pentest skills. Rules:
- No platform/challenge references in skill updates
- Only universally applicable techniques
- No bias toward specific CTF patterns
