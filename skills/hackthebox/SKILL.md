---
name: hackthebox
description: HackTheBox platform automation — login, VPN, solve challenges via orchestrator, submit flags, feed learnings back.
---

# HackTheBox

Runs **inline**. Playwright MCP required (current session only).

## Rules
- Never solve inline — delegate to orchestrator (step 8)
- No DoS, no brute force, no headless browser
- Read credentials via `env-reader.py` before asking user

## Workflow

Detailed steps: `reference/workflow.md`

1. **Credentials** — `python3 tools/env-reader.py HTB_USER HTB_PASS ANTHROPIC_API_KEY SLACK_BOT_TOKEN HTB_SLACK_CHANNEL_ID`
2. **VPN** — verify running, ask user if not
3. **Output dir** — `mkdir -p YYMMDD_<name>/{recon,findings,logs,artifacts,reports}`
4. **Login** — headed browser, handle 2FA/Cloudflare
5. **Start machine** — navigate, start, save meta
6. **Connectivity** — ping, curl, configure `/etc/hosts`
7. **Slack: started** — via `tools/slack-send.py`
8. **Orchestrator** — see below
9. **Submit flags** — via Playwright on Tab 0
10. **Skiller** — `/skiller` (MANDATORY, foreground)
11. **Stats** — read `stats.json`, write completion report
12. **Slack: completed** — full narrative

## Step 8: Orchestrator

Read `skills/coordination/reference/orchestrator-role.md` and execute its cyclic workflow **inline** with:

```
TARGET: {ip}
SCOPE: {details}
OUTPUT_DIR: {date}_{name}/
TAGS: {tags}
HTB CONSTRAINT: Logic-based solutions only. No Hydra, no wordlists.
Prioritize: source review, logic flaws, injection, misconfig, default creds, CVEs.
```

The orchestrator runs in this session (not a sub-agent) so it can spawn executor agents. Write `stats.json` before returning.

## Tab Management
- **Tab 0**: Challenge page — never close, use for Start/Stop/Submit
- **Tab 1+**: Disposable work tabs
