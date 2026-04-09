---
name: hackthebox
description: HackTheBox platform operations and automations to solve challenges, machines and capture the flags hacking competitions
context: fork
---

## Workflow
- [workflow.md](reference/workflow.md) — Complete workflow with commands. Read this for each step

### Steps
1. Get Credentials — `python3 .claude/tools/env-reader.py HTB_USER HTB_PASS ANTHROPIC_API_KEY SLACK_BOT_TOKEN HTB_SLACK_CHANNEL_ID`
2. Only for "Machine" kind of competition -> Verify vpn is running, otherwise download the vpn file from HTB and instruct the user on how to enable it
3. Generate output dirs — `mkdir -p YYMMDD_<name>/{recon,findings,logs,artifacts,reports}` for each challenge
4. Login hackthebox.com
5. If necessary, start the machines
6. If necessary, check network connectivity to the machines
7. Spawn and manage coordinator pool — max N concurrent agents, queue-based spawning (new agent spawns when previous completes)

## References
- [workflow.md](reference/workflow.md) — Workflow overview with credentials, VPN, setup, and coordinator spawn
- [coordinator-spawn.md](reference/coordinator-spawn.md) — Coordinator agent spawn prompt template (includes flag submission, reporting, skill-update, slack notifications)
- [completion-report-schema.md](../../formats/htb-completion-report.md) — Challenge completion report structure & template
- [slack-notifications.md](reference/slack-notifications.md) — Slack completion notification format & examples
- [platform-navigation.md](reference/platform-navigation.md) — HTB site navigation guide
- [vpn-setup.md](reference/vpn-setup.md) — VPN connectivity troubleshooting
- [cloudflare-bypass.md](reference/cloudflare-bypass.md) — Cloudflare detection evasion
