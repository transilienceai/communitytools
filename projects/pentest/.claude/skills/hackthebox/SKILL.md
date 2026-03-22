---
name: hackthebox
description: HackTheBox platform automation - login via Playwright, browse challenges/machines/labs, manage VPN connections, solve challenges using pentest skills, log all proceedings, and feed learnings back into skill improvement.
---

# HackTheBox

**Execute this workflow directly — do NOT spawn a subagent.** Playwright MCP tools (browser navigation, clicking, screenshots) are only available in the current session, not in subagents.

Read the agent definition and follow it step by step:

```
Read .claude/agents/hackthebox.md
```

Then execute the workflow from that file directly in this session — Phase 0 through Phase 6. You have access to all required tools: Playwright MCP (browser), Bash (including `.claude/tools/env-reader.py` and `.claude/tools/slack-send.py`), Agent (for spawning orchestrator), AskUserQuestion, Read, Write.

**Key points:**
- You ARE the hackthebox agent — execute its workflow directly
- Use Playwright MCP tools for all browser interaction (login, tab management, flag submission)
- Use `python3 .claude/tools/slack-send.py` for Slack notifications — no agent spawn needed
- Use `python3 .claude/tools/env-reader.py` for credentials — no agent spawn needed
- Spawn `Pentester Orchestrator` as subagent via Agent tool
- The user's request follows the `/hackthebox` command — pass it through
