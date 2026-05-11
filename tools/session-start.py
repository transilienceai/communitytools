#!/usr/bin/env python3
"""SessionStart hook.

Pre-emits standard environment context once per session:
- Loads canonical credentials via env-reader (silent NOT_SET).
- Asserts OUTPUT_DIR convention awareness.
- Surfaces the skills/INDEX.md router path so the coordinator knows where to look.

Replaces the manual "always run env-reader" rule that was duplicated in every skill.

Hook contract: stdout is piped into the conversation as system context. Exit 0 always
(SessionStart should never block).
"""
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_READER = REPO_ROOT / "tools" / "env-reader.py"
INDEX = REPO_ROOT / "skills" / "INDEX.md"
PRINCIPLES = REPO_ROOT / "skills" / "coordination" / "reference" / "principles.md"

CANONICAL_VARS = [
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "HTB_USER",
    "HTB_PASS",
    "HTB_TOKEN",
    "HACKERONE_TOKEN",
    "SLACK_BOT_TOKEN",
    "HTB_SLACK_CHANNEL_ID",
    "FLAG",
]


def env_status() -> dict[str, bool]:
    if not ENV_READER.exists():
        return {}
    try:
        result = subprocess.run(
            ["python3", str(ENV_READER), *CANONICAL_VARS],
            capture_output=True, text=True, timeout=5, check=False,
        )
        out = result.stdout
    except Exception:
        return {}
    status: dict[str, bool] = {}
    for line in out.splitlines():
        if "=" not in line:
            continue
        var, _, val = line.partition("=")
        status[var.strip()] = bool(val.strip()) and val.strip() != "NOT_SET"
    return status


def main() -> int:
    set_vars = env_status()
    print("# Session bootstrap")
    print()
    print(f"- Skill router: {INDEX.relative_to(REPO_ROOT)}")
    print(f"- Engagement principles: {PRINCIPLES.relative_to(REPO_ROOT)}")
    print(f"- OUTPUT_DIR: write every artifact under an engagement directory; never the repo root.")
    print()
    if set_vars:
        ready = sorted(v for v, ok in set_vars.items() if ok)
        not_set = sorted(v for v, ok in set_vars.items() if not ok)
        if ready:
            print(f"- Credentials ready: {', '.join(ready)}")
        if not_set:
            print(f"- Credentials NOT_SET: {', '.join(not_set)}")
            print("  Coordinators must NOT call AskUserQuestion. If a NOT_SET variable is needed,")
            print("  the coordinator emits status=BLOCKED with a clear BLOCKED_REASON.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
