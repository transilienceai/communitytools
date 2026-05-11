#!/usr/bin/env python3
"""PreToolUse hook on AskUserQuestion.

Blocks the call if the invoking agent's name matches a coordinator pattern.
Allows the call from the parent orchestrator (no agent name in payload, or a name
that doesn't match the coordinator regex).

The hook receives a JSON payload on stdin describing the tool call. We inspect the
agent context to detect coordinator role.

Exit codes:
  0 — allow the call
  2 — block the call (Claude sees the stderr message and aborts)
"""
import json
import os
import re
import sys

# Configurable regex via env. Default: any agent named '<...>-coordinator-<...>' or 'coordinator-<...>'.
COORDINATOR_RE = re.compile(os.environ.get(
    "BLOCK_COORDINATOR_ASK_REGEX",
    r"(?:^|/)(?:[^/]*-)?coordinator-",
))

DENY_MESSAGE = (
    "AskUserQuestion is forbidden inside coordinator agents.\n"
    "If a credential or scope item is missing:\n"
    "  1. Run `python3 tools/env-reader.py <var>` first.\n"
    "  2. If it returns NOT_SET, terminate this engagement with status=BLOCKED.\n"
    "  3. The parent orchestrator decides whether to ask the user.\n"
    "See skills/coordination/reference/role-matrix.md."
)


def detect_agent_name() -> str:
    """Best-effort agent-name detection from environment + stdin payload."""
    # 1. Some harnesses pass the agent name via env.
    for var in ("CLAUDE_AGENT_NAME", "AGENT_NAME", "SUBAGENT_NAME"):
        val = os.environ.get(var, "")
        if val:
            return val
    # 2. Fall back to stdin JSON payload (PreToolUse contract).
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return ""
    for key in ("agent_name", "agent", "subagent_name", "name"):
        val = payload.get(key) if isinstance(payload, dict) else None
        if isinstance(val, str) and val:
            return val
    # 3. Inspect nested metadata if present.
    md = payload.get("metadata") if isinstance(payload, dict) else None
    if isinstance(md, dict):
        for key in ("agent_name", "agent", "name"):
            val = md.get(key)
            if isinstance(val, str) and val:
                return val
    return ""


def main() -> int:
    name = detect_agent_name()
    if name and COORDINATOR_RE.search(name):
        sys.stderr.write(f"[block-coordinator-ask] BLOCKED for agent {name!r}.\n")
        sys.stderr.write(DENY_MESSAGE + "\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
