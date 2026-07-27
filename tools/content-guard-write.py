#!/usr/bin/env python3
"""PreToolUse hook on Write|Edit — refuse to write client data into the public tree.

The last gate before content exists on disk. pre-commit and CI both fire later,
when the mistake is already written and often already reasoned about; catching it
at the moment of the write is cheaper for everyone.

Deliberately narrow. It scans only the INCOMING content (a few KB), never the
repo, and returns early for anything under projects/ or anything gitignored — so
it stays silent during an engagement, which is where nearly every write happens.
It guards the reusable tree only.

Fails OPEN on any parse or IO error. A write-blocker that misfires makes the
repository unusable, and the deterministic guards downstream (pre-commit,
pre-push, content-guards.yml) are the ones that must be exhaustive. This one
trades recall for never being in the way.

Exit codes (matching tools/block-coordinator-ask.py, this repo's hook contract):
  0 — allow the write
  2 — block it; stderr is shown to Claude
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Structural classes only — no client-name lane. Names live in a salted digest
# file that is not always present, and a name-based miss here is picked up by the
# committed-content guards anyway.
RULES = [
    ("operator home path", re.compile(
        r"/(?:Users|home)/[A-Za-z][A-Za-z0-9._-]{2,}/"
        r"|[A-Za-z]:\\Users\\[A-Za-z][A-Za-z0-9._-]{2,}")),
    ("engagement directory", re.compile(
        r"\b(?:projects/(?:pentest|compliance|offsec|webinars|attacks-validation"
        r"|attack-path-prioritisation)/|outputs?/)\d{6,8}[_-][A-Za-z0-9_.-]+")),
    ("engagement finding id", re.compile(r"\bf\d{2}_[a-z][a-z0-9_]*\.py\b|\bF-SWEEP-[A-Za-z0-9_-]+\b")),
    ("credential material", re.compile(
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
        r"|\bgh[pousr]_[A-Za-z0-9]{30,}\b"
        r"|\bxox[baprs]-[0-9]{8,}-[A-Za-z0-9-]{10,}\b"
        r"|\bAIza[0-9A-Za-z_-]{35}\b"
        r"|-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
]

# Same suppressors as the committed-content guard: shared/lab accounts and
# placeholder metavariables are not identities.
ALLOW = re.compile(
    r"(?i:/(?:Users|home)/(?:username|users?|you|carlos|kali|claude|root|admin|administrator"
    r"|public|restricted_user|asterisk|current_user|target|victim|attacker|ubuntu|ec2-user"
    r"|vagrant|student|htb|svc_[A-Za-z0-9_]*)(?:/|\b))"
    r"|(?i:[A-Za-z]:\\Users\\(?:public|administrator|username|users?|target|current_user"
    r"|carlos|svc_[A-Za-z0-9_]*)\b)"
    r"|/(?:Users|home)/[^/\s]*[<>\[\]*%$]"
    r"|[A-Za-z]:\\Users\\[^\\\s]*[<>\[\]*%$]"
    r"|(?i:acme|example|placeholder|redacted|your)")

DENY = """[confidentiality] Refusing to write {path}.

This repository is PUBLIC. The incoming content contains:
{hits}

Write about the CLASS of issue, not the customer. Use placeholders — acme.com,
RFC 5737 addresses (203.0.113.x), <user> for home paths — and keep engagement
data under projects/, which is gitignored.

See docs/CONFIDENTIALITY.md. Engagement trees are exempt; this guard only
protects the reusable tree.
"""


def _dig(payload: dict, path: str):
    cur = payload
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _first_str(payload: dict, keys) -> str:
    for k in keys:
        v = _dig(payload, k)
        if isinstance(v, str) and v:
            return v
    return ""


def _joined(payload: dict, keys) -> str:
    parts = []
    for k in keys:
        v = _dig(payload, k)
        if isinstance(v, str) and v:
            parts.append(v)
    return "\n".join(parts)


def _git_ignored(abspath: str) -> bool:
    try:
        r = subprocess.run(["git", "-C", REPO, "check-ignore", "-q", "--no-index", abspath],
                           capture_output=True, timeout=5)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def scan(text: str) -> list[str]:
    hits = []
    for label, rx in RULES:
        for m in rx.finditer(text):
            if ALLOW.search(m.group(0)):
                continue
            line = text[:m.start()].count("\n") + 1
            # Never echo the match itself — that would reproduce the leak in a
            # transcript. Location and class are enough to act on.
            hits.append(f"  - {label} (line {line})")
            break
    return hits


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:  # noqa: BLE001 — fail OPEN
        return 0
    try:
        path = _first_str(payload, ("tool_input.file_path", "params.file_path",
                                    "input.file_path", "tool_input.path"))
        text = _joined(payload, ("tool_input.content", "tool_input.new_string",
                                 "params.content", "params.new_string",
                                 "input.content", "input.new_string"))
        if not path or not text:
            return 0
        abspath = os.path.realpath(path if os.path.isabs(path) else os.path.join(REPO, path))
        root = os.path.realpath(REPO)
        if not abspath.startswith(root + os.sep):
            return 0                                    # outside this repo
        if abspath.startswith(os.path.join(root, "projects") + os.sep):
            return 0                                    # client data belongs there
        if _git_ignored(abspath):
            return 0                                    # never published

        hits = scan(text)
        if hits:
            rel = os.path.relpath(abspath, root)
            sys.stderr.write(DENY.format(path=rel, hits="\n".join(hits)))
            return 2
    except Exception:  # noqa: BLE001 — fail OPEN on anything unexpected
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
