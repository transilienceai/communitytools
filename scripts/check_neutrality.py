#!/usr/bin/env python3
"""Fail if a real (non-documentation) public IPv4 address leaks into the reusable,
client-neutral trees: tools/, formats/, docs/, scripts/.

These trees are the single source of truth and must carry NO engagement-specific
data. Examples must use the RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24), RFC 1918 private ranges, loopback, or a small
set of well-known public resolvers. Any other public IPv4 is flagged as a probable
client/target leak. (Name/token neutrality in skills/ is enforced separately by
scripts/skill_linter.py; this guard covers the trees that linter does not.)

Exit 0 = clean; 1 = leak(s) found. Run from the repo root.
"""
from __future__ import annotations

import ipaddress
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TREES = ("tools", "formats", "docs", "scripts")
EXTS = (".py", ".md", ".json", ".sh", ".mjs", ".js", ".txt", ".yml", ".yaml")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "pci-sss"}
# Files that necessarily contain IP literals as allowlist/denylist data.
SKIP_FILES = {"check_client_data.py", "client-denylist.txt", "check_neutrality.py"}

# strict dotted-quad, each octet 0-255, not part of a longer number/version
_IP_RE = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)"
                    r"\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d))(?![\d.])")

# well-known public resolvers + universally-understood synthetic placeholders that
# are legitimate generic examples (never real client/target data).
ALLOW_PUBLIC = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "255.255.255.255",
                "1.2.3.4", "4.3.2.1"}


def _is_placeholder(s: str) -> bool:
    """Obvious synthetic placeholders a real client IP is never: repeated octets
    (N.N.N.N) or the canonical sequential 1.2.3.4 / 4.3.2.1."""
    if s in ALLOW_PUBLIC:
        return True
    octets = s.split(".")
    return len(set(octets)) == 1  # e.g. 2.2.2.2, 0.0.0.0 (already private-ish)


# The "is this address customer-specific?" rule has ONE home, in
# check_client_data.py. This file used to carry a near-identical copy, and the two
# drifted the moment one was taught about IANA special-purpose blocks and
# structural CIDR notation — leaving two guards that disagreed about the same line.
# Import it rather than restate it.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from check_client_data import is_doc_ip as _is_documentation      # noqa: E402
from check_client_data import is_structural_cidr                  # noqa: E402


def scan_file(path: str) -> list[tuple[int, str]]:
    hits = []
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return hits
    for n, line in enumerate(lines, 1):
        for m in _IP_RE.finditer(line):
            s = m.group(1)
            if _is_placeholder(s):
                continue
            try:
                ip = ipaddress.ip_address(s)
            except ValueError:
                continue
            if _is_documentation(ip) or is_structural_cidr(line, s, m.end(1)):
                continue
            hits.append((n, s))
    return hits


def main() -> int:
    leaks = []
    for tree in TREES:
        root = os.path.join(REPO, tree)
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if not fn.endswith(EXTS) or fn in SKIP_FILES:
                    continue
                p = os.path.join(dirpath, fn)
                for lineno, ip in scan_file(p):
                    leaks.append((os.path.relpath(p, REPO), lineno, ip))
    if not leaks:
        print(f"check_neutrality: OK — no non-documentation public IPs in {'/, '.join(TREES)}/")
        return 0
    print("check_neutrality: FAIL — probable client/target IP leak(s) in reusable trees:", file=sys.stderr)
    for rel, lineno, ip in leaks:
        print(f"  {rel}:{lineno}: {ip}", file=sys.stderr)
    print("\nUse an RFC 5737 doc range (203.0.113.x / 198.51.100.x / 192.0.2.x) or a private range "
          "in examples; real target IPs belong only under projects/.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
