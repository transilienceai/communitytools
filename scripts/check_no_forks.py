#!/usr/bin/env python3
"""Fail if a copy of the canonical report generator has been forked into an
engagement dir (projects/) or anywhere else outside its one sanctioned home.

A forked generate_report.py drifts from the escaping/KPI contract and can emit
un-escaped markup into a rendered PDF. The canonical file is
skills/transilience-report-style/reference/generate_report.py; any other file whose
basename is generate_report*.py (e.g. generate_report_full.py) is a fork.

Exit 0 = no forks; 1 = fork(s) found; run from the repo root.
"""
from __future__ import annotations

import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANONICAL = os.path.join("skills", "transilience-report-style", "reference", "generate_report.py")
# The reusable source-of-truth trees that MUST stay fork-free. projects/ trees are
# engagement-local and out of scope for the reusable-content guarantee, so they are
# not checked here.
TREES = ("skills", "tools", "formats", "docs")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}


def find_forks(root: str) -> list[str]:
    forks = []
    for tree in TREES:
        base = os.path.join(root, tree)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if fn.startswith("generate_report") and fn.endswith(".py"):
                    rel = os.path.relpath(os.path.join(dirpath, fn), root)
                    # the canonical file and its sibling test are allowed
                    if rel == CANONICAL or fn.startswith("test_"):
                        continue
                    # a symlink pointing at the canonical file is fine (mount points)
                    full = os.path.join(dirpath, fn)
                    if os.path.islink(full) and os.path.realpath(full) == os.path.realpath(os.path.join(root, CANONICAL)):
                        continue
                    forks.append(rel)
    return sorted(forks)


def main() -> int:
    forks = find_forks(REPO)
    if not forks:
        print("check_no_forks: OK — only the canonical generate_report.py exists")
        return 0
    print("check_no_forks: FAIL — forked report generator(s) found (drift risk):", file=sys.stderr)
    for f in forks:
        print(f"  {f}", file=sys.stderr)
    print(f"\nUse the canonical {CANONICAL} (it owns escaping + the report_data_shape guard). "
          "Do not copy/modify it per-engagement.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
