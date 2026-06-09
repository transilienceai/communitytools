#!/usr/bin/env python3
"""Print the applicable Test Requirements for one Security Objective.

Deterministic per-objective loader: the workflow's Assess phase runs this instead of
asking an LLM to read + filter work-list.json, so requirement loading carries no model
judgement (and no tokens). Prints a JSON array of the fields the assessor needs.

Usage:
  python3 tools/pci-sss/worklist.py --output-dir DIR --objective O
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

FIELDS = ["id", "objective", "requirement_id", "requirement_text", "test_requirement_text",
          "test_method", "analysis_type", "module", "dynamic_blocked"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--objective", required=True)
    args = ap.parse_args()

    wl = Path(args.output_dir) / "applicability" / "work-list.json"
    if not wl.is_file():
        print(f"worklist: missing {wl}", file=sys.stderr)
        return 2
    try:
        work = json.loads(wl.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"worklist: unparseable {wl}: {e}", file=sys.stderr)
        return 2

    want = str(args.objective)
    reqs = [{k: r.get(k) for k in FIELDS}
            for r in work.get("applicable", [])
            if r.get("id") and str(r.get("objective")) == want]
    print(json.dumps(reqs, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
