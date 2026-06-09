#!/usr/bin/env python3
"""Coverage gate — fails closed if any applicable requirement lacks a verdict.

Because enumeration is deterministic, a complete assessment must produce
exactly one verdict for every applicable Test Requirement. REQUIRES_MANUAL_REVIEW
counts as covered (it is surfaced in the report), but a MISSING verdict is a
hard failure: it means a requirement was silently skipped.

Compares applicability/work-list.json (the applicable set) against
artifacts/validated/ + artifacts/false-positives/ (the emitted verdicts).

Usage:
  python3 tools/pci-sss/coverage_gate.py --output-dir DIR

Writes artifacts/coverage.json. Exit 0 iff coverage_ratio == 1.0 and no missing ids.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _emitted_ids(output_dir: Path) -> set:
    ids = set()
    for sub in ("validated", "false-positives"):
        d = output_dir / "artifacts" / sub
        if d.is_dir():
            for jf in d.glob("*.json"):
                try:
                    v = json.loads(jf.read_text(encoding="utf-8"))
                    tid = v.get("test_requirement_id") or jf.stem
                    ids.add(tid)
                except json.JSONDecodeError:
                    ids.add(jf.stem)
    return ids


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output-dir", required=True)
    args = ap.parse_args()
    out = Path(args.output_dir)

    wl_path = out / "applicability" / "work-list.json"
    if not wl_path.is_file():
        print(f"coverage_gate: missing {wl_path}", file=sys.stderr)
        return 2
    try:
        work = json.loads(wl_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"coverage_gate: unparseable {wl_path}: {e}", file=sys.stderr)
        return 2
    applicable_ids = set(work.get("applicable_ids") or [r["id"] for r in work.get("applicable", []) if r.get("id")])

    emitted = _emitted_ids(out)
    missing = sorted(applicable_ids - emitted)
    extra = sorted(emitted - applicable_ids)   # a verdict for a non-applicable id is a fabrication signal
    ratio = round(len(applicable_ids & emitted) / len(applicable_ids), 4) if applicable_ids else 0.0

    result = {
        "applicable": len(applicable_ids),
        "emitted": len(emitted),
        "covered": len(applicable_ids & emitted),
        "coverage_ratio": ratio,
        "missing_ids": missing,
        "extra_ids": extra,
        "complete": not missing and not extra and ratio >= 1.0,
    }
    dest = out / "artifacts" / "coverage.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"coverage_gate: ratio={ratio} applicable={len(applicable_ids)} "
          f"emitted={len(emitted)} missing={len(missing)} extra={len(extra)} -> {dest}")
    for label, ids in (("MISSING", missing), ("EXTRA", extra)):
        for x in ids[:25]:
            print(f"  {label} {x}")
        if len(ids) > 25:
            print(f"  ... and {len(ids) - 25} more {label}")
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
