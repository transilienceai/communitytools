#!/usr/bin/env python3
"""Roll per-Test-Requirement verdicts up to requirement / objective / module / overall.

Reads an engagement's artifacts/validated/*.json, applies the deterministic
ladder from schema.md §10, and writes artifacts/status-rollup.json.

Usage:
  python3 tools/pci-sss/aggregate.py --output-dir DIR [--catalog PATH]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from _common import load_catalog

STATUSES = ["MET", "NOT_MET", "PARTIALLY_MET", "NOT_APPLICABLE", "REQUIRES_MANUAL_REVIEW"]


def ladder(child_statuses: list[str]) -> str:
    """Combine child statuses into a parent status (schema.md §10)."""
    s = set(child_statuses)
    if not s:
        return "REQUIRES_MANUAL_REVIEW"
    if s <= {"NOT_APPLICABLE"}:
        return "NOT_APPLICABLE"
    effective = s - {"NOT_APPLICABLE"}
    if effective <= {"MET"}:
        return "MET"
    if effective <= {"NOT_MET"}:
        return "NOT_MET"
    if "REQUIRES_MANUAL_REVIEW" in effective and "NOT_MET" not in effective and "PARTIALLY_MET" not in effective:
        return "REQUIRES_MANUAL_REVIEW"
    return "PARTIALLY_MET"


def counts(statuses: list[str]) -> dict:
    c = {k: 0 for k in STATUSES}
    for st in statuses:
        if st in c:
            c[st] += 1
    decided = c["MET"] + c["NOT_MET"] + c["PARTIALLY_MET"]
    c["pct_met"] = round(c["MET"] / decided, 4) if decided else None
    return c


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--catalog", default=None)
    args = ap.parse_args()

    out = Path(args.output_dir)
    validated = out / "artifacts" / "validated"
    if not validated.is_dir():
        print(f"aggregate: no {validated}", file=sys.stderr)
        return 1
    # Fail closed: the absence of quarantined.json proves citation_verify.py has NOT run,
    # so the verdicts have not been citation-checked and must not be rolled up as decided.
    if not (out / "artifacts" / "quarantined.json").is_file():
        print("aggregate: artifacts/quarantined.json missing — run citation_verify.py first "
              "(rollup must not count un-verified verdicts)", file=sys.stderr)
        return 2
    catalog = load_catalog(args.catalog) if args.catalog else load_catalog()
    by_id = {r["id"]: r for r in catalog["test_requirements"]}

    verdicts = []
    for jf in sorted(validated.glob("*.json")):
        try:
            verdicts.append(json.loads(jf.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue

    AFFIRM = {"MET", "NOT_MET", "PARTIALLY_MET"}

    def effective_status(v: dict) -> str:
        """An affirmative status counts only if it passed citation verification; otherwise
        it is treated as REQUIRES_MANUAL_REVIEW so an un-verified MET can never inflate %MET."""
        st = v.get("status", "REQUIRES_MANUAL_REVIEW")
        if st in AFFIRM and v.get("citation_verified") is not True:
            return "REQUIRES_MANUAL_REVIEW"
        return st

    by_req: dict[str, list[str]] = defaultdict(list)
    by_obj: dict[str, list[str]] = defaultdict(list)
    by_mod: dict[str, list[str]] = defaultdict(list)
    for v in verdicts:
        cat = by_id.get(v.get("test_requirement_id"), {})
        st = effective_status(v)
        if cat.get("requirement_id"):
            by_req[cat["requirement_id"]].append(st)
        if cat.get("objective"):
            by_obj[str(cat["objective"])].append(st)
        if cat.get("module"):
            by_mod[cat["module"]].append(st)

    rollup = {
        "overall": counts([effective_status(v) for v in verdicts]),
        "by_requirement": {r: {"status": ladder(s), **counts(s)} for r, s in sorted(by_req.items())},
        "by_objective": {o: {"status": ladder(s), **counts(s)} for o, s in sorted(by_obj.items())},
        "by_module": {m: {"status": ladder(s), **counts(s)} for m, s in sorted(by_mod.items())},
        "total_verdicts": len(verdicts),
    }
    dest = out / "artifacts" / "status-rollup.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(rollup, ensure_ascii=False, indent=2), encoding="utf-8")
    ov = rollup["overall"]
    print(f"aggregate: {len(verdicts)} verdicts -> {dest} "
          f"(MET={ov['MET']} NOT_MET={ov['NOT_MET']} PARTIAL={ov['PARTIALLY_MET']} "
          f"N/A={ov['NOT_APPLICABLE']} MANUAL={ov['REQUIRES_MANUAL_REVIEW']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
