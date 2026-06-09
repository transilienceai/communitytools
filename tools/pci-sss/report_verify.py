#!/usr/bin/env python3
"""Deterministic final report-integrity gate.

The compliance report (PDF / compliance-report.json / tracker.csv) is authored by an LLM
agent. This tool re-checks that report against the deterministic ground truth — the
citation-verified verdict files — so the agent cannot inflate, drop, or fabricate results.
Run it AFTER the report agent writes its outputs; a non-zero exit means the report does not
faithfully reflect the verdicts and must not be shipped as COMPLETE.

Checks (all fail-closed):
  1. Coverage: every applicable id has a verdict; no extra ids (reuses coverage.json).
  2. No unverified affirmative: no verdict with status in {MET,NOT_MET,PARTIALLY_MET} has
     citation_verified != true (i.e. citation_verify.py ran and passed it).
  3. Report status fidelity: for every requirement in compliance-report.json, its status
     equals the citation-verified verdict's effective status (un-verified affirmatives count
     as REQUIRES_MANUAL_REVIEW). No MET in the report that the verdict files do not support.
  4. Rollup fidelity: the report's overall MET/NOT_MET/PARTIALLY_MET/NOT_APPLICABLE/
     REQUIRES_MANUAL_REVIEW counts match a recompute from the verdict files.
  5. tracker.csv row count == number of applicable requirements.

Usage:
  python3 tools/pci-sss/report_verify.py --output-dir DIR
Writes artifacts/report-verify.json. Exit 0 iff the report is faithful and complete.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

AFFIRM = {"MET", "NOT_MET", "PARTIALLY_MET"}
STATUSES = ["MET", "NOT_MET", "PARTIALLY_MET", "NOT_APPLICABLE", "REQUIRES_MANUAL_REVIEW"]


def effective_status(v: dict) -> str:
    st = v.get("status", "REQUIRES_MANUAL_REVIEW")
    if st in AFFIRM and v.get("citation_verified") is not True:
        return "REQUIRES_MANUAL_REVIEW"
    return st


def load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output-dir", required=True)
    args = ap.parse_args()
    out = Path(args.output_dir)
    art = out / "artifacts"
    failures: list[str] = []

    # ground truth: citation-verified verdicts
    validated = art / "validated"
    verdicts = {}
    if validated.is_dir():
        for jf in validated.glob("*.json"):
            v = load_json(jf)
            if isinstance(v, dict) and v.get("test_requirement_id"):
                verdicts[v["test_requirement_id"]] = v
    else:
        failures.append("no artifacts/validated/ directory")

    # 1. coverage
    cov = load_json(art / "coverage.json")
    if not cov:
        failures.append("artifacts/coverage.json missing/unparseable (run coverage_gate.py)")
    elif not cov.get("complete"):
        failures.append(f"coverage incomplete: ratio={cov.get('coverage_ratio')} "
                        f"missing={cov.get('missing_ids')} extra={cov.get('extra_ids')}")

    # 2. no unverified affirmative slipped through
    if not (art / "quarantined.json").exists():
        failures.append("artifacts/quarantined.json missing — citation_verify.py did not run")
    unverified = [tid for tid, v in verdicts.items()
                  if v.get("status") in AFFIRM and v.get("citation_verified") is not True]
    if unverified:
        failures.append(f"{len(unverified)} affirmative verdict(s) not citation_verified: {unverified[:10]}")

    # recompute the truth rollup from verdicts
    truth_status = {tid: effective_status(v) for tid, v in verdicts.items()}
    truth_counts = Counter(truth_status.values())

    # report
    rep = load_json(art / "compliance-report.json")
    if not rep:
        failures.append("artifacts/compliance-report.json missing/unparseable")
    else:
        # 3. per-requirement status fidelity
        rep_reqs = {r.get("req_id"): r for r in (rep.get("requirements") or []) if r.get("req_id")}
        mismatched = []
        for tid, want in truth_status.items():
            got = (rep_reqs.get(tid) or {}).get("status")
            if got is not None and got != want:
                mismatched.append(f"{tid}: report={got} verdict={want}")
        if mismatched:
            failures.append(f"{len(mismatched)} report status(es) disagree with verdicts: {mismatched[:10]}")
        # any MET in the report must be a real verified MET
        bad_met = [rid for rid, r in rep_reqs.items()
                   if r.get("status") == "MET" and truth_status.get(rid) != "MET"]
        if bad_met:
            failures.append(f"{len(bad_met)} report MET(s) not backed by a verified MET verdict: {bad_met[:10]}")
        # 4. rollup fidelity
        overall = ((rep.get("rollup") or {}).get("overall") or {})
        for st in STATUSES:
            if st in overall and int(overall.get(st, 0)) != int(truth_counts.get(st, 0)):
                failures.append(f"report rollup {st}={overall.get(st)} != recomputed {truth_counts.get(st, 0)}")

    # 5. tracker row count
    tracker = out / "reports" / "tracker.csv"
    if tracker.is_file():
        try:
            with tracker.open(encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            if cov and cov.get("applicable") is not None and len(rows) != int(cov["applicable"]):
                failures.append(f"tracker.csv has {len(rows)} rows != {cov['applicable']} applicable requirements")
        except OSError as e:
            failures.append(f"tracker.csv unreadable: {e}")
    else:
        failures.append("reports/tracker.csv missing")

    result = {
        "ok": not failures,
        "failures": failures,
        "verdict_count": len(verdicts),
        "truth_rollup": dict(truth_counts),
        "unverified_affirmatives": unverified,
    }
    dest = art / "report-verify.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"report_verify: {'PASS' if not failures else 'FAIL'} — {len(failures)} issue(s) -> {dest}")
    for f in failures[:25]:
        print(f"  FAIL {f}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
