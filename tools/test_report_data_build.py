#!/usr/bin/env python3
"""Tests for tools/report_data_build.py drop-entirely policy + idempotency.

Stdlib only (tempfile + subprocess + json). Run: python3 tools/test_report_data_build.py
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "report_data_build.py")

# (id, verdict, severity, risk_score). Fa/Fb are equal-severity+equal-risk to
# exercise the id tiebreak; Fd/Fe are the hard-dropped (non VALID/REPAIRED) cases.
FINDINGS = [
    ("Fc", "VALID", "Critical", 0.9),
    ("Fa", "VALID", "High", 0.5),
    ("Fb", "REPAIRED", "High", 0.5),
    ("Fd", "DEMOTED", "Medium", 0.3),
    ("Fe", "MAYBE", "Low", 0.1),
]


def _record(fid, verdict, severity, risk):
    return {
        "finding_id": fid,
        "verdict": verdict,
        "severity": severity,
        "risk": {"risk_score": risk},
        "report_fields": {"title": f"{fid} title", "description": "d",
                          "impact": "i", "recommendation": "r"},
    }


def build_engagement(base, name_fn):
    """Write the fixtures under <base>/asset1/artifacts/validated/, naming each file
    via name_fn(index, fid) so the on-disk (sorted-glob) order can be shuffled."""
    vdir = os.path.join(base, "asset1", "artifacts", "validated")
    os.makedirs(vdir, exist_ok=True)
    for i, (fid, verdict, sev, risk) in enumerate(FINDINGS):
        with open(os.path.join(vdir, name_fn(i, fid)), "w") as f:
            json.dump(_record(fid, verdict, sev, risk), f)
    return base


def run_build(base):
    proc = subprocess.run(
        [sys.executable, SCRIPT, "--engagement-dir", base],
        capture_output=True, text=True)
    assert proc.returncode == 0, f"exit {proc.returncode}; stderr={proc.stderr}"
    summary = json.loads(proc.stdout)
    return summary, proc.stderr


def test_findings_are_valid_and_repaired_only():
    with tempfile.TemporaryDirectory() as d:
        build_engagement(d, lambda i, fid: f"{fid}.json")
        summary, _ = run_build(d)
        # Critical first; then the two equal High findings by id-tiebreak Fa<Fb.
        assert summary["finding_ids"] == ["Fc", "Fa", "Fb"], summary["finding_ids"]
        assert summary["findings"] == 3


def test_demoted_and_unknown_are_hard_dropped():
    with tempfile.TemporaryDirectory() as d:
        build_engagement(d, lambda i, fid: f"{fid}.json")
        summary, stderr = run_build(d)
        dropped = {row["finding_id"]: row["verdict"] for row in summary["hard_dropped"]}
        assert dropped == {"Fd": "DEMOTED", "Fe": "MAYBE"}, dropped
        # Also logged to stderr, never into the payload.
        assert "HARD-DROP" in stderr
        for tok in ("Fd", "Fe", "DEMOTED", "MAYBE"):
            assert tok in stderr, f"missing {tok!r} in stderr"
        assert "demoted" not in summary, "dead 'demoted' summary key must be gone"


def test_no_assurance_gaps_and_no_timestamp_in_payload():
    with tempfile.TemporaryDirectory() as d:
        build_engagement(d, lambda i, fid: f"{fid}.json")
        run_build(d)
        payload = open(os.path.join(d, "reports", "report_data.json")).read()
        assert "Assurance" not in payload, "no gaps section may appear"
        assert "needs_live_confirmation" not in payload
        low = payload.lower()
        for tok in ("timestamp", "generated_at", "\"date\""):
            assert tok not in low, f"payload must be clockless: found {tok!r}"


def test_idempotent_and_order_independent_sha():
    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
        build_engagement(d1, lambda i, fid: f"{fid}.json")
        # Same content, filenames that sort in reverse => shuffled on-disk order.
        build_engagement(d2, lambda i, fid: f"z{len(FINDINGS) - i:02d}_{fid}.json")
        s1a, _ = run_build(d1)
        s1b, _ = run_build(d1)          # rerun -> identical sha
        s2, _ = run_build(d2)           # shuffled order -> identical sha
        assert s1a["sha256"] == s1b["sha256"], "rerun must be idempotent"
        assert s1a["sha256"] == s2["sha256"], "on-disk order must not affect the sha"


# ---- activity-log folding (tool-usage + source-IP appendices) ---------------

def write_activity(base, invocations, source_ips):
    act = os.path.join(base, "logs", "activity")
    os.makedirs(act, exist_ok=True)
    with open(os.path.join(act, "tool-invocations.jsonl"), "w") as f:
        for r in invocations:
            f.write(json.dumps(r) + "\n")
    with open(os.path.join(act, "source-ips.jsonl"), "w") as f:
        for r in source_ips:
            f.write(json.dumps(r) + "\n")


def _load_report(base):
    with open(os.path.join(base, "reports", "report_data.json")) as f:
        return json.load(f)


def test_activity_tools_and_source_ips_folded():
    with tempfile.TemporaryDirectory() as d:
        build_engagement(d, lambda i, fid: f"{fid}.json")
        inv = [
            {"bins": ["nmap"], "full_command": "nmap -sV h"},
            {"bins": ["nmap"], "full_command": "nmap -p- h"},
            {"bins": ["sqlmap"], "full_command": "sqlmap -u x"},
            {"bins": ["date"], "full_command": "date"},                    # denylist
            {"bins": ["report_data_build.py"], "full_command": "python3 x"},  # denylist
        ]
        sips = [
            {"ip": "203.0.113.9", "role": "primary-runner", "provider": "", "region": ""},
            {"ip": "203.0.113.9", "role": "primary-runner", "provider": "", "region": ""},  # dup
            {"ip": "198.51.100.4", "role": "attack-vm", "provider": "gcp", "region": "asia-south1"},
        ]
        write_activity(d, inv, sips)
        summary, _ = run_build(d)
        rep = _load_report(d)
        tools = {r[0]: r for r in rep["tools_used"]}
        assert set(tools) == {"nmap", "sqlmap"}, tools
        assert tools["nmap"][2] == "invoked 2×", tools["nmap"]
        assert rep["source_ips"] == [
            ["198.51.100.4", "attack-vm", "gcp/asia-south1"],
            ["203.0.113.9", "primary-runner", ""],
        ], rep["source_ips"]
        assert summary["tools_used_count"] == 2 and summary["source_ips_count"] == 2
        low = open(os.path.join(d, "reports", "report_data.json")).read().lower()
        for tok in ("timestamp", "generated_at", '"ts"', "first_seen", "last_seen"):
            assert tok not in low, f"payload must be clockless: found {tok!r}"


def test_reconciliation_gap_and_clear():
    with tempfile.TemporaryDirectory() as d:
        build_engagement(d, lambda i, fid: f"{fid}.json")
        inv = [{"bins": ["gcloud"], "full_command": "gcloud compute instances create vm --zone z"}]
        sips = [{"ip": "203.0.113.9", "role": "primary-runner", "provider": "", "region": ""}]
        write_activity(d, inv, sips)
        summary, _ = run_build(d)
        assert summary["reconciliation_gaps"], "egress cmd + only primary IP must flag a gap"
        rep = _load_report(d)
        assert "Egress-reconciliation gaps" in rep.get("source_ips_intro", "")
        sips.append({"ip": "198.51.100.4", "role": "attack-vm", "provider": "gcp", "region": "z"})
        write_activity(d, inv, sips)
        summary2, _ = run_build(d)
        assert summary2["reconciliation_gaps"] == [], summary2["reconciliation_gaps"]


def test_malformed_line_skipped_and_idempotent():
    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
        for d in (d1, d2):
            build_engagement(d, lambda i, fid: f"{fid}.json")
        sip = {"ip": "203.0.113.9", "role": "primary-runner", "provider": "", "region": ""}
        write_activity(d1, [{"bins": ["nmap"], "full_command": "nmap h"}], [sip])
        act = os.path.join(d2, "logs", "activity")
        os.makedirs(act, exist_ok=True)
        with open(os.path.join(act, "tool-invocations.jsonl"), "w") as f:
            f.write('{"bins": ["nmap"], "full_comm\n')                       # truncated
            f.write(json.dumps({"bins": ["nmap"], "full_command": "nmap h"}) + "\n")
        with open(os.path.join(act, "source-ips.jsonl"), "w") as f:
            f.write(json.dumps(sip) + "\n")
        s1, _ = run_build(d1)
        s2, _ = run_build(d2)
        assert s1["sha256"] == s2["sha256"], "malformed line must be skipped -> same sha"


def test_meta_passthrough_when_no_logs():
    with tempfile.TemporaryDirectory() as d:
        build_engagement(d, lambda i, fid: f"{fid}.json")
        with open(os.path.join(d, "engagement-meta.json"), "w") as f:
            json.dump({"source_ips": [["1.2.3.4", "primary-runner", ""]],
                       "source_ips_intro": "hand authored",
                       "tools_used": [["burp", "proxy", "used"]]}, f)
        run_build(d)
        rep = _load_report(d)
        assert rep["source_ips"] == [["1.2.3.4", "primary-runner", ""]]
        assert rep["source_ips_intro"] == "hand authored"
        assert rep["tools_used"] == [["burp", "proxy", "used"]]


def _write_matrix(base, matrix):
    rdir = os.path.join(base, "reports")
    os.makedirs(rdir, exist_ok=True)
    with open(os.path.join(rdir, "coverage-matrix.json"), "w") as f:
        json.dump(matrix, f)


def test_attack_pattern_coverage_derived_from_matrix():
    with tempfile.TemporaryDirectory() as d:
        build_engagement(d, lambda i, fid: f"{fid}.json")
        _write_matrix(d, {
            "coverage_ratio": 0.5,
            "missing_cells": [{"class_id": "API1-BOLA", "scope_key": "u1", "asset_tag": "a", "reason": "no_ledger_entry"}],
            "per_class": {
                "API8-MISCONFIG": {"taxonomy": "API-2023", "title": "Security misconfiguration", "applicable": 1, "passed": 1, "status": "covered_negative"},
                "API1-BOLA": {"taxonomy": "API-2023", "title": "BOLA", "applicable": 2, "passed": 1, "status": "pending"},
            },
        })
        run_build(d)
        apc = _load_report(d)["attack_pattern_coverage"]
        assert apc["header"][0] == "Attack class" and len(apc["rows"]) == 2
        # sorted by taxonomy then class_id -> API1-BOLA precedes API8-MISCONFIG
        assert apc["rows"][0][0] == "API1-BOLA" and apc["rows"][0][4] == "pending"
        assert "50%" in apc["note"] and "1 cell" in apc["note"]


def test_attack_pattern_coverage_absent_when_no_matrix():
    with tempfile.TemporaryDirectory() as d:
        build_engagement(d, lambda i, fid: f"{fid}.json")
        run_build(d)
        assert "attack_pattern_coverage" not in _load_report(d), "no matrix -> key omitted"


def test_no_logs_no_appendix_keys():
    with tempfile.TemporaryDirectory() as d:
        build_engagement(d, lambda i, fid: f"{fid}.json")
        summary, _ = run_build(d)
        rep = _load_report(d)
        assert "source_ips" not in rep and "tools_used" not in rep
        assert summary["tools_used_count"] == 0 and summary["source_ips_count"] == 0
        assert summary["reconciliation_gaps"] == []


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except Exception as e:
            failed += 1
            print(f"FAIL {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
