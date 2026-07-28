#!/usr/bin/env python3
"""Tests for tools/retest_status_build.py — the retest/revalidation generator.

Stdlib only. Function-level tests import the module directly; exit-code tests drive
the CLI via subprocess. Run: python3 tools/test_retest_status_build.py

Client-neutral fixtures only (synthetic F-00x ids, example app names).
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "retest_status_build.py")
sys.path.insert(0, HERE)
import retest_status_build as R                     # noqa: E402
from report_data_shape import require_report_data_shape  # noqa: E402

# One baseline finding per status. Severities are chosen so that status-priority
# must dominate severity in the Baseline-vs-Current sort (Open is Low but must sort
# ahead of the Critical Closed finding).
BASELINE = [
    {"id": "F-001", "title": "Reflected XSS in search", "severity": "Low",
     "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
     "description": "d1", "impact": "i1", "recommendation": "r1"},
    {"id": "F-002", "title": "Broken object-level authorization", "severity": "High",
     "affected": ["/api/orders/{id}"], "description": "d2"},
    {"id": "F-003", "title": "Verbose error stack traces", "severity": "Medium",
     "description": "d3"},
    {"id": "F-004", "title": "Missing security headers", "severity": "High",
     "description": "d4"},
    {"id": "F-005", "title": "SQL injection in login", "severity": "Critical",
     "description": "d5"},
    {"id": "F-006", "title": "Autocomplete enabled on password field", "severity": "Info",
     "description": "d6"},
]

VERDICTS = {
    "F-001": {"status": "Open", "note": "still reflects the payload",
              "retest_evidence": "curl '...q=<svg/onload>' -> reflected"},
    "F-002": {"status": "Partially-Remediated", "note": "authz added on read, not on write"},
    "F-003": {"status": "Needs-Live-Retest", "note": "endpoint unreachable during window"},
    "F-004": {"status": "Risk-Accepted", "note": "accepted by product owner"},
    "F-005": {"status": "Closed", "note": "parameterized; 500 on payload", "current_severity": "Info"},
    "F-006": {"status": "False-Positive", "note": "field is not a credential field"},
}


def _row_by_id(section, fid):
    return next(r for r in section["table"]["rows"] if r[0] == fid)


def test_build_rollup_actionable_and_shape():
    rep = R.build_retest(BASELINE, VERDICTS, {"engagement": {"title": "Example App Retest"}})
    require_report_data_shape(rep)  # must not raise

    # Rollup counts: one of each status, total 6.
    assert rep["retest_rollup"] == {
        "Open": 1, "Partially-Remediated": 1, "Needs-Live-Retest": 1,
        "Risk-Accepted": 1, "Closed": 1, "False-Positive": 1}, rep["retest_rollup"]

    # Summary section rollup table carries every status + a Total row.
    summary = next(s for s in rep["sections"] if s["title"] == "Retest Status Summary")
    assert ["Total", "6"] in summary["table"]["rows"]
    for st in R.RETEST_STATUSES:
        assert [st, "1"] in summary["table"]["rows"], st

    # KPI metrics = per-status counts, coloured, capped at 6.
    assert len(rep["metrics"]) == 6
    labels = {m["label"]: m for m in rep["metrics"]}
    assert set(labels) == set(R.RETEST_STATUSES)
    assert labels["Open"]["value"] == 1 and labels["Open"]["color"] == R.STATUS_COLORS["Open"]

    # ONLY Open / Partially-Remediated / Needs-Live-Retest reach findings[].
    fids = [f["id"] for f in rep["findings"]]
    assert set(fids) == {"F-001", "F-002", "F-003"}, fids
    for gone in ("F-004", "F-005", "F-006"):
        assert gone not in fids, gone

    # findings[] carry the retest status into the body + preserve baseline fields.
    f1 = next(f for f in rep["findings"] if f["id"] == "F-001")
    assert f1["description"].startswith("Retest status: Open.")
    assert "cvss_vector" in f1 and "poc" in f1  # retest_evidence -> a poc step
    # colour hint present.
    assert rep["retest_status_colors"]["Closed"] == "#27ae60"


def test_baseline_vs_current_sorted_by_status_then_severity():
    rep = R.build_retest(BASELINE, VERDICTS, {})
    bvc = next(s for s in rep["sections"] if s["title"] == "Baseline vs Current")
    order = [r[0] for r in bvc["table"]["rows"]]
    # status-priority order: Open, Partially, Needs-Live-Retest, Risk-Accepted, Closed, FP
    assert order == ["F-001", "F-002", "F-003", "F-004", "F-005", "F-006"], order
    # Open finding is Low severity yet sorts FIRST; Critical Closed finding sits at 4 —
    # proving status-priority dominates severity.
    assert _row_by_id(bvc, "F-001")[2] == "Low" and _row_by_id(bvc, "F-001")[3] == "Open"
    assert _row_by_id(bvc, "F-005")[2] == "Critical" and order.index("F-005") == 4
    # header shape.
    assert bvc["table"]["header"] == ["Baseline ID", "Title", "Baseline Severity",
                                      "Retest Status", "Note"]


def test_invalid_status_raises():
    try:
        R.build_retest(BASELINE, {"F-001": {"status": "Fixed"}}, {})
    except R.InvalidRetestStatus:
        return
    raise AssertionError("an out-of-vocabulary status must raise InvalidRetestStatus")


def test_detect_controls_disabled_ssl_marker():
    det = R.detect_controls_disabled("ExampleApp_SSL_Disabled_v3.apk")
    assert det["test_build"] is True
    assert "_ssl_disabled_" in det["markers"]
    assert "pinning" in det["disabled_controls"] and "ssl" in det["disabled_controls"]
    assert det["affected_status_override"] == "Needs-Live-Retest"
    # a clean production filename is NOT a test build.
    assert R.detect_controls_disabled("ExampleApp-release.apk")["test_build"] is False
    # explicit flag form.
    assert R.detect_controls_disabled({"controls_disabled": True})["test_build"] is True


def test_controls_disabled_override_scoped_to_disabled_controls():
    baseline = [
        {"id": "F-001", "title": "SSL pinning not enforced", "severity": "Medium",
         "description": "no pin"},
        {"id": "F-002", "title": "Exported activity without permission", "severity": "Medium",
         "description": "exported"},
    ]
    verdicts = {
        "F-001": {"status": "Closed", "note": "pin added"},   # on a DISABLED control
        "F-002": {"status": "Closed", "note": "permission set"},  # unrelated control
    }
    meta = {"controls_disabled": "ExampleApp_SSL_Disabled_v3.apk"}
    rep = R.build_retest(baseline, verdicts, meta)

    bvc = next(s for s in rep["sections"] if s["title"] == "Baseline vs Current")
    row1, row2 = _row_by_id(bvc, "F-001"), _row_by_id(bvc, "F-002")
    # pinning finding bounced to Needs-Live-Retest with the canonical note...
    assert row1[3] == "Needs-Live-Retest", row1
    assert row1[4] == R.OVERRIDE_NOTE, row1
    # ...and now carried into findings[] as actionable.
    assert "F-001" in [f["id"] for f in rep["findings"]]
    # the unrelated Closed finding is NOT overridden.
    assert row2[3] == "Closed", row2
    assert "F-002" not in [f["id"] for f in rep["findings"]]
    assert rep["retest_rollup"]["Needs-Live-Retest"] == 1
    assert rep["retest_rollup"]["Closed"] == 1


def test_portfolio_rollup_matrix():
    doc_a = R.build_retest(
        [{"id": "A-1", "title": "t", "severity": "High"},
         {"id": "A-2", "title": "t", "severity": "Low"}],
        {"A-1": {"status": "Open"}, "A-2": {"status": "Closed"}},
        {"engagement": {"title": "App A"}})
    doc_b = R.build_retest(
        [{"id": "B-1", "title": "t", "severity": "Medium"}],
        {"B-1": {"status": "Closed"}},
        {"engagement": {"title": "App B"}})

    port = R.portfolio_rollup([doc_a, doc_b], {"engagement": {"title": "Portfolio"}})
    require_report_data_shape(port)
    matrix = next(s for s in port["sections"] if s["title"] == "Portfolio Retest Matrix")
    rows = matrix["table"]["rows"]
    labels = [r[0] for r in rows]
    assert labels == ["App A", "App B", "Overall"], labels

    # overall: 1 Open, 2 Closed across both engagements.
    assert port["retest_rollup"]["Open"] == 1 and port["retest_rollup"]["Closed"] == 2
    open_col = matrix["table"]["header"].index("Open")
    total_col = len(matrix["table"]["header"]) - 1
    overall = next(r for r in rows if r[0] == "Overall")
    assert overall[open_col] == "1" and overall[total_col] == "3"
    # per-engagement totals.
    assert next(r for r in rows if r[0] == "App A")[total_col] == "2"
    assert next(r for r in rows if r[0] == "App B")[total_col] == "1"


# ---- CLI exit-code tests ----------------------------------------------------

def _run(args):
    return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)


def test_cli_happy_path_exit0():
    with tempfile.TemporaryDirectory() as d:
        bpath = os.path.join(d, "baseline.json")
        vpath = os.path.join(d, "verdicts.json")
        opath = os.path.join(d, "out.json")
        with open(bpath, "w") as f:
            json.dump(BASELINE, f)
        with open(vpath, "w") as f:
            json.dump(VERDICTS, f)
        proc = _run(["--baseline", bpath, "--verdicts", vpath, "-o", opath])
        assert proc.returncode == 0, proc.stderr
        summary = json.loads(proc.stdout)
        assert summary["findings"] == 3, summary
        with open(opath) as f:
            require_report_data_shape(json.load(f))


def test_cli_invalid_status_exit1():
    with tempfile.TemporaryDirectory() as d:
        bpath = os.path.join(d, "baseline.json")
        vpath = os.path.join(d, "verdicts.json")
        with open(bpath, "w") as f:
            json.dump(BASELINE, f)
        with open(vpath, "w") as f:
            json.dump({"F-001": {"status": "Remediated?"}}, f)
        proc = _run(["--baseline", bpath, "--verdicts", vpath])
        assert proc.returncode == 1, (proc.returncode, proc.stderr)


def test_cli_usage_exit2():
    # missing required args
    assert _run(["--baseline", "x.json"]).returncode == 2
    # mutually exclusive
    assert _run(["--portfolio", "p.json", "--baseline", "b.json"]).returncode == 2


def test_cli_portfolio_exit0():
    with tempfile.TemporaryDirectory() as d:
        doc = R.build_retest([{"id": "A-1", "title": "t", "severity": "High"}],
                             {"A-1": {"status": "Open"}}, {"engagement": {"title": "App A"}})
        ppath = os.path.join(d, "portfolio.json")
        opath = os.path.join(d, "out.json")
        with open(ppath, "w") as f:
            json.dump([doc, doc], f)
        proc = _run(["--portfolio", ppath, "-o", opath])
        assert proc.returncode == 0, proc.stderr
        with open(opath) as f:
            port = json.load(f)
        assert port["retest_rollup"]["Open"] == 2


def test_severity_cross_tab_reports_critical_high_closure():
    """The status rollup answers "how many closed", not "were the ones that
    mattered closed" — which is what a re-validation is contracted to confirm."""
    base = [{"id": "F-001", "title": "RCE", "severity": "Critical"},
            {"id": "F-002", "title": "SQLi", "severity": "High"},
            {"id": "F-003", "title": "XSS", "severity": "High"},
            {"id": "F-004", "title": "Header", "severity": "Low"}]
    verd = {"F-001": {"status": "Closed"}, "F-002": {"status": "Open"},
            "F-003": {"status": "Risk-Accepted"}, "F-004": {"status": "Closed"}}
    doc = R.build_retest(base, verd, {})
    sec = [s for s in doc["sections"] if s["title"] == "Closure by Severity"]
    assert sec, "the severity cross-tab section must be emitted"
    sec = sec[0]
    # Risk-Accepted counts as closed: the client owns it deliberately.
    assert "Critical/High closed: 2 of 3" in sec["paragraphs"][0], sec["paragraphs"][0]
    assert "1 remain unresolved" in sec["paragraphs"][0]
    assert sec["table"]["header"][0] == "Retest Status"
    assert "Critical" in sec["table"]["header"] and "High" in sec["table"]["header"]
    totals = [r for r in sec["table"]["rows"] if r[0] == "Total"][0]
    assert totals[-1] == "4", totals


def test_severity_cross_tab_handles_a_baseline_with_no_high_findings():
    doc = R.build_retest([{"id": "F-1", "title": "x", "severity": "Low"}],
                         {"F-1": {"status": "Closed"}}, {})
    sec = [s for s in doc["sections"] if s["title"] == "Closure by Severity"][0]
    assert "No Critical or High findings" in sec["paragraphs"][0]


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
