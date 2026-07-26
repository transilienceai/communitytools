#!/usr/bin/env python3
"""Tests for tools/report_data_revise.py — incremental report_data.json revision.

Stdlib only (tempfile + subprocess + json + csv). Synthetic, client-neutral
fixtures (F-001-style ids; example.com / example.net / TEST-NET-3 hosts).
Run: python3 tools/test_report_data_revise.py
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "report_data_revise.py")

# Baseline report: 3 findings, narratives that quote the count "3 findings".
BASE_REPORT = {
    "engagement": {"title": "Synthetic External Assessment", "report_id": "SYN-2026-001"},
    "executive_summary": {
        "narrative": ["The assessment confirmed all 3 findings across the estate.",
                      "Overall posture is moderate; see the register below."],
        "key_risks": ["3 findings require remediation attention."],
        "positives": ["No Critical issues were observed."],
    },
    "findings": [
        {"id": "F-1", "title": "SQL injection in login", "severity": "High",
         "cvss_score": 7.5, "affected": ["https://app.example.com/login"]},
        {"id": "F-2", "title": "Missing security headers", "severity": "Low",
         "cvss_score": 3.1, "affected": ["203.0.113.10"]},
        {"id": "F-3", "title": "Verbose error message", "severity": "Info",
         "affected": ["api.example.net"]},
    ],
    "conclusion": {"narrative": ["In total 3 findings were confirmed during the window."]},
}


def make_base(d, name="report_data.json"):
    p = os.path.join(d, name)
    with open(p, "w") as f:
        json.dump(BASE_REPORT, f, indent=2)
    return p


def write_json(d, name, obj):
    p = os.path.join(d, name)
    with open(p, "w") as f:
        json.dump(obj, f)
    return p


def write_text(d, name, text):
    p = os.path.join(d, name)
    with open(p, "w") as f:
        f.write(text)
    return p


def run(args, expect=0):
    proc = subprocess.run([sys.executable, SCRIPT] + args, capture_output=True, text=True)
    assert proc.returncode == expect, \
        f"exit {proc.returncode} (want {expect}); stderr={proc.stderr}; stdout={proc.stdout}"
    return proc


def run_ok(args):
    proc = run(args, expect=0)
    return json.loads(proc.stdout)


def load_out(path):
    with open(path) as f:
        return json.load(f)


def narratives(rep):
    """Flatten every scrubbable narrative string for count assertions."""
    out = []
    es = rep.get("executive_summary", {})
    for k in ("narrative", "key_risks", "positives"):
        out += es.get(k, [])
    out += rep.get("conclusion", {}).get("narrative", [])
    return " || ".join(out)


# --------------------------------------------------------------------------- #
def test_append_adds_and_rederives_metrics_and_cve_register():
    with tempfile.TemporaryDirectory() as d:
        base = make_base(d)
        add = write_json(d, "add.json", [
            {"id": "F-4", "title": "Outdated TLS library", "severity": "Medium",
             "cvss_score": 5.0, "affected": ["203.0.113.10"],
             "cves": [{"id": "CVE-2024-9999", "score": 5.0, "severity": "Medium"}]},
        ])
        out = base + ".revised.json"
        summary = run_ok([base, "--append", add])
        assert summary["findings_before"] == 3 and summary["findings_after"] == 4
        rep = load_out(out)
        assert len(rep["findings"]) == 4
        # metrics re-derived as a list; Medium box now reflects the appended finding.
        assert isinstance(rep["metrics"], list)
        med = next(m for m in rep["metrics"] if m["sev"] == "Medium")
        assert med["value"] == 1, rep["metrics"]
        # cve_register rebuilt from the new finding's CVE.
        assert any(r["cve"] == "CVE-2024-9999" for r in rep["cve_register"]), rep.get("cve_register")


def test_supersede_replaces_by_id_and_adds_new():
    with tempfile.TemporaryDirectory() as d:
        base = make_base(d)
        sup = write_json(d, "sup.json", [
            {"id": "F-1", "title": "SQLi -> full DB read (escalated)", "severity": "Critical",
             "cvss_score": 9.8, "affected": ["https://app.example.com/login"]},
            {"id": "F-9", "title": "New RCE", "severity": "High",
             "cvss_score": 8.1, "affected": ["app.example.com"]},
        ])
        out = base + ".revised.json"
        summary = run_ok([base, "--supersede", sup])
        assert summary["findings_after"] == 4, summary  # F-1 replaced, F-9 added
        rep = load_out(out)
        f1 = next(f for f in rep["findings"] if f["id"] == "F-1")
        assert f1["severity"] == "Critical" and "escalated" in f1["title"]
        assert any(f["id"] == "F-9" for f in rep["findings"])
        # Critical now present -> default_metrics must include a Critical box.
        assert any(m["sev"] == "Critical" for m in rep["metrics"]), rep["metrics"]


def test_rescore_vector_recomputes_band_and_wins_over_bad_csv():
    with tempfile.TemporaryDirectory() as d:
        base = make_base(d)
        # F-2 vector scores 9.8 (Critical); the csv column says "Low" (contradictory).
        csv_text = ("id,severity,cvss_score,cvss_vector,disposition\n"
                    "F-2,Low,,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H,confirmed\n"
                    "F-404,Medium,,,not-present\n")
        disp = write_text(d, "disp.csv", csv_text)
        out = base + ".revised.json"
        summary = run_ok([base, "--rescore", disp])
        rep = load_out(out)
        f2 = next(f for f in rep["findings"] if f["id"] == "F-2")
        assert f2["severity"] == "Critical", f2            # vector band wins over "Low"
        assert f2["cvss_score"] == 9.8, f2
        assert "F-404" in summary["unknown_rescore_ids"], summary
        # the band-over-csv override is recorded.
        ov = summary.get("rescore_band_overrides", [])
        assert any(o["id"] == "F-2" and o["csv_severity"] == "Low"
                   and o["vector_band"] == "Critical" for o in ov), summary


def test_rescore_without_vector_uses_csv_columns():
    with tempfile.TemporaryDirectory() as d:
        base = make_base(d)
        csv_text = ("id,severity,cvss_score\n"
                    "F-3,Medium,5.4\n")
        disp = write_text(d, "disp.csv", csv_text)
        out = base + ".revised.json"
        run_ok([base, "--rescore", disp])
        rep = load_out(out)
        f3 = next(f for f in rep["findings"] if f["id"] == "F-3")
        assert f3["severity"] == "Medium" and f3["cvss_score"] == 5.4, f3


def test_scope_keeps_intersecting_findings_and_renumbers():
    with tempfile.TemporaryDirectory() as d:
        base = make_base(d)
        allow = write_text(d, "allow.txt", "app.example.com\napi.example.net\n")
        out = base + ".revised.json"
        summary = run_ok([base, "--scope", allow])
        # F-2 (203.0.113.10) is out of scope -> dropped; F-1, F-3 kept.
        assert summary["findings_after"] == 2, summary
        rep = load_out(out)
        ids = [f["id"] for f in rep["findings"]]
        assert ids == ["F-001", "F-002"], ids           # renumbered in sort order
        # High (old F-1) sorts before Info (old F-3).
        assert rep["findings"][0]["title"].startswith("SQL injection")
        assert summary["renumbered"] == {"F-1": "F-001", "F-3": "F-002"}, summary["renumbered"]


def test_scope_scrubs_narrative_count_to_new_total():
    with tempfile.TemporaryDirectory() as d:
        base = make_base(d)
        allow = write_text(d, "allow.txt", "app.example.com\n")   # keeps only F-1
        out = base + ".revised.json"
        summary = run_ok([base, "--scope", allow])
        assert summary["findings_after"] == 1, summary
        rep = load_out(out)
        text = narratives(rep)
        # The OLD count is gone everywhere; the new total (1) is present.
        assert "3 findings" not in text and "all 3" not in text, text
        assert "1 finding" in text, text                          # "1 finding" or "1 findings"


def test_cross_feed_tags_merged_from_and_preserves_existing():
    with tempfile.TemporaryDirectory() as d:
        base = make_base(d)
        sibling = write_json(d, "sibling.json", {
            "engagement": {"report_id": "SIB-2026-02"},
            "findings": [
                {"id": "S-1", "title": "Open redirect", "severity": "Low",
                 "affected": ["www.example.org"]},
                {"id": "S-2", "title": "Info leak", "severity": "Info",
                 "affected": ["www.example.org"], "merged_from": "PRE-EXISTING"},
            ],
        })
        out = base + ".revised.json"
        summary = run_ok([base, "--cross-feed", sibling])
        assert summary["findings_after"] == 5, summary
        rep = load_out(out)
        s1 = next(f for f in rep["findings"] if f["id"] == "S-1")
        s2 = next(f for f in rep["findings"] if f["id"] == "S-2")
        assert s1["merged_from"] == "SIB-2026-02", s1     # tagged from sibling engagement id
        assert s2["merged_from"] == "PRE-EXISTING", s2     # pre-existing tag preserved


def test_composed_ops_apply_in_canonical_order():
    """append + rescore + scope together: the appended finding is re-scored, then
    scope filters+renumbers the settled set (order-independent of CLI order)."""
    with tempfile.TemporaryDirectory() as d:
        base = make_base(d)
        add = write_json(d, "add.json", [
            {"id": "F-4", "title": "Reflected XSS", "severity": "Low",
             "affected": ["https://app.example.com/search"]},
        ])
        # Re-score the just-appended F-4 up to High (7.5) via a vector; scope to app host.
        csv_text = ("id,severity,cvss_vector\n"
                    "F-4,Low,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H\n")
        disp = write_text(d, "disp.csv", csv_text)
        allow = write_text(d, "allow.txt", "app.example.com\n")
        out = base + ".revised.json"
        # scope given first on the CLI, but must still run LAST.
        summary = run_ok([base, "--scope", allow, "--rescore", disp, "--append", add])
        rep = load_out(out)
        # Kept: F-1 (app.example.com) + F-4 (app.example.com/search); F-2/F-3 dropped.
        assert summary["findings_after"] == 2, summary
        # F-4 was re-scored to High before renumbering; it now sorts alongside F-1.
        sevs = sorted(f["severity"] for f in rep["findings"])
        assert sevs == ["High", "High"], [(f["id"], f["severity"]) for f in rep["findings"]]
        assert [f["id"] for f in rep["findings"]] == ["F-001", "F-002"]


def test_original_never_mutated_when_out_differs():
    with tempfile.TemporaryDirectory() as d:
        base = make_base(d)
        before = open(base).read()
        add = write_json(d, "add.json", [
            {"id": "F-4", "title": "X", "severity": "Low", "affected": ["app.example.com"]}])
        # default out (input + .revised.json)
        summary = run_ok([base, "--append", add])
        assert summary["out"] == base + ".revised.json"
        assert open(base).read() == before, "input file must be byte-identical (default out)"
        # explicit -o to a different path
        other = os.path.join(d, "elsewhere.json")
        run_ok([base, "--append", add, "-o", other])
        assert open(base).read() == before, "input file must be byte-identical (explicit -o)"
        assert os.path.isfile(other)


def test_explicit_out_equal_to_input_overwrites_in_place():
    with tempfile.TemporaryDirectory() as d:
        base = make_base(d)
        add = write_json(d, "add.json", [
            {"id": "F-4", "title": "X", "severity": "Low", "affected": ["app.example.com"]}])
        summary = run_ok([base, "--append", add, "-o", base])
        assert summary["out"] == os.path.abspath(base)
        rep = load_out(base)                       # input WAS overwritten (explicit)
        assert len(rep["findings"]) == 4


def test_usage_errors_exit_2():
    with tempfile.TemporaryDirectory() as d:
        base = make_base(d)
        # no ops
        run([base], expect=2)
        # missing input
        run([os.path.join(d, "nope.json"), "--append", base], expect=2)
        # unreadable input JSON
        bad = write_text(d, "bad.json", "{not json")
        run([bad, "--append", base], expect=2)
        # missing op file
        run([base, "--append", os.path.join(d, "missing.json")], expect=2)


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
