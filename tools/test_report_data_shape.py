#!/usr/bin/env python3
"""Tests for tools/report_data_shape.py. Stdlib only; imports the module directly
(no reportlab). Run: python3 tools/test_report_data_shape.py

Client-neutral: the fixtures use a synthetic engagement + synthetic findings.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report_data_shape as rds


def _valid_doc():
    """A minimal doc that satisfies every crash-invariant."""
    return {
        "engagement": {"title": "Synthetic Assessment"},
        "executive_summary": {
            "narrative": ["Para one.", "Para two."],
            "key_risks": ["Risk A"],
            "positives": ["Positive A"],
        },
        "sections": [{"title": "Scope", "paragraphs": ["In scope: the lab app."]}],
        "conclusion": {"narrative": ["Closing remarks."]},
        "findings": [
            {"id": "F-01", "title": "Example finding", "severity": "High"},
        ],
    }


def _expect_valueerror(fn, needle=None):
    try:
        fn()
    except ValueError as e:
        if needle is not None:
            assert needle in str(e), "message %r missing %r" % (str(e), needle)
        return
    raise AssertionError("expected ValueError, none raised")


def test_valid_minimal_doc_does_not_raise():
    rds.require_report_data_shape(_valid_doc())  # must not raise


def test_not_a_dict_raises():
    _expect_valueerror(lambda: rds.require_report_data_shape(["not", "a", "dict"]))


def test_missing_findings_raises():
    d = _valid_doc()
    del d["findings"]
    _expect_valueerror(lambda: rds.require_report_data_shape(d), "findings")


def test_missing_engagement_raises():
    d = _valid_doc()
    del d["engagement"]
    _expect_valueerror(lambda: rds.require_report_data_shape(d), "engagement")


def test_string_narrative_raises():
    d = _valid_doc()
    d["executive_summary"]["narrative"] = "one big string"
    _expect_valueerror(lambda: rds.require_report_data_shape(d), "narrative")


def test_string_section_paragraphs_raises():
    d = _valid_doc()
    d["sections"][0]["paragraphs"] = "a single paragraph as a string"
    _expect_valueerror(lambda: rds.require_report_data_shape(d), "paragraphs")


def test_string_conclusion_narrative_raises():
    d = _valid_doc()
    d["conclusion"]["narrative"] = "closing string"
    _expect_valueerror(lambda: rds.require_report_data_shape(d), "conclusion.narrative")


def test_bad_severity_raises():
    d = _valid_doc()
    d["findings"][0]["severity"] = "Catastrophic"
    _expect_valueerror(lambda: rds.require_report_data_shape(d), "severity")


def test_finding_missing_title_raises():
    d = _valid_doc()
    del d["findings"][0]["title"]
    _expect_valueerror(lambda: rds.require_report_data_shape(d), "title")


def test_metrics_not_a_list_raises():
    d = _valid_doc()
    d["metrics"] = {"label": "X"}
    _expect_valueerror(lambda: rds.require_report_data_shape(d), "metrics")


def test_poc_not_a_list_raises():
    d = _valid_doc()
    d["findings"][0]["poc"] = "step one"
    _expect_valueerror(lambda: rds.require_report_data_shape(d), "poc")


def test_absent_optional_raw_fields_ok():
    # A doc with only the required keys must pass (RAW fields are all optional).
    rds.require_report_data_shape({
        "engagement": {}, "findings": [
            {"id": "F-01", "title": "t", "severity": "Info"}]})


def test_default_metrics_includes_critical_when_present():
    findings = [
        {"id": "F-01", "title": "t", "severity": "Critical"},
        {"id": "F-02", "title": "t", "severity": "High"},
        {"id": "F-03", "title": "t", "severity": "Low"},
    ]
    metrics = rds.default_metrics(findings)
    sevs = {m["sev"] for m in metrics}
    assert "Critical" in sevs, metrics
    crit = next(m for m in metrics if m["sev"] == "Critical")
    assert crit["value"] == 1 and crit["label"] == "CRITICAL", crit
    assert len(metrics) <= 6, metrics


def test_default_metrics_omits_critical_when_none():
    findings = [
        {"id": "F-01", "title": "t", "severity": "High"},
        {"id": "F-02", "title": "t", "severity": "Medium"},
    ]
    metrics = rds.default_metrics(findings)
    assert all(m["sev"] != "Critical" for m in metrics), metrics
    assert len(metrics) <= 6, metrics
    high = next(m for m in metrics if m["sev"] == "High")
    assert high["value"] == 1, high


def test_default_metrics_capped_at_six():
    # Even with every band populated, never exceed 6 boxes.
    findings = [{"id": "F", "title": "t", "severity": s}
                for s in rds.SEVERITIES]
    assert len(rds.default_metrics(findings)) <= 6


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print("PASS %s" % t.__name__)
        except Exception as e:
            failed += 1
            print("FAIL %s: %s: %s" % (t.__name__, type(e).__name__, e))
    print("\n%d/%d passed" % (len(tests) - failed, len(tests)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
