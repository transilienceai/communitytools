#!/usr/bin/env python3
"""Tests for tools/report_data_lint.py. Stdlib only (tempfile + subprocess + json).
Run: python3 tools/test_report_data_lint.py

Client-neutral: synthetic engagement + synthetic findings only.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "report_data_lint.py")


def _valid_doc():
    return {
        "engagement": {"title": "Synthetic Assessment"},
        "executive_summary": {
            "narrative": ["A clean paragraph with a safe <b>bold</b> span."],
            "key_risks": ["A risk with an &amp; entity and a <font color=\"#c00\">tag</font>."],
            "positives": ["Controls held."],
        },
        "sections": [{"title": "Scope", "paragraphs": ["In scope: the lab app."]}],
        "conclusion": {"narrative": ["Closing remarks."]},
        "findings": [
            {"id": "F-01", "title": "Reflected input handling", "severity": "High",
             "description": "d", "impact": "i", "recommendation": "r"},
        ],
    }


def _run(doc_or_text, *args):
    """Write doc/text to a temp file, run the linter, return (rc, parsed_json_or_None)."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "report_data.json")
        with open(path, "w") as f:
            if isinstance(doc_or_text, str):
                f.write(doc_or_text)
            else:
                json.dump(doc_or_text, f)
        proc = subprocess.run(
            [sys.executable, SCRIPT, path, *args],
            capture_output=True, text=True)
        out = None
        try:
            out = json.loads(proc.stdout)
        except ValueError:
            pass
        return proc.returncode, out


def test_valid_doc_exit_0():
    rc, out = _run(_valid_doc())
    assert rc == 0, (rc, out)
    assert out["ok"] is True and out["errors"] == [], out


def test_string_narrative_exit_1():
    d = _valid_doc()
    d["executive_summary"]["narrative"] = "one big string"
    rc, out = _run(d)
    assert rc == 1 and out["ok"] is False, (rc, out)
    assert any("narrative" in e for e in out["errors"]), out


def test_bad_severity_exit_1():
    d = _valid_doc()
    d["findings"][0]["severity"] = "Catastrophic"
    rc, out = _run(d)
    assert rc == 1 and any("severity" in e for e in out["errors"]), (rc, out)


def test_bare_ampersand_in_narrative_exit_1():
    d = _valid_doc()
    d["executive_summary"]["narrative"] = ["Rock & roll breaks the parser."]
    rc, out = _run(d)
    assert rc == 1 and any("bare '&'" in e for e in out["errors"]), (rc, out)


def test_valid_entity_in_narrative_ok():
    d = _valid_doc()
    d["executive_summary"]["narrative"] = ["Rock &amp; roll &#8212; fine &lt;here&gt;."]
    rc, out = _run(d)
    assert rc == 0 and out["errors"] == [], (rc, out)


def test_unbalanced_angle_in_narrative_exit_1():
    d = _valid_doc()
    d["sections"][0]["paragraphs"] = ["An unterminated <b tag here."]
    rc, out = _run(d)
    assert rc == 1 and any("unbalanced" in e for e in out["errors"]), (rc, out)


def test_img_tag_in_narrative_exit_1_security():
    d = _valid_doc()
    d["executive_summary"]["narrative"] = ["Look <img src=x onerror=alert(1)> here."]
    rc, out = _run(d)
    assert rc == 1 and any("img" in e and "allowlist" in e for e in out["errors"]), (rc, out)


def test_anchor_tag_in_narrative_exit_1_security():
    d = _valid_doc()
    d["conclusion"]["narrative"] = ['Click <a href="http://evil.example">here</a>.']
    rc, out = _run(d)
    assert rc == 1 and any(e.startswith("conclusion.narrative") and "allowlist" in e
                           for e in out["errors"]), (rc, out)


def test_allowlisted_tags_in_narrative_ok():
    d = _valid_doc()
    d["executive_summary"]["narrative"] = [
        "Mixed <b>bold</b> <i>italic</i> <u>u</u> <em>em</em> "
        "<strong>s</strong> line<br/> <font color=\"#111\">x</font>."]
    rc, out = _run(d)
    assert rc == 0 and out["errors"] == [], (rc, out)


def test_preescaped_entity_in_finding_title_warns_then_fails_strict():
    d = _valid_doc()
    d["findings"][0]["title"] = "Race &amp; TOCTOU in checkout"
    # default: warning, exit 0
    rc, out = _run(d)
    assert rc == 0 and out["ok"] is True, (rc, out)
    assert any("double-escaped" in w for w in out["warnings"]), out
    # --strict: the same warning becomes a hard failure
    rc2, out2 = _run(d, "--strict")
    assert rc2 == 1 and out2["ok"] is False, (rc2, out2)


def test_critical_without_metrics_warns_exit_0():
    d = _valid_doc()
    d["findings"][0]["severity"] = "Critical"
    rc, out = _run(d)
    assert rc == 0, (rc, out)
    assert any("metrics" in w for w in out["warnings"]), out


def test_critical_with_metrics_no_warning():
    d = _valid_doc()
    d["findings"][0]["severity"] = "Critical"
    d["metrics"] = [{"label": "CRITICAL", "value": 1, "sev": "Critical"}]
    rc, out = _run(d)
    assert rc == 0 and not any("metrics" in w for w in out["warnings"]), (rc, out)


def test_malformed_json_exit_2():
    rc, out = _run('{"engagement": {}, "findings": [ ')  # truncated
    assert rc == 2, (rc, out)
    assert out is not None and out["ok"] is False, out


def test_missing_path_usage_exit_2():
    proc = subprocess.run([sys.executable, SCRIPT], capture_output=True, text=True)
    assert proc.returncode == 2, proc.returncode


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
