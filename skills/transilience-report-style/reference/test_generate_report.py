#!/usr/bin/env python3
"""Render-smoke for the source_ips appendix + findings score/label rendering.
Builds a PDF from report_data that includes a source_ips table (with an
HTML-special char to exercise esc), a count-style tools_used table, and findings
that exercise the always-show-both rule: one WITH a cvss_score and one WITHOUT
(so the 'n/a' branch and the severity-label default are covered). Asserts a
non-empty PDF is produced with no exception, and unit-checks cvss_display().
Skips cleanly if reportlab is unavailable.
Run: python3 skills/transilience-report-style/reference/test_generate_report.py
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GEN = os.path.join(HERE, "generate_report.py")


def main():
    try:
        import reportlab  # noqa: F401
    except Exception:
        print("SKIP: reportlab not installed")
        return 0

    sys.path.insert(0, HERE)
    from generate_report import cvss_display
    # cvss_display: numeric score renders as-is; absent -> 'n/a' (never blank).
    assert cvss_display(8.1) == "8.1", cvss_display(8.1)
    assert cvss_display(0) == "0", cvss_display(0)
    assert cvss_display(None) == "n/a", cvss_display(None)
    assert cvss_display("") == "n/a", repr(cvss_display(""))
    print("PASS: cvss_display() pairs a score (or n/a) with every finding")

    data = {
        "engagement": {
            "title": "Test Report", "client": "Acme", "report_id": "R-1",
            "date": "2026", "version": "1.0", "classification": "CONFIDENTIAL",
        },
        # F-1 has a CVSS score; F-2 has none -> must still render label + 'n/a'.
        # F-1 also exercises the new poc[] renderer: prose description, code-styled
        # command, and an image_url that is NOT available (must skip, not error).
        "findings": [
            {"id": "F-1", "title": "Scored finding", "severity": "High",
             "cvss_score": 8.1, "description": "has a score",
             "poc": [
                 {"description": "Open a terminal on the tester host.",
                  "command": "curl -s https://target.example/x -H 'Authorization: Bearer <t>'"},
                 {"description": "The response returns the secret — proving the issue.",
                  "image_url": "/nonexistent/does-not-exist.png"},
             ]},
            {"id": "F-2", "title": "Unscored finding", "severity": "Low",
             "description": "no cvss_score -> renders CVSS n/a with its label"},
        ],
        "tools_used": [["nmap", "Port & service enumeration", "invoked 12×"]],
        "source_ips_intro": "Origins of all testing traffic.",
        "source_ips": [
            ["203.0.113.9", "primary-runner", ""],
            ["198.51.100.4 <b>", "attack-vm", "gcp/asia-south1"],  # exercises esc()
        ],
        # exercises every statuscol arm (covered / covered_negative / pending)
        "attack_pattern_coverage": {
            "header": ["Attack class", "Taxonomy", "Description", "Cells", "Status"],
            "rows": [
                ["API1-BOLA", "API-2023", "Broken Object Level Authorization", "3/3", "covered"],
                ["API8-MISCONFIG", "API-2023", "Security misconfiguration", "1/1", "covered_negative"],
                ["XC-TLS-POSTURE", "Cross-cut", "TLS posture", "0/2", "pending"],
            ],
            "widths": [0.20, 0.12, 0.40, 0.12, 0.16],
            "note": "Deterministic coverage: 67% of applicable cells covered — 1 cell(s) untested.",
        },
    }
    failed = 0
    with tempfile.TemporaryDirectory() as d:
        dj = os.path.join(d, "report_data.json")
        out = os.path.join(d, "out.pdf")
        with open(dj, "w") as f:
            json.dump(data, f)
        p = subprocess.run([sys.executable, GEN, dj, "-o", out],
                           capture_output=True, text=True)
        if p.returncode != 0:
            print(f"FAIL: generator exit {p.returncode}: {p.stderr.strip()}")
            failed = 1
        elif not (os.path.isfile(out) and os.path.getsize(out) > 0):
            print("FAIL: PDF not produced or empty")
            failed = 1
        else:
            print(f"PASS: source_ips appendix renders ({os.path.getsize(out)} bytes)")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
