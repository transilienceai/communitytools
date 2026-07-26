#!/usr/bin/env python3
"""Tests for tools/report_ingest.py — the canonical report_data ingestor.

Run: python3 tools/test_report_ingest.py   (or via pytest)
Stdlib unittest. Deterministic parity is asserted on the reliably-testable
formats (json / xlsx / markdown); pdf/docx are exercised only when their optional
dependency is importable, else skipped-with-note.

Client-neutral: synthetic engagement, F-001 ids, *.example.test hosts.
"""
import contextlib
import io
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import report_ingest as RI

try:
    import openpyxl  # noqa: F401
    import report_xlsx_build as RX
    HAVE_OPENPYXL = True
except ImportError:
    HAVE_OPENPYXL = False

try:
    import docx  # noqa: F401
    HAVE_DOCX = True
except ImportError:
    HAVE_DOCX = False


# Canonical report_data with a spread of severities/CVSS/CWE for round-tripping.
REPORT_DATA = {
    "engagement": {"title": "External Penetration Test", "target": "Example Corp",
                   "sector": "SaaS", "date": "2026-07-23", "report_id": "ING-001",
                   "method": "OWASP / PTES", "classification": "Confidential"},
    "findings": [
        {"id": "F-001", "title": "SQL Injection", "severity": "High",
         "cvss_score": 8.1,
         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "cwe": "CWE-89", "owasp": "A03:2021",
         "affected": ["api.example.test"],
         "description": "Union-based injection.", "impact": "DB read.",
         "recommendation": "Parameterize.", "needs_live_confirmation": False},
        {"id": "F-002", "title": "Reflected XSS", "severity": "Medium",
         "cvss_score": 6.1, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
         "cwe": "CWE-79", "affected": ["www.example.test"],
         "needs_live_confirmation": True},
        {"id": "F-003", "title": "Verbose Error Message", "severity": "Info",
         "cvss_score": None, "cwe": "CWE-200", "affected": ["10.0.0.5"]},
    ],
}


def _by_id(findings):
    return {f["id"]: f for f in findings}


def _projection(f):
    """The subset asserted for parity across formats."""
    return (f.get("severity"), f.get("cvss_score"), f.get("cwe"),
            tuple(f.get("affected") or []))


class TestJson(unittest.TestCase):
    def test_json_passthrough_identical_findings(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "report_data.json")
            with open(p, "w", encoding="utf-8") as fh:
                import json
                json.dump(REPORT_DATA, fh)
            result, code = RI.ingest(p)
            self.assertEqual(code, RI.EXIT_OK)
            self.assertEqual(result["ingest"]["format"], "json")
            # passthrough copies findings verbatim
            self.assertEqual(result["findings"], REPORT_DATA["findings"])
            self.assertEqual(result["engagement"]["target"], "Example Corp")

    def test_non_null_guard_warns_on_missing_cwe_and_vector(self):
        data = {"engagement": {"title": "T"},
                "findings": [{"id": "F-009", "title": "No classification",
                              "severity": "Low"}]}  # no cwe, no cvss_vector
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.json")
            with open(p, "w", encoding="utf-8") as fh:
                import json
                json.dump(data, fh)
            result, code = RI.ingest(p)
            warns = result["ingest"]["warnings"]
            self.assertTrue(any("F-009" in w and "cwe" in w for w in warns), warns)
            self.assertTrue(any("F-009" in w and "cvss_vector" in w for w in warns), warns)

    def test_unreadable_source_exit_2(self):
        # nonexistent path
        result, code = RI.ingest(os.path.join(tempfile.gettempdir(), "no-such-x.json"))
        self.assertIsNone(result)
        self.assertEqual(code, RI.EXIT_USAGE)
        # malformed json -> exit 2 too
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.json")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("{ this is not json ]")
            _, code2 = RI.ingest(p)
            self.assertEqual(code2, RI.EXIT_USAGE)

    def test_main_returns_2_on_missing_file(self):
        with contextlib.redirect_stderr(io.StringIO()):
            rc = RI.main([os.path.join(tempfile.gettempdir(), "definitely-missing.json")])
        self.assertEqual(rc, RI.EXIT_USAGE)


@unittest.skipUnless(HAVE_OPENPYXL, "openpyxl not installed")
class TestXlsxRoundTrip(unittest.TestCase):
    def test_xlsx_is_faithful_inverse_of_report_xlsx_build(self):
        ov = {"target": None, "title": None, "location": None, "date": None}
        wb, n = RX.build_workbook(REPORT_DATA, ov)
        self.assertEqual(n, 3)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "register.xlsx")
            wb.save(p)
            result, code = RI.ingest(p)
        self.assertEqual(code, RI.EXIT_OK)
        self.assertEqual(result["ingest"]["format"], "xlsx")
        got = _by_id(result["findings"])
        want = _by_id(REPORT_DATA["findings"])
        self.assertEqual(set(got), set(want))
        for fid, wf in want.items():
            gf = got[fid]
            self.assertEqual(gf["title"], wf["title"], fid)
            self.assertEqual(gf["severity"], wf["severity"], fid)   # Info stays Info
            self.assertEqual(gf.get("cwe"), wf.get("cwe"), fid)
            self.assertEqual(gf.get("cvss_score"), wf.get("cvss_score"), fid)
        # engagement round-trips from the Summary sheet
        self.assertEqual(result["engagement"].get("target"), "Example Corp")
        self.assertEqual(result["engagement"].get("report_id"), "ING-001")


class TestMarkdown(unittest.TestCase):
    TABLE = (
        "# Findings\n\n"
        "| ID | Title | Severity | CVSS | CWE | Affected |\n"
        "|----|-------|----------|------|-----|----------|\n"
        "| F-001 | SQL Injection | High | 8.1 | CWE-89 | api.example.test |\n"
        "| F-002 | Reflected XSS | Medium | 6.1 | CWE-79 | www.example.test |\n"
    )
    SECTIONED = (
        "# Findings\n\n"
        "## F-001 — SQL Injection\n"
        "Severity: High\n"
        "CVSS: 8.1\n"
        "CWE: CWE-89\n"
        "Affected: api.example.test\n\n"
        "## F-002 — Reflected XSS\n"
        "Severity: Medium\n"
        "CVSS: 6.1\n"
        "CWE: CWE-79\n"
        "Affected: www.example.test\n"
    )

    def test_table_and_sectioned_parse_to_same_findings(self):
        _, t_findings, _ = RI.ingest_md(self.TABLE)
        _, s_findings, _ = RI.ingest_md(self.SECTIONED)
        self.assertEqual([f["id"] for f in t_findings], ["F-001", "F-002"])
        self.assertEqual([f["id"] for f in s_findings], ["F-001", "F-002"])
        self.assertEqual([_projection(f) for f in t_findings],
                         [_projection(f) for f in s_findings])
        # sanity on the actual values
        self.assertEqual(_projection(t_findings[0]),
                         ("High", 8.1, "CWE-89", ("api.example.test",)))

    def test_prose_section_is_not_a_finding(self):
        text = ("## Executive Summary\nAll good.\n\n"
                "## F-100 — Open Redirect\nSeverity: Low\nCWE: CWE-601\n")
        _, findings, _ = RI.ingest_md(text)
        self.assertEqual([f["id"] for f in findings], ["F-100"])

    def test_ingest_via_file_and_auto_detect(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings.md")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(self.TABLE)
            result, code = RI.ingest(p)
            self.assertEqual(code, RI.EXIT_OK)
            self.assertEqual(result["ingest"]["format"], "md")
            self.assertEqual(len(result["findings"]), 2)


class TestPlaintext(unittest.TestCase):
    """Exercises the extractor the PDF/DOCX fallbacks share, without a real PDF."""

    def test_plaintext_finding_blocks(self):
        text = (
            "F-001  SQL Injection\n"
            "Severity: High\n"
            "CVSS: 8.1\n"
            "CWE: CWE-89\n"
            "Affected: api.example.test\n"
            "\n"
            "F-002  Reflected XSS\n"
            "Severity: Medium\n"
            "CWE: CWE-79\n"
            "Affected: www.example.test\n"
        )
        findings = RI.parse_plaintext(text)
        self.assertEqual([f["id"] for f in findings], ["F-001", "F-002"])
        self.assertEqual(findings[0]["cwe"], "CWE-89")
        self.assertEqual(findings[0]["cvss_score"], 8.1)


class TestPdf(unittest.TestCase):
    @unittest.skip("PDF end-to-end needs a renderer to build a fixture; the shared "
                   "extractor is covered by TestPlaintext, and ingest_pdf degrades "
                   "to exit 3 when no pdftotext/pdfminer is present.")
    def test_pdf_end_to_end(self):
        pass


@unittest.skipUnless(HAVE_DOCX, "python-docx not installed")
class TestDocx(unittest.TestCase):
    def test_docx_findings_table(self):
        doc = docx.Document()
        headers = ["ID", "Title", "Severity", "CVSS", "CWE", "Affected"]
        rows = [["F-001", "SQL Injection", "High", "8.1", "CWE-89", "api.example.test"],
                ["F-002", "Reflected XSS", "Medium", "6.1", "CWE-79", "www.example.test"]]
        table = doc.add_table(rows=1, cols=len(headers))
        for c, h in zip(table.rows[0].cells, headers):
            c.text = h
        for r in rows:
            cells = table.add_row().cells
            for c, v in zip(cells, r):
                c.text = v
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "report.docx")
            doc.save(p)
            result, code = RI.ingest(p)
        self.assertEqual(code, RI.EXIT_OK)
        self.assertEqual(result["ingest"]["format"], "docx")
        got = _by_id(result["findings"])
        self.assertEqual(set(got), {"F-001", "F-002"})
        self.assertEqual(got["F-001"]["cwe"], "CWE-89")
        self.assertEqual(got["F-001"]["cvss_score"], 8.1)


class TestDetect(unittest.TestCase):
    def test_extension_detection(self):
        for name, fmt in [("a.json", "json"), ("a.xlsx", "xlsx"), ("a.md", "md"),
                          ("a.markdown", "md"), ("a.pdf", "pdf"), ("a.docx", "docx")]:
            self.assertEqual(RI.detect_format(name), fmt)


if __name__ == "__main__":
    unittest.main(verbosity=2)
