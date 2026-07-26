#!/usr/bin/env python3
"""Tests for tools/certin_metadata_build.py (stdlib unittest; mirrors test_report_data_build.py).

Covers: CLI summary shape + exit codes, report_data-vs-glob preference/verdict filter,
technical/compliance routing, enum coercion -> <FILL> + needs_manual, deterministic
derivations (severity/occurrence/attributing-factor/manpower), redaction on BOTH outputs,
the real 67 MB sheet2 xlsx round-trip (example rows cleared, hidden sheets + table1 +
dataValidations preserved, sheet2 dimension preserved, well-formed), and the stdlib-only
import guard.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BUILD = os.path.join(HERE, "certin_metadata_build.py")
TEMPLATE = os.path.join(REPO, "formats", "certin-audit-metadata", "Audit-Metadata-Format-2026.xlsx")
ENUMS = os.path.join(REPO, "formats", "certin-audit-metadata", "enums.json")
HAVE_TEMPLATE = os.path.isfile(TEMPLATE)


def write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f)


def make_engagement(tmp, findings, certin=None, use_report_data=True, validated=None):
    eng = os.path.join(tmp, "260101_acme")
    os.makedirs(os.path.join(eng, "reports"), exist_ok=True)
    os.makedirs(os.path.join(eng, "input"), exist_ok=True)
    if use_report_data:
        write(os.path.join(eng, "reports", "report_data.json"),
              {"engagement": {"target": "acme.example"}, "findings": findings})
    if validated:
        for v in validated:
            write(os.path.join(eng, "artifacts", "validated", v["finding_id"] + ".json"), v)
    if certin is not None:
        write(os.path.join(eng, "input", "certin.json"), certin)
    return eng


def run(eng, extra=None):
    cmd = [sys.executable, BUILD, "--engagement-dir", eng]
    if extra:
        cmd += extra
    p = subprocess.run(cmd, capture_output=True, text=True)
    last = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else "{}"
    try:
        summary = json.loads(last)
    except ValueError:
        summary = {}
    return p.returncode, summary, p.stdout, p.stderr


FULL_CERTIN = {
    "ambak_no": "AUD202601010001",
    "auditor": {"org": "Transilience", "validated_by": "A. Manager", "designation": "CISO", "email": "a@x.io", "mobile": "9990001111"},
    "auditee": {"name": "Acme Corp", "category": "Private Sector", "sector": "Finance", "subsector": "Fintech", "state_ut": "Maharashtra"},
    "audit_type": "Website /Web Application Audit", "reason": "Regulatory directions",
    "standards": ["OWASP Top 10", "PCI DSS"], "first_final": "First Audit",
    "dates": {"completion": "01.01.2026", "last_audit": "NA"},
    "manpower": [{"name": "Jane Doe", "email": "jane@x.io", "certs": ["OSCP", "CEH"], "years": 6}],
}

TECH = {"id": "F-01", "title": "SQL injection in login", "severity": "High", "cvss_score": 8.1,
        "cwe": "CWE-89", "affected": ["https://acme.example/login", "https://acme.example/api"], "cves": []}
VULN = {"id": "F-02", "title": "Outdated Apache 2.4.58", "severity": "Critical", "cvss_score": 9.8,
        "cwe": "CWE-1104", "affected": ["10.0.0.5"], "cves": [{"id": "CVE-2023-43622", "score": 9.8, "severity": "Critical"}]}
COMPLIANCE = {"id": "C-01", "title": "NTP not synced", "severity": "High", "control_id": "Clause (i) CERT-In Directions",
              "framework": "IT Act 2000", "type": "compliance", "affected": ["ntp"]}


class TestBuild(unittest.TestCase):
    @unittest.skipUnless(HAVE_TEMPLATE, "template not present")
    def test_happy_path_summary_and_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = make_engagement(tmp, [TECH, VULN, COMPLIANCE], FULL_CERTIN)
            rc, s, out, err = run(eng)
            self.assertEqual(rc, 0, err)
            self.assertEqual(set(s), {"technical", "compliance", "audits", "needs_manual", "sha256", "out", "xlsx"})
            self.assertEqual(s["technical"], 2)
            self.assertEqual(s["compliance"], 1)
            self.assertEqual(s["audits"], 1)
            self.assertEqual(s["needs_manual"], [])  # fully-valid config -> nothing to fill
            self.assertTrue(os.path.isfile(s["out"]) and os.path.isfile(s["xlsx"]))

    @unittest.skipUnless(HAVE_TEMPLATE, "template not present")
    def test_deterministic_derivations(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = make_engagement(tmp, [TECH, VULN], FULL_CERTIN)
            rc, s, out, err = run(eng)
            self.assertEqual(rc, 0, err)
            body = json.load(open(s["out"]))
            tech = {r["issue_name"]: r for r in body["security_issues_technical"]}
            self.assertEqual(tech["SQL injection in login"]["occurrence_count"], 2)  # len(affected)
            self.assertEqual(tech["SQL injection in login"]["attributing_factor"], "Coding Error")  # CWE-89
            self.assertEqual(tech["Outdated Apache 2.4.58"]["attributing_factor"], "Vulnerable Software Versions")  # has CVE
            self.assertEqual(tech["Outdated Apache 2.4.58"]["reference"], "CVE-2023-43622")
            self.assertEqual(tech["Outdated Apache 2.4.58"]["severity"], "Critical")
            self.assertEqual(body["audits_completed"][0]["vulns_first_audit"], 2)
            self.assertEqual(body["audits_completed"][0]["ai_assisted"][:3], "Yes")

    @unittest.skipUnless(HAVE_TEMPLATE, "template not present")
    def test_severity_info_to_informational(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = {"id": "F-9", "title": "Verbose banner", "severity": "Info", "affected": ["x"]}
            eng = make_engagement(tmp, [f], FULL_CERTIN)
            rc, s, out, err = run(eng)
            body = json.load(open(s["out"]))
            self.assertEqual(body["security_issues_technical"][0]["severity"], "Informational")

    @unittest.skipUnless(HAVE_TEMPLATE, "template not present")
    def test_enum_coercion_and_needs_manual(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = dict(FULL_CERTIN)
            bad["auditee"] = dict(FULL_CERTIN["auditee"], category="Not A Category", subsector="Not A Subsector")
            eng = make_engagement(tmp, [TECH], bad)
            rc, s, out, err = run(eng)
            self.assertEqual(rc, 0, err)
            self.assertIn("auditee.category", s["needs_manual"])
            self.assertIn("auditee.subsector", s["needs_manual"])
            body = json.load(open(s["out"]))
            self.assertEqual(body["audits_completed"][0]["category"], "<FILL: auditee.category>")

    @unittest.skipUnless(HAVE_TEMPLATE, "template not present")
    def test_manpower_ai_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = dict(FULL_CERTIN)
            cfg.pop("manpower")
            eng = make_engagement(tmp, [TECH], cfg)
            rc, s, out, err = run(eng)
            self.assertIn("manpower.auditor_name", s["needs_manual"])
            body = json.load(open(s["out"]))
            self.assertEqual(len(body["manpower"]), 1)
            self.assertIn("Claude Opus", body["manpower"][0]["name"])
            self.assertTrue(all(v == "No" for v in body["manpower"][0]["certifications"].values()))

    @unittest.skipUnless(HAVE_TEMPLATE, "template not present")
    def test_report_data_preferred_and_verdict_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            # report_data present -> used; validated dir should be ignored
            validated = [{"finding_id": "V-1", "verdict": "VALID", "report_fields": {"title": "glob-only", "affected": ["z"]}}]
            eng = make_engagement(tmp, [TECH], FULL_CERTIN, validated=validated)
            rc, s, _, err = run(eng)
            body = json.load(open(s["out"]))
            names = [r["issue_name"] for r in body["security_issues_technical"]]
            self.assertIn("SQL injection in login", names)
            self.assertNotIn("glob-only", names)

    @unittest.skipUnless(HAVE_TEMPLATE, "template not present")
    def test_glob_fallback_filters_non_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            validated = [
                {"finding_id": "V-1", "verdict": "VALID", "report_fields": {"title": "kept-valid", "affected": ["a"]}},
                {"finding_id": "V-2", "verdict": "REPAIRED", "report_fields": {"title": "kept-repaired", "affected": ["b"]}},
                {"finding_id": "V-3", "verdict": "DEMOTED", "report_fields": {"title": "dropped", "affected": ["c"]}},
            ]
            eng = make_engagement(tmp, [], FULL_CERTIN, use_report_data=False, validated=validated)
            rc, s, _, err = run(eng)
            self.assertEqual(rc, 0, err)
            body = json.load(open(s["out"]))
            names = sorted(r["issue_name"] for r in body["security_issues_technical"])
            self.assertEqual(names, ["kept-repaired", "kept-valid"])

    @unittest.skipUnless(HAVE_TEMPLATE, "template not present")
    def test_redaction_both_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            secret = {"id": "S", "title": "Leak AKIAABCDEFGHIJKLMNOP and PAN ABCDE1234F", "severity": "High", "cwe": "CWE-200", "affected": ["x"]}
            eng = make_engagement(tmp, [secret], FULL_CERTIN)
            rc, s, _, err = run(eng)
            raw = open(s["out"]).read()
            self.assertNotIn("AKIAABCDEFGHIJKLMNOP", raw)
            self.assertNotIn("ABCDE1234F", raw)
            self.assertIn("[REDACTED AWS KEY]", raw)
            self.assertIn("[REDACTED PAN]", raw)
            # xlsx too
            z = zipfile.ZipFile(s["xlsx"])
            blob = z.read("xl/worksheets/sheet4.xml").decode("utf8")
            self.assertNotIn("AKIAABCDEFGHIJKLMNOP", blob)
            self.assertIn("REDACTED AWS KEY", blob)

    @unittest.skipUnless(HAVE_TEMPLATE, "template not present")
    def test_xlsx_roundtrip_structure_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = make_engagement(tmp, [TECH, VULN, COMPLIANCE], FULL_CERTIN)
            rc, s, _, err = run(eng)
            self.assertEqual(rc, 0, err)
            src = zipfile.ZipFile(TEMPLATE)
            out = zipfile.ZipFile(s["xlsx"])
            self.assertEqual(set(src.namelist()), set(out.namelist()))
            # table1 + hidden sheets byte-identical
            self.assertEqual(src.read("xl/tables/table1.xml"), out.read("xl/tables/table1.xml"))
            self.assertEqual(src.read("xl/worksheets/sheet7.xml"), out.read("xl/worksheets/sheet7.xml"))
            self.assertEqual(src.read("xl/worksheets/sheet8.xml"), out.read("xl/worksheets/sheet8.xml"))
            # every sheet still well-formed XML
            for n in out.namelist():
                if n.endswith(".xml"):
                    ET.fromstring(out.read(n))
            # sheet2 (67MB) dimension preserved + response written
            s2 = out.read("xl/worksheets/sheet2.xml").decode("utf8")
            self.assertIn('<dimension ref="A1:E1048572"/>', s2)
            self.assertIn("Transilience", s2)
            # example rows cleared from data sheets
            s3 = out.read("xl/worksheets/sheet3.xml").decode("utf8")
            self.assertNotIn("ABC Corp", s3)
            self.assertIn("Acme Corp", s3)
            # dataValidations preserved on sheet3
            self.assertIn("INDIRECT(SUBSTITUTE", s3)
            # technical sheet has 2 data rows (row3, row4)
            s4 = out.read("xl/worksheets/sheet4.xml").decode("utf8")
            self.assertIn('<row r="3"', s4)
            self.assertIn('<row r="4"', s4)
            self.assertNotIn('<row r="5"', s4)

    @unittest.skipUnless(HAVE_TEMPLATE, "template not present")
    def test_overrides_applied(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = make_engagement(tmp, [TECH], FULL_CERTIN)
            ov = {"attributing_factors": {"F-01": "Design Error"}, "challenges": "Tight SLA"}
            ovp = os.path.join(eng, "reports", "certin-overrides.json")
            write(ovp, ov)
            rc, s, _, err = run(eng, ["--overrides", ovp])
            body = json.load(open(s["out"]))
            self.assertEqual(body["security_issues_technical"][0]["attributing_factor"], "Design Error")
            self.assertEqual(body["audits_completed"][0]["challenges"], "Tight SLA")

    def test_exit_missing_dir(self):
        rc, s, _, err = run(os.path.join(tempfile.gettempdir(), "no_such_eng_dir_xyz"))
        self.assertEqual(rc, 1)

    def test_exit_no_findings_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = os.path.join(tmp, "empty")
            os.makedirs(os.path.join(eng, "reports"))
            rc, s, _, err = run(eng)
            self.assertEqual(rc, 1)

    def test_exit_malformed_certin(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = make_engagement(tmp, [TECH], None)
            with open(os.path.join(eng, "input", "certin.json"), "w") as f:
                f.write("{not json")
            rc, s, _, err = run(eng)
            self.assertEqual(rc, 2)

    def test_no_forbidden_imports(self):
        src = open(BUILD).read()
        self.assertIsNone(re.search(r"\b(import\s+openpyxl|from\s+openpyxl|import\s+xlsxwriter|from\s+xlsxwriter)\b", src),
                          "builder must be stdlib-only (openpyxl/xlsxwriter are installed and would NOT raise)")

    @unittest.skipUnless(HAVE_TEMPLATE, "template not present")
    def test_deterministic_sha(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = make_engagement(tmp, [TECH, VULN], FULL_CERTIN)
            rc1, s1, _, _ = run(eng)
            rc2, s2, _, _ = run(eng)
            self.assertEqual(s1["sha256"], s2["sha256"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
