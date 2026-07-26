#!/usr/bin/env python3
"""Tests for tools/appliance_version_infer.py (deterministic appliance fingerprinting).

Signals are injected as dicts — no network. Targets are client-neutral
(example.test / 203.0.113.x)."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

from appliance_version_infer import (
    applicability, infer, main, _parse_ver, _range_matches,
)

_TOOL = str(Path(__file__).resolve().parent / "appliance_version_infer.py")


class InferVendorTest(unittest.TestCase):
    def test_fortigate_header_plus_path(self):
        # Obfuscated Server header + a /remote/login marker -> Fortinet, >=2 strong.
        r = infer({
            "http_headers": {"Server": "xxxxxxxx-xxxxx"},
            "login_page_markers": ["/remote/login"],
        })
        self.assertEqual(r["vendor"], "Fortinet")
        self.assertEqual(r["product"], "FortiGate")
        self.assertIn(r["confidence"], ("medium", "high"))
        self.assertEqual(r["confidence"], "high")  # two independent strong signals
        self.assertTrue(any("Server header" in m for m in r["matched_signals"]))
        self.assertTrue(any("/remote/login" in m for m in r["matched_signals"]))

    def test_fortigate_version_from_body(self):
        r = infer({
            "http_headers": {"Server": "abcd1234-ef567"},
            "http_body": "<title>FortiGate</title> FortiOS 7.2.4 build1396",
            "login_page_markers": ["/logincheck", "/migadmin"],
        })
        self.assertEqual(r["vendor"], "Fortinet")
        self.assertEqual(r["version_guess"], "7.2.4")
        self.assertEqual(r["build"], "1396")
        self.assertEqual(r["confidence"], "high")

    def test_panos_globalprotect(self):
        r = infer({
            "http_headers": {"Server": "PanWeb Server/1.0"},
            "http_body": "<html>GlobalProtect Portal</html>",
            "login_page_markers": ["/global-protect/login.esp"],
        })
        self.assertEqual(r["vendor"], "Palo Alto Networks")
        self.assertEqual(r["product"], "PAN-OS")
        self.assertEqual(r["confidence"], "high")

    def test_panos_version_from_login_css(self):
        r = infer({
            "http_body": 'link href="/global-protect/portal/css/login.css?version=10.1.5"',
            "login_page_markers": ["/global-protect/login.esp"],
            "tls_cert": {"subject": "CN=gp.example.test, O=paloaltonetworks"},
        })
        self.assertEqual(r["vendor"], "Palo Alto Networks")
        self.assertEqual(r["version_guess"], "10.1.5")

    def test_cisco_asa_cscoe_marker(self):
        r = infer({
            "login_page_markers": ["/+CSCOE+/logon.html"],
            "http_body": "webvpn AnyConnect ASA 9.8(4)",
        })
        self.assertEqual(r["vendor"], "Cisco")
        self.assertEqual(r["product"], "ASA")
        self.assertEqual(r["version_guess"], "9.8(4)")
        self.assertIn(r["confidence"], ("medium", "high"))

    def test_citrix_nsc_cookie_plus_vpn_path(self):
        r = infer({
            "http_headers": {"Set-Cookie": "NSC_AAAC=abcdef; path=/; Secure"},
            "login_page_markers": ["/vpn/index.html"],
        })
        self.assertEqual(r["vendor"], "Citrix")
        self.assertEqual(r["product"], "ADC/NetScaler")
        self.assertEqual(r["confidence"], "high")

    def test_citrix_cert_and_build(self):
        r = infer({
            "http_body": "NetScaler NS13.0: Build 82.45",
            "tls_cert": {"subject": "CN=ns.example.test", "issuer": "CN=netscaler"},
        })
        self.assertEqual(r["vendor"], "Citrix")
        self.assertEqual(r["version_guess"], "13.0")
        self.assertEqual(r["build"], "82.45")

    def test_ambiguous_signals_yield_no_vendor(self):
        r = infer({"http_headers": {"Server": "nginx"}, "http_body": "<h1>hi</h1>"})
        self.assertIsNone(r["vendor"])
        self.assertIsNone(r["version_guess"])
        self.assertEqual(r["confidence"], "low")
        self.assertEqual(r["matched_signals"], [])

    def test_empty_signals_yield_no_vendor(self):
        for empty in ({}, None):
            r = infer(empty)
            self.assertIsNone(r["vendor"])
            self.assertEqual(r["confidence"], "low")

    def test_single_strong_signal_is_medium(self):
        # Only a cert CN — one strong signal -> medium, not high.
        r = infer({"tls_cert": {"subject": "CN=FortiGate"}})
        self.assertEqual(r["vendor"], "Fortinet")
        self.assertEqual(r["confidence"], "medium")

    def test_non_dict_signals_raises(self):
        with self.assertRaises(ValueError):
            infer(["not", "a", "dict"])

    def test_deterministic(self):
        s = {"http_headers": {"Server": "deadbeef-1234"},
             "login_page_markers": ["/remote/login"]}
        self.assertEqual(infer(s), infer(dict(s)))


class ApplicabilityTest(unittest.TestCase):
    _CVE = {"cpe": "cpe:2.3:o:fortinet:fortios:*",
            "affected_ranges": [{"ge": "7.0.0", "lt": "7.0.12"}]}

    def test_version_inside_range_is_applicable(self):
        inferred = {"vendor": "Fortinet", "version_guess": "7.0.5", "confidence": "high"}
        r = applicability(inferred, self._CVE)
        self.assertIs(r["applicable"], True)

    def test_version_outside_range_is_false(self):
        inferred = {"vendor": "Fortinet", "version_guess": "7.0.12", "confidence": "high"}
        r = applicability(inferred, self._CVE)
        self.assertIs(r["applicable"], False)

    def test_version_below_range_is_false(self):
        inferred = {"vendor": "Fortinet", "version_guess": "6.4.9", "confidence": "medium"}
        self.assertIs(applicability(inferred, self._CVE)["applicable"], False)

    def test_none_version_is_undetermined_never_applicable(self):
        inferred = {"vendor": "Fortinet", "version_guess": None, "confidence": "high"}
        r = applicability(inferred, self._CVE)
        self.assertEqual(r["applicable"], "undetermined")
        self.assertIsNot(r["applicable"], True)

    def test_low_confidence_is_undetermined_never_applicable(self):
        # Even a version squarely inside the range must NOT be asserted applicable
        # when confidence is low.
        inferred = {"vendor": "Fortinet", "version_guess": "7.0.5", "confidence": "low"}
        r = applicability(inferred, self._CVE)
        self.assertEqual(r["applicable"], "undetermined")
        self.assertNotEqual(r["applicable"], True)

    def test_no_affected_ranges_is_undetermined(self):
        inferred = {"vendor": "Cisco", "version_guess": "9.8", "confidence": "high"}
        r = applicability(inferred, {"cpe": "cpe:2.3:o:cisco:asa:*"})
        self.assertEqual(r["applicable"], "undetermined")

    def test_infer_then_applicability_end_to_end(self):
        inferred = infer({
            "http_headers": {"Server": "abcd1234-ef567"},
            "http_body": "FortiOS 7.0.6",
            "login_page_markers": ["/remote/login"],
        })
        self.assertIs(applicability(inferred, self._CVE)["applicable"], True)

    def test_ge_only_open_upper_bound(self):
        inferred = {"version_guess": "13.1", "confidence": "high"}
        cve = {"affected_ranges": [{"ge": "13.0"}]}
        self.assertIs(applicability(inferred, cve)["applicable"], True)

    def test_multiple_ranges_any_match(self):
        inferred = {"version_guess": "9.8", "confidence": "high"}
        cve = {"affected_ranges": [{"lt": "9.0"}, {"ge": "9.5", "lt": "10.0"}]}
        self.assertIs(applicability(inferred, cve)["applicable"], True)


class HelperTest(unittest.TestCase):
    def test_parse_ver(self):
        self.assertEqual(_parse_ver("7.0.12"), (7, 0, 12))
        self.assertEqual(_parse_ver("9.8(4)"), (9, 8, 4))
        self.assertIsNone(_parse_ver(None))
        self.assertIsNone(_parse_ver("none"))

    def test_range_matches_bounds(self):
        v = _parse_ver("7.0.5")
        self.assertTrue(_range_matches(v, {"ge": "7.0.0", "lt": "7.0.12"}))
        self.assertFalse(_range_matches(v, {"ge": "7.0.6"}))
        self.assertTrue(_range_matches(v, {}))  # open range matches


class CliTest(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, _TOOL, *args],
            capture_output=True, text=True)

    def test_cli_infer_only(self):
        signals = json.dumps({"http_headers": {"Server": "xxxxxxxx-xxxxx"},
                              "login_page_markers": ["/remote/login"]})
        p = self._run("--signals", signals)
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertEqual(out["inferred"]["vendor"], "Fortinet")
        self.assertNotIn("applicability", out)

    def test_cli_with_cve(self):
        signals = json.dumps({"http_headers": {"Server": "abcd1234-ef567"},
                              "http_body": "FortiOS 7.0.6",
                              "login_page_markers": ["/remote/login"]})
        cve = json.dumps({"affected_ranges": [{"ge": "7.0.0", "lt": "7.0.12"}]})
        p = self._run("--signals", signals, "--cve", cve, "--json")
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertIs(out["applicability"]["applicable"], True)

    def test_cli_bad_json_exits_1(self):
        p = self._run("--signals", "{not json")
        self.assertEqual(p.returncode, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
