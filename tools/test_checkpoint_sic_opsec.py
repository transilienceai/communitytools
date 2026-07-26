#!/usr/bin/env python3
"""Tests for tools/checkpoint_sic_opsec.py.

Deterministic and offline: every probe set is injected, so no network is touched
and the module-level `_probe` seam is never called. Client-neutral placeholder
host/IPs only (203.0.113.x / TEST-NET-3, RFC 5737).
"""
import json
import os
import subprocess
import sys
import unittest

import checkpoint_sic_opsec as C

HOST = "203.0.113.10"   # RFC 5737 documentation address — never a real target


def _open(port, **kw):
    p = {"port": port, "open": True, "banner": "", "http_status": None,
         "http_headers": {}, "http_body": ""}
    p.update(kw)
    return p


def _cve(preconds, cid):
    for e in preconds:
        if e.get("cve") == cid:
            return e
    return None


def _issue(preconds, name):
    for e in preconds:
        if e.get("issue") == name:
            return e
    return None


class FingerprintTest(unittest.TestCase):
    def test_sic_ports_open(self):
        probes = [_open(18190), _open(18191)]
        fp = C.fingerprint(probes)
        self.assertTrue(fp["is_checkpoint"])
        names = {s["name"] for s in fp["services"]}
        self.assertTrue(any("SIC CPMI" in n for n in names))
        self.assertTrue(any("SIC FWM" in n for n in names))
        self.assertEqual({s["port"] for s in fp["services"]}, {18190, 18191})
        self.assertFalse(fp["gaia_portal"])
        self.assertFalse(fp["remote_access"])

    def test_gaia_portal_without_ra_marker(self):
        probes = [_open(443, http_status=200,
                        http_headers={"Server": "Check Point SVN foundation"},
                        http_body="<title>Gaia Portal</title> /cgi-bin/home.tcl")]
        fp = C.fingerprint(probes)
        self.assertTrue(fp["is_checkpoint"])
        self.assertTrue(fp["gaia_portal"])
        self.assertFalse(fp["remote_access"])     # no RA/Mobile-Access marker
        self.assertEqual(fp["product"], "Gaia")

    def test_gaia_portal_with_ra_marker(self):
        probes = [_open(443, http_status=200,
                        http_headers={"Server": "Check Point SVN foundation"},
                        http_body="Mobile Access portal — SSL Network Extender login")]
        fp = C.fingerprint(probes)
        self.assertTrue(fp["gaia_portal"])
        self.assertTrue(fp["remote_access"])

    def test_version_hint_extracted(self):
        probes = [_open(443, http_status=200,
                        http_body="Check Point Gaia R81.10 build")]
        self.assertEqual(C.fingerprint(probes)["version_hint"], "R81.10")

    def test_non_checkpoint(self):
        probes = [_open(80, banner="", http_status=200,
                        http_headers={"Server": "nginx/1.25.0"},
                        http_body="<html>hello world</html>"),
                  _open(22, banner="SSH-2.0-OpenSSH_9.6")]
        fp = C.fingerprint(probes)
        self.assertFalse(fp["is_checkpoint"])
        self.assertEqual(fp["services"], [])
        self.assertEqual(fp["product"], "unknown")
        self.assertFalse(fp["gaia_portal"])

    def test_closed_ports_ignored(self):
        # A closed SIC port must not register the service or the appliance.
        probes = [{"port": 18190, "open": False}]
        fp = C.fingerprint(probes)
        self.assertFalse(fp["is_checkpoint"])
        self.assertEqual(fp["services"], [])

    def test_probes_must_be_list(self):
        with self.assertRaises(ValueError):
            C.fingerprint({"port": 18190})


class PreconditionTest(unittest.TestCase):
    def test_sic_exposure_applicable(self):
        preconds = C.cve_preconditions(C.fingerprint([_open(18190), _open(18191)]))
        sic = _issue(preconds, "sic-exposed")
        self.assertIsNotNone(sic)
        self.assertEqual(sic["status"], "applicable")
        self.assertIn("18190", sic["evidence"])
        self.assertIn("18191", sic["evidence"])
        # SIC-only surface has no Gaia portal → the file-read CVE is not applicable.
        cve = _cve(preconds, "CVE-2024-24919")
        self.assertEqual(cve["status"], "not_applicable")

    def test_cve_2024_24919_applicable_with_ra_marker(self):
        probes = [_open(443, http_status=200,
                        http_headers={"Server": "Check Point SVN foundation"},
                        http_body="Mobile Access — SSL Network Extender")]
        cve = _cve(C.cve_preconditions(C.fingerprint(probes)), "CVE-2024-24919")
        self.assertIsNotNone(cve)
        self.assertEqual(cve["status"], "applicable")
        self.assertIn("safe_check", cve)

    def test_cve_2024_24919_undetermined_without_ra_marker(self):
        probes = [_open(443, http_status=200,
                        http_headers={"Server": "Check Point SVN foundation"},
                        http_body="<title>Gaia Portal</title> home.tcl login")]
        cve = _cve(C.cve_preconditions(C.fingerprint(probes)), "CVE-2024-24919")
        self.assertIsNotNone(cve)
        self.assertEqual(cve["status"], "undetermined")
        # Precondition NOT met but portal present → never claimed applicable.
        self.assertNotEqual(cve["status"], "applicable")

    def test_opsec_lea_exposure(self):
        preconds = C.cve_preconditions(C.fingerprint([_open(18183)]))
        opsec = _issue(preconds, "opsec-lea-ela-exposed")
        self.assertIsNotNone(opsec)
        self.assertEqual(opsec["status"], "applicable")
        self.assertIn("18183", opsec["evidence"])

    def test_non_checkpoint_has_no_preconditions(self):
        probes = [_open(80, http_status=200,
                        http_headers={"Server": "nginx"}, http_body="hi"),
                  _open(22, banner="SSH-2.0-OpenSSH_9.6")]
        self.assertEqual(C.cve_preconditions(C.fingerprint(probes)), [])

    def test_never_applicable_without_marker_invariant(self):
        # Across every gate, `applicable` requires an observed marker/open port.
        for e in C.cve_preconditions(C.fingerprint([_open(18184)])):
            if e["status"] == "applicable":
                self.assertTrue(e["evidence"].strip())

    def test_ca_ica_exposure(self):
        preconds = C.cve_preconditions(C.fingerprint([_open(18210)]))
        ca = _issue(preconds, "ica-ca-exposed")
        self.assertIsNotNone(ca)
        self.assertEqual(ca["status"], "applicable")
        self.assertIn("18210", ca["evidence"])


class CliTest(unittest.TestCase):
    def setUp(self):
        self.script = os.path.join(os.path.dirname(os.path.abspath(C.__file__)),
                                   "checkpoint_sic_opsec.py")

    def test_cli_probes_json_exit_zero(self):
        probes = [_open(18190), _open(18191),
                  _open(443, http_status=200,
                        http_body="Mobile Access SSL Network Extender")]
        p = subprocess.run([sys.executable, self.script, "--probes", json.dumps(probes),
                            "--json"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertTrue(out["fingerprint"]["is_checkpoint"])
        cve = _cve(out["preconditions"], "CVE-2024-24919")
        self.assertEqual(cve["status"], "applicable")

    def test_cli_requires_an_input(self):
        p = subprocess.run([sys.executable, self.script], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)   # argparse usage error


if __name__ == "__main__":
    unittest.main(verbosity=2)
