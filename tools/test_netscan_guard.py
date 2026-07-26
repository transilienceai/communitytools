#!/usr/bin/env python3
"""Tests for tools/netscan_guard.py (deterministic nmap-XML soundness guards).

Client-neutral: every fixture uses TEST-NET IPs (198.51.100.x / 203.0.113.x).
"""
import contextlib
import io
import json
import os
import tempfile
import unittest

import netscan_guard
from netscan_guard import (
    capability_check, host_timeout_guard, parse_scan, parse_vulners_output,
    suppress_cves, udp_guard,
)


# --------------------------------------------------------------------------- #
# Synthetic nmap XML fixtures
# --------------------------------------------------------------------------- #
XML_TRUNCATED = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT --host-timeout 12m 198.51.100.5 198.51.100.6">
  <scaninfo type="connect" protocol="tcp"/>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="198.51.100.5" addrtype="ipv4"/>
    <ports></ports>
    <times srtt="180000" rttvar="30000" to="300000"/>
  </host>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="198.51.100.6" addrtype="ipv4"/>
    <ports></ports>
    <times srtt="200000" rttvar="30000" to="320000"/>
  </host>
</nmaprun>
"""

XML_SOUND = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT --host-timeout 12m 198.51.100.5 198.51.100.6">
  <scaninfo type="connect" protocol="tcp"/>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="198.51.100.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="198.51.100.6" addrtype="ipv4"/>
    <ports></ports>
  </host>
</nmaprun>
"""

XML_NO_HOSTTIMEOUT = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT 198.51.100.5 198.51.100.6">
  <scaninfo type="connect" protocol="tcp"/>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="198.51.100.5" addrtype="ipv4"/>
    <ports></ports>
  </host>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="198.51.100.6" addrtype="ipv4"/>
    <ports></ports>
  </host>
</nmaprun>
"""

XML_UDP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sU 203.0.113.9">
  <scaninfo type="udp" protocol="udp"/>
  <host>
    <status state="up" reason="udp-response"/>
    <address addr="203.0.113.9" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="161">
        <state state="open|filtered" reason="no-response"/>
        <service name="snmp"/>
      </port>
      <port protocol="udp" portid="53">
        <state state="open" reason="udp-response"/>
        <service name="domain"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

XML_MARIADB = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -sV 203.0.113.20">
  <scaninfo type="connect" protocol="tcp"/>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="203.0.113.20" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack"/>
        <service name="mysql" product="MariaDB" version="5.5.5-10.3.34"/>
        <script id="vulners" output="cpe:/a:mysql:mysql:5.5.5:&#10;    CVE-2012-5611  10.0  https://vulners.com/cve/CVE-2012-5611&#10;"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

XML_PRIOR_RTT = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT 198.51.100.5">
  <scaninfo type="connect" protocol="tcp"/>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="198.51.100.5" addrtype="ipv4"/>
    <ports></ports>
    <times srtt="210000" rttvar="40000" to="400000"/>
  </host>
</nmaprun>
"""

XML_NOT_NMAP = """<?xml version="1.0"?><report><item>not nmap</item></report>"""


def _write(dirpath, name, content):
    path = os.path.join(dirpath, name)
    with open(path, "w") as f:
        f.write(content)
    return path


def _run(argv):
    """Invoke main() capturing stdout; return (exit_code, parsed_json_or_None)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = netscan_guard.main(argv)
    text = buf.getvalue().strip()
    return code, (json.loads(text) if text else None)


class HostTimeoutGuardTest(unittest.TestCase):
    def test_truncated_is_unsound_and_lists_rescan_hosts(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "trunc.xml", XML_TRUNCATED)
            code, out = _run(["--xml", p])
        self.assertEqual(code, 20)
        self.assertFalse(out["sound"])
        self.assertEqual(out["guards"]["host_timeout_truncation"]["verdict"], "UNSOUND")
        self.assertEqual(sorted(out["rescan_hosts"]), ["198.51.100.5", "198.51.100.6"])

    def test_open_port_makes_it_sound(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "sound.xml", XML_SOUND)
            code, out = _run(["--xml", p])
        self.assertEqual(code, 0)
        self.assertTrue(out["sound"])
        self.assertEqual(out["guards"]["host_timeout_truncation"]["verdict"], "SOUND")
        self.assertEqual(out["rescan_hosts"], [])

    def test_zero_open_without_host_timeout_is_sound(self):
        # Unattributable: a zero can't be blamed on truncation with no --host-timeout.
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "noht.xml", XML_NO_HOSTTIMEOUT)
            code, out = _run(["--xml", p])
        self.assertEqual(code, 0)
        self.assertTrue(out["sound"])
        self.assertFalse(out["guards"]["host_timeout_truncation"]["has_host_timeout"])

    def test_unit_not_connect_scan_is_sound(self):
        scan = parse_scan  # sanity: symbol import
        self.assertTrue(callable(scan))
        g = host_timeout_guard([{
            "args": "nmap -sS --host-timeout 5m", "scaninfo_types": ["syn"],
            "hosts": [{"ip": "198.51.100.1", "state": "up", "tcp_open": [], "udp_ports": []}],
        }])
        self.assertFalse(g["unsound"])


class UdpStatesTest(unittest.TestCase):
    def test_open_filtered_ambiguous_and_true_open(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "udp.xml", XML_UDP)
            code, out = _run(["--xml", p])
        self.assertEqual(code, 0)
        udp = out["guards"]["udp_states"]
        amb_ports = {r["port"] for r in udp["ambiguous_open_filtered"]}
        open_ports = {r["port"] for r in udp["true_open"]}
        self.assertEqual(amb_ports, {"161"})
        self.assertEqual(open_ports, {"53"})

    def test_udp_guard_unit(self):
        scans = [{"hosts": [{"udp_ports": [
            {"ip": "203.0.113.9", "port": "500", "state": "open", "reason": "no-response"},
        ]}]}]
        g = udp_guard(scans)
        # 'open' with a timeout reason must NOT be counted as a confirmed open port.
        self.assertEqual(g["true_open"], [])
        self.assertEqual(len(g["ambiguous_open_filtered"]), 1)


class CveSuppressionTest(unittest.TestCase):
    def test_mariadb_phantom_mysql_cve_suppressed(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "mariadb.xml", XML_MARIADB)
            code, out = _run(["--xml", p, "--suppress-cves"])
        self.assertEqual(code, 0)
        cve = out["guards"]["cve_suppression"]
        self.assertTrue(cve["enabled"])
        self.assertEqual(len(cve["suppressed"]), 1)
        entry = cve["suppressed"][0]
        self.assertEqual(entry["cve"], "CVE-2012-5611")
        self.assertIn("mariadb", entry["reason"].lower())
        self.assertEqual(entry["ip"], "203.0.113.20")
        self.assertEqual(cve["kept"], [])

    def test_suppression_disabled_by_default(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "mariadb.xml", XML_MARIADB)
            code, out = _run(["--xml", p])
        self.assertEqual(code, 0)
        self.assertFalse(out["guards"]["cve_suppression"]["enabled"])

    def test_suppress_cves_unit_keeps_unrelated(self):
        services = [{"ip": "203.0.113.20", "product": "MariaDB", "version": "5.5.5-10.3.34"}]
        candidates = [
            {"cve": "CVE-2012-5611", "cpe": "cpe:/a:mysql:mysql:5.5.5", "text": "CVE-2012-5611 cpe:/a:mysql:mysql:5.5.5"},
            {"cve": "CVE-2021-0001", "text": "CVE-2021-0001"},
        ]
        r = suppress_cves(services, candidates)
        self.assertEqual([e["cve"] for e in r["suppressed"]], ["CVE-2012-5611"])
        self.assertEqual(r["kept"], ["CVE-2021-0001"])

    def test_no_mariadb_service_suppresses_nothing(self):
        services = [{"ip": "203.0.113.30", "product": "MySQL", "version": "5.5.5"}]
        candidates = [{"cve": "CVE-2012-5611", "text": "CVE-2012-5611 cpe:/a:mysql:mysql:5.5.5"}]
        r = suppress_cves(services, candidates)
        self.assertEqual(r["suppressed"], [])
        self.assertEqual(r["kept"], ["CVE-2012-5611"])

    def test_parse_vulners_output(self):
        blob = "cpe:/a:mysql:mysql:5.5.5:\n    CVE-2012-5611  10.0  https://x\n    CVE-2012-5612 9.0 y\n"
        pairs = list(parse_vulners_output(blob))
        self.assertEqual([c for _, c in pairs], ["CVE-2012-5611", "CVE-2012-5612"])
        self.assertTrue(all(cpe == "cpe:/a:mysql:mysql:5.5.5" for cpe, _ in pairs))


class CapabilityCheckTest(unittest.TestCase):
    def test_unprivileged_full_range_with_prior_rtt(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "prior.xml", XML_PRIOR_RTT)
            code, out = _run(["--capability-check", "--prior-xml", p, "--uid", "1000", "--full-range"])
        self.assertEqual(code, 0)
        cap = out["capability"]
        recs = cap["recommendations"]
        self.assertTrue(any(r == "-sT" for r in recs))
        self.assertTrue(any("--max-rate" in r for r in recs))
        self.assertEqual(cap["rtt_floor_us"], 210000)
        self.assertTrue(cap["route_to_root_vantage"])
        self.assertTrue(any("--max-rtt-timeout" in r for r in recs))

    def test_privileged_no_routing(self):
        cap, parsed, _ = capability_check(uid=0, full_range=True, udp=True, prior_xml_paths=[])
        self.assertTrue(cap["privileged"])
        self.assertFalse(cap["route_to_root_vantage"])
        self.assertIsNone(cap["rtt_floor_us"])
        self.assertEqual(parsed, [])

    def test_unprivileged_no_full_range_no_udp_no_routing(self):
        cap, _, _ = capability_check(uid=1000, full_range=False, udp=False, prior_xml_paths=[])
        self.assertFalse(cap["route_to_root_vantage"])


class ErrorExitTest(unittest.TestCase):
    def test_empty_glob_exits_3(self):
        with tempfile.TemporaryDirectory() as d:
            code, out = _run(["--xml", os.path.join(d, "nope-*.xml")])
        self.assertEqual(code, 3)
        self.assertIn("error", out)

    def test_non_nmap_xml_exits_3(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "other.xml", XML_NOT_NMAP)
            code, out = _run(["--xml", p])
        self.assertEqual(code, 3)

    def test_no_mode_is_usage_error(self):
        code, out = _run([])
        self.assertEqual(code, 2)


class GlobMultiFileTest(unittest.TestCase):
    def test_glob_parses_all_matched_files(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "a.xml", XML_SOUND)
            _write(d, "b.xml", XML_UDP)
            code, out = _run(["--xml", os.path.join(d, "*.xml")])
        self.assertEqual(code, 0)
        self.assertEqual(len(out["files"]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
