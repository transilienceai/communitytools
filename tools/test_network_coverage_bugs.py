#!/usr/bin/env python3
"""Regression tests for two coverage defects that both produced a FALSE PASS.

Both were invisible in the worst way: the pipeline reported success while
assessing nothing.

1. `load_network_host()` read only the documented `ports[]` shape. Every one of
   the 72 committed host.json files uses `open_services: ["443/nginx", ...]` and
   none uses `ports`, so the loader returned None for every real host, enumerated
   zero cells, and the gate had nothing to fail on.

2. `network_coverage_map.map_host()` wrote `covered_negative` for EVERY enumerated
   cell, corroborated by whatever file happened to exist under recon/. "A file
   exists" stood in for "the probe ran and found nothing", so adding SMB/SNMP/RDP
   classes to a sweep would have closed them all without a single probe.

Run: python3 tools/test_network_coverage_bugs.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import enumerate_cells as EC          # noqa: E402
import network_coverage_map as NCM    # noqa: E402


def _host(tmp, ip="203.0.113.10", **body):
    d = os.path.join(tmp, "hosts", ip)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "host.json"), "w", encoding="utf-8") as fh:
        json.dump({"ip": ip, "live": True, **body}, fh)
    return d


class TestOpenServicesShape(unittest.TestCase):
    """Bug 1 — the loader must read the shape engagements actually emit."""

    def test_open_services_host_loads(self):
        with tempfile.TemporaryDirectory() as t:
            d = _host(t, open_services=["443/IIS-ASP.NET", "8443/ssl-listener"])
            got = EC.load_network_host(os.path.join(d, "host.json"))
        self.assertIsNotNone(got, "a host in the real shape must load, not return None")
        self.assertEqual(len(got["open_listeners"]), 2)

    def test_documented_ports_shape_still_loads(self):
        with tempfile.TemporaryDirectory() as t:
            d = _host(t, ports=[{"port": 443, "service": "https", "product": "nginx",
                                 "version": "1.18.0", "state": "open"}])
            got = EC.load_network_host(os.path.join(d, "host.json"))
        self.assertIsNotNone(got)
        self.assertEqual(len(got["open_listeners"]), 1)

    def test_flags_are_derived_from_the_service_label(self):
        with tempfile.TemporaryDirectory() as t:
            d = _host(t, open_services=["443/IIS-ASP.NET", "22/ssh-OpenSSH 8.9"])
            got = EC.load_network_host(os.path.join(d, "host.json"))
        flags = got["listener_flags"]
        https = flags["203.0.113.10:443"]
        self.assertIn("http_listener", https, "IIS in the label must mark an HTTP listener")
        self.assertIn("tls_listener", https, "port 443 must mark a TLS listener")
        self.assertIn("version_fingerprinted", flags["203.0.113.10:22"],
                      "a version in the label must mark the listener fingerprinted")

    def test_dead_or_surfaceless_host_still_yields_nothing(self):
        """The zero-units guard must survive the fix — a dead host has no cells."""
        with tempfile.TemporaryDirectory() as t:
            d = _host(t, ip="203.0.113.11", open_services=["443/x"])
            with open(os.path.join(d, "host.json"), "w", encoding="utf-8") as fh:
                json.dump({"ip": "203.0.113.11", "live": False,
                           "open_services": ["443/x"]}, fh)
            self.assertIsNone(EC.load_network_host(os.path.join(d, "host.json")))
            d2 = _host(t, ip="203.0.113.12", open_services=[])
            self.assertIsNone(EC.load_network_host(os.path.join(d2, "host.json")))

    def test_malformed_entries_are_skipped_not_crashed(self):
        with tempfile.TemporaryDirectory() as t:
            d = _host(t, open_services=["notaport/x", "", "443/ok"])
            got = EC.load_network_host(os.path.join(d, "host.json"))
        self.assertEqual(len(got["open_listeners"]), 1, "only the parseable entry counts")

    def test_every_committed_host_json_is_readable(self):
        """The bug in one line: the loader must work on the real corpus."""
        import glob
        repo = os.path.abspath(os.path.join(HERE, ".."))
        paths = glob.glob(os.path.join(repo, "projects/**/hosts/*/host.json"), recursive=True)
        if not paths:
            self.skipTest("no engagement host.json corpus in this checkout")
        live = [p for p in paths if json.load(open(p, encoding="utf-8")).get("live")
                and json.load(open(p, encoding="utf-8")).get("open_services")]
        loaded = [p for p in live if EC.load_network_host(p)]
        self.assertEqual(len(loaded), len(live),
                         "every live host with open services must load; "
                         f"{len(live) - len(loaded)} returned None")


class TestSweepCannotAutoClose(unittest.TestCase):
    """Bug 2 — a sweep may only close what a sweep can actually evidence."""

    def test_sweep_tail_cannot_auto_close_non_http_cells(self):
        """The headline regression: a class with no corroborating token stays
        pending, even though a file exists under recon/."""
        self.assertNotIn("XC-TLS-POSTURE", NCM.CORROBORATOR_REQUIRED,
                         "a port sweep cannot evidence cipher strength")
        self.assertNotIn("XC-SECURITY-HEADERS", NCM.CORROBORATOR_REQUIRED,
                         "a port sweep issues no HTTP request")

    def test_corroborator_requires_a_token_inside_the_file(self):
        with tempfile.TemporaryDirectory() as t:
            d = os.path.join(t, "hosts", "203.0.113.20")
            os.makedirs(os.path.join(d, "recon"), exist_ok=True)
            with open(os.path.join(d, "recon", "scan.txt"), "w", encoding="utf-8") as fh:
                fh.write("unrelated output\n")
            self.assertIsNotNone(NCM._raw_scan_ref(d),
                                 "without tokens, any file is still a reference")
            self.assertIsNone(NCM._raw_scan_ref(d, ("vulners",)),
                              "a file lacking the token must NOT corroborate")
            with open(os.path.join(d, "recon", "scan.txt"), "w", encoding="utf-8") as fh:
                fh.write("PORT STATE SERVICE\n443/tcp open  vulners: no findings\n")
            self.assertIsNotNone(NCM._raw_scan_ref(d, ("vulners",)),
                                 "a file containing the token must corroborate")

    def test_unclosable_classes_are_reported_not_dropped_silently(self):
        """A bounded coverage claim must say what it did not cover."""
        import inspect
        src = inspect.getsource(NCM.map_host)
        self.assertIn("not_sweep_closable", src,
                      "map_host must record the cells it declined to close")


if __name__ == "__main__":
    unittest.main(verbosity=2)
