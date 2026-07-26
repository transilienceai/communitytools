#!/usr/bin/env python3
"""Tests for tools/vantage_diagnose.py (deterministic filtered-host classifier).

Every network / subprocess seam is reassigned to a fake so no live traffic is sent.
TEST-NET (RFC 5737) IPs only — client-neutral. Run: python3 tools/test_vantage_diagnose.py
"""
import io
import json
import unittest
from contextlib import redirect_stdout

import vantage_diagnose as V


def _restore(saved):
    for name, fn in saved.items():
        setattr(V, name, fn)


class VantageDiagnoseTest(unittest.TestCase):
    def setUp(self):
        # Snapshot every seam so each test starts from a known baseline and setUp
        # can restore them in tearDown regardless of what the test reassigned.
        self._saved = {n: getattr(V, n) for n in
                       ("_tcp_probe", "_http_get", "_provider_auth", "_resolve_ptr", "_sleep")}
        # Safe defaults: dark host, no PTR, no cloud auth, instant sleep. Passive HTTP
        # is left unset (raises) so a test that forgets to wire it fails loudly.
        V._tcp_probe = lambda ip, port, timeout=8: (False, "tcp-timeout")
        V._resolve_ptr = lambda ip: None
        V._provider_auth = lambda: {"gcp": False, "aws": False, "az": False}
        V._sleep = lambda s: None

        def _no_http(url, timeout=8, headers=None):
            raise AssertionError("unexpected _http_get(%s)" % url)
        V._http_get = _no_http

    def tearDown(self):
        _restore(self._saved)

    def _diag(self, **kw):
        base = dict(ip="198.51.100.20", port=443, prior=False,
                    allow_third_party=False, nodes=["us1", "de1"])
        base.update(kw)
        return V.diagnose(**base)

    # ------------------------------------------------------------------ tests
    def test_reachable_shortcircuit(self):
        V._tcp_probe = lambda ip, port, timeout=8: (True, "tcp-open")
        called = {"http": 0, "ptr": 0}

        def _http(url, timeout=8, headers=None):
            called["http"] += 1
            raise AssertionError("passive seam must not run when primary is reachable")

        def _ptr(ip):
            called["ptr"] += 1
            return "should-not-run"
        V._http_get = _http
        V._resolve_ptr = _ptr

        r = self._diag(ip="203.0.113.10")
        self.assertEqual(r["classification"], "reachable")
        self.assertTrue(r["primary_egress"]["reachable"])
        self.assertEqual(called["http"], 0)   # passive corroborators NOT called
        self.assertEqual(called["ptr"], 0)
        self.assertIsNone(r["filtered_signal"])
        self.assertFalse(r["escalation"]["recommended"])

    def test_ip_allowlist_passive_default(self):
        # Primary filtered; InternetDB says the host exists; check-host DISABLED.
        def _http(url, timeout=8, headers=None):
            self.assertIn("internetdb", url)   # only the passive corroborator runs
            return (200, {"ip": "198.51.100.20", "ports": [22, 443],
                          "hostnames": [], "vulns": [], "tags": []})
        V._http_get = _http
        r = self._diag(ip="198.51.100.20")
        self.assertEqual(r["classification"], "ip-allowlist")
        self.assertEqual(r["third_party_probe"], "off")
        self.assertIsNone(r["passive"]["checkhost"])
        self.assertTrue(r["passive"]["internetdb"]["present"])
        self.assertEqual(r["passive"]["internetdb"]["ports"], [22, 443])
        self.assertIn("host-up-but-all-filtered", (r["filtered_signal"],))

    def test_geo_fence_active(self):
        # Active third-party probe: one geo node connects, another times out => geo-fence.
        def _http(url, timeout=8, headers=None):
            if "internetdb" in url:
                return (200, {"ports": [443], "hostnames": [], "vulns": []})
            if "check-tcp" in url:
                return (200, {"ok": 1, "request_id": "abc123", "nodes": {"us1": [], "de1": []}})
            if "check-result" in url:
                return (200, {"us1": [{"address": "198.51.100.20", "time": 0.2}],
                              "de1": [{"error": "timeout"}]})
            raise AssertionError("unexpected url %s" % url)
        V._http_get = _http
        r = self._diag(ip="198.51.100.20", allow_third_party=True, nodes=["us1", "de1"])
        self.assertEqual(r["classification"], "geo-fence")
        self.assertEqual(r["third_party_probe"], "on")
        self.assertEqual(r["passive"]["checkhost"]["reachable_from"], ["us1"])
        self.assertEqual(r["passive"]["checkhost"]["unreachable_from"], ["de1"])
        self.assertEqual(r["passive"]["checkhost"]["nodes_total"], 2)

    def test_down(self):
        # Corroborator reachable but finds nothing; no PTR; active off => down.
        def _http(url, timeout=8, headers=None):
            self.assertIn("internetdb", url)
            return (404, {"detail": "No information available"})
        V._http_get = _http
        r = self._diag(ip="203.0.113.50")
        self.assertEqual(r["classification"], "down")
        self.assertIsNone(r["filtered_signal"])
        self.assertFalse(r["escalation"]["recommended"])

    def test_cloud_auth_gate(self):
        # ip-allowlist inputs but NO cloud provider authed => not recommended.
        def _http(url, timeout=8, headers=None):
            return (200, {"ports": [8443], "hostnames": [], "vulns": []})
        V._http_get = _http
        V._provider_auth = lambda: {"gcp": False, "aws": False, "az": False}
        r = self._diag(ip="198.51.100.20")
        self.assertEqual(r["classification"], "ip-allowlist")
        self.assertFalse(r["escalation"]["recommended"])
        self.assertEqual(r["escalation"]["reason"], "no-cloud-auth")
        self.assertFalse(r["cloud_auth"]["any"])
        # Same inputs but a provider IS authed => recommended, provider surfaced.
        V._provider_auth = lambda: {"gcp": False, "aws": True, "az": False}
        r2 = self._diag(ip="198.51.100.20")
        self.assertTrue(r2["escalation"]["recommended"])
        self.assertEqual(r2["escalation"]["provider"], "aws")
        self.assertTrue(r2["cloud_auth"]["any"])

    def test_unknown_when_corroborators_down(self):
        def _boom(url, timeout=8, headers=None):
            raise OSError("no route to host")
        V._http_get = _boom
        r = self._diag(ip="198.51.100.20")
        self.assertEqual(r["classification"], "unknown")
        self.assertIsNone(r["filtered_signal"])
        # main() must translate an unknown classification to exit code 3.
        import sys
        argv = sys.argv
        sys.argv = ["vantage_diagnose.py", "--ip", "198.51.100.20"]
        try:
            with redirect_stdout(io.StringIO()):
                rc = V.main()
        finally:
            sys.argv = argv
        self.assertEqual(rc, 3)

    def test_provider_auth_flag(self):
        V._provider_auth = lambda: {"gcp": True, "aws": False, "az": False}
        import sys
        argv = sys.argv
        sys.argv = ["vantage_diagnose.py", "--provider-auth"]
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                rc = V.main()
        finally:
            sys.argv = argv
        self.assertEqual(rc, 0)
        obj = json.loads(buf.getvalue())
        # ONLY the cloud_auth object is printed — no classification wrapper.
        self.assertEqual(set(obj.keys()), {"gcp", "aws", "az", "any"})
        self.assertTrue(obj["gcp"])
        self.assertTrue(obj["any"])

    def test_bounded_poll(self):
        # check-host never settles (all nodes pending) -> the poll loop must stop at
        # CHECKHOST_MAX_POLLS and _sleep is called a bounded number of times.
        sleeps = {"n": 0}
        V._sleep = lambda s: sleeps.__setitem__("n", sleeps["n"] + 1)

        def _http(url, timeout=8, headers=None):
            if "internetdb" in url:
                return (200, {"ports": [443], "hostnames": [], "vulns": []})
            if "check-tcp" in url:
                return (200, {"ok": 1, "request_id": "rid-pending"})
            if "check-result" in url:
                return (200, {"us1": None, "de1": None})   # bare null = still pending, never settles
            raise AssertionError("unexpected url %s" % url)
        V._http_get = _http
        r = self._diag(ip="198.51.100.20", allow_third_party=True, nodes=["us1", "de1"])
        self.assertLessEqual(sleeps["n"], V.CHECKHOST_MAX_POLLS)
        self.assertEqual(sleeps["n"], V.CHECKHOST_MAX_POLLS)   # exhausted, then terminated
        self.assertEqual(r["passive"]["checkhost"]["reachable_from"], [])

    def test_filtered_signal_enum(self):
        # Across a spread of inputs, filtered_signal is always a strict enum member or null.
        cases = [
            dict(ip="203.0.113.10", tcp=(True, "tcp-open"), http=None),                # reachable
            dict(ip="198.51.100.20", tcp=(False, "tcp-rst"),
                 http=(200, {"ports": [443], "hostnames": [], "vulns": []})),          # ip-allowlist
            dict(ip="198.51.100.21", tcp=(False, "icmp-admin-prohibited"),
                 http=(200, {"ports": [443], "hostnames": [], "vulns": []})),          # ip-allowlist
            dict(ip="203.0.113.50", tcp=(False, "tcp-timeout"), http=(404, {}), prior=True),  # prior
            dict(ip="203.0.113.51", tcp=(False, "tcp-timeout"), http=(404, {})),       # down
        ]
        for c in cases:
            V._tcp_probe = lambda ip, port, timeout=8, _t=c["tcp"]: _t
            if c["http"] is None:
                V._http_get = lambda url, timeout=8, headers=None: (_ for _ in ()).throw(
                    AssertionError("no passive for reachable"))
            else:
                V._http_get = lambda url, timeout=8, headers=None, _r=c["http"]: _r
            r = self._diag(ip=c["ip"], prior=c.get("prior", False))
            fs = r["filtered_signal"]
            self.assertTrue(fs is None or fs in V.FILTERED_SIGNALS,
                            "bad filtered_signal %r for %r" % (fs, c["ip"]))
        # prior explicitly wins the signal mapping.
        V._tcp_probe = lambda ip, port, timeout=8: (False, "tcp-timeout")
        V._http_get = lambda url, timeout=8, headers=None: (404, {})
        rp = self._diag(ip="203.0.113.50", prior=True)
        self.assertEqual(rp["classification"], "ip-allowlist")
        self.assertEqual(rp["filtered_signal"], "prior-report-known-live")


if __name__ == "__main__":
    unittest.main(verbosity=2)
