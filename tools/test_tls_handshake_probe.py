#!/usr/bin/env python3
"""Tests for tools/tls_handshake_probe.py.

No live network: the `_handshake` connect seam (and, for the real supported-logic
tests, the deeper `_connect` seam) is replaced with a fake returning canned
per-version results. Client-neutral placeholders (example.test / 203.0.113.x)."""
import io
import json
import unittest
from contextlib import redirect_stdout

import tls_handshake_probe as thp


def _by_version(summary, version):
    for r in summary["results"]:
        if r["version"] == version:
            return r
    raise AssertionError("no result for %s" % version)


def _fake_handshake(support_map):
    """Return a drop-in _handshake. support_map maps version ->
    (supported, negotiated_protocol, cipher, error). A version absent from the map
    models an ABORTED handshake (supported False, error set) — the openssl
    false-positive case."""
    def fake(host, port, version, timeout=8):
        if version in support_map:
            supported, negotiated, cipher, error = support_map[version]
        else:
            supported, negotiated, cipher, error = False, None, None, "handshake aborted (server refused)"
        return {"version": version, "supported": supported, "negotiated_protocol": negotiated,
                "negotiated_cipher": cipher, "error": error}
    return fake


class ProbeTest(unittest.TestCase):
    """probe() over a faked _handshake seam."""

    def setUp(self):
        self._orig = thp._handshake
        self.addCleanup(lambda: setattr(thp, "_handshake", self._orig))

    def test_only_modern_completes(self):
        thp._handshake = _fake_handshake({
            "TLSv1.2": (True, "TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", None),
            "TLSv1.3": (True, "TLSv1.3", "TLS_AES_256_GCM_SHA384", None),
        })
        s = thp.probe("example.test")
        self.assertEqual(s["supported_versions"], ["TLSv1.2", "TLSv1.3"])
        self.assertEqual(s["weak_supported"], [])

    def test_weak_tls10_flagged(self):
        # A host that completes a TLS 1.0 handshake — the finding this tool exists for.
        thp._handshake = _fake_handshake({
            "TLSv1": (True, "TLSv1", "AES256-SHA", None),
            "TLSv1.2": (True, "TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", None),
        })
        s = thp.probe("203.0.113.10")
        self.assertIn("TLSv1", s["supported_versions"])
        self.assertEqual(s["weak_supported"], ["TLSv1"])

    def test_aborted_handshake_excluded_openssl_falsepositive(self):
        # THE BUG BEING FIXED: TLSv1.1 handshake did NOT complete — the fake returns
        # supported=False WITH an error. A naive `openssl s_client -tls1_1` exit-code
        # check would have counted it as supported; the handshake-completion probe
        # must NOT. It appears in results (never a silent skip) but not in either list.
        thp._handshake = _fake_handshake({
            "TLSv1.1": (False, None, None, "tlsv1 alert protocol version"),
            "TLSv1.2": (True, "TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", None),
        })
        s = thp.probe("203.0.113.11")
        self.assertNotIn("TLSv1.1", s["supported_versions"])
        self.assertNotIn("TLSv1.1", s["weak_supported"])
        self.assertEqual(s["supported_versions"], ["TLSv1.2"])
        r = _by_version(s, "TLSv1.1")
        self.assertFalse(r["supported"])
        self.assertTrue(r["error"])

    def test_probe_respects_supported_flag_not_negotiated_presence(self):
        # A negotiated protocol is present (no error) but supported=False because it
        # differs from the request. probe must key off `supported`, not the mere
        # presence of a negotiated protocol/cipher.
        thp._handshake = _fake_handshake({
            "TLSv1": (False, "TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", None),
        })
        s = thp.probe("example.test", versions=["TLSv1"])
        self.assertEqual(s["supported_versions"], [])
        self.assertEqual(s["weak_supported"], [])

    def test_versions_subset_only_probed(self):
        thp._handshake = _fake_handshake({"TLSv1.2": (True, "TLSv1.2", "c", None)})
        s = thp.probe("example.test", versions=["TLSv1.2"])
        self.assertEqual([r["version"] for r in s["results"]], ["TLSv1.2"])

    def test_all_refused_empty(self):
        thp._handshake = _fake_handshake({})  # every version aborts
        s = thp.probe("example.test")
        self.assertEqual(s["supported_versions"], [])
        self.assertEqual(s["weak_supported"], [])
        self.assertEqual(len(s["results"]), 4)

    def test_result_order_matches_request(self):
        thp._handshake = _fake_handshake({v: (True, v, "c", None) for v in thp.DEFAULT_VERSIONS})
        s = thp.probe("example.test", versions=["TLSv1.3", "TLSv1"])
        self.assertEqual(s["supported_versions"], ["TLSv1.3", "TLSv1"])
        self.assertEqual(s["weak_supported"], ["TLSv1"])


class HandshakeLogicTest(unittest.TestCase):
    """The real _handshake supported-decision, over a faked _connect seam."""

    def setUp(self):
        self._orig = thp._connect
        self.addCleanup(lambda: setattr(thp, "_connect", self._orig))

    def test_negotiated_equals_requested_supported(self):
        thp._connect = lambda host, port, ctx, sni, timeout: ("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256")
        r = thp._handshake("example.test", 443, "TLSv1.2")
        self.assertTrue(r["supported"])
        self.assertEqual(r["negotiated_protocol"], "TLSv1.2")
        self.assertIsNone(r["error"])

    def test_negotiated_differs_not_supported(self):
        # Real _handshake code: pinned TLSv1 but the stack came back with TLSv1.2.
        # supported must be False even though the handshake "completed" — the exact
        # silent-downgrade that fooled the openssl-exit check.
        thp._connect = lambda host, port, ctx, sni, timeout: ("TLSv1.2", "c")
        r = thp._handshake("example.test", 443, "TLSv1")
        self.assertFalse(r["supported"])
        self.assertEqual(r["negotiated_protocol"], "TLSv1.2")

    def test_connect_raises_is_aborted_not_supported(self):
        def boom(*a, **k):
            raise ssl_error()
        thp._connect = boom
        r = thp._handshake("203.0.113.20", 443, "TLSv1.1")
        self.assertFalse(r["supported"])
        self.assertIsNone(r["negotiated_protocol"])
        self.assertTrue(r["error"])

    def test_unknown_version_errors_without_connect(self):
        called = []
        thp._connect = lambda *a, **k: called.append(1) or ("TLSv1.2", "c")
        r = thp._handshake("example.test", 443, "SSLv2")
        self.assertFalse(r["supported"])
        self.assertIn("unknown TLS version", r["error"])
        self.assertEqual(called, [])  # never attempted a connection


class CliTest(unittest.TestCase):
    def setUp(self):
        self._orig = thp._handshake
        self.addCleanup(lambda: setattr(thp, "_handshake", self._orig))

    def test_cli_json_exit0(self):
        thp._handshake = _fake_handshake({
            "TLSv1": (True, "TLSv1", "AES256-SHA", None),
            "TLSv1.2": (True, "TLSv1.2", "c", None),
        })
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = thp.main(["203.0.113.30", "--port", "8443", "--json"])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["port"], 8443)
        self.assertEqual(out["weak_supported"], ["TLSv1"])


def ssl_error():
    import ssl
    return ssl.SSLError("tlsv1 alert protocol version")


if __name__ == "__main__":
    unittest.main(verbosity=2)
