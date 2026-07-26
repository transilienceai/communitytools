#!/usr/bin/env python3
"""Tests for tools/perimeter_forensics.py (RST-TTL forgery + IKE Notify decode).

Deterministic and offline: TTL classification is pure arithmetic, IKE decode is
pure parsing, and the one live step is a seam (`_probe_ttls`) that a test
monkeypatches. Nothing here touches a network.
"""
import json
import os
import subprocess
import sys
import unittest

import perimeter_forensics as pf
from perimeter_forensics import (
    classify, decode_ike_notify, guess_initial_ttl, hop_estimate,
    probe_and_classify,
)

_TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "perimeter_forensics.py")


def _ike_notify_bytes(next_payload, protocol_id, spi, notify_type, data, trailing=b""):
    """Build a wire-format ISAKMP/IKEv2 Notify payload for a fixture.

    `trailing` appends bytes AFTER the declared payload_length to model a slice
    of a larger packet (decode must stop at payload_length, not the buffer end).
    """
    spi, data = bytes(spi), bytes(data)
    body = bytes([protocol_id, len(spi)]) + notify_type.to_bytes(2, "big") + spi + data
    total = 4 + len(body)
    header = bytes([next_payload, 0]) + total.to_bytes(2, "big")
    return header + body + bytes(trailing)


class TtlArithmeticTest(unittest.TestCase):
    def test_guess_initial_ttl_nearest_at_or_above(self):
        self.assertEqual(guess_initial_ttl(50), 64)
        self.assertEqual(guess_initial_ttl(200), 255)
        self.assertEqual(guess_initial_ttl(120), 128)

    def test_guess_initial_ttl_exact_and_boundary(self):
        self.assertEqual(guess_initial_ttl(64), 64)
        self.assertEqual(guess_initial_ttl(128), 128)
        self.assertEqual(guess_initial_ttl(255), 255)
        self.assertEqual(guess_initial_ttl(65), 128)   # just over 64 -> next tier
        self.assertEqual(guess_initial_ttl(300), 255)  # invalid, clamps to max

    def test_hop_estimate(self):
        self.assertEqual(hop_estimate(59), 5)    # 64 - 59
        self.assertEqual(hop_estimate(116), 12)  # 128 - 116


class ClassifyTest(unittest.TestCase):
    def test_forged_rst_vs_open_service(self):
        # The forged-RST false-positive fix: RSTs imply 5 hops, but the genuinely
        # open service is 12 hops away -> the RSTs are crafted by the firewall.
        rsts = [
            {"port": 444, "state": "closed", "response_ttl": 59},
            {"port": 8082, "state": "closed", "response_ttl": 59},
        ]
        r = classify(rsts, open_service_ttl=116)
        self.assertEqual(r["verdict"], "rst-forged-by-filter")
        self.assertEqual(r["rst_hops"], [5])
        self.assertEqual(r["open_service_hops"], 12)

    def test_agreeing_ttls_are_single_host(self):
        rsts = [
            {"port": 81, "state": "closed", "response_ttl": 116},
            {"port": 82, "state": "closed", "response_ttl": 116},
        ]
        r = classify(rsts, open_service_ttl=116)
        self.assertEqual(r["verdict"], "consistent-single-host")

    def test_rsts_alone_are_undetermined_never_internal_host(self):
        # Self-consistent RSTs, NO open-service baseline. This is the exact input
        # that produced the false "internal host behind FW" claim; the verdict
        # must be undetermined and must NOT assert an internal/live host.
        rsts = [
            {"port": 444, "state": "closed", "response_ttl": 59},
            {"port": 8082, "state": "closed", "response_ttl": 59},
        ]
        r = classify(rsts)
        self.assertEqual(r["verdict"], "undetermined")
        self.assertEqual(
            r["note"],
            "cannot distinguish host RST from filter RST without an open-service baseline")
        blob = json.dumps(r).lower()
        self.assertNotIn("internal host", blob)
        self.assertNotIn("live host", blob)

    def test_open_entry_inside_list_is_used_as_baseline(self):
        # No explicit open_service_ttl, but an "open" entry supplies the baseline.
        entries = [
            {"port": 444, "state": "closed", "response_ttl": 59},   # 5 hops
            {"port": 18264, "state": "open", "response_ttl": 116},   # 12 hops
        ]
        r = classify(entries)
        self.assertEqual(r["verdict"], "rst-forged-by-filter")
        self.assertEqual(r["open_service_hops"], 12)

    def test_divergent_rsts_without_baseline_are_forged(self):
        # RSTs from different "closed" ports imply different hop counts -> at least
        # some must be crafted; a single host would answer all from one position.
        rsts = [
            {"port": 444, "state": "closed", "response_ttl": 59},   # 5 hops
            {"port": 8082, "state": "closed", "response_ttl": 116},  # 12 hops
        ]
        r = classify(rsts)
        self.assertEqual(r["verdict"], "rst-forged-by-filter")

    def test_no_responses_is_undetermined(self):
        r = classify([{"port": 80, "state": "filtered", "response_ttl": None}])
        self.assertEqual(r["verdict"], "undetermined")

    def test_non_list_raises(self):
        with self.assertRaises(TypeError):
            classify({"port": 80})

    def test_probe_seam_injection(self):
        # Inject the live seam; the offline classify must drive the verdict.
        original = pf._probe_ttls
        pf._probe_ttls = lambda host, ports, timeout=2.0: [
            {"port": p, "state": "closed", "response_ttl": 59} for p in ports
        ]
        try:
            r = probe_and_classify("203.0.113.10", [444, 8082], open_service_ttl=116)
        finally:
            pf._probe_ttls = original
        self.assertEqual(r["verdict"], "rst-forged-by-filter")


class IkeNotifyTest(unittest.TestCase):
    def test_nat_detection_source_ip(self):
        # 16388 = NAT_DETECTION_SOURCE_IP (IKEv2); data is a 20-byte SHA-1 hash.
        digest = bytes(range(20))
        payload = _ike_notify_bytes(
            next_payload=41, protocol_id=0, spi=b"", notify_type=16388, data=digest)
        d = decode_ike_notify(payload)
        self.assertEqual(d["notify_type"], 16388)
        self.assertEqual(d["notify_name"], "NAT_DETECTION_SOURCE_IP")
        self.assertEqual(d["next_payload"], 41)
        self.assertEqual(d["protocol_id"], 0)
        self.assertEqual(d["spi_size"], 0)
        self.assertEqual(d["spi"], "")
        self.assertEqual(d["data"], digest.hex())

    def test_no_proposal_chosen(self):
        payload = _ike_notify_bytes(
            next_payload=0, protocol_id=1, spi=b"", notify_type=14, data=b"")
        d = decode_ike_notify(payload)
        self.assertEqual(d["notify_type"], 14)
        self.assertEqual(d["notify_name"], "NO_PROPOSAL_CHOSEN")
        self.assertEqual(d["protocol_id"], 1)
        self.assertEqual(d["data"], "")

    def test_spi_is_extracted(self):
        # protocol_id 3 (ESP), 4-byte SPI, INVALID_SPI (11).
        payload = _ike_notify_bytes(
            next_payload=0, protocol_id=3, spi=b"\xde\xad\xbe\xef", notify_type=11, data=b"")
        d = decode_ike_notify(payload)
        self.assertEqual(d["notify_name"], "INVALID_SPI")
        self.assertEqual(d["spi_size"], 4)
        self.assertEqual(d["spi"], "deadbeef")

    def test_data_bounded_by_payload_length_not_buffer(self):
        # Trailing bytes past payload_length (a larger packet) are not notify data.
        payload = _ike_notify_bytes(
            next_payload=0, protocol_id=1, spi=b"", notify_type=14, data=b"",
            trailing=b"\x99\x99\x99")
        self.assertEqual(decode_ike_notify(payload)["data"], "")

    def test_unknown_type_is_named_unknown(self):
        payload = _ike_notify_bytes(
            next_payload=0, protocol_id=0, spi=b"", notify_type=40000, data=b"")
        self.assertEqual(decode_ike_notify(payload)["notify_name"], "UNKNOWN")

    def test_too_short_raises(self):
        with self.assertRaises(ValueError):
            decode_ike_notify(b"\x00\x00\x00")

    def test_spi_size_overrun_raises(self):
        # spi_size claims 8 bytes but the buffer only holds the 8-byte header.
        with self.assertRaises(ValueError):
            decode_ike_notify(bytes([0, 0, 0, 16, 1, 8]) + (14).to_bytes(2, "big"))


class CliTest(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run([sys.executable, _TOOL, *args],
                              capture_output=True, text=True)

    def test_cli_classify_ttls_forged(self):
        p = self._run("--classify-ttls",
                      json.dumps([{"port": 444, "state": "closed", "response_ttl": 59}]),
                      "--open-service-ttl", "116")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["verdict"], "rst-forged-by-filter")

    def test_cli_ike_notify(self):
        payload = _ike_notify_bytes(
            next_payload=0, protocol_id=1, spi=b"", notify_type=14, data=b"")
        p = self._run("--ike-notify", payload.hex())
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["notify_name"], "NO_PROPOSAL_CHOSEN")

    def test_cli_bad_hex_exit_1(self):
        p = self._run("--ike-notify", "zzzz")
        self.assertEqual(p.returncode, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
