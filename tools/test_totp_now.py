#!/usr/bin/env python3
"""Tests for tools/totp_now.py against the RFC 6238 Appendix B test vectors."""
import base64
import unittest

import totp_now
from totp_now import hotp, totp

# RFC 6238 Appendix B uses ASCII seeds, repeated to the digest's key length.
SEEDS = {
    "sha1": b"12345678901234567890",
    "sha256": b"12345678901234567890123456789012",
    "sha512": b"1234567890123456789012345678901234567890123456789012345678901234",
}
B32 = {mode: base64.b32encode(seed).decode() for mode, seed in SEEDS.items()}

# (unix_time, digest) -> expected 8-digit TOTP, verbatim from RFC 6238 Appendix B.
VECTORS = {
    (59, "sha1"): "94287082",
    (59, "sha256"): "46119246",
    (59, "sha512"): "90693936",
    (1111111109, "sha1"): "07081804",
    (1111111109, "sha256"): "68084774",
    (1111111109, "sha512"): "25091201",
    (1111111111, "sha1"): "14050471",
    (1111111111, "sha256"): "67062674",
    (1111111111, "sha512"): "99943326",
    (1234567890, "sha1"): "89005924",
    (1234567890, "sha256"): "91819424",
    (1234567890, "sha512"): "93441116",
    (2000000000, "sha1"): "69279037",
    (2000000000, "sha256"): "90698825",
    (2000000000, "sha512"): "38618901",
    (20000000000, "sha1"): "65353130",
    (20000000000, "sha256"): "77737706",
    (20000000000, "sha512"): "47863826",
}


class RFC6238VectorTest(unittest.TestCase):
    def test_appendix_b_8digit_vectors(self):
        for (at, digest), expected in VECTORS.items():
            with self.subTest(at=at, digest=digest):
                self.assertEqual(
                    totp(B32[digest], at_unix=at, digits=8, digest=digest), expected
                )

    def test_six_digit_is_low_six_of_eight(self):
        # 10^6 divides 10^8, so the 6-digit code is the last 6 of the 8-digit one.
        self.assertEqual(totp(B32["sha1"], at_unix=59, digits=6), "287082")
        self.assertEqual(totp(B32["sha256"], at_unix=59, digits=6, digest="sha256"),
                         "119246")


class HotpTest(unittest.TestCase):
    def test_hotp_rfc4226_vectors(self):
        # RFC 4226 Appendix D, secret "12345678901234567890", counters 0..2.
        secret = SEEDS["sha1"]
        self.assertEqual(hotp(secret, 0), "755224")
        self.assertEqual(hotp(secret, 1), "287082")
        self.assertEqual(hotp(secret, 2), "359152")

    def test_unsupported_digest_raises(self):
        with self.assertRaises(ValueError):
            hotp(SEEDS["sha1"], 0, digest="md5")


class Base32ToleranceTest(unittest.TestCase):
    def test_lowercase_no_padding_and_spaces(self):
        canonical = totp(B32["sha1"], at_unix=59, digits=8)
        lowered_unpadded = B32["sha1"].rstrip("=").lower()
        self.assertEqual(totp(lowered_unpadded, at_unix=59, digits=8), canonical)
        spaced = " ".join(B32["sha1"][i:i + 4] for i in range(0, len(B32["sha1"]), 4))
        self.assertEqual(totp(spaced, at_unix=59, digits=8), canonical)


class NowSeamTest(unittest.TestCase):
    def test_injected_clock_is_deterministic(self):
        original = totp_now._now
        totp_now._now = lambda: 59
        try:
            self.assertEqual(totp(B32["sha1"], digits=8), "94287082")
            self.assertEqual(totp(B32["sha1"], digits=8), "94287082")  # stable
        finally:
            totp_now._now = original


if __name__ == "__main__":
    unittest.main(verbosity=2)
