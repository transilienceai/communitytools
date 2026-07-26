#!/usr/bin/env python3
"""Tests for tools/ntlm_decode.py (NTLMSSP Type-2 CHALLENGE decoder).

Type-2 messages are built as byte fixtures in-code (a valid NTLMSSP CHALLENGE with
a known AV_PAIR TargetInfo block, optional Version field), then decoded and the
extracted intel asserted. Hostnames are synthetic (WIN-SRV01 / CORP /
srv01.corp.example) and client-neutral."""
import base64
import contextlib
import io
import struct
import unittest

import ntlm_decode
from ntlm_decode import decode, decode_type2

SIGNATURE = b"NTLMSSP\x00"
DEFAULT_CHALLENGE = bytes.fromhex("1122334455667788")

# Flag bits used by the fixtures.
F_UNICODE = 0x00000001
F_TARGET_INFO = 0x00800000
F_VERSION = 0x02000000


def u16(s: str) -> bytes:
    return s.encode("utf-16-le")


def encode_av_pairs(pairs) -> bytes:
    """pairs: list of (av_id, value_bytes) -> a TargetInfo block ending in EOL."""
    out = b"".join(struct.pack("<HH", av_id, len(vb)) + vb for av_id, vb in pairs)
    return out + struct.pack("<HH", 0, 0)  # MsvAvEOL terminator


def build_type2(target_name="CORP", av_list=None, challenge=DEFAULT_CHALLENGE,
                flags=F_UNICODE | F_TARGET_INFO, version=None):
    """Construct a valid NTLMSSP Type-2 message. When `version` is a
    (major, minor, build) tuple, an 8-byte Version field is appended and the
    NEGOTIATE_VERSION flag is set so decode() reads it."""
    header_len = 48 + (8 if version is not None else 0)
    if version is not None:
        flags |= F_VERSION
    tn = u16(target_name) if target_name else b""
    ti = encode_av_pairs(av_list) if av_list is not None else b""
    tn_off = header_len
    ti_off = header_len + len(tn)

    msg = bytearray()
    msg += SIGNATURE
    msg += struct.pack("<I", 2)                             # message type = CHALLENGE
    msg += struct.pack("<HHI", len(tn), len(tn), tn_off)    # TargetName fields
    msg += struct.pack("<I", flags)                         # NegotiateFlags
    msg += challenge                                        # 8-byte ServerChallenge
    msg += b"\x00" * 8                                      # Reserved
    msg += struct.pack("<HHI", len(ti), len(ti), ti_off)    # TargetInfo fields
    if version is not None:
        major, minor, build = version
        msg += struct.pack("<BBH", major, minor, build) + b"\x00\x00\x00" + b"\x0f"
    msg += tn
    msg += ti
    return bytes(msg)


class DecodeType2Test(unittest.TestCase):
    def test_netbios_and_dns_extraction(self):
        av = [
            (1, u16("WIN-SRV01")),          # NetBIOS computer
            (2, u16("CORP")),               # NetBIOS domain
            (3, u16("srv01.corp.example")), # DNS computer (FQDN)
            (4, u16("corp.example")),       # DNS domain
            (5, u16("corp.example")),       # DNS tree/forest
        ]
        r = decode_type2(build_type2(target_name="CORP", av_list=av))
        self.assertTrue(r["signature_ok"])
        self.assertEqual(r["message_type"], 2)
        self.assertEqual(r["netbios_computer"], "WIN-SRV01")
        self.assertEqual(r["netbios_domain"], "CORP")
        self.assertEqual(r["dns_computer"], "srv01.corp.example")
        self.assertEqual(r["dns_domain"], "corp.example")
        self.assertEqual(r["dns_forest"], "corp.example")
        self.assertEqual(r["target_name"], "CORP")
        self.assertEqual(r["server_challenge"], "1122334455667788")
        self.assertEqual(r["negotiate_flags"], "0x00800001")

    def test_av_pairs_listed_with_names_and_no_eol(self):
        av = [(1, u16("WIN-SRV01")), (2, u16("CORP"))]
        r = decode_type2(build_type2(av_list=av))
        ids = [p["id"] for p in r["av_pairs"]]
        self.assertEqual(ids, [1, 2])            # EOL (id 0) is not listed
        names = {p["id"]: p["name"] for p in r["av_pairs"]}
        self.assertEqual(names[1], "MsvAvNbComputerName")
        self.assertEqual(names[2], "MsvAvNbDomainName")
        values = {p["id"]: p["value"] for p in r["av_pairs"]}
        self.assertEqual(values[1], "WIN-SRV01")

    def test_os_version_decoded_when_negotiate_version_set(self):
        # Windows Server 2019 / build 17763.
        r = decode_type2(build_type2(av_list=[(1, u16("WIN-SRV01"))], version=(10, 0, 17763)))
        self.assertEqual(r["os_version"], "10.0.17763")
        self.assertEqual(r["negotiate_flags"][-1], "1")  # version bit folded into flags
        self.assertTrue(int(r["negotiate_flags"], 16) & F_VERSION)

    def test_os_version_none_without_version_flag(self):
        r = decode_type2(build_type2(av_list=[(1, u16("WIN-SRV01"))], version=None))
        self.assertIsNone(r["os_version"])
        self.assertFalse(int(r["negotiate_flags"], 16) & F_VERSION)

    def test_filetime_timestamp_parsed(self):
        filetime = 133_200_000_000_000_000  # a plausible FILETIME (100ns since 1601)
        av = [(1, u16("WIN-SRV01")), (7, struct.pack("<Q", filetime))]
        r = decode_type2(build_type2(av_list=av))
        self.assertEqual(r["timestamp_filetime"], filetime)
        ts = [p for p in r["av_pairs"] if p["id"] == 7]
        self.assertEqual(len(ts), 1)
        self.assertEqual(ts[0]["name"], "MsvAvTimestamp")
        self.assertEqual(ts[0]["value"], filetime)

    def test_msvav_flags_rendered_as_hex(self):
        av = [(1, u16("WIN-SRV01")), (6, struct.pack("<I", 0x00000002))]
        r = decode_type2(build_type2(av_list=av))
        flag_pair = next(p for p in r["av_pairs"] if p["id"] == 6)
        self.assertEqual(flag_pair["name"], "MsvAvFlags")
        self.assertEqual(flag_pair["value"], "0x00000002")

    def test_empty_target_name_is_none(self):
        r = decode_type2(build_type2(target_name="", av_list=[(1, u16("WIN-SRV01"))]))
        self.assertIsNone(r["target_name"])
        self.assertEqual(r["netbios_computer"], "WIN-SRV01")


class DecodeDispatchTest(unittest.TestCase):
    def setUp(self):
        self.msg = build_type2(av_list=[(1, u16("WIN-SRV01")), (2, u16("CORP"))])

    def test_base64_input(self):
        r = decode(base64.b64encode(self.msg).decode())
        self.assertEqual(r["netbios_computer"], "WIN-SRV01")
        self.assertEqual(r["netbios_domain"], "CORP")

    def test_base64_input_with_www_authenticate_prefix(self):
        token = "NTLM " + base64.b64encode(self.msg).decode()
        self.assertEqual(decode(token)["netbios_computer"], "WIN-SRV01")

    def test_hex_input(self):
        r = decode(self.msg.hex())
        self.assertEqual(r["netbios_computer"], "WIN-SRV01")
        self.assertEqual(r["netbios_domain"], "CORP")

    def test_hex_preferred_over_base64_when_both_decode(self):
        # The hex encoding of a real message can also be valid base64; the NTLMSSP
        # signature must decide, so a hex token still parses as the message.
        r = decode(self.msg.hex())
        self.assertTrue(r["signature_ok"])
        self.assertEqual(r["message_type"], 2)


class BadInputTest(unittest.TestCase):
    def test_garbage_string_signature_not_ok(self):
        r = decode("this is not a real ntlm token at all")
        self.assertFalse(r["signature_ok"])
        self.assertIsNone(r["message_type"])

    def test_base64_of_non_ntlm_bytes_signature_not_ok(self):
        r = decode(base64.b64encode(b"hello world, not ntlmssp").decode())
        self.assertFalse(r["signature_ok"])

    def test_valid_signature_wrong_message_type(self):
        # Type-1 (NEGOTIATE) message: right signature, message type 1, not a Type-2.
        raw = SIGNATURE + struct.pack("<I", 1) + b"\x00" * 8
        r = decode_type2(raw)
        self.assertTrue(r["signature_ok"])
        self.assertEqual(r["message_type"], 1)
        self.assertIsNone(r["netbios_computer"])

    def test_truncated_header_raises(self):
        raw = SIGNATURE + struct.pack("<I", 2) + b"\x00" * 4  # sig+type but < 48 bytes
        with self.assertRaises(ValueError):
            decode_type2(raw)


class CliExitCodeTest(unittest.TestCase):
    def _run(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = ntlm_decode.main(argv)
        return rc, buf.getvalue()

    def test_exit_0_on_valid_type2(self):
        msg = build_type2(av_list=[(1, u16("WIN-SRV01"))])
        rc, out = self._run([base64.b64encode(msg).decode()])
        self.assertEqual(rc, 0)
        self.assertIn("WIN-SRV01", out)

    def test_exit_2_on_non_type2(self):
        rc, _ = self._run([base64.b64encode(b"not ntlm").decode()])
        self.assertEqual(rc, 2)

    def test_exit_2_on_garbage(self):
        rc, _ = self._run(["@@@ not base64 or hex @@@"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
