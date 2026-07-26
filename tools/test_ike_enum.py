#!/usr/bin/env python3
"""Tests for tools/ike_enum.py — deterministic, no network.

Builders are asserted byte-for-byte on fixed cookies/KE/nonce; parse_response is
exercised on crafted ISAKMP/IKEv2 fixtures; scan() runs against an injected _send.
All hosts use the RFC 5737 documentation range (203.0.113.x)."""
import struct
import unittest

import ike_enum as I


# A fixed initiator cookie so the IKEv1 builder is deterministic in tests.
ICOOKIE = bytes.fromhex("1122334455667788")
ISPI = bytes.fromhex("aabbccddeeff0011")


class BuildIKEv1Test(unittest.TestCase):
    def test_single_transform_byte_for_byte(self):
        # 3DES / SHA1 / PSK / modp1024, 28800s lifetime, Main Mode.
        pkt = I.build_ikev1_sa([{"enc": 5, "hash": 2, "auth": 1, "group": 2}],
                               icookie=ICOOKIE, exchange_type=I.EXCH_MAIN)
        attrs = bytes.fromhex(
            "80010005"          # ENC = 3DES (5)   [TV]
            "80020002"          # HASH = SHA1 (2)
            "80030001"          # AUTH = PSK (1)
            "80040002"          # GROUP = modp1024 (2)
            "800b0001"          # LIFE_TYPE = seconds
            "000c000400007080"  # LIFE_DURATION = 28800  [TLV]
        )
        transform = bytes.fromhex("00000024" "01010000") + attrs      # np=0,len=36; t#1,id=KEY_IKE
        proposal = bytes.fromhex("0000002c" "01010001") + transform   # np=0,len=44; prop1,ISAKMP,spi0,1trans
        sa = bytes.fromhex("00000038" "00000001" "00000001") + proposal  # np=0,len=56; DOI=IPSEC,SIT=1
        header = ICOOKIE + bytes(8) + bytes.fromhex("01" "10" "02" "00" "00000000" "00000054")
        self.assertEqual(pkt, header + sa)

    def test_header_fields(self):
        pkt = I.build_ikev1_sa([{"enc": 5, "hash": 2, "auth": 1, "group": 2}],
                               icookie=ICOOKIE, exchange_type=I.EXCH_AGGRESSIVE)
        self.assertEqual(pkt[0:8], ICOOKIE)          # initiator cookie region
        self.assertEqual(pkt[8:16], bytes(8))        # responder cookie zero on request
        self.assertEqual(pkt[16], I.PT1_SA)          # next payload = SA
        self.assertEqual(pkt[17], I.IKEV1_VERSION)   # 0x10
        self.assertEqual(pkt[18], I.EXCH_AGGRESSIVE) # exchange type 4
        self.assertEqual(struct.unpack("!I", pkt[24:28])[0], len(pkt))  # length field == total

    def test_key_length_attr_added_for_aes(self):
        no_kl = I.build_ikev1_sa([{"enc": 7, "hash": 2, "auth": 1, "group": 14}], icookie=ICOOKIE)
        with_kl = I.build_ikev1_sa([{"enc": 7, "hash": 2, "auth": 1, "group": 14, "key_length": 256}], icookie=ICOOKIE)
        self.assertEqual(len(with_kl) - len(no_kl), 4)   # one extra TV attribute

    def test_symbolic_names_resolve(self):
        by_id = I.build_ikev1_sa([{"enc": 5, "hash": 2, "auth": 1, "group": 2}], icookie=ICOOKIE)
        by_name = I.build_ikev1_sa([{"enc": "3DES", "hash": "SHA1", "auth": "PSK", "group": "modp1024"}], icookie=ICOOKIE)
        self.assertEqual(by_id, by_name)

    def test_multiple_transforms_chain_next_payload(self):
        pkt = I.build_ikev1_sa([{"enc": 5, "hash": 2, "auth": 1, "group": 2},
                                {"enc": 1, "hash": 1, "auth": 1, "group": 2}], icookie=ICOOKIE)
        parsed = I.parse_response(pkt)
        # proposal announces 2 transforms; parser recovers the first.
        self.assertEqual(parsed["accepted_transform"]["encryption"]["id"], 5)

    def test_bad_cookie_length_rejected(self):
        with self.assertRaises(ValueError):
            I.build_ikev1_sa([{"enc": 5}], icookie=b"short")

    def test_empty_transforms_rejected(self):
        with self.assertRaises(ValueError):
            I.build_ikev1_sa([], icookie=ICOOKIE)


class BuildIKEv2Test(unittest.TestCase):
    def test_sa_init_structure_and_length(self):
        ke, nonce = bytes(96), bytes(32)
        pkt = I.build_ikev2_sa_init([14], ke, nonce, ispi=ISPI, encr=[(12, 256)], prf=[5], integ=[12])
        self.assertEqual(pkt[0:8], ISPI)
        self.assertEqual(pkt[8:16], bytes(8))
        self.assertEqual(pkt[16], I.PT_SA)             # next payload = SA
        self.assertEqual(pkt[17], I.IKEV2_VERSION)     # 0x20
        self.assertEqual(pkt[18], I.EXCH_IKE_SA_INIT)  # 34
        self.assertEqual(pkt[19], I.FLAG_INITIATOR)    # initiator bit
        self.assertEqual(struct.unpack("!I", pkt[24:28])[0], len(pkt))


class ParseIKEv1Test(unittest.TestCase):
    def test_aggressive_mode_flagged(self):
        # A crafted Aggressive Mode response (exchange type 4) with an SA transform.
        resp = I.build_ikev1_sa([{"enc": 5, "hash": 2, "auth": 1, "group": 2}],
                                icookie=ICOOKIE, exchange_type=I.EXCH_AGGRESSIVE)
        r = I.parse_response(resp)
        self.assertEqual(r["ike_version"], 1)
        self.assertEqual(r["exchange_type"], I.EXCH_AGGRESSIVE)
        self.assertTrue(r["aggressive_mode"])
        self.assertEqual(r["accepted_transform"]["encryption"]["name"], "3DES")
        self.assertEqual(r["accepted_transform"]["dh_group"]["id"], 2)

    def test_main_mode_not_aggressive(self):
        resp = I.build_ikev1_sa([{"enc": 7, "hash": 2, "auth": 1, "group": 14, "key_length": 256}],
                                icookie=ICOOKIE, exchange_type=I.EXCH_MAIN)
        r = I.parse_response(resp)
        self.assertFalse(r["aggressive_mode"])
        self.assertEqual(r["accepted_transform"]["encryption"]["name"], "AES")
        self.assertEqual(r["accepted_transform"]["key_length"], 256)
        self.assertEqual(r["accepted_transform"]["dh_group"]["name"], "modp2048")

    def test_ikev1_notify_no_proposal_chosen(self):
        # ISAKMP header (Informational, next=Notify) + a Notification payload type 14.
        notify_body = struct.pack("!I", I.DOI_IPSEC) + struct.pack("!BBH", I.PROTO_ISAKMP, 0, 14)
        notify = struct.pack("!BBH", I.PT1_NONE, 0, 4 + len(notify_body)) + notify_body
        hdr = ICOOKIE + bytes(8) + struct.pack("!BBBBII", I.PT1_NOTIFY, I.IKEV1_VERSION,
                                               I.EXCH_INFORMATIONAL_V1, 0, 0, 28 + len(notify))
        r = I.parse_response(hdr + notify)
        self.assertEqual(r["notifies"], [{"type": 14, "name": "NO-PROPOSAL-CHOSEN"}])
        self.assertFalse(r["nat_t"])


class ParseIKEv2Test(unittest.TestCase):
    def _ikev2(self, first_np, payloads):
        body = b"".join(payloads)
        hdr = ISPI + bytes.fromhex("1122334455667788") + struct.pack(
            "!BBBBII", first_np, I.IKEV2_VERSION, I.EXCH_IKE_SA_INIT, I.FLAG_RESPONSE, 0, 28 + len(body))
        return hdr + body

    def _notify(self, next_np, msgtype):
        nb = struct.pack("!BBH", 0, 0, msgtype)   # proto=0, spi_size=0, type
        return struct.pack("!BBH", next_np, 0, 4 + len(nb)) + nb

    def test_nat_detection_sets_nat_t(self):
        pkt = self._ikev2(I.PT_NOTIFY, [self._notify(I.PT1_NONE, I.NAT_DETECTION_SOURCE_IP)])
        r = I.parse_response(pkt)
        self.assertEqual(r["ike_version"], 2)
        self.assertEqual(r["exchange_type"], I.EXCH_IKE_SA_INIT)
        self.assertTrue(r["nat_t"])
        self.assertEqual(r["notifies"], [{"type": 16388, "name": "NAT_DETECTION_SOURCE_IP"}])

    def test_two_notifies_including_dest_nat(self):
        pkt = self._ikev2(I.PT_NOTIFY, [
            self._notify(I.PT_NOTIFY, I.NAT_DETECTION_SOURCE_IP),
            self._notify(I.PT1_NONE, I.NAT_DETECTION_DESTINATION_IP),
        ])
        r = I.parse_response(pkt)
        self.assertTrue(r["nat_t"])
        self.assertEqual([n["type"] for n in r["notifies"]],
                         [I.NAT_DETECTION_SOURCE_IP, I.NAT_DETECTION_DESTINATION_IP])

    def test_no_proposal_chosen_not_nat(self):
        pkt = self._ikev2(I.PT_NOTIFY, [self._notify(I.PT1_NONE, I.NO_PROPOSAL_CHOSEN)])
        r = I.parse_response(pkt)
        self.assertFalse(r["nat_t"])
        self.assertEqual(r["notifies"], [{"type": 14, "name": "NO_PROPOSAL_CHOSEN"}])

    def test_invalid_ke_payload_notify(self):
        pkt = self._ikev2(I.PT_NOTIFY, [self._notify(I.PT1_NONE, I.INVALID_KE_PAYLOAD)])
        r = I.parse_response(pkt)
        self.assertEqual(r["notifies"], [{"type": 17, "name": "INVALID_KE_PAYLOAD"}])

    def test_short_packet(self):
        r = I.parse_response(b"\x00" * 10)
        self.assertIn("error", r)


class RoundTripTest(unittest.TestCase):
    def test_ikev1_recovers_transform(self):
        proposed = {"enc": 5, "hash": 2, "auth": 1, "group": 2}
        r = I.parse_response(I.build_ikev1_sa([proposed], icookie=ICOOKIE))
        at = r["accepted_transform"]
        self.assertEqual(at["encryption"]["id"], 5)
        self.assertEqual(at["hash"]["id"], 2)
        self.assertEqual(at["authentication"]["id"], 1)
        self.assertEqual(at["dh_group"]["id"], 2)
        self.assertEqual(at["lifetime"], 28800)

    def test_ikev2_recovers_transform(self):
        pkt = I.build_ikev2_sa_init([14], bytes(96), bytes(32), ispi=ISPI,
                                    encr=[(12, 256)], prf=[5], integ=[12])
        at = I.parse_response(pkt)["accepted_transform"]
        self.assertEqual(at["encryption"]["id"], 12)
        self.assertEqual(at["encryption"]["key_length"], 256)
        self.assertEqual(at["prf"]["id"], 5)
        self.assertEqual(at["integrity"]["id"], 12)
        self.assertEqual(at["dh_group"]["id"], 14)


class AttrParseTest(unittest.TestCase):
    def test_tv_and_tlv_roundtrip(self):
        buf = I._attr_tv(I.ATTR_ENC, 5) + I._attr_tlv(I.ATTR_LIFE_DURATION, struct.pack("!I", 28800))
        parsed = I._parse_attrs(buf)
        self.assertEqual(parsed[I.ATTR_ENC], 5)
        self.assertEqual(parsed[I.ATTR_LIFE_DURATION], 28800)


class IkeScanParseTest(unittest.TestCase):
    def test_main_mode_output(self):
        text = ("Starting ike-scan\n"
                "203.0.113.10\tMain Mode Handshake returned "
                "HDR=(CKY-R=deadbeef) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK "
                "LifeType=Seconds LifeDuration=28800)\n"
                "Ending ike-scan\n")
        out = I._parse_ike_scan_output(text)
        self.assertTrue(out["responded"])
        self.assertFalse(out["aggressive_mode"])
        self.assertEqual(out["transform"]["enc"], "3DES")
        self.assertEqual(out["transform"]["group"], "2:modp1024")

    def test_aggressive_output(self):
        text = "203.0.113.10\tAggressive Mode Handshake returned HDR=(...) SA=(Enc=3DES Hash=SHA1 Auth=PSK Group=2:modp1024)\n"
        out = I._parse_ike_scan_output(text)
        self.assertTrue(out["aggressive_mode"])
        self.assertTrue(out["responded"])

    def test_no_response(self):
        out = I._parse_ike_scan_output("Starting ike-scan\nEnding ike-scan: 0 returned handshake\n")
        self.assertFalse(out["responded"])
        self.assertFalse(out["aggressive_mode"])


class ScanTest(unittest.TestCase):
    """scan() with the live _send seam replaced by a byte fixture."""

    def setUp(self):
        self._orig = I._send

    def tearDown(self):
        I._send = self._orig

    def test_raw_aggressive_detects_and_flags(self):
        captured = {}

        def fake_send(host, port, packet, timeout):
            captured["host"], captured["port"], captured["packet"] = host, port, packet
            return I.build_ikev1_sa([{"enc": 5, "hash": 2, "auth": 1, "group": 2}],
                                    icookie=ICOOKIE, exchange_type=I.EXCH_AGGRESSIVE)

        I._send = fake_send
        res = I.scan("203.0.113.20", {"prefer": "raw", "aggressive": True})
        self.assertEqual(captured["host"], "203.0.113.20")
        self.assertEqual(captured["port"], 500)
        self.assertTrue(res["responded"])
        self.assertTrue(res["aggressive_mode"])
        ids = [f["id"] for f in res["findings"]]
        self.assertIn("IKE-AGGRESSIVE-MODE", ids)
        self.assertIn("IKE-WEAK-DH-GROUP", ids)  # modp1024 accepted

    def test_raw_ikev2_nat_t(self):
        def fake_send(host, port, packet, timeout):
            nb = struct.pack("!BBH", 0, 0, I.NAT_DETECTION_SOURCE_IP)
            notify = struct.pack("!BBH", I.PT1_NONE, 0, 4 + len(nb)) + nb
            hdr = ISPI + bytes(8) + struct.pack("!BBBBII", I.PT_NOTIFY, I.IKEV2_VERSION,
                                                I.EXCH_IKE_SA_INIT, I.FLAG_RESPONSE, 0, 28 + len(notify))
            return hdr + notify

        I._send = fake_send
        res = I.scan("203.0.113.21", {"prefer": "raw", "ikev2": True, "port": 4500})
        self.assertEqual(res["port"], 4500)
        self.assertTrue(res["responded"])
        self.assertTrue(res["nat_t"])
        self.assertEqual(res["ike_version"], 2)

    def test_no_response_is_clean(self):
        I._send = lambda *a, **k: b""
        res = I.scan("203.0.113.22", {"prefer": "raw"})
        self.assertFalse(res["responded"])
        self.assertEqual(res["findings"], [])

    def test_des_cipher_flagged(self):
        def fake_send(host, port, packet, timeout):
            return I.build_ikev1_sa([{"enc": 1, "hash": 1, "auth": 1, "group": 2}],
                                    icookie=ICOOKIE, exchange_type=I.EXCH_MAIN)

        I._send = fake_send
        res = I.scan("203.0.113.23", {"prefer": "raw"})
        self.assertIn("IKE-WEAK-CIPHER-DES", [f["id"] for f in res["findings"]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
