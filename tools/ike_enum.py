#!/usr/bin/env python3
"""IKE/IPsec VPN enumeration — deterministic, tested, non-destructive.

Perimeter engagements repeatedly hand-rolled raw-socket ISAKMP builders to answer
three questions about a UDP-500/4500 VPN head-end:

  * Does IKEv1 **Aggressive Mode** work?  It transmits the responder identity and a
    hash of the pre-shared key in the clear, so its mere support is a finding
    (offline PSK cracking is out-of-band — we flag exposure, never crack in-band).
  * Which Phase-1 **transforms / DH groups** does it accept?  Weak DH groups
    (1/768, 2/1024, 5/1536) and DES/MD5 are the enumeration payoff.
  * What **NOTIFY** payloads / **NAT-T** markers come back (NO_PROPOSAL_CHOSEN,
    INVALID_KE_PAYLOAD, NAT_DETECTION_SOURCE_IP/DESTINATION_IP)?

This module wraps `ike-scan` when it is on PATH and otherwise falls back to a pure
raw ISAKMP/IKE builder + parser (stdlib struct/socket only). The builders are pure
and deterministic (cookies / KE / nonce are arguments, since we do no in-band DH),
so they are testable byte-for-byte; live I/O is isolated behind the module-level
`_send` seam so the parser and orchestrator can be exercised on byte fixtures with
no network.

Usage:
  python3 tools/ike_enum.py <host> [--port 500] [--ikev2] [--aggressive] [--json]

Exit 0.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys

# ---------------------------------------------------------------------------
# Protocol constants (RFC 2408 ISAKMP, RFC 2409 IKEv1, RFC 7296 IKEv2).
# ---------------------------------------------------------------------------
IKEV1_VERSION = 0x10
IKEV2_VERSION = 0x20

# ISAKMP / IKEv1 exchange types
EXCH_MAIN = 2          # Identity Protection (Main Mode)
EXCH_AGGRESSIVE = 4    # Aggressive Mode — leaks the PSK hash
EXCH_INFORMATIONAL_V1 = 5
# IKEv2 exchange types
EXCH_IKE_SA_INIT = 34
EXCH_IKE_AUTH = 35
EXCH_INFORMATIONAL_V2 = 37

IKEV1_EXCH = {0: "NONE", 1: "Base", 2: "Main", 3: "AuthOnly", 4: "Aggressive",
              5: "Informational", 6: "Transaction", 32: "QuickMode"}
IKEV2_EXCH = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL"}

# IKEv1 payload (next-payload) types
PT1_NONE, PT1_SA, PT1_PROP, PT1_TRANS, PT1_KE, PT1_ID, PT1_NONCE, PT1_NOTIFY = 0, 1, 2, 3, 4, 5, 10, 11
PT1_VID = 13
PT1_NATD = 20          # RFC 3947 NAT-D
PT1_NATD_DRAFT = 130   # draft-ietf-ipsec-nat-t-ike NAT-D
IKEV1_PAYLOAD = {0: "None", 1: "SA", 2: "Proposal", 3: "Transform", 4: "KE", 5: "ID",
                 6: "CERT", 7: "CR", 8: "Hash", 9: "SIG", 10: "Nonce", 11: "Notify",
                 12: "Delete", 13: "VID", 20: "NAT-D", 130: "NAT-D(draft)"}

# IKEv2 payload types
PT_SA, PT_KE, PT_IDI, PT_IDR, PT_NONCE, PT_NOTIFY = 33, 34, 35, 36, 40, 41
IKEV2_PAYLOAD = {33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT", 38: "CERTREQ",
                 39: "AUTH", 40: "Nonce", 41: "Notify", 42: "Delete", 43: "VID",
                 44: "TSi", 45: "TSr", 46: "SK", 47: "CP", 48: "EAP"}

# ISAKMP flags / IKEv2 flags
FLAG_INITIATOR = 0x08  # IKEv2 initiator bit
FLAG_RESPONSE = 0x20   # IKEv2 response bit

# IKEv1 SA / proposal
DOI_IPSEC = 1
SIT_IDENTITY_ONLY = 1
PROTO_ISAKMP = 1
TRANS_ID_KEY_IKE = 1

# IKEv1 Phase-1 attribute classes (RFC 2409 Appendix A)
ATTR_ENC, ATTR_HASH, ATTR_AUTH, ATTR_GROUP = 1, 2, 3, 4
ATTR_LIFE_TYPE, ATTR_LIFE_DURATION, ATTR_KEYLEN = 11, 12, 14

IKEV1_ENC = {1: "DES", 2: "IDEA", 3: "Blowfish", 4: "RC5", 5: "3DES", 6: "CAST", 7: "AES"}
IKEV1_HASH = {1: "MD5", 2: "SHA1", 3: "Tiger", 4: "SHA2-256", 5: "SHA2-384", 6: "SHA2-512"}
IKEV1_AUTH = {1: "PSK", 2: "DSS-Sig", 3: "RSA-Sig", 4: "RSA-Enc", 5: "RSA-Enc-Rev",
              64221: "Hybrid-RSA", 65001: "XAUTHInitPSK"}
IKEV1_GROUP = {1: "modp768", 2: "modp1024", 5: "modp1536", 14: "modp2048", 15: "modp3072",
               16: "modp4096", 19: "ecp256", 20: "ecp384", 21: "ecp521"}
IKEV1_NOTIFY = {1: "INVALID-PAYLOAD-TYPE", 7: "INVALID-EXCHANGE-TYPE",
                9: "INVALID-PROTOCOL-ID", 14: "NO-PROPOSAL-CHOSEN",
                15: "BAD-PROPOSAL-SYNTAX", 17: "INVALID-KEY-INFORMATION",
                24: "AUTHENTICATION-FAILED", 29: "ATTRIBUTES-NOT-SUPPORTED",
                24576: "RESPONDER-LIFETIME", 24577: "REPLAY-STATUS",
                24578: "INITIAL-CONTACT"}

# IKEv2 transform types + IDs (RFC 7296 3.3.2)
TT_ENCR, TT_PRF, TT_INTEG, TT_DH, TT_ESN = 1, 2, 3, 4, 5
PROTO_IKE = 1
IKEV2_ENCR = {3: "3DES", 12: "AES-CBC", 13: "AES-CTR", 20: "AES-GCM-16"}
IKEV2_PRF = {1: "HMAC-MD5", 2: "HMAC-SHA1", 5: "HMAC-SHA2-256", 6: "HMAC-SHA2-384", 7: "HMAC-SHA2-512"}
IKEV2_INTEG = {1: "HMAC-MD5-96", 2: "HMAC-SHA1-96", 12: "HMAC-SHA2-256-128",
               13: "HMAC-SHA2-384-192", 14: "HMAC-SHA2-512-256"}
IKEV2_DH = dict(IKEV1_GROUP)  # DH group numbers are shared with IKEv1
IKEV2_ESN = {0: "No-ESN", 1: "ESN"}

# IKEv2 NOTIFY message types (RFC 7296 3.10.1)
NO_PROPOSAL_CHOSEN = 14
INVALID_KE_PAYLOAD = 17
AUTHENTICATION_FAILED_V2 = 24
NAT_DETECTION_SOURCE_IP = 16388
NAT_DETECTION_DESTINATION_IP = 16389
IKEV2_NOTIFY = {7: "INVALID_SYNTAX", 14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD",
                24: "AUTHENTICATION_FAILED", 34: "SINGLE_PAIR_REQUIRED",
                16384: "INITIAL_CONTACT", 16388: "NAT_DETECTION_SOURCE_IP",
                16389: "NAT_DETECTION_DESTINATION_IP", 16390: "COOKIE"}

WEAK_DH_GROUPS = {1, 2, 5}  # 768 / 1024 / 1536-bit MODP — flag as weak

# Default proposal sets used by the raw-fallback scan path.
DEFAULT_IKEV1_TRANSFORMS = [
    {"enc": 7, "hash": 2, "auth": 1, "group": 14, "key_length": 256},  # AES-256/SHA1/PSK/modp2048
    {"enc": 7, "hash": 2, "auth": 1, "group": 2, "key_length": 128},   # AES-128/SHA1/PSK/modp1024
    {"enc": 5, "hash": 2, "auth": 1, "group": 2},                       # 3DES/SHA1/PSK/modp1024
    {"enc": 5, "hash": 1, "auth": 1, "group": 2},                       # 3DES/MD5/PSK/modp1024
    {"enc": 1, "hash": 2, "auth": 1, "group": 2},                       # DES/SHA1/PSK/modp1024
    {"enc": 1, "hash": 1, "auth": 1, "group": 2},                       # DES/MD5/PSK/modp1024
]
DEFAULT_DH_GROUPS = [14, 2, 5, 19, 20]
DEFAULT_IKEV2_ENCR = [(12, 256), (12, 128), (3, None)]  # AES-256, AES-128, 3DES
DEFAULT_IKEV2_PRF = [5, 2]      # SHA2-256, SHA1
DEFAULT_IKEV2_INTEG = [12, 2]   # SHA2-256-128, SHA1-96


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


# ---------------------------------------------------------------------------
# Attribute / value helpers.
# ---------------------------------------------------------------------------
def _norm(name) -> str:
    return str(name).upper().replace("-", "").replace("_", "").replace(" ", "")


def _reverse(table: dict) -> dict:
    return {_norm(v): k for k, v in table.items()}


def _resolve(value, table: dict) -> int:
    """Accept an int id or a symbolic name (looked up case/punctuation-insensitively)."""
    if isinstance(value, int):
        return value
    return _reverse(table)[_norm(value)]


def _attr_tv(atype: int, value: int) -> bytes:
    """Basic (Type/Value) attribute: AF bit set, value carried in the length field."""
    return struct.pack("!HH", 0x8000 | (atype & 0x7FFF), value & 0xFFFF)


def _attr_tlv(atype: int, value: bytes) -> bytes:
    """Variable (Type/Length/Value) attribute: AF bit clear, real length + value."""
    return struct.pack("!HH", atype & 0x7FFF, len(value)) + value


def _parse_attrs(buf: bytes) -> dict:
    """Walk a run of ISAKMP SA attributes (TV and TLV) into {type: int_value}."""
    out, off = {}, 0
    while off + 4 <= len(buf):
        atype, aval = struct.unpack("!HH", buf[off:off + 4])
        real = atype & 0x7FFF
        if atype & 0x8000:              # TV — value is in the second field
            out[real] = aval
            off += 4
        else:                            # TLV — aval is a byte length
            val = buf[off + 4:off + 4 + aval]
            out[real] = int.from_bytes(val, "big") if val else 0
            off += 4 + aval
    return out


# ---------------------------------------------------------------------------
# IKEv1 builder.
# ---------------------------------------------------------------------------
def _ikev1_transform(index: int, tdef: dict, next_payload: int) -> bytes:
    enc = _resolve(tdef.get("enc", 5), IKEV1_ENC)
    hsh = _resolve(tdef.get("hash", 2), IKEV1_HASH)
    auth = _resolve(tdef.get("auth", 1), IKEV1_AUTH)
    group = _resolve(tdef.get("group", 2), IKEV1_GROUP)
    keylen = tdef.get("key_length")
    lifetime = tdef.get("lifetime", 28800)

    attrs = _attr_tv(ATTR_ENC, enc)
    if keylen:
        attrs += _attr_tv(ATTR_KEYLEN, int(keylen))
    attrs += _attr_tv(ATTR_HASH, hsh)
    attrs += _attr_tv(ATTR_AUTH, auth)
    attrs += _attr_tv(ATTR_GROUP, group)
    if lifetime is not None:
        attrs += _attr_tv(ATTR_LIFE_TYPE, 1)  # seconds
        attrs += _attr_tlv(ATTR_LIFE_DURATION, struct.pack("!I", int(lifetime)))

    body = struct.pack("!BBH", index, TRANS_ID_KEY_IKE, 0) + attrs
    return struct.pack("!BBH", next_payload, 0, 4 + len(body)) + body


def _ikev1_proposal(transforms: list, next_payload: int = PT1_NONE) -> bytes:
    n = len(transforms)
    tbytes = b"".join(
        _ikev1_transform(i + 1, t, PT1_TRANS if i < n - 1 else PT1_NONE)
        for i, t in enumerate(transforms)
    )
    body = struct.pack("!BBBB", 1, PROTO_ISAKMP, 0, n) + tbytes  # prop#, proto, spi-size=0, #trans
    return struct.pack("!BBH", next_payload, 0, 4 + len(body)) + body


def _ikev1_sa_payload(transforms: list, next_payload: int = PT1_NONE) -> bytes:
    prop = _ikev1_proposal(transforms, next_payload=PT1_NONE)
    body = struct.pack("!II", DOI_IPSEC, SIT_IDENTITY_ONLY) + prop
    return struct.pack("!BBH", next_payload, 0, 4 + len(body)) + body


def _isakmp_header(icookie: bytes, rcookie: bytes, next_payload: int, version: int,
                   exchange_type: int, flags: int, msgid: int, length: int) -> bytes:
    return icookie + rcookie + struct.pack("!BBBBII", next_payload, version,
                                           exchange_type, flags, msgid, length)


def build_ikev1_sa(transforms, icookie: bytes | None = None,
                   exchange_type: int = EXCH_MAIN) -> bytes:
    """Build an ISAKMP Phase-1 SA proposal packet: header + SA + proposal + N transforms.

    Deterministic given `icookie` (pass a fixed 8-byte cookie in tests). `exchange_type`
    selects Main (2) vs Aggressive (4). Each transform is a dict with enc/hash/auth/group
    (int id or symbolic name), optional key_length and lifetime (seconds; None omits)."""
    if not transforms:
        raise ValueError("at least one transform is required")
    if icookie is None:
        icookie = os.urandom(8)
    if len(icookie) != 8:
        raise ValueError("initiator cookie must be 8 bytes")
    sa = _ikev1_sa_payload(transforms, next_payload=PT1_NONE)
    hdr = _isakmp_header(icookie, b"\x00" * 8, PT1_SA, IKEV1_VERSION,
                         exchange_type, 0, 0, 28 + len(sa))
    return hdr + sa


# ---------------------------------------------------------------------------
# IKEv2 builder.
# ---------------------------------------------------------------------------
def _ikev2_transform(ttype: int, tid: int, last: bool, keylen=None) -> bytes:
    attrs = _attr_tv(ATTR_KEYLEN, int(keylen)) if keylen else b""
    body = struct.pack("!BBH", ttype, 0, tid) + attrs
    return struct.pack("!BBH", 0 if last else 3, 0, 4 + len(body)) + body


def _ikev2_proposal(prop_num: int, transforms_bytes: bytes, num_transforms: int,
                    last: bool = True, spi: bytes = b"") -> bytes:
    body = struct.pack("!BBBB", prop_num, PROTO_IKE, len(spi), num_transforms) + spi + transforms_bytes
    return struct.pack("!BBH", 0 if last else 2, 0, 4 + len(body)) + body


def _ikev2_generic(next_payload: int, body: bytes) -> bytes:
    return struct.pack("!BBH", next_payload, 0, 4 + len(body)) + body


def build_ikev2_sa_init(dh_groups, ke_data: bytes, nonce: bytes,
                        ispi: bytes | None = None, encr=None, prf=None, integ=None,
                        ke_group: int | None = None) -> bytes:
    """Build an IKEv2 IKE_SA_INIT: header + SA (proposing encr/prf/integ + each dh_group)
    + KE + Nonce. KE public value and nonce are passed in (no in-band DH), so the packet
    is deterministic and testable. `dh_groups` is a list of DH group numbers."""
    dh_groups = [_resolve(g, IKEV2_DH) for g in dh_groups]
    if not dh_groups:
        raise ValueError("at least one DH group is required")
    encr = DEFAULT_IKEV2_ENCR if encr is None else encr
    prf = DEFAULT_IKEV2_PRF if prf is None else prf
    integ = DEFAULT_IKEV2_INTEG if integ is None else integ
    if ispi is None:
        ispi = os.urandom(8)
    if len(ispi) != 8:
        raise ValueError("initiator SPI must be 8 bytes")

    tlist = []
    for tid, keylen in encr:
        tlist.append((TT_ENCR, _resolve(tid, IKEV2_ENCR), keylen))
    for tid in prf:
        tlist.append((TT_PRF, _resolve(tid, IKEV2_PRF), None))
    for tid in integ:
        tlist.append((TT_INTEG, _resolve(tid, IKEV2_INTEG), None))
    for g in dh_groups:
        tlist.append((TT_DH, g, None))

    n = len(tlist)
    tbytes = b"".join(
        _ikev2_transform(tt, tid, last=(i == n - 1), keylen=kl)
        for i, (tt, tid, kl) in enumerate(tlist)
    )
    prop = _ikev2_proposal(1, tbytes, n, last=True)
    sa = _ikev2_generic(PT_KE, prop)
    grp = ke_group if ke_group is not None else dh_groups[0]
    ke = _ikev2_generic(PT_NONCE, struct.pack("!HH", grp, 0) + ke_data)
    non = _ikev2_generic(PT1_NONE, nonce)
    body = sa + ke + non
    hdr = ispi + b"\x00" * 8 + struct.pack("!BBBBII", PT_SA, IKEV2_VERSION,
                                           EXCH_IKE_SA_INIT, FLAG_INITIATOR, 0, 28 + len(body))
    return hdr + body


# ---------------------------------------------------------------------------
# Parser.
# ---------------------------------------------------------------------------
def _named(table: dict, key: int) -> dict:
    return {"id": key, "name": table.get(key, "unknown")}


def _parse_ikev1_transform_attrs(attrs: dict) -> dict:
    out = {
        "encryption": _named(IKEV1_ENC, attrs[ATTR_ENC]) if ATTR_ENC in attrs else None,
        "hash": _named(IKEV1_HASH, attrs[ATTR_HASH]) if ATTR_HASH in attrs else None,
        "authentication": _named(IKEV1_AUTH, attrs[ATTR_AUTH]) if ATTR_AUTH in attrs else None,
        "dh_group": _named(IKEV1_GROUP, attrs[ATTR_GROUP]) if ATTR_GROUP in attrs else None,
    }
    if ATTR_KEYLEN in attrs:
        out["key_length"] = attrs[ATTR_KEYLEN]
    if ATTR_LIFE_DURATION in attrs:
        out["lifetime"] = attrs[ATTR_LIFE_DURATION]
    return out


def _parse_ikev1_sa(body: bytes):
    """SA body = DOI(4) + Situation(4) + Proposal. Return the first transform's classes."""
    if len(body) < 16:
        return None
    prop = body[8:]                                   # skip DOI + Situation
    _np, _res, _plen = struct.unpack("!BBH", prop[0:4])
    _pnum, _proto, spi_size, _ntrans = struct.unpack("!BBBB", prop[4:8])
    off = 8 + spi_size
    if off + 8 > len(prop):
        return None
    _tnp, _tres, tlen = struct.unpack("!BBH", prop[off:off + 4])
    attrs = _parse_attrs(prop[off + 8:off + tlen])
    return _parse_ikev1_transform_attrs(attrs)


def _parse_ikev1_notify(body: bytes):
    # DOI(4) + Protocol(1) + SPI-size(1) + Notify-type(2) + SPI + data
    if len(body) < 8:
        return None
    msgtype = struct.unpack("!H", body[6:8])[0]
    return {"type": msgtype, "name": IKEV1_NOTIFY.get(msgtype, "NOTIFY-%d" % msgtype)}


def _walk_ikev1(buf: bytes, first_np: int, result: dict) -> None:
    np, off = first_np, 0
    while np != PT1_NONE and off + 4 <= len(buf):
        p_np, _res, plen = struct.unpack("!BBH", buf[off:off + 4])
        if plen < 4 or off + plen > len(buf):
            break
        body = buf[off + 4:off + plen]
        result["payloads"].append({"type": np, "name": IKEV1_PAYLOAD.get(np, "?"), "length": plen})
        if np == PT1_SA and result["accepted_transform"] is None:
            result["accepted_transform"] = _parse_ikev1_sa(body)
        elif np == PT1_NOTIFY:
            n = _parse_ikev1_notify(body)
            if n:
                result["notifies"].append(n)
        elif np in (PT1_NATD, PT1_NATD_DRAFT):
            result["nat_t"] = True
        off += plen
        np = p_np


def _record_ikev2_transform(classes: dict, ttype: int, tid: int, attrs: dict) -> None:
    keymap = {TT_ENCR: ("encryption", IKEV2_ENCR), TT_PRF: ("prf", IKEV2_PRF),
              TT_INTEG: ("integrity", IKEV2_INTEG), TT_DH: ("dh_group", IKEV2_DH),
              TT_ESN: ("esn", IKEV2_ESN)}
    if ttype not in keymap:
        return
    key, table = keymap[ttype]
    if key in classes:                                # keep the first of each class
        return
    entry = _named(table, tid)
    if ttype == TT_ENCR and ATTR_KEYLEN in attrs:
        entry["key_length"] = attrs[ATTR_KEYLEN]
    classes[key] = entry


def _parse_ikev2_sa(body: bytes):
    if len(body) < 8:
        return None
    _first, _res, _plen = struct.unpack("!BBH", body[0:4])
    _pnum, _proto, spi_size, num_trans = struct.unpack("!BBBB", body[4:8])
    off = 8 + spi_size
    classes: dict = {}
    for _ in range(num_trans):
        if off + 8 > len(body):
            break
        _tfirst, _tres, tlen = struct.unpack("!BBH", body[off:off + 4])
        ttype, _tres2, tid = struct.unpack("!BBH", body[off + 4:off + 8])
        if tlen < 8:
            break
        attrs = _parse_attrs(body[off + 8:off + tlen])
        _record_ikev2_transform(classes, ttype, tid, attrs)
        off += tlen
    return classes or None


def _parse_ikev2_notify(body: bytes):
    if len(body) < 4:
        return None
    msgtype = struct.unpack("!H", body[2:4])[0]
    return {"type": msgtype, "name": IKEV2_NOTIFY.get(msgtype, "NOTIFY-%d" % msgtype)}


def _walk_ikev2(buf: bytes, first_np: int, result: dict) -> None:
    np, off = first_np, 0
    while np != 0 and off + 4 <= len(buf):
        p_np, _crit, plen = struct.unpack("!BBH", buf[off:off + 4])
        if plen < 4 or off + plen > len(buf):
            break
        body = buf[off + 4:off + plen]
        result["payloads"].append({"type": np, "name": IKEV2_PAYLOAD.get(np, "?"), "length": plen})
        if np == PT_SA and result["accepted_transform"] is None:
            result["accepted_transform"] = _parse_ikev2_sa(body)
        elif np == PT_NOTIFY:
            n = _parse_ikev2_notify(body)
            if n:
                result["notifies"].append(n)
                if n["type"] in (NAT_DETECTION_SOURCE_IP, NAT_DETECTION_DESTINATION_IP):
                    result["nat_t"] = True
        off += plen
        np = p_np


def parse_response(raw: bytes) -> dict:
    """Parse an ISAKMP/IKEv1 or IKEv2 response into a structured dict."""
    result = {"ike_version": None, "exchange_type": None, "exchange_name": None,
              "flags": None, "aggressive_mode": False, "accepted_transform": None,
              "notifies": [], "nat_t": False, "payloads": []}
    if len(raw) < 28:
        result["error"] = "short packet (%d bytes)" % len(raw)
        return result
    next_payload, version, exch, flags, _msgid, _length = struct.unpack("!BBBBII", raw[16:28])
    major = version >> 4
    result["ike_version"] = major
    result["exchange_type"] = exch
    result["flags"] = flags
    if major == 1:
        result["exchange_name"] = IKEV1_EXCH.get(exch, "unknown")
        result["aggressive_mode"] = (exch == EXCH_AGGRESSIVE)
        _walk_ikev1(raw[28:], next_payload, result)
    elif major == 2:
        result["exchange_name"] = IKEV2_EXCH.get(exch, "unknown")
        _walk_ikev2(raw[28:], next_payload, result)
    else:
        result["error"] = "unknown IKE major version %d" % major
    return result


# ---------------------------------------------------------------------------
# Live I/O seam — tests inject a fixture response in place of this.
# ---------------------------------------------------------------------------
def _send(host: str, port: int, packet: bytes, timeout: float = 3.0) -> bytes:
    """Send one UDP datagram and return the first reply (b"" on timeout)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(packet, (host, port))
        data, _addr = s.recvfrom(65535)
        return data
    except (socket.timeout, OSError):
        return b""
    finally:
        s.close()


# ---------------------------------------------------------------------------
# ike-scan wrapper.
# ---------------------------------------------------------------------------
_SA_RE = re.compile(r"SA=\(([^)]*)\)")


def _parse_ike_scan_sa(s: str) -> dict:
    d = {}
    for tok in s.split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            d[k.lower()] = v
    return d


def _parse_ike_scan_output(text: str) -> dict:
    out = {"responded": False, "aggressive_mode": False, "transform": None}
    if "Handshake returned" in text:
        out["responded"] = True
    if "Aggressive Mode Handshake returned" in text:
        out["aggressive_mode"] = True
    m = _SA_RE.search(text)
    if m:
        out["transform"] = _parse_ike_scan_sa(m.group(1))
    return out


def _scan_with_ike_scan(host: str, port: int, aggressive: bool, timeout: float, result: dict) -> None:
    cmd = ["ike-scan"]
    if aggressive:
        cmd.append("-A")
    if port and port != 500:
        cmd.append("--dport=%d" % port)
    cmd.append(host)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max(10, timeout * 3))
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["error"] = "ike-scan failed: %s" % exc
        return
    parsed = _parse_ike_scan_output(proc.stdout)
    result["responded"] = parsed["responded"]
    result["aggressive_mode"] = parsed["aggressive_mode"]
    if parsed["transform"]:
        result["accepted_transform"] = parsed["transform"]
    result["raw_ike_scan"] = proc.stdout.strip()


# ---------------------------------------------------------------------------
# Raw-fallback scan path.
# ---------------------------------------------------------------------------
def _scan_raw(host: str, port: int, ikev2: bool, aggressive: bool, timeout: float, result: dict) -> None:
    if ikev2:
        packet = build_ikev2_sa_init(DEFAULT_DH_GROUPS, b"\x00" * 256, b"\x00" * 32)
    else:
        exch = EXCH_AGGRESSIVE if aggressive else EXCH_MAIN
        packet = build_ikev1_sa(DEFAULT_IKEV1_TRANSFORMS, icookie=os.urandom(8), exchange_type=exch)
    raw = _send(host, port, packet, timeout)
    if not raw:
        return
    result["responded"] = True
    parsed = parse_response(raw)
    result["ike_version"] = parsed["ike_version"] or result["ike_version"]
    result["exchange_type"] = parsed["exchange_type"]
    result["aggressive_mode"] = result["aggressive_mode"] or parsed["aggressive_mode"]
    result["accepted_transform"] = parsed["accepted_transform"]
    result["notifies"] = parsed["notifies"]
    result["nat_t"] = parsed["nat_t"]


def _derive_findings(result: dict) -> list:
    findings = []
    if result.get("aggressive_mode"):
        findings.append({
            "id": "IKE-AGGRESSIVE-MODE",
            "severity": "medium",
            "title": "IKEv1 Aggressive Mode supported",
            "detail": ("The VPN answered an Aggressive Mode Phase-1 request (exchange type 4). "
                       "Aggressive Mode sends the responder identity and a hash of the pre-shared "
                       "key in the clear, enabling offline PSK cracking. Flag the exposure; do not "
                       "crack the hash in-band without explicit authorization."),
        })
    at = result.get("accepted_transform") or {}
    grp = at.get("dh_group") if isinstance(at, dict) else None
    if isinstance(grp, dict) and grp.get("id") in WEAK_DH_GROUPS:
        findings.append({
            "id": "IKE-WEAK-DH-GROUP",
            "severity": "low",
            "title": "Weak Diffie-Hellman group accepted (%s)" % grp.get("name"),
            "detail": ("The head-end accepted DH group %d (%s). Groups 1/2/5 (768/1024/1536-bit "
                       "MODP) are below current strength and susceptible to precomputation "
                       "(Logjam-class) attacks." % (grp.get("id"), grp.get("name"))),
        })
    enc = at.get("encryption") if isinstance(at, dict) else None
    if isinstance(enc, dict) and enc.get("id") == 1:  # DES
        findings.append({
            "id": "IKE-WEAK-CIPHER-DES",
            "severity": "medium",
            "title": "Weak IKE cipher accepted (DES)",
            "detail": "The head-end accepted single-DES for Phase-1 — a broken 56-bit cipher.",
        })
    return findings


def scan(host: str, opts: dict | None = None) -> dict:
    """Enumerate an IKE head-end. Uses ike-scan when present (auto), else the raw path.

    opts: port(500), ikev2(False), aggressive(False), timeout(3.0),
          prefer('auto'|'ike-scan'|'raw' — force a path, used by tests)."""
    opts = opts or {}
    port = opts.get("port", 500)
    ikev2 = bool(opts.get("ikev2", False))
    aggressive = bool(opts.get("aggressive", False))
    timeout = opts.get("timeout", 3.0)
    prefer = opts.get("prefer", "auto")

    result = {"host": host, "port": port, "ike_version": 2 if ikev2 else 1, "method": None,
              "responded": False, "aggressive_mode": False, "accepted_transform": None,
              "notifies": [], "nat_t": False, "findings": []}

    use_ike_scan = (prefer == "ike-scan") or (prefer == "auto" and not ikev2 and _have("ike-scan"))
    if use_ike_scan:
        result["method"] = "ike-scan"
        _scan_with_ike_scan(host, port, aggressive, timeout, result)
    else:
        result["method"] = "raw"
        _scan_raw(host, port, ikev2, aggressive, timeout, result)

    result["findings"] = _derive_findings(result)
    return result


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------
def _human(result: dict) -> str:
    lines = ["IKE enumeration: %s:%d (method=%s)" % (result["host"], result["port"], result["method"])]
    lines.append("  responded: %s   ike_version: v%s" % (result["responded"], result["ike_version"]))
    lines.append("  aggressive_mode: %s   nat_t: %s" % (result["aggressive_mode"], result["nat_t"]))
    at = result.get("accepted_transform")
    if at:
        parts = []
        for k, v in at.items():
            parts.append("%s=%s" % (k, v.get("name") if isinstance(v, dict) else v))
        lines.append("  accepted transform: " + ", ".join(parts))
    for n in result.get("notifies", []):
        lines.append("  NOTIFY: %s (%d)" % (n["name"], n["type"]))
    for f in result.get("findings", []):
        lines.append("  [%s] %s — %s" % (f["severity"].upper(), f["id"], f["title"]))
    if result.get("error"):
        lines.append("  error: %s" % result["error"])
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="IKE/IPsec VPN enumeration (aggressive-mode, transform/DH, NAT-T/NOTIFY).")
    ap.add_argument("host", help="target IP/host (e.g. 203.0.113.10)")
    ap.add_argument("--port", type=int, default=500, help="UDP port (500 or 4500 for NAT-T)")
    ap.add_argument("--ikev2", action="store_true", help="probe IKEv2 (IKE_SA_INIT) instead of IKEv1")
    ap.add_argument("--aggressive", action="store_true", help="probe IKEv1 Aggressive Mode")
    ap.add_argument("--prefer", choices=("auto", "ike-scan", "raw"), default="auto", help="force a scan path")
    ap.add_argument("--timeout", type=float, default=3.0, help="per-probe timeout (seconds)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a human summary")
    args = ap.parse_args(argv)

    result = scan(args.host, {"port": args.port, "ikev2": args.ikev2,
                              "aggressive": args.aggressive, "prefer": args.prefer,
                              "timeout": args.timeout})
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(_human(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
