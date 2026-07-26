#!/usr/bin/env python3
"""Decode an NTLM Type-2 (CHALLENGE) message into host / domain / OS-build intel.

An SMB, HTTP (``WWW-Authenticate: NTLM <b64>``), LDAP, RDP or RPC endpoint that
speaks NTLM answers the negotiate with a Type-2 CHALLENGE. That message carries an
unauthenticated TargetInfo (AV_PAIR) block that leaks, for free: the NetBIOS
computer & domain names, the DNS FQDN, the DNS domain, the DNS tree/forest, a
server timestamp, and — when the server sets NEGOTIATE_VERSION — the exact Windows
build number. This is the "NTLM Type-2 information disclosure" finding raised on
several external network engagements; this tool is that decoder, hand-written twice
before and now promoted to a shared, tested tool.

Interface (stdlib only — base64 / struct / binascii):
  * decode_type2(raw: bytes) -> dict   parse a raw NTLMSSP Type-2 message.
  * decode(s: str) -> dict             accept base64 (the typical WWW-Authenticate
                                       value, optional "NTLM "/"Negotiate " prefix)
                                       OR hex, then dispatch to decode_type2.

CLI:
  python3 tools/ntlm_decode.py <base64-or-hex>
  python3 tools/ntlm_decode.py --stdin        # read the token from stdin
Prints the decode as JSON (indent=2). Exit 0 when it is a valid Type-2 message,
2 on a usage error or when the input is not an NTLMSSP Type-2 message.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import struct
import sys

SIGNATURE = b"NTLMSSP\x00"          # 8-byte NTLMSSP signature
MESSAGE_TYPE_CHALLENGE = 2          # Type-2 = CHALLENGE
NTLMSSP_NEGOTIATE_VERSION = 0x02000000  # server appended an 8-byte Version field

# AV_PAIR (attribute-value pair) identifiers from the TargetInfo block (MS-NLMP).
AV_EOL = 0
AV_NAMES = {
    0: "MsvAvEOL",
    1: "MsvAvNbComputerName",   # NetBIOS computer name
    2: "MsvAvNbDomainName",     # NetBIOS domain name
    3: "MsvAvDnsComputerName",  # DNS computer name (FQDN)
    4: "MsvAvDnsDomainName",    # DNS domain name
    5: "MsvAvDnsTreeName",      # DNS tree / forest name
    6: "MsvAvFlags",            # 4-byte flags
    7: "MsvAvTimestamp",        # 8-byte FILETIME
    8: "MsvAvSingleHost",
    9: "MsvAvTargetName",       # target/SPN
    10: "MsvAvChannelBindings",
}
# AV_PAIRs whose value is a UTF-16LE string.
STRING_AV_IDS = {1, 2, 3, 4, 5, 9}


def _u16le(b: bytes) -> str:
    """UTF-16LE-decode an AV_PAIR / TargetName string, tolerating trailing junk."""
    return b.decode("utf-16-le", "replace")


def _decode_version(v: bytes) -> str:
    """8-byte NTLM Version field -> an OS build string like "10.0.17763".

    Layout: major(1) minor(1) build(2 LE) reserved(3) NTLMRevisionCurrent(1)."""
    major, minor = v[0], v[1]
    (build,) = struct.unpack_from("<H", v, 2)
    return "%d.%d.%d" % (major, minor, build)


def _parse_av_pairs(data: bytes) -> list[tuple[int, bytes]]:
    """Walk the TargetInfo block into (av_id, raw_value) tuples, stopping at EOL.

    Each pair is a 2-byte id, 2-byte length, then that many value bytes. A
    malformed / truncated tail simply ends the walk rather than raising."""
    pairs: list[tuple[int, bytes]] = []
    off, n = 0, len(data)
    while off + 4 <= n:
        av_id, av_len = struct.unpack_from("<HH", data, off)
        off += 4
        if av_id == AV_EOL:
            break
        if off + av_len > n:  # truncated value — stop, keep what we have
            break
        pairs.append((av_id, data[off:off + av_len]))
        off += av_len
    return pairs


def _av_value(av_id: int, vb: bytes):
    """Render an AV_PAIR value: string for names, int FILETIME for the timestamp,
    hex flags for MsvAvFlags, raw hex for anything else."""
    if av_id in STRING_AV_IDS:
        return _u16le(vb)
    if av_id == 6 and len(vb) >= 4:
        (flags,) = struct.unpack_from("<I", vb, 0)
        return "0x%08x" % flags
    if av_id == 7 and len(vb) >= 8:
        (filetime,) = struct.unpack_from("<Q", vb, 0)
        return filetime
    return vb.hex()


def _blank_result() -> dict:
    return {
        "signature_ok": False,
        "message_type": None,
        "target_name": None,
        "netbios_computer": None,
        "netbios_domain": None,
        "dns_computer": None,
        "dns_domain": None,
        "dns_forest": None,
        "os_version": None,
        "server_challenge": None,
        "timestamp_filetime": None,
        "av_pairs": [],
        "negotiate_flags": None,
    }


def decode_type2(raw: bytes) -> dict:
    """Parse a raw NTLMSSP Type-2 (CHALLENGE) message into an intel dict.

    Verifies the 8-byte signature and message type. A buffer that is not an
    NTLMSSP message (bad/short signature, or message type != 2) returns a result
    with ``signature_ok``/``message_type`` reflecting that and no fields filled —
    it never raises for hostile input. A message with a valid signature+type but a
    physically truncated fixed header raises ValueError."""
    res = _blank_result()
    if len(raw) < 8 or raw[:8] != SIGNATURE:
        return res
    res["signature_ok"] = True
    if len(raw) < 12:
        return res  # signature present but no room for the message-type field
    (msg_type,) = struct.unpack_from("<I", raw, 8)
    res["message_type"] = msg_type
    if msg_type != MESSAGE_TYPE_CHALLENGE:
        return res
    if len(raw) < 48:
        raise ValueError("truncated Type-2 message: fixed header < 48 bytes")

    tn_len, _tn_max, tn_off = struct.unpack_from("<HHI", raw, 12)
    (flags,) = struct.unpack_from("<I", raw, 20)
    challenge = raw[24:32]
    ti_len, _ti_max, ti_off = struct.unpack_from("<HHI", raw, 40)

    res["negotiate_flags"] = "0x%08x" % flags
    res["server_challenge"] = challenge.hex()

    if tn_len and tn_off + tn_len <= len(raw):
        res["target_name"] = _u16le(raw[tn_off:tn_off + tn_len])

    # The 8-byte Version field sits at offset 48 only when the flag is set.
    if flags & NTLMSSP_NEGOTIATE_VERSION and len(raw) >= 56:
        res["os_version"] = _decode_version(raw[48:56])

    if ti_len and ti_off + ti_len <= len(raw):
        for av_id, vb in _parse_av_pairs(raw[ti_off:ti_off + ti_len]):
            value = _av_value(av_id, vb)
            res["av_pairs"].append({
                "id": av_id,
                "name": AV_NAMES.get(av_id, "Av%d" % av_id),
                "value": value,
            })
            if av_id == 1:
                res["netbios_computer"] = value
            elif av_id == 2:
                res["netbios_domain"] = value
            elif av_id == 3:
                res["dns_computer"] = value
            elif av_id == 4:
                res["dns_domain"] = value
            elif av_id == 5:
                res["dns_forest"] = value
            elif av_id == 7:
                res["timestamp_filetime"] = value
    return res


def _to_bytes(s: str) -> bytes:
    """Turn a Type-2 token string into raw bytes: strip an auth-scheme prefix, then
    try hex and base64, preferring whichever decode yields the NTLMSSP signature."""
    s = s.strip()
    for prefix in ("NTLM ", "Negotiate "):
        if s[:len(prefix)].lower() == prefix.lower():
            s = s[len(prefix):].strip()
            break
    compact = re.sub(r"\s+", "", s)

    candidates: list[bytes] = []
    if compact and re.fullmatch(r"[0-9a-fA-F]+", compact) and len(compact) % 2 == 0:
        try:
            candidates.append(binascii.unhexlify(compact))
        except (binascii.Error, ValueError):
            pass
    try:
        candidates.append(base64.b64decode(compact, validate=True))
    except (binascii.Error, ValueError):
        pass

    for cand in candidates:
        if cand[:8] == SIGNATURE:
            return cand
    return candidates[0] if candidates else b""


def decode(s: str) -> dict:
    """Decode a Type-2 token given as base64 or hex (see _to_bytes) into the dict."""
    return decode_type2(_to_bytes(s))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Decode an NTLM Type-2 (CHALLENGE) message into host/domain/OS intel.")
    ap.add_argument("token", nargs="?",
                    help="the Type-2 message as base64 (WWW-Authenticate value) or hex")
    ap.add_argument("--stdin", action="store_true", help="read the token from stdin")
    args = ap.parse_args(argv)

    if args.stdin:
        token = sys.stdin.read()
    elif args.token is not None:
        token = args.token
    else:
        ap.error("provide a token argument or --stdin")
        return 2  # unreachable; argparse exits

    try:
        result = decode(token)
    except ValueError as exc:
        print(json.dumps({"error": str(exc), "signature_ok": False}, indent=2))
        return 2

    print(json.dumps(result, indent=2))
    if not result["signature_ok"] or result["message_type"] != MESSAGE_TYPE_CHALLENGE:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
