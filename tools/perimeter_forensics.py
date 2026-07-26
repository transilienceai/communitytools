#!/usr/bin/env python3
"""Perimeter forensics: an RST-TTL forgery discriminator + IKE Notify decoder.

Two deterministic, fully-testable primitives for perimeter-appliance engagements.
All arithmetic and parsing live here; the single live-probing step sits behind a
seam (`_probe_ttls`) so nothing in this module touches the network under test —
tests inject the seam and call the pure functions directly.

1. RST-TTL FORGERY DISCRIMINATOR
   The exact ambiguity this resolves produced a FALSE "internal host behind the
   firewall" finding on a perimeter engagement until a skeptic + an active probe
   caught it: a
   firewall configured to *reject* (rather than drop) forges a TCP RST on the
   host's behalf. That crafted RST is indistinguishable from a real closed-port
   RST by flags alone — but NOT by its IP TTL. A single host answers every one of
   its ports from the same network position, so the observed TTL of its RSTs and
   the observed TTL of a genuinely-open service's SYN-ACK imply the SAME hop
   count. When the RSTs imply a DIFFERENT hop count than a real open service (the
   observed case: RSTs ~5 hops, real service ~12), the RSTs are being forged by an
   intermediary filter and are NOT evidence of a live host behind it.

   Critically: on RSTs ALONE, with no open-service baseline to compare against,
   the honest verdict is `undetermined` — the original false finding was asserting
   "internal host" from a lone crafted RST TTL, which this tool refuses to do.

   TTL arithmetic: hosts start the IP TTL at a small set of well-known initial
   values {64, 128, 255}; each router hop decrements it by one. The nearest such
   value at-or-above the observed TTL is the likely initial value, and the
   difference is the hop count.

2. IKE NOTIFY DECODE (`decode_ike_notify`)
   Parse an ISAKMP / IKEv2 Notify payload (generic payload header + Notify body):
   next-payload, protocol-id, SPI size, Notify Message Type (+ name), SPI, and the
   notification data. Notify-type NAMES follow the IKEv2 registry (RFC 7296) — the
   modern authoritative numbering, in which NO_PROPOSAL_CHOSEN is 14 and
   NAT_DETECTION_SOURCE_IP is 16388. (IKEv1/ISAKMP reuses some code points with
   different meanings, e.g. 9 = INVALID_EXCHANGE_TYPE there vs INVALID_MESSAGE_ID
   here; a value like INVALID_MAJOR_VERSION = 5 in a UDP/500 reply is the usual
   tell that a responder is IKEv1-only.)

Usage:
    perimeter_forensics.py --classify-ttls '<json list of {port,state,response_ttl}>' \
        [--open-service-ttl N]
    perimeter_forensics.py --ike-notify <hex>
    perimeter_forensics.py --probe <host> --ports 80,443 [--open-service-ttl N]  # LIVE

Prints a JSON object. Exit 0 on success, 1 on bad input.
"""
import argparse
import json
import sys

# Well-known initial IP TTL values. A host sets one of these; each hop -1.
CANONICAL_INITIAL_TTLS = (64, 128, 255)

# IKEv2 Notify Message Type registry (RFC 7296 + common status types). Error
# types are 1..16383, status types 16384+.
IKE_NOTIFY_TYPES = {
    1: "UNSUPPORTED_CRITICAL_PAYLOAD",
    4: "INVALID_IKE_SPI",
    5: "INVALID_MAJOR_VERSION",
    7: "INVALID_SYNTAX",
    9: "INVALID_MESSAGE_ID",
    11: "INVALID_SPI",
    14: "NO_PROPOSAL_CHOSEN",
    17: "INVALID_KE_PAYLOAD",
    24: "AUTHENTICATION_FAILED",
    34: "SINGLE_PAIR_REQUIRED",
    35: "NO_ADDITIONAL_SAS",
    36: "INTERNAL_ADDRESS_FAILURE",
    37: "FAILED_CP_REQUIRED",
    38: "TS_UNACCEPTABLE",
    39: "INVALID_SELECTORS",
    16384: "INITIAL_CONTACT",
    16385: "SET_WINDOW_SIZE",
    16386: "ADDITIONAL_TS_POSSIBLE",
    16387: "IPCOMP_SUPPORTED",
    16388: "NAT_DETECTION_SOURCE_IP",
    16389: "NAT_DETECTION_DESTINATION_IP",
    16390: "COOKIE",
    16391: "USE_TRANSPORT_MODE",
    16392: "HTTP_CERT_LOOKUP_SUPPORTED",
    16393: "REKEY_SA",
    16394: "ESP_TFC_PADDING_NOT_SUPPORTED",
    16395: "NON_FIRST_FRAGMENTS_ALSO",
}


# ---------------------------------------------------------------------------
# TTL arithmetic
# ---------------------------------------------------------------------------
def guess_initial_ttl(ttl):
    """The smallest well-known initial TTL at-or-above the observed `ttl`.

    An observed TTL of 50 came from an initial 64 (14 hops); 120 from 128; 200
    from 255. Clamps to the maximum for the (invalid) case ttl > 255.
    """
    for c in CANONICAL_INITIAL_TTLS:
        if c >= ttl:
            return c
    return CANONICAL_INITIAL_TTLS[-1]


def hop_estimate(ttl):
    """Router hops implied by an observed TTL = guessed_initial - observed."""
    return guess_initial_ttl(ttl) - ttl


def _analyze_entry(entry):
    """Annotate a probe entry with its guessed initial TTL and hop count."""
    ttl = entry.get("response_ttl")
    out = {"port": entry.get("port"), "state": entry.get("state"), "response_ttl": ttl}
    if isinstance(ttl, int):
        out["initial_ttl"] = guess_initial_ttl(ttl)
        out["hops"] = hop_estimate(ttl)
    return out


def classify(ports_ttls, open_service_ttl=None, tolerance=1):
    """Decide whether observed RSTs come from a real host or a forging filter.

    `ports_ttls` is a list of {port, state, response_ttl}. Entries whose state is
    not "open" and that carry an integer TTL are treated as RST responses; an
    entry with state == "open" (or the explicit `open_service_ttl`) is the
    genuinely-open-service baseline. `tolerance` is the hop jitter (default 1)
    tolerated before two responders are considered to sit at different positions.

    Verdicts:
      * "rst-forged-by-filter"    — RST hop count differs (> tolerance) from the
        open service's hop count, OR (no baseline) the RSTs themselves imply
        divergent hop counts. The RSTs are crafted by an intermediary; they are
        NOT proof of a live host behind the firewall.
      * "consistent-single-host"  — RST and open-service hop counts agree; the
        responses plausibly come from one host.
      * "undetermined"            — RSTs are self-consistent but there is no
        open-service baseline to compare against. NEVER asserts an internal host
        from RSTs alone (this is the forged-RST false-positive guard).
    """
    if not isinstance(ports_ttls, list):
        raise TypeError("ports_ttls must be a list of {port,state,response_ttl}")

    analyzed = [_analyze_entry(e) for e in ports_ttls]
    rst = [a for a in analyzed
           if isinstance(a.get("response_ttl"), int) and a.get("state") != "open"]

    open_ttl = open_service_ttl
    if open_ttl is None:
        opens = [a for a in analyzed
                 if isinstance(a.get("response_ttl"), int) and a.get("state") == "open"]
        if opens:
            open_ttl = opens[0]["response_ttl"]

    rst_hops = sorted({a["hops"] for a in rst})
    base = {"ports": analyzed, "rst_hops": rst_hops}
    open_hops = None
    if open_ttl is not None:
        open_hops = hop_estimate(open_ttl)
        base["open_service_ttl"] = open_ttl
        base["open_service_hops"] = open_hops

    if not rst_hops:
        return dict(base, verdict="undetermined",
                    note="no RST responses to analyze; cannot assess forgery")

    if open_hops is not None:
        # Compare the RST responders' hop counts to the genuinely-open service.
        if any(abs(h - open_hops) > tolerance for h in rst_hops):
            shown = rst_hops if len(rst_hops) > 1 else rst_hops[0]
            return dict(base, verdict="rst-forged-by-filter",
                        note=("RST TTLs imply %s hop(s) but a genuinely-open service is "
                              "%d hop(s) away; the RSTs are forged by an intermediary "
                              "filter and are NOT proof of a live host behind the firewall"
                              % (shown, open_hops)))
        return dict(base, verdict="consistent-single-host",
                    note=("RST and open-service responses agree at ~%d hop(s); "
                          "consistent with a single responding host" % open_hops))

    # No open-service baseline to anchor against.
    if max(rst_hops) - min(rst_hops) > tolerance:
        return dict(base, verdict="rst-forged-by-filter",
                    note=("RSTs from ports that should share one host imply divergent "
                          "hop counts %s; at least some are forged by an intermediary "
                          "filter, not a single live host" % rst_hops))
    return dict(base, verdict="undetermined",
                note="cannot distinguish host RST from filter RST without an open-service baseline")


# ---------------------------------------------------------------------------
# Live probing seam (never exercised by tests; tests monkeypatch _probe_ttls)
# ---------------------------------------------------------------------------
def _probe_ttls(host, ports, timeout=2.0):
    """LIVE seam: SYN-probe each port, recording the observed IP TTL of the reply.

    Returns per-port {port, state, response_ttl}: state "open" (SYN-ACK),
    "closed" (RST), or "filtered" (no reply, response_ttl None). Kept behind this
    seam so all the arithmetic above stays deterministic and offline-testable —
    tests replace this function; classify() never calls the network.
    """
    try:
        from scapy.all import IP, TCP, sr1  # noqa: WPS433 - optional live dependency
    except Exception as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "live probing requires scapy (pip install scapy) and raw-socket "
            "privileges; inject _probe_ttls in tests instead: %s" % exc)
    out = []
    for port in ports:  # pragma: no cover - requires a live target
        ans = sr1(IP(dst=host) / TCP(dport=int(port), flags="S"), timeout=timeout, verbose=0)
        if ans is None:
            out.append({"port": int(port), "state": "filtered", "response_ttl": None})
            continue
        flags = int(ans[TCP].flags) if ans.haslayer(TCP) else 0
        state = "open" if (flags & 0x12) == 0x12 else "closed"  # SYN|ACK vs RST
        out.append({"port": int(port), "state": state, "response_ttl": int(ans[IP].ttl)})
    return out


def probe_and_classify(host, ports, timeout=2.0, open_service_ttl=None, tolerance=1):
    """Live path: probe `host` via the seam, then classify the result offline."""
    return classify(_probe_ttls(host, ports, timeout=timeout),
                    open_service_ttl=open_service_ttl, tolerance=tolerance)


# ---------------------------------------------------------------------------
# IKE / ISAKMP Notify decode
# ---------------------------------------------------------------------------
def decode_ike_notify(payload):
    """Decode an ISAKMP/IKEv2 Notify payload (generic header + Notify body).

    Wire layout (RFC 7296 s3.2/s3.10):
      next_payload(1) | critical+reserved(1) | payload_length(2) |
      protocol_id(1) | spi_size(1) | notify_message_type(2) | spi(spi_size) | data

    `payload` may be a slice of a larger packet; the notify data is bounded by the
    declared payload_length when that is sane, else by the end of the buffer.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")
    b = bytes(payload)
    if len(b) < 8:
        raise ValueError("ISAKMP Notify payload is at least 8 bytes; got %d" % len(b))

    next_payload = b[0]
    # b[1] = critical bit (IKEv2) / RESERVED (ISAKMP); parsed past, not returned.
    payload_length = int.from_bytes(b[2:4], "big")
    protocol_id = b[4]
    spi_size = b[5]
    notify_type = int.from_bytes(b[6:8], "big")

    spi_end = 8 + spi_size
    if spi_end > len(b):
        raise ValueError("SPI size %d overruns %d-byte payload" % (spi_size, len(b)))
    spi = b[8:spi_end]
    end = payload_length if spi_end <= payload_length <= len(b) else len(b)
    data = b[spi_end:end]

    return {
        "next_payload": next_payload,
        "protocol_id": protocol_id,
        "spi_size": spi_size,
        "notify_type": notify_type,
        "notify_name": IKE_NOTIFY_TYPES.get(notify_type, "UNKNOWN"),
        "spi": spi.hex(),
        "data": data.hex(),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--classify-ttls", metavar="JSON",
                      help="JSON list of {port,state,response_ttl} to classify")
    mode.add_argument("--ike-notify", metavar="HEX",
                      help="hex of an ISAKMP/IKEv2 Notify payload to decode")
    mode.add_argument("--probe", metavar="HOST",
                      help="LIVE: SYN-probe HOST (needs --ports and scapy) then classify")
    ap.add_argument("--ports", help="comma-separated ports for --probe")
    ap.add_argument("--open-service-ttl", type=int,
                    help="observed TTL of a genuinely-open service (classify baseline)")
    args = ap.parse_args(argv)

    try:
        if args.classify_ttls is not None:
            result = classify(json.loads(args.classify_ttls),
                              open_service_ttl=args.open_service_ttl)
        elif args.ike_notify is not None:
            result = decode_ike_notify(bytes.fromhex(args.ike_notify.replace(" ", "")))
        else:
            ports = [int(p) for p in (args.ports or "").split(",") if p.strip()]
            if not ports:
                print("ERROR: --probe requires --ports", file=sys.stderr)
                return 1
            result = probe_and_classify(args.probe, ports,
                                        open_service_ttl=args.open_service_ttl)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
