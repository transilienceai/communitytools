#!/usr/bin/env python3
"""Determine which TLS versions a host ACTUALLY supports — by whether a handshake
COMPLETES to exactly the pinned protocol, not by an `openssl s_client` exit code.

Why this exists (an observed openssl exit-code false-positive): shelling to `openssl s_client
-tls1` and reading its exit status wrongly reported TLS 1.0/1.1 as "supported".
The exit code is influenced by SECLEVEL / cipher policy and can be 0 even when the
handshake never negotiated the requested protocol — so a hardened server looked
weak. The fix here is to ask the real question directly with the stdlib `ssl`
module: build an SSLContext with `minimum_version == maximum_version` pinned to
exactly ONE protocol, actually complete the handshake, and count the version as
supported ONLY when the negotiated protocol equals the one we pinned. An aborted /
refused / errored handshake is NOT support.

This is a posture probe, not certificate validation: CERT_NONE + check_hostname
off, so self-signed or posture targets are still measured. It performs one short
TLS handshake per requested version and reads nothing but the negotiated
protocol/cipher — non-destructive.

Interface:
  _handshake(host, port, version, timeout) -> dict   (the connect seam; tests fake it)
  probe(host, port=443, versions=None, timeout=8) -> dict
  CLI: tls_handshake_probe.py <host> [--port 443] [--versions TLSv1,TLSv1.2] [--json]

Usage:
  python3 tools/tls_handshake_probe.py example.test
  python3 tools/tls_handshake_probe.py 203.0.113.10 --port 8443 --versions TLSv1,TLSv1.2 --json
Prints a summary (or JSON with --json) and exits 0.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import ssl
import sys
import warnings

# The four TLS protocol versions this tool measures, in ascending order. The
# spelling matches what ssl.SSLSocket.version() returns, so a negotiated protocol
# compares directly against the requested version string.
DEFAULT_VERSIONS = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]

# Deprecated protocols: their presence is the finding.
WEAK_VERSIONS = {"TLSv1", "TLSv1.1"}

_VERSION_MAP = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _pinned_context(tlsver: "ssl.TLSVersion") -> ssl.SSLContext:
    """A client context pinned to EXACTLY one protocol (min == max), posture-only
    (no cert/hostname validation) so self-signed targets are still measurable."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Pinning TLSv1/TLSv1.1 is deliberate here (we are measuring weak-protocol
    # posture); silence the stdlib's deprecation warning for those on purpose.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = tlsver
        ctx.maximum_version = tlsver
    return ctx


def _connect(host: str, port: int, ctx: ssl.SSLContext, server_hostname, timeout: int):
    """The actual TLS connect. Returns (negotiated_protocol, negotiated_cipher).
    Raises on any socket/TLS error — the caller treats a raise as 'not supported'.
    Isolated as its own seam so _handshake's supported-decision logic is unit
    testable without a live network."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=server_hostname) as ss:
            cipher = ss.cipher()
            return ss.version(), (cipher[0] if cipher else None)


def _handshake(host: str, port: int, version: str, timeout: int = 8) -> dict:
    """Attempt a handshake pinned to EXACTLY `version`. Returns
    {version, supported, negotiated_protocol, negotiated_cipher, error}.

    supported is True ONLY when the handshake COMPLETED and the negotiated
    protocol equals the requested one. A pinned protocol the local OpenSSL build
    refuses to offer, a server that aborts/refuses, a timeout, or a silent
    downgrade to a different protocol all yield supported=False — this is the
    correction to the openssl-exit-code false-positive."""
    result = {"version": version, "supported": False, "negotiated_protocol": None,
              "negotiated_cipher": None, "error": None}
    tlsver = _VERSION_MAP.get(version)
    if tlsver is None:
        result["error"] = "unknown TLS version: %s" % version
        return result
    try:
        ctx = _pinned_context(tlsver)
    except (ValueError, ssl.SSLError) as e:  # build won't even pin this protocol
        result["error"] = "client cannot pin %s: %s" % (version, e)
        return result
    server_hostname = None if _is_ip(host) else host
    try:
        negotiated, cipher = _connect(host, port, ctx, server_hostname, timeout)
    except Exception as e:  # noqa: BLE001 — refused/aborted/timeout/TLS alert => not supported
        result["error"] = str(e)
        return result
    result["negotiated_protocol"] = negotiated
    result["negotiated_cipher"] = cipher
    # The core rule: a completed handshake counts only if it landed on the exact
    # protocol we pinned. Anything else is not support.
    result["supported"] = (negotiated == version)
    return result


def probe(host: str, port: int = 443, versions=None, timeout: int = 8) -> dict:
    """Run _handshake for each requested version (default: all four) and summarise.

    Returns {host, port, results:[...], supported_versions:[...], weak_supported:[...]}
    where supported_versions preserves request order and lists only versions whose
    handshake COMPLETED to that exact protocol; weak_supported is the deprecated
    (TLSv1 / TLSv1.1) subset of that — the finding."""
    if versions is None:
        versions = list(DEFAULT_VERSIONS)
    results = [_handshake(host, port, v, timeout) for v in versions]
    supported = [r["version"] for r in results if r.get("supported")]
    weak = [v for v in supported if v in WEAK_VERSIONS]
    return {"host": host, "port": port, "results": results,
            "supported_versions": supported, "weak_supported": weak}


def _format(summary: dict) -> str:
    lines = ["TLS handshake probe: %s:%s" % (summary["host"], summary["port"]), ""]
    for r in summary["results"]:
        if r["supported"]:
            lines.append("  [supported] %-8s  cipher=%s" % (r["version"], r["negotiated_cipher"]))
        elif r.get("negotiated_protocol") and r["negotiated_protocol"] != r["version"]:
            lines.append("  [ refused ] %-8s  (downgraded to %s — not counted)" % (r["version"], r["negotiated_protocol"]))
        else:
            lines.append("  [ refused ] %-8s  %s" % (r["version"], r.get("error") or "handshake did not complete"))
    lines.append("")
    lines.append("supported: %s" % (", ".join(summary["supported_versions"]) or "(none)"))
    if summary["weak_supported"]:
        lines.append("WEAK/deprecated protocols accepted: %s" % ", ".join(summary["weak_supported"]))
    else:
        lines.append("No deprecated (TLSv1/TLSv1.1) protocols accepted.")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Probe which TLS versions a host actually completes a handshake with.")
    ap.add_argument("host", help="hostname or IP to probe")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--versions", default="", help="comma-separated subset, e.g. TLSv1,TLSv1.2 (default: all four)")
    ap.add_argument("--timeout", type=int, default=8, help="per-handshake timeout seconds (default 8)")
    ap.add_argument("--json", action="store_true", help="emit the raw JSON summary")
    args = ap.parse_args(argv)

    versions = [v.strip() for v in args.versions.split(",") if v.strip()] or None
    summary = probe(args.host, args.port, versions, args.timeout)
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(_format(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
