#!/usr/bin/env python3
"""Classify a filtered/dark host and decide whether a 2nd-vantage escalation is warranted.

When a target answers ping/existence probes but every service is filtered from the
primary runner's egress, the loop must decide WHY before wasting budget: is the host
actually down, geo-fenced (reachable only from another country), behind a per-host
source-IP allowlist (reachable only from a whitelisted egress), or simply reachable
after all? This tool is the reusable classifier that answer that question and, when a
different vantage would help, recommends escalation to the provisioner
(tools/provision_vantage.sh — handle format ``gcp:zone:name``). It NEVER provisions.

Classifications: ``reachable | geo-fence | ip-allowlist | reachable | down | unknown``.
"down" is only ever concluded when a corroborator was actually reached and found the
host absent — an unreachable corroborator yields "unknown" (exit 3), never a
fabricated "down".

PASSIVE (default) vs ACTIVE (opt-in) corroborators
--------------------------------------------------
* DEFAULT passive: Shodan InternetDB (``GET https://internetdb.shodan.io/{ip}``) —
  no packet touches the target, no source IP to register. existence proof = HTTP 200
  with any of ``ports`` / ``hostnames`` / ``vulns`` (404 = absent/unknown).
* OPT-IN active: check-host.net (``--allow-third-party-probe``) is a third-party prober
  that leaks the target IP and connects from source IPs you cannot register — OFF by
  default. When on, it sharpens geo-fence-vs-ip-allowlist (nodes that connected from
  distinct geographies == geo-fence). With it OFF you can still separate
  reachable / ip-allowlist (via InternetDB / PTR / prior report) / down / unknown.

The three cloud CLIs are prechecked (``_provider_auth``) so "no vantage available" is
only concluded when NO provider is authed; a warranted class with an authed provider
yields ``escalation.recommended = true``.

Usage:
  vantage_diagnose.py --ip <ip> [--port 443] [--prior-known-live] [--nodes n1,n2]
                      [--allow-third-party-probe] [--provider-auth] [--json]
  vantage_diagnose.py --provider-auth        # print ONLY the cloud_auth object, exit 0

Exit codes: 0 produced a classification; 3 degraded/unknown (corroborators down);
2 usage error (argparse).

Seams (module-level so tests reassign them — no live network / subprocess in tests):
``_tcp_probe``, ``_http_get``, ``_provider_auth``, ``_resolve_ptr``, ``_sleep``.
"""
from __future__ import annotations

import argparse
import errno
import json
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

VERSION = 1

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
CHECKHOST_TCP_URL = "https://check-host.net/check-tcp?host={host}"
CHECKHOST_RESULT_URL = "https://check-host.net/check-result/{rid}"
# Multi-geo default nodes (only used behind --allow-third-party-probe).
DEFAULT_NODES = ["us1.node.check-host.net", "de1.node.check-host.net", "jp1.node.check-host.net"]
CHECKHOST_MAX_POLLS = 4          # bounded poll loop — never infinite
CHECKHOST_POLL_SECONDS = 2

# The 5-value filtered_signal enum (strict — asserted in tests).
FILTERED_SIGNALS = {
    "host-up-but-all-filtered", "tcp-rst", "icmp-admin-prohibited",
    "ptr-resolves", "prior-report-known-live",
}


# --- network / auth seams (reassigned by tests) ------------------------------
def _tcp_probe(ip: str, port: int, timeout: int = 8) -> tuple:
    """Primary-egress TCP connect. Returns (reachable, signal) with signal in
    {tcp-open, tcp-rst, tcp-timeout, icmp-admin-prohibited}."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, int(port)))
        return (True, "tcp-open")
    except ConnectionRefusedError:
        return (False, "tcp-rst")
    except socket.timeout:
        return (False, "tcp-timeout")
    except OSError as e:
        if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EACCES, errno.EHOSTDOWN):
            return (False, "icmp-admin-prohibited")
        return (False, "tcp-timeout")
    finally:
        try:
            s.close()
        except OSError:
            pass


def _http_get(url: str, timeout: int = 8, headers: dict | None = None) -> tuple:
    """One GET via stdlib urllib. Returns (status, body) where body is a parsed dict
    (JSON) or the raw str. HTTP error responses (4xx/5xx) still return (code, body);
    transport failures (no route / timeout / TLS) propagate — the caller maps those
    to a 'corroborator down' -> unknown, never a fabricated 'down'."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            raw = resp.read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            raw = e.read(200000).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            raw = ""
    try:
        return (status, json.loads(raw))
    except (ValueError, TypeError):
        return (status, raw)


def _provider_auth() -> dict:
    """Run the three cloud-CLI auth idioms. A missing/erroring CLI counts as False."""
    def ok(cmd, need_stdout=False):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        except Exception:  # noqa: BLE001 — CLI absent / timeout / permission
            return False
        if p.returncode != 0:
            return False
        return bool(p.stdout.strip()) if need_stdout else True

    return {
        "gcp": ok(["gcloud", "auth", "list", "--filter=status:ACTIVE",
                   "--format=value(account)"], need_stdout=True),
        "aws": ok(["aws", "sts", "get-caller-identity"]),
        "az": ok(["az", "account", "show"]),
    }


def _resolve_ptr(ip: str) -> str | None:
    try:
        name, _aliases, _addrs = socket.gethostbyaddr(ip)
        return name or None
    except OSError:
        return None


def _sleep(seconds: float) -> None:
    import time
    time.sleep(seconds)


# --- passive + active corroborators ------------------------------------------
def query_internetdb(ip: str, timeout: int) -> dict:
    """Shodan InternetDB existence lookup. Returns a dict with ``reachable`` (was the
    corroborator itself answerable) and, when reachable, ``present`` + the ports /
    hostnames / vulns evidence. reachable=False => corroborator down => unknown."""
    try:
        status, body = _http_get(INTERNETDB_URL.format(ip=ip), timeout=timeout,
                                 headers={"Accept": "application/json"})
    except Exception:  # noqa: BLE001 — transport failure = corroborator unreachable
        return {"reachable": False, "present": False, "ports": [], "hostnames": [], "vulns": []}
    if status >= 500:
        return {"reachable": False, "present": False, "ports": [], "hostnames": [], "vulns": []}
    if status == 404 or not isinstance(body, dict):
        # 404 = host absent from Shodan (a real, usable answer: reachable, not present).
        return {"reachable": True, "present": False, "ports": [], "hostnames": [], "vulns": []}
    ports = body.get("ports") or []
    hostnames = body.get("hostnames") or []
    vulns = body.get("vulns") or []
    return {"reachable": True, "present": bool(ports or hostnames or vulns),
            "ports": ports, "hostnames": hostnames, "vulns": vulns}


def checkhost_probe(ip: str, port: int, nodes: list, timeout: int) -> dict | None:
    """ACTIVE third-party TCP probe via check-host.net from multiple geo nodes.
    Returns {request_id, reachable_from, unreachable_from, nodes_total} or None if the
    probe could not be started. The result poll is a BOUNDED loop (never infinite)."""
    host = f"{ip}:{port}"
    url = CHECKHOST_TCP_URL.format(host=urllib.parse.quote(host)) + \
        "".join("&node=" + urllib.parse.quote(n) for n in nodes)
    try:
        _status, body = _http_get(url, timeout=timeout, headers={"Accept": "application/json"})
    except Exception:  # noqa: BLE001 — active corroborator failed to start
        return None
    if not isinstance(body, dict) or not body.get("request_id"):
        return None
    rid = body["request_id"]

    results: dict = {}
    for _ in range(CHECKHOST_MAX_POLLS):
        _sleep(CHECKHOST_POLL_SECONDS)
        try:
            _s, rbody = _http_get(CHECKHOST_RESULT_URL.format(rid=rid), timeout=timeout,
                                  headers={"Accept": "application/json"})
        except Exception:  # noqa: BLE001 — a transient poll failure; try again
            continue
        if isinstance(rbody, dict):
            results = rbody
            settled = all(results.get(n) is not None for n in nodes) if nodes \
                else all(v is not None for v in results.values())
            if results and settled:
                break

    reachable_from, unreachable_from = [], []
    for node, res in results.items():
        if isinstance(res, list) and res and isinstance(res[0], dict):
            if "address" in res[0]:
                reachable_from.append(node)
            elif "error" in res[0]:
                unreachable_from.append(node)
        # [null] (pending / node unavailable) is neither reachable nor a hard failure
    return {"request_id": rid, "reachable_from": sorted(reachable_from),
            "unreachable_from": sorted(unreachable_from), "nodes_total": len(nodes)}


# --- classification ----------------------------------------------------------
def _cloud_auth_obj() -> dict:
    auth = _provider_auth()
    any_auth = bool(auth.get("gcp") or auth.get("aws") or auth.get("az"))
    return {"gcp": bool(auth.get("gcp")), "aws": bool(auth.get("aws")),
            "az": bool(auth.get("az")), "any": any_auth}


def _filtered_signal(classification: str, prior: bool, ptr: str | None, primary_signal: str) -> str | None:
    if classification not in ("geo-fence", "ip-allowlist"):
        return None
    if prior:
        return "prior-report-known-live"
    if ptr:
        return "ptr-resolves"
    if primary_signal == "tcp-rst":
        return "tcp-rst"
    if primary_signal == "icmp-admin-prohibited":
        return "icmp-admin-prohibited"
    return "host-up-but-all-filtered"


def _escalation(classification: str, cloud_auth: dict) -> dict:
    """geo-fence / ip-allowlist warrant a fresh vantage; recommend one only if a
    provider is authed. All three unauthed => 'no vantage available' (no-cloud-auth)."""
    if classification not in ("geo-fence", "ip-allowlist"):
        return {"recommended": False, "provider": None,
                "reason": f"classification {classification} — no vantage change needed"}
    if not cloud_auth["any"]:
        return {"recommended": False, "provider": None, "reason": "no-cloud-auth"}
    provider = "gcp" if cloud_auth["gcp"] else ("aws" if cloud_auth["aws"] else "az")
    return {"recommended": True, "provider": provider,
            "reason": (f"provision a {provider} vantage via "
                       f"tools/provision_vantage.sh --provider {provider} --region <r> "
                       f"to bypass {classification}")}


def diagnose(ip: str, port: int, prior: bool, allow_third_party: bool,
             nodes: list, timeout: int = 8) -> dict:
    reachable, signal = _tcp_probe(ip, port, timeout)

    # Defaults for the short-circuit (passive seams are NOT called when P is true).
    idb = {"reachable": True, "present": False, "ports": [], "hostnames": [], "vulns": []}
    ptr: str | None = None
    checkhost: dict | None = None
    reachable_from: list = []

    if reachable:
        classification = "reachable"
    else:
        idb = query_internetdb(ip, timeout)
        ptr = _resolve_ptr(ip)
        if allow_third_party:
            checkhost = checkhost_probe(ip, port, nodes, timeout)
            if checkhost:
                reachable_from = checkhost["reachable_from"]
        idb_present = idb["reachable"] and idb["present"]
        if reachable_from:
            classification = "geo-fence"
        elif idb_present or prior or ptr:
            classification = "ip-allowlist"
        elif not idb["reachable"]:
            classification = "unknown"          # corroborator down — never fabricate 'down'
        else:
            classification = "down"

    existence_proof: list = []
    if reachable:
        existence_proof.append(f"primary-egress:{signal}")
    if reachable_from:
        existence_proof.append("check-host:reachable-from=" + ",".join(reachable_from))
    if idb["reachable"] and idb["present"]:
        existence_proof.append("internetdb:ports=" + ",".join(str(p) for p in idb["ports"]))
        if idb["vulns"]:
            existence_proof.append("internetdb:vulns=" + ",".join(idb["vulns"]))
    if ptr:
        existence_proof.append("ptr:" + ptr)
    if prior:
        existence_proof.append("prior-report-known-live")

    cloud_auth = _cloud_auth_obj()
    return {
        "ip": ip,
        "port": port,
        "classification": classification,
        "primary_egress": {"reachable": reachable, "signal": signal},
        "passive": {
            "internetdb": {"present": idb["present"], "ports": idb["ports"],
                           "hostnames": idb["hostnames"], "vulns": idb["vulns"]},
            "checkhost": checkhost,
        },
        "third_party_probe": "on" if allow_third_party else "off",
        "existence_proof": existence_proof,
        "cloud_auth": cloud_auth,
        "escalation": _escalation(classification, cloud_auth),
        "filtered_signal": _filtered_signal(classification, prior, ptr, signal),
        "version": VERSION,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Classify a filtered/dark host (down|geo-fence|ip-allowlist|reachable|unknown) "
                    "and recommend a 2nd-vantage escalation.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ip", help="target IP to diagnose")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--prior-known-live", action="store_true",
                    help="a prior report recorded this host as live (existence prior)")
    ap.add_argument("--nodes", default="",
                    help="comma-separated check-host node ids (multi-geo)")
    ap.add_argument("--allow-third-party-probe", action="store_true",
                    help="enable the ACTIVE check-host.net probe (leaks target IP; off by default)")
    ap.add_argument("--provider-auth", action="store_true",
                    help="print ONLY the cloud_auth object and exit 0 (the JS bash-guard seam)")
    ap.add_argument("--json", action="store_true", help="emit compact single-line JSON")
    args = ap.parse_args()

    if args.provider_auth:
        print(json.dumps(_cloud_auth_obj()))
        return 0

    if not args.ip:
        ap.error("--ip is required")  # argparse exits 2

    nodes = [n.strip() for n in args.nodes.split(",") if n.strip()] or DEFAULT_NODES
    result = diagnose(ip=args.ip, port=args.port, prior=args.prior_known_live,
                      allow_third_party=args.allow_third_party_probe, nodes=nodes)
    print(json.dumps(result) if args.json else json.dumps(result, indent=2))
    return 3 if result["classification"] == "unknown" else 0


if __name__ == "__main__":
    raise SystemExit(main())
