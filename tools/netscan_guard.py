#!/usr/bin/env python3
"""
netscan_guard — soundness guards over nmap XML output (NETWORK-mode scans).

Dependency-free (stdlib `xml.etree.ElementTree` only). Two modes:

  VERDICT (post-scan)      netscan_guard.py --xml <path-or-glob> [--suppress-cves] [--cves a,b]
  CAPABILITY (pre-scan)    netscan_guard.py --capability-check [--prior-xml P] [--uid N]
                                            [--full-range] [--udp]

It catches the recurring failure modes that make a network sweep quietly lie:

  1. host-timeout truncation — an unprivileged connect scan (`-sT`) run with
     `--host-timeout` can be cut off before any port is probed, yielding a false
     "zero exposure" for hosts that are actually up. When every up-host shows 0
     open ports under those conditions the verdict is UNSOUND and the hosts must
     be re-scanned before they are called dead.
  2. capability / RTT — an unprivileged vantage cannot craft raw SYN/UDP packets
     and its socket table exhausts at high rates (false 'filtered'). Advises the
     `-sT` + `--max-rate` cap, an RTT-timeout floor derived from a prior scan's
     sRTT, and whether a full-range / UDP scan should be routed to a root vantage.
  3. banner-artifact CVE suppression — MariaDB prepends "5.5.5-" to its reported
     version for MySQL client compatibility, so a naive CPE match invents phantom
     MySQL-5.5.5 CVEs. Seeded, extensible suppression table.
  4. UDP states — `open|filtered` is a *timeout*, not a confirmed open port, and
     must never be counted as exposure; only `open` with a real response is.

Output is JSON (indent=2). Exit codes:
  0   SOUND, or a capability report was produced
  20  UNSOUND — caller MUST re-scan `rescan_hosts` before calling them dead
  3   no parseable <nmaprun> in any file / empty glob (verdict mode)
  2   usage error
"""

import argparse
import glob as globmod
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

VERSION = 1

# UDP "open" with one of these reasons is really a timeout, not a response.
_TIMEOUT_REASONS = {"no-response", "no-reply", "no-responses"}

# Guard 3 — banner artifacts that make a naive CPE match surface phantom CVEs.
# Each rule fires when a *service* matches (product_re / banner_re / version_prefix);
# once fired, any candidate CVE/CPE matching a `suppress` pattern is filtered out.
SUPPRESS_TABLE = [
    {
        "name": "mariadb-5.5.5-mysql-phantom",
        "product_re": r"(?i)mariadb",
        "version_prefix": "5.5.5-",
        "banner_re": r"5\.5\.5-",
        "suppress": [
            r"(?i)cpe:/a:mysql:mysql:5\.5\.5",
            r"(?i)cpe:2\.3:a:mysql:mysql:5\.5\.5",
            r"(?i)\bmysql\b.*5\.5\.5",
        ],
        "reason": (
            "MariaDB prepends '5.5.5-' to its reported version for MySQL client "
            "protocol compatibility (the real version is the suffix, e.g. 10.3.34). "
            "A naive CPE match reads this as MySQL 5.5.5 and surfaces phantom MySQL "
            "5.5.5 CVEs that do not apply to MariaDB."
        ),
    },
]


# --------------------------------------------------------------------------- #
# Guard 3 — banner-artifact CVE suppression
# --------------------------------------------------------------------------- #
def _service_matches_rule(svc, rule):
    """True iff a service triggers a suppression rule (product / banner / version)."""
    product = (svc.get("product") or "")
    version = (svc.get("version") or "")
    banner = (svc.get("banner") or (product + " " + version)).strip()
    if rule.get("product_re") and product and re.search(rule["product_re"], product):
        return True
    if rule.get("banner_re") and banner and re.search(rule["banner_re"], banner):
        return True
    vp = rule.get("version_prefix")
    if vp and version.startswith(vp):
        return True
    return False


def _candidate_text(cand):
    """Searchable string for a candidate CVE (id / cpe / product context)."""
    if isinstance(cand, dict):
        parts = [str(cand.get(k, "")) for k in ("text", "cve", "id", "cpe", "product", "version")]
        return " ".join(p for p in parts if p)
    return str(cand)


def _candidate_id(cand):
    if isinstance(cand, dict):
        return cand.get("cve") or cand.get("id") or _candidate_text(cand)
    return str(cand)


def suppress_cves(services, candidate_cves):
    """Filter phantom CVEs produced by banner artifacts.

    A rule fires from the `services` present; each candidate whose text matches a
    fired rule's `suppress` pattern is dropped (scoped to the firing service's IP
    when the candidate carries one). Returns {"suppressed":[...], "kept":[...]}.
    """
    fired = [(rule, svc)
             for rule in SUPPRESS_TABLE
             for svc in services
             if _service_matches_rule(svc, rule)]
    suppressed, kept = [], []
    for cand in candidate_cves:
        text = _candidate_text(cand)
        cid = _candidate_id(cand)
        cand_ip = cand.get("ip") if isinstance(cand, dict) else None
        hit = None
        for rule, svc in fired:
            if cand_ip and svc.get("ip") and cand_ip != svc.get("ip"):
                continue
            if any(re.search(pat, text) for pat in rule.get("suppress", [])):
                hit = (rule, svc)
                break
        if hit:
            entry = {"cve": cid, "reason": hit[0]["reason"]}
            if hit[1].get("ip"):
                entry["ip"] = hit[1]["ip"]
            suppressed.append(entry)
        else:
            kept.append(cid)
    return {"suppressed": suppressed, "kept": kept}


# --------------------------------------------------------------------------- #
# nmap XML parsing
# --------------------------------------------------------------------------- #
def _host_ip(host_el):
    addrs = host_el.findall("address")
    for want in ("ipv4", "ipv6"):
        for a in addrs:
            if a.get("addrtype") == want:
                return a.get("addr")
    return addrs[0].get("addr") if addrs else None


def parse_vulners_output(text):
    """Yield (cpe, cve) pairs from an nmap 'vulners' NSE script output blob.

    vulners groups CVE rows under a `cpe:/...` header line; the header carries the
    (possibly phantom) product/version that generated the finding.
    """
    cpe = ""
    seen = set()  # a vulners row repeats its CVE id in the trailing URL — dedupe.
    for line in (text or "").splitlines():
        s = line.strip().lstrip("|").strip()
        if s.lower().startswith("cpe:") and "CVE-" not in s.upper():
            cpe = s.rstrip(":").strip()
            continue
        for m in re.finditer(r"CVE-\d{4}-\d{4,}", s):
            key = (cpe, m.group(0))
            if key not in seen:
                seen.add(key)
                yield cpe, m.group(0)


def parse_scan(path):
    """Parse one nmap XML file into a normalized dict, or None if not an <nmaprun>."""
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError, ValueError):
        return None
    if root.tag != "nmaprun":
        return None

    args = root.get("args", "") or ""
    scaninfo_types = [si.get("type", "") for si in root.findall("scaninfo")]
    hosts, services, candidates, times = [], [], [], []

    for h in root.findall("host"):
        st = h.find("status")
        state = st.get("state") if st is not None else None
        ip = _host_ip(h)
        tcp_open, udp_ports = [], []

        ports_el = h.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                proto = p.get("protocol", "")
                portid = p.get("portid", "")
                se = p.find("state")
                pstate = se.get("state", "") if se is not None else ""
                preason = se.get("reason", "") if se is not None else ""
                if proto == "tcp" and pstate == "open":
                    tcp_open.append(portid)
                if proto == "udp":
                    udp_ports.append({"ip": ip, "port": portid,
                                      "state": pstate, "reason": preason})
                svc = p.find("service")
                if svc is not None:
                    product = svc.get("product", "") or ""
                    version = svc.get("version", "") or ""
                    extra = svc.get("extrainfo", "") or ""
                    services.append({
                        "ip": ip, "port": portid, "protocol": proto,
                        "name": svc.get("name", "") or "",
                        "product": product, "version": version,
                        "banner": " ".join(x for x in (product, version, extra) if x),
                    })
                for scr in p.findall("script"):
                    if scr.get("id") == "vulners":
                        for cpe, cve in parse_vulners_output(scr.get("output", "")):
                            candidates.append({"cve": cve, "cpe": cpe, "ip": ip,
                                               "text": " ".join(x for x in (cve, cpe) if x)})

        for scr in h.findall("hostscript/script"):
            if scr.get("id") == "vulners":
                for cpe, cve in parse_vulners_output(scr.get("output", "")):
                    candidates.append({"cve": cve, "cpe": cpe, "ip": ip,
                                       "text": " ".join(x for x in (cve, cpe) if x)})

        for t in h.findall("times"):
            srtt = t.get("srtt")
            if srtt and srtt.lstrip("-").isdigit():
                times.append(int(srtt))

        hosts.append({"ip": ip, "state": state,
                      "tcp_open": tcp_open, "udp_ports": udp_ports})

    return {
        "path": path, "args": args, "scaninfo_types": scaninfo_types,
        "hosts": hosts, "services": services, "candidates": candidates, "times": times,
    }


# --------------------------------------------------------------------------- #
# Guard 1 — host-timeout truncation
# --------------------------------------------------------------------------- #
def host_timeout_guard(scans):
    """UNSOUND iff `--host-timeout` + a connect scan + every up-host has 0 open TCP
    ports (a zero that could be an artifact of truncation rather than real closure)."""
    args = " ".join(s["args"] for s in scans)
    tokens = args.split()
    has_ht = "--host-timeout" in args
    types = [t for s in scans for t in s["scaninfo_types"]]
    is_connect = ("-sT" in tokens) or ("connect" in types)

    up_zero, any_open, up_total = [], False, 0
    for s in scans:
        for h in s["hosts"]:
            if h["state"] == "up":
                up_total += 1
                if h["tcp_open"]:
                    any_open = True
                elif h["ip"] is not None:
                    up_zero.append(h["ip"])

    unsound = bool(has_ht and is_connect and not any_open and up_zero)
    if unsound:
        reason = ("--host-timeout on a connect (-sT) scan and every up-host has 0 open "
                  "TCP ports; the zero may be truncation, not real closure. Re-scan "
                  "rescan_hosts (no host-timeout, or a raw-socket vantage) before calling them dead.")
    elif not has_ht:
        reason = "No --host-timeout in args; a zero-open result cannot be attributed to truncation."
    elif not is_connect:
        reason = "Not a connect scan; a zero-open result cannot be attributed to connect-scan truncation."
    elif any_open:
        reason = "At least one up-host has an open port; the scan reached the ports (not truncated)."
    else:
        reason = "No up-hosts with 0 open ports."

    return {
        "verdict": "UNSOUND" if unsound else "SOUND",
        "unsound": unsound,
        "has_host_timeout": has_ht,
        "is_connect_scan": is_connect,
        "up_hosts": up_total,
        "any_up_host_with_open_port": any_open,
        "rescan_hosts": up_zero,
        "reason": reason,
    }


# --------------------------------------------------------------------------- #
# Guard 4 — UDP states
# --------------------------------------------------------------------------- #
def udp_guard(scans):
    """Separate confirmed-open UDP ports from `open|filtered` timeouts."""
    true_open, ambiguous = [], []
    for s in scans:
        for h in s["hosts"]:
            for p in h["udp_ports"]:
                rec = {"ip": p["ip"], "port": p["port"], "reason": p["reason"]}
                if p["state"] == "open|filtered":
                    ambiguous.append(rec)
                elif p["state"] == "open" and p["reason"] not in _TIMEOUT_REASONS:
                    true_open.append(rec)
                elif p["state"] == "open":
                    # 'open' but the reason is a timeout — do not count as exposure.
                    ambiguous.append(rec)
    return {
        "true_open": true_open,
        "ambiguous_open_filtered": ambiguous,
        "note": ("open|filtered means no UDP response was received (a timeout); it is "
                 "NOT a confirmed open port and must not be counted as exposure."),
    }


# --------------------------------------------------------------------------- #
# Guard 3 driver (CLI)
# --------------------------------------------------------------------------- #
def cve_suppression_guard(scans, extra_cves):
    services = [svc for s in scans for svc in s["services"]]
    candidates = [c for s in scans for c in s["candidates"]]
    for cid in extra_cves:
        candidates.append({"cve": cid, "text": cid})
    result = suppress_cves(services, candidates)
    result["enabled"] = True
    result["services_considered"] = len(services)
    result["candidates_considered"] = len(candidates)
    return result


# --------------------------------------------------------------------------- #
# Guard 2 — capability / RTT (pre-scan)
# --------------------------------------------------------------------------- #
def capability_check(uid, full_range, udp, prior_xml_paths):
    """Pre-scan advisory: raw-packet capability, socket-table cap, RTT floor, routing."""
    privileged = (uid == 0)
    recs, limitations = [], []

    if privileged:
        recs.append("-sS")
    else:
        recs.append("-sT")            # unprivileged: cannot craft raw SYN packets
        recs.append("--max-rate 500")  # cap: connect-scan socket exhaustion -> false 'filtered'
        limitations.append(
            "Unprivileged (uid != 0): raw-packet scans (-sS/-sU/-O) are unavailable; the "
            "connect scan (-sT) exhausts the local socket table at high rates, producing "
            "false 'filtered' results — hence the --max-rate cap.")

    parsed, all_times = [], []
    for p in prior_xml_paths:
        sc = parse_scan(p)
        if sc:
            parsed.append(p)
            all_times.extend(sc["times"])
    rtt_floor = max(all_times) if all_times else None
    if rtt_floor is not None:
        recs.append("--initial-rtt-timeout %dus" % rtt_floor)
        recs.append("--max-rtt-timeout %dus" % (rtt_floor * 2))
        limitations.append(
            "Prior-scan sRTT floor is %d us; RTT timeouts below this drop slow hosts as "
            "false 'down'/'filtered'." % rtt_floor)

    route = (not privileged) and (full_range or udp)
    if route:
        limitations.append(
            "Unprivileged vantage requested a full-range and/or UDP (-sU) scan; route to a "
            "root-capable vantage (raw sockets) to avoid systematic false negatives.")

    cap = {
        "uid": uid,
        "privileged": privileged,
        "recommendations": recs,
        "rtt_floor_us": rtt_floor,
        "full_range_requested": full_range,
        "udp_requested": udp,
        "route_to_root_vantage": route,
    }
    return cap, parsed, limitations


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _build_limitations(ht, udp, suppress_enabled):
    lim = ["Static analysis of nmap XML only; performs no network I/O."]
    if ht["has_host_timeout"] and not ht["is_connect_scan"]:
        lim.append("--host-timeout present but the scan is not a connect scan; a zero-open "
                   "result cannot be attributed to truncation and is left SOUND — verify independently.")
    amb = udp["ambiguous_open_filtered"]
    if amb:
        lim.append("%d UDP port(s) are open|filtered (a timeout, not a confirmed open port); "
                   "excluded from the open count." % len(amb))
    if not suppress_enabled:
        lim.append("CVE banner-artifact suppression not run (pass --suppress-cves); phantom CVEs "
                   "from mislabeled banners (e.g. MariaDB '5.5.5-') are not filtered.")
    return lim


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter, add_help=True)
    ap.add_argument("--xml", help="nmap XML path or glob (verdict mode)")
    ap.add_argument("--capability-check", action="store_true", help="pre-scan capability advisory")
    ap.add_argument("--prior-xml", help="prior nmap XML for the sRTT floor (capability mode)")
    ap.add_argument("--uid", type=int, help="assume this uid (default: os.getuid())")
    ap.add_argument("--full-range", action="store_true", help="a full-range (all-port) scan is planned")
    ap.add_argument("--udp", action="store_true", help="a UDP (-sU) scan is planned")
    ap.add_argument("--suppress-cves", action="store_true", help="run banner-artifact CVE suppression")
    ap.add_argument("--cves", help="comma-separated candidate CVE ids to vet")
    args = ap.parse_args(argv)

    if args.capability_check:
        uid = args.uid if args.uid is not None else os.getuid()
        prior = [args.prior_xml] if args.prior_xml else []
        cap, parsed, limitations = capability_check(uid, args.full_range, args.udp, prior)
        out = {
            "mode": "capability-check",
            "files": parsed,
            "capability": cap,
            "guards": {},
            "rescan_hosts": [],
            "limitations": limitations,
            "sound": True,
            "version": VERSION,
        }
        print(json.dumps(out, indent=2))
        return 0

    if not args.xml:
        print("usage: netscan_guard.py --xml <path-or-glob> [--suppress-cves] [--cves a,b] | "
              "--capability-check [--prior-xml P] [--uid N] [--full-range] [--udp]", file=sys.stderr)
        return 2

    paths = sorted(globmod.glob(args.xml))
    scans = [sc for sc in (parse_scan(p) for p in paths) if sc]
    if not scans:
        print(json.dumps({
            "mode": "verdict", "files": [],
            "error": "no parseable <nmaprun> found (empty glob or non-nmap XML)",
            "guards": {}, "rescan_hosts": [], "limitations": [], "sound": False, "version": VERSION,
        }, indent=2))
        return 3

    ht = host_timeout_guard(scans)
    udp = udp_guard(scans)
    extra_cves = [c.strip() for c in (args.cves or "").split(",") if c.strip()]
    cve = cve_suppression_guard(scans, extra_cves) if args.suppress_cves else {"enabled": False}

    unsound = ht["unsound"]
    out = {
        "mode": "verdict",
        "files": [s["path"] for s in scans],
        "guards": {
            "host_timeout_truncation": ht,
            "udp_states": udp,
            "cve_suppression": cve,
        },
        "rescan_hosts": ht["rescan_hosts"] if unsound else [],
        "limitations": _build_limitations(ht, udp, args.suppress_cves),
        "sound": not unsound,
        "version": VERSION,
    }
    print(json.dumps(out, indent=2))
    return 20 if unsound else 0


if __name__ == "__main__":
    raise SystemExit(main())
