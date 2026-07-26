#!/usr/bin/env python3
"""Check Point SIC / OPSEC / management fingerprint + CVE-PRECONDITION map.

Given a set of PROBES (one per observed port: openness, banner, and — for an
HTTPS portal — status/headers/body), identify which Check Point management and
OPSEC services are exposed, then emit a map of relevant Check Point CVEs/issues
to their PRECONDITION and a precondition-gated `status`. This tool NEVER fires an
exploit and NEVER asserts "vulnerable": it reports whether the precondition for a
CVE is *met on the observed surface* (`applicable`), *not shown either way*
(`undetermined`), or *absent* (`not_applicable`). The safe check to confirm is
described per entry; the engagement runs it, not this tool.

The headline gate: CVE-2024-24919 (Gaia Portal arbitrary file read) is
`applicable` ONLY when the Remote-Access VPN / Mobile-Access blade marker is
observed on the portal. A Gaia Portal with no such marker is `undetermined`
(the blade may still be on — we just cannot see it) and is NEVER inflated to
`applicable`. This mirrors the precondition-gated methodology of the
network-appliance-offensive skill.

Services fingerprinted (Check Point default ports):
  * SIC        18190 (CPMI) / 18191 (FWM)          — management interface
  * OPSEC      18183 (LEA)  / 18184 (ELA)          — log export / event log
  * CA / ICA   18192 (CPD AMON) / 18210 (ICA pull) — certificate services
  * FW1        256 (control/Topology) / 264 (SecuRemote/Topology)
  * Gaia Portal HTTPS (Server header, /cgi-bin/home.tcl, Gaia/SVN login marker)

Fingerprint + precondition logic is pure and deterministic (stdlib only, no
network) so it is unit-testable offline. Live probing sits behind the module-level
`_probe(host, port, timeout)` seam, which tests inject.

Probe object (extra keys ignored; only `port` is required):

    {
      "port": 18190,
      "open": true,
      "banner": "…raw TCP banner…",           # optional
      "http_status": 200,                       # optional (HTTPS portal)
      "http_headers": {"Server": "…"},          # optional (HTTPS portal)
      "http_body": "…response body…"            # optional (HTTPS portal)
    }

Usage:
    checkpoint_sic_opsec.py --probes <json|path> [--json]
    checkpoint_sic_opsec.py --host 203.0.113.10 [--ports 18190,18191,443] [--json]

`--json` emits compact single-line JSON (default: indented). Exit 0 on success,
2 on a usage/parse error.
"""
import argparse
import json
import os
import re
import socket
import ssl
import sys

# ---- Check Point service map ------------------------------------------------

SIC_PORTS = {18190: "SIC CPMI (management interface)",
             18191: "SIC FWM (management)"}
OPSEC_PORTS = {18183: "OPSEC LEA (log export)",
               18184: "OPSEC ELA (event log)"}
CA_PORTS = {18192: "CPD AMON (monitoring)",
            18210: "ICA pull (FW1_ica_pull certificate)"}
FW1_PORTS = {256: "FW1 (Check Point control / Topology)",
             264: "FW1 SecuRemote / Topology download"}
# Every non-HTTP Check Point service port and its human name.
CP_SERVICE_PORTS = {}
for _m in (SIC_PORTS, OPSEC_PORTS, CA_PORTS, FW1_PORTS):
    CP_SERVICE_PORTS.update(_m)

GAIA_PORTAL_NAME = "Gaia Portal / gateway HTTPS portal"

# Ports that `_probe` (and --host) treats as HTTPS portal candidates.
HTTPS_PORTS = (443, 4434, 4433, 8443)
DEFAULT_HOST_PORTS = tuple(sorted(CP_SERVICE_PORTS)) + (443,)

# ---- marker sets (all matched case-insensitively) ---------------------------

# Strongly Check-Point-specific HTTPS-portal / Gaia login markers.
GAIA_MARKERS = (
    "check point gaia", "gaia portal", "gaia", "home.tcl", "/cgi-bin/home.tcl",
    "cpportal", "check point svn", "svn foundation",
)
# Remote-Access VPN / Mobile-Access blade markers — the CVE-2024-24919 gate.
RA_MARKERS = (
    "mobile access", "ssl network extender", "/clients/mycrl", "cvpn",
    "check point mobile", "connectra", "sslvpn/", "endpoint security vpn",
)
# Any of these on an HTTPS response ⇒ a Check Point web portal is exposed.
CP_HTTPS_MARKERS = tuple(sorted(set(GAIA_MARKERS + RA_MARKERS + ("check point",))))
# SecurePlatform (pre-Gaia) product hints.
SECUREPLATFORM_MARKERS = ("secureplatform", "splat")

_VER_RE = re.compile(r"\bR\d{2}(?:\.\d{1,2})?\b", re.IGNORECASE)


def _probe(host, port, timeout=4.0):
    """LIVE seam: probe one port, return the standard probe dict. Tests inject.

    Non-destructive: a TCP connect + short banner read, and for an HTTPS-portal
    port a single `GET /` over TLS to capture status/headers/body. Never sends an
    exploit payload. Failures degrade to `open: False` rather than raising.
    """
    result = {"port": port, "open": False, "banner": "",
              "http_status": None, "http_headers": {}, "http_body": ""}
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return result
    result["open"] = True
    try:
        if port in HTTPS_PORTS:
            ctx = ssl._create_unverified_context()
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                tls.settimeout(timeout)
                req = ("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
                       "User-Agent: cp-fingerprint\r\n\r\n" % host)
                tls.sendall(req.encode("latin-1"))
                data = _recv_all(tls, timeout)
            status, headers, body = _split_http(data)
            result["http_status"] = status
            result["http_headers"] = headers
            result["http_body"] = body
            result["banner"] = headers.get("Server", "")
        else:
            raw.settimeout(timeout)
            try:
                result["banner"] = raw.recv(2048).decode("latin-1", "replace")
            except OSError:
                result["banner"] = ""
    except OSError:
        pass
    finally:
        try:
            raw.close()
        except OSError:
            pass
    return result


def _recv_all(sock, timeout, cap=65536):
    sock.settimeout(timeout)
    chunks, total = [], 0
    try:
        while total < cap:
            b = sock.recv(4096)
            if not b:
                break
            chunks.append(b)
            total += len(b)
    except OSError:
        pass
    return b"".join(chunks)


def _split_http(data):
    """Parse a raw HTTP response into (status:int|None, headers:dict, body:str)."""
    text = data.decode("latin-1", "replace")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    status = None
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    headers = {}
    for ln in lines[1:]:
        k, sep, v = ln.partition(":")
        if sep:
            headers[k.strip()] = v.strip()
    return status, headers, body


# ---- fingerprint ------------------------------------------------------------

def _probe_text(p):
    """Lowercased haystack of banner + HTTP headers + body for marker matching."""
    parts = []
    if p.get("banner"):
        parts.append(str(p["banner"]))
    if p.get("http_body"):
        parts.append(str(p["http_body"]))
    h = p.get("http_headers")
    if isinstance(h, dict):
        parts.extend("%s: %s" % (k, v) for k, v in h.items())
    elif isinstance(h, (list, tuple)):
        parts.extend(str(x) for x in h)
    elif h:
        parts.append(str(h))
    return " ".join(parts).lower()


def _is_http_like(p):
    return (p.get("http_status") is not None
            or bool(p.get("http_body")) or bool(p.get("http_headers")))


def fingerprint(probes):
    """Identify exposed Check Point services from a list of probe dicts.

    Returns:
        {
          "is_checkpoint": bool,
          "product": "Gaia" | "SecurePlatform" | "unknown",
          "services": [{"port": int, "name": str}, ...],   # sorted by port
          "gaia_portal": bool,               # a Check Point HTTPS portal is exposed
          "remote_access": bool,             # RA VPN / Mobile-Access marker observed
          "version_hint": str,               # e.g. "R81.10" or "" when unknown
          "portal_port": int | None,         # port the portal was seen on
          "open_ports": [int, ...],          # sorted, for evidence
        }
    """
    if not isinstance(probes, list):
        raise ValueError("probes must be a JSON array of probe objects")

    open_ports = sorted({p["port"] for p in probes
                         if isinstance(p, dict) and "port" in p and p.get("open")})

    services = [{"port": port, "name": CP_SERVICE_PORTS[port]}
                for port in open_ports if port in CP_SERVICE_PORTS]

    gaia_portal = remote_access = cp_banner = False
    product = "unknown"
    version_hint = ""
    portal_port = None

    for p in probes:
        if not (isinstance(p, dict) and p.get("open")):
            continue
        text = _probe_text(p)
        if not version_hint:
            m = _VER_RE.search(text)
            if m:
                version_hint = m.group(0).upper()
        if product == "unknown" and any(m in text for m in SECUREPLATFORM_MARKERS):
            product = "SecurePlatform"
        if "check point" in text or "checkpoint" in text:
            cp_banner = True
        if _is_http_like(p) and any(m in text for m in CP_HTTPS_MARKERS):
            gaia_portal = True
            if portal_port is None:
                portal_port = p.get("port")
            if any(m in text for m in RA_MARKERS):
                remote_access = True
            if any(m in text for m in GAIA_MARKERS):
                product = "Gaia"

    if gaia_portal:
        services.append({"port": portal_port, "name": GAIA_PORTAL_NAME})
        if product == "unknown":
            product = "Gaia"          # a CP web portal runs on Gaia by default

    services.sort(key=lambda s: (s["port"] is None, s["port"]))

    is_checkpoint = bool(services) or gaia_portal or cp_banner or product != "unknown"

    return {
        "is_checkpoint": is_checkpoint,
        "product": product,
        "services": services,
        "gaia_portal": gaia_portal,
        "remote_access": remote_access,
        "version_hint": version_hint,
        "portal_port": portal_port,
        "open_ports": open_ports,
    }


# ---- CVE / issue precondition map -------------------------------------------

def cve_preconditions(fp):
    """Map relevant Check Point CVEs/issues to their PRECONDITION + gated status.

    Each entry: {cve|issue, title, precondition, status, evidence, safe_check}
    where status is "applicable" | "undetermined" | "not_applicable". A status is
    NEVER "applicable" unless the observed precondition marker is present.

    Returns [] for a non-Check-Point fingerprint.
    """
    if not fp.get("is_checkpoint"):
        return []

    out = []
    open_ports = fp.get("open_ports") or []

    # --- CVE-2024-24919: Gaia/gateway Portal arbitrary file read -------------
    if fp.get("gaia_portal"):
        if fp.get("remote_access"):
            status = "applicable"
            evidence = ("Check Point HTTPS portal on port %s with a Remote-Access "
                        "VPN / Mobile-Access blade marker observed — the vulnerable "
                        "blade is enabled." % fp.get("portal_port"))
        else:
            status = "undetermined"
            evidence = ("Check Point HTTPS portal on port %s observed, but no "
                        "Remote-Access / Mobile-Access blade marker was seen. The "
                        "blade may still be enabled — cannot confirm the precondition."
                        % fp.get("portal_port"))
    else:
        status = "not_applicable"
        evidence = ("No Check Point HTTPS management / gateway portal was observed "
                    "among the probed ports; the arbitrary-file-read surface is not "
                    "exposed on this surface.")
    out.append({
        "cve": "CVE-2024-24919",
        "title": "Gaia Portal arbitrary file read (Quantum Security Gateway)",
        "precondition": ("Gaia / gateway HTTPS Portal reachable AND the Remote-Access "
                         "VPN or Mobile-Access Software Blade enabled."),
        "status": status,
        "evidence": evidence,
        "safe_check": ("Send ONE crafted POST to /clients/MyCRL requesting a benign, "
                       "world-readable path (e.g. a version/build file) over HTTPS; a "
                       "200 returning file contents confirms the read. Read only benign "
                       "files — never /etc/shadow, secrets, or private keys. "
                       "Non-destructive, single request."),
    })

    # --- SIC management exposed to an untrusted network ----------------------
    sic_open = sorted(p for p in open_ports if p in SIC_PORTS)
    if sic_open:
        out.append({
            "issue": "sic-exposed",
            "title": "SIC (Secure Internal Communication) exposed to untrusted network",
            "precondition": ("TCP 18190 (CPMI) and/or 18191 (FWM) reachable from an "
                             "untrusted network."),
            "status": "applicable",
            "evidence": "SIC management port(s) open: %s." % ", ".join(map(str, sic_open)),
            "safe_check": ("TCP-connect and read the presented SIC certificate / banner "
                           "only. Do NOT attempt SIC one-time-password auth, cpca_client, "
                           "or any key push."),
        })

    # --- OPSEC LEA/ELA log services exposed ----------------------------------
    opsec_open = sorted(p for p in open_ports if p in OPSEC_PORTS)
    if opsec_open:
        out.append({
            "issue": "opsec-lea-ela-exposed",
            "title": "OPSEC LEA/ELA log service exposed",
            "precondition": ("TCP 18183 (LEA) and/or 18184 (ELA) reachable — an "
                             "information-exposure / log-pull surface."),
            "status": "applicable",
            "evidence": "OPSEC port(s) open: %s." % ", ".join(map(str, opsec_open)),
            "safe_check": ("Confirm the port accepts a connection and note any OPSEC "
                           "service banner. Do NOT supply an OPSEC application object / "
                           "SIC certificate to pull logs."),
        })

    # --- ICA certificate pull exposed ----------------------------------------
    ca_open = sorted(p for p in open_ports if p in CA_PORTS)
    if ca_open:
        out.append({
            "issue": "ica-ca-exposed",
            "title": "Internal CA / certificate services exposed",
            "precondition": ("TCP 18192 (CPD AMON) and/or 18210 (ICA pull) reachable — "
                             "certificate-service surface exposed externally."),
            "status": "applicable",
            "evidence": "CA/ICA port(s) open: %s." % ", ".join(map(str, ca_open)),
            "safe_check": ("Observe that the port is reachable and records the ICA/AMON "
                           "banner. Do NOT attempt an ICA certificate pull."),
        })

    return out


# ---- analysis convenience ---------------------------------------------------

def analyze(probes):
    """Full result: fingerprint + preconditions from a list of probe dicts."""
    fp = fingerprint(probes)
    return {"fingerprint": fp, "preconditions": cve_preconditions(fp)}


def probe_host(host, ports=None, timeout=4.0):
    """Live-probe `ports` on `host` via the `_probe` seam; return probe dicts."""
    ports = ports or DEFAULT_HOST_PORTS
    return [_probe(host, port, timeout) for port in ports]


# ---- CLI --------------------------------------------------------------------

def _load_json_arg(val):
    """Accept either an inline JSON string or a path to a JSON file."""
    if os.path.isfile(val):
        with open(val) as fh:
            return json.load(fh)
    return json.loads(val)


def _parse_ports(spec):
    return [int(x) for x in spec.replace(",", " ").split()]


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--probes",
                    help="probe objects as a JSON array (string) or a path to a JSON file")
    ap.add_argument("--host",
                    help="live-probe this host via the _probe seam instead of --probes")
    ap.add_argument("--ports", help="comma/space list of ports for --host "
                    "(default: Check Point service ports + 443)")
    ap.add_argument("--timeout", type=float, default=4.0, help="per-port probe timeout (s)")
    ap.add_argument("--json", action="store_true",
                    help="emit compact single-line JSON (default: indented)")
    args = ap.parse_args(argv)

    if not args.probes and not args.host:
        ap.error("one of --probes or --host is required")

    try:
        if args.host:
            ports = _parse_ports(args.ports) if args.ports else None
            probes = probe_host(args.host, ports, args.timeout)
        else:
            probes = _load_json_arg(args.probes)
        result = analyze(probes)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
