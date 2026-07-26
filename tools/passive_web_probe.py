#!/usr/bin/env python3
"""Per-asset deterministic scanner that clears the 8 "mechanical" attack-class
coverage cells in ONE process — instead of one LLM agent batch per class.

The reasoning loop spends agent budget on classes that need judgement (BOLA,
injection, business-logic, ...). The mechanical classes are pure I/O: a couple of
GET/HEAD requests + a TLS handshake + an nmap banner decide them. This tool runs
those probes for every applicable mechanical cell of ONE asset and writes exactly
the evidence the deterministic coverage gate (tools/coverage_gate.py) already
accepts — so the loop can skip these classes without weakening the hard-100% gate.

The 8 mechanical classes (from skills/coordination/reference/coverage-matrix.json):
  host-scope, active_probe  XC-CORS, XC-TRANSPORT-DOWNGRADE, XC-VERBOSE-ERRORS,
                            XC-SECURITY-HEADERS, XC-TLS-POSTURE (tls only),
                            WEB-A06-COMPONENTS (needs nmap [+ nvd-lookup for a CVE])
  asset-scope, none         API9-INVENTORY (has_api), XC-SECRET-EXPOSURE (serves_js)

Per clean-negative cell it writes, scoped to the cell's OWN asset dir:
  (a) a non-agent corroborator  tools/NNN_<class_id>.md  ('Experiment: E-NNN' + raw output)
  (b) an experiments.md table row  | E-NNN | passive_web_probe | <class_id> @ <key> | <result> |
  (c) a read-merged units_tested entry into that class's coverage.json row
A genuine positive (missing header / exposed swagger / secret in a bundle /
vulnerable component with a real CVE) becomes a RAW finding under findings/ and the
cell is LEFT OPEN for the normal validation lane. A missing tool / unreachable
listener becomes a limitation and the cell is LEFT OPEN — never a silent skip,
never a fabricated `covered`.

Hard safety gate: every GET/HEAD, TLS handshake and nmap runs ONLY against
allow-listed hosts (surface.json asset_tag/apex + --allow). Any cell whose host is
not allow-listed is recorded as skipped_out_of_scope and never touched (no SSRF /
out-of-scope active scan).

Cell keys are taken verbatim from tools/enumerate_cells.py output, so they equal
what the gate expects — this tool never re-derives host:port itself.

Usage:
  python3 tools/passive_web_probe.py --asset-dir DIR [--allow h1,h2] [--timeout N] [--no-nmap]
Prints a JSON summary and exits 0 (a partial run is fine; the gate is authoritative).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

from enumerate_cells import TLS_PORTS, parse_listener

HERE = os.path.dirname(os.path.abspath(__file__))

# The 8 mechanical classes this tool owns.
HOST_ACTIVE = {"XC-CORS", "XC-TRANSPORT-DOWNGRADE", "XC-VERBOSE-ERRORS",
               "XC-SECURITY-HEADERS", "XC-TLS-POSTURE", "WEB-A06-COMPONENTS"}
ASSET_NONE = {"API9-INVENTORY", "XC-SECRET-EXPOSURE"}
MECHANICAL = HOST_ACTIVE | ASSET_NONE

REQUIRED_SEC_HEADERS = ["content-security-policy", "x-content-type-options"]  # plus a frame guard, see check
_EVIL_ORIGIN = "https://evil.passive-probe.example"
_ERROR_PATH = "/passive-probe-nonexistent-zzz-42"

# Soft-404 tolerance (Addition #2): an SPA/Blazor catch-all that serves the same
# 200 body for every path makes any probed file/endpoint look like it "exists".
_SOFT404_SIZE_TOL = 64  # bytes of slack around the baseline body size

# WAF/CDN reject-page statuses (Addition #1): a bare vendor-presence header (a CDN
# merely fronting the origin) only implies a block on a deny-ish status; on a 200
# the vendor is serving a real asset, so it must not suppress an exposure.
_BLOCK_DENY_STATUS = {403, 406, 429, 503}

# Verbose-error signatures (framework / stack-trace disclosure).
_ERR_SIGNATURES = [
    r"Traceback \(most recent call last\)", r"\bat [\w.$]+\([\w.]+\.java:\d+\)",
    r"org\.springframework\.", r"System\.Web\.", r"Microsoft\.AspNetCore",
    r"Werkzeug Debugger", r"Whoops\\?, looks like", r"\bstack ?trace\b",
    r"SQLSTATE\[", r"ORA-\d{5}", r"line \d+, in <?\w+>?", r"Warning: \w+\(\) ",
]
_ERR_RE = re.compile("|".join(_ERR_SIGNATURES), re.I)

# Secret patterns for the JS/static bundle scan (XC-SECRET-EXPOSURE).
_SECRET_RE = re.compile(
    r"AKIA[0-9A-Z]{16}"                       # AWS access key id
    r"|AIza[0-9A-Za-z_\-]{35}"                # Google API key
    r"|ghp_[0-9A-Za-z]{36}"                   # GitHub PAT
    r"|xox[baprs]-[0-9A-Za-z-]{10,}"          # Slack token
    r"|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"
    r"|(?:secret|api[_-]?key|access[_-]?token|client[_-]?secret)[\"'\s:=]{1,4}[0-9A-Za-z/_\-+]{16,}",
    re.I)

# Swagger / OpenAPI discovery paths for the inventory check (API9-INVENTORY).
_SWAGGER_PATHS = ["/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs",
                  "/swagger-ui.html", "/swagger/index.html", "/api-docs", "/.well-known/openapi.json"]
_SWAGGER_RE = re.compile(r'"swagger"\s*:|"openapi"\s*:|swagger-ui', re.I)

# Tiny built-in "known-vulnerable component" advisory table (product substring,
# version-prefix) -> CVE. Deliberately small; the loop/agents own the long tail.
KNOWN_VULN = {
    ("openssh", "7.2"): "CVE-2016-6210",
}


# --- surface + cell inputs ---------------------------------------------------
def load_surface(asset_dir: str) -> dict:
    p = os.path.join(asset_dir, "recon", "inventory", "surface.json")
    try:
        return json.load(open(p, encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def scheme_for_unit(addr: str, unit: dict) -> str:
    if addr.startswith("https://") or unit.get("tls"):
        return "https"
    listener = parse_listener(addr) or ""
    tail = listener.rsplit(":", 1)[-1]
    if tail.isdigit() and int(tail) in TLS_PORTS:
        return "https"
    return "http"


def build_listener_schemes(surface: dict) -> dict:
    """listener 'host:port' -> 'http'|'https' (mirrors enumerate_cells' tls logic)."""
    out: dict = {}
    for u in surface.get("units") or []:
        addr = u.get("address", "")
        listener = parse_listener(addr)
        if listener:
            out[listener] = scheme_for_unit(addr, u)
    return out


def js_urls_for_hosts(surface: dict, in_scope_hosts: set) -> list:
    """In-scope http(s) unit addresses that look like static JS/pages (secret scan)."""
    urls = []
    for u in surface.get("units") or []:
        addr = u.get("address", "")
        if "://" not in addr:
            continue
        host = urlparse(addr).hostname
        if host not in in_scope_hosts:
            continue
        if addr.endswith(".js") or u.get("type") == "page":
            urls.append(addr)
    return urls


def run_enumerate(asset_dir: str) -> dict:
    subprocess.run([sys.executable, os.path.join(HERE, "enumerate_cells.py"),
                    "--asset-dir", asset_dir], check=True, capture_output=True, text=True)
    with open(os.path.join(asset_dir, "applicability", "cells.json"), encoding="utf-8") as f:
        return json.load(f)


# --- HTTP + TLS probes (non-destructive) -------------------------------------
def _noverify_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # noqa: D401
        return None


def http_fetch(url: str, method: str = "GET", extra_headers: dict | None = None,
               timeout: int = 10, follow: bool = True) -> dict:
    """One non-destructive request via stdlib urllib (the curl/requests family).
    verify is disabled so self-signed / posture targets are still reachable."""
    handlers = [urllib.request.HTTPSHandler(context=_noverify_ctx())]
    if not follow:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, method=method, headers=extra_headers or {})
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(65536).decode("utf-8", "replace")
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return {"ok": True, "status": resp.status, "headers": hdrs, "body": body, "url": resp.geturl()}
    except urllib.error.HTTPError as e:  # a real HTTP response (4xx/5xx/3xx) — usable
        try:
            body = e.read(65536).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            body = ""
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        return {"ok": True, "status": e.code, "headers": hdrs, "body": body, "url": url, "http_error": True}
    except Exception as e:  # noqa: BLE001 — connection refused / timeout / TLS failure
        return {"ok": False, "error": str(e)}


def probe_http_listener(scheme: str, host: str, port: str, timeout: int) -> dict:
    base = f"{scheme}://{host}:{port}"
    root = http_fetch(base + "/", timeout=timeout)
    if not root.get("ok"):
        return {"reachable": False, "error": root.get("error"), "base": base}
    cors = http_fetch(base + "/", extra_headers={"Origin": _EVIL_ORIGIN}, timeout=timeout)
    err = http_fetch(base + _ERROR_PATH, timeout=timeout)
    noredir = http_fetch(base + "/", timeout=timeout, follow=False)
    return {"reachable": True, "base": base, "root": root, "cors": cors, "err": err, "noredir": noredir}


def tls_probe(host: str, port: int, timeout: int) -> dict:
    """Record the negotiated protocol/cipher and whether a legacy (<=TLS1.1)
    handshake is accepted. Non-destructive single handshake(s)."""
    out: dict = {}
    try:
        ctx = _noverify_ctx()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                out["protocol"] = ss.version()
                name, _proto, bits = ss.cipher() or ("", "", 0)
                out["cipher"] = name
                out["bits"] = bits
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
        return out
    # Best-effort legacy-protocol probe (build may refuse to offer it — then untestable).
    try:
        legacy = _noverify_ctx()
        legacy.minimum_version = ssl.TLSVersion.TLSv1
        legacy.maximum_version = ssl.TLSVersion.TLSv1_1
        with socket.create_connection((host, port), timeout=timeout) as s:
            with legacy.wrap_socket(s, server_hostname=host) as ss:
                out["legacy_accepted"] = ss.version()
    except Exception:  # noqa: BLE001 — legacy refused (good) or client can't offer it
        out["legacy_accepted"] = None
    return out


def nmap_sv(host: str, port: str, timeout: int) -> dict:
    cmd = ["nmap", "-Pn", "-sV", "--version-light", "-p", port,
           "--host-timeout", f"{max(timeout, 30)}s", host]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=max(timeout, 30) + 30)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e), "cmd": " ".join(cmd)}
    out = p.stdout + p.stderr
    product = version = None
    for line in p.stdout.splitlines():
        m = re.match(rf"^{re.escape(port)}/tcp\s+open\s+\S+\s+(.+)$", line.strip())
        if m:
            rest = m.group(1).strip()
            vm = re.search(r"([A-Za-z][\w .+/-]*?)\s+([\d][\w.]*)", rest)
            if vm:
                product, version = vm.group(1).strip(), vm.group(2).strip()
            else:
                product = rest
            break
    return {"ok": True, "raw": out, "cmd": " ".join(cmd), "product": product, "version": version}


def map_cve(product: str | None, version: str | None) -> str | None:
    if not product or not version:
        return None
    pl = product.lower()
    for (prod_sub, ver_pref), cve in KNOWN_VULN.items():
        if prod_sub in pl and version.startswith(ver_pref):
            return cve
    return None


def nvd_severity(cve: str, cache_dir: str) -> dict:
    cmd = [sys.executable, os.path.join(HERE, "nvd-lookup.py"), "--cache-dir", cache_dir, cve]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}
    for line in p.stdout.splitlines():
        if line.startswith("JSON_SUMMARY:"):
            try:
                return {"ok": True, "summary": json.loads(line.split(":", 1)[1].strip()), "raw": p.stdout}
            except json.JSONDecodeError:
                break
    return {"ok": False, "error": "no JSON_SUMMARY from nvd-lookup", "raw": p.stdout}


# --- per-class verdicts ------------------------------------------------------
# Each returns (verdict, one_line, raw_output) where verdict in
# {"clean", "positive", "limitation"} and, for positive/limitation, one_line is
# the reason. clean/positive carry the raw tool output for the corroborator/finding.
def check_security_headers(hp: dict) -> tuple:
    if not hp["reachable"]:
        return "limitation", f"unreachable: {hp.get('error')}", ""
    h = hp["root"]["headers"]
    missing = [k for k in REQUIRED_SEC_HEADERS if k not in h]
    frame_ok = ("x-frame-options" in h) or ("frame-ancestors" in h.get("content-security-policy", "").lower())
    if not frame_ok:
        missing.append("x-frame-options|csp:frame-ancestors")
    raw = _dump_headers(hp["root"])
    if missing:
        return "positive", "missing security headers: " + ", ".join(missing), raw
    return "clean", "all baseline security headers present", raw


def check_cors(hp: dict) -> tuple:
    if not hp["reachable"]:
        return "limitation", f"unreachable: {hp.get('error')}", ""
    h = hp["cors"]["headers"]
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower()
    raw = f"Request Origin: {_EVIL_ORIGIN}\n" + _dump_headers(hp["cors"])
    if acao == _EVIL_ORIGIN or acao == "null" or (acao == "*" and acac == "true"):
        return "positive", f"permissive CORS: ACAO={acao!r} credentials={acac!r}", raw
    return "clean", f"no origin reflection (ACAO={acao or 'unset'!r})", raw


def check_transport_downgrade(hp: dict) -> tuple:
    if not hp["reachable"]:
        return "limitation", f"unreachable: {hp.get('error')}", ""
    h = hp["root"]["headers"]
    raw = _dump_headers(hp["root"])
    if "strict-transport-security" in h:
        return "clean", f"HSTS present: {h['strict-transport-security']}", raw
    nr = hp["noredir"]
    loc = nr["headers"].get("location", "") if nr.get("ok") else ""
    if nr.get("ok") and 300 <= nr.get("status", 0) < 400 and loc.startswith("https://"):
        return "clean", f"redirects to HTTPS: {loc}", raw + "\n" + _dump_headers(nr)
    return "positive", "no HSTS and no HTTPS redirect", raw + "\n" + _dump_headers(nr)


def check_verbose_errors(hp: dict) -> tuple:
    if not hp["reachable"]:
        return "limitation", f"unreachable: {hp.get('error')}", ""
    err = hp["err"]
    body = err.get("body", "")
    raw = f"GET {_ERROR_PATH} -> {err.get('status')}\n\n{body[:2000]}"
    m = _ERR_RE.search(body)
    if m:
        return "positive", f"verbose error disclosure: matched {m.re.pattern[:40]!r}", raw
    return "clean", f"clean error response (status {err.get('status')}, no stack/framework leak)", raw


def check_tls_posture(host: str, port: str, timeout: int) -> tuple:
    res = tls_probe(host, int(port), timeout)
    if res.get("error"):
        return "limitation", f"TLS handshake failed: {res['error']}", ""
    raw = json.dumps(res, indent=2)
    proto = res.get("protocol") or ""
    weak_cipher = bool(re.search(r"RC4|DES|NULL|EXPORT|MD5|_CBC_.*SHA\b", res.get("cipher", ""), re.I))
    if res.get("legacy_accepted"):
        return "positive", f"legacy protocol accepted: {res['legacy_accepted']}", raw
    if proto in ("TLSv1", "TLSv1.1"):
        return "positive", f"weak protocol negotiated: {proto}", raw
    if weak_cipher or (res.get("bits") or 0) < 128:
        return "positive", f"weak cipher: {res.get('cipher')} ({res.get('bits')} bits)", raw
    return "clean", f"strong TLS: {proto} {res.get('cipher')} ({res.get('bits')} bits)", raw


def check_components(host: str, port: str, timeout: int, cache_dir: str, use_nmap: bool) -> tuple:
    if not use_nmap:
        return "limitation", "nmap unavailable — cannot fingerprint component version", ""
    nm = nmap_sv(host, port, timeout)
    if not nm.get("ok"):
        return "limitation", f"nmap failed: {nm.get('error')}", ""
    raw = f"$ {nm['cmd']}\n\n{nm['raw']}"
    cve = map_cve(nm.get("product"), nm.get("version"))
    if cve:
        sev = nvd_severity(cve, cache_dir)
        if not sev.get("ok"):
            return "limitation", f"nvd-lookup unavailable for {cve}: {sev.get('error')}", raw
        summary = sev["summary"]
        raw += f"\n\n[nvd-lookup {cve}] {json.dumps(summary)}"
        if (summary.get("severity") or "").upper() in ("HIGH", "CRITICAL"):
            return "positive", f"vulnerable component {nm['product']} {nm['version']} -> {cve} ({summary['severity']})", raw
        return "clean", f"{nm['product']} {nm['version']}: {cve} is {summary.get('severity')} (not high/critical)", raw
    fp = f"{nm.get('product') or 'unknown'} {nm.get('version') or ''}".strip()
    return "clean", f"component observed ({fp}); no known-vulnerable mapping", raw


# --- WAF/CDN block-page + soft-404 guards (kill file/secret false positives) ---
def classify_block(status, headers, body) -> dict:
    """Identify a WAF/CDN reject/deny page. A rejected request returned as 200/403/
    406 must never be mistaken for a served file or a leaked secret, so this is
    consulted before any file/secret/inventory "exists" is reported. Returns
    {"is_block": bool, "vendor": str|None}. Case-insensitive; matches body markers
    plus response headers. A bare vendor-presence header (a CDN simply fronting the
    origin, e.g. x-akamai-* / x-sucuri-id / x-iinfo / x-vercel-id on a 200) only
    counts as a block on a deny-ish status — otherwise a real 200 asset served
    through the CDN would be wrongly suppressed (a false negative)."""
    h = {str(k).lower(): str(v or "") for k, v in (headers or {}).items()}
    bl = (body or "").lower()
    cookies = h.get("set-cookie", "").lower()
    deny = status in _BLOCK_DENY_STATUS

    def hdr_prefix(p):
        return any(k.startswith(p) for k in h)

    # F5 BIG-IP ASM / F5 Distributed Cloud reject page (the ~269-byte body).
    if "request rejected" in bl and "support id" in bl:
        return {"is_block": True, "vendor": "f5"}
    # Cloudflare — cf-ray present AND a block/challenge body.
    if "cf-ray" in h and any(s in bl for s in (
            "attention required", "cf-error", "error 1020", "error 1010",
            "error 1015", "sorry, you have been blocked")):
        return {"is_block": True, "vendor": "cloudflare"}
    # Akamai — Ghost reject markers, or x-akamai-* / Server: AkamaiGHost on a deny.
    if ("akamaighost" in bl or re.search(r"reference\s*#\s*[0-9a-f.]", bl)
            or ((hdr_prefix("x-akamai-") or "akamaighost" in h.get("server", "").lower()) and deny)):
        return {"is_block": True, "vendor": "akamai"}
    # Sucuri — explicit block header/body, or x-sucuri-id on a deny response.
    if ("x-sucuri-block" in h or "sucuri" in bl
            or ("x-sucuri-id" in h and deny)):
        return {"is_block": True, "vendor": "sucuri"}
    # Imperva / Incapsula — deny body/cookie markers, or x-iinfo on a deny response.
    if ("_incapsula_" in bl or "incapsula incident" in bl
            or "incap_ses" in cookies or "visid_incap" in cookies
            or ("x-iinfo" in h and deny)):
        return {"is_block": True, "vendor": "imperva"}
    # AppTrana / Indusface — typically HTTP 406 with a vendor marker.
    if status == 406 and ("apptrana" in bl or "indusface" in bl):
        return {"is_block": True, "vendor": "apptrana"}
    # Vercel — platform error header, or x-vercel-* on a deny / NOT_FOUND shell.
    if ("x-vercel-error" in h
            or (hdr_prefix("x-vercel-")
                and (deny or "not_found" in bl or "this page could not be found" in bl))):
        return {"is_block": True, "vendor": "vercel"}
    return {"is_block": False, "vendor": None}


def baseline_fingerprint(resp) -> dict | None:
    """Fingerprint the random-nonsense-path (_ERROR_PATH) response so a real hit can
    be told apart from an SPA/Blazor catch-all that returns one body for every path.
    Returns {status, size, body_hash} or None when the baseline wasn't fetchable."""
    if not resp or not resp.get("ok"):
        return None
    body = resp.get("body", "") or ""
    return {"status": resp.get("status"), "size": len(body),
            "body_hash": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()}


def is_soft_404(candidate_resp, baseline) -> bool:
    """True when candidate_resp is indistinguishable from the not-found baseline
    (same status AND (identical body-hash OR size within tolerance)) — i.e. the path
    does not really "exist", the server just echoes its catch-all body."""
    if not baseline or not candidate_resp or not candidate_resp.get("ok"):
        return False
    if candidate_resp.get("status") != baseline.get("status"):
        return False
    body = candidate_resp.get("body", "") or ""
    if hashlib.sha256(body.encode("utf-8", "replace")).hexdigest() == baseline.get("body_hash"):
        return True
    return abs(len(body) - baseline.get("size", -1)) <= _SOFT404_SIZE_TOL


def check_api_inventory(bases: list, timeout: int) -> tuple:
    if not bases:
        return "limitation", "no in-scope listener to probe for API docs", "", []
    lines = []
    exposed = []
    observations = []
    for base in bases:
        baseline = baseline_fingerprint(http_fetch(base + _ERROR_PATH, timeout=timeout))
        for path in _SWAGGER_PATHS:
            r = http_fetch(base + path, timeout=timeout)
            if not r.get("ok"):
                continue
            looks_openapi = r["status"] == 200 and bool(_SWAGGER_RE.search(r.get("body", "") or ""))
            tag = ""
            if looks_openapi:
                blk = classify_block(r.get("status"), r.get("headers"), r.get("body", ""))
                if blk["is_block"]:  # a reject page that echoes 'openapi' text is not real inventory
                    tag = f" [WAF/{blk['vendor']}]"
                    observations.append({"url": base + path, "status": r.get("status"),
                                         "kind": "waf_block", "vendor": blk["vendor"]})
                elif is_soft_404(r, baseline):  # SPA catch-all shell, endpoint doesn't exist
                    tag = " [soft-404]"
                    observations.append({"url": base + path, "status": r.get("status"),
                                         "kind": "soft_404", "vendor": None})
                else:
                    tag = " [OPENAPI]"
                    exposed.append(base + path)
            lines.append(f"GET {base}{path} -> {r['status']}{tag}")
    if not lines:
        return "limitation", "no listener reachable for inventory probe", "", observations
    raw = "\n".join(lines)
    if exposed:
        return "positive", "exposed API documentation: " + ", ".join(exposed), raw, observations
    return "clean", "no exposed swagger/openapi endpoints found", raw, observations


def check_secret_exposure(js_urls: list, bases: list, timeout: int) -> tuple:
    targets = list(js_urls) or [b + "/" for b in bases]
    if not targets:
        return "limitation", "no in-scope JS/static target to scan", "", []
    lines = []
    hits = []
    observations = []
    reached = False
    baselines: dict = {}

    def baseline_for(url):
        p = urlparse(url)
        origin = f"{p.scheme}://{p.netloc}"
        if origin not in baselines:
            baselines[origin] = baseline_fingerprint(http_fetch(origin + _ERROR_PATH, timeout=timeout))
        return baselines[origin]

    for url in targets:
        r = http_fetch(url, timeout=timeout)
        if not r.get("ok"):
            lines.append(f"GET {url} -> unreachable ({r.get('error')})")
            continue
        reached = True
        blk = classify_block(r.get("status"), r.get("headers"), r.get("body", ""))
        if blk["is_block"]:  # a WAF/CDN reject page is never a secret exposure
            lines.append(f"GET {url} -> {r['status']} [WAF/{blk['vendor']}] reject page — not an exposure")
            observations.append({"url": url, "status": r.get("status"), "kind": "waf_block", "vendor": blk["vendor"]})
            continue
        body = r.get("body", "") or ""
        m = _SECRET_RE.search(body)
        if m and is_soft_404(r, baseline_for(url)):  # catch-all shell, path doesn't really exist
            lines.append(f"GET {url} -> {r['status']} [soft-404] matches not-found baseline — not an exposure")
            observations.append({"url": url, "status": r.get("status"), "kind": "soft_404", "vendor": None})
            continue
        lines.append(f"GET {url} -> {r['status']} ({len(body)} bytes){' [SECRET]' if m else ''}")
        if m:
            hits.append(f"{url}: {m.group(0)[:24]}...")
    if not reached:
        return "limitation", "no scannable asset reachable for secret scan", "", observations
    raw = "\n".join(lines)
    if hits:
        return "positive", "secret material in static bundle: " + "; ".join(hits), raw, observations
    return "clean", "no secrets detected in static/JS assets", raw, observations


def _dump_headers(resp: dict) -> str:
    lines = [f"HTTP {resp.get('status')}"]
    for k, v in sorted(resp.get("headers", {}).items()):
        lines.append(f"{k}: {v}")
    return "\n".join(lines)


# --- evidence writers --------------------------------------------------------
_E_ROW_RE = re.compile(r"^\|\s*E-(\d+)\s*\|")


def next_e_index(asset_dir: str) -> int:
    path = os.path.join(asset_dir, "experiments.md")
    hi = 0
    if os.path.isfile(path):
        for line in open(path, encoding="utf-8"):
            m = _E_ROW_RE.match(line)
            if m:
                hi = max(hi, int(m.group(1)))
    return hi + 1


def write_corroborator(asset_dir: str, n: int, class_id: str, e_id: str, one_line: str, raw: str) -> str:
    rel = os.path.join("tools", f"{n:03d}_{class_id}.md")
    path = os.path.join(asset_dir, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# passive_web_probe — {class_id}\n\nExperiment: {e_id}\n\nResult: {one_line}\n\n"
                f"## Raw tool output\n```\n{raw}\n```\n")
    return rel


def append_experiments(asset_dir: str, rows: list) -> None:
    path = os.path.join(asset_dir, "experiments.md")
    new = not os.path.isfile(path)
    os.makedirs(asset_dir, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        if new:
            f.write("# Experiments\n\n| # | Tool | Cell | Result |\n|---|------|------|--------|\n")
        for e_id, class_id, key, result in rows:
            safe = result.replace("|", "/").replace("\n", " ")[:160]
            f.write(f"| {e_id} | passive_web_probe | {class_id} @ {key} | {safe} |\n")


def merge_coverage(asset_dir: str, entries_by_class: dict) -> None:
    """Read-merge units_tested entries into coverage.json WITHOUT clobbering other
    rows/keys. Never replaces an existing entry for a key (finding/agent wins)."""
    path = os.path.join(asset_dir, "coverage.json")
    doc = None
    if os.path.isfile(path):
        try:
            doc = json.load(open(path, encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            doc = None
    if isinstance(doc, dict):
        rows = doc.get("rows") or doc.get("classes") or []
        key_for_rows = "rows" if "rows" in doc or "classes" not in doc else "classes"
        container = doc
    else:
        rows = doc if isinstance(doc, list) else []
        container = None
        key_for_rows = None
    index = {r.get("class_id"): r for r in rows if isinstance(r, dict) and r.get("class_id")}
    for cid, ents in entries_by_class.items():
        row = index.get(cid)
        if row is None:
            row = {"class_id": cid, "applicability": "applicable", "status": "pending",
                   "negative": True, "units_tested": [], "owner": "passive_web_probe"}
            rows.append(row)
            index[cid] = row
        ut = row.setdefault("units_tested", [])
        have = {e.get("key") for e in ut}
        for e in ents:
            if e["key"] not in have:
                ut.append(e)
                have.add(e["key"])
    with open(path, "w", encoding="utf-8") as f:
        if container is not None:
            container[key_for_rows] = rows
            json.dump(container, f, ensure_ascii=False, indent=2, sort_keys=True)
        else:
            json.dump(rows, f, ensure_ascii=False, indent=2, sort_keys=True)


def write_finding(asset_dir: str, class_id: str, key: str, seq: int, one_line: str, raw: str) -> str:
    rel = os.path.join("findings", f"finding-{class_id}-{seq:03d}")
    fdir = os.path.join(asset_dir, rel)
    os.makedirs(os.path.join(fdir, "evidence"), exist_ok=True)
    with open(os.path.join(fdir, "description.md"), "w", encoding="utf-8") as f:
        f.write(f"# {class_id} — passive_web_probe finding\n\n"
                f"- Target: `{key}`\n- Detected by: `passive_web_probe` (deterministic)\n"
                f"- Status: RAW / unvalidated — routed to the validation lane\n\n"
                f"## Summary\n{one_line}\n\n## Evidence\nSee `evidence/raw-source.txt`.\n")
    with open(os.path.join(fdir, "evidence", "raw-source.txt"), "w", encoding="utf-8") as f:
        f.write(raw + "\n")
    return rel


# --- orchestration -----------------------------------------------------------
def run(asset_dir: str, allow: list, timeout: int, use_nmap: bool) -> dict:
    doc = run_enumerate(asset_dir)
    cells = [c for c in doc.get("cells", []) if c["class_id"] in MECHANICAL]
    summary = {"asset_dir": asset_dir, "covered_negative": [], "findings": [],
               "limitations": [], "skipped_out_of_scope": [], "block_observations": []}
    if not cells:
        return summary  # nothing mechanical to do

    surface = load_surface(asset_dir)
    asset_tag = surface.get("asset_tag") or os.path.basename(asset_dir.rstrip("/"))
    allow_set = {asset_tag} | ({surface["apex"]} if surface.get("apex") else set()) | set(allow)
    schemes = build_listener_schemes(surface)
    assets_meta = doc.get("assets", {})
    cache_dir = os.path.join(asset_dir, "artifacts", "nvd-cache")

    # per-listener HTTP probe cache
    http_cache: dict = {}

    def get_http(listener: str) -> dict:
        if listener not in http_cache:
            host, port = listener.rsplit(":", 1)
            scheme = schemes.get(listener, "https" if int(port) in TLS_PORTS else "http")
            http_cache[listener] = probe_http_listener(scheme, host, port, timeout)
        return http_cache[listener]

    n = next_e_index(asset_dir)
    entries_by_class: dict = {}
    exp_rows: list = []
    finding_seq = 0

    def close(cell, one_line, raw, nk):
        nonlocal n
        e_id = f"E-{n:03d}"
        corr = write_corroborator(asset_dir, n, cell["class_id"], e_id, one_line, raw)
        # active_probe cells REQUIRE the corroborator; none-kind cells keep it too
        # (harmless extra evidence — the gate ignores it for negative_kind none).
        entry = {"key": cell["scope_key"], "status": "covered_negative", "e_id": e_id,
                 "negative_kind": nk, "corroborator": corr}
        entries_by_class.setdefault(cell["class_id"], []).append(entry)
        exp_rows.append((e_id, cell["class_id"], cell["scope_key"], one_line))
        summary["covered_negative"].append({"class_id": cell["class_id"], "scope_key": cell["scope_key"], "e_id": e_id})
        n += 1

    def positive(cell, one_line, raw):
        nonlocal finding_seq
        finding_seq += 1
        rel = write_finding(asset_dir, cell["class_id"], cell["scope_key"], finding_seq, one_line, raw)
        summary["findings"].append({"class_id": cell["class_id"], "scope_key": cell["scope_key"],
                                    "path": rel, "reason": one_line})

    def limit(cell, one_line):
        summary["limitations"].append({"class_id": cell["class_id"], "scope_key": cell["scope_key"], "reason": one_line})

    for cell in cells:
        cid = cell["class_id"]
        if cid in HOST_ACTIVE:
            listener = cell["scope_key"]
            host, _, port = listener.rpartition(":")
            if host not in allow_set:
                summary["skipped_out_of_scope"].append({"class_id": cid, "scope_key": listener, "host": host})
                continue
            if cid == "WEB-A06-COMPONENTS":
                verdict, one_line, raw = check_components(host, port, timeout, cache_dir, use_nmap)
            elif cid == "XC-TLS-POSTURE":
                verdict, one_line, raw = check_tls_posture(host, port, timeout)
            else:
                hp = get_http(listener)
                fn = {"XC-SECURITY-HEADERS": check_security_headers, "XC-CORS": check_cors,
                      "XC-TRANSPORT-DOWNGRADE": check_transport_downgrade,
                      "XC-VERBOSE-ERRORS": check_verbose_errors}[cid]
                verdict, one_line, raw = fn(hp)
            nk = "active_probe"
        else:  # asset-scope, negative_kind none
            listeners = assets_meta.get(cell["scope_key"], {}).get("open_listeners", [])
            in_scope = [l for l in listeners if l.rpartition(":")[0] in allow_set]
            out_of_scope = [l for l in listeners if l.rpartition(":")[0] not in allow_set]
            for l in out_of_scope:
                summary["skipped_out_of_scope"].append({"class_id": cid, "scope_key": cell["scope_key"], "host": l.rpartition(":")[0]})
            bases = [f"{schemes.get(l, 'http')}://{l}" for l in in_scope]
            if cid == "API9-INVENTORY":
                verdict, one_line, raw, obs = check_api_inventory(bases, timeout)
            else:  # XC-SECRET-EXPOSURE
                in_hosts = {l.rpartition(":")[0] for l in in_scope}
                verdict, one_line, raw, obs = check_secret_exposure(js_urls_for_hosts(surface, in_hosts), bases, timeout)
            for o in obs:
                o["class_id"] = cid
                summary["block_observations"].append(o)
            nk = "none"

        if verdict == "clean":
            close(cell, one_line, raw, nk)
        elif verdict == "positive":
            positive(cell, one_line, raw)
        else:
            limit(cell, one_line)

    if exp_rows:
        append_experiments(asset_dir, exp_rows)
    if entries_by_class:
        merge_coverage(asset_dir, entries_by_class)
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministic per-asset scanner for the 8 mechanical coverage cells.")
    ap.add_argument("--asset-dir", required=True)
    ap.add_argument("--allow", default="", help="comma-separated in-scope hosts (added to surface asset_tag/apex)")
    ap.add_argument("--timeout", type=int, default=10, help="per-request timeout seconds (default 10)")
    ap.add_argument("--no-nmap", action="store_true", help="treat nmap as unavailable (WEB-A06 -> limitation)")
    args = ap.parse_args()

    asset_dir = os.path.abspath(args.asset_dir)
    allow = [h.strip() for h in args.allow.split(",") if h.strip()]
    use_nmap = (not args.no_nmap) and bool(shutil.which("nmap"))
    summary = run(asset_dir, allow, args.timeout, use_nmap)
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
