#!/usr/bin/env python3
"""Safe, non-disruptive firmware/patch-level inference for perimeter appliances.

Maps PASSIVELY-observed signals (already-collected HTTP headers, a login-page
body, TLS cert fields, login-path markers, a banner, a favicon hash) to a vendor
+ product + a version/build GUESS + a CONFIDENCE, so CVE applicability stops
being left UNDETERMINED across whole estates. It fires NO exploits and makes NO
network calls — every input is injected as a dict, so it is deterministic and
unit-testable offline. It is the active counterpart's *precondition* feeder: a
version guess is an input to applicability scoring, never a "confirmed vuln".

The vendor rule table (`_RULES`) currently covers the four perimeter appliances
whose n-day CVEs dominate external estates:

  * Fortinet FortiGate  — obfuscated `Server: xxxxxxxx-xxxxx` header, `/remote/login`
                          or `/logincheck` path, cert `CN=FortiGate`/`FGT`, body
                          `Forticlient`, `/migadmin` admin marker.
  * Palo Alto PAN-OS    — GlobalProtect portal markers, `/global-protect/login.esp`,
                          `Server: PanWeb Server`, cert `CN=...paloaltonetworks`,
                          the GP `login.css` build query.
  * Cisco ASA           — `/+CSCOE+/logon.html` (and `/+CSCOU+/`, `+webvpn+`) WebVPN
                          markers, cert CN, ASA/ASDM version strings.
  * Citrix ADC/NetScaler— `/vpn/index.html`, `/logon/LogonPoint`, `NSC_` cookies,
                          cert `CN=...netscaler`, the `/vpn/js/` build string.

CONFIDENCE is purely a function of how many INDEPENDENT strong signals matched:
  * >= 2 strong signals -> "high"
  * exactly 1           -> "medium"
  * 0 (no vendor)       -> "low"  (vendor None)
A version_guess/build never raises confidence — a lone leaked banner is spoofable
and backportable, so it is a version hint, not corroboration of the vendor.

`applicability(inferred, cve_meta)` is deliberately conservative: it returns
`undetermined` whenever the version is unknown OR confidence is "low", and NEVER
asserts `applicable` on a low-confidence / None-version guess. This is the
precondition gate the network-appliance-offensive skill relies on.

Signals dict (every key optional):
    {
      "http_headers": {"Server": "xxxxxxxx-xxxxx", ...},
      "http_body": "<html>...Forticlient...",
      "tls_cert": {"subject": "CN=FortiGate", "issuer": "...",
                   "serial": "...", "not_before": "..."},
      "favicon_hash": "-12345678",           # mmh3 (str or int), advisory only
      "login_page_markers": ["/remote/login", "/migadmin"],
      "banner": "..."
    }

CVE meta for applicability (affected-version predicate, no network):
    {"cpe": "cpe:2.3:o:fortinet:fortios:*", "affected_ranges": [{"ge": "7.0.0", "lt": "7.0.12"}]}

Usage:
    appliance_version_infer.py --signals <json|path> [--cve <json|path>] [--json]

Exit 0 always on well-formed input; 1 on unreadable/invalid JSON input.
"""
import argparse
import json
import os
import re
import sys

_STRONG = "strong"  # marker for readability in rule declarations


def _lc(s):
    return s.lower() if isinstance(s, str) else ""


def _header(headers, name):
    """Case-insensitive header lookup returning the value as a string ('' if absent)."""
    if not isinstance(headers, dict):
        return ""
    want = name.lower()
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() == want:
            return v if isinstance(v, str) else ("" if v is None else str(v))
    return ""


def _cert_fields(cert):
    """Lowercased (subject, issuer, serial) blob from a tls_cert dict."""
    if not isinstance(cert, dict):
        return ""
    return " ".join(
        _lc(cert.get(k, "")) for k in ("subject", "issuer", "serial", "cn")
    )


def _blob(signals):
    """One lowercased haystack of body + banner + every login-page marker + set-cookie."""
    body = _lc(signals.get("http_body"))
    banner = _lc(signals.get("banner"))
    markers = signals.get("login_page_markers") or []
    marker_txt = " ".join(_lc(m) if isinstance(m, str) else str(m).lower() for m in markers)
    set_cookie = _lc(_header(signals.get("http_headers"), "set-cookie"))
    return " ".join([body, banner, marker_txt, set_cookie])


# ---- version extraction -----------------------------------------------------

def _search(text, patterns):
    """First capture group across `patterns` (case-insensitive), or None."""
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


# ---- per-vendor detection ---------------------------------------------------

def _detect_fortinet(signals, blob, cert, server):
    matched = []
    # Obfuscated Server header: FortiOS emits a random token like "xxxxxxxx-xxxxx".
    if re.fullmatch(r"[0-9a-z]{6,}-[0-9a-z]{4,}", _lc(server)):
        matched.append("obfuscated Server header (%s)" % server)
    for needle, label in (
        ("/remote/login", "path:/remote/login"),
        ("/logincheck", "path:/logincheck"),
        ("/remote/fgt_lang", "path:/remote/fgt_lang"),
        ("/migadmin", "path:/migadmin"),
    ):
        if needle in blob:
            matched.append(label)
    if "forticlient" in blob or "fortigate" in blob or "fortios" in blob:
        matched.append("body:forti* marker")
    if "fortigate" in cert or re.search(r"\bcn=fgt", cert) or "fortinet" in cert:
        matched.append("cert CN=FortiGate/FGT")
    version = _search(blob, [
        r"fortios[^0-9]{0,12}(\d+\.\d+(?:\.\d+)?)",
        r"fortigate[^0-9]{0,12}(\d+\.\d+(?:\.\d+)?)",
    ])
    build = _search(blob, [r"build[^0-9]{0,4}(\d{3,5})"])
    return matched, version, build


def _detect_paloalto(signals, blob, cert, server):
    matched = []
    if "panweb" in _lc(server):
        matched.append("Server: PanWeb Server")
    if "globalprotect" in blob or "global-protect" in blob:
        matched.append("body:GlobalProtect marker")
    for needle, label in (
        ("/global-protect/login.esp", "path:/global-protect/login.esp"),
        ("/global-protect/portal", "path:/global-protect/portal"),
        ("/sslmgr", "path:/sslmgr"),
    ):
        if needle in blob:
            matched.append(label)
    if "paloaltonetworks" in cert or "palo alto" in cert:
        matched.append("cert CN=...paloaltonetworks")
    version = _search(blob, [
        r"pan-?os[^0-9]{0,12}(\d+\.\d+(?:\.\d+)?)",
        r"login\.css\?[^\"'>\s]*?(?:v|ver|version)=(\d+\.\d+(?:\.\d+)?)",
        r"globalprotect[^0-9]{0,12}(\d+\.\d+(?:\.\d+)?)",
    ])
    return matched, version, None


def _detect_cisco_asa(signals, blob, cert, server):
    matched = []
    for needle, label in (
        ("/+cscoe+/logon.html", "path:/+CSCOE+/logon.html"),
        ("+cscoe+", "path:/+CSCOE+/"),
        ("+cscou+", "path:/+CSCOU+/"),
        ("+webvpn+", "path:/+webvpn+/"),
        ("/+cscoe+/logon.html?fcadbadd", "path:webvpn logon"),
    ):
        if needle in blob:
            matched.append(label)
    if "webvpn" in blob or "anyconnect" in blob:
        matched.append("body:WebVPN/AnyConnect marker")
    if re.search(r"\bcn=[^,]*asa", cert) or "cisco" in cert:
        matched.append("cert CN=...ASA/Cisco")
    version = _search(blob, [
        r"\basa[^0-9]{0,6}(\d+\.\d+(?:\([0-9a-z.]+\))?)",
    ])
    build = _search(blob, [r"asdm[^0-9]{0,6}(\d+\.\d+(?:\([0-9a-z.]+\))?)"])
    return matched, version, build


def _detect_citrix(signals, blob, cert, server):
    matched = []
    for needle, label in (
        ("/vpn/index.html", "path:/vpn/index.html"),
        ("/logon/logonpoint", "path:/logon/LogonPoint"),
        ("/vpn/js/", "path:/vpn/js/"),
        ("/citrix/", "path:/citrix/"),
    ):
        if needle in blob:
            matched.append(label)
    if "nsc_" in blob:
        matched.append("NSC_ cookie")
    if "citrix" in blob or "netscaler" in blob:
        matched.append("body:Citrix/NetScaler marker")
    if "netscaler" in cert or "citrix" in cert:
        matched.append("cert CN=...netscaler")
    version = _search(blob, [
        r"netscaler\s+ns(\d+\.\d+)",
        r"\bns(\d+\.\d+)\b",
        r"/vpn/js/[^\"'\s]*?(\d+\.\d+(?:\.\d+)?)",
    ])
    build = _search(blob, [r"build\s*(\d+\.\d+)"])
    return matched, version, build


# vendor, product, detector.
_RULES = [
    ("Fortinet", "FortiGate", _detect_fortinet),
    ("Palo Alto Networks", "PAN-OS", _detect_paloalto),
    ("Cisco", "ASA", _detect_cisco_asa),
    ("Citrix", "ADC/NetScaler", _detect_citrix),
]


def _confidence(n_strong):
    if n_strong >= 2:
        return "high"
    if n_strong == 1:
        return "medium"
    return "low"


def infer(signals):
    """Map passive signals -> {vendor, product, version_guess, build, confidence,
    matched_signals, notes}. vendor/product are None when nothing matched."""
    signals = signals or {}
    if not isinstance(signals, dict):
        raise ValueError("signals must be a dict")
    headers = signals.get("http_headers") or {}
    server = _header(headers, "server")
    cert = _cert_fields(signals.get("tls_cert"))
    blob = _blob(signals)

    best = None  # (n_strong, order_index, vendor, product, matched, version, build)
    for idx, (vendor, product, detect) in enumerate(_RULES):
        matched, version, build = detect(signals, blob, cert, server)
        if not matched:
            continue
        score = len(matched)
        cand = (score, -idx, vendor, product, matched, version, build)
        if best is None or cand[:2] > best[:2]:
            best = cand

    if best is None:
        return {
            "vendor": None,
            "product": None,
            "version_guess": None,
            "build": None,
            "confidence": "low",
            "matched_signals": [],
            "notes": "no known appliance fingerprint matched the supplied signals",
        }

    score, _neg_idx, vendor, product, matched, version, build = best
    confidence = _confidence(score)
    if version is None:
        note = ("%s %s fingerprinted on %d signal(s); no version leaked "
                "(applicability will be UNDETERMINED)" % (vendor, product, score))
    else:
        note = ("%s %s v%s inferred from %d signal(s); banner is a HINT — "
                "gate CVEs via applicability()" % (vendor, product, version, score))
    return {
        "vendor": vendor,
        "product": product,
        "version_guess": version,
        "build": build,
        "confidence": confidence,
        "matched_signals": matched,
        "notes": note,
    }


# ---- CVE applicability ------------------------------------------------------

def _parse_ver(v):
    """Dotted version -> tuple of ints (ignores non-numeric noise), or None."""
    if v is None:
        return None
    nums = re.findall(r"\d+", str(v))
    return tuple(int(n) for n in nums) if nums else None


def _cmp(a, b):
    """Three-way compare of zero-padded version tuples."""
    n = max(len(a), len(b))
    a2 = a + (0,) * (n - len(a))
    b2 = b + (0,) * (n - len(b))
    return (a2 > b2) - (a2 < b2)


def _range_matches(v, r):
    """True iff version tuple v satisfies every present bound of range dict r.

    Supported bound keys: ge/gt/lt/le (and eq). A range with no parseable bound
    is treated as open (matches) — the CPE scoping already selected it.
    """
    if not isinstance(r, dict):
        return False
    checks = (("ge", ">="), ("gt", ">"), ("lt", "<"), ("le", "<="), ("eq", "=="))
    for key, op in checks:
        if r.get(key) is None:
            continue
        bound = _parse_ver(r[key])
        if bound is None:
            continue
        c = _cmp(v, bound)
        if op == ">=" and c < 0:
            return False
        if op == ">" and c <= 0:
            return False
        if op == "<" and c >= 0:
            return False
        if op == "<=" and c > 0:
            return False
        if op == "==" and c != 0:
            return False
    # Every present bound passed; a range with no parseable bound is open (matches).
    return True


def _fmt_range(r):
    return ", ".join("%s %s" % (k, r[k]) for k in ("ge", "gt", "le", "lt", "eq")
                     if isinstance(r, dict) and r.get(k) is not None) or "(open)"


def applicability(inferred, cve_meta):
    """Precondition gate: {applicable: True|False|"undetermined", reason}.

    Returns "undetermined" (NEVER True) when the inferred version is None or the
    inferred confidence is "low" — a version guess we do not trust must not be
    scored against a CVE. Otherwise True when the version falls inside any
    affected range, else False.
    """
    inferred = inferred or {}
    version = inferred.get("version_guess")
    confidence = inferred.get("confidence")

    if version is None:
        return {"applicable": "undetermined",
                "reason": "no version inferred — cannot score CVE applicability"}
    if confidence == "low":
        return {"applicable": "undetermined",
                "reason": "confidence 'low' — version guess untrusted; not scoring CVE"}

    v = _parse_ver(version)
    if v is None:
        return {"applicable": "undetermined",
                "reason": "inferred version %r is not parseable" % version}

    ranges = (cve_meta or {}).get("affected_ranges") or []
    if not ranges:
        return {"applicable": "undetermined",
                "reason": "CVE has no affected_ranges to evaluate against"}

    for r in ranges:
        if _range_matches(v, r):
            return {"applicable": True,
                    "reason": "version %s within affected range [%s]" % (version, _fmt_range(r))}
    return {"applicable": False,
            "reason": "version %s outside every affected range" % version}


# ---- CLI --------------------------------------------------------------------

def _load_json_arg(val, what):
    """Accept either an inline JSON string or a path to a JSON file."""
    if val is None:
        return None
    if os.path.isfile(val):
        with open(val) as fh:
            return json.load(fh)
    return json.loads(val)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--signals", required=True,
                    help="passive signals as a JSON string or a path to a JSON file")
    ap.add_argument("--cve",
                    help="CVE meta {cpe, affected_ranges:[{ge,lt}]} as JSON string/path")
    ap.add_argument("--json", action="store_true",
                    help="emit compact single-line JSON (default: indented)")
    args = ap.parse_args(argv)

    try:
        signals = _load_json_arg(args.signals, "signals")
        cve_meta = _load_json_arg(args.cve, "cve")
    except (OSError, json.JSONDecodeError) as e:
        print("ERROR: cannot read/parse input: %s" % e, file=sys.stderr)
        return 1

    try:
        inferred = infer(signals)
    except ValueError as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 1

    out = {"inferred": inferred}
    if cve_meta is not None:
        out["applicability"] = applicability(inferred, cve_meta)

    if args.json:
        print(json.dumps(out, sort_keys=True))
    else:
        print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
