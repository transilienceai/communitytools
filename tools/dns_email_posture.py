#!/usr/bin/env python3
"""Deterministic email/DNS/TLS security-posture scanner — the firewall-review
analogue for the DNS & email attack surface.

Email/DNS posture (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, CAA, DNSSEC) is a
recurring finding class on nearly every web engagement — historically the LARGEST
finding cluster on some. Today it is assembled by hand with ad-hoc `dig`
one-liners, which produces inconsistent severities from one report to the next.

This tool ingests an apex list, enumerates the full record set through a small set
of DNS/HTTPS seams, applies a FIXED severity rubric, and emits PRE-SCORED findings
already shaped for report_data (skills/transilience-report-style/reference/
report-data-schema.json). One process, one rubric, the same severity every time.

Seams (module-level so tests inject fakes; NO live DNS is performed in tests):
  _txt(name)        -> list[str]     TXT records (multi-string chunks joined)
  _mx(name)         -> list[str]     MX hostnames
  _cname(name)      -> str | None    CNAME target (DKIM is often a delegated CNAME)
  _caa(name)        -> list[str]     CAA records
  _has_dnssec(name) -> bool          zone publishes a DNSKEY (is signed)
  _https_get(url, timeout=8) -> (status:int, body:str)   MTA-STS policy + security.txt

Rubric (each check -> 0..N findings at a rubric-fixed severity):
  SPF      missing -> Medium; +all / no -all|~all -> Medium; multiple records -> Low
  DMARC    missing -> Medium; p=none -> Low; no sp= -> Info; no rua= -> Info
  DKIM     no common selector found -> Info (advisory; cannot be fully enumerated blind)
  MTA-STS  no TXT or unreachable/invalid policy -> Low
  TLS-RPT  missing -> Info
  BIMI     missing -> Info (advisory)
  CAA      missing -> Low
  DNSSEC   unsigned -> Low
  MX       none while other mail records exist -> Info
  security.txt  missing -> Info

Positive+negative control: a fully-hardened apex (SPF -all, DMARC p=reject+sp+rua,
MTA-STS enforce, TLS-RPT, DKIM, BIMI, CAA, DNSSEC) emits NO findings — so the
rubric cannot false-positive.

Usage:
  dns_email_posture.py <apex...> | --apex-file F [--selectors a,b,c] [--timeout N] [--json]
Emits {"apexes": [...], "findings": [...], "version": 1} with report_data-shaped
findings (affected=[apex], stable ids DNSMAIL-<apex>-<check>). Exits 0.
"""
from __future__ import annotations

import argparse
import json
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

DEFAULT_SELECTORS = ["default", "google", "selector1", "selector2", "k1"]

# CWE mapping — spoofing (SPF/DMARC), cleartext downgrade (MTA-STS/TLS-RPT),
# authenticity of DNS/issuance (CAA/DNSSEC). Advisory Info items carry no CWE.
CWE_SPOOF = "CWE-940"         # Improper Verification of Source of a Communication Channel
CWE_CLEARTEXT = "CWE-319"     # Cleartext Transmission of Sensitive Information
CWE_AUTHENTICITY = "CWE-345"  # Insufficient Verification of Data Authenticity

REF = {
    "spf": ["https://www.rfc-editor.org/rfc/rfc7208"],
    "dmarc": ["https://www.rfc-editor.org/rfc/rfc7489"],
    "dkim": ["https://www.rfc-editor.org/rfc/rfc6376"],
    "mta_sts": ["https://www.rfc-editor.org/rfc/rfc8461"],
    "tlsrpt": ["https://www.rfc-editor.org/rfc/rfc8460"],
    "bimi": ["https://datatracker.ietf.org/doc/draft-blank-ietf-bimi/"],
    "caa": ["https://www.rfc-editor.org/rfc/rfc8659"],
    "dnssec": ["https://www.rfc-editor.org/rfc/rfc4033"],
    "securitytxt": ["https://www.rfc-editor.org/rfc/rfc9116"],
}


# --- live seams (subprocess dig + urllib; monkeypatched away in tests) --------
def _dig(name: str, rrtype: str, extra: list | None = None) -> list:
    cmd = ["dig", "+short"] + (extra or []) + [name, rrtype]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except Exception:  # noqa: BLE001 — dig missing / timeout -> treat as no records
        return []
    return [ln.strip() for ln in p.stdout.splitlines() if ln.strip()]


def _txt(name: str) -> list:
    """TXT records. `dig +short TXT` yields quoted, possibly multi-string values;
    join the chunks of each record into one logical string."""
    out = []
    for line in _dig(name, "TXT"):
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', line)
        out.append("".join(parts) if parts else line.strip('"'))
    return out


def _mx(name: str) -> list:
    hosts = []
    for line in _dig(name, "MX"):
        m = re.match(r"^\d+\s+(\S+?)\.?$", line)
        hosts.append((m.group(1) if m else line).rstrip("."))
    return hosts


def _cname(name: str) -> str | None:
    out = _dig(name, "CNAME")
    return out[0].rstrip(".") if out else None


def _caa(name: str) -> list:
    return _dig(name, "CAA")


def _has_dnssec(name: str) -> bool:
    # A DNSSEC-signed zone publishes a DNSKEY RRset at its apex.
    return bool(_dig(name, "DNSKEY"))


def _https_get(url: str, timeout: int = 8) -> tuple:
    """(status, body). Any connection/TLS failure -> (0, '')."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "dns-email-posture/1"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:  # noqa: BLE001
        return 0, ""


# --- record gathering (uses the seams) ---------------------------------------
def gather(apex: str, selectors: list, timeout: int = 8) -> dict:
    """Enumerate every posture record for one apex via the seams."""
    spf = [t for t in _txt(apex) if t.strip().lower().startswith("v=spf1")]
    dmarc = [t for t in _txt("_dmarc." + apex) if "v=dmarc1" in t.lower()]

    dkim = {}
    for sel in selectors:
        name = f"{sel}._domainkey.{apex}"
        recs = _txt(name)
        has_txt = any(re.search(r"v=dkim1|(?:^|;)\s*[pk]=", r, re.I) for r in recs)
        dkim[sel] = {"present": has_txt or (_cname(name) is not None), "txt": recs}

    mta_txt = [t for t in _txt("_mta-sts." + apex) if "v=stsv1" in t.lower()]
    mta_status, mta_body = _https_get(f"https://mta-sts.{apex}/.well-known/mta-sts.txt", timeout)
    tlsrpt = [t for t in _txt("_smtp._tls." + apex) if "v=tlsrptv1" in t.lower()]
    bimi = [t for t in _txt("default._bimi." + apex) if "v=bimi1" in t.lower()]
    caa = _caa(apex)
    dnssec = bool(_has_dnssec(apex))
    mx = _mx(apex)
    sec_status, _ = _https_get(f"https://{apex}/.well-known/security.txt", timeout)
    return {"spf": spf, "dmarc": dmarc, "dkim": dkim, "mta_txt": mta_txt,
            "mta_status": mta_status, "mta_body": mta_body, "tlsrpt": tlsrpt,
            "bimi": bimi, "caa": caa, "dnssec": dnssec, "mx": mx, "sec_status": sec_status}


# --- scoring (pure) ----------------------------------------------------------
def _f(apex, check, severity, title, description, impact, recommendation,
       cwe=None, references=None) -> dict:
    fnd = {"id": f"DNSMAIL-{apex}-{check}", "title": title, "severity": severity,
           "affected": [apex], "description": description, "impact": impact,
           "recommendation": recommendation}
    if cwe:
        fnd["cwe"] = cwe
    if references:
        fnd["references"] = references
    return fnd


def _tags(record: str) -> dict:
    out = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


def evaluate(apex: str, g: dict) -> list:
    """Apply the fixed rubric to gathered records -> report_data findings."""
    F: list = []

    # SPF ---------------------------------------------------------------------
    spf = g["spf"]
    if not spf:
        F.append(_f(apex, "spf-missing", "Medium", "SPF record missing",
            "No SPF (v=spf1) TXT record is published for the domain, so receiving "
            "mail servers have no authoritative list of hosts permitted to send on "
            "its behalf.",
            "Attackers can spoof mail that appears to originate from this domain "
            "(phishing / business-email-compromise) without tripping SPF.",
            "Publish an SPF record listing only authorized senders and ending in -all.",
            CWE_SPOOF, REF["spf"]))
    else:
        rec = spf[0]
        low = rec.lower()
        if ("+all" in low) or not re.search(r"[~\-]all", low):
            F.append(_f(apex, "spf-weak-all", "Medium",
                "SPF record does not fail unauthorized senders",
                f"The SPF record ('{rec}') uses +all or omits a -all/~all "
                "qualifier, so any host passes SPF evaluation.",
                "The record provides no anti-spoofing value; arbitrary hosts can "
                "send mail as this domain and still pass SPF.",
                "Terminate the SPF record with -all (or ~all during rollout).",
                CWE_SPOOF, REF["spf"]))
        if len(spf) > 1:
            F.append(_f(apex, "spf-multiple", "Low",
                "Multiple SPF records published",
                f"{len(spf)} separate v=spf1 records were found; RFC 7208 permits "
                "exactly one.",
                "Receivers may resolve SPF to permerror and disable SPF evaluation "
                "entirely, silently removing the protection.",
                "Consolidate into a single v=spf1 record.",
                CWE_SPOOF, REF["spf"]))

    # DMARC -------------------------------------------------------------------
    dmarc = g["dmarc"]
    if not dmarc:
        F.append(_f(apex, "dmarc-missing", "Medium", "DMARC record missing",
            "No DMARC (v=DMARC1) TXT record is published at _dmarc." + apex + ".",
            "Without DMARC, SPF/DKIM failures are not enforced and no receiver "
            "policy or reporting exists, leaving the domain spoofable.",
            "Publish a DMARC record, starting at p=none for monitoring and moving "
            "to p=quarantine/reject once aligned.",
            CWE_SPOOF, REF["dmarc"]))
    else:
        tags = _tags(dmarc[0])
        policy = tags.get("p", "").lower()
        if policy in ("", "none"):
            F.append(_f(apex, "dmarc-p-none", "Low",
                "DMARC policy is monitoring-only (p=none)",
                f"The DMARC policy is p={policy or 'unset'}, which only reports and "
                "does not act on failing mail.",
                "Spoofed mail failing SPF/DKIM is still delivered; the domain gains "
                "visibility but no enforcement.",
                "Advance the policy to p=quarantine, then p=reject.",
                CWE_SPOOF, REF["dmarc"]))
        if "sp" not in tags:
            F.append(_f(apex, "dmarc-sp-missing", "Info",
                "DMARC has no explicit subdomain policy (sp=)",
                "The DMARC record does not set an sp= tag, so subdomains inherit the "
                "top-level policy implicitly.",
                "Subdomains may be handled less strictly than intended if the "
                "top-level policy is later relaxed.",
                "Set an explicit sp= (e.g. sp=reject) to pin subdomain handling.",
                CWE_SPOOF, REF["dmarc"]))
        if "rua" not in tags:
            F.append(_f(apex, "dmarc-rua-missing", "Info",
                "DMARC has no aggregate reporting address (rua=)",
                "The DMARC record does not specify an rua= mailbox, so no aggregate "
                "reports are collected.",
                "Spoofing attempts and authentication failures go unobserved.",
                "Add an rua=mailto: address to receive aggregate reports.",
                None, REF["dmarc"]))

    # DKIM --------------------------------------------------------------------
    if not any(d["present"] for d in g["dkim"].values()):
        sels = ", ".join(g["dkim"].keys())
        F.append(_f(apex, "dkim-none-found", "Info",
            "No DKIM key found on common selectors",
            f"None of the probed DKIM selectors ({sels}) returned a key. DKIM "
            "selectors cannot be fully enumerated blind, so this is ADVISORY — mail "
            "may still be signed under a private selector.",
            "Unsigned mail is easier to spoof and weakens DMARC alignment.",
            "Publish a DKIM key and confirm the selector, or disregard if signing "
            "under a non-standard selector.",
            None, REF["dkim"]))

    # MTA-STS -----------------------------------------------------------------
    if not g["mta_txt"]:
        F.append(_f(apex, "mta-sts-missing", "Low", "MTA-STS not configured",
            "No _mta-sts TXT record is published, so sending servers cannot require "
            "TLS for inbound SMTP to this domain.",
            "An active network attacker can strip STARTTLS and downgrade inbound "
            "mail to cleartext.",
            "Publish an MTA-STS policy (TXT record + HTTPS policy file, mode: enforce).",
            CWE_CLEARTEXT, REF["mta_sts"]))
    elif g["mta_status"] != 200 or "stsv1" not in (g["mta_body"] or "").lower():
        F.append(_f(apex, "mta-sts-policy-unreachable", "Low",
            "MTA-STS TXT present but policy is unreachable or invalid",
            f"The _mta-sts TXT record exists but the policy at "
            f"https://mta-sts.{apex}/.well-known/mta-sts.txt returned "
            f"status {g['mta_status']} or did not contain a valid STSv1 policy.",
            "Sending MTAs cannot apply the policy, so inbound SMTP can still be "
            "downgraded to cleartext by a MITM.",
            "Serve a valid mta-sts.txt (version: STSv1, mode: enforce) over HTTPS "
            "at mta-sts.<domain>.",
            CWE_CLEARTEXT, REF["mta_sts"]))

    # TLS-RPT -----------------------------------------------------------------
    if not g["tlsrpt"]:
        F.append(_f(apex, "tlsrpt-missing", "Info",
            "SMTP TLS Reporting (TLS-RPT) not configured",
            "No _smtp._tls TXT record is published, so the domain receives no "
            "reports about failed inbound SMTP TLS negotiations.",
            "TLS downgrade or delivery failures against the mail domain go unnoticed.",
            "Publish a TLS-RPT record (v=TLSRPTv1; rua=mailto:...).",
            None, REF["tlsrpt"]))

    # BIMI --------------------------------------------------------------------
    if not g["bimi"]:
        F.append(_f(apex, "bimi-missing", "Info", "BIMI not configured (advisory)",
            "No default._bimi TXT record is published. BIMI is optional brand "
            "indication and depends on an enforced DMARC policy.",
            "No brand logo is displayed in supporting mail clients; not a direct "
            "security weakness.",
            "Optionally publish a BIMI record once DMARC is at enforcement.",
            None, REF["bimi"]))

    # CAA ---------------------------------------------------------------------
    if not g["caa"]:
        F.append(_f(apex, "caa-missing", "Low",
            "No CAA record restricting certificate issuance",
            "The domain publishes no CAA record, so any public CA may issue "
            "certificates for it.",
            "A mis-issued or fraudulently obtained certificate from any CA would be "
            "accepted, enabling impersonation.",
            "Publish CAA records naming the authorized CA(s).",
            CWE_AUTHENTICITY, REF["caa"]))

    # DNSSEC ------------------------------------------------------------------
    if not g["dnssec"]:
        F.append(_f(apex, "dnssec-unsigned", "Low", "DNS zone is not DNSSEC-signed",
            "The zone publishes no DNSKEY, so its DNS responses are not "
            "cryptographically signed.",
            "DNS responses can be forged or cache-poisoned, redirecting mail and "
            "web traffic without detection.",
            "Enable DNSSEC signing and publish a DS record at the parent zone.",
            CWE_AUTHENTICITY, REF["dnssec"]))

    # MX ----------------------------------------------------------------------
    mail_records = bool(g["spf"] or g["dmarc"] or any(d["present"] for d in g["dkim"].values()))
    if not g["mx"] and mail_records:
        F.append(_f(apex, "mx-missing", "Info",
            "No MX records although mail policy records exist",
            "The domain publishes mail-authentication records (SPF/DMARC/DKIM) but "
            "advertises no MX host.",
            "Likely a misconfiguration or a send-only domain; inbound mail — "
            "including DMARC/TLS reports — cannot be delivered.",
            "Publish MX records, or for a no-mail domain use a null MX ('. ') with "
            "v=spf1 -all.",
            None, None))

    # security.txt ------------------------------------------------------------
    if g["sec_status"] != 200:
        F.append(_f(apex, "securitytxt-missing", "Info", "No security.txt published",
            f"https://{apex}/.well-known/security.txt did not return 200 "
            f"(got {g['sec_status']}).",
            "Security researchers lack a documented, machine-readable disclosure "
            "channel, slowing coordinated reporting.",
            "Publish a signed security.txt per RFC 9116.",
            None, REF["securitytxt"]))

    return F


def analyze(apex: str, selectors: list | None = None, timeout: int = 8) -> list:
    return evaluate(apex, gather(apex, selectors or DEFAULT_SELECTORS, timeout))


def run(apexes: list, selectors: list | None = None, timeout: int = 8) -> dict:
    findings: list = []
    for apex in apexes:
        findings.extend(analyze(apex, selectors, timeout))
    return {"apexes": list(apexes), "findings": findings, "version": 1}


# --- CLI ---------------------------------------------------------------------
_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _print_summary(result: dict) -> None:
    by_apex: dict = {a: [] for a in result["apexes"]}
    for f in result["findings"]:
        by_apex.setdefault(f["affected"][0], []).append(f)
    for apex, fs in by_apex.items():
        tally = {s: 0 for s in _SEV_ORDER}
        for f in fs:
            tally[f["severity"]] = tally.get(f["severity"], 0) + 1
        counts = " ".join(f"{s}:{tally[s]}" for s in _SEV_ORDER if tally[s])
        print(f"{apex}  ({counts or 'no findings'})")
        for f in sorted(fs, key=lambda x: _SEV_ORDER.index(x["severity"])):
            print(f"  [{f['severity']:<6}] {f['id']} — {f['title']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Deterministic email/DNS/TLS posture scanner.")
    ap.add_argument("apex", nargs="*", help="apex domain(s) to assess")
    ap.add_argument("--apex-file", help="file with one apex per line (# comments ok)")
    ap.add_argument("--selectors", default="", help="comma-separated DKIM selectors to probe")
    ap.add_argument("--timeout", type=int, default=8, help="per-request timeout seconds")
    ap.add_argument("--json", action="store_true", help="emit the report_data JSON document")
    args = ap.parse_args(argv)

    apexes = list(args.apex)
    if args.apex_file:
        with open(args.apex_file, encoding="utf-8") as f:
            apexes += [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    if not apexes:
        ap.error("no apex domains provided (positional or --apex-file)")

    selectors = [s.strip() for s in args.selectors.split(",") if s.strip()] or None
    result = run(apexes, selectors, args.timeout)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        _print_summary(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
