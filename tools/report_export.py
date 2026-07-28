#!/usr/bin/env python3
"""report_export.py — the single report_data -> row projection, plus CSV and XML writers.

WHY THIS FILE EXISTS
--------------------
`report_xlsx_build.py` owned the only report_data -> table projection, and
`report_ingest.py` is written as its faithful inverse (asserted by
test_report_ingest.TestXlsxRoundTrip). Adding CSV and XML by copying that
projection would have produced three divergent copies of one contract and two
more spellings for `report_ingest` to chase. So the projection moved HERE, the
xlsx builder imports it, and every machine-readable export is the same rows.

Add a column once, in REGISTER_COLUMNS, and xlsx + CSV + XML all carry it.

Stdlib only, on purpose: openpyxl is optional in this repo, and CSV/XML must
still emit on a machine that does not have it.

Usage:
    python3 tools/report_export.py report_data.json --format csv -o findings.csv
    python3 tools/report_export.py report_data.json --format xml -o findings.xml
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
from xml.etree import ElementTree as ET

EXIT_OK = 0
EXIT_USAGE = 2

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

# A spreadsheet treats a cell opening with any of these as a formula, so a
# crafted finding title becomes code in the reader's client (CWE-1236). We
# prefix such a value with a single quote on export; read_cell() below is the
# exact inverse, so the round-trip through report_ingest still matches.
_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")
_SENTINEL = "'"


def neutralize(value):
    """Disarm spreadsheet formula injection without altering the logical value."""
    s = "" if value is None else str(value)
    return _SENTINEL + s if s[:1] in _FORMULA_LEAD else s


def read_cell(value):
    """Inverse of neutralize(): strip the sentinel we added, and only that."""
    s = "" if value is None else str(value)
    if s[:1] == _SENTINEL and s[1:2] in _FORMULA_LEAD:
        return s[1:]
    return s


# ---- field helpers (the canonical spellings; report_xlsx_build re-exports) ----
def norm_sev(s):
    """Canonicalize a severity label; 'Info' displays as 'Informational'."""
    s = (s or "").strip().title()
    if s in ("Info", "Informational"):
        return "Informational"
    return s if s in ("Critical", "High", "Medium", "Low") else "Informational"


def sev_display(s):
    return norm_sev(s)


def cvss_str(f):
    v = f.get("cvss_score")
    if v is None or v == "" or (isinstance(v, str) and v.strip().lower() in ("n/a", "none")):
        return "N/A"
    try:
        return f"{float(v):.1f}"
    except (TypeError, ValueError):
        return str(v)


def cvss_version(f):
    """CVSS version tag ('v4.0'/'v3.1'/'v3.0'/'v2.0') from the finding's vector
    prefix, or '' when unknown. v4.0 is the primary version repo-wide; a
    prefix-less vector is CVSS v2.0."""
    vec = f.get("cvss_vector") or ""
    m = re.match(r"(?i)^CVSS:(\d\.\d)/", str(vec))
    if m:
        return "v" + m.group(1)
    return "v2.0" if vec else ""


def cvss_label(f):
    """'CVSS v4.0 9.3' — score paired with its version when both are known."""
    score = cvss_str(f)
    ver = cvss_version(f)
    if score == "N/A":
        return "CVSS N/A"
    return f"CVSS {ver} {score}".replace("  ", " ")


def classification(f):
    bits = [b for b in (f.get("cwe"), f.get("owasp")) if b]
    return "; ".join(bits) if bits else "—"


def status_of(f):
    return "Open — needs live confirmation" if f.get("needs_live_confirmation") else "Open — confirmed"


def refs_str(f):
    refs = f.get("references") or []
    return "; ".join(str(x) for x in refs) if refs else "—"


def cves_str(f):
    out = []
    for c in (f.get("cves") or []):
        cid = c.get("id") if isinstance(c, dict) else c
        if cid:
            out.append(str(cid))
    return ", ".join(out)


def attack_str(f):
    """MITRE technique ids as a flat string. One field carries both ATT&CK
    (T1234[.001]) and ATLAS (AML.T0000) because an AI/LLM finding has no ATT&CK
    technique — ATLAS is the only taxonomy that can describe it."""
    ids = f.get("attack") or []
    if isinstance(ids, str):
        ids = [ids]
    out = [str(t).strip() for t in ids if str(t).strip()]
    return ", ".join(out)


def poc_text(f):
    """Render the ordered PoC steps as a single readable cell."""
    lines = []
    for i, step in enumerate(f.get("poc") or [], start=1):
        if not isinstance(step, dict):
            continue
        desc = (step.get("description") or "").strip()
        cmd = (step.get("command") or "").strip()
        seg = f"{i}. {desc}" if desc else f"{i}."
        if cmd:
            seg += f"\n    $ {cmd}"
        lines.append(seg)
    return "\n".join(lines) if lines else "See evidence appendix / proof package."


def affected_list(f):
    return [str(a) for a in (f.get("affected") or []) if str(a).strip()]


# ---- the projection ---------------------------------------------------------
# (header, xml element name, extractor). The header strings ARE the xlsx
# Findings Register header row and the CSV header row; report_ingest maps them
# back by these exact spellings, so changing one is a contract change.
REGISTER_COLUMNS = [
    ("ID",                   "id",             lambda f: f.get("id") or ""),
    ("Finding",              "title",          lambda f: f.get("title") or ""),
    ("Severity",             "severity",       lambda f: sev_display(f.get("severity"))),
    ("CVSS",                 "cvss",           cvss_str),
    ("CVSS Vector",          "cvss_vector",    lambda f: f.get("cvss_vector") or "—"),
    ("Affected Hosts",       "affected",       lambda f: "\n".join(affected_list(f)) or "—"),
    ("CWE / Classification", "classification", classification),
    ("CVE(s)",               "cves",           lambda f: cves_str(f) or "—"),
    ("MITRE",                "attack",         lambda f: attack_str(f) or "—"),
    ("Status",               "status",         status_of),
    ("References",           "references",     refs_str),
]

HEADERS = [h for h, _, _ in REGISTER_COLUMNS]


def finding_row(f):
    """One finding -> the canonical ordered list of display strings (raw, not
    neutralized: the xlsx builder styles cells and neutralizes separately)."""
    return [fn(f) for _, _, fn in REGISTER_COLUMNS]


def sort_key(f):
    """Severity-major, then id — the order every export presents findings in."""
    try:
        rank = SEV_ORDER.index(norm_sev(f.get("severity")))
    except ValueError:
        rank = len(SEV_ORDER)
    return (rank, str(f.get("id") or ""))


def findings_of(data):
    return [f for f in (data.get("findings") or []) if isinstance(f, dict)]


# ---- writers ----------------------------------------------------------------
def to_csv(data):
    """RFC 4180: CRLF terminators, quotes doubled inside quoted fields. Emitted
    with a UTF-8 BOM because Excel reads a BOM-less UTF-8 CSV as the local
    codepage and mangles every non-ASCII character (the em-dash placeholders
    here are non-ASCII, so this is not hypothetical)."""
    buf = io.StringIO(newline="")
    w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    w.writerow(HEADERS)
    for f in sorted(findings_of(data), key=sort_key):
        w.writerow([neutralize(v) for v in finding_row(f)])
    return "﻿" + buf.getvalue()


def to_xml(data):
    """A 1:1 mirror of the same rows. Built with ElementTree so escaping is the
    library's job — hand-built XML is how injection gets in."""
    eng = data.get("engagement") or {}
    root = ET.Element("report")
    meta = ET.SubElement(root, "engagement")
    for k in ("title", "subtitle", "target", "sector", "method", "date",
              "classification", "report_id", "prepared_by"):
        if eng.get(k):
            ET.SubElement(meta, k).text = str(eng[k])

    findings = sorted(findings_of(data), key=sort_key)
    fs = ET.SubElement(root, "findings", count=str(len(findings)))
    for f in findings:
        el = ET.SubElement(fs, "finding")
        for (_, tag, fn) in REGISTER_COLUMNS:
            # XML has no formula semantics, so values go in verbatim.
            ET.SubElement(el, tag).text = fn(f)
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"


WRITERS = {"csv": to_csv, "xml": to_xml}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Export report_data.json findings as CSV or XML.")
    ap.add_argument("report_data", help="path to report_data.json")
    ap.add_argument("--format", required=True, choices=sorted(WRITERS), help="output format")
    ap.add_argument("-o", "--out", help="output path (default: stdout)")
    a = ap.parse_args(argv)

    if not os.path.isfile(a.report_data):
        print(f"report_export: no such file: {a.report_data}", file=sys.stderr)
        return EXIT_USAGE
    try:
        with open(a.report_data, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        print(f"report_export: cannot read {a.report_data}: {e}", file=sys.stderr)
        return EXIT_USAGE
    if not isinstance(data, dict):
        print("report_export: report_data.json must be a JSON object", file=sys.stderr)
        return EXIT_USAGE

    text = WRITERS[a.format](data)
    n = len(findings_of(data))
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        print(f"report_export: wrote {n} finding(s) -> {a.out} ({a.format})")
    else:
        sys.stdout.write(text)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
