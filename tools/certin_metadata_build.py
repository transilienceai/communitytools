#!/usr/bin/env python3
"""Build the CERT-In Audit Metadata deliverables from a finished engagement.

Deterministic assembler — NO LLM authors the structured bytes (mirrors
tools/report_data_build.py). Reads a finished engagement's findings + an
operator config (input/certin.json) and emits, under the engagement's reports/:

  * certin-audit-metadata.json  — intermediate JSON mirroring the v2.3 fields
  * CERT-In-Audit-Metadata.xlsx — a filled copy of the official v2.3 workbook

Any field that cannot be resolved to a legal value (absent required admin field,
illegal enum, sub-sector not under its sector) is emitted as the literal
"<FILL: field>" placeholder and listed in the summary's needs_manual[] — nothing
is ever invented. Every emitted vocabulary value is validated against
formats/certin-audit-metadata/enums.json.

STDLIB ONLY (zipfile + xml). The official sheet "1. Auditor Details" is 67 MB
(≈1.05M pre-styled empty rows) so its response cells are byte-spliced, never
DOM-parsed.

Exit: 0 ok; 1 missing inputs; 2 runtime/JSON error. Last stdout line is a JSON
summary: {technical, compliance, audits, needs_manual, sha256, out, xlsx}.
"""
import argparse
import glob
import hashlib
import json
import os
import re
import sys
import zipfile
from xml.sax.saxutils import escape as xml_escape

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DEFAULT_ENUMS = os.path.join(REPO, "formats", "certin-audit-metadata", "enums.json")
DEFAULT_TEMPLATE = os.environ.get("CERTIN_TEMPLATE") or os.path.join(
    REPO, "formats", "certin-audit-metadata", "Audit-Metadata-Format-2026.xlsx")
TEMPLATE_VERSION = "2.3 July 2026"

AI_OPERATOR = "Claude Opus 4.8 (Anthropic) via Claude Code"
AI_ASSISTED_DEFAULT = "Yes — " + AI_OPERATOR + "; token usage unavailable (no runtime counter)"

# ---------------------------------------------------------------------------
# Redaction — ported from wf-helpers.mjs redactSecrets (+ Aadhaar). Applied to
# every emitted string (JSON and xlsx). Order matters: card (Luhn) before the
# broader digit patterns.
# ---------------------------------------------------------------------------
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----", re.S)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{8,}", re.I)
_AWS = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_PAN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
_CARDLIKE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_AADHAAR = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")


def _luhn_ok(digits):
    s, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        s += d
        alt = not alt
    return s % 10 == 0


def _card_sub(m):
    digits = re.sub(r"\D", "", m.group(0))
    return "[REDACTED CARD]" if 13 <= len(digits) <= 19 and _luhn_ok(digits) else m.group(0)


def redact(text):
    if not isinstance(text, str) or not text:
        return text
    t = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)
    t = _JWT.sub("[REDACTED JWT]", t)
    t = _BEARER.sub("Bearer [REDACTED]", t)
    t = _AWS.sub("[REDACTED AWS KEY]", t)
    t = _CARDLIKE.sub(_card_sub, t)
    t = _AADHAAR.sub("[REDACTED AADHAAR]", t)
    t = _PAN.sub("[REDACTED PAN]", t)
    return t


# ---------------------------------------------------------------------------
# Enum validation + <FILL> placeholders
# ---------------------------------------------------------------------------
class Fills:
    def __init__(self):
        self.needs = set()

    def fill(self, field):
        self.needs.add(field)
        return "<FILL: %s>" % field

    def choose(self, value, allowed, field):
        """Return value if legal (case-insensitive exact against `allowed`), else <FILL>."""
        if value is None or str(value).strip() == "":
            return self.fill(field)
        v = str(value).strip()
        for a in allowed:
            if v == a:
                return a
        low = v.lower()
        for a in allowed:
            if low == a.lower():
                return a
        return self.fill(field)

    def text(self, value, field):
        if value is None or str(value).strip() == "":
            return self.fill(field)
        return str(value).strip()


# CWE-number -> Attributing Factor default (overridable by the Classify workflow).
_CWE_FACTOR = {
    # Coding errors (injection / memory / logic-in-code)
    "79": "Coding Error", "89": "Coding Error", "78": "Coding Error", "77": "Coding Error",
    "90": "Coding Error", "91": "Coding Error", "94": "Coding Error", "95": "Coding Error",
    "74": "Coding Error", "502": "Coding Error", "611": "Coding Error", "918": "Coding Error",
    "434": "Coding Error", "352": "Coding Error", "22": "Coding Error", "98": "Coding Error",
    "1336": "Coding Error", "917": "Coding Error", "116": "Coding Error", "80": "Coding Error",
    # Configuration errors (headers / TLS / CORS / defaults)
    "16": "Configuration Error", "942": "Configuration Error", "614": "Configuration Error",
    "319": "Configuration Error", "693": "Configuration Error", "1188": "Configuration Error",
    "756": "Configuration Error", "776": "Configuration Error", "1004": "Configuration Error",
    "326": "Configuration Error", "327": "Configuration Error", "295": "Configuration Error",
    # Design errors (authz / access control / missing controls by design)
    "284": "Design Error", "285": "Design Error", "862": "Design Error", "863": "Design Error",
    "639": "Design Error", "306": "Design Error", "269": "Design Error", "732": "Design Error",
    "287": "Design Error", "384": "Design Error", "613": "Design Error", "522": "Design Error",
    # Deployment errors (exposed dev/debug/backup artifacts)
    "489": "Deployment Error", "552": "Deployment Error", "527": "Deployment Error",
    "540": "Deployment Error", "541": "Deployment Error", "615": "Deployment Error",
    "260": "Deployment Error", "798": "Deployment Error",
    # Operation errors (logging / monitoring / operational lapses)
    "778": "Operation Error", "223": "Operation Error", "532": "Operation Error",
    "779": "Operation Error", "1188 ": "Operation Error",
}


def default_attributing_factor(finding):
    if finding.get("cves"):
        return "Vulnerable Software Versions"
    cwe = str(finding.get("cwe") or "")
    m = re.search(r"(\d+)", cwe)
    if m and m.group(1) in _CWE_FACTOR:
        return _CWE_FACTOR[m.group(1)]
    return "Configuration Error"


_SEV_MAP = {"critical": "Critical", "high": "High", "medium": "Medium", "med": "Medium",
            "low": "Low", "info": "Informational", "informational": "Informational",
            "information": "Informational", "none": "Informational"}


def map_severity(finding):
    sev = finding.get("severity")
    if sev:
        m = _SEV_MAP.get(str(sev).strip().lower())
        if m:
            return m
    try:
        s = float(finding.get("cvss_score"))
    except (TypeError, ValueError):
        return "Informational"
    if s >= 9:
        return "Critical"
    if s >= 7:
        return "High"
    if s >= 4:
        return "Medium"
    if s > 0:
        return "Low"
    return "Informational"


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
def load_json(path):
    with open(path) as f:
        return json.load(f)


def load_findings(eng_dir):
    """Return (findings[], source, engagement_meta). Prefer report_data.json;
    else recursive glob of validated verdict JSONs (VALID/REPAIRED only)."""
    rd_path = os.path.join(eng_dir, "reports", "report_data.json")
    if os.path.isfile(rd_path):
        try:
            data = load_json(rd_path)
            if isinstance(data, dict) and isinstance(data.get("findings"), list):
                return data["findings"], "report_data.json", (data.get("engagement") or {})
        except (ValueError, OSError):
            pass  # malformed -> fall back to glob
    findings = []
    for p in sorted(glob.glob(os.path.join(eng_dir, "**", "artifacts", "validated", "*.json"), recursive=True)):
        try:
            v = load_json(p)
        except (ValueError, OSError):
            continue
        if str(v.get("verdict", "")).upper() not in ("VALID", "REPAIRED"):
            continue
        rf = v.get("report_fields") or {}
        findings.append({
            "id": v.get("finding_id") or v.get("id"),
            "title": rf.get("title") or v.get("title"),
            "severity": v.get("severity"),
            "cvss_score": v.get("cvss_score"),
            "cwe": rf.get("cwe") or v.get("cwe"),
            "owasp": rf.get("owasp") or v.get("owasp"),
            "affected": rf.get("affected") or v.get("affected") or [],
            "cves": v.get("cves") or [],
            "control_id": v.get("control_id") or rf.get("control_id"),
            "clause": v.get("clause") or rf.get("clause"),
            "type": v.get("type") or rf.get("type"),
            "framework": v.get("framework") or rf.get("framework"),
        })
    src = "artifacts/validated/*.json" if findings else None
    return findings, src, {}


def is_compliance(f):
    return bool(f.get("control_id") or f.get("clause") or str(f.get("type", "")).lower() == "compliance")


def cve_cwe_ref(f):
    ids = [c.get("id") for c in (f.get("cves") or []) if isinstance(c, dict) and c.get("id")]
    if ids:
        return ", ".join(ids)
    return str(f.get("cwe") or "").strip()


def audit_type_from_scope(eng_dir, engagement_meta):
    """Best-effort audit-type inference from the engagement scope; else None."""
    scope = {}
    sp = os.path.join(eng_dir, "engagement-scope.json")
    if os.path.isfile(sp):
        try:
            scope = load_json(sp)
        except (ValueError, OSError):
            scope = {}
    if scope.get("targets") and not scope.get("apex_domains"):
        return "Network Infrastructure Audit"
    types = {str(a.get("type", "")).lower() for a in (scope.get("assets") or []) if isinstance(a, dict)}
    if "api" in types and types <= {"api"}:
        return "API Security Audit"
    if scope.get("apex_domains") or scope.get("assets"):
        return "Website /Web Application Audit"
    method = str(engagement_meta.get("method", "")).lower()
    if "network" in method:
        return "Network Infrastructure Audit"
    return None


# ---------------------------------------------------------------------------
# Build the intermediate JSON
# ---------------------------------------------------------------------------
def build_intermediate(eng_dir, certin, overrides, enums, findings, source, engagement_meta):
    F = Fills()
    ov = overrides or {}
    cfg = certin or {}

    def pick(field, *sources):
        for s in sources:
            if s not in (None, ""):
                return s
        return None

    ambak = F.text(cfg.get("ambak_no"), "ambak_no")
    auditor = cfg.get("auditor") or {}
    auditee = cfg.get("auditee") or {}

    auditor_details = {
        "org": F.text(auditor.get("org"), "auditor.org"),
        "validated_by": F.text(auditor.get("validated_by"), "auditor.validated_by"),
        "designation": F.text(auditor.get("designation"), "auditor.designation"),
        "email": F.text(auditor.get("email"), "auditor.email"),
        "mobile": F.text(auditor.get("mobile"), "auditor.mobile"),
    }

    auditee_org = F.text(pick("auditee_org", auditee.get("name"), engagement_meta.get("target")), "auditee.name")

    # audit type: overrides > config > scope inference > FILL
    at_raw = pick("audit_type", ov.get("audit_type"), cfg.get("audit_type"), audit_type_from_scope(eng_dir, engagement_meta))
    audit_type = F.choose(at_raw, enums["audit_type"], "audit_type")
    audit_type_other = str(cfg.get("audit_type_other") or ov.get("audit_type_other") or "").strip() or (
        "NA" if audit_type != "Any other(Pls specify in adjacent column)" else F.fill("audit_type_other"))

    category = F.choose(auditee.get("category") or ov.get("category"), enums["category"], "auditee.category")
    sector = F.choose(auditee.get("sector") or ov.get("sector"), list(enums["sector"].keys()), "auditee.sector")
    subs_allowed = enums["sector"].get(sector, [])
    subsector = F.choose(auditee.get("subsector") or ov.get("subsector"), subs_allowed, "auditee.subsector")

    reason = F.choose(cfg.get("reason") or ov.get("reason"), enums["reason"], "reason")

    # standards: list -> validate each -> join legal; illegal-only -> FILL
    std_in = pick("standards", ov.get("standards"), cfg.get("standards")) or []
    if isinstance(std_in, str):
        std_in = [std_in]
    legal_std = [s for s in std_in if s in enums["standards"]]
    standards = ", ".join(legal_std) if legal_std else F.fill("standards")

    report_type = F.choose(pick("report_type", cfg.get("first_final"), ov.get("first_final")), enums["first_final"], "first_final")

    ai_assisted = str(cfg.get("ai_assisted") or ov.get("ai_assisted") or "").strip() or AI_ASSISTED_DEFAULT
    challenges = str(cfg.get("challenges") or ov.get("challenges") or "").strip() or "NA"

    # infra details: config > unique affected assets > FILL
    infra = str(auditee.get("infra") or cfg.get("infra_details") or "").strip()
    if not infra:
        assets = []
        for f in findings:
            for a in (f.get("affected") or []):
                if a and a not in assets:
                    assets.append(a)
        infra = "; ".join(assets[:20]) if assets else F.fill("infra_details")

    followup = cfg.get("followup") or {}
    dates = cfg.get("dates") or {}

    def count_val(value, field, default=None):
        if value is None or str(value).strip() == "":
            return default if default is not None else F.fill(field)
        v = str(value).strip()
        try:
            return int(v)
        except ValueError:
            return v if v in enums["count_specials"] else F.fill(field)

    vulns_first = followup.get("first_audit_count")
    if vulns_first in (None, ""):
        vulns_first = len(findings)
    vulns_first_audit = count_val(vulns_first, "followup.first_audit_count", default=len(findings))

    audit_row = {
        "sno": 1,
        "ambak_no": ambak,
        "auditee_org": auditee_org,
        "category": category,
        "sector": sector,
        "subsector": subsector,
        "audit_type": audit_type,
        "audit_type_other": audit_type_other,
        "infra_details": infra,
        "ai_assisted": ai_assisted,
        "reason": reason,
        "standards": standards,
        "challenges": challenges,
        "report_type": report_type,
        "vulns_first_audit": vulns_first_audit,
        "patch_days": count_val(followup.get("patch_days"), "followup.patch_days", default="Follow up audit not performed"),
        "followup_gap_days": count_val(followup.get("gap_days"), "followup.gap_days", default="Follow up audit not performed"),
        "open_issues": count_val(followup.get("open_issues"), "followup.open_issues", default="Follow up audit not performed"),
        "state_ut": F.choose(auditee.get("state_ut") or ov.get("state_ut"), enums["state_ut"], "auditee.state_ut"),
        "completion_date": F.text(dates.get("completion"), "dates.completion"),
        "last_audit_date": str(dates.get("last_audit") or "").strip() or "NA",
    }

    # per-finding attributing-factor overrides (by finding id)
    factor_ov = ov.get("attributing_factors") or {}

    def issue_row(idx, f):
        fid = f.get("id")
        factor_raw = factor_ov.get(fid) or default_attributing_factor(f)
        return {
            "sno": idx,
            "ambak_no": ambak,
            "auditee_org": auditee_org,
            "infra_details": infra,
            "audit_type": audit_type,
            "audit_type_other": audit_type_other,
            "report_type": report_type,
            "issue_name": F.text(f.get("title"), "finding.title"),
            "reference": cve_cwe_ref(f) or "NA",
            "severity": F.choose(map_severity(f), enums["severity"], "severity"),
            "occurrence_count": max(1, len(f.get("affected") or [])),
            "attributing_factor": F.choose(factor_raw, enums["attributing_factor"], "attributing_factor"),
        }

    def compliance_row(idx, f):
        row = issue_row(idx, f)
        ref = str(f.get("control_id") or f.get("clause") or "").strip()
        fw = str(f.get("framework") or "").strip()
        row["reference"] = (ref + (" (" + fw + ")" if fw else "")) if ref else "NA"
        return row

    tech, comp = [], []
    for f in findings:
        if is_compliance(f):
            comp.append(compliance_row(len(comp) + 1, f))
        else:
            tech.append(issue_row(len(tech) + 1, f))

    # manpower
    manpower = []
    roster = cfg.get("manpower") or []
    for i, m in enumerate(roster, start=1):
        certs_have = {str(c).strip().lower() for c in (m.get("certs") or [])}
        manpower.append({
            "sno": i, "ambak_no": ambak,
            "name": F.text(m.get("name"), "manpower[%d].name" % i),
            "email": F.text(m.get("email"), "manpower[%d].email" % i),
            "certifications": {c: ("Yes" if c.lower() in certs_have else "No") for c in enums["certifications"]},
            "years": m.get("years") if isinstance(m.get("years"), int) else (str(m.get("years") or "").strip() or "NA"),
        })
    if not manpower:
        manpower.append({
            "sno": 1, "ambak_no": ambak,
            "name": AI_OPERATOR + " (AI-assisted)",
            "email": "NA",
            "certifications": {c: "No" for c in enums["certifications"]},
            "years": "NA",
        })
        F.fill("manpower.auditor_name")  # prompt operator to add a named human auditor

    intermediate = {
        "auditor_details": {k: redact(v) for k, v in auditor_details.items()},
        "audits_completed": [{k: (redact(v) if isinstance(v, str) else v) for k, v in audit_row.items()}],
        "security_issues_technical": [{k: (redact(v) if isinstance(v, str) else v) for k, v in r.items()} for r in tech],
        "issues_compliance": [{k: (redact(v) if isinstance(v, str) else v) for k, v in r.items()} for r in comp],
        "manpower": manpower,
    }
    return intermediate, sorted(F.needs), source


# ---------------------------------------------------------------------------
# xlsx fill (stdlib zipfile + targeted XML surgery)
# ---------------------------------------------------------------------------
NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


def _cell(col, rownum, value, style, numeric):
    ref = '%s%d' % (col, rownum)
    s = ' s="%s"' % style if style else ''
    if value is None or str(value).strip() == "":
        return '<c r="%s"%s/>' % (ref, s)
    if numeric:
        return '<c r="%s"%s><v>%s</v></c>' % (ref, s, value)
    txt = xml_escape(_strip_ctrl(str(value)))
    return '<c r="%s"%s t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>' % (ref, s, txt)


def _strip_ctrl(s):
    # XML 1.0 legal chars only (tab/lf/cr allowed)
    return "".join(ch for ch in s if ch in "\t\n\r" or 0x20 <= ord(ch) <= 0xD7FF or 0xE000 <= ord(ch) <= 0xFFFD)


def _row_styles(sheetdata, rownum):
    """Return ({col: style}, spans) from the example row `rownum`, if present."""
    m = re.search(r'<row r="%d"([^>]*)>(.*?)</row>' % rownum, sheetdata, re.S)
    if not m:
        return {}, None
    spans = re.search(r'spans="([^"]+)"', m.group(1))
    styles = {}
    for cm in re.finditer(r'<c r="([A-Z]+)%d"(?:\s+s="([^"]+)")?' % rownum, m.group(2)):
        styles[cm.group(1)] = cm.group(2)
    return styles, (spans.group(1) if spans else None)


def _replace_sheetdata(xml, first_data_row, rows_xml):
    """Keep header rows (< first_data_row), drop all data/empty rows, append rows_xml."""
    def repl(m):
        inner = m.group(1)
        kept = []
        for rm in re.finditer(r'<row r="(\d+)"[^>]*?(?:/>|>.*?</row>)', inner, re.S):
            if int(rm.group(1)) < first_data_row:
                kept.append(rm.group(0))
        return "<sheetData>" + "".join(kept) + rows_xml + "</sheetData>"
    return re.sub(r"<sheetData>(.*)</sheetData>", repl, xml, count=1, flags=re.S)


def _set_dimension(xml, last_col, last_row):
    return re.sub(r'<dimension ref="[^"]*"/>', '<dimension ref="A1:%s%d"/>' % (last_col, last_row), xml, count=1)


def _fill_data_sheet(xml_bytes, first_data_row, records, colmap, numeric_cols, last_col):
    xml = xml_bytes.decode("utf-8")
    styles, spans = _row_styles(xml, first_data_row)
    rows_xml = []
    rownum = first_data_row
    for rec in records:
        cells = []
        for col, key in colmap:
            val = rec.get(key)
            cells.append(_cell(col, rownum, val, styles.get(col), col in numeric_cols and isinstance(val, int)))
        span_attr = ' spans="%s"' % spans if spans else ''
        rows_xml.append('<row r="%d"%s>%s</row>' % (rownum, span_attr, "".join(cells)))
        rownum += 1
    xml = _replace_sheetdata(xml, first_data_row, "".join(rows_xml))
    last_row = max(first_data_row - 1, rownum - 1)
    xml = _set_dimension(xml, last_col, last_row)
    return xml.encode("utf-8")


def _fill_auditor_sheet(xml_bytes, responses):
    """Byte-splice C3:C7 only; never DOM-parse the 67 MB sheet; keep <dimension>."""
    xml = xml_bytes.decode("utf-8")
    for i, value in enumerate(responses):  # responses[0]->C3 ... responses[4]->C7
        rownum = 3 + i
        pattern = r'<c r="C%d"(\s+s="[^"]*")?\s*/>' % rownum

        def repl(m, value=value):
            s = m.group(1) or ''
            if value is None or str(value).strip() == "" or str(value).startswith("<FILL"):
                # keep the cell empty for a genuine placeholder? write the FILL text so operator sees it
                if not (value and str(value).strip()):
                    return m.group(0)
            txt = xml_escape(_strip_ctrl(str(value)))
            return '<c r="C%d"%s t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>' % (rownum, s, txt)
        xml = re.sub(pattern, repl, xml, count=1)
    return xml.encode("utf-8")


AUDITS_COLMAP = [("A", "sno"), ("B", "ambak_no"), ("C", "auditee_org"), ("D", "category"),
                 ("E", "sector"), ("F", "subsector"), ("G", "audit_type"), ("H", "audit_type_other"),
                 ("I", "infra_details"), ("J", "ai_assisted"), ("K", "reason"), ("L", "standards"),
                 ("M", "challenges"), ("N", "report_type"), ("O", "vulns_first_audit"), ("P", "patch_days"),
                 ("Q", "followup_gap_days"), ("R", "open_issues"), ("S", "state_ut"), ("T", "completion_date"),
                 ("U", "last_audit_date")]
ISSUE_COLMAP = [("A", "sno"), ("B", "ambak_no"), ("C", "auditee_org"), ("D", "infra_details"),
                ("E", "audit_type"), ("F", "audit_type_other"), ("G", "report_type"), ("H", "issue_name"),
                ("I", "reference"), ("J", "severity"), ("K", "occurrence_count"), ("L", "attributing_factor")]
MANPOWER_CERT_COLS = [("E", "CISSP"), ("F", "CISA"), ("G", "CISM"), ("H", "ISO"), ("I", "DISA"), ("J", "OSCP"), ("K", "CEH")]


def _manpower_records(rows):
    out = []
    for m in rows:
        rec = {"sno": m["sno"], "ambak_no": m["ambak_no"], "name": m["name"], "email": m["email"], "years": m["years"]}
        for col, cert in MANPOWER_CERT_COLS:
            rec[col] = (m.get("certifications") or {}).get(cert, "No")
        out.append(rec)
    return out


def fill_workbook(template_path, out_path, data):
    zin = zipfile.ZipFile(template_path)
    names = zin.namelist()
    parts = {n: zin.read(n) for n in names}
    infos = {n: zin.getinfo(n) for n in names}

    parts["xl/worksheets/sheet2.xml"] = _fill_auditor_sheet(
        parts["xl/worksheets/sheet2.xml"],
        [data["auditor_details"][k] for k in ("org", "validated_by", "designation", "email", "mobile")])

    parts["xl/worksheets/sheet3.xml"] = _fill_data_sheet(
        parts["xl/worksheets/sheet3.xml"], 4, data["audits_completed"], AUDITS_COLMAP, {"A", "O"}, "U")
    parts["xl/worksheets/sheet4.xml"] = _fill_data_sheet(
        parts["xl/worksheets/sheet4.xml"], 3, data["security_issues_technical"], ISSUE_COLMAP, {"A", "K"}, "L")
    parts["xl/worksheets/sheet5.xml"] = _fill_data_sheet(
        parts["xl/worksheets/sheet5.xml"], 3, data["issues_compliance"], ISSUE_COLMAP, {"A", "K"}, "L")
    man_colmap = [("A", "sno"), ("B", "ambak_no"), ("C", "name"), ("D", "email")] + MANPOWER_CERT_COLS + [("L", "years")]
    parts["xl/worksheets/sheet6.xml"] = _fill_data_sheet(
        parts["xl/worksheets/sheet6.xml"], 3, _manpower_records(data["manpower"]), man_colmap, {"A", "L"}, "L")

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zout:
        for n in names:
            zi = zipfile.ZipInfo(n, date_time=infos[n].date_time)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = infos[n].external_attr
            zout.writestr(zi, parts[n])


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engagement-dir", required=True)
    ap.add_argument("--certin", default=None, help="operator config (default <dir>/input/certin.json)")
    ap.add_argument("--overrides", default=None, help="Classify overrides JSON (optional)")
    ap.add_argument("--enums", default=DEFAULT_ENUMS)
    ap.add_argument("--template", default=DEFAULT_TEMPLATE)
    ap.add_argument("-o", "--out", default=None)
    ap.add_argument("--xlsx", default=None)
    args = ap.parse_args()

    eng = args.engagement_dir.rstrip("/")
    if not os.path.isdir(eng):
        print("certin-build: engagement dir not found: %s" % eng, file=sys.stderr)
        return 1
    out_json = args.out or os.path.join(eng, "reports", "certin-audit-metadata.json")
    out_xlsx = args.xlsx or os.path.join(eng, "reports", "CERT-In-Audit-Metadata.xlsx")
    certin_path = args.certin or os.path.join(eng, "input", "certin.json")

    try:
        enums = load_json(args.enums)
    except (ValueError, OSError) as e:
        print("certin-build: cannot read enums %s: %s" % (args.enums, e), file=sys.stderr)
        return 2

    findings, source, engagement_meta = load_findings(eng)
    if source is None:
        print("certin-build: no findings source (report_data.json or artifacts/validated/*.json) under %s" % eng, file=sys.stderr)
        return 1

    certin = None
    if os.path.isfile(certin_path):
        try:
            certin = load_json(certin_path)
        except ValueError as e:
            print("certin-build: malformed certin config %s: %s" % (certin_path, e), file=sys.stderr)
            return 2
    overrides = None
    if args.overrides and os.path.isfile(args.overrides):
        try:
            overrides = load_json(args.overrides)
        except ValueError as e:
            print("certin-build: malformed overrides %s: %s" % (args.overrides, e), file=sys.stderr)
            return 2

    try:
        intermediate, needs_manual, source = build_intermediate(
            eng, certin, overrides, enums, findings, source, engagement_meta)
    except (KeyError, TypeError, ValueError) as e:
        print("certin-build: build error: %s" % e, file=sys.stderr)
        return 2

    body = {k: v for k, v in intermediate.items()}
    payload_bytes = json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")
    sha = hashlib.sha256(payload_bytes).hexdigest()
    body["meta"] = {"sha256": sha, "source": source, "template_version": TEMPLATE_VERSION,
                    "tlp": "AMBER", "generated_from": os.path.basename(eng)}

    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    with open(out_json, "w") as f:
        json.dump(body, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")

    try:
        fill_workbook(args.template, out_xlsx, body)
    except (OSError, zipfile.BadZipFile, KeyError) as e:
        print("certin-build: xlsx fill failed (template=%s): %s" % (args.template, e), file=sys.stderr)
        return 2

    print(json.dumps({
        "technical": len(body["security_issues_technical"]),
        "compliance": len(body["issues_compliance"]),
        "audits": len(body["audits_completed"]),
        "needs_manual": needs_manual,
        "sha256": sha,
        "out": out_json,
        "xlsx": out_xlsx,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
