#!/usr/bin/env python3
"""Crash-invariant guard + KPI helper for the Transilience report generator.

STDLIB ONLY. This module MUST import cleanly with NO reportlab present (the
offline CI lint job has no reportlab), so it imports nothing beyond the stdlib.

`generate_report.py` imports two things from here:
  * require_report_data_shape(data) -- the last-line-of-defense guard, run right
    before build(), that raises ValueError on the invariants that would otherwise
    make ReportLab crash or silently mis-render.
  * default_metrics(findings)        -- the KPI metric boxes, INCLUDING a Critical
    box when any Critical finding exists (the generator's inline default omits it).

Why the RAW-fed list fields matter: a handful of report_data fields are handed to
ReportLab's Paragraph() WITHOUT html.escape() -- so they may carry inline markup
(<b>, <font>, ...). Each is rendered as `for item in field: Paragraph(item)`. If
one of those fields is a bare STRING instead of a list, ReportLab iterates it over
CHARACTERS and emits one Paragraph per character -- a silent, garbled render. Those
same fields are therefore the crash surface this guard defends.
"""

from collections import Counter

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

# The RAW-fed (un-escaped) list fields, as (dotted-label, parent_key, field_key,
# per_section). These are the ONLY report_data fields whose items reach a
# Paragraph() without esc(); everything under findings[] and every table cell is
# auto-escaped by the generator. Kept as the single source of truth that
# iter_raw_fields() walks, so the guard and the linter never drift apart.
#   executive_summary.narrative   -> generate_report.py Paragraph(p) ~:317
#   executive_summary.key_risks   -> Paragraph("&bull; " + t)        ~:336
#   executive_summary.positives   -> Paragraph("&bull; " + t)        ~:339
#   sections[].paragraphs         -> Paragraph(p)                    ~:349
#   conclusion.narrative          -> Paragraph(p)                    ~:531
RAW_LIST_FIELDS = (
    ("executive_summary.narrative", "executive_summary", "narrative", False),
    ("executive_summary.key_risks", "executive_summary", "key_risks", False),
    ("executive_summary.positives", "executive_summary", "positives", False),
    ("sections[].paragraphs", "sections", "paragraphs", True),
    ("conclusion.narrative", "conclusion", "narrative", False),
)


def iter_raw_fields(data):
    """Yield (label, value) for each RAW-fed list field PRESENT in `data`.

    `value` is the raw object found at that location (str / list / other) -- the
    caller decides whether that shape is acceptable. Absent fields are skipped.
    Shared by the shape guard (str-not-list check) and the linter (per-item
    content checks), so both agree on exactly which fields are un-escaped.
    """
    if not isinstance(data, dict):
        return
    for label, parent_key, field_key, per_section in RAW_LIST_FIELDS:
        parent = data.get(parent_key)
        if per_section:
            if isinstance(parent, list):
                for i, blk in enumerate(parent):
                    if isinstance(blk, dict) and field_key in blk:
                        yield ("%s[%d].%s" % (parent_key, i, field_key), blk[field_key])
        elif isinstance(parent, dict) and field_key in parent:
            yield (label, parent[field_key])


def require_report_data_shape(data):
    """Raise ValueError on the CRASH-CAUSING invariants only. Returns None.

    This is the generator's last-line-of-defense guard, not a full linter -- it
    covers exactly the shapes that would crash ReportLab or silently mis-render:
      * top-level not a dict, or missing `engagement` / `findings`;
      * any RAW list-field present as a bare str (renders one Paragraph per char);
      * any findings[] entry missing id/title/severity, or severity not a valid band;
      * top-level `metrics` / a finding's `poc` present but not a list.
    """
    if not isinstance(data, dict):
        raise ValueError(
            "report_data must be a JSON object, got %s" % type(data).__name__)
    for key in ("engagement", "findings"):
        if key not in data:
            raise ValueError("report_data missing required top-level key %r" % key)
    if not isinstance(data["findings"], list):
        raise ValueError(
            "report_data.findings must be a list, got %s"
            % type(data["findings"]).__name__)

    # RAW list-fields must be lists -- never a bare string (would render one
    # Paragraph per character), never any other non-list type.
    for label, value in iter_raw_fields(data):
        if isinstance(value, str):
            raise ValueError(
                "%s must be a list of strings, not a bare string "
                "(a string renders as one Paragraph per CHARACTER)" % label)
        if not isinstance(value, list):
            raise ValueError(
                "%s must be a list, got %s" % (label, type(value).__name__))

    for i, f in enumerate(data["findings"]):
        if not isinstance(f, dict):
            raise ValueError("findings[%d] must be an object" % i)
        for key in ("id", "title", "severity"):
            if key not in f:
                raise ValueError("findings[%d] missing required key %r" % (i, key))
        if f["severity"] not in SEVERITIES:
            raise ValueError(
                "findings[%d] severity %r not one of %s"
                % (i, f["severity"], list(SEVERITIES)))
        poc = f.get("poc")
        if poc is not None and not isinstance(poc, list):
            raise ValueError(
                "findings[%d].poc must be a list when present, got %s"
                % (i, type(poc).__name__))

    metrics = data.get("metrics")
    if metrics is not None and not isinstance(metrics, list):
        raise ValueError(
            "metrics must be a list when present, got %s" % type(metrics).__name__)


def default_metrics(findings):
    """KPI metric boxes derived from severity counts, capped to 6.

    Drop-in replacement for the generator's inline default (~:320), except a
    Critical box is included WHENEVER any Critical finding exists -- the inline
    default hard-codes [High, Medium, Low, Info] and would drop Critical counts.
    A clean report (no Criticals) gets no empty Critical box.
    """
    counts = Counter(
        f.get("severity", "Info") for f in findings if isinstance(f, dict))
    keys = [k for k in SEVERITIES if k != "Critical"]
    if counts.get("Critical", 0) > 0:
        keys = list(SEVERITIES)
    keys = keys[:6]
    return [{"label": k.upper(), "value": counts.get(k, 0), "sev": k} for k in keys]
