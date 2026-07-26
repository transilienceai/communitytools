#!/usr/bin/env python3
"""Preflight linter for a Transilience report_data.json.

Runs the deterministic checks that catch a report the schema alone would pass but
that would crash ReportLab, render garbled, or smuggle unsafe markup into the PDF.
Reuses report_data_shape.require_report_data_shape for the hard structural
invariants, then adds content checks on the un-escaped RAW list fields plus a
double-escape sniff on the auto-escaped fields.

STDLIB ONLY. Usage:
    report_data_lint.py <report_data.json> [--strict]

Prints {"ok", "errors": [...], "warnings": [...]} as JSON. Exit codes:
    0  clean (warnings are allowed unless --strict)
    1  any hard error, or -- under --strict -- any warning
    2  usage error, or the file is unreadable / not valid JSON
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report_data_shape  # noqa: E402  (sibling module; path fixed above)

# A well-formed HTML/XML entity: numeric decimal, numeric hex, or named.
_ENTITY_RE = re.compile(r"&(?:#[0-9]+|#x[0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]*);")
# A single markup tag; group(2) is the (case-folded) tag name.
_TAG_RE = re.compile(r"<\s*/?\s*([A-Za-z][A-Za-z0-9]*)[^>]*>")
# ReportLab's inline paragraph markup allowlist. Anything else in a RAW (un-escaped)
# field is unsafe -- a balanced <img>/<a href> is still an injected element.
_ALLOWED_TAGS = frozenset({"b", "i", "u", "br", "font", "strong", "em"})

# Finding string fields that the generator auto-escapes via esc(); a pre-escaped
# entity here would be double-escaped and render literally (e.g. "&amp;" on the page).
_ESC_FINDING_FIELDS = (
    "title", "description", "impact", "recommendation",
    "ease_of_exploitation", "calibration",
)


def _has_bare_ampersand(s):
    """True if `s` has an '&' that does not begin a valid entity."""
    for m in re.finditer(r"&", s):
        if not _ENTITY_RE.match(s, m.start()):
            return True
    return False


def _has_unbalanced_angle(s):
    """True if a '<' has no matching '>' (a broken/unterminated tag).

    Strip every well-formed <...> chunk; a leftover '<' means an unbalanced tag,
    which aborts ReportLab's paragraph parse.
    """
    return "<" in re.sub(r"<[^<>]*>", "", s)


def _disallowed_tags(s):
    """Tag names present in `s` that fall outside the ReportLab inline allowlist."""
    return [m.group(1).lower() for m in _TAG_RE.finditer(s)
            if m.group(1).lower() not in _ALLOWED_TAGS]


def _iter_esc_fields(data):
    """Yield (label, value) for auto-escaped string fields (findings + table cells)."""
    for i, f in enumerate(data.get("findings", []) or []):
        if not isinstance(f, dict):
            continue
        for key in _ESC_FINDING_FIELDS:
            v = f.get(key)
            if isinstance(v, str):
                yield ("findings[%d].%s" % (i, key), v)
        for j, aff in enumerate(f.get("affected", []) or []):
            if isinstance(aff, str):
                yield ("findings[%d].affected[%d]" % (i, j), aff)
    for i, blk in enumerate(data.get("sections", []) or []):
        if not isinstance(blk, dict):
            continue
        table = blk.get("table")
        if not isinstance(table, dict):
            continue
        for h_i, h in enumerate(table.get("header", []) or []):
            if isinstance(h, str):
                yield ("sections[%d].table.header[%d]" % (i, h_i), h)
        for r_i, row in enumerate(table.get("rows", []) or []):
            if isinstance(row, list):
                for c_i, cell in enumerate(row):
                    if isinstance(cell, str):
                        yield ("sections[%d].table.rows[%d][%d]" % (i, r_i, c_i), cell)


def lint(data, strict=False):
    """Return (errors, warnings). `strict` does not change WHAT is collected here;
    the caller escalates warnings to a hard failure under --strict."""
    errors, warnings = [], []

    # Hard structural invariants first. If the shape is broken (e.g. narrative is a
    # str, or a finding lacks a severity), deeper content checks are meaningless.
    try:
        report_data_shape.require_report_data_shape(data)
    except ValueError as e:
        errors.append(str(e))
        return errors, warnings

    # Content checks on the RAW (un-escaped) list fields.
    for label, value in report_data_shape.iter_raw_fields(data):
        for j, item in enumerate(value):        # value is a list (guard passed)
            if not isinstance(item, str):
                continue
            loc = "%s[%d]" % (label, j)
            if _has_bare_ampersand(item):
                errors.append(
                    "%s: bare '&' that is not a valid entity "
                    "(use &amp;) -- breaks ReportLab paragraph parsing" % loc)
            if _has_unbalanced_angle(item):
                errors.append(
                    "%s: unbalanced '<...>' -- breaks ReportLab paragraph parsing"
                    % loc)
            for tag in _disallowed_tags(item):
                errors.append(
                    "%s: <%s> is outside the ReportLab inline allowlist "
                    "{b,i,u,br,font,strong,em} -- unsafe markup in a RAW field"
                    % (loc, tag))

    # Double-escape sniff on the auto-escaped fields (WARN; hard only under --strict,
    # which the caller enforces).
    for loc, val in _iter_esc_fields(data):
        if _ENTITY_RE.search(val):
            warnings.append(
                "%s: pre-escaped HTML entity in an auto-escaped field -- will be "
                "double-escaped and render literally" % loc)

    # Critical findings but no explicit metrics: the generator's inline default KPI
    # row omits Critical. (The default_metrics() fix renders it, but surface it.)
    sevs = [f.get("severity") for f in data.get("findings", []) if isinstance(f, dict)]
    if "Critical" in sevs and data.get("metrics") is None:
        warnings.append(
            "Critical findings present but no explicit top-level 'metrics' -- the "
            "default KPI row omits Critical")

    return errors, warnings


def _usage(msg):
    sys.stderr.write("usage: report_data_lint.py <report_data.json> [--strict]\n")
    if msg:
        sys.stderr.write("error: %s\n" % msg)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    strict = False
    paths = []
    for a in argv:
        if a == "--strict":
            strict = True
        elif a.startswith("-"):
            _usage("unknown option: %s" % a)
            return 2
        else:
            paths.append(a)
    if len(paths) != 1:
        _usage("expected exactly one <report_data.json> path")
        return 2

    try:
        with open(paths[0], "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        print(json.dumps(
            {"ok": False, "errors": ["cannot read/parse %s: %s" % (paths[0], e)],
             "warnings": []}, indent=2))
        return 2

    errors, warnings = lint(data, strict=strict)
    hard = bool(errors) or (strict and bool(warnings))
    print(json.dumps({"ok": not hard, "errors": errors, "warnings": warnings}, indent=2))
    return 1 if hard else 0


if __name__ == "__main__":
    sys.exit(main())
