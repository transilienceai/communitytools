#!/usr/bin/env python3
"""Deterministic retest / revalidation report_data.json assembler.

The generator behind a retest engagement: take a PRIOR report's baseline findings
plus a per-finding retest verdict and emit ONE canonical report_data.json matching
skills/transilience-report-style/reference/report-data-schema.json — with NO LLM in
the loop. This retires the per-engagement one-offs (bespoke hand-written
revalidation generators, hand-transcribed portfolio roll-ups): the
baseline-vs-current table, the status-summary rollup, the drop-entirely discipline
(only still-actionable findings reach the report body) and the multi-app portfolio
matrix are all owned by this one tool.

Canonical retest-status vocabulary (any other value is rejected):
    Closed | Open | Partially-Remediated | Risk-Accepted | Needs-Live-Retest |
    False-Positive

Baseline shape (the prior report's findings — a list):
    [{"id": "F-001", "title": "...", "severity": "High",
      "cvss_vector": "CVSS:3.1/...", "affected": ["..."], "description": "...",
      "impact": "...", "recommendation": "...", ...}, ...]

Verdicts shape (a map id -> verdict):
    {"F-001": {"status": "Open", "note": "still exploitable",
               "retest_evidence": "curl ... -> 200", "current_severity": "Medium"}, ...}

Drop-entirely discipline (mirrors report_data_build): only the still-ACTIONABLE
statuses (Open / Partially-Remediated / Needs-Live-Retest) are carried into
findings[] and detailed in the report body. Closed / Risk-Accepted / False-Positive
appear only in the Baseline-vs-Current audit table and the rollup — never as a
full finding.

Controls-disabled test-build guard: an APK/build tested with security controls
switched off (a `_SSL_Disabled_`, `pinning-off`, `debug` build, or an explicit
flag) cannot prove a control is fixed. When meta.controls_disabled is set, any
Closed / Partially-Remediated verdict whose finding is about a DISABLED control is
overridden to Needs-Live-Retest ("production re-verification required").

Usage:
    retest_status_build.py --baseline <json> --verdicts <json> [--meta <json>] [-o OUT]
    retest_status_build.py --portfolio <json-list-of-docs> [--meta <json>] [-o OUT]

Exit codes: 0 ok; 1 an invalid status appeared in verdicts; 2 usage / bad input.
"""
import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import report_data_build as B                      # noqa: E402  (severity_band/SEVERITY_ORDER/sort_findings/normalize_poc)
from report_data_shape import require_report_data_shape  # noqa: E402  (validate the OUTPUT)

# --- the fixed retest vocabulary + presentation hints ------------------------
RETEST_STATUSES = ("Closed", "Open", "Partially-Remediated", "Risk-Accepted",
                   "Needs-Live-Retest", "False-Positive")

# Sort / display priority: most-urgent first (Open > Partially > Needs-Live-Retest
# > Risk-Accepted > Closed > False-Positive). Drives both the Baseline-vs-Current
# table ordering and the rollup/metric column order.
STATUS_PRIORITY = {"Open": 0, "Partially-Remediated": 1, "Needs-Live-Retest": 2,
                   "Risk-Accepted": 3, "Closed": 4, "False-Positive": 5}

# Still-actionable statuses carried into findings[] (the report body).
ACTIONABLE = frozenset({"Open", "Partially-Remediated", "Needs-Live-Retest"})
# Statuses that mean "this no longer needs remediation work". Risk-Accepted counts:
# the client owns it deliberately, which is a decision, not an outstanding fix.
CLOSED_STATUSES = frozenset({"Closed", "Risk-Accepted", "False-Positive"})
# The severities a re-validation is normally contracted to confirm.
CRITICAL_HIGH = ("Critical", "High")

# Per-status colour hint the generator can render (metric boxes read `color`; the
# map is also emitted top-level so a caller can colour the status column).
STATUS_COLORS = {
    "Open": "#c0392b",                 # red — still exploitable
    "Partially-Remediated": "#e67e22",  # orange — improved but residual risk
    "Needs-Live-Retest": "#8e44ad",    # purple — verdict pending live confirmation
    "Risk-Accepted": "#2980b9",        # blue — accepted by the business
    "Closed": "#27ae60",               # green — remediated
    "False-Positive": "#7f8c8d",       # grey — never a real issue
}

STATUS_ORDER = sorted(RETEST_STATUSES, key=lambda s: STATUS_PRIORITY[s])

# Controls-disabled / test-build markers -> the control keywords such a build
# leaves UNPROVEN. A Closed/Partially verdict whose finding mentions one of these
# keywords can't be trusted from that build and is bounced to Needs-Live-Retest.
CONTROLS_DISABLED_MARKERS = {
    "_ssl_disabled_": ("ssl", "pinning", "tls", "certificate"),
    "ssl_disabled": ("ssl", "pinning", "tls", "certificate"),
    "ssl-disabled": ("ssl", "pinning", "tls", "certificate"),
    "pinning-off": ("pinning", "ssl", "tls"),
    "pinning_off": ("pinning", "ssl", "tls"),
    "nopinning": ("pinning", "ssl", "tls"),
    "no-pin": ("pinning", "ssl", "tls"),
    "debug": ("debug", "root", "tamper", "pinning", "ssl"),
}

OVERRIDE_NOTE = "production re-verification required (retested on a controls-disabled build)"

# report-schema finding fields carried verbatim from a baseline finding.
_CARRY_FIELDS = ("cvss_score", "cvss_vector", "cwe", "owasp", "ease_of_exploitation",
                 "references", "affected", "impact", "recommendation", "cves")


class InvalidRetestStatus(ValueError):
    """A verdict carried a status outside the fixed vocabulary (CLI exit 1)."""


def _resolve_severity(sev, cvss_score=None):
    """Return a valid severity band; fall back to the CVSS-derived band else Info."""
    if sev in B.SEVERITY_ORDER:
        return sev
    return B.severity_band(cvss_score)


def detect_controls_disabled(build_markers):
    """Detect a controls-disabled / test build from filename markers or flags.

    `build_markers` may be a filename str, a list of str (filenames/flags), a bool
    (explicit flag), or a dict:
        {"filename": "...", "markers": [...], "flags": [...],
         "controls_disabled": true, "disabled_controls": ["pinning", ...],
         "disabled_finding_ids": ["F-001", ...]}

    Returns {test_build, markers, disabled_controls, disabled_finding_ids,
    affected_status_override}. `disabled_controls` are the control keywords the
    build leaves unproven; `affected_status_override` is the status a matching
    Closed/Partially verdict is bounced to.
    """
    strings, explicit, disabled_ids, extra_controls = [], False, [], []
    if isinstance(build_markers, bool):
        explicit = build_markers
    elif isinstance(build_markers, str):
        strings = [build_markers]
    elif isinstance(build_markers, (list, tuple)):
        strings = [str(x) for x in build_markers]
    elif isinstance(build_markers, dict):
        for key in ("filename", "file", "apk", "build", "path"):
            if build_markers.get(key):
                strings.append(str(build_markers[key]))
        for key in ("markers", "flags"):
            val = build_markers.get(key)
            if isinstance(val, (list, tuple)):
                strings.extend(str(x) for x in val)
            elif isinstance(val, str):
                strings.append(val)
        explicit = bool(build_markers.get("controls_disabled") or build_markers.get("test_build"))
        dc = build_markers.get("disabled_controls")
        if isinstance(dc, (list, tuple)):
            extra_controls = [str(x).lower() for x in dc]
        di = build_markers.get("disabled_finding_ids")
        if isinstance(di, (list, tuple)):
            disabled_ids = [str(x) for x in di]

    hay = " ".join(strings).lower()
    matched, controls = [], set(extra_controls)
    for marker, kws in CONTROLS_DISABLED_MARKERS.items():
        if marker in hay:
            matched.append(marker)
            controls.update(kws)

    return {
        "test_build": bool(matched) or explicit,
        "markers": sorted(set(matched)),
        "disabled_controls": sorted(controls),
        "disabled_finding_ids": disabled_ids,
        "affected_status_override": "Needs-Live-Retest",
    }


def _actionable_finding(base, status, note, current_severity, retest_evidence):
    """Build a report_data findings[] entry from a still-actionable baseline finding."""
    fid = base.get("id")
    sev = current_severity if current_severity in B.SEVERITY_ORDER else base.get("severity")
    sev = _resolve_severity(sev, base.get("cvss_score"))
    f = {
        "id": str(fid) if fid is not None else (base.get("title") or "finding"),
        "title": base.get("title") or (str(fid) if fid is not None else "Finding"),
        "severity": sev,
    }
    for k in _CARRY_FIELDS:
        if base.get(k) is not None:
            f[k] = base[k]
    retest_line = f"Retest status: {status}." + (f" {note}" if note else "")
    desc = base.get("description")
    f["description"] = retest_line + (("\n\n" + desc) if desc else "")
    poc = B.normalize_poc(base.get("poc"))
    if retest_evidence:
        poc = poc + [{"description": f"Retest evidence: {retest_evidence}"}]
    if poc:
        f["poc"] = poc
    # Weight so B.sort_findings orders Open > Partially > Needs-Live-Retest within a
    # severity band (higher _risk sorts first; sort_findings pops the key).
    f["_risk"] = 100 - STATUS_PRIORITY.get(status, 9)
    return f


def _validate_verdicts(verdicts):
    """Reject any verdict whose status is outside the fixed vocabulary."""
    if not isinstance(verdicts, dict):
        raise ValueError("verdicts must be a map of id -> verdict object")
    for vid, v in verdicts.items():
        if not isinstance(v, dict):
            raise InvalidRetestStatus(f"verdict for {vid!r} must be an object")
        st = v.get("status")
        if st not in RETEST_STATUSES:
            raise InvalidRetestStatus(
                f"invalid retest status {st!r} for {vid!r}; must be one of {list(RETEST_STATUSES)}")


def _summary_paragraph(rollup, total):
    parts = [f"{rollup[s]} {s}" for s in STATUS_ORDER if rollup[s]]
    return f"{total} baseline finding(s) retested: {', '.join(parts) if parts else 'none'}."


def _severity_cross_tab(rows):
    """Status x severity, plus the closure rate for Critical/High.

    The status rollup alone answers "how many are closed" but not "were the ones
    that mattered closed". Re-validation is normally contracted for critical and
    high findings specifically, so that number has to be readable without the
    reader cross-referencing two tables by hand.
    """
    sevs = [s for s in B.SEVERITY_ORDER if any(r["severity"] == s for r in rows)]
    header = ["Retest Status"] + sevs + ["Total"]
    table_rows = []
    for st in STATUS_ORDER:
        counts = [sum(1 for r in rows if r["status"] == st and r["severity"] == s) for s in sevs]
        if not any(counts):
            continue
        table_rows.append([st] + [str(c) for c in counts] + [str(sum(counts))])
    totals = [sum(1 for r in rows if r["severity"] == s) for s in sevs]
    table_rows.append(["Total"] + [str(c) for c in totals] + [str(len(rows))])

    high = [r for r in rows if r["severity"] in CRITICAL_HIGH]
    closed = sum(1 for r in high if r["status"] in CLOSED_STATUSES)
    para = (f"Critical/High closed: {closed} of {len(high)}." if high
            else "No Critical or High findings in the baseline.")
    if high and closed < len(high):
        para += (f" {len(high) - closed} remain unresolved — these are the items a "
                 "re-validation is normally contracted to confirm.")
    n = max(2, len(header))
    return {
        "title": "Closure by Severity",
        "paragraphs": [para],
        "table": {"header": header, "rows": table_rows,
                  "widths": [round(1.0 / n, 4)] * n},
    }


def build_retest(baseline, verdicts, meta=None):
    """Assemble a canonical retest-status report_data from baseline + verdicts.

    Emits: a "Retest Status Summary" section (status->count rollup) + top-level KPI
    metrics; a "Baseline vs Current" section (audit table, status-priority sorted);
    findings[] carrying ONLY the still-actionable items; and per-status colour hints.
    """
    meta = meta or {}
    if not isinstance(baseline, list):
        raise ValueError("baseline must be a list of findings")
    _validate_verdicts(verdicts)

    # Controls-disabled test-build guard.
    det, disabled_kw, disabled_ids = None, set(), set()
    if meta.get("controls_disabled"):
        det = detect_controls_disabled(meta["controls_disabled"])
        if det["test_build"]:
            disabled_kw = set(det["disabled_controls"])
            disabled_ids = set(det["disabled_finding_ids"])

    rows, actionable = [], []
    rollup = {s: 0 for s in RETEST_STATUSES}
    for base in baseline:
        bid = base.get("id")
        v = verdicts.get(bid) or {}
        status = v.get("status") or "Needs-Live-Retest"
        note = v.get("note") or ("" if v else "No retest verdict recorded.")

        if det and status in ("Closed", "Partially-Remediated"):
            title_l = (base.get("title") or "").lower()
            note_l = (note or "").lower()
            if bid in disabled_ids or any(kw in title_l or kw in note_l for kw in disabled_kw):
                status, note = "Needs-Live-Retest", OVERRIDE_NOTE

        rollup[status] += 1
        base_sev = _resolve_severity(base.get("severity"), base.get("cvss_score"))
        rows.append({
            "id": str(bid) if bid is not None else "",
            "title": base.get("title") or "",
            "severity": base_sev,
            "status": status,
            "note": note,
        })
        if status in ACTIONABLE:
            actionable.append(_actionable_finding(
                base, status, note, v.get("current_severity"), v.get("retest_evidence")))

    rows.sort(key=lambda r: (STATUS_PRIORITY.get(r["status"], 9),
                             B.SEVERITY_ORDER.get(r["severity"], 9), r["id"]))
    findings = B.sort_findings(actionable)

    summary_rows = [[s, str(rollup[s])] for s in STATUS_ORDER]
    summary_rows.append(["Total", str(len(baseline))])
    summary_section = {
        "title": "Retest Status Summary",
        "paragraphs": [_summary_paragraph(rollup, len(baseline))],
        "table": {"header": ["Retest Status", "Count"], "rows": summary_rows, "widths": [0.7, 0.3]},
    }
    sev_section = _severity_cross_tab(rows)
    bvc_section = {
        "title": "Baseline vs Current",
        "paragraphs": ["Every prior-report finding with its retest verdict. Closed, "
                       "Risk-Accepted and False-Positive items are retained here for the "
                       "audit trail only; still-actionable items (Open, Partially-Remediated, "
                       "Needs-Live-Retest) are detailed in the findings section."],
        "table": {
            "header": ["Baseline ID", "Title", "Baseline Severity", "Retest Status", "Note"],
            "rows": [[r["id"], r["title"], r["severity"], r["status"], r["note"]] for r in rows],
            "widths": [0.12, 0.34, 0.14, 0.18, 0.22],
        },
    }
    metrics = [{"label": s, "value": rollup[s], "color": STATUS_COLORS[s]} for s in STATUS_ORDER]

    report = {
        "engagement": meta.get("engagement", {}),
        "findings": findings,
        "metrics": metrics,
        "sections": [summary_section, sev_section, bvc_section],
        "retest_status_colors": dict(STATUS_COLORS),
        "retest_rollup": rollup,
        "retest_engagement_label": _label_from_meta(meta),
    }
    if meta.get("sections"):
        report["sections"].extend(meta["sections"])
    for k in ("executive_summary", "conclusion", "disclaimer", "ruled_out",
              "coverage_table", "tools_used", "tools_intro", "source_ips",
              "source_ips_intro", "roadmap"):
        if meta.get(k) is not None:
            report[k] = meta[k]
    if det:
        report["controls_disabled_detection"] = det

    require_report_data_shape(report)
    return report


def _label_from_meta(meta):
    eng = meta.get("engagement") or {}
    return (meta.get("label") or eng.get("title") or eng.get("target")
            or eng.get("report_id") or "")


def _rollup_from_doc(doc):
    """A retest doc's status->count. Prefer the embedded retest_rollup; else derive
    from its Baseline-vs-Current table so foreign docs still consolidate."""
    rr = doc.get("retest_rollup")
    if isinstance(rr, dict):
        return {s: int(rr.get(s, 0)) for s in RETEST_STATUSES}
    r = {s: 0 for s in RETEST_STATUSES}
    for sec in doc.get("sections") or []:
        if isinstance(sec, dict) and sec.get("title") == "Baseline vs Current":
            for row in (sec.get("table") or {}).get("rows") or []:
                if isinstance(row, list) and len(row) >= 4 and row[3] in RETEST_STATUSES:
                    r[row[3]] += 1
    return r


def _doc_label(doc, i):
    return (doc.get("retest_engagement_label")
            or (doc.get("engagement") or {}).get("title")
            or (doc.get("engagement") or {}).get("target")
            or f"Engagement {i + 1}")


def portfolio_rollup(retest_docs, meta=None):
    """Merge N retest-status docs into ONE portfolio matrix (engagement x status
    counts + an Overall rollup) for a multi-app consolidation."""
    meta = meta or {}
    if not isinstance(retest_docs, list):
        raise ValueError("retest_docs must be a list of retest-status report_data docs")

    matrix_rows, overall = [], {s: 0 for s in RETEST_STATUSES}
    for i, doc in enumerate(retest_docs):
        if not isinstance(doc, dict):
            raise ValueError("each retest doc must be an object")
        r = _rollup_from_doc(doc)
        matrix_rows.append([_doc_label(doc, i)] + [str(r[s]) for s in STATUS_ORDER] + [str(sum(r.values()))])
        for s in RETEST_STATUSES:
            overall[s] += r[s]
    grand_total = sum(overall.values())
    matrix_rows.append(["Overall"] + [str(overall[s]) for s in STATUS_ORDER] + [str(grand_total)])

    header = ["Engagement"] + list(STATUS_ORDER) + ["Total"]
    n_status = len(STATUS_ORDER)
    rest = round((1.0 - 0.24 - 0.10) / n_status, 4)
    widths = [0.24] + [rest] * n_status + [0.10]

    section = {
        "title": "Portfolio Retest Matrix",
        "paragraphs": [f"{len(retest_docs)} engagement(s) consolidated; "
                       f"{grand_total} baseline finding(s) retested overall."],
        "table": {"header": header, "rows": matrix_rows, "widths": widths},
    }
    metrics = [{"label": s, "value": overall[s], "color": STATUS_COLORS[s]} for s in STATUS_ORDER]

    report = {
        "engagement": meta.get("engagement", {}),
        "findings": [],
        "metrics": metrics,
        "sections": [section],
        "retest_status_colors": dict(STATUS_COLORS),
        "retest_rollup": overall,
    }
    if meta.get("sections"):
        report["sections"].extend(meta["sections"])
    for k in ("executive_summary", "conclusion", "disclaimer"):
        if meta.get(k) is not None:
            report[k] = meta[k]

    require_report_data_shape(report)
    return report


def _load(path):
    with open(path) as f:
        return json.load(f)


def _emit(report, out):
    payload = json.dumps(report, indent=2, sort_keys=True)
    if out:
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        with open(out, "w") as f:
            f.write(payload)
    else:
        sys.stdout.write(payload + "\n")
    summary = {
        "out": out or "(stdout)",
        "sha256": hashlib.sha256(payload.encode()).hexdigest(),
        "bytes": len(payload),
        "findings": len(report.get("findings", [])),
        "rollup": report.get("retest_rollup"),
    }
    # Summary to stdout when a file was written; to stderr when the payload owns stdout.
    print(json.dumps(summary), file=(sys.stdout if out else sys.stderr))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baseline", help="prior report's findings (JSON array)")
    ap.add_argument("--verdicts", help="map id -> {status, note, ...} (JSON object)")
    ap.add_argument("--meta", help="engagement meta / passthrough sections (JSON object)")
    ap.add_argument("--portfolio", help="JSON list of retest-status docs (or their paths)")
    ap.add_argument("-o", "--out", help="output path (default: stdout)")
    args = ap.parse_args(argv)

    try:
        if args.portfolio:
            if args.baseline or args.verdicts:
                print("ERROR: --portfolio is mutually exclusive with --baseline/--verdicts",
                      file=sys.stderr)
                return 2
            docs = _load(args.portfolio)
            if not isinstance(docs, list):
                print("ERROR: --portfolio file must contain a JSON list of docs (or paths)",
                      file=sys.stderr)
                return 2
            docs = [_load(d) if isinstance(d, str) else d for d in docs]
            report = portfolio_rollup(docs, _load(args.meta) if args.meta else {})
        else:
            if not args.baseline or not args.verdicts:
                print("ERROR: --baseline and --verdicts are required (or use --portfolio)",
                      file=sys.stderr)
                return 2
            report = build_retest(_load(args.baseline), _load(args.verdicts),
                                  _load(args.meta) if args.meta else {})
    except InvalidRetestStatus as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(f"ERROR: file not found: {e}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"ERROR: invalid JSON: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    _emit(report, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
