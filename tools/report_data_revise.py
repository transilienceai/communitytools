#!/usr/bin/env python3
"""In-place, non-destructive reviser for an EXISTING report_data.json.

This is the INCREMENTAL-revision entry point — distinct from merge-reports'
N->1 consolidation. When a finished engagement needs a new round folded in, a
re-score applied, the scope narrowed, or sibling findings cross-fed, doing it by
hand means fragile `list.insert()` + string `.replace()` surgery on the JSON, and
the narrative finding-counts silently desync from the actual finding set. This
tool makes each of those a composable, deterministic operation and — after ANY
op — re-derives everything downstream of the finding set so the prose can never
disagree with the numbers.

Deterministic bytes only — NO LLM authors the output. Every derived structure is
recomputed from the existing report_data_build / report_data_shape / cvss_calc
helpers (never hand-rolled here):

  * findings order        -> report_data_build.sort_findings
  * KPI metric boxes      -> report_data_shape.default_metrics
  * CVE register          -> report_data_build.build_cve_register
  * severity band <- score-> report_data_build.severity_band
  * CVSS score+band       -> cvss_calc.base_score / severity / detect_version

Operations (composable; applied in the fixed canonical order below regardless of
CLI order — set-changing ops first, then re-score, then scope/renumber last so it
runs on the settled, re-scored set):

  1. --append      <findings.json>  add findings (a JSON list, or a report_data
                                    with a findings[] key).
  2. --supersede   <findings.json>  replace existing findings by matching id
                                    (add when the id is new).
  3. --cross-feed  <sibling.json>   like --append but tags each merged finding
                                    with a `merged_from` note (the sibling's
                                    engagement report_id/title, or filename).
  4. --rescore     <disposition.csv> header `id,severity[,cvss_score,cvss_vector,
                                    disposition]`; update each row's finding. When
                                    a cvss_vector is given the score+band are
                                    recomputed from it and the vector-derived band
                                    WINS over a contradictory csv severity (the
                                    override is recorded). Unknown ids are
                                    reported, never fatal.
  5. --scope       <allowlist>      text (one host/asset per line) or a JSON list;
                                    KEEP only findings whose affected/asset/url
                                    intersects the allowlist, then RENUMBER the
                                    survivors F-001..F-NNN in sort order.

ALWAYS after the ops: re-sort, rebuild metrics + cve_register, and SCRUB
finding-count phrases ("N findings", "all N findings", "N vulnerabilities") in
executive_summary.narrative/key_risks/positives and conclusion to the NEW total.
Every other key is preserved verbatim.

Usage:
    python3 tools/report_data_revise.py <report_data.json> [ops...] [-o OUT]

Output defaults to <input>.revised.json — the input is NEVER clobbered unless -o
is given and resolves to the input path explicitly.

Exit codes: 0 ok; 1 revision error (revised report fails shape validation);
2 usage / unreadable JSON. Prints a JSON summary
{ok, ops_applied, findings_before, findings_after, renumbered,
 unknown_rescore_ids, out} on success.
"""
import argparse
import csv
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import report_data_build as B      # noqa: E402  severity_band/SEVERITY_ORDER/sort_findings/build_cve_register
import report_data_shape as S      # noqa: E402  default_metrics / require_report_data_shape
import cvss_calc                   # noqa: E402  base_score / severity / detect_version


class OpInputError(Exception):
    """An operation input file is missing / unreadable / wrong shape -> exit 2."""


def err(msg):
    print(f"ERROR: {msg}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Loaders
# --------------------------------------------------------------------------- #
def load_json_file(path):
    with open(path) as f:
        return json.load(f)


def load_op_json(path):
    try:
        return load_json_file(path)
    except FileNotFoundError:
        raise OpInputError(f"op input not found: {path}")
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
        raise OpInputError(f"op input not valid JSON ({path}): {e}")


def load_findings_list(path):
    """Return (findings_list, container_or_None). Accepts either a bare JSON list
    of finding objects or a full report_data object carrying a findings[] key."""
    data = load_op_json(path)
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return data["findings"], data
    if isinstance(data, list):
        return data, None
    raise OpInputError(f"{path}: expected a findings list or report_data with findings[]")


def load_allowlist(path):
    """A JSON list, or a text file with one host/asset per line (# comments and
    blank lines ignored)."""
    try:
        with open(path) as f:
            raw = f.read()
    except FileNotFoundError:
        raise OpInputError(f"scope allowlist not found: {path}")
    except (OSError, UnicodeDecodeError) as e:
        raise OpInputError(f"scope allowlist unreadable ({path}): {e}")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, list):
        return [str(x).strip() for x in data if str(x).strip()]
    return [ln.strip() for ln in raw.splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


# --------------------------------------------------------------------------- #
# Finding normalization + set operations
# --------------------------------------------------------------------------- #
def normalize_finding(f):
    """Guarantee a valid severity band on an INCOMING finding (from an op file);
    everything else is preserved verbatim. Non-dicts are dropped (return None)."""
    if not isinstance(f, dict):
        return None
    if f.get("severity") not in B.SEVERITY_ORDER:
        f = dict(f)
        f["severity"] = B.severity_band(f.get("cvss_score"))
    return f


def apply_append(findings, incoming):
    added = 0
    for nf in incoming:
        nf = normalize_finding(nf)
        if nf is None:
            continue
        findings.append(nf)
        added += 1
    return added


def apply_supersede(findings, incoming):
    """Replace findings by matching id (first occurrence), add when id is new."""
    idx = {}
    for i, f in enumerate(findings):
        fid = f.get("id")
        if fid is not None:
            idx.setdefault(fid, i)
    replaced = added = 0
    for nf in incoming:
        nf = normalize_finding(nf)
        if nf is None:
            continue
        fid = nf.get("id")
        if fid is not None and fid in idx:
            findings[idx[fid]] = nf
            replaced += 1
        else:
            findings.append(nf)
            if fid is not None:
                idx[fid] = len(findings) - 1
            added += 1
    return replaced, added


def apply_cross_feed(findings, incoming, container, src_name):
    """Like append, but stamp each merged finding with a `merged_from` provenance
    note (unless it already carries one)."""
    tag = None
    if isinstance(container, dict):
        eng = container.get("engagement") or {}
        tag = eng.get("report_id") or eng.get("title")
    if not tag:
        tag = src_name
    added = 0
    for nf in incoming:
        nf = normalize_finding(nf)
        if nf is None:
            continue
        nf = dict(nf)
        if not nf.get("merged_from"):
            nf["merged_from"] = tag
        findings.append(nf)
        added += 1
    return added


def apply_rescore(findings, path):
    """Update findings per a disposition CSV. Returns
    (unknown_ids, updated_count, band_overrides, vector_errors)."""
    by_id = {}
    for f in findings:
        fid = f.get("id")
        if fid is not None:
            by_id.setdefault(str(fid), []).append(f)

    unknown, updated, overrides, errors = [], 0, [], []
    try:
        fh = open(path, newline="")
    except FileNotFoundError:
        raise OpInputError(f"rescore CSV not found: {path}")
    except (OSError, UnicodeDecodeError) as e:
        raise OpInputError(f"rescore CSV unreadable ({path}): {e}")
    with fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or "id" not in reader.fieldnames:
            raise OpInputError(f"rescore CSV missing required 'id' header column: {path}")
        for row in reader:
            fid = (row.get("id") or "").strip()
            if not fid:
                continue
            targets = by_id.get(fid)
            if not targets:
                unknown.append(fid)
                continue
            csv_sev = (row.get("severity") or "").strip()
            vec = (row.get("cvss_vector") or "").strip()
            score_str = (row.get("cvss_score") or "").strip()

            band = score = None
            if vec:
                try:
                    score = cvss_calc.base_score(vec)
                    band = cvss_calc.severity(score, cvss_calc.detect_version(vec))
                except ValueError as e:
                    errors.append({"id": fid, "vector": vec, "error": str(e)})
                    vec = ""  # fall back to the csv severity/score columns
            for f in targets:
                if vec:
                    f["cvss_vector"] = vec
                    f["cvss_score"] = score
                    f["severity"] = band
                    if csv_sev and csv_sev != band:
                        overrides.append({"id": fid, "csv_severity": csv_sev,
                                          "vector_band": band})
                else:
                    if score_str:
                        try:
                            f["cvss_score"] = float(score_str)
                        except ValueError:
                            pass
                    if csv_sev in B.SEVERITY_ORDER:
                        f["severity"] = csv_sev
                    elif csv_sev:                       # given but not a valid band
                        f["severity"] = B.severity_band(f.get("cvss_score"))
                    elif score_str:                     # only a score -> derive band
                        f["severity"] = B.severity_band(f.get("cvss_score"))
                updated += 1
    return unknown, updated, overrides, errors


# --------------------------------------------------------------------------- #
# Scope filtering + renumbering
# --------------------------------------------------------------------------- #
def finding_assets(f):
    """Every asset-ish string a finding names (affected[] / asset / url)."""
    vals = []
    for key in ("affected", "asset", "url"):
        v = f.get(key)
        if isinstance(v, list):
            vals.extend(str(x) for x in v)
        elif isinstance(v, str):
            vals.append(v)
    return [v for v in vals if v]


def in_scope(f, allow_lc):
    """A finding is in scope if any allowlist token and any of its asset strings
    coincide by containment (either direction), case-insensitively — so
    'app.example.com' matches 'https://app.example.com/x' and '192.0.2.10' matches
    '192.0.2.10:443'."""
    assets = [a.lower() for a in finding_assets(f)]
    for tok in allow_lc:
        for a in assets:
            if tok == a or tok in a or a in tok:
                return True
    return False


def renumber(findings):
    """Assign F-001..F-NNN over an already-sorted list; return the old->new map
    (every kept finding recorded, so the map is truthy whenever survivors exist)."""
    width = max(3, len(str(len(findings))))
    mapping = {}
    for i, f in enumerate(findings, 1):
        new = f"F-{i:0{width}d}"
        mapping[str(f.get("id"))] = new
        f["id"] = new
    return mapping


# --------------------------------------------------------------------------- #
# Narrative finding-count scrub
# --------------------------------------------------------------------------- #
# The count sits immediately before a finding/vulnerability noun (severity-scoped
# phrases like "3 High findings" put a word between the two and are left alone).
# The lookbehind avoids matching a digit inside a decimal / hyphenated id.
_COUNT_RE = re.compile(
    r'(?<![\d.\-])(\d+)(\s+)(findings?|vulnerabilit(?:y|ies))\b', re.IGNORECASE)


def _scrub_str(s, total):
    return _COUNT_RE.sub(lambda m: f"{total}{m.group(2)}{m.group(3)}", s)


def scrub_counts(value, total):
    """Recursively rewrite finding-count phrases in strings within lists/dicts."""
    if isinstance(value, str):
        return _scrub_str(value, total)
    if isinstance(value, list):
        return [scrub_counts(v, total) for v in value]
    if isinstance(value, dict):
        return {k: scrub_counts(v, total) for k, v in value.items()}
    return value


def scrub_report_counts(report, total):
    es = report.get("executive_summary")
    if isinstance(es, dict):
        for k in ("narrative", "key_risks", "positives"):
            if k in es:
                es[k] = scrub_counts(es[k], total)
    if "conclusion" in report:
        report["conclusion"] = scrub_counts(report["conclusion"], total)


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def revise(report, args):
    """Apply the ops to `report` in place; return the summary dict (minus `out`)."""
    findings = report["findings"]
    findings_before = len(findings)
    ops_applied = []
    unknown_ids, band_overrides, rescore_errors = [], [], []

    # 1. append
    for p in args.append:
        inc, _ = load_findings_list(os.path.abspath(p))
        n = apply_append(findings, inc)
        ops_applied.append(f"append:{os.path.basename(p)}(+{n})")
    # 2. supersede
    for p in args.supersede:
        inc, _ = load_findings_list(os.path.abspath(p))
        rep, add = apply_supersede(findings, inc)
        ops_applied.append(f"supersede:{os.path.basename(p)}(replaced {rep}, added {add})")
    # 3. cross-feed
    for p in args.cross_feed:
        inc, container = load_findings_list(os.path.abspath(p))
        n = apply_cross_feed(findings, inc, container, os.path.basename(p))
        ops_applied.append(f"cross-feed:{os.path.basename(p)}(+{n})")
    # 4. rescore (over the settled set — a just-appended finding can be re-scored)
    for p in args.rescore:
        unk, upd, ov, errs = apply_rescore(findings, os.path.abspath(p))
        unknown_ids.extend(unk)
        band_overrides.extend(ov)
        rescore_errors.extend(errs)
        ops_applied.append(f"rescore:{os.path.basename(p)}({upd} updated, {len(unk)} unknown)")

    findings = B.sort_findings(findings)

    # 5. scope (last: renumbering ids must run on the final, re-scored set)
    renumbered = {}
    if args.scope:
        allow_lc = []
        for p in args.scope:
            allow_lc.extend(t.lower() for t in load_allowlist(os.path.abspath(p)))
        before = len(findings)
        kept = B.sort_findings([f for f in findings if in_scope(f, allow_lc)])
        renumbered = renumber(kept)
        ops_applied.append(f"scope({len(args.scope)} list(s)): kept {len(kept)}/{before}, renumbered")
        findings = kept

    findings_after = len(findings)

    # Always re-derive everything downstream of the finding set.
    report["findings"] = findings
    report["metrics"] = S.default_metrics(findings)
    cve_register = B.build_cve_register(findings)
    if cve_register:
        report["cve_register"] = cve_register
    elif "cve_register" in report:
        del report["cve_register"]
    scrub_report_counts(report, findings_after)

    summary = {
        "ok": True,
        "ops_applied": ops_applied,
        "findings_before": findings_before,
        "findings_after": findings_after,
        "renumbered": renumbered,
        "unknown_rescore_ids": unknown_ids,
    }
    if band_overrides:
        summary["rescore_band_overrides"] = band_overrides
    if rescore_errors:
        summary["rescore_errors"] = rescore_errors
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report", help="existing report_data.json to revise")
    ap.add_argument("--append", action="append", default=[], metavar="FINDINGS.json")
    ap.add_argument("--supersede", action="append", default=[], metavar="FINDINGS.json")
    ap.add_argument("--cross-feed", action="append", default=[], dest="cross_feed",
                    metavar="SIBLING.json")
    ap.add_argument("--rescore", action="append", default=[], metavar="DISPOSITION.csv")
    ap.add_argument("--scope", action="append", default=[], metavar="ALLOWLIST")
    ap.add_argument("-o", "--out", help="output path (default <input>.revised.json)")
    args = ap.parse_args(argv)

    in_path = os.path.abspath(args.report)
    if not os.path.isfile(in_path):
        err(f"input not found: {args.report}")
        return 2
    try:
        report = load_json_file(in_path)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
        err(f"cannot read input JSON ({args.report}): {e}")
        return 2
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        err("input is not a report_data object with a findings[] list")
        return 2

    if not (args.append or args.supersede or args.cross_feed or args.rescore or args.scope):
        err("no operations given (need at least one of "
            "--append/--supersede/--cross-feed/--rescore/--scope)")
        return 2

    out_path = os.path.abspath(args.out) if args.out else in_path + ".revised.json"

    try:
        summary = revise(report, args)
    except OpInputError as e:
        err(str(e))
        return 2

    # Guard the revised payload against the shapes that would crash / mis-render
    # the PDF generator; a violation is a revision error (exit 1), not a write.
    try:
        S.require_report_data_shape(report)
    except ValueError as e:
        err(f"revised report failed shape validation: {e}")
        return 1

    payload = json.dumps(report, indent=2)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w") as f:
        f.write(payload)

    summary["out"] = out_path
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
