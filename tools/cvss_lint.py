#!/usr/bin/env python3
"""Authoring-time CVSS self-consistency linter.

Recomputes a finding's base score and qualitative band FROM its `cvss_vector`
and flags contradictions BEFORE the finding is filed — a claimed score that does
not match the vector, a severity label that does not match the recomputed band,
a CVE labelled inconsistently with its own score, or an unparseable vector.

All CVSS arithmetic is delegated to the canonical calculator (tools/cvss_calc.py)
— this module computes NO CVSS math of its own and does not use the pip `cvss`
package. It only compares what the author claimed against what cvss_calc returns.

Input shapes (auto-detected):
  * a report_data.json — a dict with a top-level `findings` array (override the
    array key with --findings-key),
  * a bare JSON list of findings,
  * a single finding dict.

Exit codes: 0 = every finding self-consistent; 1 = at least one inconsistency;
2 = usage error or unreadable / malformed JSON.

CLI:
    python3 tools/cvss_lint.py report_data.json
    python3 tools/cvss_lint.py --lenient finding.json
    cat report_data.json | python3 tools/cvss_lint.py
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import cvss_calc as C  # noqa: E402  (canonical CVSS math — the ONLY score source)

# Result schema version, surfaced on every lint_finding() result.
SCHEMA_VERSION = 1

# Version assumed when a bare score+severity pair carries no vector to detect
# from (v3.1 is the modern default band set: None/Low/Medium/High/Critical).
_DEFAULT_VERSION = "3.1"

# Canonical band each cvss_calc severity() may return.
_CANON_BANDS = {"none": "None", "low": "Low", "medium": "Medium",
                "high": "High", "critical": "Critical"}


def _normalize_band(label) -> str:
    """Map a claimed severity label onto a cvss_calc band for comparison.

    Case-insensitive. 'Info' / 'Informational' / '' all fold to 'None' (cvss_calc
    has no Informational band). An unrecognized label passes through unchanged so
    it can never silently match a real band."""
    t = str(label).strip().lower()
    if t in ("info", "informational", "none", ""):
        return "None"
    return _CANON_BANDS.get(t, str(label).strip())


def _is_number(x) -> bool:
    """True for a real int/float, excluding bool (a subclass of int)."""
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _score_issue(scope, claimed, recomputed, vector, cve=None):
    """A score_mismatch issue when |recomputed - claimed| exceeds the 0.1 band."""
    delta = round(abs(recomputed - claimed), 1)
    if delta <= 0.1:  # boundary: exactly 0.1 is within tolerance, not a mismatch
        return None
    issue = {"scope": scope, "kind": "score_mismatch", "claimed": claimed,
             "recomputed": recomputed, "delta": delta, "vector": vector}
    if cve is not None:
        issue["cve"] = cve
    return issue


def _band_issue(scope, claimed, expected, vector=None, recomputed_score=None,
                cve=None, assumed_version=None):
    """A band_mismatch issue when a claimed label disagrees with the band."""
    if _normalize_band(claimed) == expected:
        return None
    issue = {"scope": scope, "kind": "band_mismatch", "claimed": claimed,
             "expected": expected}
    if recomputed_score is not None:
        issue["recomputed_score"] = recomputed_score
    if vector is not None:
        issue["vector"] = vector
    if cve is not None:
        issue["cve"] = cve
    if assumed_version is not None:
        issue["assumed_version"] = assumed_version
    return issue


def _score_vector(vector):
    """Delegate to cvss_calc. Return (score, version, band) or raise ValueError."""
    score = C.base_score(vector)
    version = C.detect_version(vector)
    return score, version, C.severity(score, version)


def lint_finding(finding: dict, lenient: bool = False) -> dict:
    """Lint one finding for internal CVSS consistency.

    Returns {"id", "ok", "issues", "recomputed" | None, "version"}. `ok` is True
    when there are no blocking issues; under `lenient`, an unparseable_vector is
    recorded but does not block."""
    issues = []
    recomputed = None
    finding_version = None  # from the finding's own vector; band-default for CVEs

    vector = finding.get("cvss_vector")
    if vector:
        try:
            score, version, band = _score_vector(vector)
            finding_version = version
            recomputed = {"score": score, "severity": band, "version": version}
            claimed_score = finding.get("cvss_score")
            if _is_number(claimed_score):
                issue = _score_issue("finding", claimed_score, score, vector)
                if issue:
                    issues.append(issue)
            claimed_sev = finding.get("severity")
            if isinstance(claimed_sev, str) and claimed_sev.strip():
                issue = _band_issue("finding", claimed_sev, band, vector=vector,
                                    recomputed_score=score)
                if issue:
                    issues.append(issue)
        except ValueError as exc:
            issues.append({"scope": "finding", "kind": "unparseable_vector",
                           "vector": vector, "error": str(exc)})

    for cve in finding.get("cves") or []:
        if not isinstance(cve, dict):
            continue
        cid = cve.get("id")
        cvec = cve.get("vector")
        if cvec:
            try:
                cscore, _, cband = _score_vector(cvec)
                claimed_cscore = cve.get("score")
                if _is_number(claimed_cscore):
                    issue = _score_issue("cve", claimed_cscore, cscore, cvec, cve=cid)
                    if issue:
                        issues.append(issue)
                claimed_csev = cve.get("severity")
                if isinstance(claimed_csev, str) and claimed_csev.strip():
                    issue = _band_issue("cve", claimed_csev, cband, vector=cvec,
                                        recomputed_score=cscore, cve=cid)
                    if issue:
                        issues.append(issue)
            except ValueError as exc:
                issues.append({"scope": "cve", "cve": cid,
                               "kind": "unparseable_vector", "vector": cvec,
                               "error": str(exc)})
        else:
            # No vector on this CVE: band-check its score against a version
            # detected from the finding's vector, else the assumed default.
            claimed_cscore = cve.get("score")
            claimed_csev = cve.get("severity")
            if _is_number(claimed_cscore) and isinstance(claimed_csev, str) \
                    and claimed_csev.strip():
                version = finding_version or _DEFAULT_VERSION
                assumed = _DEFAULT_VERSION if finding_version is None else None
                cband = C.severity(claimed_cscore, version)
                issue = _band_issue("cve", claimed_csev, cband, cve=cid,
                                    assumed_version=assumed)
                if issue:
                    issue["score"] = claimed_cscore
                    issues.append(issue)

    blocking = [i for i in issues
                if not (lenient and i["kind"] == "unparseable_vector")]
    return {
        "id": finding.get("id"),
        "ok": not blocking,
        "issues": issues,
        "recomputed": recomputed,
        "version": SCHEMA_VERSION,
    }


def lint_all(data, findings_key="findings", lenient=False):
    """Auto-detect the input shape and lint every finding it contains.

    Returns (results, exit_code). exit_code is 2 for an unrecognized shape."""
    if isinstance(data, dict) and isinstance(data.get(findings_key), list):
        findings = data[findings_key]
    elif isinstance(data, list):
        findings = data
    elif isinstance(data, dict):
        findings = [data]
    else:
        return None, 2
    results = [lint_finding(f, lenient=lenient) for f in findings
               if isinstance(f, dict)]
    inconsistent = sum(1 for r in results if not r["ok"])
    return results, (1 if inconsistent else 0)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", metavar="JSON",
                    help="report_data.json / findings list / single finding "
                         "(reads stdin when omitted)")
    ap.add_argument("--findings-key", default="findings",
                    help="top-level array key to lint (default: findings)")
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--strict", action="store_true",
                     help="unparseable vectors block (the default)")
    grp.add_argument("--lenient", action="store_true",
                     help="unparseable vectors are reported but do not block")
    args = ap.parse_args(argv)

    try:
        if args.path:
            with open(args.path, "r", encoding="utf-8") as fh:
                raw = fh.read()
        else:
            raw = sys.stdin.read()
    except OSError as exc:
        print(f"ERROR: cannot read input: {exc}", file=sys.stderr)
        return 2

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: input is not valid JSON: {exc}", file=sys.stderr)
        return 2

    lenient = args.lenient and not args.strict
    results, code = lint_all(data, findings_key=args.findings_key, lenient=lenient)
    if results is None:
        print(f"ERROR: unrecognized input shape: {type(data).__name__}",
              file=sys.stderr)
        return 2

    inconsistent = sum(1 for r in results if not r["ok"])
    print(json.dumps({
        "ok": inconsistent == 0,
        "findings_linted": len(results),
        "inconsistent": inconsistent,
        "results": results,
    }, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
