#!/usr/bin/env python3
"""catalog_validate.py — integrity gate for a cloud posture-control catalogue.

WHY THIS EXISTS
---------------
`scripts/skill_linter.py` globs `*.md` only, so a catalogue JSON is unlinted: nothing
otherwise stops a control set from silently losing entries, drifting from its pinned
count, or — the expensive failure — accumulating text copied out of a restricted
source benchmark.

Every catalogue ships this validator plus a test in the same PR. One validator serves
every provider (OCI, Azure, Kubernetes, SaaS); a catalogue declares its own framework
and pinned counts in `meta`, and the checks are provider-agnostic.

Usage:
    python3 tools/posture/catalog_validate.py <catalog.json> [--strict-licence]
    python3 tools/posture/catalog_validate.py --all
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

EXIT_OK = 0
EXIT_INVALID = 1
EXIT_USAGE = 2

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CATALOG_GLOB = os.path.join(
    REPO, "skills", "cloud-containers", "reference", "posture", "catalog", "*.json")

CONTROL_REQUIRED = ("control_id", "section", "level", "assessment", "service",
                    "title", "objective", "procedure", "api", "evidence",
                    "verdict_rule", "remediation")
META_REQUIRED = ("catalog_id", "framework", "framework_version", "provider",
                 "control_count", "source_url", "licence_note", "sections")
ASSESSMENTS = {"Automated", "Manual"}

# A catalogue derived from a restricted benchmark must carry OUR text. `cis_title_hint`
# is an authoring aid that must never ship, and any field whose value is a verbatim
# source title is a licence problem, not a style problem.
BANNED_FIELDS = ("cis_title_hint", "cis_text", "source_text", "benchmark_text",
                 "description_verbatim")

# Phrasing that indicates transcribed benchmark prose rather than our own procedure.
_TRANSCRIPTION_MARKERS = (
    "from console:", "from cli:", "profile applicability", "rationale statement",
    "impact statement", "audit procedure:", "remediation procedure:",
    "default value:", "cis controls", "click in the search bar",
)


def _err(errors, cid, field, msg):
    errors.append(f"[{cid}] {field}: {msg}")


def validate(catalog: dict, *, strict_licence: bool = True) -> list[str]:
    errors: list[str] = []
    meta = catalog.get("meta") or {}
    controls = catalog.get("controls")

    for k in META_REQUIRED:
        if not meta.get(k):
            errors.append(f"meta.{k} missing or empty")
    if not isinstance(controls, list) or not controls:
        return errors + ["controls[] missing or empty"]

    # Pinned count: adding or losing a control must be an explicit, acknowledged edit,
    # exactly as tools/coverage_catalog.py pins CLASS_COUNT.
    if meta.get("control_count") != len(controls):
        errors.append(
            f"meta.control_count {meta.get('control_count')!r} != {len(controls)} controls present")

    declared_sections = meta.get("sections") or {}
    seen: set = set()
    level_counts: dict = {}
    assess_counts: dict = {}

    for c in controls:
        cid = c.get("control_id", "<missing>")
        if not isinstance(c, dict):
            errors.append(f"control {cid} is not an object")
            continue
        for f in CONTROL_REQUIRED:
            if f not in c or c[f] in (None, "", []):
                _err(errors, cid, f, "missing or empty")
        if cid in seen:
            errors.append(f"duplicate control_id {cid!r}")
        seen.add(cid)

        for bad in BANNED_FIELDS:
            if bad in c:
                _err(errors, cid, bad,
                     "authoring-aid / source-text field must never ship in a catalogue")

        sec = str(c.get("section", ""))
        if sec and declared_sections and sec not in declared_sections:
            _err(errors, cid, "section", f"{sec!r} not declared in meta.sections")
        if cid != "<missing>" and sec and not str(cid).startswith(sec):
            _err(errors, cid, "section", f"{sec!r} inconsistent with control_id {cid!r}")

        lvl = c.get("level")
        if lvl not in (1, 2):
            _err(errors, cid, "level", f"{lvl!r} must be 1 or 2")
        else:
            level_counts[lvl] = level_counts.get(lvl, 0) + 1

        a = c.get("assessment")
        if a not in ASSESSMENTS:
            _err(errors, cid, "assessment", f"{a!r} not in {sorted(ASSESSMENTS)}")
        else:
            assess_counts[a] = assess_counts.get(a, 0) + 1

        api = c.get("api")
        if isinstance(api, list) and not any(str(x).strip() for x in api):
            _err(errors, cid, "api", "no concrete API/CLI invocation given")

        # A Manual control is Manual because judgement is required; saying so is the
        # whole value of the field. Silence here reads as 'fully automated'.
        if a == "Manual" and not str(c.get("caveat", "")).strip():
            _err(errors, cid, "caveat",
                 "a Manual control must state what a human has to judge and why")

        if strict_licence:
            errors += _licence_check(c, cid)

    for k, v in (meta.get("level_split") or {}).items():
        if level_counts.get(int(k)) != v:
            errors.append(f"meta.level_split[{k}]={v} != recomputed {level_counts.get(int(k))}")
    for k, v in (meta.get("assessment_split") or {}).items():
        if assess_counts.get(k) != v:
            errors.append(f"meta.assessment_split[{k}]={v} != recomputed {assess_counts.get(k)}")

    if not re.search(r"http", str(meta.get("source_url", ""))):
        errors.append("meta.source_url must cite where the framework is obtained")
    if len(str(meta.get("licence_note", ""))) < 60:
        errors.append("meta.licence_note must state the reproduction constraint substantively")

    return errors


def _licence_check(c: dict, cid: str) -> list[str]:
    """Structural signals that source prose was transcribed rather than authored."""
    errors: list[str] = []
    for field in ("title", "objective", "procedure", "remediation", "evidence"):
        val = str(c.get(field, ""))
        low = val.lower()
        for marker in _TRANSCRIPTION_MARKERS:
            if marker in low:
                _err(errors, cid, field,
                     f"contains benchmark-document phrasing {marker!r} — write the procedure "
                     "in our own words; the source text may not be reproduced")
                break
    title = str(c.get("title", ""))
    if title.lower().startswith("ensure ") and len(title.split()) > 3:
        # Not fatal on its own, but 'Ensure ...' is the source's house style; ours should
        # read as an imperative control objective rather than an echo of it.
        _err(errors, cid, "title",
             "starts with 'Ensure ' — the source benchmark's phrasing convention; "
             "restate the objective in our own voice")
    return errors


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Validate cloud posture-control catalogue(s).")
    ap.add_argument("catalog", nargs="?", help="path to a catalogue JSON")
    ap.add_argument("--all", action="store_true", help="validate every shipped catalogue")
    ap.add_argument("--no-licence-check", action="store_true",
                    help="skip the transcription heuristics (never use in CI)")
    a = ap.parse_args(argv)

    paths = sorted(glob.glob(CATALOG_GLOB)) if a.all else ([a.catalog] if a.catalog else [])
    if not paths:
        print("catalog_validate: nothing to validate (pass a path or --all)", file=sys.stderr)
        return EXIT_USAGE

    rc = EXIT_OK
    for p in paths:
        try:
            with open(p, encoding="utf-8") as fh:
                cat = json.load(fh)
        except (OSError, ValueError) as e:
            print(f"catalog_validate: cannot read {p}: {e}", file=sys.stderr)
            rc = EXIT_INVALID
            continue
        errs = validate(cat, strict_licence=not a.no_licence_check)
        name = os.path.basename(p)
        if errs:
            rc = EXIT_INVALID
            print(f"catalog_validate: {name} — {len(errs)} error(s)")
            for e in errs:
                print(f"  ERROR {e}")
        else:
            n = len(cat.get("controls") or [])
            m = cat.get("meta", {})
            print(f"catalog_validate: {name} clean — {n} controls, "
                  f"{m.get('framework')} {m.get('framework_version')} ({m.get('provider')})")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
