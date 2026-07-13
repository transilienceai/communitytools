#!/usr/bin/env python3
"""Structural validator for the attack-class coverage catalog.

Deterministic. Exits non-zero on any hard violation so coverage-matrix.json
cannot silently drift from coverage-matrix.md or from the pinned invariants
(scope split, flag vocabulary, predicate grammar). Run in CI and after every
catalog edit.

Usage:
  python3 tools/validate_catalog.py [--catalog PATH] [--md PATH]

Checks (all hard):
  1. exactly 24 classes, unique class_ids
  2. every class has the 9 required fields
  3. scope in {unit,host,asset}; key_by == the scope's canonical key
  4. negative_kind in {active_probe,reachability,none}; min_vantages int >= 0,
     and min_vantages > 0 iff negative_kind == reachability
  5. scope counts exactly {unit:12, host:6, asset:6} and match meta.scope_split
  6. negative_kind counts match meta.negative_kind_split
  7. meta.agent_flags == the 14 agent flags; meta.derived_flags == the 6 derived
  8. every applies_when parses against the DSL grammar and references only vocab flags
  9. catalog class_id set == coverage-matrix.md 'Class catalog' table class_id set
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter

from coverage_catalog import (
    AGENT_FLAGS,
    ALL_FLAGS,
    DERIVED_FLAGS,
    KEY_BY_FOR_SCOPE,
    NEGATIVE_KINDS,
    SCOPES,
    CatalogError,
    collect_flags,
    eval_applies,
    load_catalog,
    md_class_ids,
)

REQUIRED_FIELDS = ("class_id", "taxonomy", "title", "scope", "key_by",
                   "applies_when", "negative_kind", "min_vantages", "technique_ref")
EXPECTED_SCOPE_SPLIT = {"unit": 12, "host": 6, "asset": 6}


def validate(catalog: dict, md_path) -> list[str]:
    errors: list[str] = []
    meta = catalog.get("meta", {})
    rows = catalog.get("classes", [])

    if len(rows) != 24:
        errors.append(f"expected 24 classes, found {len(rows)}")

    ids: list[str] = []
    scope_counts: Counter = Counter()
    neg_counts: Counter = Counter()

    for r in rows:
        cid = r.get("class_id", "<missing>")
        tag = f"[{cid}]"
        # 2. required fields
        for fld in REQUIRED_FIELDS:
            if fld not in r:
                errors.append(f"{tag} missing required field {fld!r}")
        ids.append(cid)
        # 3. scope / key_by
        scope = r.get("scope")
        if scope not in SCOPES:
            errors.append(f"{tag} scope {scope!r} not in {sorted(SCOPES)}")
        else:
            scope_counts[scope] += 1
            if r.get("key_by") != KEY_BY_FOR_SCOPE[scope]:
                errors.append(f"{tag} key_by {r.get('key_by')!r} != {KEY_BY_FOR_SCOPE[scope]!r} for scope {scope!r}")
        # 4. negative_kind / min_vantages
        nk = r.get("negative_kind")
        if nk not in NEGATIVE_KINDS:
            errors.append(f"{tag} negative_kind {nk!r} not in {sorted(NEGATIVE_KINDS)}")
        else:
            neg_counts[nk] += 1
        mv = r.get("min_vantages")
        if not isinstance(mv, int) or isinstance(mv, bool) or mv < 0:
            errors.append(f"{tag} min_vantages {mv!r} must be a non-negative int")
        elif (mv > 0) != (nk == "reachability"):
            errors.append(f"{tag} min_vantages {mv} inconsistent with negative_kind {nk!r} (>0 iff reachability)")
        # 8. applies_when grammar + vocab
        aw = r.get("applies_when")
        try:
            eval_applies(aw, set())
            referenced: set = set()
            collect_flags(aw, referenced)
            bad = referenced - ALL_FLAGS
            if bad:
                errors.append(f"{tag} applies_when references unknown flags: {sorted(bad)}")
        except CatalogError as e:
            errors.append(f"{tag} applies_when invalid: {e}")

    # 1. uniqueness
    dupes = [c for c, n in Counter(ids).items() if n > 1]
    if dupes:
        errors.append(f"duplicate class_ids: {sorted(dupes)}")

    # 5. scope split
    if dict(scope_counts) != EXPECTED_SCOPE_SPLIT:
        errors.append(f"scope split {dict(scope_counts)} != expected {EXPECTED_SCOPE_SPLIT}")
    if meta.get("scope_split") and dict(meta["scope_split"]) != dict(scope_counts):
        errors.append(f"meta.scope_split {meta['scope_split']} != recomputed {dict(scope_counts)}")

    # 6. negative_kind split
    if meta.get("negative_kind_split") and dict(meta["negative_kind_split"]) != dict(neg_counts):
        errors.append(f"meta.negative_kind_split {meta['negative_kind_split']} != recomputed {dict(neg_counts)}")

    # 7. flag vocabulary declared in meta
    if set(meta.get("agent_flags", [])) != AGENT_FLAGS:
        errors.append(f"meta.agent_flags != the 14 canonical agent flags")
    if set(meta.get("derived_flags", [])) != DERIVED_FLAGS:
        errors.append(f"meta.derived_flags != the 6 canonical derived flags")

    # 9. catalog <-> md parity
    try:
        md_ids = md_class_ids(md_path)
        cat_ids = set(ids)
        only_cat = sorted(cat_ids - md_ids)
        only_md = sorted(md_ids - cat_ids)
        if only_cat:
            errors.append(f"class_ids in JSON catalog but not in md table: {only_cat}")
        if only_md:
            errors.append(f"class_ids in md table but not in JSON catalog: {only_md}")
    except FileNotFoundError:
        errors.append(f"coverage-matrix.md not found at {md_path}")

    return errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--catalog", default=None)
    ap.add_argument("--md", default=None)
    args = ap.parse_args()

    from coverage_catalog import DEFAULT_CATALOG, DEFAULT_MD
    catalog = load_catalog(args.catalog or DEFAULT_CATALOG)
    errors = validate(catalog, args.md or DEFAULT_MD)

    if errors:
        print(f"validate_catalog: {len(errors)} error(s)")
        for e in errors:
            print(f"  ERROR {e}")
        return 1
    print(f"validate_catalog: clean — {len(catalog['classes'])} classes, md parity OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
