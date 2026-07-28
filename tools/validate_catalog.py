#!/usr/bin/env python3
"""Structural validator for the attack-class coverage catalog.

Deterministic. Exits non-zero on any hard violation so coverage-matrix.json
cannot silently drift from coverage-matrix.md or from the pinned invariants
(scope split, flag vocabulary, predicate grammar). Run in CI and after every
catalog edit.

Usage:
  python3 tools/validate_catalog.py [--catalog PATH] [--md PATH]

Checks (all hard):
  1. exactly CLASS_COUNT classes (pinned in coverage_catalog.py), unique class_ids,
     and meta.class_count agrees with the pin
  2. every class has the 9 required fields
  3. scope in {unit,host,asset}; key_by == the scope's canonical key
  4. negative_kind in {active_probe,reachability,none}; min_vantages int >= 0,
     and min_vantages > 0 iff negative_kind == reachability
  5. scope counts match meta.scope_split (the split itself is NOT pinned — see
     CLASS_COUNT's docstring; meta-vs-recomputed catches the silent failure mode)
  6. negative_kind counts match meta.negative_kind_split
  7. meta.agent_flags == AGENT_FLAGS; meta.derived_flags == DERIVED_FLAGS
  8. every applies_when parses against the DSL grammar and references only vocab flags
  9. catalog class_id set == coverage-matrix.md 'Class catalog' table class_id set
 10. no dead flags: every vocabulary flag is referenced by >= 1 applies_when
 11. every technique_ref resolves to a file on disk (any #anchor is stripped)
 12. proof_mode, where present, is in PROOF_MODES and appears only on MAS-* rows
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter

from coverage_catalog import (
    AGENT_FLAGS,
    ALL_FLAGS,
    CLASS_COUNT,
    DERIVED_FLAGS,
    KEY_BY_FOR_SCOPE,
    NEGATIVE_KINDS,
    PROOF_MODES,
    REPO,
    SCOPES,
    CatalogError,
    collect_flags,
    eval_applies,
    load_catalog,
    md_class_ids,
)

REQUIRED_FIELDS = ("class_id", "taxonomy", "title", "scope", "key_by",
                   "applies_when", "negative_kind", "min_vantages", "technique_ref")


def validate(catalog: dict, md_path) -> list[str]:
    errors: list[str] = []
    meta = catalog.get("meta", {})
    rows = catalog.get("classes", [])

    if len(rows) != CLASS_COUNT:
        errors.append(f"expected {CLASS_COUNT} classes, found {len(rows)}")
    if meta.get("class_count") != CLASS_COUNT:
        errors.append(f"meta.class_count {meta.get('class_count')!r} != pinned {CLASS_COUNT}")

    ids: list[str] = []
    scope_counts: Counter = Counter()
    neg_counts: Counter = Counter()
    referenced_all: set = set()

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
            referenced_all |= referenced
            bad = referenced - ALL_FLAGS
            if bad:
                errors.append(f"{tag} applies_when references unknown flags: {sorted(bad)}")
        except CatalogError as e:
            errors.append(f"{tag} applies_when invalid: {e}")
        # 11. technique_ref resolves on disk (an #anchor is a doc fragment, not a path)
        ref = r.get("technique_ref")
        if ref and not (REPO / str(ref).split("#", 1)[0]).is_file():
            errors.append(f"{tag} technique_ref does not resolve: {ref}")
        # 12. proof_mode well-formed, and MAS-* only
        if "proof_mode" in r:
            if r["proof_mode"] not in PROOF_MODES:
                errors.append(f"{tag} proof_mode {r['proof_mode']!r} not in {sorted(PROOF_MODES)}")
            if not str(cid).startswith("MAS-"):
                errors.append(f"{tag} proof_mode is a mobile-only field but {cid!r} is not a MAS-* class")

    # 1. uniqueness
    dupes = [c for c, n in Counter(ids).items() if n > 1]
    if dupes:
        errors.append(f"duplicate class_ids: {sorted(dupes)}")

    # 5. scope split (meta-vs-recomputed only; the split is not separately pinned)
    if meta.get("scope_split") and dict(meta["scope_split"]) != dict(scope_counts):
        errors.append(f"meta.scope_split {meta['scope_split']} != recomputed {dict(scope_counts)}")

    # 6. negative_kind split
    if meta.get("negative_kind_split") and dict(meta["negative_kind_split"]) != dict(neg_counts):
        errors.append(f"meta.negative_kind_split {meta['negative_kind_split']} != recomputed {dict(neg_counts)}")

    # 7. flag vocabulary declared in meta
    if set(meta.get("agent_flags", [])) != AGENT_FLAGS:
        errors.append(f"meta.agent_flags != the {len(AGENT_FLAGS)} canonical agent flags "
                      f"(missing {sorted(AGENT_FLAGS - set(meta.get('agent_flags', [])))}, "
                      f"extra {sorted(set(meta.get('agent_flags', [])) - AGENT_FLAGS)})")
    if set(meta.get("derived_flags", [])) != DERIVED_FLAGS:
        errors.append(f"meta.derived_flags != the {len(DERIVED_FLAGS)} canonical derived flags "
                      f"(missing {sorted(DERIVED_FLAGS - set(meta.get('derived_flags', [])))}, "
                      f"extra {sorted(set(meta.get('derived_flags', [])) - DERIVED_FLAGS)})")

    # 10. no dead flags — a vocabulary flag no predicate references is dead weight
    #     that silently never enumerates anything.
    dead = sorted(ALL_FLAGS - referenced_all)
    if dead:
        errors.append(f"vocabulary flags referenced by no applies_when (dead): {dead}")

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

    # 13. OWASP Top 10 accountability. Claiming OWASP alignment is only honest if
    #     every category is either exercised by a class or excluded on the record.
    #     A category that is simply absent reads as covered, which is the failure
    #     this check exists to prevent.
    errors += _validate_owasp(meta, rows)

    return errors


def _validate_owasp(meta: dict, rows: list) -> list[str]:
    errors: list[str] = []
    block = meta.get("owasp_top10_2021")
    if not block:
        return ["meta.owasp_top10_2021 missing — the OWASP accountability map is required"]

    valid = {f"A{n:02d}:2021" for n in range(1, 11)}
    covered: set = set()
    for r in rows:
        refs = r.get("owasp_refs", [])
        if not isinstance(refs, list):
            errors.append(f"[{r.get('class_id')}] owasp_refs must be a list, got {type(refs).__name__}")
            continue
        bad = [x for x in refs if x not in valid]
        if bad:
            errors.append(f"[{r.get('class_id')}] owasp_refs has unknown categor(ies): {bad}")
        covered |= {x for x in refs if x in valid}

    excluded = block.get("not_assessed") or {}
    if not isinstance(excluded, dict):
        return errors + ["meta.owasp_top10_2021.not_assessed must be an object {category: reason}"]
    bad_excl = [k for k in excluded if k not in valid]
    if bad_excl:
        errors.append(f"not_assessed has unknown categor(ies): {sorted(bad_excl)}")
    thin = [k for k, v in excluded.items() if not isinstance(v, str) or len(v.strip()) < 40]
    if thin:
        errors.append(f"not_assessed needs a substantive reason (>=40 chars) for: {sorted(thin)}")

    both = sorted(covered & set(excluded))
    if both:
        errors.append(f"categor(ies) both covered by a class and listed not_assessed: {both}")

    unaccounted = sorted(valid - covered - set(excluded))
    if unaccounted:
        errors.append(
            "OWASP categor(ies) neither covered by a class nor explicitly excluded: "
            f"{unaccounted} — add owasp_refs to the class that exercises it, or record it "
            "in meta.owasp_top10_2021.not_assessed with a reason")

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
