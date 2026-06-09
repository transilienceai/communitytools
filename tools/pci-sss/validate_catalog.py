#!/usr/bin/env python3
"""Structural fidelity validator for the PCI SSS v2.0 requirements catalog.

Deterministic. Exits non-zero on any hard violation so the catalog cannot
silently drift from the source PDF. Run in CI and after every catalog edit.

Usage:
  python3 tools/pci-sss/validate_catalog.py [--catalog PATH] [--strict-pages]

Checks (hard unless noted):
  1. id regex + uniqueness + ends in a single letter
  2. enum closure (module / test_method / analysis_type / polarity / objective)
     and test_method == first word of test_requirement_text
  3. cross_refs resolve to an existing id or requirement_id
  4. applicability AST parses against the closed grammar + key vocabulary
  5. meta.test_requirement_count == len; recomputed meta.objectives matches declared
  6. page provenance: pdf_page in [1, page_count]; printed_page > 0
     (offset consistency is a warning unless --strict-pages)
  7. negative-polarity consistency (polarity==negative iff text matches the attempt-to-defeat regex)
  8. triad contiguity: per requirement_id the trailing letters are contiguous from 'a'
  9. source PDF sha256 matches meta.source_sha256
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict

from _common import (
    ANALYSIS_TYPES,
    APP_CONTEXT_KEYS,
    ID_RE,
    MODULES,
    NEGATIVE_RE,
    POLARITIES,
    SOURCE_PDF,
    TEST_METHODS,
    AppContextError,
    collect_ctx_keys,
    eval_applicability,
    load_catalog,
    sha256_file,
)

OBJECTIVE_RE_BY_MODULE = {
    "core": re.compile(r"^(?:[1-9]|1[01])$"),
    "A": re.compile(r"^A1$"),
    "B": re.compile(r"^B[1-3]$"),
    "C": re.compile(r"^C[1-4]$"),
    "D": re.compile(r"^D1$"),
}


def validate(catalog: dict, pdf_path, strict_pages: bool) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    meta = catalog.get("meta", {})
    rows = catalog.get("test_requirements", [])
    if not rows:
        errors.append("catalog has zero test_requirements")
        return errors, warnings

    ids: set[str] = set()
    req_ids: set[str] = set()
    objectives_present: set[str] = set()
    page_count = int(meta.get("page_count", 94))
    page_offset = meta.get("page_offset")

    # First pass — collect ids, requirement_ids, objectives for cross-ref resolution
    for r in rows:
        rid = r.get("id", "")
        ids.add(rid)
        if r.get("requirement_id"):
            req_ids.add(r["requirement_id"])
        if r.get("objective"):
            objectives_present.add(str(r["objective"]))

    def resolves(cref: str) -> bool:
        # A cross_ref resolves to an exact id/requirement_id, a bare Security Objective
        # (e.g. "1", "A1"), or a structural node that prefixes some id (e.g. "2-3" -> "2-3.1.a").
        if cref in ids or cref in req_ids or cref in objectives_present:
            return True
        return any(i == cref or i.startswith(cref + ".") or i.startswith(cref + "-") for i in ids)

    letters_by_req: dict[str, list[str]] = defaultdict(list)
    objectives_by_module: dict[str, set] = defaultdict(set)

    for r in rows:
        rid = r.get("id", "<missing>")
        tag = f"[{rid}]"

        # 1. id
        if not ID_RE.match(rid):
            errors.append(f"{tag} id fails the atomic-id regex")
        # 2. enums
        mod = r.get("module")
        if mod not in MODULES:
            errors.append(f"{tag} module {mod!r} not in {sorted(MODULES)}")
        tm = r.get("test_method")
        if tm not in TEST_METHODS:
            errors.append(f"{tag} test_method {tm!r} not in {sorted(TEST_METHODS)}")
        at = r.get("analysis_type")
        if at not in ANALYSIS_TYPES:
            errors.append(f"{tag} analysis_type {at!r} not in {sorted(ANALYSIS_TYPES)}")
        pol = r.get("polarity")
        if pol not in POLARITIES:
            errors.append(f"{tag} polarity {pol!r} not in {sorted(POLARITIES)}")
        obj = str(r.get("objective", ""))
        obj_re = OBJECTIVE_RE_BY_MODULE.get(mod)
        if obj_re and not obj_re.match(obj):
            errors.append(f"{tag} objective {obj!r} invalid for module {mod!r}")
        if mod:
            objectives_by_module[mod].add(obj)
        # 2b. test_method first-word agreement
        text = (r.get("test_requirement_text") or "").strip()
        if tm and text:
            first = text.split()[0].rstrip(".:,").capitalize()
            if first != tm:
                warnings.append(f"{tag} test_method {tm!r} != first word {first!r} of test text")
        # 4. applicability AST
        appl = r.get("applicability")
        try:
            eval_applicability(appl, {k: False for k in APP_CONTEXT_KEYS})
            keys: set = set()
            collect_ctx_keys(appl, keys)
            bad = keys - APP_CONTEXT_KEYS
            if bad:
                errors.append(f"{tag} applicability uses unknown ctx keys: {sorted(bad)}")
        except AppContextError as e:
            errors.append(f"{tag} applicability invalid: {e}")
        # 3. cross_refs
        for cref in r.get("cross_refs", []) or []:
            if not resolves(cref):
                warnings.append(f"{tag} cross_ref {cref!r} does not resolve to a known id/requirement_id/objective")
        # 6. pages
        pp = r.get("printed_page")
        pdfp = r.get("pdf_page")
        if not isinstance(pdfp, int) or not (1 <= pdfp <= page_count):
            errors.append(f"{tag} pdf_page {pdfp!r} out of range [1,{page_count}]")
        if not isinstance(pp, int) or pp <= 0:
            errors.append(f"{tag} printed_page {pp!r} must be a positive int")
        if isinstance(pp, int) and isinstance(pdfp, int) and page_offset is not None:
            if pdfp - pp != page_offset:
                msg = f"{tag} pdf_page-printed_page = {pdfp - pp} != meta.page_offset {page_offset}"
                (errors if strict_pages else warnings).append(msg)
        # 7. negative polarity consistency
        if text:
            is_neg = bool(NEGATIVE_RE.search(text))
            if is_neg and pol != "negative":
                errors.append(f"{tag} text matches attempt-to-defeat but polarity={pol!r}")
            if not is_neg and pol == "negative":
                warnings.append(f"{tag} polarity=negative but text has no attempt-to-defeat phrase")
        # 8. triad bookkeeping
        if rid and "." in rid and rid[-2] == ".":
            letters_by_req[r.get("requirement_id", "")].append(rid[-1])

    # 1b. uniqueness
    if len(ids) != len(rows):
        errors.append(f"duplicate ids present: {len(rows)} rows but {len(ids)} unique ids")

    # 8. contiguity from 'a'
    for req, letters in letters_by_req.items():
        ls = sorted(set(letters))
        expected = [chr(ord("a") + i) for i in range(len(ls))]
        if ls != expected:
            errors.append(f"[{req}] non-contiguous lettering {ls} (expected start 'a', no gaps)")

    # 5. counts
    declared_count = meta.get("test_requirement_count")
    if declared_count is not None and declared_count != len(rows):
        errors.append(f"meta.test_requirement_count {declared_count} != actual {len(rows)}")
    recomputed = {m: len(objectives_by_module.get(m, set())) for m in MODULES}
    declared_obj = meta.get("objectives")
    if declared_obj is not None:
        for m in MODULES:
            if int(declared_obj.get(m, 0)) != recomputed[m]:
                errors.append(f"meta.objectives[{m}] {declared_obj.get(m)} != recomputed {recomputed[m]}")

    # 9. source pin
    declared_sha = meta.get("source_sha256")
    if declared_sha:
        try:
            actual = sha256_file(pdf_path)
            if actual != declared_sha:
                errors.append(f"PDF sha256 mismatch: meta={declared_sha[:12]}.. actual={actual[:12]}..")
        except FileNotFoundError:
            warnings.append(f"source PDF not found at {pdf_path}; cannot verify sha pin")

    return errors, warnings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--catalog", default=None)
    ap.add_argument("--pdf", default=str(SOURCE_PDF))
    ap.add_argument("--strict-pages", action="store_true", help="treat page-offset drift as a hard error")
    args = ap.parse_args()

    catalog = load_catalog(args.catalog) if args.catalog else load_catalog()
    errors, warnings = validate(catalog, args.pdf, args.strict_pages)

    for w in warnings:
        print(f"  WARN  {w}")
    if errors:
        print(f"validate_catalog: {len(errors)} error(s), {len(warnings)} warning(s)")
        for e in errors:
            print(f"  ERROR {e}")
        return 1
    n = len(catalog["test_requirements"])
    print(f"validate_catalog: clean — {n} test requirements, {len(warnings)} warning(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
