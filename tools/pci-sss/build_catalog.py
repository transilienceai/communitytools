#!/usr/bin/env python3
"""Merge per-objective catalog parts into the canonical catalog file.

Each parts/*.json is a JSON array of CatalogTestRequirement objects
(schema.md §1) for one Security Objective or Module. This tool concatenates
them in id order, recomputes the meta block (counts, objectives, sha256),
and writes skills/pci-secure-software/reference/catalog/pci-sss-v2.0.json.

Usage:
  python3 tools/pci-sss/build_catalog.py [--parts-dir DIR] [--out PATH] [--page-offset N]

After building, always run validate_catalog.py.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from _common import DEFAULT_CATALOG, MODULES, NEGATIVE_RE, SOURCE_PDF, sha256_file

PARTS_DIR = DEFAULT_CATALOG.parent / "parts"
OVERRIDES = Path(__file__).resolve().parent / "catalog_overrides.json"

DISCLAIMER = (
    "Readiness gap-analysis only; not an official PCI SSS validation. "
    "The PCI Secure Software Standard defines no In-Place/Not-in-Place marking scheme; "
    "marking occurs solely in the ROV/AOV templates assessed by a qualified assessor."
)


def _id_sort_key(rid: str):
    # Sort like 1-1, 1-1.1, 1-3.c, 11-6.a, A1-1.a, C2-1.d — module group then numeric path then letter.
    head, _, tail = rid.partition("-")
    mod_order = {"core": 0, "A": 1, "B": 2, "C": 3, "D": 4}
    if head[:1].isalpha():
        grp = mod_order.get(head[0], 9)
        obj_num = int(head[1:]) if head[1:].isdigit() else 0
    else:
        grp = -1
        obj_num = int(head) if head.isdigit() else 0
    parts = tail.split(".")
    letter = parts[-1] if parts and parts[-1].isalpha() else ""
    nums = [int(x) for x in parts if x.isdigit()]
    return (grp, obj_num, nums, letter)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--parts-dir", default=str(PARTS_DIR))
    ap.add_argument("--out", default=str(DEFAULT_CATALOG))
    ap.add_argument("--pdf", default=str(SOURCE_PDF))
    ap.add_argument("--page-offset", type=int, default=4,
                    help="pdf_page - printed_page in the document body (informational)")
    args = ap.parse_args()

    parts_dir = Path(args.parts_dir)
    if not parts_dir.is_dir():
        print(f"build_catalog: no parts dir {parts_dir}", file=sys.stderr)
        return 2

    rows: list[dict] = []
    seen: set[str] = set()
    for pf in sorted(parts_dir.glob("*.json")):
        try:
            arr = json.loads(pf.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"build_catalog: {pf.name} is not valid JSON: {e}", file=sys.stderr)
            return 2
        if not isinstance(arr, list):
            print(f"build_catalog: {pf} is not a JSON array", file=sys.stderr)
            return 2
        for r in arr:
            rid = r.get("id")
            if rid in seen:
                print(f"build_catalog: duplicate id {rid} (in {pf.name})", file=sys.stderr)
                return 2
            seen.add(rid)
            rows.append(r)

    rows.sort(key=lambda r: _id_sort_key(r.get("id", "")))

    # Deterministic normalizations applied to every build (reproducible + auditable):
    #  (1) test_method overrides for rows whose verbatim text does not begin with the
    #      assessment verb (the naive first-word method was wrong);
    #  (2) polarity re-derived from the text via the canonical NEGATIVE_RE.
    overrides = {}
    if OVERRIDES.is_file():
        overrides = json.loads(OVERRIDES.read_text(encoding="utf-8")).get("test_method", {})
    n_method, n_polarity, n_prefix = 0, 0, 0
    for r in rows:
        rid = r.get("id")
        # Some transcribers prefixed the verbatim text with the id label (e.g. "2-1.3.1.a Is stored ...").
        # Strip a leading "<id>" label so test_requirement_text is the requirement sentence itself.
        txt = r.get("test_requirement_text", "") or ""
        if rid and txt.startswith(rid):
            stripped = txt[len(rid):].lstrip(" .–-\t")
            if stripped:
                r["test_requirement_text"] = stripped
                n_prefix += 1
        if rid in overrides and r.get("test_method") != overrides[rid]:
            r["test_method"] = overrides[rid]
            n_method += 1
        derived = "negative" if NEGATIVE_RE.search(r.get("test_requirement_text", "") or "") else "positive"
        if r.get("polarity") != derived:
            r["polarity"] = derived
            n_polarity += 1
    if n_method or n_polarity or n_prefix:
        print(f"build_catalog: applied {n_method} test_method override(s), re-derived {n_polarity} polarity value(s), "
              f"stripped {n_prefix} id-label prefix(es)")

    objectives_by_module: dict[str, set] = defaultdict(set)
    for r in rows:
        objectives_by_module[r.get("module", "core")].add(str(r.get("objective", "")))

    try:
        sha = sha256_file(args.pdf)
    except FileNotFoundError:
        sha = ""

    catalog = {
        "meta": {
            "framework": "PCI_SSS",
            "version": "2.0",
            "source_document": Path(args.pdf).name,
            "source_sha256": sha,
            "published": "2025",
            "page_count": 94,
            "page_offset": args.page_offset,
            "objectives": {m: len(objectives_by_module.get(m, set())) for m in MODULES},
            "test_requirement_count": len(rows),
            "catalog_schema_version": "1.0.0",
            "disclaimer": DISCLAIMER,
        },
        "test_requirements": rows,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"build_catalog: merged {len(rows)} rows from {parts_dir} -> {out}")
    print(f"  objectives: {catalog['meta']['objectives']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
