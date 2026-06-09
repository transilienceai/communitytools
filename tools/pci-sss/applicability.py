#!/usr/bin/env python3
"""Deterministic applicability filter for the PCI SSS v2.0 catalog.

Given an AppContext (the 7 booleans, schema.md §2), filter the pinned
catalog to the set of Test Requirements that apply to THIS application.
No LLM judgement — pure evaluation of each row's applicability AST.

Usage:
  python3 tools/pci-sss/applicability.py --context CTX [--catalog PATH] [--out-dir DIR] [--running-instance]

  --context accepts inline JSON ({"account_data":true,...}) or a path to a JSON file.
  Missing keys default to False (conservative: an unproven condition does not
  pull in its conditional requirements, but core always applies).

Outputs (when --out-dir given, treated as the engagement OUTPUT_DIR):
  <out-dir>/applicability/{applicable.jsonl, not-applicable.jsonl, work-list.json}.
Always prints a one-line summary and exits 0 (a usage/parse error exits 2).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _common import APP_CONTEXT_KEYS, eval_applicability, load_catalog


def parse_context(raw: str) -> dict:
    p = Path(raw)
    text = p.read_text(encoding="utf-8") if p.is_file() else raw
    ctx = json.loads(text)
    if not isinstance(ctx, dict):
        raise ValueError("context must be a JSON object of the 7 AppContext booleans")
    unknown = set(ctx) - APP_CONTEXT_KEYS
    if unknown:
        raise ValueError(f"unknown AppContext keys: {sorted(unknown)}; allowed: {sorted(APP_CONTEXT_KEYS)}")
    return {k: bool(ctx.get(k, False)) for k in APP_CONTEXT_KEYS}


def dynamic_blocked(row: dict, running_instance: bool) -> bool:
    """A row needs live execution we cannot honestly fake without an instance."""
    at = row.get("analysis_type")
    needs_dyn = at == "dynamic" or (
        at == "static-and-or-dynamic" and row.get("test_method") in ("Perform", "Test")
    )
    return needs_dyn and not running_instance


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--context", required=True, help="inline JSON or path to a JSON file of the 7 booleans")
    ap.add_argument("--catalog", default=None)
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--running-instance", action="store_true",
                    help="a running instance + authorization is available for dynamic analysis")
    args = ap.parse_args()

    try:
        ctx = parse_context(args.context)
    except (ValueError, json.JSONDecodeError) as e:
        print(f"applicability: bad --context: {e}", file=sys.stderr)
        return 2

    catalog = load_catalog(args.catalog) if args.catalog else load_catalog()
    rows = catalog["test_requirements"]

    applicable, not_applicable = [], []
    for r in rows:
        if eval_applicability(r.get("applicability"), ctx):
            r2 = dict(r)
            r2["dynamic_blocked"] = dynamic_blocked(r, args.running_instance)
            applicable.append(r2)
        else:
            not_applicable.append({
                "id": r.get("id"), "module": r.get("module"), "objective": r.get("objective"),
                "requirement_id": r.get("requirement_id"),
                "reason": "applicability predicate evaluated false under AppContext",
                "applicability": r.get("applicability"),
            })

    if args.out_dir:
        out = Path(args.out_dir) / "applicability"
        out.mkdir(parents=True, exist_ok=True)
        with (out / "applicable.jsonl").open("w", encoding="utf-8") as fh:
            for r in applicable:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        with (out / "not-applicable.jsonl").open("w", encoding="utf-8") as fh:
            for r in not_applicable:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        work = {
            "context": ctx,
            "running_instance": args.running_instance,
            "counts": {"applicable": len(applicable), "not_applicable": len(not_applicable),
                       "dynamic_blocked": sum(1 for r in applicable if r["dynamic_blocked"])},
            "applicable_ids": [r["id"] for r in applicable],
            "applicable": applicable,
        }
        (out / "work-list.json").write_text(json.dumps(work, ensure_ascii=False, indent=2), encoding="utf-8")

    dyn = sum(1 for r in applicable if r["dynamic_blocked"])
    print(f"applicability: {len(applicable)} applicable, {len(not_applicable)} not-applicable, "
          f"{dyn} dynamic-blocked (no running instance)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
