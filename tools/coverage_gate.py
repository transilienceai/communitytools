#!/usr/bin/env python3
"""Deterministic attack-class coverage gate — fails closed unless EVERY applicable
(surface-unit x attack-class) cell has cross-checked evidence.

Generalizes tools/pci-sss/coverage_gate.py from flat requirement-ids to
(asset_tag, scope_key, class_id) cells. The applicable set comes from the
code-produced applicability/cells.json (enumerate_cells.py) — separate from, and
un-fabricatable by, the agent's coverage.json scoreboard. Each cell must resolve
to a real on-disk evidence record, scoped to that cell's OWN asset directory
(no cross-asset contamination).

PASS predicates per applicable cell:
  covered            -> a coverage.json units_tested entry {status:covered, key==scope_key,
                        e_id in experiments.md} AND a validated finding with
                        verdict in {VALID,REPAIRED}, class_id==cell.class_id,
                        scope_key in unit_refs, asset_tag==cell.asset_tag.
  covered_negative   -> {status:covered_negative, e_id in experiments.md}, not contradicted
                        by a VALID finding, and per negative_kind:
                          reachability  -> >= min_vantages distinct VERIFIED regions in
                                           source-ips.jsonl (verified:false excluded)
                          active_probe  -> a non-agent corroborator (tools/*.md 'Experiment:'
                                           header, or an existing 'corroborator' file)
                          none          -> the experiment reference alone suffices
FAIL (cell counts as missing) otherwise. status:NA on a code-applicable cell is a
hard fabrication FAIL. Also: extra_cell (claim for a non-applicable cell),
false_NA (class marked N/A where it has >=1 applicable cell), surface_undercount
(web recon host not covered by the surface inventory).

Writes <root>/reports/coverage-matrix.json. Exit 0 iff coverage_ratio==1.0 and no
extra/false_NA/surface_undercount; 1 otherwise; 2 fail-closed (unreadable catalog/cells).
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from collections import defaultdict

from coverage_catalog import CatalogError, catalog_by_id, load_catalog
from enumerate_cells import build as enumerate_build

_E_RE = re.compile(r"^\|\s*(E-\d+|SWEEP-[\w.\-]+)\s*\|")
_TOOL_EXP_RE = re.compile(r"Experiment:\s*(E-\d+|SWEEP-[\w.\-]+)")

# E2 equivalence-class validation: a unit-scope cell may be credited when a SIBLING
# cell in the same equiv_group carries a DIRECT validated finding of that class.
# Bounds "one representative collapses an unbounded group": at most this many
# siblings per (asset_tag, class_id, equiv_group) may ride a single representative.
EQUIV_GROUP_MAX = 8


# --- evidence loaders (all scoped to a single asset directory) ---------------
def load_coverage_rows(asset_dir: str) -> dict:
    """class_id -> row {applicability, status, units_tested:[...]}."""
    path = os.path.join(asset_dir, "coverage.json")
    if not os.path.isfile(path):
        return {}
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    rows = data if isinstance(data, list) else data.get("rows") or data.get("classes") or []
    return {r.get("class_id"): r for r in rows if isinstance(r, dict) and r.get("class_id")}


def load_e_set(asset_dir: str) -> set:
    path = os.path.join(asset_dir, "experiments.md")
    if not os.path.isfile(path):
        return set()
    ids = set()
    for line in open(path, encoding="utf-8"):
        m = _E_RE.match(line)
        if m:
            ids.add(m.group(1))
    return ids


def load_validated(asset_dir: str) -> list:
    out = []
    for p in sorted(glob.glob(os.path.join(asset_dir, "artifacts", "validated", "*.json"))):
        try:
            out.append(json.load(open(p, encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            continue
    return out


def load_tool_eids(asset_dir: str) -> set:
    ids = set()
    for p in glob.glob(os.path.join(asset_dir, "tools", "*.md")):
        try:
            txt = open(p, encoding="utf-8").read()
        except OSError:
            continue
        for m in _TOOL_EXP_RE.finditer(txt):
            ids.add(m.group(1))
    return ids


def load_verified_regions(dirs) -> set:
    regions = set()
    for d in dirs:
        path = os.path.join(d, "logs", "activity", "source-ips.jsonl")
        if not os.path.isfile(path):
            continue
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("verified") and row.get("region"):
                regions.add(row["region"])
    return regions


# --- per-cell verdict --------------------------------------------------------
def _pick_entry(entries, scope_key):
    matches = [e for e in entries if e.get("key") == scope_key]
    if not matches:
        return None
    order = {"covered": 0, "covered_negative": 1}
    return sorted(matches, key=lambda e: order.get(e.get("status"), 9))[0]


def _finding_matches(validated, class_id, scope_key, asset_tag):
    """(has_valid_match, class_mismatch_seen)."""
    mismatch = False
    for f in validated:
        if f.get("verdict") not in ("VALID", "REPAIRED"):
            continue
        refs = f.get("unit_refs") or []
        if scope_key in refs and (f.get("asset_tag") in (None, asset_tag)):
            if f.get("class_id") == class_id:
                return True, mismatch
            mismatch = True
    return False, mismatch


def _is_corroborated(entry, asset_dir, tool_eids):
    if entry.get("e_id") in tool_eids:
        return True
    corr = entry.get("corroborator")
    return bool(corr and os.path.isfile(os.path.join(asset_dir, corr)))


def _equiv_representative(cell, ctx):
    """E2 fallback (bounded). Return a SIBLING scope_key that carries a DIRECT
    validated finding of this class in the same equiv_group, or None. Only ever
    fires for unit-scope cells with a truthy equiv_group; never for host/asset
    cells or None-group cells. A cell can never be its own representative, and at
    most EQUIV_GROUP_MAX siblings per (asset, class, group) may ride one rep."""
    if cell["scope"] != "unit":
        return None
    group = cell.get("equiv_group")
    if not group:
        return None
    cid = cell["class_id"]
    reps = ctx["equiv_reps"].get((cid, group)) or set()
    others = sorted(reps - {cell["scope_key"]})
    if not others:
        return None
    counts = ctx["equiv_counts"]
    ckey = (cell["asset_tag"], cid, group)
    if counts[ckey] >= EQUIV_GROUP_MAX:
        return None
    counts[ckey] += 1
    return others[0]


def eval_cell(cell, ctx):
    """Return (passed: bool, reason: str, mode: covered|covered_negative|None)."""
    cid = cell["class_id"]
    key = cell["scope_key"]
    row = ctx["rows"].get(cid) or {}
    entry = _pick_entry(row.get("units_tested") or [], key)
    if not entry:
        return False, "no_ledger_entry", None
    status = entry.get("status")
    e_id = entry.get("e_id")

    if status == "NA":
        return False, "na_fabrication", None
    if status not in ("covered", "covered_negative"):
        return False, f"bad_status:{status}", None
    if e_id not in ctx["e_set"]:
        return False, "dangling_e_id", None

    if status == "covered":
        ok, mismatch = _finding_matches(ctx["validated"], cid, key, cell["asset_tag"])
        if ok:
            return True, "covered", "covered"
        if mismatch:
            return False, "class_mismatch", None
        # E2 equivalence-class fallback: credit this cell iff a DIFFERENT sibling in
        # the same equiv_group has a direct validated finding of this class (bounded).
        rep = _equiv_representative(cell, ctx)
        if rep is not None:
            ctx["chosen_rep"] = rep
            return True, "covered_equiv", "covered_equiv"
        return False, "no_matching_finding", None

    # covered_negative
    ok, _ = _finding_matches(ctx["validated"], cid, key, cell["asset_tag"])
    if ok:
        return False, "negative_contradicted", None
    nk = cell["negative_kind"]
    if nk == "reachability":
        vantages = {v for v in (entry.get("vantages") or []) if v in ctx["verified_regions"]}
        if len(vantages) >= cell["min_vantages"]:
            return True, "covered_negative", "covered_negative"
        return False, "insufficient_vantages", None
    if nk == "active_probe":
        if _is_corroborated(entry, ctx["asset_dir"], ctx["tool_eids"]):
            return True, "covered_negative", "covered_negative"
        return False, "uncorroborated_negative", None
    return True, "covered_negative", "covered_negative"  # none


# --- gate over the whole cell set --------------------------------------------
def run_gate(root: str, single: bool) -> dict:
    cells_path = os.path.join(root, "applicability", "cells.json")
    if os.path.isfile(cells_path):
        cellsdoc = json.load(open(cells_path, encoding="utf-8"))
    else:
        cellsdoc = enumerate_build(root, single)
    cells = cellsdoc.get("cells", [])
    assets_meta = cellsdoc.get("assets", {})
    catalog = catalog_by_id(load_catalog())

    cells_by_asset = defaultdict(list)
    for c in cells:
        cells_by_asset[c["asset_tag"]].append(c)

    results = []
    per_class = defaultdict(lambda: {"applicable": 0, "passed": 0, "modes": []})
    per_asset = defaultdict(lambda: {"applicable": 0, "passed": 0})
    extra_cells, false_na, surface_undercount = [], [], []

    for asset_tag, acells in cells_by_asset.items():
        meta = assets_meta.get(asset_tag, {})
        asset_dir = os.path.normpath(os.path.join(root, meta.get("dir", ".")))
        ctx = {
            "rows": load_coverage_rows(asset_dir),
            "e_set": load_e_set(asset_dir),
            "validated": load_validated(asset_dir),
            "tool_eids": load_tool_eids(asset_dir),
            "verified_regions": load_verified_regions({asset_dir, root}),
            "asset_dir": asset_dir,
        }
        applicable_keys = defaultdict(set)  # class_id -> set(scope_key) that ARE applicable
        for c in acells:
            applicable_keys[c["class_id"]].add(c["scope_key"])

        # E2 first pass: which (class, equiv_group) have a DIRECT validated finding, and
        # on which unit(s). Computed over the whole asset BEFORE scoring so a rep anywhere
        # in the group is visible. equiv_counts bounds fallback credit per group.
        equiv_reps = defaultdict(set)  # (class_id, equiv_group) -> {scope_key with a direct finding}
        for c in acells:
            if c["scope"] == "unit" and c.get("equiv_group"):
                ok, _ = _finding_matches(ctx["validated"], c["class_id"], c["scope_key"], c["asset_tag"])
                if ok:
                    equiv_reps[(c["class_id"], c["equiv_group"])].add(c["scope_key"])
        ctx["equiv_reps"] = equiv_reps
        ctx["equiv_counts"] = defaultdict(int)  # (asset_tag, class_id, equiv_group) -> credited siblings

        for c in acells:
            passed, reason, mode = eval_cell(c, ctx)
            rec = {"asset_tag": asset_tag, "scope": c["scope"], "scope_key": c["scope_key"],
                   "class_id": c["class_id"], "passed": passed, "reason": reason,
                   "equiv_group": c.get("equiv_group")}
            if mode == "covered_equiv":
                rec["representative"] = ctx.get("chosen_rep")
            results.append(rec)
            per_class[c["class_id"]]["applicable"] += 1
            per_asset[asset_tag]["applicable"] += 1
            if passed:
                per_class[c["class_id"]]["passed"] += 1
                per_asset[asset_tag]["passed"] += 1
                per_class[c["class_id"]]["modes"].append(mode)

        # extra_cell + false_NA: inspect the agent scoreboard against the code work-list
        for cid, row in ctx["rows"].items():
            appl = applicable_keys.get(cid, set())
            for e in row.get("units_tested") or []:
                if e.get("status") in ("covered", "covered_negative") and e.get("key") not in appl:
                    extra_cells.append({"asset_tag": asset_tag, "class_id": cid, "scope_key": e.get("key")})
            if appl and (row.get("status") == "NA" or row.get("applicability") == "not_applicable"):
                false_na.append({"asset_tag": asset_tag, "class_id": cid,
                                 "reason": "class marked N/A but code enumerated applicable cells"})

        # surface_undercount (web only): recon-discovered hosts not present in the surface inventory
        if meta.get("kind") == "web":
            missing = sorted(set(meta.get("recon_hosts") or []) - set(meta.get("surface_hosts") or []))
            if missing:
                surface_undercount.append({"asset_tag": asset_tag, "missing_hosts": missing})

    applicable = len(results)
    passed = sum(1 for r in results if r["passed"])
    ratio = round(passed / applicable, 4) if applicable else 1.0
    missing_cells = [r for r in results if not r["passed"]]
    covered_equiv = [r for r in results if "representative" in r]  # siblings collapsed onto a rep

    per_class_out = {}
    for cid, pc in per_class.items():
        cls = catalog.get(cid, {})
        if pc["applicable"] == pc["passed"] and pc["applicable"] > 0:
            status = "covered_negative" if "covered_negative" in pc["modes"] and "covered" not in pc["modes"] else "covered"
        else:
            status = "pending"
        per_class_out[cid] = {"taxonomy": cls.get("taxonomy"), "title": cls.get("title"),
                              "applicable": pc["applicable"], "passed": pc["passed"], "status": status}

    complete = (not missing_cells) and (not extra_cells) and (not false_na) and (not surface_undercount)
    return {
        "generated_by": "coverage_gate.py",
        "applicable": applicable,
        "passed": passed,
        "coverage_ratio": ratio,
        "complete": complete,
        "missing_cells": sorted(missing_cells, key=lambda r: (r["asset_tag"], r["class_id"], r["scope_key"])),
        "covered_equiv": sorted(covered_equiv, key=lambda r: (r["asset_tag"], r["class_id"], r["scope_key"])),
        "extra_cells": sorted(extra_cells, key=lambda r: (r["asset_tag"], r["class_id"], str(r["scope_key"]))),
        "false_NA": sorted(false_na, key=lambda r: (r["asset_tag"], r["class_id"])),
        "surface_undercount": sorted(surface_undercount, key=lambda r: r["asset_tag"]),
        "per_class": dict(sorted(per_class_out.items())),
        "per_asset": {k: dict(v) for k, v in sorted(per_asset.items())},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--asset-dir")
    g.add_argument("--engagement-dir")
    ap.add_argument("-o", "--out")
    ap.add_argument("--emit-open", action="store_true", help="print the open-cell backlog and exit")
    args = ap.parse_args()

    root = os.path.abspath(args.asset_dir or args.engagement_dir)
    single = bool(args.asset_dir)
    try:
        result = run_gate(root, single)
    except CatalogError as e:
        print(f"coverage_gate: {e}", file=sys.stderr)
        return 2

    if args.emit_open:
        _emit_open(result)
        return 0 if result["complete"] else 1

    out = args.out or os.path.join(root, "reports", "coverage-matrix.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2, sort_keys=True)

    print(f"coverage_gate: ratio={result['coverage_ratio']} applicable={result['applicable']} "
          f"passed={result['passed']} missing={len(result['missing_cells'])} extra={len(result['extra_cells'])} "
          f"false_NA={len(result['false_NA'])} undercount={len(result['surface_undercount'])} -> {out}")
    for r in result["missing_cells"][:25]:
        print(f"  MISSING {r['class_id']} @ {r['scope_key']} ({r['asset_tag']}) — {r['reason']}")
    if len(result["missing_cells"]) > 25:
        print(f"  ... and {len(result['missing_cells']) - 25} more missing")
    return 0 if result["complete"] else 1


def _emit_open(result: dict) -> None:
    """Compact open-cell backlog for injection into a THINK prompt."""
    openc = result["missing_cells"]
    if not openc:
        print("OPEN_CELLS: none — coverage complete")
        return
    if len(openc) <= 60:
        for r in openc:
            eq = f" [equiv:{r['equiv_group']}]" if r.get("equiv_group") else ""
            print(f"OPEN {r['class_id']} @ {r['scope_key']} ({r['asset_tag']}){eq} — {r['reason']}")
    else:
        by_class = defaultdict(int)
        for r in openc:
            by_class[r["class_id"]] += 1
        print(f"OPEN_CELLS: {len(openc)} open (summarized per class):")
        for cid, n in sorted(by_class.items(), key=lambda kv: -kv[1]):
            print(f"  {cid}: {n} open")


if __name__ == "__main__":
    sys.exit(main())
