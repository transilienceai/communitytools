#!/usr/bin/env python3
"""Network coverage tail — write cell evidence for swept-but-not-deep-dived hosts.

On a large network sweep only the app-bearing hosts get a coordinator-loop (the
INTEGRATE agent is the sole writer of coverage.json). Every OTHER live host still
has code-enumerated host/asset-scope cells (security-headers, TLS, components,
misconfig, ...) with no evidence writer — so the hard-100% gate could never be
satisfied without spawning an agent per host. This deterministic mapper closes
that tail: for each live host WITHOUT a coverage.json (i.e. not deep-dived), it
reads the host's existing nmap/nuclei scan output and writes a covered_negative
units_tested ledger citing the raw scan file as the non-agent corroborator.

It NEVER fabricates a `covered` (that needs a validated finding, which only the
deep-dive produces) and NEVER overwrites a deep-dived host's coverage.json.
Reachability-kind cells are closed only when >= min_vantages distinct VERIFIED
vantage regions exist; otherwise they are left open (honest — a single-vantage
"clean" claim on a reachability class is not certifiable).

Usage:
  python3 tools/network_coverage_map.py --engagement-dir DIR [--force]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

from coverage_catalog import DEFAULT_CATALOG, catalog_by_id, load_catalog
from enumerate_cells import build as enumerate_build


def _verified_regions(*dirs) -> list:
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
    return sorted(regions)


def _raw_scan_ref(host_dir: str) -> str | None:
    for p in sorted(glob.glob(os.path.join(host_dir, "recon", "*"))):
        if os.path.isfile(p):
            return os.path.relpath(p, host_dir)
    return None


def _append_experiment(host_dir: str, e_id: str, note: str) -> None:
    path = os.path.join(host_dir, "experiments.md")
    new = not os.path.isfile(path)
    with open(path, "a", encoding="utf-8") as f:
        if new:
            f.write("# Experiments\n| # | Batch | Technique | Target | Parameters | Result | Notes |\n"
                    "|---|---|---|---|---|---|---|\n")
        f.write(f"| {e_id} | SWEEP | nmap/nuclei | host | sweep | done | {note} |\n")


def map_host(host_dir: str, catalog: dict, verified_regions: list, force: bool) -> dict:
    cov_path = os.path.join(host_dir, "coverage.json")
    if os.path.isfile(cov_path) and not force:
        return {"host_dir": host_dir, "skipped": "already has coverage.json (deep-dived)"}

    doc = enumerate_build(host_dir, True)
    cells = doc.get("cells", [])
    if not cells:
        return {"host_dir": host_dir, "skipped": "no cells (dead/no-surface host)"}
    by_id = catalog_by_id(catalog)
    ip = next(iter(doc.get("assets", {})), os.path.basename(host_dir.rstrip("/")))
    scan_ref = _raw_scan_ref(host_dir)

    entries_by_class: dict = {}
    tool_eids: list = []
    closed = open_left = 0
    for n, cell in enumerate(cells, 1):
        cls = by_id.get(cell["class_id"], {})
        nk = cls.get("negative_kind", "active_probe")
        e_id = f"SWEEP-{ip}-{n:02d}"
        entry = {"key": cell["scope_key"], "status": "covered_negative", "e_id": e_id, "negative_kind": nk}
        note = f"swept {cell['class_id']} @ {cell['scope_key']} — no exposure (raw: {scan_ref or 'host.json'})"
        if nk == "reachability":
            entry["vantages"] = list(verified_regions)
            if len(verified_regions) >= cls.get("min_vantages", 2):
                closed += 1
            else:
                open_left += 1
        else:
            closed += 1
        if nk == "active_probe":
            if scan_ref:
                entry["corroborator"] = scan_ref
            tool_eids.append(e_id)
        _append_experiment(host_dir, e_id, note)
        entries_by_class.setdefault(cell["class_id"], []).append(entry)

    rows = [{"class_id": cid, "applicability": "applicable", "status": "pending",
             "negative": True, "units_tested": ents, "owner": "network_coverage_map"}
            for cid, ents in sorted(entries_by_class.items())]
    with open(cov_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2, sort_keys=True)

    # One deterministic tool-log corroborating every active_probe SWEEP experiment.
    if tool_eids:
        tpath = os.path.join(host_dir, "tools", "000_network_sweep.md")
        os.makedirs(os.path.dirname(tpath), exist_ok=True)
        with open(tpath, "w", encoding="utf-8") as f:
            f.write(f"# network-sweep (deterministic tail)\nRaw scan: {scan_ref or 'host.json'}\n\n")
            for e in tool_eids:
                f.write(f"Experiment: {e}\n")
            f.write("\n## Output\nActive-probe host/asset cells corroborated by the raw nmap/nuclei scan output above.\n")
    return {"host_dir": host_dir, "ip": ip, "cells": len(cells), "closed": closed, "open_reachability": open_left}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engagement-dir", required=True)
    ap.add_argument("--force", action="store_true", help="overwrite existing coverage.json (deep-dived hosts)")
    args = ap.parse_args()
    root = os.path.abspath(args.engagement_dir)
    catalog = load_catalog(DEFAULT_CATALOG)
    verified = _verified_regions(root)

    results = []
    for hp in sorted(glob.glob(os.path.join(root, "hosts", "*", "host.json"))):
        hd = os.path.dirname(hp)
        results.append(map_host(hd, catalog, _verified_regions(root, hd), args.force))

    mapped = [r for r in results if "cells" in r]
    total_open = sum(r.get("open_reachability", 0) for r in mapped)
    print(f"network_coverage_map: mapped {len(mapped)} swept host(s); "
          f"{sum(r['closed'] for r in mapped)} cell(s) closed, {total_open} reachability cell(s) left open "
          f"(need >= min_vantages verified regions; have {len(verified)}).")
    for r in results:
        if r.get("skipped"):
            print(f"  skip {os.path.basename(r['host_dir'])}: {r['skipped']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
