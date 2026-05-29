#!/usr/bin/env python3
"""Deterministic risk-based prioritisation.

Reads attack-paths.json + business-tier-map.csv, scores every confirmed path
and standalone validated finding, and writes a stable ranked list. Implements
the formula in skills/risk-prioritiser/reference/scoring-formula.md.

Confirmed vs inferred enforcement (RFP §3.3 compliance):
    Only paths with `path_class == "confirmed"` enter the remediation SLA
    buckets (immediate / short_term / medium_term / monitor). Inferred paths
    are placed in `theoretical` regardless of numeric score.

Usage:
    python3 tools/risk-prioritise.py --output-dir runs/org/
    python3 tools/risk-prioritise.py --output-dir runs/org/ \
        --thresholds '{"immediate":0.6,"short_term":0.3,"medium_term":0.1}' \
        --tier-weights '{"crown_jewel":1.0,"revenue":0.85,"support":0.4,"dev":0.2}'

Exit codes:
    0 — ranked file written
    1 — missing required inputs
    2 — runtime error
"""

import argparse
import csv
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

DEFAULT_TIER_WEIGHTS = {
    "crown_jewel": 1.0,
    "revenue": 0.7,
    "support": 0.4,
    "dev": 0.2,
    "unknown": 0.3,
}
DEFAULT_THRESHOLDS = {"immediate": 0.6, "short_term": 0.3, "medium_term": 0.1}


def utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_tier_map(output_dir: Path) -> tuple[dict[str, str], str]:
    repo_root = Path(__file__).resolve().parent.parent
    instance = output_dir / "business-tier-map.csv"
    default = repo_root / "cloud-agents" / "schemas" / "business-tier-map.csv"
    for source_label, p in (("instance", instance), ("repo-default", default)):
        if p.is_file():
            with p.open() as f:
                reader = csv.DictReader(f)
                tiers = {row["asset_id"]: row["tier"]
                         for row in reader
                         if row.get("asset_id") and row.get("tier")}
            return tiers, source_label
    return {}, "absent"


def bucket_for(score: float, thresholds: dict[str, float]) -> str:
    if score >= thresholds["immediate"]:
        return "immediate"
    if score >= thresholds["short_term"]:
        return "short_term"
    if score >= thresholds["medium_term"]:
        return "medium_term"
    return "monitor"


def remediation_focus(path: dict) -> str | None:
    """Pick the asset whose patch breaks the chain most cheaply.

    Heuristic:
    - If the path has any edge with feasibility < 1.0, focus on the SOURCE of
      the lowest-feasibility edge: it's the weakest link by definition, and
      hardening it costs the attacker their cheapest pivot.
    - If every edge is fully exploitable (confirmed chain, all feasibility=1.0),
      focus on the entry asset (`hops[0]`): patching the external foothold
      breaks every downstream hop and is the cheapest patch surface
      operationally.

    Always returns a single deterministic asset id.
    """
    hops = path.get("hops") or []
    edges = path.get("edges") or []
    if not hops:
        return None
    if not edges:
        return hops[0]
    weak = min(edges, key=lambda e: (e.get("feasibility", 1.0), e["src"]))
    if weak.get("feasibility", 1.0) < 1.0:
        return weak["src"]
    return hops[0]


def score_path(path: dict, node_tier: dict[str, str], tier_weights: dict[str, float]) -> dict:
    dst = path["hops"][-1] if path.get("hops") else None
    src = path["hops"][0] if path.get("hops") else None
    dst_weight = tier_weights.get(node_tier.get(dst, "unknown"), tier_weights["unknown"])
    feasibility = path.get("feasibility", 0.0)
    max_cvss = path.get("max_cvss", 0.0) or 0.0
    technical = max_cvss / 10.0 if max_cvss > 0 else 0.5
    entry_exposure = 1.0  # caller filters non-external entry points
    score = feasibility * technical * dst_weight * entry_exposure
    return {
        "kind": "path",
        "path_class": path.get("path_class", "inferred"),
        "path_id": "->".join(path.get("hops", [])),
        "hops": path.get("hops", []),
        "src": src,
        "dst": dst,
        "feasibility": round(feasibility, 4),
        "max_cvss": round(max_cvss, 2),
        "technical_severity": round(technical, 4),
        "business_impact": round(dst_weight, 4),
        "entry_exposure": entry_exposure,
        "score": round(score, 4),
        "cvss_missing": max_cvss <= 0,
    }


def score_standalone_finding(node: dict, tier_weights: dict[str, float]) -> dict | None:
    if not node.get("findings"):
        return None
    weight = tier_weights.get(node.get("tier", "unknown"), tier_weights["unknown"])
    max_cvss = node.get("max_cvss", 0.0) or 0.0
    technical = max_cvss / 10.0 if max_cvss > 0 else 0.5
    entry_exposure = 1.0 if node.get("external") else 0.5
    score = 1.0 * technical * weight * entry_exposure
    return {
        "kind": "finding",
        "path_class": "confirmed",
        "asset": node["id"],
        "finding_ids": list(node["findings"]),
        "feasibility": 1.0,
        "max_cvss": round(max_cvss, 2),
        "technical_severity": round(technical, 4),
        "business_impact": round(weight, 4),
        "entry_exposure": entry_exposure,
        "score": round(score, 4),
        "cvss_missing": max_cvss <= 0,
    }


def tie_break_key(row: dict) -> tuple:
    """Total ordering — guaranteed deterministic across replays and FS order."""
    hops = row.get("hops") or []
    stable_id = row.get("path_id") or row.get("asset") or ""
    # Findings: include the first finding_id (sorted) so two findings on the
    # same asset with same score tie-break by finding id, not glob order.
    if row.get("kind") == "finding":
        fids = sorted(row.get("finding_ids") or [])
        stable_id = f"{row.get('asset','')}::{fids[0] if fids else ''}"
    return (
        -row["score"],
        -(row.get("max_cvss") or 0),
        len(hops) if hops else 1,
        0 if row.get("kind") == "path" else 1,  # paths before findings on tie
        row.get("path_class", "zzz"),  # confirmed < inferred < plausible alphabetically
        stable_id,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--thresholds", type=str,
                    help='JSON override e.g. \'{"immediate":0.6,"short_term":0.3,"medium_term":0.1}\'')
    ap.add_argument("--tier-weights", type=str,
                    help='JSON override e.g. \'{"crown_jewel":1.0,"revenue":0.85,...}\'')
    args = ap.parse_args()

    output_dir = Path(args.output_dir).resolve()
    graph_path = output_dir / "artifacts" / "attack-paths.json"
    if not graph_path.is_file():
        print(f"ERROR: missing {graph_path} (run task-06 first)", file=sys.stderr)
        return 1
    try:
        graph = json.loads(graph_path.read_text())
    except json.JSONDecodeError as e:
        print(f"ERROR: {graph_path} is not valid JSON: {e}", file=sys.stderr)
        return 2

    tier_weights = dict(DEFAULT_TIER_WEIGHTS)
    if args.tier_weights:
        tier_weights.update(json.loads(args.tier_weights))
    thresholds = dict(DEFAULT_THRESHOLDS)
    if args.thresholds:
        thresholds.update(json.loads(args.thresholds))

    tier_map, tier_map_source = load_tier_map(output_dir)
    node_tier: dict[str, str] = {}
    for n in graph.get("nodes", []):
        node_tier[n["id"]] = tier_map.get(n["id"], n.get("tier") or "unknown")
    unmapped = sorted({n["id"] for n in graph.get("nodes", []) if n["id"] not in tier_map})

    ranked: list[dict] = []
    nodes_in_paths: set[str] = set()

    for jewel in graph.get("confirmed_paths", []):
        for p in jewel.get("paths", []):
            row = score_path(p, node_tier, tier_weights)
            row["remediation_focus"] = remediation_focus(p)
            row["bucket"] = bucket_for(row["score"], thresholds)
            ranked.append(row)
            for h in p.get("hops", []):
                nodes_in_paths.add(h)

    for jewel in graph.get("inferred_paths", []):
        for p in jewel.get("paths", []):
            row = score_path(p, node_tier, tier_weights)
            row["remediation_focus"] = remediation_focus(p)
            row["bucket"] = "theoretical"
            ranked.append(row)

    by_id = {n["id"]: n for n in graph.get("nodes", [])}
    for node_id, node in by_id.items():
        if node_id in nodes_in_paths:
            continue
        row = score_standalone_finding(node, tier_weights)
        if row is None:
            continue
        row["bucket"] = bucket_for(row["score"], thresholds)
        ranked.append(row)

    ranked.sort(key=tie_break_key)
    for i, row in enumerate(ranked, 1):
        row["rank"] = i

    buckets: dict[str, int] = {}
    for r in ranked:
        buckets[r["bucket"]] = buckets.get(r["bucket"], 0) + 1

    out = {
        "generated_at": utc_iso(),
        "tier_weights_used": tier_weights,
        "thresholds_used": thresholds,
        "tier_map_source": tier_map_source,
        "unmapped_assets": unmapped,
        "buckets": buckets,
        "ranked": ranked,
    }

    artifacts = output_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "attack-paths-ranked.json").write_text(json.dumps(out, indent=2, sort_keys=True))

    md = [f"# Attack Paths — Ranked ({utc_iso()})", "",
          f"Source tier map: **{tier_map_source}**" + (
              " ⚠️ (placeholder — replace with client mapping)" if tier_map_source == "repo-default" else ""),
          "", "## Buckets", ""]
    for b in ("immediate", "short_term", "medium_term", "monitor", "theoretical"):
        md.append(f"- **{b}**: {buckets.get(b, 0)}")
    md.append("")
    md.append("## Top 20 ranked items")
    md.append("")
    md.append("| Rank | Kind | Class | Asset / Path | Score | CVSS | Bucket | Remediation focus |")
    md.append("|---|---|---|---|---|---|---|---|")
    for r in ranked[:20]:
        label = r.get("path_id") or r.get("asset", "")
        md.append(f"| {r['rank']} | {r['kind']} | {r['path_class']} | {label} | "
                  f"{r['score']:.3f} | {r['max_cvss']:.1f} | {r['bucket']} | "
                  f"{r.get('remediation_focus') or ''} |")
    (artifacts / "attack-paths-ranked.md").write_text("\n".join(md))

    print(json.dumps({
        "buckets": buckets,
        "top_score": ranked[0]["score"] if ranked else None,
        "unmapped_assets": unmapped,
        "tier_map_source": tier_map_source,
        "outputs": ["artifacts/attack-paths-ranked.json", "artifacts/attack-paths-ranked.md"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
