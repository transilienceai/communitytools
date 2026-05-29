# Task 07 — Risk-Based Prioritisation

**Project**: attack-path-prioritisation — **core deliverable** (ranked attack paths driving remediation roadmap)
**Trigger**: Cron daily 03:30 UTC (immediately after task-06).
**Skill**: `risk-prioritiser`

## Inputs

- `OUTPUT_DIR`
- Requires: `artifacts/attack-paths.json` (from task-06).
- Requires: `business-tier-map.csv` — search order:
  1. `$OUTPUT_DIR/business-tier-map.csv` (client-instance override)
  2. `projects/attack-path-prioritisation/schemas/business-tier-map.csv` (repo default with example rows; treated as placeholder — emits a warning)

## Procedure

1. Load `skills/risk-prioritiser/SKILL.md` and `reference/scoring-formula.md` (the algorithm reference).
2. Run the deterministic implementation:
   ```
   python3 tools/risk-prioritise.py --output-dir "$OUTPUT_DIR"
   ```
   The tool enforces:
   - Only paths with `path_class == "confirmed"` may be placed in `immediate / short_term / medium_term / monitor`.
   - Inferred paths always go to `theoretical`, regardless of numeric score (attack-path-prioritisation compliance gate).
   - Stable rank for stable input — `sort_keys=True` JSON output, deterministic tie-breaks.
3. Read tool stdout JSON and emit task status.

To override thresholds or tier weights for a specific client:

```
python3 tools/risk-prioritise.py --output-dir "$OUTPUT_DIR" \
  --tier-weights '{"crown_jewel":1.0,"revenue":0.85,"support":0.5,"dev":0.2}' \
  --thresholds   '{"immediate":0.65,"short_term":0.35,"medium_term":0.15}'
```

Any override is recorded in `attack-paths-ranked.json` under `tier_weights_used` / `thresholds_used` for audit.

## Outputs

- `$OUTPUT_DIR/artifacts/attack-paths-ranked.json`
- `$OUTPUT_DIR/artifacts/attack-paths-ranked.md`

## Constraints

- Derive-only — never re-runs PoCs or alters validation verdicts (Rule 1 of skill).
- Stable rank for stable input (Rule 3) — re-running on identical input must produce byte-identical output.
- `business-tier-map.csv` is authoritative for tier weights (Rule 2). Missing assets → `unknown` weight + `unmapped_assets[]` flag.

## Status emit

```json
{"task": "risk-prioritiser", "status": "OK",
 "buckets": {"immediate": 4, "short_term": 11, "medium_term": 22, "monitor": 8},
 "top_score": 0.98,
 "unmapped_assets": ["asset_unknown_43"],
 "outputs": ["artifacts/attack-paths-ranked.json"],
 "next": [{"task": "task-08-exec-report", "reason": "ranking-updated"}]}
```

`buckets.immediate > 0` is the signal that the weekly exec report should run on its next scheduled tick (or sooner if the analyst chooses to invoke task-08 manually).
