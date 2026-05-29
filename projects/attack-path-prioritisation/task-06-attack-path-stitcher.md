# Task 06 — Attack Path Stitcher

**Project**: attack-path-prioritisation — **core deliverable** (multi-hop confirmed attack paths)
**Trigger**: Cron daily 03:00 UTC. Also event after task-03 validates a new finding.
**Skill**: `attack-path-stitcher`

## Inputs

- `OUTPUT_DIR`
- Requires: `validated/*.json` (≥1) and `artifacts/org-surface.json`.
- `validated/*.json` is **pulled from the latest `attacks-validation` session over the platform REST API** — attacks-validation and attack-path-prioritisation run in separate MCS sessions and do not share a filesystem. See step 2 below.

## Procedure

1. Load `skills/attack-path-stitcher/SKILL.md` and `reference/edge-detectors.md`.

2. Pull validated findings from the latest attacks-validation session into `$OUTPUT_DIR/validated/`:
   ```
   python3 tools/fetch-validated-findings.py --output-dir "$OUTPUT_DIR"
   ```
   The tool emits a one-line JSON status and **reconciles** — local `finding-*.json` files in `$OUTPUT_DIR/validated/` that the latest attacks-validation session no longer contains are removed, so findings attacks-validation has re-classified to false-positive cannot pollute the stitcher input.

   Propagate the tool's status to task-06:

   | Tool status | task-06 action |
   |---|---|
   | `OK` | Continue to step 3. |
   | `NOOP` (no attacks-validation session yet, or session has no validated findings) | Emit task-06 `NOOP` and stop. |
   | `FAILED` / `FAILED_partial` | Emit task-06 `FAILED` (include the tool's error) and stop. |

3. Run the stitcher:
   ```
   python3 tools/chain-merger.py --output-dir "$OUTPUT_DIR"
   ```
   It implements all 7 edge detectors (credential-reuse, shared-secret, trust-zone, ad-path, iam-chain, ssrf-reach, supply-chain) and writes:
   - `artifacts/attack-paths.json`
   - `artifacts/attack-paths.dot`
   - `artifacts/attack-paths.md`

4. Read the stitcher's stdout JSON. Emit task status.

## Outputs

- `$OUTPUT_DIR/artifacts/attack-paths.json` — graph with nodes, edges, entry-points, crown-jewel paths
- `$OUTPUT_DIR/artifacts/attack-paths.dot` — Graphviz source (render externally if needed)
- `$OUTPUT_DIR/artifacts/attack-paths.md` — human ranked list

## Constraints

- Edges require evidence — no speculative edges (Rule 1 of skill).
- Graph capped at 50,000 edges (Rule 7). If hit, `truncated: true` is set and downstream prioritisation should re-run after asset-inventory pruning.
- Read-only — never touches `findings/` (Rule 6).

## Status emit

```json
{"task": "attack-path-stitcher", "status": "OK",
 "nodes": 142, "edges": 318, "entry_points": 8,
 "confirmed_paths": 11, "inferred_paths": 23,
 "truncation": {"edge_cap_hit": false, "depth_truncated_count": 0, "topn_dropped_count": 0, "max_depth": 8, "edge_cap": 50000},
 "outputs": ["artifacts/attack-paths.json"],
 "next": [{"task": "task-07-risk-prioritiser"}]}
```

Alert if `truncation.depth_truncated_count > 0` or `truncation.topn_dropped_count > 0` — the runtime should bump `--max-depth` and re-run; otherwise paths are silently dropped.

`NOOP` when no validated findings exist yet (early-stage engagement).
`BLOCKED` if `artifacts/org-surface.json` is missing — emit `BLOCKED_REASON: run task-05-org-recon-refresh first`.
