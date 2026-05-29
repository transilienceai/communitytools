# Task 05 — Org Recon Refresh

**Project**: attack-path-prioritisation (surface graph input to stitcher)
**Trigger**: Cron weekly (Sundays 22:00 UTC), or prompt-invoked when an analyst adds an asset to inventory and wants the surface refreshed immediately.
**Skills**: `reconnaissance`, `osint`, `techstack-identification`

## Inputs

- `OUTPUT_DIR`
- Asset inventory file: `$OUTPUT_DIR/inventory.json` (client-supplied or CMDB-synced).
- Optional `--asset` to limit refresh to a single asset (event mode).

## Procedure

1. Load `skills/reconnaissance/SKILL.md`, `skills/osint/SKILL.md`, `skills/techstack-identification/SKILL.md`.
2. For each asset in inventory (or just the `--asset` argument):
   1. **Recon** — `reconnaissance` skill produces `$OUTPUT_DIR/recon/{asset}/{ports.json, endpoints.json, subdomains.json}` per `formats/reconnaissance.md`.
   2. **OSINT** — `osint` skill produces `$OUTPUT_DIR/recon/{asset}/osint.json` (repos, leaked secrets, employee footprint).
   3. **Tech stack** — `techstack-identification` skill produces `$OUTPUT_DIR/recon/{asset}/techstack.json`.
3. Concurrency: max 8 assets in parallel (recon is I/O-heavy, lots of waiting).
4. **Aggregate** — merge per-asset outputs into one org graph at `$OUTPUT_DIR/artifacts/org-surface.json`. Schema:
   ```json
   {
     "generated_at": "...",
     "nodes": [{"id": "...", "tier": "...", "services": [...], "zone": "...",
                "external": true|false, "internal_endpoints": [...]}],
     "network_zones": {"dmz": [...], "internal": [...]},
     "trust_edges": [...],
     "ad_principals": {"PrincipalName": "owner_asset_id"},
     "iam_roles": {"RoleName": "owner_asset_id"},
     "sbom": {"asset_dependent": ["asset_provider"]}
   }
   ```
5. `tier` is pulled from `projects/attack-path-prioritisation/schemas/business-tier-map.csv` if present, else `unknown`.
6. Emit status JSON.

## Outputs

- `$OUTPUT_DIR/recon/{asset}/...` (per-asset)
- `$OUTPUT_DIR/artifacts/org-surface.json` (org-wide)

## Constraints

- Recon is non-intrusive — no exploitation, no auth attempts, no creds. Respect any `--scope` boundaries declared in inventory.
- If a previous run's `org-surface.json` exists, the new file overwrites it. Snapshots are kept by the runtime, not by this task.
- Asset entries missing `external` or `zone` get sensible defaults: `external: true` for any asset with a public-facing endpoint discovered during recon, `zone: "unknown"` otherwise.

## Status emit

```json
{"task": "org-recon-refresh", "status": "OK",
 "assets_refreshed": 142,
 "new_endpoints": 23,
 "outputs": ["artifacts/org-surface.json"],
 "next": [{"task": "task-06-attack-path-stitcher"}]}
```
