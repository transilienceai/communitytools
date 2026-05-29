# business-tier-map.csv — Schema

Client-supplied mapping from asset ID → business criticality tier. Drives the `business_impact` weight in `risk-prioritiser`.

## Columns

| Column | Required | Type | Description |
|---|---|---|---|
| `asset_id` | Yes | string | Must match the `id` field used in `inventory.json` and `org-surface.json`. |
| `tier` | Yes | enum | One of `crown_jewel`, `revenue`, `support`, `dev`. |
| `owner` | No | string | Team or individual responsible for the asset (used in report attribution). |
| `notes` | No | string | Free-text rationale or compliance tags (e.g., "SOX-scoped", "GDPR PII"). |

## Tier semantics

| Tier | Definition | Default weight |
|---|---|---|
| `crown_jewel` | Compromise causes existential business impact: data breach, regulator fine, revenue cliff, IP loss. | 1.00 |
| `revenue` | Outage or compromise directly degrades a revenue stream (customer-facing apps, billing systems, transactional APIs). | 0.70 |
| `support` | Internal-facing systems that are required for ops but not customer-revenue (HR, internal wiki, support tooling). | 0.40 |
| `dev` | Non-production: CI, staging, sandboxes. Lower direct impact, but credentials there often leak into higher tiers. | 0.20 |
| _missing_ | Asset not in the map. Tier defaults to `unknown`, weight 0.30 — deliberately above `support` to bias toward investigation. | 0.30 |

## Onboarding

A new client engagement starts by:

1. Pulling `inventory.json` from the client's CMDB (or analyst-curated).
2. Populating this CSV — typically a 30-minute session with the client's security lead.
3. Dropping the CSV at `{OUTPUT_DIR}/business-tier-map.csv` (the per-engagement override location).

The repo-level default at `projects/attack-path-prioritisation/schemas/business-tier-map.csv` contains example rows only and triggers a warning in `risk-prioritiser` output (`tier_map_source: "repo-default — replace with client mapping"`).

## Overriding tier weights

If a client's business model gives a non-standard weighting (e.g., a SaaS where "support" infrastructure actually carries revenue), invoke task-07 with `--tier-weights '{"support": 0.65, "revenue": 0.85}'` to override the defaults for that run. The weights used are recorded in `attack-paths-ranked.json` under `tier_weights_used`.

## Validation rules

- `asset_id` must be unique. Duplicates → last row wins; warning emitted.
- `tier` must be one of the four enums. Invalid values → row dropped, warning emitted.
- Empty CSV is valid but treated as "all assets unknown" with a runtime warning.
