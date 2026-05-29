# TI Ingest — Input/Output Schemas

## Input — TI signal payload

```json
{
  "signal_id": "ti-2026-0042",
  "source": "vendor-advisory | threat-feed | analyst | scanner",
  "cve": ["CVE-2024-12345"],
  "assets": [
    {"id": "asset42", "url": "https://app.example.com", "ip": "1.2.3.4"}
  ],
  "claim": "Free-text 1-line description of the alleged vulnerability",
  "confidence": "low | medium | high",
  "references": ["https://nvd.nist.gov/...", "https://vendor/advisory/..."]
}
```

### Required

- `signal_id` — opaque string, unique per submission (analyst-chosen or assigned by the source system).
- `cve` — array of CVE IDs (regex `CVE-\d{4}-\d{4,}`). At least one.
- `assets` — array of objects, each with `id`. At least one. `url` or `ip` strongly recommended.
- `claim` — 1-line human description.

### Optional

- `confidence` — default `medium` if absent.
- `source`, `references` — kept for audit, not used for de-dup.

## Output — queued scope row

See SKILL.md "Output" section for the canonical shape. One file per `(asset, cve)` pair.

## De-dup logic

```
key = f"{asset.id}::{cve}"
existing = glob queue/scope-*-{asset.id}-{cve}.json + validated/*.json + false-positives/*.json
if existing:
    if any(e.status == "queued" or e.status == "VALID"):
        skip — already known
    if all(e.status == "REJECTED") and incoming.confidence == "high" and existing[-1].confidence != "high":
        re-queue — analyst is escalating
    else:
        skip
```

## Asset tier

The `tier` field on the queued row is populated from `business-tier-map.csv` (see `projects/rfp-3.3/schemas/business-tier-map.csv`). If the asset is not in the map, `tier = "unknown"` and the row carries `unknown_asset: true`.
