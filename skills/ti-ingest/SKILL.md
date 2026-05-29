---
name: ti-ingest
description: Threat-intel signal ingest — converts a CVE + affected-asset + claim payload into a queued engagement-scope row for the validation pipeline.
---

# Threat-Intel Signal Ingest

Convert a threat-intel signal into a queued engagement-scope row that the Exploitability Validation Run (cloud-agent task #3) consumes.

## Trigger

Two modes:
- **Prompt-invoked**: an analyst runs the skill against a `signal.json` they have on hand.
- **Scheduled poll**: the cloud-agent runtime polls `{OUTPUT_DIR}/inbox/` on a cron (default every 15 minutes) and processes any new signal files it finds.

## Workflow

1. **Read the payload** — `tools/ti-ingest.py --in <path-or-stdin>`.
2. **Validate schema** — required keys: `signal_id`, `cve` (one or more), `assets` (one or more), `claim`. Optional: `confidence`, `source`, `references`.
3. **Enrich with NVD** — for every CVE in the payload, run `tools/nvd-lookup.py <CVE>` and attach `{score, severity, cwe}` to the row.
4. **De-dup** — skip rows whose `(asset, cve)` pair already exists in `queue/scope-*.json`. Re-queue only if the prior row's status is `REJECTED` AND the TI signal carries a higher `confidence` than the last attempt.
5. **Write queue row** — one JSON file per `(asset, cve)` pair at `queue/scope-{ts}-{asset_id}-{cve}.json`. The Validation Run task picks these up.

## Output

```
{OUTPUT_DIR}/
  inbox/
    signal-{ts}.json        # raw payload, kept for audit
  queue/
    scope-{ts}-{asset}-{cve}.json
```

Per scope row:

```json
{
  "scope_id": "scope-20260513-asset42-CVE-2024-12345",
  "signal_id": "ti-2026-0042",
  "asset": {"id": "asset42", "url": "https://app.example.com", "tier": "revenue"},
  "cve": "CVE-2024-12345",
  "nvd": {"score": 9.8, "severity": "CRITICAL", "cwe": "CWE-79"},
  "claim": "Reflected XSS via search parameter",
  "confidence": "high",
  "source": "vendor-advisory",
  "references": ["https://..."],
  "queued_at": "2026-05-13T10:00:00Z",
  "status": "queued"
}
```

## Rules

1. **Idempotent.** Re-running on the same payload must not produce duplicate queue rows.
2. **No execution.** Ingest never runs PoCs. It only queues scope for downstream tasks.
3. **Audit trail.** Raw payload is always copied to `inbox/` before any transformation.
4. **NVD failures are non-blocking.** If `nvd-lookup` errors, write the row with `nvd: null` and `nvd_error: "..."`; do not drop the signal.
5. **Asset must be in inventory.** Cross-check `asset.id` against `artifacts/org-surface.json` (from Org Recon Refresh task). Unknown assets get a row but flagged `unknown_asset: true` so the validator skips them.

## References

- `reference/ingest-schema.md` — full input/output JSON schemas.
