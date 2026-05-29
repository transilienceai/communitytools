# Task 01 — TI Signal Ingest

**Project**: attacks-validation (entry point)
**Trigger**: Prompt-invoked by an analyst with a `signal.json` in hand, or a cron job (default every 15 min) that polls `{OUTPUT_DIR}/inbox/` for new signal files.
**Skill**: `ti-ingest`

## Inputs

- `OUTPUT_DIR` (env): engagement root.
- `signal.json` (stdin or file): TI signal payload — see `skills/ti-ingest/reference/ingest-schema.md`.

## Procedure

1. Invoke `ti-ingest` skill — load `skills/ti-ingest/SKILL.md`.
2. Run:
   ```
   python3 tools/ti-ingest.py --in signal.json --output-dir "$OUTPUT_DIR"
   ```
3. Read tool stdout. For each `written` path, emit a `next` entry pointing to `task-03-validation-run` keyed on the scope file. The runtime picks these up on the next scheduled tick.
4. Emit task status JSON.

## Outputs

- `$OUTPUT_DIR/inbox/signal-{ts}.json` — raw audit copy
- `$OUTPUT_DIR/queue/scope-{ts}-{asset}-{cve}.json` — one per `(asset, cve)` pair

## Status emit

```json
{"task": "ti-ingest", "status": "OK",
 "outputs": ["queue/scope-20260513T100000Z-asset42-CVE-2024-12345.json"],
 "next": [{"task": "task-03-validation-run", "scope": "queue/scope-..."}]}
```

`NOOP` if all incoming `(asset, cve)` pairs are duplicates and nothing was queued.
