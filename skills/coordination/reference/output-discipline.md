# Output Discipline

Single canonical OUTPUT_DIR rule + directory tree.

## Rule

Never write any file to the repo root or current working directory. Every file an agent produces — tool output, downloads, scripts, evidence — goes inside an engagement's `OUTPUT_DIR`.

Create the full tree at the start of any engagement, before any tool invocation:

```bash
mkdir -p $OUTPUT_DIR/{input,recon,findings,logs,artifacts,tools,reports}
```

### `input/` — captured engagement inputs (req 11)

At flow start, **every attached or referenced input file** (scope file, a `prior_report` PDF/JSON, a Postman
export, an APK, …) is ingested into `$OUTPUT_DIR/input/` — **idempotently** (skip when an identical file by
`sha256` is already present, or the path already lives under the engagement tree). The ingest step records an
`input_manifest: [{original, stored, bytes, sha256, already_present}]` in `engagement-meta.json`, and every
downstream step reads the **stored copy** — so the engagement is self-contained and re-runnable.

## Tree

```
OUTPUT_DIR/
├── input/              # Ingested engagement inputs (scope, prior report, …) — the self-contained source set
├── recon/              # Scans, fingerprinting, source dumps, share spiders
├── findings/
│   └── finding-NNN/
│       ├── description.md
│       ├── poc.py
│       ├── poc_output.txt
│       └── evidence/
│           ├── raw-source.txt
│           └── validation/   # Validator writes here
├── logs/               # NDJSON activity logs, mission reports
│   └── activity/
│       ├── tool-invocations.jsonl   # Deterministic per-Bash-call audit (PostToolUse hook)
│       └── source-ips.jsonl         # Every registered source/egress IP (register_source_ip.py)
├── artifacts/          # Tool-generated files (.crt, .key, dumps, hashes, configs)
│   ├── validated/      # CONFIRMED (VALID/REPAIRED) finding JSONs — the ONLY findings that reach the report
│   ├── false-positives/ # REJECTED findings (adversarial majority) — audit trail only
│   ├── dropped/        # Uncured DEMOTED findings (drop-entirely) — audit trail only, never the report
│   ├── nvd-cache/      # Frozen per-engagement NVD snapshots (nvd-lookup.py --cache-dir) — deterministic operands
│   ├── kev-snapshot.json # Frozen CISA KEV snapshot (kev-lookup.py) — deterministic operands
│   ├── validation-cache/ # content-hash replay cache (validation_cache.py) — validate-findings re-validation of an UNCHANGED finding dir restores its recorded verdict byte-identically (no LLM lane)
│   ├── engagement-validation.json
│   └── engagement-validation-summary.md
├── tools/              # Per-invocation tool archive (input + output)
├── reports/            # Final PDF, completion report
├── attack-chain.md     # Coordinator's living theory
├── experiments.md      # Append-only experiment ledger
├── stats.json          # Engagement metrics (parent orchestrator finalizes)
└── flags.txt           # Submitted flags (if applicable)
```

## Activity & source-IP logging

`logs/activity/tool-invocations.jsonl` and `logs/activity/source-ips.jsonl` are first-class,
deterministic audit artifacts — machine-written, append-only, and part of every deliverable.

- `logs/activity/tool-invocations.jsonl` — one line per Bash command, written by the harness-run
  PostToolUse hook (`tools/activity-logger.py`). The **full command string of every Bash call is
  harness-guaranteed** — the hook fires on the tool boundary, so no invocation can slip past it.
  Tool-bin extraction (the `bins` field) is **best-effort** parsing of that string. Command strings
  are REDACTED by default.
- `logs/activity/source-ips.jsonl` — one line per source/egress IP, written by
  `tools/register_source_ip.py`. The **primary-runner IP is guaranteed** — deterministic Setup code
  registers it. Every **non-primary egress** (attack VM, proxy, VPN, SOCKS) is **convention-enforced**
  (route provisioning through `tools/provision_vantage.sh`, which registers automatically) and
  **reconciliation-flagged** when an unregistered egress is observed. Auto-`detected` rows are
  `verified:false` and never clear a coverage gap on their own.

State this honestly: command strings are complete, bin parsing and non-primary IP coverage are
best-effort/convention-enforced — never claim a uniform "100%".

## Deliverable ZIP (req 14)

After all outputs complete, `pentest-engagement`'s Package phase emits a single, verified deliverable archive
`<report_id>_deliverable.zip` at the OUTPUT_DIR root, built **directory-based** (never empty globs) from the
clean tree and gated on `unzip -l` (exists ∧ non-empty ∧ entry count):

```
<report_id>_deliverable.zip
├── reports/     # report_data.json (the canonical JSON) + the final PDF (or custom render) + summary.md
├── input/       # the ingested engagement inputs
├── logs/        # NDJSON activity logs
└── artifacts/   # validated finding JSONs, attack-paths-ranked, org-surface
```

`report_data.json` inside `reports/` is the single source of truth; every finding it lists carries a
`proof_dir` pointing back into the tree, so the evidence packages remain traceable.

## Naming

- `OUTPUT_DIR` is named `YYMMDD_<engagement-tag>/` or similar timestamp + tag.
- Findings monotonically increment: `finding-001`, `finding-002`, …
- Tool logs monotonically increment: `tools/001_nmap.md`, `tools/002_curl.md`, …

## Why this discipline matters

- The engagement-validator (P5) reads the directory tree to judge thoroughness. A missing `recon/` or empty `tools/` directory means the engagement skipped phases.
- The PostToolUse hook (W6) increments `stats.json` counters by detecting writes to `findings/finding-NNN/` etc. The path shape is part of the contract.
- Skill linter and CI use this tree to validate runs.

## Anti-patterns

- Writing `nmap_output.txt` in the repo root.
- Reusing one `output/` directory across engagements (clobbers prior runs).
- Putting validator artifacts in `findings/{id}/` directly instead of `findings/{id}/evidence/validation/`.
- Putting `attack-chain.md` inside a subdirectory — it lives at the OUTPUT_DIR root.
