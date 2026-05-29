# Attack Path Identification & Prioritisation

Cloud-agent task specifications for the **Attack Path Identification & Prioritisation** pipeline: org surface refresh → attack-path stitching → risk-based prioritisation → executive reporting.

The user is **pre-authorized** for all testing activities. All activities remain non-destructive and ethical (see `## Ethics & authorization` below).

## Setup

After clone or whenever you run `cldpm sync --all`:

```bash
cldpm sync --all
./scripts/link-pentest-assets.sh
```

`cldpm sync` restores shared dependencies (`platform-api`, `session-start-credentials`) from `project.json`. The link script symlinks pipeline skills, formats, and CLI tools from `projects/pentest/.claude/` — sync removes those skill symlinks because they are not CLDPM shared components.

## Role
You are a cybersecurity expert. Professional, clean, thoughtful. Think before deciding what to do.

## Task index — attack-path-prioritisation

| # | File | Trigger | Primary skill(s) |
|---|------|---------|------------------|
| 5 | [task-05-org-recon-refresh.md](task-05-org-recon-refresh.md) | Cron weekly, or prompt | `reconnaissance`, `osint`, `techstack-identification` |
| 6 | [task-06-attack-path-stitcher.md](task-06-attack-path-stitcher.md) | Cron daily | `attack-path-stitcher` |
| 7 | [task-07-risk-prioritiser.md](task-07-risk-prioritiser.md) | Cron daily after #6 | `risk-prioritiser` |
| 8 | [task-08-exec-report.md](task-08-exec-report.md) | Cron weekly | `formats/transilience-report-style/pentest-report.md` |

Each `task-NN-*.md` is a self-contained prompt the cloud-agent runtime loads when firing the task. Tasks reference skills in `.claude/skills/` and tools in `.claude/tools/`.

## Common contract

Every task receives:

- `OUTPUT_DIR` — absolute path to the org's engagement root. All artifacts go here. See [`skills/coordination/reference/output-discipline.md`](.claude/skills/coordination/reference/output-discipline.md).
- Credentials are loaded by the task itself via `python3 tools/env-reader.py <VAR>`; the runtime does not pass them inline.

Every task emits a one-line JSON status object on stdout when complete:

```json
{"task": "attack-path-stitcher", "status": "OK", "nodes": 142, "edges": 318, "outputs": ["artifacts/attack-paths.json"], "next": ["task-07-risk-prioritiser"]}
```

`status ∈ {OK, NOOP, BLOCKED, FAILED_partial, FAILED}`. The `next` array lists tasks the runtime should consider firing on the next cron tick.

## Cross-RFP inputs

attack-path-prioritisation consumes the validated findings produced by attacks-validation. The stitcher and prioritiser are **derive-only** — they never re-validate findings, never execute attacker techniques, never touch live targets.

`attacks-validation` and `attack-path-prioritisation` run in **separate MCS sessions**. The shared `platform-api` skill is the transport — declared in `project.json` (`dependencies.skills: ["platform-api"]`) and symlinked at `.claude/skills/platform-api/`. Two purpose-built fetchers in `tools/` share auth + pagination logic via `_platform_client.py`:

| Tool | Pulls | Used by | RFP property enforced |
|---|---|---|---|
| `tools/fetch-validated-findings.py` | `validated/*.json` (strict path filter) | task-06 stitcher | attack-path-prioritisation "**confirmed** attack paths" — reconciles stale local files so re-classified findings cannot pollute the stitcher input |
| `tools/fetch-regression-summaries.py` | the latest `artifacts/regression-{YYYYWww}.json` | task-08 exec report | attacks-validation "weekly regression drift detection" surfaces into the exec report; optional input, NOOP cleanly when attacks-validation has not run task-04 yet |

Both tools call `/project/sessions?scope=org` filtered to `project_id == "attacks-validation"`, sort by `created_at` desc, and use `/project/files/{sessionId}` for listing + reading. See `.claude/skills/platform-api/SKILL.md` for the API reference and `_platform_client.py` for the shared client code.

- Stitcher input: `$OUTPUT_DIR/validated/*.json` (pulled from attacks-validation task-03 via `tools/fetch-validated-findings.py`) + `$OUTPUT_DIR/artifacts/org-surface.json` (from task-05).
- Prioritiser input: `$OUTPUT_DIR/artifacts/attack-paths.json` (from task-06) + `schemas/business-tier-map.csv`.
- Exec report input: ranked paths + org surface + optionally `$OUTPUT_DIR/artifacts/regression-{YYYYWww}.json` (pulled via `tools/fetch-regression-summaries.py`).

## Standing principles

See [`skills/coordination/reference/principles.md`](.claude/skills/coordination/reference/principles.md) — source-code first, three hypotheses + wildcard, depth over breadth, conceptual-goal stuck detection, blind validators, append-only audit, CLI tools first.

## Skill selection

1. Read [`skills/INDEX.md`](.claude/skills/INDEX.md) — the skill router.
2. Pick 1-2 skills matching the objective (recon scope, graph operation, scoring policy).
3. Read each chosen skill's `SKILL.md` to load context. Read specific reference files (`reference/*.md`) for techniques you need to apply.
4. Begin execution immediately — do not ask the user which skills to use.

Never load all skills. attack-path-prioritisation tasks are deterministic-derivation tasks; favor the canonical CLI tools (`chain-merger.py`, `risk-prioritise.py`) over re-implementing the logic.

## Cross-cutting rules (single canonical home)

| Concern | Canonical file |
|---------|----------------|
| Engagement principles | [`skills/coordination/reference/principles.md`](.claude/skills/coordination/reference/principles.md) |
| Output discipline (OUTPUT_DIR tree) | [`skills/coordination/reference/output-discipline.md`](.claude/skills/coordination/reference/output-discipline.md) |
| Credential loading (env-reader) | [`skills/coordination/reference/credential-loading.md`](.claude/skills/coordination/reference/credential-loading.md) |
| Business-tier mapping schema | [`schemas/business-tier-map.schema.md`](schemas/business-tier-map.schema.md) |
| Output formats (reports, schemas) | [`formats/INDEX.md`](.claude/formats/INDEX.md) |

## CVE risk lookup

Whenever a CVE ID (`CVE-YYYY-NNNNN`) appears, run `python3 tools/nvd-lookup.py <CVE-ID>` to fetch the authoritative CVSS, severity, and CWE before acting on it.

## Safety envelope

attack-path-prioritisation tasks are **non-intrusive**:

- **Recon (task-05) is observation-only.** No exploitation, no auth attempts, no creds. Respect any `--scope` boundaries declared in inventory.
- **Stitcher and prioritiser (tasks 06-07) are derive-only.** They read existing artifacts; they never touch live targets, never re-validate, never re-fire PoCs.
- **Exec report (task-08) is render-only.** It never re-validates findings. Stale ranking artifacts cause a BLOCKED emit, not silent re-derivation.
- **No speculative edges.** Stitcher edges require explicit evidence per detector (Rule 1 of `attack-path-stitcher`).
- **Inferred paths never enter remediation buckets.** Only `path_class == "confirmed"` paths land in `immediate / short_term / medium_term / monitor` (attack-path-prioritisation compliance gate).

## Ethics & authorization

The user has explicit authorization for all engagements. Stay within declared scope. Document findings with complete evidence chains. Report unexpected access or data exposure immediately.
