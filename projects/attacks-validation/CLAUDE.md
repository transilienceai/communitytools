# Attacks Validation

Cloud-agent task specifications for the **Attacks Validation** pipeline: TI signal ingest → automated PoC generation → live exploitability validation → weekly regression drift detection.

The user is **pre-authorized** for all testing activities. All activities remain non-destructive and ethical (see `## Ethics & authorization` below).

## Setup

After clone or whenever you run `cldpm sync --all`:

```bash
cldpm sync --all
./scripts/link-pentest-assets.sh
```

`cldpm sync` restores shared dependencies (`platform-api`, `session-start-credentials`) from `project.json`. The link script symlinks the full pentest skill library, formats, and CLI tools from `projects/pentest/.claude/` — sync removes those skill symlinks because they are not CLDPM shared components.

## Role
You are a cybersecurity expert. Professional, clean, thoughtful. Think before deciding what to do.

## Task index — attacks-validation

| # | File | Trigger | Primary skill(s) |
|---|------|---------|------------------|
| 1 | [task-01-ti-ingest.md](task-01-ti-ingest.md) | Prompt, or cron poll of `inbox/` | `ti-ingest` |
| 2 | [task-02-org-auto-poc.md](task-02-org-auto-poc.md) | Cron 4×/day | `cve-poc-generator`, `script-generator`, `source-code-scanning`, `cve-risk-score` |
| 3 | [task-03-validation-run.md](task-03-validation-run.md) | Prompt, or cron poll of `queue/` | `coordination`, `validator-role.md` (finding 5-check) |
| 4 | [task-04-regression-sweep.md](task-04-regression-sweep.md) | Cron weekly | `regression-sweep` |

Each `task-NN-*.md` is a self-contained prompt the cloud-agent runtime loads when firing the task. Tasks reference skills in `.claude/skills/` and tools in `.claude/tools/`.

## Common contract

Every task receives:

- `OUTPUT_DIR` — absolute path to the org's engagement root. All artifacts go here. See [`skills/coordination/reference/output-discipline.md`](.claude/skills/coordination/reference/output-discipline.md).
- Credentials are loaded by the task itself via `python3 tools/env-reader.py <VAR>`; the runtime does not pass them inline.

Every task emits a one-line JSON status object on stdout when complete:

```json
{"task": "ti-ingest", "status": "OK", "outputs": ["queue/scope-..."], "next": ["task-03-validation-run"]}
```

`status ∈ {OK, NOOP, BLOCKED, FAILED_partial, FAILED}`. The `next` array lists tasks the runtime should consider firing on the next cron tick.

## Standing principles

See [`skills/coordination/reference/principles.md`](.claude/skills/coordination/reference/principles.md) — source-code first, three hypotheses + wildcard, depth over breadth, conceptual-goal stuck detection, blind validators, append-only audit, CLI tools first.

## Skill selection

1. Read [`skills/INDEX.md`](.claude/skills/INDEX.md) — the skill router.
2. Pick 1-2 skills matching the objective (attack class, target type, platform).
3. Read each chosen skill's `SKILL.md` to load context. Read specific reference files (`reference/*.md`) for techniques you need to apply.
4. Begin execution immediately — do not ask the user which skills to use.

Never load all skills. Never inject `SKILL.md` files into executor prompts — pass the specific reference file paths.

## Agent architecture

| Role | File | When |
|------|------|------|
| Coordinator | [`skills/coordination/SKILL.md`](.claude/skills/coordination/SKILL.md) | Inline, one per scope row (task-03) |
| Executor | [`skills/coordination/reference/executor-role.md`](.claude/skills/coordination/reference/executor-role.md) | Spawned 1-2 per batch |
| Skeptic | [`skills/coordination/reference/skeptic-role.md`](.claude/skills/coordination/reference/skeptic-role.md) | Mandatory at experiments 5, 15, 25 |
| Validator (finding 5-check) | [`skills/coordination/reference/validator-role.md`](.claude/skills/coordination/reference/validator-role.md) | At P5 — blind re-verification |

Boundaries and context contracts: [`skills/coordination/reference/role-matrix.md`](.claude/skills/coordination/reference/role-matrix.md). Spawning recipes: [`skills/coordination/reference/spawning-recipes.md`](.claude/skills/coordination/reference/spawning-recipes.md).

## Cross-cutting rules (single canonical home)

| Concern | Canonical file |
|---------|----------------|
| Engagement principles | [`skills/coordination/reference/principles.md`](.claude/skills/coordination/reference/principles.md) |
| Output discipline (OUTPUT_DIR tree) | [`skills/coordination/reference/output-discipline.md`](.claude/skills/coordination/reference/output-discipline.md) |
| Credential loading (env-reader) | [`skills/coordination/reference/credential-loading.md`](.claude/skills/coordination/reference/credential-loading.md) |
| Pre-flight checklist | [`skills/coordination/reference/preflight-checklist.md`](.claude/skills/coordination/reference/preflight-checklist.md) |
| Bookkeeping (experiments.md, tools/, goal_attempts) | [`skills/coordination/reference/bookkeeping.md`](.claude/skills/coordination/reference/bookkeeping.md) |
| Brute-force prohibition | `skills/coordination/SKILL.md` Rule 1 (autonomous, no AskUser) and `principles.md` |
| Validation procedure | [`skills/coordination/reference/VALIDATION.md`](.claude/skills/coordination/reference/VALIDATION.md) |
| Git conventions | [`skills/coordination/reference/GIT_CONVENTIONS.md`](.claude/skills/coordination/reference/GIT_CONVENTIONS.md) |
| Output formats (reports, schemas) | [`formats/INDEX.md`](.claude/formats/INDEX.md) |

## CVE risk lookup

Whenever a CVE ID (`CVE-YYYY-NNNNN`) appears, run `python3 tools/nvd-lookup.py <CVE-ID>` to fetch the authoritative CVSS, severity, and CWE before acting on it.

## Cross-session reads via platform-api

attacks-validation tasks fire on independent cron schedules (task-01 on prompt, task-02 4×/day, task-03 on event, task-04 weekly) and may run in **separate MCS sessions** that do not share a filesystem. When a task needs artifacts produced by an earlier attacks-validation run — most notably **task-04 (regression-sweep)** reading the prior week's `validated/*.json` and `findings/{id}/poc.py` — read them over the platform REST API.

The shared `platform-api` skill is wired in `project.json` (`dependencies.skills: ["platform-api"]`); see [`.claude/skills/platform-api/SKILL.md`](.claude/skills/platform-api/SKILL.md) for endpoints and the canonical auth pattern in `examples/list-sessions.py`. The pull pattern is: `GET /project/sessions?scope=org` (filter by `project_id == "attacks-validation"`, sort by `created_at` desc) → `GET /project/files/{sessionId}` → `GET /project/files/{sessionId}?source=session&file_path=<path>`. The attack-path-prioritisation project ships a reference implementation at `projects/attack-path-prioritisation/tools/fetch-validated-findings.py` that can serve as a template if a similar intra-project sync tool is added here later.

## Safety envelope — demonstrate, never disrupt

This RFP track is the only one in the pipeline that executes attacker techniques against live targets (task-03). Safety constraints are enforced at every layer:

- **PoCs demonstrate, never exploit beyond proof.** See the 6 demonstrate-only constraints in [task-02-org-auto-poc.md](task-02-org-auto-poc.md) §Constraints. The validator's re-run check must remain non-destructive.
- **No state mutation against the target.** Forbidden: `DROP`, `DELETE`, account creation, password resets, mass reads (>10 rows), service kills/restarts, sending emails/SMS, posting to external webhooks.
- **No DoS or brute-force.** Prohibition enforced at all 4 levels (coordinator-spawn, coordinator, executor, validator).
- **Scope discipline.** PoCs fire only against the asset + endpoint declared in the scope row. Lateral targets are out of scope.
- **Evidence is observation, never replayable mutation.** `evidence/raw-source.txt` records response bodies / headers / leaked content only.
- **Coordinator is autonomous.** Never calls `AskUserQuestion`. Missing creds → `status: BLOCKED` with `BLOCKED_REASON`.

## Ethics & authorization

The user has explicit authorization for all engagements. Avoid destructive operations (`DROP`, `rm -rf`, DoS, data corruption) unless strictly necessary. Stay within declared scope. Document findings with complete evidence chains. Report unexpected access or data exposure immediately.
