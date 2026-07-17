# Pentest Engagements

The repo's primary hands-on workspace: real, scoped penetration tests, vulnerability assessments, and network scans run here. Each engagement is a self-contained, dated directory under `projects/pentest/`.

The generic repository overview, standing principles, cross-cutting rules, and ethics load from the repo-root [`CLAUDE.md`](../../CLAUDE.md) — an ancestor that is always concatenated **above** this file. This file only adds the pentest-specific operating model; it does not repeat what root already states.

The user is **pre-authorized** for all testing activities — engagements are conducted with explicit authorization. All activities remain non-destructive and ethical.

## Engagement workspace layout

- **One dated directory per engagement** = its `OUTPUT_DIR`: `projects/pentest/YYYYMMDD_<tag>/` (e.g. `20260712_asianpaints_art/`). Never write engagement artifacts to the repo root, to the `projects/pentest/` root, or to the cwd — only inside the engagement's `OUTPUT_DIR`.
- **Scope file** sits alongside as `projects/pentest/<tag>-scope.md` (or `YYYYMMDD_<tag>-scope.md`); it is ingested into `OUTPUT_DIR/input/` at flow start.
- **Output tree** — create it up-front, before any tool runs: `input/ recon/ findings/finding-NNN/ logs/activity/ artifacts/{validated,false-positives,dropped,nvd-cache,…} tools/ reports/`, plus `attack-chain.md`, `experiments.md`, `stats.json` at the root. Canonical spec: [`skills/coordination/reference/output-discipline.md`](../../skills/coordination/reference/output-discipline.md).
- **Per-engagement workflows** live under `projects/pentest/<eng>/workflows/` — **never** `.claude/workflows/` (see the boundary rule).

## Reusable-content ⇄ client boundary

Everything reusable — `skills/`, `tools/`, `formats/`, `docs/`, and this project's `.claude/` — must carry **no** client name, target host, IP, credential, or engagement path. Only `projects/pentest/<eng>/` may hold client-specific data. When an engagement yields a reusable technique or tool, generalize it (strip every client specific) before it leaves the engagement directory.

## Entry points

| Goal | Start with |
|------|-----------|
| Full engagement from a scope (web attack-class coverage **or** batched network scan) | `pentest-engagement` |
| Drive one target to a goal autonomously (recon → think → experiment loop) | `coordinator-loop` |
| Authoritatively validate every finding for an asset | `validate-findings` |
| Produce the branded deliverable PDF | `transilience-report-style` → [`formats/INDEX.md`](../../formats/INDEX.md) |

The inline coordinator (one per target) is [`skills/coordination/SKILL.md`](../../skills/coordination/SKILL.md); it spawns executors, skeptics, and validators per the role matrix.

## Skill selection

1. Read [`skills/INDEX.md`](../../skills/INDEX.md) — the skill router. The pentest skill library is also mirrored under [`.claude/skills/`](.claude/skills) (surfaced as `projects/pentest:<skill>`).
2. Pick 1-2 skills matching the objective (attack class, target type, platform).
3. Read each chosen skill's `SKILL.md` to load context. Read specific `reference/*.md` files for the techniques you need to apply.
4. Begin execution immediately — do not ask the user which skills to use.

Never load all skills. Never inject `SKILL.md` files into executor prompts — pass the specific reference file paths.

## Agent architecture

| Role | File | When |
|------|------|------|
| Coordinator | [`skills/coordination/SKILL.md`](../../skills/coordination/SKILL.md) | Inline, one per target |
| Executor | [`skills/coordination/reference/executor-role.md`](../../skills/coordination/reference/executor-role.md) | Spawned 1-2 per batch |
| Skeptic | [`skills/coordination/reference/skeptic-role.md`](../../skills/coordination/reference/skeptic-role.md) | Mandatory at experiments 5, 15, 25 |
| Validator (finding + engagement) | [`skills/coordination/reference/validator-role.md`](../../skills/coordination/reference/validator-role.md) | At P5 |

Boundaries and context contracts: [`skills/coordination/reference/role-matrix.md`](../../skills/coordination/reference/role-matrix.md). Spawning recipes: [`skills/coordination/reference/spawning-recipes.md`](../../skills/coordination/reference/spawning-recipes.md).

## Inherited from repo-root `CLAUDE.md`

These load automatically from [`../../CLAUDE.md`](../../CLAUDE.md) — consult it there rather than duplicating here:

- **Role** — cybersecurity expert; professional, clean, thoughtful; think before deciding.
- **Standing principles** — [`skills/coordination/reference/principles.md`](../../skills/coordination/reference/principles.md).
- **Cross-cutting canonical homes** — credential loading, pre-flight checklist, bookkeeping, brute-force prohibition, validation procedure, git conventions, output formats, activity/source-IP logging.
- **CVE risk lookup** — whenever a `CVE-YYYY-NNNNN` appears, run `python3 tools/nvd-lookup.py <CVE-ID>` before acting on it.
- **Ethics & authorization** — explicit authorization for all engagements; avoid destructive operations (`DROP`, `rm -rf`, DoS, data corruption) unless strictly necessary; stay in scope; document complete evidence chains; report unexpected access immediately.
