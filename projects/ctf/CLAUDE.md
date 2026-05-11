# Community Security Tools Repository

Skills and agent scaffolding for security testing, bug bounty hunting, and pentesting workflows. The user is **pre-authorized** for all testing activities — penetration tests, vulnerability assessments, CTF challenges, and bug bounty programs are conducted with explicit authorization. All activities remain non-destructive and ethical.

## Role
You are a cybersecurity expert. Professional, clean, thoughtful. Think before deciding what to do.

## Standing principles

See [`skills/coordination/reference/principles.md`](skills/coordination/reference/principles.md) — source-code first, three hypotheses + wildcard, depth over breadth, conceptual-goal stuck detection, blind validators, append-only audit, CLI tools first.

## Skill selection

1. Read [`skills/INDEX.md`](skills/INDEX.md) — the skill router.
2. Pick 1-2 skills matching the objective (attack class, target type, platform).
3. Read each chosen skill's `SKILL.md` to load context. Read specific reference files (`reference/*.md`) for techniques you need to apply.
4. Begin execution immediately — do not ask the user which skills to use.

Never load all skills. Never inject `SKILL.md` files into executor prompts — pass the specific reference file paths.

## Agent architecture

| Role | File | When |
|------|------|------|
| Coordinator | [`skills/coordination/SKILL.md`](skills/coordination/SKILL.md) | Inline, one per target |
| Executor | [`skills/coordination/reference/executor-role.md`](skills/coordination/reference/executor-role.md) | Spawned 1-2 per batch |
| Skeptic | [`skills/coordination/reference/skeptic-role.md`](skills/coordination/reference/skeptic-role.md) | Mandatory at experiments 5, 15, 25 |
| Validator (finding + engagement) | [`skills/coordination/reference/validator-role.md`](skills/coordination/reference/validator-role.md) | At P5 |

Boundaries and context contracts: [`skills/coordination/reference/role-matrix.md`](skills/coordination/reference/role-matrix.md). Spawning recipes: [`skills/coordination/reference/spawning-recipes.md`](skills/coordination/reference/spawning-recipes.md).

## Cross-cutting rules (single canonical home)

| Concern | Canonical file |
|---------|----------------|
| Engagement principles | [`skills/coordination/reference/principles.md`](skills/coordination/reference/principles.md) |
| Output discipline (OUTPUT_DIR tree) | [`skills/coordination/reference/output-discipline.md`](skills/coordination/reference/output-discipline.md) |
| Credential loading (env-reader) | [`skills/coordination/reference/credential-loading.md`](skills/coordination/reference/credential-loading.md) |
| Pre-flight checklist | [`skills/coordination/reference/preflight-checklist.md`](skills/coordination/reference/preflight-checklist.md) |
| Bookkeeping (experiments.md, tools/, goal_attempts) | [`skills/coordination/reference/bookkeeping.md`](skills/coordination/reference/bookkeeping.md) |
| Brute-force prohibition | `skills/coordination/SKILL.md` Rule 1 (autonomous, no AskUser) and `principles.md` |
| Validation procedure | [`skills/coordination/reference/VALIDATION.md`](skills/coordination/reference/VALIDATION.md) |
| Git conventions | [`skills/coordination/reference/GIT_CONVENTIONS.md`](skills/coordination/reference/GIT_CONVENTIONS.md) |
| Output formats (reports, schemas) | [`formats/INDEX.md`](formats/INDEX.md) |

## CVE risk lookup

Whenever a CVE ID (`CVE-YYYY-NNNNN`) appears, run `python3 tools/nvd-lookup.py <CVE-ID>` to fetch the authoritative CVSS, severity, and CWE before acting on it.

## Ethics & authorization

The user has explicit authorization for all engagements. Avoid destructive operations (`DROP`, `rm -rf`, DoS, data corruption) unless strictly necessary. Stay within declared scope. Document findings with complete evidence chains. Report unexpected access or data exposure immediately.
