---
name: skill-update
description: Skill creation, update and management — generates skill directory structure, validates against best practices, enforces line count limits. Use when creating, updating, or improving skills.
model: opus
---

# Skill Update

Generate or refine Claude Code skills following Anthropic best practices.

## Hard caps (enforced by `scripts/skill_linter.py`)

- `SKILL.md` ≤ 150 lines
- `reference/*.md` ≤ 200 lines (`reference/scenarios/*.md` ≤ 400 lines)
- `README.md` ≤ 100 lines
- Every `SKILL.md` has YAML frontmatter with `name` + `description`
- No `DO NOT` / `MUST NOT` / `NEVER` outside an `## Anti-Patterns` section
- No challenge-specific identifiers (machine names, lab IDs, lab IPs, preserved flags)
- Every `[link](path)` resolves
- Every reference file is linked from at least one other file (no orphans)

## Principles

- **Brevity first.** Every file short, simple, human-readable. Challenge every token.
- **Progressive disclosure.** SKILL.md navigates; `reference/` holds detail; `reference/scenarios/` holds concrete exploit flows.
- **Separation of concern.** SKILL.md = WHAT + when. `reference/role-*.md` = HOW agents behave when spawned.
- **Single canonical home** for any cross-cutting rule (output discipline, credential loading, brute-force, etc.). Other files reference, never restate.

## File structure

```
skills/<skill-name>/
├── SKILL.md           # ≤150 lines, YAML + navigation
├── reference/
│   ├── *-principles.md  # ≤150 lines (decision tree)
│   ├── INDEX.md
│   ├── *.md             # patterns, ≤200 lines
│   └── scenarios/
│       └── <category>/
│           └── *.md     # ≤400 lines, self-contained
└── README.md          # optional, ≤100 lines
```

## SKILL.md template

```yaml
---
name: <skill-name>
description: What it does AND when to use. Include trigger phrases.
---

# <Skill Name>

<one-paragraph scope>

## When to use

- <bullet>

## Workflow / Quick start

<≤30 lines>

## References

- [reference/...](reference/...)

## Anti-Patterns

- <when negative framing is genuinely needed, put it here>
```

## When to update an existing skill

Process the techniques and failure modes from completed engagements. Promote a learning to the skill base only if **all four** hold:

1. **Generalizable.** Reusable pattern, not target-specific lore. No machine names, lab IDs, target IPs, preserved flags, writeup attributions.
2. **Material improvement.** Adds coverage, efficiency, or decision-quality for future engagements.
3. **Not already captured** elsewhere in the skill base. (`scripts/skill_linter.py` flags duplicates.)
4. **Minimal footprint.** Prefer extending an existing entry over adding a new file. Keep the base lean and high-signal.

## Reframing recipe

Always frame as a reusable pattern: *"when encountering X condition, try Y approach"* — never *"on box-N, Y worked"*. Use `<TARGET_IP>`, `<DC_FQDN>`, `<DOMAIN>` placeholders in tool examples.

## Pre-write check

Before writing, run `python3 scripts/skill_linter.py`. Reject any change that:
- Re-introduces challenge-specific lore.
- Pushes a `SKILL.md` past 150 or a reference past its cap.
- Duplicates a single-owner rule (brute-force, output discipline, env-reader).
- Adds `DO NOT` / `MUST NOT` / `NEVER` outside an Anti-Patterns block.

## Output

Concise change report:
- **Updated.** File + one-line summary of edit.
- **Skipped.** Notable findings intentionally not added, with brief reasoning.
- **No changes.** State explicitly when nothing warranted an update.

## Reference

- [STRUCTURE.md](reference/STRUCTURE.md) — directory layout requirements.
- [FRONTMATTER.md](reference/FRONTMATTER.md) — YAML rules.
- [CONTENT.md](reference/CONTENT.md) — writing guidelines.

## Anti-Patterns

- Creating CHANGELOG.md / SUMMARY.md / VERIFICATION.md auxiliary files.
- Meta-documentation about the creation process inside the skill itself.
- Verbose inline templates and examples (link to `reference/` instead).
- Re-introducing duplicate rule prose (brute-force, output-dir, env-reader).
- Files past their cap — split into `reference/` immediately.
