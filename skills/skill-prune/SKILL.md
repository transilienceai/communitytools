---
name: skill-prune
description: Identify and remove negative-ROI skill content — orphan files, never-read entries, duplicates, content reintroducing challenge-specific lore. Inverse of /skill-update. Use during quarterly maintenance or after the linter flags issues.
---

# Skill Prune

Inverse of `/skill-update`. Removes content rather than adding it. Run during quarterly maintenance, after engagements, or when `scripts/skill_linter.py` reports orphans / duplicates.

## When to invoke

- Quarterly cadence (`scripts/quarterly_refactor.md`).
- After `scripts/skill_linter.py --check-orphans` reports orphan reference files.
- After a SKILL.md or reference file grows past its cap and needs trimming.
- After a de-specialization sweep, to drop content tied to retired challenges.

## Prune criteria (the four signals — same shape as /skill-update, inverted)

A reference / scenario / line is a **prune candidate** when it satisfies any of:

1. **Orphan** — not linked from any SKILL.md or other reference file in the last 60 days.
2. **Referenced only by failed engagements** — appeared in `attack-chain.md` of runs that ended `status=BLOCKED`, never in a successful chain.
3. **Contradicted by newer content** — a later scenario / pattern supersedes it; the older entry no longer reflects current technique.
4. **Redundant with newer content** — same technique covered more clearly elsewhere.

Removing content fails any of these → keep it.

## Safety rules

- **Never** prune a file with `<!-- KEEP: <reason> -->` annotation.
- **Never** prune content cited in a still-open engagement's `OUTPUT_DIR/attack-chain.md`.
- **Never** prune the canonical-home file for a single-owner rule (brute-force, output-discipline, env-reader, skill-update).
- Bias toward keeping technique-rich content over operational lore.

## Procedure

1. Run `scripts/skill_linter.py --check-orphans` to surface orphans.
2. For each candidate file or block, evaluate the four signals.
3. Build a deletion plan — show files / lines to remove with one-line rationale per item.
4. Apply deletions only after the plan is approved (skill-prune does not auto-delete during invocation).
5. Re-run `scripts/skill_linter.py` to confirm the change broke no other links and didn't reintroduce duplicates.

## Output

Concise change report:

- **Removed.** File or block + one-line rationale per item.
- **Kept (flagged for follow-up).** Items that failed all four signals but are worth revisiting next quarter.
- **No prunes.** State explicitly when nothing warranted removal.

## Anti-Patterns

- Pruning content because it's old — age alone is not a signal; relevance is.
- Pruning a reference because its parent SKILL.md is bloated — fix the SKILL.md instead.
- Removing a single-owner canonical file (brute-force / output-discipline / env-reader).
- Pruning during an active engagement that may still cite the content.
