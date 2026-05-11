## Summary

<!-- Brief description of what this PR does. 1-3 sentences. -->

## Related Issue

<!-- REQUIRED: Link the issue this PR addresses. PRs without a linked issue will not be merged. -->

Closes #

## Changes Made

<!-- Bullet list of specific changes. -->

-

## Type of Change

<!-- Check all that apply. -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New skill or agent
- [ ] Enhancement to existing skill/agent
- [ ] Documentation update
- [ ] CI/CD or infrastructure
- [ ] Refactoring (no functional change)
- [ ] Other: <!-- describe -->

## Testing

<!-- How did you verify this works? -->

- [ ] Tested skill/agent in Claude Code session
- [ ] Tested against vulnerable application (DVWA, WebGoat, Juice Shop, etc.)
- [ ] Verified no false positives
- [ ] Ran existing tests (`python -m pytest tests/`)
- [ ] Manual review only (documentation/config changes)

**Test details:**

<!-- Describe what you tested and the results. -->

## Checklist

- [ ] My code follows the [contribution guidelines](../CONTRIBUTING.md)
- [ ] Commits use conventional format: `type(scope): description`
- [ ] I've updated documentation where needed
- [ ] New skills include `SKILL.md` and `reference/` directory
- [ ] No secrets, credentials, or unauthorized target information included
- [ ] This PR links to an issue with `Closes #N`

## Skill / agent checklist (if PR touches `skills/`)

- [ ] `python3 scripts/skill_linter.py` runs clean (or rationale below).
- [ ] No new challenge-specific identifiers outside `skills/hackthebox/` (no machine names, no XBEN/Vulnlab IDs, no preserved `FLAG{...}` literals, no lab IPs).
- [ ] `SKILL.md` ≤ 150 lines; `reference/*.md` ≤ 200 lines; `reference/scenarios/*.md` ≤ 400 lines.
- [ ] No new `DO NOT` / `MUST NOT` / `NEVER` outside `## Anti-Patterns` (unless file is in linter's hard-contract allowlist).
- [ ] Cross-cutting rules (brute-force, output-discipline, env-reader, skill-update) live in exactly one canonical home; other files reference it.
- [ ] If removing content, ran `/skill-prune` to confirm negative ROI.

## Screenshots / Evidence

<!-- If applicable, add screenshots, logs, or output samples. -->
