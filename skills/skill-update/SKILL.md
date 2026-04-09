---
name: skill-update
description: Skill creation, update and management — generates skill directory structure, validates against best practices, enforces line count limits. Use when creating, updating, or improving skills.
model: opus
---

# Skill Update

Generate Claude Code skills following Anthropic best practices.

## Core Rules

**Brevity First**: Every file MUST be short, simple, human-readable.
- SKILL.md: < 150 lines 
- Role prompt files: < 200 lines
- README.md: < 100 lines
- Reference files: < 200 lines each

**Challenge every token**. If it's not essential, delete it.

## Quick Start

```
1. Read this file
2. Gather: name, description, 3-5 features
3. Create: SKILL.md (< 150 lines), README.md (< 100 lines)
4. Validate: wc -l SKILL.md (must be < 150)
```

## Principles

**Concise**: Only context Claude doesn't have. Link to reference/ for details.

**Progressive disclosure**: Main files < 150 lines. Details in reference/.

**Separation**:
- SKILL.md: WHAT to do (techniques, checklists, indexes)
- Role prompt files in `reference/`: HOW agents should behave when spawned

## File Structure

```
.claude/skills/skill-name/
├── SKILL.md          # < 150 lines, YAML + instructions
├── README.md         # < 100 lines, user docs
├── reference/        # Details, < 200 lines each
└── outputs/.gitkeep
```

## SKILL.md Template

```yaml
---
name: skill-name
description: What it does AND when to use. Include triggers. < 1024 chars.
---

# Skill Name

Quick start (< 20 lines)

## Key Workflows

Workflow 1 (< 30 lines)
Workflow 2 (< 30 lines)

## Reference

- [Details](reference/) - Move detailed content here

## Critical Rules

- Rule 1
- Rule 2
```

**Total**: < 150 lines

## Validation

```bash
# Check line count (CRITICAL)
wc -l SKILL.md  # MUST be < 150
wc -l README.md # MUST be < 100

# Check frontmatter
head -n 1 SKILL.md | grep -q "^---$"

# Check files exist
test -f SKILL.md README.md
```

**If files > limit**: Split into reference/ files immediately.

## Common Mistakes

**TOO LONG** (most common):
- ❌ Verbose explanations
- ❌ Multiple examples inline
- ❌ Detailed templates in main file
- ❌ Step-by-step workflows with 50+ lines

**Fix**: Move details to reference/, keep main file < 150 lines.

**TOO COMPLEX**:
- ❌ Nested references
- ❌ Over-explaining simple concepts
- ❌ Multiple conditional workflows

**Fix**: Simplify, assume Claude is smart, provide defaults.

## Reference

See reference/ for:
- [STRUCTURE.md](reference/STRUCTURE.md) - Directory requirements
- [FRONTMATTER.md](reference/FRONTMATTER.md) - YAML rules
- [CONTENT.md](reference/CONTENT.md) - Writing guidelines

**Official**: https://www.anthropic.com/engineering/claude-code-best-practices

## Anti-Patterns

- ❌ Creating CHANGELOG.md, SUMMARY.md, VERIFICATION.md
- ❌ Meta-documentation about creation process
- ❌ Files > 150 lines (SKILL.md)
- ❌ Files > 200 lines (reference/)
- ❌ Verbose templates and examples inline

## Workflow

1. **Gather**: name, description, 3-5 features
2. **Create**: SKILL.md (< 150 lines), README.md (< 100 lines)
3. **Validate**: wc -l SKILL.md (must show < 150)
4. **Test**: 3+ scenarios
5. **Fix**: If too long, split into reference/

## How to update skills
When updating skills, process all activities done previously. Any successful techniques, failed attempts, and key discoveries and evaluate whether to update to the pentest skills, agent behavior, or reference files.
Update if: 
1. Represent generalizable attack patterns or techniques (not specific to this target) that is not mentioned in the files
2. Materially improve efficiency, coverage, or decision-making for future engagements
3. Are not already adequately captured in existing skill/agent/reference files
Strict constraints:
* No target-specific data: Do not include machine names, challenge names, hostnames, IPs, flags, or any identifiers tied to this specific engagement
* No clutter: Do not pad files with marginal or redundant information. If existing content already covers a technique sufficiently, skip it
* Generalize everything: Frame all updates as reusable patterns — e.g., "when encountering X condition, try Y approach" rather than "on this box, Y worked"
* Minimal footprint: Prefer updating existing entries over adding new ones. Keep skills/agents/reference files lean and high-signal
Output: Provide a concise change report structured as:
* Updated: What changed and why (file + summary of edit)
* Skipped: Notable findings that were intentionally not added, with brief reasoning
* No changes: If nothing warranted an update, state that explicitly
