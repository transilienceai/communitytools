# Skiller

Generate Claude Code skills following Anthropic best practices.

## Core Rules

**Brevity First**: Every file MUST be short, simple, human-readable.
- SKILL.md: < 150 lines 
- Agent MD: < 150 lines 
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
- Agent MD: HOW to do it (workflow, tools, execution)

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
- ❌ Files > 150 lines (SKILL.md, Agent MD)
- ❌ Files > 200 lines (reference/)
- ❌ Verbose templates and examples inline

## Workflow

1. **Gather**: name, description, 3-5 features
2. **Create**: SKILL.md (< 150 lines), README.md (< 100 lines)
3. **Validate**: wc -l SKILL.md (must show < 150)
4. **Test**: 3+ scenarios
5. **Fix**: If too long, split into reference/
