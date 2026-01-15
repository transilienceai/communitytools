# Generating Skills - Claude Context

Context for working with the generating-skills skill.

## Purpose

Generate and update Claude Code skills following Anthropic best practices.

## Key Files

- **SKILL.md** - Main workflow (216 lines)
- **README.md** - User docs
- **reference/FRONTMATTER.md** - YAML rules
- **reference/STRUCTURE.md** - Directory requirements
- **reference/CONTENT.md** - Writing guidelines

## Critical Rules

**Name**: 64 chars, lowercase-with-hyphens, gerund form, no "anthropic"/"claude"

**Description**: 1024 chars, third person, include WHAT and WHEN, key terms

**Structure**: SKILL.md < 500 lines, references one level deep, forward slashes

**Content**: Concise, progressive disclosure, workflows with checklists

## Common Tasks

**Create skill**: Follow SKILL.md workflow, use generating-skills skill

**Validate**: Check frontmatter, files, size, references, terminology

**Update skill**: Observe behavior, identify gaps, make targeted changes

**Test**: 3+ scenarios, check activation, test with models

## Quick Reference

**Skill location**: `.claude/skills/[skill-name]/`

**Agent**: `.claude/agents/skill-generator.md`

**Best practices**:
- https://www.anthropic.com/engineering/claude-code-best-practices
- https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices

## Workflow Summary

1. Design structure (naming, organization)
2. Create directory and files
3. Write SKILL.md with frontmatter
4. Add README
5. Validate structure
6. Test with real scenarios
