# Generating Skills - Claude Context

Auto-loaded context when working with the generating-skills skill.

## Purpose

Help developers create and update Claude Code skills following official Anthropic best practices.

## Key Files

- **SKILL.md** - Main skill instructions with complete workflow
- **README.md** - User-facing documentation
- **reference/FRONTMATTER.md** - YAML frontmatter rules and examples
- **reference/STRUCTURE.md** - Directory structure requirements
- **reference/CONTENT.md** - Content writing guidelines
- **reference/BEST-PRACTICES.md** - Complete best practices guide

## When Working on Skills

**Creating new skills**:
1. Follow the workflow in SKILL.md step by step
2. Reference FRONTMATTER.md for YAML rules
3. Use STRUCTURE.md for directory organization
4. Apply CONTENT.md guidelines for writing
5. Validate against checklists

**Updating existing skills**:
1. Read current skill files
2. Check against best practices
3. Identify gaps or issues
4. Make targeted improvements
5. Validate changes

## Critical Rules

**Name validation**:
- 64 characters max
- lowercase-with-hyphens
- Gerund form preferred: "processing-pdfs"
- No "anthropic" or "claude"

**Description requirements**:
- 1024 characters max
- Include WHAT and WHEN
- Third person only
- Key terms and triggers

**Structure rules**:
- SKILL.md under 500 lines
- References one level deep
- Use forward slashes (not backslashes)
- Required files: SKILL.md, README.md, tools/__init__.py, outputs/.gitkeep

**Content principles**:
- Concise is key (challenge every token)
- Assume Claude is smart
- Progressive disclosure for details
- Workflows always have checklists
- Set appropriate degrees of freedom

## Common Tasks

**Validate a skill structure**:
→ Check SKILL.md frontmatter, file structure, reference depth

**Check SKILL.md length**:
→ `wc -l .claude/skills/[skill-name]/SKILL.md` (should be < 500)

**Verify required files**:
→ SKILL.md, README.md, tools/__init__.py, outputs/.gitkeep

**Test skill activation**:
→ Create test scenarios with expected triggers

## Quick Reference

**Best practice docs**:
- https://www.anthropic.com/engineering/claude-code-best-practices
- https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices

**Skill location**:
- `.claude/skills/[skill-name]/`

**Agent location**:
- `.claude/agents/skill-generator.md`

## Development Workflow

1. Design skill structure
2. Generate directory and files
3. Write SKILL.md following templates
4. Create reference files
5. Validate structure
6. Test with real scenarios
7. Iterate based on observations
