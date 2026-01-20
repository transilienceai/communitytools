# Skiller

Generate Claude Code skills following Anthropic best practices.

## Quick Start

```
Skill Generation:
- [ ] Design structure (naming, organization)
- [ ] Create directory and files
- [ ] Write SKILL.md with frontmatter
- [ ] Add README
- [ ] Validate structure
- [ ] Test with real scenarios
```

## Core Principles

**Concise**: Only add context Claude doesn't have. Challenge every token.

**Progressive disclosure**: SKILL.md < 500 lines. Link to reference files for details.

**Degrees of freedom**:
- High (text): Multiple valid approaches
- Medium (templates): Preferred patterns
- Low (scripts): Exact operations

## Workflow

### 1. Design Structure

**Naming** (gerund form):
- ✓ `processing-pdfs`, `analyzing-data`, `testing-code`
- ✗ `helper`, `utils`, names with "anthropic"/"claude"

**Organization**:
- SKILL.md: Overview, quick start, workflows
- reference/: Detailed docs, examples, advanced topics
- Multi-domain? Organize by domain (finance.md, sales.md)

See [STRUCTURE.md](reference/STRUCTURE.md)

### 2. Create Files

**Required**:
```
.claude/skills/skill-name/
├── SKILL.md          # YAML + instructions
├── README.md         # User docs
└── outputs/.gitkeep  # Test outputs
```

**Optional**:
- CLAUDE.md - Auto-loaded context
- reference/ - Progressive disclosure files
- tools/ - Python utilities (needs __init__.py)

### 3. Write SKILL.md

**Frontmatter**:
```yaml
---
name: skill-name
description: What it does AND when to use it. Include key terms and triggers.
---
```

**Rules**:
- name: 64 chars max, lowercase-with-hyphens, no "anthropic"/"claude"
- description: 1024 chars max, third person, include WHAT and WHEN

See [FRONTMATTER.md](reference/FRONTMATTER.md)

**Body structure**:
1. Quick start (most common use case)
2. Workflows with checklists
3. Common patterns
4. Reference links
5. Troubleshooting

See [CONTENT.md](reference/CONTENT.md)

### 4. Add Documentation

**README.md**: Overview, installation, examples, links

**CLAUDE.md** (optional): Context for working in skill directory

### 5. Validate

```bash
# Check frontmatter
head -n 1 SKILL.md | grep -q "^---$"

# Check size
wc -l SKILL.md  # Should be < 500

# Check required files
test -f SKILL.md README.md
```

**Checklist**:
- [ ] Valid YAML frontmatter
- [ ] Required files present
- [ ] References one level deep
- [ ] Forward slashes (not backslashes)
- [ ] SKILL.md under 500 lines
- [ ] Consistent terminology

### 6. Test

**Create 3+ scenarios**:
1. Does description trigger correctly?
2. Does Claude follow workflows?
3. Works with target models?

**Observe**:
- File read order
- Reference following
- Content usage
- Skill activation

## Updating Skills

1. Use in real tasks
2. Observe behavior
3. Identify improvements
4. Make targeted changes
5. Test and iterate

**Common fixes**:
- Make critical info more prominent
- Use stronger language ("MUST" vs "always")
- Add missing workflows
- Split large files
- Improve description triggers

## Common Patterns

### Workflows with Checklists
```markdown
Copy this checklist:
\`\`\`
Progress:
- [ ] Step 1: Action
- [ ] Step 2: Action
\`\`\`

**Step 1**: Instructions

**Step 2**: Instructions
```

### Validation Feedback Loop
```markdown
1. Create output
2. **Validate**: `python validate.py output.json`
3. If fails: fix and re-validate
4. **Only proceed when passes**
```

### Progressive Disclosure
```markdown
## Quick Start
[20 lines here]

## Advanced
See [ADVANCED.md](reference/ADVANCED.md) for:
- Feature 1
- Feature 2
```

### Conditional Workflow
```markdown
**Creating new?** → Follow creation workflow
**Editing existing?** → Follow editing workflow
```

## Anti-Patterns

- Too many options (provide default with escape hatch)
- Punting to Claude (scripts should handle errors)
- Vague naming ("helper", "utils")
- Nested references (keep one level deep)
- Over-explaining (assume Claude is smart)
- Time-sensitive content (use "old patterns" section)
- Inconsistent terminology (choose one term)

## Reference

**Guides**:
- [STRUCTURE.md](reference/STRUCTURE.md) - Directory requirements
- [FRONTMATTER.md](reference/FRONTMATTER.md) - YAML rules
- [CONTENT.md](reference/CONTENT.md) - Writing guidelines

**Official**:
- [Claude Code Best Practices](https://www.anthropic.com/engineering/claude-code-best-practices)
- [Agent Skills Best Practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)

## Troubleshooting

**Skill not activating**: Add specific triggers and key terms to description

**Claude ignoring files**: Make references more prominent, use descriptive names

**Context overflow**: Split SKILL.md into reference files

**Inconsistent behavior**: Add more structure, provide defaults

**Scripts failing**: Handle errors explicitly, helpful messages
