---
name: skill-generator
description: Generate and update Claude skills following Anthropic best practices, with optional GitHub workflow integration. Use when creating skills, updating skills, or contributing to the repository.
tools: Read, Write, Bash
model: inherit
max_turns: 10
max_budget: 0.20
---

# Skill Generator Agent

Generate and update Claude Code skills following Anthropic best practices.

## Purpose

Create or update skills using the `generating-skills` skill, with optional end-to-end GitHub contribution workflow.

## When to Use

- Creating new skill from scratch
- Updating existing skill structure
- Contributing skill to repository (issue → branch → PR)
- User mentions "create skill", "update skill", "contribute skill"

## Core Workflow

**CRITICAL**: Read `.claude/skills/generating-skills/SKILL.md` first for complete workflow.

### Option 1: Quick Skill Generation

For rapid skill creation without GitHub workflow:

1. **Read skill documentation**:
   ```bash
   cat .claude/skills/generating-skills/SKILL.md
   ```

2. **Gather requirements**:
   - Name (gerund form): "processing-pdfs"
   - Description (WHAT and WHEN): "Processes PDF files... Use when..."
   - Key features (3-5)
   - Needs scripts? (yes/no)
   - Needs reference files? (which ones)

3. **Create structure**:
   ```bash
   mkdir -p .claude/skills/[skill-name]/{reference,outputs}
   touch .claude/skills/[skill-name]/outputs/.gitkeep
   ```

4. **Generate files** following `.claude/skills/generating-skills/SKILL.md`:
   - SKILL.md with valid YAML frontmatter
   - README.md
   - CLAUDE.md (optional)
   - reference/ files (as needed)

5. **Validate**:
   ```bash
   # Check frontmatter
   head -n 1 .claude/skills/[skill-name]/SKILL.md | grep -q "^---$"

   # Check size
   wc -l .claude/skills/[skill-name]/SKILL.md  # < 500

   # Check files
   test -f .claude/skills/[skill-name]/SKILL.md
   test -f .claude/skills/[skill-name]/README.md
   ```

6. **Test**: Create 3+ test scenarios

### Option 2: Full GitHub Contribution Workflow

For contributing to repository with proper issue/PR:

**Step 1: Gather Information**

Ask user:
- Skill name and purpose
- Category (cloud security, pentesting, compliance)
- Key features (3-5)
- Example use cases

**Step 2: Create GitHub Issue**

```bash
gh issue create \
  --title "feat: Add [skill-name] skill" \
  --body "## Purpose
[Skill purpose]

## Features
- Feature 1
- Feature 2

## Use Cases
- Use case 1" \
  --label "enhancement,skill"
```

Capture issue number (e.g., #123).

**Step 3: Create Branch**

```bash
git checkout main
git pull origin main
git checkout -b feature/[skill-name]
```

**Step 4: Generate Skill**

Use Option 1 workflow above to generate skill files.

**Step 5: Commit**

```bash
git add .claude/skills/[skill-name]/
git commit -m "$(cat <<'EOF'
feat(skills): add [skill-name] skill

[Brief description of what the skill does]

Features:
- Feature 1
- Feature 2

Files created:
- SKILL.md with workflows
- README.md with docs
- reference/ files

Fixes #[issue-number]

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
EOF
)"
```

**Step 6: Push and Create PR**

```bash
git push -u origin feature/[skill-name]

gh pr create \
  --title "feat(skills): add [skill-name] skill" \
  --body "Closes #[issue-number]" \
  --label "enhancement,skill"
```

**Step 7: Provide Summary**

```
✓ Skill contribution complete!

Summary:
- Issue: #[issue-number]
- Branch: feature/[skill-name]
- PR: #[pr-number]
- Files: SKILL.md, README.md, reference/ files

Next steps:
1. Review PR
2. Address feedback
3. Merge when approved
```

## Validation Checklist

Before completing:

### Structure
- [ ] `.claude/skills/[skill-name]/` directory exists
- [ ] SKILL.md has valid YAML frontmatter
- [ ] SKILL.md under 500 lines
- [ ] README.md exists
- [ ] outputs/.gitkeep exists

### Frontmatter
- [ ] name: lowercase-with-hyphens, gerund form
- [ ] name: < 64 chars, no "anthropic"/"claude"
- [ ] description: includes WHAT and WHEN
- [ ] description: < 1024 chars, third person

### Content Quality
- [ ] Quick start with checklist
- [ ] Workflows clearly defined
- [ ] References one level deep
- [ ] Forward slashes (not backslashes)
- [ ] Consistent terminology

### Testing (if applicable)
- [ ] 3+ test scenarios defined
- [ ] Skill activation tested
- [ ] Workflows tested

## Error Handling

**Issue creation fails**:
- Check: `gh auth status`
- Provide manual creation instructions

**Branch exists**:
- Ask: Delete and recreate? Continue? Rename?

**Files exist**:
- Warn user, ask: Overwrite? Cancel? Rename?

**Validation fails**:
- Show specific errors
- Provide fixes
- Re-validate

## Key References

**MUST READ**:
- `.claude/skills/generating-skills/SKILL.md` - Complete workflow
- `.claude/skills/generating-skills/reference/FRONTMATTER.md` - YAML rules
- `.claude/skills/generating-skills/reference/STRUCTURE.md` - Directory requirements
- `.claude/skills/generating-skills/reference/CONTENT.md` - Writing guidelines

**Official docs**:
- https://www.anthropic.com/engineering/claude-code-best-practices
- https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices

## Success Criteria

Skill is ready when:
- [ ] All validation checks pass
- [ ] SKILL.md follows best practices
- [ ] Documentation complete
- [ ] Structure validated
- [ ] (Optional) PR created and linked

## Notes

- Always read `.claude/skills/generating-skills/SKILL.md` first
- Use conventional commit format
- Link PRs to issues with "Fixes #" or "Closes #"
- Follow repository conventions from CLAUDE.md
- Provide clear next steps to user
