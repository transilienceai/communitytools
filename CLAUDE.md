# Community Security Tools Repository

This repo provides Claude Code skills and agents for security testing, bug bounty hunting, and pentesting workflows.

## Repository Structure

- `.claude/skills/` - Security testing skills (pentest, cve-testing, domain-assessment, etc.)
- `.claude/agents/` - Workflow automation agents (contribute-skill, git-issue-creator, etc.)
- `.claude/commands/` - Slash commands for common tasks
- `templates/` - Skill templates and GitHub templates

## Git Conventions

IMPORTANT: Always follow these git workflows:

**Branches:**
- Create from main: `feature/skill-name`, `bugfix/description`, `docs/update`
- NEVER commit directly to main

**Commits:**
- Format: `type(scope): description`
- Types: feat, fix, docs, refactor, test, chore
- Example: `feat(pentest): add JWT testing agent`

**Pull Requests:**
- MUST link to issue: "Fixes #123" or "Closes #123"
- Create issue BEFORE starting work
- Use PR template in `.github/pull_request_template.md`

## Common Workflows

**Contributing a new skill (Recommended - Using /skiller):**
```bash
# Easy way: Use the /skiller slash command
/skiller
# Then select: CREATE → provide details → choose GitHub workflow
# This automates: issue creation, branch, skill generation, validation, commit, PR
```

**Contributing a new skill (Manual):**
```bash
# 1. Create issue first (using gh or GitHub UI)
gh issue create --title "Add skill: X" --body "Description..."

# 2. Create branch
git checkout -b feature/skill-name

# 3. Use skill scaffolding tools in templates/ or /skiller command
# 4. Commit with conventional format
# 5. Push and create PR linking to issue
```

**Testing changes:**
```bash
# The skills are used directly by Claude Code
# Test by invoking the skill in a Claude session
```

## Output Standards

**CRITICAL**: All skills follow standardized output formats.

See `.claude/OUTPUT_STANDARDS.md` for complete specification.

**Three formats**:
- **Reconnaissance**: inventory/ + analysis/ → testing checklist
- **Vulnerability testing**: findings/ + evidence/ → actionable reports
- **Bug bounty**: Platform-ready submissions (HackerOne, Bugcrowd)

## Critical Rules

IMPORTANT: When working with security testing skills:
- All testing MUST be authorized and legal
- Never perform destructive operations
- Always document findings using standardized formats (see OUTPUT_STANDARDS.md)
- Follow responsible disclosure practices
- Generate complete evidence (screenshots, HTTP captures, videos)
- Create actionable reports with remediation guidance

IMPORTANT: Skill structure requirements are in `.claude/skills/CLAUDE.md` (auto-loaded when working in that directory)
