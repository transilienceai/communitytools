# Community Security Tools Repository

This repo provides Claude Code skills and agents for security testing, bug bounty hunting, and pentesting workflows.

## Architecture: AGENTS.md + Skills

**IMPORTANT**: Based on Vercel research, this repository uses a hybrid architecture:

**AGENTS.md** (`/AGENTS.md` in root):
- **Passive context** - Always loaded, available in every conversation turn
- **100% pass rate** in Vercel agent evals (vs 53-79% for skills alone)
- Contains compressed security testing knowledge (80% reduction: ~40KB → ~8KB)
- Pipe-delimited indexing: `Vulnerability|Payloads|Details|Reference`
- "Prefer retrieval-led reasoning" directive for security tasks
- Includes: Vulnerability payloads, methodologies (PTES, OWASP, MITRE), CVSS scoring, PoC standards

**Skills** (`.claude/skills/`):
- **User-triggered workflows** - Invoked explicitly with `/skill-name`
- Orchestration and coordination (parallel agents, aggregation, reporting)
- Complex multi-step processes with checkpointing
- User preference gathering and decision workflows
- Examples: `/pentest`, `/hackerone`, `/authenticating`

**Why this works better**:
- Eliminates decision-making friction (no "should I load the skill?" question)
- Consistent availability (AGENTS.md always present, skills loaded on-demand)
- No sequencing problems (passive knowledge + explicit workflows)
- Faster context access (no async skill loading delay)

**Reference**: [Vercel Blog - AGENTS.md outperforms skills in our agent evals](https://vercel.com/blog/agents-md-outperforms-skills-in-our-agent-evals)

## Repository Structure

- `AGENTS.md` - **Passive security testing knowledge base** (always loaded)
- `.claude/skills/` - **Workflow orchestration skills** (user-triggered)
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

**AGENTS.md vs Skills Decision** (for contributors):

**Add to AGENTS.md when:**
- General framework/library knowledge (APIs, patterns)
- Frequently referenced information (payloads, scoring, mappings)
- Methodology frameworks (PTES, OWASP, MITRE ATT&CK)
- Quick reference data that doesn't require user action
- Content that benefits from always being available

**Create a Skill when:**
- Multi-step workflow orchestration (parallel agents, aggregation)
- User-triggered explicit actions (/pentest, /hackerone)
- Complex processes with checkpointing
- User preference gathering (AskUserQuestion patterns)
- Task coordination requiring state management

**Compression Guidelines**:
- Aim for 80% reduction in AGENTS.md content
- Use pipe-delimited indexing: `Topic|Key Info|Details|Reference Path`
- Keep critical info inline, link to detailed documentation
- Example: `SQL Injection|Union: ' UNION SELECT|Time: SLEEP(5)|.claude/skills/pentest/attacks/injection/sql-injection/`

**Security Testing Rules**:
- All testing MUST be authorized and legal
- Never perform destructive operations
- Always document findings using standardized formats (see OUTPUT_STANDARDS.md)
- Follow responsible disclosure practices
- Generate complete evidence (screenshots, HTTP captures, videos)
- Create actionable reports with remediation guidance

**Skill Structure**: Requirements are in `.claude/skills/CLAUDE.md` (auto-loaded when working in that directory)
