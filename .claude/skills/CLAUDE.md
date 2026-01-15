# Skills Development Guide

This file is automatically loaded when working with skills in this directory.

## Skill Structure

IMPORTANT: Every skill MUST have this structure:

```
skill-name/
├── SKILL.md          # YAML frontmatter + description
├── README.md         # User-facing documentation
├── CLAUDE.md         # (Optional) Skill-specific context
├── agents/           # Agent definitions (.md files)
├── tools/            # Python tools (if needed)
│   └── __init__.py
└── outputs/          # Test outputs and reports
    └── .gitkeep
```

## File Requirements

**SKILL.md format:**
```markdown
---
name: skill-name
description: One-line description of what this skill does
---

# Skill Name

Detailed description and documentation...
```

**Naming conventions:**
- Skill directories: `lowercase_with_underscores`
- Agent files: `lowercase-with-hyphens.md`
- Follow existing patterns in the repo

## Available Skills

Current skills in this repo:
- `pentest` - Comprehensive penetration testing with 40+ attack types
- `common-appsec-patterns` - Common web app vulnerabilities (XSS, SQLi, SSRF, etc.)
- `cve-testing` - CVE vulnerability testing and exploitation
- `domain-assessment` - Domain recon and attack surface mapping
- `web-application-mapping` - Web app discovery and enumeration
- `bugbounty` - Bug bounty hunting workflows

## Contributing Workflow

Use the automation agents (in `.claude/agents/`) to help with the workflow:

1. **Create issue** - Use `git-issue-creator` agent or `gh issue create`
2. **Create branch** - Use `git-branch-manager` agent
3. **Generate structure** - Use `skill-generator` agent or copy from `templates/skill_template/`
4. **Develop** - Add agents, tools, and documentation
5. **Create PR** - Use `git-pr-creator` agent

IMPORTANT: Always create the GitHub issue BEFORE starting work on a new skill.

## Agent Development

Agents are markdown files that define specialized testing workflows.

**Agent file structure:**
```markdown
# Agent Name

Brief description of what this agent does.

## Core Responsibilities

- Responsibility 1
- Responsibility 2

## Methodology

Step-by-step approach...

## Tools & Techniques

List of tools, payloads, techniques...
```

See existing agents in each skill's `agents/` directory for examples.

## Testing Skills

Skills are tested by:
1. Invoking them in Claude Code sessions: `/skill-name`
2. Running agents through the Task tool with appropriate subagent_type
3. Validating outputs in the `outputs/` directory
