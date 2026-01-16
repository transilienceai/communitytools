# Workflow Automation Agents

This file is automatically loaded when working with automation agents.

## Available Agents

**Skill contribution workflow:**
- `contribute-skill.md` - Main orchestrator for contributing new skills
- `git-issue-creator.md` - Create GitHub issues with proper templates
- `git-branch-manager.md` - Branch creation and management
- `git-pr-creator.md` - Create pull requests with proper linking
- `skiller.md` - Generate skill directory structure

**Security testing agents:**
- `pentester.md` - Universal penetration testing orchestrator
- `hackerone-bounty-hunter.md` - Bug bounty hunting automation
- `specialized/` - 30+ specialized vulnerability testing agents

## Agent Usage

Agents are invoked through the Task tool with appropriate `subagent_type`:

```typescript
Task(
  subagent_type: "contribute-skill",
  prompt: "Help user create a new skill",
  description: "Create new skill"
)
```

## Agent Development

When creating or modifying agents:

1. **Keep it focused** - Each agent should do one thing well
2. **Clear responsibilities** - Document what the agent does and doesn't do
3. **Explicit tools** - List available tools in the agent definition
4. **Error handling** - Provide clear guidance for common errors
5. **Examples** - Include usage examples when helpful

## Agent Structure

```markdown
# Agent Name

One-line description.

## When to Use

- Scenario 1
- Scenario 2

## Core Responsibilities

- What this agent does
- What it doesn't do

## Workflow

Step-by-step process...

## Tools Available

List of tools this agent can use...
```

IMPORTANT: Keep agents concise. Long procedural documentation should go in README files or skill documentation, not agent definitions.
