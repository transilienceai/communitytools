# Slash Commands

Slash commands are shortcuts that users can type to invoke common workflows. When a user types `/command-name`, Claude Code expands it to the full skill prompt.

## Available Commands

**Git Workflows:**
- `/commit` - Generate conventional commit and create commit
- `/push` - Stage, commit, and push in one workflow
- `/branch` - Create new branch with conventional naming
- `/pr` - Create pull request with auto-generated description
- `/merge` - Merge pull request and cleanup branches

**Development:**
- `/test` - Run tests and auto-fix failures
- `/lint` - Run linter and auto-fix issues
- `/fix-pipeline` - Debug and fix CI/CD pipeline failures

**Project Management:**
- `/issue` - Create GitHub issue with structured format

**Skill Development:**
- `/skiller` - Create, update, or remove Claude Code skills using skiller skill and skiller agent

## Command Development

When creating new commands:

1. **Keep it simple** - Commands should trigger well-defined workflows
2. **Clear purpose** - Each command does one specific thing
3. **Naming** - Use kebab-case: `my-command`
4. **Documentation** - Include usage examples

## Command Structure

Commands are markdown files that expand to prompts:

```markdown
# Command Name

Your task is to [do something specific].

[Instructions for Claude on how to complete the task]
```

The file name becomes the command: `command-name.md` → `/command-name`

IMPORTANT: Commands should be concise. Complex workflows should use agents (in `.claude/agents/`) instead.
