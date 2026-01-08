# Claude Code Slash Commands

This directory contains custom slash commands for automating git workflows and development tasks with Claude Code.

## Available Commands

| Command | Purpose | Model | Speed |
|---------|---------|-------|-------|
| `/branch` | Create feature branches with conventional naming | Sonnet | Medium |
| `/lint` | Run linter with auto-fix | Haiku | Fast (~20s) |
| `/test` | Execute tests and fix failures | Haiku | Fast (~20s) |
| `/commit` | Generate Conventional Commit messages | Sonnet | Medium |
| `/push` | Stage, commit, and push in one action | Sonnet | Medium |
| `/fix-pipeline` | Debug and resolve CI failures | Sonnet | Medium |
| `/pr` | Create pull requests with generated descriptions | Sonnet | Medium |
| `/issue` | Create GitHub issues with structured format | Sonnet | Medium |
| `/merge` | Merge PR with cleanup | Sonnet | Medium |

## Quick Start

### Basic Git Workflow

1. **Start a new feature:**
   ```bash
   /branch
   ```
   Creates a feature branch with conventional naming (e.g., `feature/new-skill`)

2. **Make your changes**, then:
   ```bash
   /lint
   /test
   ```
   Ensures code quality and tests pass

3. **Commit and push:**
   ```bash
   /push
   ```
   Stages, commits with conventional format, and pushes to remote

4. **Create pull request:**
   ```bash
   /pr
   ```
   Generates PR with description from commits and diffs

5. **After approval:**
   ```bash
   /merge
   ```
   Squash merges and cleans up branches

### Reporting Issues

```bash
/issue
```
Creates a structured GitHub issue with templates

### CI/CD Debugging

```bash
/fix-pipeline
```
Analyzes failed CI runs and applies fixes

## Command Details

### /branch

Creates a new Git branch following conventional naming patterns.

**Usage:**
- Checks current status
- Asks for branch type (feature/bugfix/docs)
- Creates branch from main
- Verifies no uncommitted changes

**Examples:**
- `feature/aws-log-parser`
- `bugfix/auth-issue`
- `docs/readme-update`

### /lint

Runs appropriate linter based on project type with auto-fix.

**Supports:**
- Python: ruff, pylint, flake8
- JavaScript/TypeScript: eslint
- Go: golangci-lint
- Ruby: rubocop

**Features:**
- Auto-detects project configuration
- Fixes issues automatically
- Reports remaining manual fixes

### /test

Executes test suite and fixes failures.

**Supports:**
- Python: pytest
- JavaScript/TypeScript: jest, vitest, mocha
- Go: go test
- Ruby: rspec

**Features:**
- Analyzes test failures
- Fixes implementation issues
- Re-runs to verify fixes

### /commit

Generates Conventional Commit messages.

**Format:**
```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding/updating tests
- `chore`: Maintenance tasks
- `perf`: Performance improvements
- `ci`: CI/CD changes
- `build`: Build system changes

**Examples:**
```
feat(auth): add OAuth2 authentication flow
fix(api): resolve rate limiting bug
docs(readme): update installation instructions
refactor(parser): simplify log parsing logic
```

### /push

Complete workflow: stage → commit → push.

**Features:**
- Stages changes (all or specific files)
- Generates conventional commit message
- Pushes to remote with upstream tracking
- Warns before pushing to main

### /pr

Creates pull request with auto-generated description.

**Generates:**
- Title from commits
- Summary of changes (bullet points)
- Detailed change list
- Testing notes
- Issue links (Fixes #123)

**Requires:**
- GitHub CLI (`gh`) installed and authenticated
- Commits pushed to remote branch

### /issue

Creates GitHub issue with structured format.

**Includes:**
- Title and description
- Type (bug/feature/question)
- Steps to reproduce (for bugs)
- Expected vs actual behavior
- Environment details
- Labels

### /fix-pipeline

Debugs CI/CD pipeline failures.

**Process:**
1. Fetches failed run logs
2. Identifies failure point
3. Analyzes error messages
4. Applies fixes
5. Tests locally
6. Commits and monitors new run

**Handles:**
- Linting failures
- Test failures
- Build errors
- Deployment issues
- Timeouts

### /merge

Merges pull request and cleans up.

**Process:**
1. Verifies checks pass
2. Confirms approvals
3. Merges (squash/rebase/merge)
4. Deletes remote branch
5. Updates local main
6. Cleans local branches

## Shell Aliases

For even faster execution, add to your `.zshrc` or `.bashrc`:

```bash
# Claude Code command aliases
alias clbranch="claude -p '/branch'"
alias cllint="claude -p '/lint'"
alias cltest="claude -p '/test'"
alias clcommit="claude -p '/commit'"
alias clpush="claude -p '/push'"
alias clpr="claude -p '/pr'"
alias clissue="claude -p '/issue'"
alias clfix="claude -p '/fix-pipeline'"
alias clmerge="claude -p '/merge'"

# Combined workflows
alias clship="cllint && cltest && clpush && clpr"  # Complete feature workflow
alias clcheck="cllint && cltest"                   # Quick quality check
```

Then use single commands:
```bash
clbranch      # Creates new branch
clcheck       # Runs lint + test
clship        # Ships feature (lint, test, push, PR)
```

## Advanced Usage

### Non-Interactive Mode

Run commands non-interactively with `-p` flag:

```bash
claude -p '/lint'
claude -p '/test'
```

### Bash Command Injection

Commands use `!` prefix to inject live command output:

```bash
!git status          # Runs git status and injects output
!git log -5          # Shows recent commits
!gh pr list          # Lists pull requests
```

This provides real-time context for Claude to make informed decisions.

### Model Selection

Commands use appropriate models for performance:

- **Haiku**: Fast tasks (lint, test) - ~20 seconds
- **Sonnet**: Complex reasoning (commits, PRs, CI debugging) - ~30-60 seconds

Override in command frontmatter:
```yaml
---
model: haiku  # or sonnet or opus
---
```

### Custom Commands

Create your own commands in `.claude/commands/`:

1. Create `<name>.md` file
2. Add optional frontmatter:
   ```yaml
   ---
   model: sonnet
   ---
   ```
3. Write instructions using markdown
4. Use `!command` syntax for bash injection
5. Command becomes available as `/<name>`

## Best Practices

### Safety Guardrails

All commands include safety checks:
- Verify prerequisites before running
- Check for existing resources (branches, PRs)
- Warn before destructive operations
- Validate before committing/pushing
- Don't commit sensitive files

### Workflow Tips

1. **Branch naming**: Use consistent types (feature/bugfix/docs)
2. **Commit often**: Small, focused commits are easier to review
3. **Test locally**: Always run `/lint` and `/test` before pushing
4. **Link issues**: Reference issue numbers in PRs (Fixes #123)
5. **Clean history**: Use squash merge for cleaner git history

### Performance Optimization

- Use `/lint` and `/test` (Haiku) for quick checks
- Batch operations with `/push` instead of separate commands
- Run `/lint` before committing to catch issues early
- Use shell aliases for frequent commands

## Troubleshooting

### GitHub CLI Not Found

```bash
# Install GitHub CLI
brew install gh            # macOS
sudo apt install gh        # Ubuntu/Debian
winget install GitHub.cli  # Windows

# Authenticate
gh auth login
```

### Command Not Found

Commands must be in `.claude/commands/` directory. Verify:

```bash
ls -la .claude/commands/
```

### Permission Denied

Ensure proper git configuration:

```bash
git config --list
gh auth status
```

### Linter/Test Not Found

Install project dependencies:

```bash
npm install        # JavaScript/TypeScript
pip install -e .   # Python
bundle install     # Ruby
go mod download    # Go
```

## Contributing

To add new commands:

1. Create `.claude/commands/<name>.md`
2. Follow existing command patterns
3. Include frontmatter with model selection
4. Add safety guardrails
5. Document in this README
6. Test thoroughly

## References

- [Claude Code Documentation](https://docs.anthropic.com/en/docs/claude-code)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [GitHub CLI](https://cli.github.com/)
- [Original Guide](https://alexop.dev/posts/claude-code-slash-commands-guide/)

## License

Same as parent repository.
