# GitHub Workflow Skill

Automates the full GitHub development lifecycle: branching, committing, pushing, pull requests, issues, and code review.

## Usage

```
/github-workflow
```

Or invoke naturally: "commit my changes", "create a PR", "make a branch for this feature".

## Capabilities

- **Branching** — Create conventional branches (`feature/`, `bugfix/`, `docs/`)
- **Committing** — Stage files, write conventional commit messages
- **Pushing** — Push with upstream tracking, handle rejections
- **Pull Requests** — Create, review, merge PRs with `gh` CLI
- **Issues** — Create well-formatted GitHub issues
- **Code Review** — View diffs, check CI, approve/request changes

## Prerequisites

- **git** — installed and configured
- **gh** — GitHub CLI, authenticated (`gh auth login`)

## Conventions

- Commit format: `type(scope): description`
- Branch format: `type/short-description`
- PRs link to issues: `Fixes #N`
- Never force-push main, never commit secrets

## Reference

- [commit-conventions.md](reference/commit-conventions.md) — Message format and examples
- [pr-workflow.md](reference/pr-workflow.md) — PR lifecycle
- [branch-strategy.md](reference/branch-strategy.md) — Branching model
