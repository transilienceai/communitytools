---
model: sonnet
---

Generate a conventional commit message and create a commit for all changes, additions, deletions and new files.

**Instructions:**

1. Check current git status and diff:
```bash
!git status
!git diff --cached
!git diff
```

2. Analyze recent commits for project style:
```bash
!git log --oneline -10
```

3. Stage files if not already staged:
   - If user wants to commit specific files, ask which ones
   - Otherwise stage all changes: `git add .`

4. Generate commit message following Conventional Commits format:
   - **Type**: feat, fix, docs, style, refactor, test, chore, perf, ci, build
   - **Scope**: (optional) affected component/module
   - **Description**: clear, concise summary (imperative mood, lowercase, no period)
   - **Body**: (optional) detailed explanation
   - **Footer**: (optional) breaking changes, issue references

   Format: `<type>(<scope>): <description>`

   Examples:
   - `feat(auth): add OAuth2 authentication flow`
   - `fix(api): resolve rate limiting bug`
   - `docs(readme): update installation instructions`
   - `refactor(parser): simplify log parsing logic`

5. Present the commit message to user for approval

6. Create the commit:
```bash
!git commit -m "<generated message>"
```

7. Confirm commit created:
```bash
!git log -1 --oneline
```

**Guardrails:**
- Don't commit if no staged changes
- Follow project's existing commit style (analyze git log)
- Keep description under 72 characters
- Use imperative mood ("add" not "added" or "adds")
- Don't commit sensitive files (.env, credentials, etc.)
