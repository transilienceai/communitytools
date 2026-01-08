---
model: sonnet
---

Create a pull request with auto-generated description.

**Instructions:**

1. Verify GitHub CLI is available:
```bash
!gh --version
!gh auth status
```

2. Check current branch and commits:
```bash
!git branch --show-current
!git log origin/main..HEAD --oneline
```

3. Get detailed diff for PR description:
```bash
!git diff origin/main...HEAD
```

4. Check if PR already exists:
```bash
!gh pr list --head $(git branch --show-current)
```

5. If no PR exists, generate PR description:
   - **Title**: Summary of changes (from commit messages)
   - **Summary**: What changed and why (2-4 bullet points)
   - **Changes**: Detailed list of modifications
   - **Testing**: How changes were tested
   - **Related Issues**: Link with "Fixes #123" or "Closes #123"

6. Create PR using GitHub CLI:
```bash
!gh pr create --title "<title>" --body "<description>" --base main
```

7. Apply labels if appropriate:
```bash
!gh pr edit --add-label "enhancement" # or "bug", "documentation", etc.
```

8. Return PR URL and number:
```bash
!gh pr view --web
```

**Guardrails:**
- Don't create PR if already exists (offer to update instead)
- Don't create PR from main branch
- Verify commits are pushed before creating PR
- Link to related issues if they exist
- Follow project's PR template if available
