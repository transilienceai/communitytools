---
model: haiku
---

Create a new Git branch following conventional naming patterns.

**Instructions:**

1. Check current branch status:
```bash
!git status
!git branch -a
```

2. Ask the user for:
   - Branch type (feature/bugfix/docs/enhancement)
   - Brief descriptive name (use kebab-case)

3. Verify main/master branch is up to date:
```bash
!git fetch origin
!git status
```

4. Create and switch to the new branch using format: `<type>/<descriptive-name>`
   - Examples: `feature/aws-log-parser`, `bugfix/auth-issue`, `docs/readme-update`

5. Confirm branch creation and provide next steps:
   - Make your changes
   - Use `/commit` when ready to commit
   - Use `/pr` to create pull request

**Guardrails:**
- Don't create branch if uncommitted changes exist (offer to stash or commit first)
- Don't create if branch name already exists
- Always branch from main/master unless explicitly specified
