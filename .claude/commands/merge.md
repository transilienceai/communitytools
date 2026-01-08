---
model: sonnet
---

Merge pull request and cleanup branches.

**Instructions:**

1. Verify PR is ready to merge:
```bash
!gh pr status
!gh pr checks
```

2. Check PR details:
```bash
!gh pr view
```

3. Ensure all checks pass:
   - CI/CD pipeline successful
   - Code review approved
   - No merge conflicts
   - Required reviews obtained

4. Ask user for merge strategy:
   - **Squash merge** (recommended): Combines all commits into one
   - **Rebase merge**: Maintains linear history
   - **Merge commit**: Preserves all commits

5. Merge the PR:
```bash
!gh pr merge --squash --delete-branch
# or --rebase or --merge depending on choice
```

6. Switch back to main and pull:
```bash
!git checkout main
!git pull origin main
```

7. Clean up local branches:
```bash
!git branch -d <feature-branch>
!git fetch --prune
```

8. Confirm merge:
```bash
!git log --oneline -5
!gh pr view <pr-number>
```

**Guardrails:**
- Don't merge if checks are failing
- Don't merge without required approvals
- Confirm before deleting branches
- Default to squash merge for cleaner history
- Verify on main branch after merge
