---
model: sonnet
---

Stage changes, create commit, and push to remote in one workflow.

**Instructions:**

1. Check current status and branch:
```bash
!git status
!git branch --show-current
!git log origin/$(git branch --show-current)..HEAD 2>/dev/null || echo "No upstream branch"
```

2. Show diff of changes:
```bash
!git diff
!git diff --cached
```

3. Stage changes:
   - Ask user if they want to stage all or specific files
   - `git add .` for all, or `git add <files>` for specific

4. Generate conventional commit message (same as /commit):
   - Analyze changes
   - Review recent commit style: `!git log --oneline -10`
   - Create message following format: `<type>(<scope>): <description>`

5. Create commit:
```bash
!git commit -m "<generated message>"
```

6. Push to remote:
   - If no upstream: `git push -u origin <current-branch>`
   - If upstream exists: `git push`

7. Confirm push success:
```bash
!git status
!git log -1 --oneline
```

**Guardrails:**
- Don't push if no changes to commit
- Verify commit message follows project conventions
- Don't force push unless explicitly requested
- Warn if pushing to main/master (should use PR instead)
- Don't push sensitive files (.env, secrets, credentials)
