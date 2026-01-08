---
model: sonnet
---

Debug and resolve CI/CD pipeline failures.

**Instructions:**

1. Check for CI pipeline status:
```bash
!gh run list --limit 5
!gh run view --log-failed
```

2. If using GitHub Actions, read workflow files:
```bash
!ls -la .github/workflows/
!cat .github/workflows/*.yml
```

3. Identify the failure:
   - Parse error messages from logs
   - Identify which job/step failed
   - Note the specific error or exit code

4. Common issues to check:
   - **Linting failures**: Run `/lint` locally
   - **Test failures**: Run `/test` locally
   - **Build failures**: Check dependencies, versions
   - **Deployment failures**: Check credentials, configurations
   - **Timeout issues**: Optimize slow steps

5. Fix the root cause:
   - Read relevant files mentioned in errors
   - Apply fixes using Edit tool
   - Test locally before pushing

6. Commit and push fixes:
```bash
!git add .
!git commit -m "ci: fix pipeline failure - <specific issue>"
!git push
```

7. Monitor new pipeline run:
```bash
!gh run watch
```

8. Report resolution:
   - ✓ Pipeline fixed - link to successful run
   - ⚠ Still investigating - what's been tried
   - 📝 Files modified

**Guardrails:**
- Read actual error logs, don't guess
- Test fixes locally when possible
- Don't disable checks to "fix" pipeline
- Consider pipeline performance (caching, parallelization)
