---
model: sonnet
---

Create a GitHub issue with structured information.

**Instructions:**

1. Verify GitHub CLI is available:
```bash
!gh --version
!gh auth status
```

2. Check available issue templates:
```bash
!ls -la .github/ISSUE_TEMPLATE/ 2>/dev/null || echo "No templates found"
```

3. Gather issue information from user:
   - **Title**: Clear, concise summary
   - **Type**: bug, feature, enhancement, question, documentation
   - **Description**: Detailed explanation
   - **Steps to reproduce** (for bugs)
   - **Expected behavior** (for bugs)
   - **Environment** (if relevant)
   - **Additional context**

4. Format issue body using markdown:
```markdown
## Description
[Detailed description]

## Steps to Reproduce (for bugs)
1. Step one
2. Step two
3. ...

## Expected Behavior
[What should happen]

## Actual Behavior
[What actually happens]

## Environment
- OS: [e.g., macOS, Linux, Windows]
- Version: [e.g., v1.2.3]
- Other relevant details

## Additional Context
[Screenshots, logs, related issues]
```

5. Create the issue:
```bash
!gh issue create --title "<title>" --body "<formatted-body>"
```

6. Apply appropriate labels:
```bash
!gh issue edit <issue-number> --add-label "bug" # or "enhancement", "question", etc.
```

7. Return issue URL and number:
```bash
!gh issue view <issue-number> --web
```

**Guardrails:**
- Use project's issue templates if available
- Don't create duplicate issues (search first)
- Include all relevant context and details
- Apply appropriate labels for triage
- Link related issues or PRs if they exist
