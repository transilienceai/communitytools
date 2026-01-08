---
model: haiku
---

Run code linter and automatically fix issues.

**Instructions:**

1. Detect the project type and available linters:
```bash
!ls -la | grep -E "package.json|pyproject.toml|setup.py|requirements.txt|Gemfile|go.mod"
!cat package.json 2>/dev/null || cat pyproject.toml 2>/dev/null || echo "No config found"
```

2. Run the appropriate linter based on project:
   - **Python**: `ruff check --fix .` or `pylint` or `flake8`
   - **JavaScript/TypeScript**: `npm run lint` or `eslint --fix .`
   - **Go**: `golangci-lint run --fix`
   - **Ruby**: `rubocop -a`

3. Capture and display results:
```bash
![detected linter command with --fix flag]
```

4. If errors remain that can't be auto-fixed:
   - Read the error output
   - Identify the files and lines with issues
   - Fix them manually using Edit tool
   - Re-run linter to verify

5. Report final status:
   - ✓ All issues fixed
   - ⚠ Manual fixes required (list them)

**Guardrails:**
- Always use the project's configured linter (check package.json scripts, pyproject.toml, etc.)
- Don't modify code beyond linting fixes
- Show summary of what was changed
