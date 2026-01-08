---
model: haiku
---

Run tests and automatically fix failures.

**Instructions:**

1. Detect test framework:
```bash
!ls -la | grep -E "package.json|pytest.ini|pyproject.toml|go.mod|Gemfile"
!cat package.json 2>/dev/null | grep -E "vitest|jest|mocha" || cat pyproject.toml 2>/dev/null | grep pytest || echo "Detecting test framework..."
```

2. Run appropriate test command:
   - **Python**: `pytest -v` or `python -m pytest`
   - **JavaScript/TypeScript**: `npm test` or `npx vitest` or `npx jest`
   - **Go**: `go test ./...`
   - **Ruby**: `bundle exec rspec`

3. Capture test output:
```bash
![detected test command]
```

4. If tests fail:
   - Analyze the error messages and stack traces
   - Identify which tests failed and why
   - Read the failing test files
   - Read the implementation files being tested
   - Fix the issues using Edit tool
   - Re-run tests to verify fixes

5. Report results:
   - ✓ All tests passing (X passed, Y skipped)
   - ⚠ Tests still failing (list them)
   - 📝 Files modified to fix tests

**Guardrails:**
- Don't modify test assertions unless they're clearly wrong
- Focus on fixing implementation to pass tests
- If test expectations are incorrect, ask user before changing them
- Always re-run tests after fixes to verify
