---
name: source-code-scanning
description: Security-focused source code review and SAST. Scans for vulnerabilities (OWASP Top 10, CWE Top 25), CVEs in third-party dependencies/packages, hardcoded secrets, malicious code, and insecure patterns. Use when given source code, a repo path, or asked to "audit", "scan", "review" code security, or "check dependencies for CVEs".
---

# Source Code Security Review

## Quick Start

1. **Identify** - languages, frameworks, package managers present
2. **Automated SAST** - run tools appropriate to the stack
3. **Dependency CVEs** - scan lockfiles/manifests for known CVEs
4. **Secrets scan** - detect hardcoded credentials/tokens
5. **Manual review** - trace high-risk sinks (exec, eval, query, deserialize)
6. **Malicious code** - check for backdoors, obfuscation, suspicious network calls
7. **Report** - findings with CWE/CVE refs, severity, PoC, remediation

## Workflow

### Phase 1: Enumerate
```
- Languages: ls **/*.{py,js,ts,java,go,rb,php,cs,rs}
- Packages: find package.json, requirements.txt, go.mod, pom.xml, Gemfile, composer.json, Cargo.toml
- Entry points: main(), index.*, app.*, server.*
- Config files: .env*, config.*, settings.*, *.yaml, *.toml
```

### Phase 2: Automated SAST
See [sast-tools.md](reference/sast-tools.md) for commands per language.

Key tools:
- **Multi-language**: Semgrep (`semgrep --config=auto .`)
- **Python**: Bandit (`bandit -r . -f json`)
- **JavaScript/TS**: ESLint security plugin, njsscan
- **Java**: SpotBugs + FindSecBugs
- **Go**: gosec (`gosec ./...`)
- **PHP**: PHPCS Security Audit
- **Ruby**: Brakeman (`brakeman -o report.json`)
- **All**: CodeQL (via `gh codeql`)

### Phase 3: Dependency CVE Scan
See [dependency-cve-scanning.md](reference/dependency-cve-scanning.md) for commands.

| Ecosystem | Command |
|---|---|
| npm/yarn | `npm audit --json` / `yarn audit` |
| Python | `pip-audit -r requirements.txt` |
| Java | `dependency-check --scan .` |
| Go | `govulncheck ./...` |
| Ruby | `bundle audit` |
| Generic | `trivy fs .` / `grype dir:.` |

### Phase 4: Secrets Detection
See [secrets-detection.md](reference/secrets-detection.md).
```bash
trufflehog filesystem . --json
gitleaks detect --source . -v
```

### Phase 5: Manual Review
Focus on high-risk sinks — see [manual-review.md](reference/manual-review.md):
- Injection sinks: `exec`, `eval`, `query`, `system`, `popen`
- Deserialization: `pickle.loads`, `ObjectInputStream`, `unserialize`
- Crypto: hardcoded keys, weak algorithms (MD5, SHA1, DES, ECB)
- Auth: JWT validation, session management, RBAC enforcement
- File ops: path construction with user input

### Phase 6: Malicious Code
See [malicious-code.md](reference/malicious-code.md):
- Obfuscated strings (base64, hex, charCode)
- Unexpected network calls in library code
- Typosquatting indicators
- Postinstall/lifecycle script abuse
- Hidden backdoors in dependencies

## Language-Specific Patterns
See [language-patterns.md](reference/language-patterns.md) for Python, JS, Java, Go, PHP, Ruby.

## Severity Mapping

| Severity | CVSS | Examples |
|---|---|---|
| Critical | 9.0+ | RCE, SQLi with exfil, auth bypass |
| High | 7.0-8.9 | Stored XSS, SSRF, insecure deserialization |
| Medium | 4.0-6.9 | Reflected XSS, info disclosure, IDOR |
| Low | 0.1-3.9 | Missing headers, verbose errors |

## Output Format

```
findings/
  <severity>-<vuln-type>-<location>.md   # One file per finding
evidence/
  <tool>-output.json                      # Raw tool output
summary-report.md                         # Executive summary
```

Each finding: CWE/CVE ID | File:Line | Severity | PoC | Remediation

## Critical Rules
- Never execute untrusted code during review
- Treat all findings as potential until verified
- Always cross-reference CVEs against actual version in use
- Report supply chain issues separately (they affect all users)
