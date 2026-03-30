# Source Code Security Scanning

Security-focused static analysis: SAST, dependency CVE scanning, secrets detection, and malicious code review.

## When to Use

- Given a local repo or source directory to audit
- Asked to "review code security", "find vulnerabilities in source", "check dependencies for CVEs"
- Pre-deployment security gate
- Bug bounty recon revealing open-source repos

## What It Covers

| Area | Tools | Reference |
|---|---|---|
| SAST (automated) | Semgrep, Bandit, gosec, Brakeman, CodeQL | `reference/sast-tools.md` |
| Dependency CVEs | pip-audit, npm audit, govulncheck, Trivy, Grype | `reference/dependency-cve-scanning.md` |
| Secrets detection | TruffleHog, Gitleaks, detect-secrets | `reference/secrets-detection.md` |
| Manual review patterns | Taint analysis, CWE Top 25, sinks/sources | `reference/manual-review.md` |
| Language patterns | Python, JS, Java, Go, PHP, Ruby | `reference/language-patterns.md` |
| Malicious code | Backdoors, obfuscation, supply chain | `reference/malicious-code.md` |

## Quick Usage

```bash
# Full auto scan (multi-language)
semgrep --config=auto --json -o semgrep.json .

# Dependency CVEs
trivy fs --format json -o trivy.json .

# Secrets
trufflehog filesystem . --json > secrets.json
gitleaks detect --source . --report-path gitleaks.json
```

## Output

```
findings/<severity>-<type>-<location>.md
evidence/<tool>-output.json
summary-report.md
```

## Key Standards
- CWE Top 25 weaknesses
- OWASP Top 10 / ASVS L2
- CVSS v3.1 severity scoring
- NVD CVE database for dependency issues
