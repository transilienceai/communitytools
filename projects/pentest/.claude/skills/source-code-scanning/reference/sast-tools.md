# SAST Tools Reference

## Universal / Multi-Language

### Semgrep (primary tool)
```bash
# Auto-detect language + community rules
semgrep --config=auto --json -o semgrep.json .

# OWASP Top 10 ruleset
semgrep --config=p/owasp-top-ten --json .

# Secrets ruleset
semgrep --config=p/secrets .

# Custom rule inline
semgrep -e 'os.system($X)' --lang python .
```

### CodeQL
```bash
# Create database
codeql database create db --language=python --source-root=.

# Run security queries
codeql database analyze db --format=sarif-latest -o results.sarif \
  codeql/python-queries:Security/

# Via GitHub CLI
gh codeql analyze
```

### Snyk (SAST + SCA)
```bash
snyk code test --json > snyk-code.json
snyk test --json > snyk-deps.json
```

## Language-Specific Tools

### Python — Bandit
```bash
bandit -r . -f json -o bandit.json
bandit -r . -ll          # high severity only
bandit -r . -t B105,B106 # specific test IDs
```

Key Bandit test IDs:
- B101: assert used (can be disabled)
- B102: exec used
- B103: setting permissions
- B105/B106/B107: hardcoded passwords
- B201: Flask debug mode
- B301: pickle usage
- B303: MD5/SHA1
- B311: random (not cryptographic)
- B501-B510: SSL/TLS weaknesses
- B602: subprocess shell=True
- B608: SQL injection risk

### JavaScript / TypeScript
```bash
# njsscan (Node.js focused)
njsscan --json -o njsscan.json .

# ESLint security plugin
npm install -D eslint-plugin-security eslint-plugin-no-unsanitized
eslint --rulesdir . --format json -o eslint.json .

# Retire.js (known vuln libraries)
retire --outputformat json --outputpath retire.json
```

### Java
```bash
# SpotBugs + FindSecBugs plugin
spotbugs -textui -xml:withMessages -output spotbugs.xml target/

# PMD security rules
pmd check -d src -R category/java/security.xml -f json

# Semgrep Java
semgrep --config=p/java .
```

### Go
```bash
# gosec
gosec -fmt json -out gosec.json ./...

# staticcheck
staticcheck ./...

# govulncheck (also deps)
govulncheck ./...
```

Key gosec rules:
- G101: hardcoded credentials
- G102: bind to all interfaces
- G104: errors unhandled
- G201/G202: SQL formatting
- G304: file path from variable
- G401-G403: weak crypto
- G501-G505: blocklisted imports

### Ruby
```bash
brakeman -o brakeman.json --no-progress .
brakeman -w 2 .  # only medium+ warnings
```

### PHP
```bash
# PHPCS Security Audit
phpcs --standard=Security .

# Progpilot
php progpilot.phar --file index.php
```

### C/C++
```bash
# Flawfinder
flawfinder --html . > flawfinder.html

# Cppcheck
cppcheck --enable=all --xml . 2> cppcheck.xml
```

### Terraform / IaC
```bash
tfsec . --format json > tfsec.json
checkov -d . -o json > checkov.json
```

## Triage Priority

1. Critical/High from any tool with user-controlled input path
2. Crypto weaknesses in auth or data storage
3. SQL/command/SSTI injection sinks
4. Deserialization of untrusted data
5. Medium findings in authentication flows

## SARIF Aggregation
```bash
# Merge SARIF results
sarif summary *.sarif
sarif copy --output merged.sarif *.sarif
```
