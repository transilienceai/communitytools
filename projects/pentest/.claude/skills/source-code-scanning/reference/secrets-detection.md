# Secrets Detection in Source Code

## Tools

### TruffleHog (primary)
```bash
# Filesystem scan
trufflehog filesystem . --json > trufflehog.json

# Git history (all commits)
trufflehog git file://. --json > trufflehog-git.json

# Remote repo
trufflehog github --repo https://github.com/org/repo

# Only verified secrets
trufflehog filesystem . --only-verified --json
```

### Gitleaks
```bash
# Working directory
gitleaks detect --source . --report-path gitleaks.json --report-format json

# Git history
gitleaks detect --source . --log-opts="--all" --report-path gitleaks-history.json

# Pre-commit hook
gitleaks protect --staged
```

### detect-secrets
```bash
pip install detect-secrets
detect-secrets scan . > .secrets.baseline
detect-secrets audit .secrets.baseline
```

### git-secrets (AWS-focused)
```bash
git secrets --scan
git secrets --scan-history
```

## High-Value Secret Patterns

| Category | Pattern Examples |
|---|---|
| API keys | `sk-`, `AIza`, `AKIA`, `xoxb-`, `ghp_`, `glpat-` |
| Passwords | `password=`, `passwd=`, `pwd=`, `secret=` |
| Private keys | `BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY` |
| DB connection strings | `mongodb://`, `postgresql://user:pass@`, `mysql://` |
| JWT secrets | long base64 strings near `secret`, `key`, `signing` |
| Cloud credentials | AWS_SECRET, AZURE_CLIENT_SECRET, GCP_SERVICE_ACCOUNT |
| Tokens | `token=`, `Bearer `, `Authorization:` hardcoded |

## Manual Grep Patterns
```bash
# High-signal patterns
grep -rn "password\s*=\s*['\"][^'\"]\+['\"]" . --include="*.{py,js,java,go,rb,php}"
grep -rn "secret\s*=\s*['\"][^'\"]\+['\"]" .
grep -rn "api_key\s*=\s*['\"][^'\"]\+['\"]" .
grep -rn "BEGIN.*PRIVATE KEY" .
grep -rn "AKIA[0-9A-Z]{16}" .          # AWS Access Key
grep -rn "token\s*=\s*['\"][^'\"]\+['\"]" .

# .env files committed
find . -name ".env" -not -path "*/.git/*"
find . -name ".env.*" -not -path "*/.git/*"
```

## Common False Positive Indicators
- Test/example values: `your_password_here`, `REPLACE_ME`, `<token>`
- Empty strings or single chars
- Values from env vars: `os.getenv(...)`, `process.env.X`, `${VAR}`
- Values from config injection: `${config.secret}`

## Remediation Steps

1. Revoke the secret immediately (rotate keys, invalidate tokens)
2. Remove from codebase AND git history:
   ```bash
   git filter-repo --path-glob '*.env' --invert-paths
   # or use BFG Repo Cleaner
   bfg --delete-files .env
   ```
3. Add to `.gitignore` going forward
4. Use a secrets manager: AWS Secrets Manager, HashiCorp Vault, Azure Key Vault

## Prevention Checks

- [ ] `.gitignore` includes `.env`, `*.pem`, `*.key`, `config/secrets*`
- [ ] Pre-commit hook (gitleaks protect) is active
- [ ] CI/CD secret scanning enabled (GitHub: push protection, GitLab: secret detection)
- [ ] Secrets loaded from environment, not hardcoded
- [ ] No secrets in Docker build args / image layers
