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

## Compiled artifacts hold what source hides

Source frequently shows a placeholder (`<OBFUSCATED>`, `***`, `getenv(...)`, `process.env.X`) where the real secret is *baked into the build*. When source ships alongside compiled output (a leaked project zip, `bin/`/`obj/`, an APK, a published DLL/JAR), extract strings from the compiled artifact — the literal is usually there. **If source says placeholder but a compiled copy exists, the compiled copy is the priority target.**

- **.NET (PE/DLL/EXE):** string literals live in the `#US` heap as **UTF-16LE**, which ASCII `strings` misses. Use `strings -el` (GNU) or:
  ```bash
  python3 -c "import re,sys;d=open(sys.argv[1],'rb').read();[print(repr(x)) for x in sorted(set(re.findall(r'[\x20-\x7e]{6,}',d.decode('utf-16le','ignore')))) if any(k in x.lower() for k in('pass','pwd','conn','token','key'))]" app.dll
  ```
  Decompilers (dnSpy, ilspycmd) recover the exact `private static string Password = "...";`. (macOS `strings` has no `-el`; use the Python one-liner.)
- **JVM:** `unzip` the jar; `javap -c -p` or CFR/procyon for full decompile.
- **Native ELF/Mach-O/PE:** `strings -a`, check BOTH ASCII and wide (UTF-16) encodings.

A recovered DB/service password also unlocks **direct protocol access** (MSSQL 1433, redis, SMB) that app-layer injection couldn't reach, and is worth spraying as **credential reuse** across other users/services. (Real case: HTB Context — `webappusr` SQL password was `<OBFUSCATED>` in `Database.cs` but present verbatim in `obj/Debug/WebApplication.dll`, enabling a direct 1433 connection.)

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
