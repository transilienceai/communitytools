# Repository Reconnaissance Reference

## Overview

Public repositories regularly expose API keys, credentials, internal infrastructure, and architecture details. Git history amplifies this — secrets "deleted" in a commit remain fully accessible in the commit object until the repo is force-pushed/rewritten.

**MITRE ATT&CK**: T1593.003 (Search Open Websites/Domains - Code Repositories), T1552.001 (Credentials In Files)

---

## Phase 1: Organization & Repo Discovery

### Find the target org

```bash
# GitHub CLI — list all public repos in an org
gh repo list <org-name> --limit 200 --json name,description,updatedAt,primaryLanguage

# Also search for name variants
gh search repos --owner <org-name>

# API search for org code (requires token)
curl -H "Authorization: token TOKEN" \
  "https://api.github.com/search/code?q=org:TARGET+filename:.env"
```

### Name variants to try
- `company-name`, `companyname`, `company_name`
- `company-eng`, `company-dev`, `company-security`
- Product names, brand names, internal codenames

### Find employee accounts
```bash
# Search GitHub for employees by company email domain
gh search users --type users "company.com in:email"

# Or by org membership (if public)
gh api orgs/<org>/members --paginate | jq '.[].login'
```

### Check other platforms
- `gitlab.com/<org-name>` — direct URL check
- `bitbucket.org/<org-name>` — direct URL check
- `sourcegraph.com/search?q=org:<org>` — cross-platform code search
- `grep.app` — fast search across GitHub

---

## Phase 2: GitHub Search Dorks

Run these searches at `github.com/search?type=code` or via API:

### High-value dorks
```
org:TARGET "api_key"
org:TARGET "api_secret"
org:TARGET "AWS_ACCESS_KEY_ID"
org:TARGET "AWS_SECRET_ACCESS_KEY"
org:TARGET "password" filename:.env
org:TARGET "private_key" extension:pem
org:TARGET "BEGIN RSA PRIVATE KEY"
org:TARGET "BEGIN OPENSSH PRIVATE KEY"
org:TARGET "token" filename:config
org:TARGET "jdbc:mysql"
org:TARGET "mongodb+srv"
org:TARGET "redis://"
org:TARGET "Authorization: Bearer"
org:TARGET "internal" filename:docker-compose.yml
org:TARGET extension:sql "INSERT INTO users"
```

### Infrastructure discovery dorks
```
org:TARGET "10.0." OR "192.168." OR "172.16."
org:TARGET ".internal" OR ".corp" OR ".local"
org:TARGET "staging" OR "dev" OR "preprod" filename:.env
org:TARGET "DATABASE_URL"
org:TARGET "SLACK_WEBHOOK"
org:TARGET "STRIPE_SECRET"
org:TARGET "SENDGRID_API_KEY"
```

---

## Phase 3: Secret Scanning Tools

### TruffleHog (best for history)
```bash
# Scan a single repo including full git history
trufflehog git https://github.com/ORG/REPO --json > raw/osint/trufflehog-REPO.json

# Scan entire GitHub org
trufflehog github --org=TARGET --json > raw/osint/trufflehog-org.json

# Scan with specific detectors only
trufflehog git https://github.com/ORG/REPO --only-verified

# Scan from a specific commit depth
trufflehog git REPO_URL --since-commit=HEAD~500
```

### Gitleaks
```bash
# Scan cloned repo
gitleaks detect --source /path/to/repo --report-format json \
  --report-path raw/osint/gitleaks-REPO.json

# Scan with git log history
gitleaks detect --source /path/to/repo --log-opts="HEAD~1000..HEAD" \
  --report-format json --report-path raw/osint/gitleaks-history.json
```

### Gitrob (org-wide)
```bash
# Enumerate and scan all org repos
gitrob -github-access-token TOKEN TARGET_ORG
```

---

## Phase 4: Code Intelligence

### Extract endpoints and config from repos
```bash
# Clone and grep for common patterns
git clone https://github.com/ORG/REPO /tmp/repo-scan

# Internal hostnames
grep -rE '(https?://[a-z0-9.-]+\.(internal|corp|local|dev|staging))' /tmp/repo-scan/

# Hardcoded IPs
grep -rE '\b(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' /tmp/repo-scan/

# Auth patterns
grep -rE '(Authorization|Bearer|apikey|api_key|secret|password)\s*[=:]\s*["\x27][^"\x27]{8,}' /tmp/repo-scan/

# Dependency versions (for CVE lookup)
cat /tmp/repo-scan/package.json /tmp/repo-scan/requirements.txt \
    /tmp/repo-scan/Gemfile /tmp/repo-scan/pom.xml 2>/dev/null
```

### CI/CD config files to review
```
.github/workflows/*.yml      — GitHub Actions: secrets, deploy keys, env vars
.gitlab-ci.yml               — GitLab CI: tokens, registry creds
Jenkinsfile                  — Jenkins: credentials, internal URLs
.circleci/config.yml         — CircleCI: env vars, contexts
.travis.yml                  — Travis: encrypted vars
Dockerfile, docker-compose.yml — ARG secrets, internal services
terraform/, .tf files        — Cloud infra, IAM, resource names
```

---

## Output Format

Save to `{OUTPUT_DIR}/recon/repositories.json`:

```json
{
  "asset_type": "repositories",
  "target_org": "example",
  "platforms": ["github", "gitlab"],
  "repositories": [
    {
      "name": "example/backend-api",
      "url": "https://github.com/example/backend-api",
      "platform": "github",
      "language": "Python",
      "last_updated": "2024-11-01",
      "risk_level": "critical",
      "findings": [
        {
          "type": "secret",
          "description": "AWS Access Key ID in commit a1b2c3d",
          "file": "config/settings.py",
          "commit": "a1b2c3d",
          "detector": "trufflehog",
          "verified": true
        }
      ]
    }
  ],
  "employee_accounts": [
    {
      "platform": "github",
      "username": "jsmith-example",
      "repos_scanned": 12,
      "findings": []
    }
  ],
  "stats": {
    "total_repos": 34,
    "repos_with_findings": 5,
    "total_secrets_found": 8,
    "verified_secrets": 3
  }
}
```

---

## Finding Severity Guidelines

| Finding | Severity |
|---------|----------|
| Active cloud key (AWS/GCP/Azure) with verified access | CRITICAL |
| Database connection string with credentials | CRITICAL |
| Private SSH/TLS key | CRITICAL |
| API key for payment/auth service (Stripe, Twilio) | HIGH |
| Internal hostname/IP + service version | MEDIUM |
| Hardcoded staging/dev credentials | MEDIUM |
| Tech stack / dependency versions | LOW |
| Internal endpoint paths | LOW / INFORMATIONAL |

---

## References

- **MITRE ATT&CK**: T1593.003, T1552.001, T1213.003
- **Tools**: trufflehog (https://github.com/trufflesecurity/trufflehog), gitleaks (https://github.com/gitleaks/gitleaks), gitrob (https://github.com/michenriksen/gitrob)
- **Search**: grep.app, sourcegraph.com, github.com/search
