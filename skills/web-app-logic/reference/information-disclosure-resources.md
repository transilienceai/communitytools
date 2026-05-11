# Information Disclosure — Resources

## OWASP

- A05:2021 Security Misconfiguration — https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
- A01:2021 Broken Access Control (covers exposed admin)
- OWASP Web Security Testing Guide — Information Gathering
- OWASP Cheat Sheet — Logging
- OWASP Cheat Sheet — Error Handling
- OWASP ASVS V14 — Configuration

## CWE

- CWE-200 — Exposure of Sensitive Information
- CWE-201 — Information Through Sent Data
- CWE-209 — Generation of Error Message Containing Sensitive Information
- CWE-538 — Insertion of Sensitive Information into Externally-Accessible File
- CWE-552 — Files or Directories Accessible to External Parties
- CWE-668 — Exposure of Resource to Wrong Sphere
- CWE-916 — Use of Password Hash With Insufficient Computational Effort

## Notable disclosure cases

- Capital One AWS metadata disclosure (2019, CVE-2019-15107)
- GitHub Enterprise SSH key disclosure
- Facebook access-token exposure
- Uber `.git` repo exposure
- DeepSeek (2025) — public ClickHouse DB
- CVE-2017-5638 — Apache Struts 2 (Equifax breach)
- CVE-2019-0604 — SharePoint info disclosure → RCE
- CVE-2021-41773 — Apache HTTPD path traversal + disclosure
- CVE-2023-23752 — Joomla unauthenticated config leak

## Tools

### Burp extensions

- **Logger++** — request/response logging
- **Param Miner** — find hidden parameters
- **Retire.js** — vulnerable JS libraries
- **Software Version Reporter** — software fingerprinting
- **Error Message Checks** — verbose error detection
- **Git Digger** — `.git/` exposure
- **Backslash Powered Scanner** — advanced injection points

### Web scanners

- **Nikto** — `nikto -h target.com -C all`
- **Nuclei** — `nuclei -u target.com -t exposures/`
- **WPScan** — WordPress
- **droopescan / joomscan** — Drupal / Joomla
- **ffuf** — directory fuzzing

### Git dumping

- **git-dumper** — `pip install git-dumper`; `git-dumper https://target/.git/ output/`
- **GitTools** (gitdumper.sh, extractor.sh, commit-stream.sh)

### Secret scanning

- **truffleHog** — entropy + regex on filesystem / git history
- **gitleaks** — `gitleaks detect --source /path/to/repo`
- **git-secrets** — pre-commit hooks
- **detect-secrets** — Yelp's tool
- **noseyparker** — fast secret search

### Header analysis

- **securityheaders.com** — public scoring
- **Mozilla Observatory** — https://observatory.mozilla.org/
- **testssl.sh** — TLS configuration

## PortSwigger / labs

- Web Security Academy — Information Disclosure — https://portswigger.net/web-security/information-disclosure
- TryHackMe — Information Gathering rooms

## Wordlists

- SecLists `Discovery/Web-Content/`
  - `common.txt`, `big.txt`, `raft-large-files.txt`
  - `RAFT-medium-words.txt`
  - `api/api-endpoints.txt`
  - `CMS/admin-paths.txt`
- Backup extensions: `.bak .backup .old .orig .copy .save .tmp ~ .swp _backup -old .1 .2`
- Debug paths: `phpinfo.php info.php debug.php test.php console`

## Common information disclosure paths

```
/.env                 /robots.txt
/.git/config          /.svn/
/.hg/                 /backup/
/config.php.bak       /web.config
/wp-config.php.old    /database.yml
/phpinfo.php          /info.php
/openapi.json         /swagger.json
/api/swagger.json     /api-docs
/.well-known/security.txt
```

## Custom commands

```bash
# Quick wins
curl -s https://target.com/robots.txt
curl -s https://target.com/.git/config && echo "GIT EXPOSED!"
curl -s https://target.com/phpinfo.php | grep -i "php version"
curl -s https://target.com | grep -oP '<!--.*?-->'
curl -X TRACE https://target.com -v 2>&1 | grep -i "x-"

# Backup file fuzzing
for ext in bak old backup; do curl -I https://target.com/index.php.$ext; done

# Debug paths
for path in debug phpinfo info test dev console; do
  curl -I https://target.com/$path.php 2>&1 | grep "200 OK" && echo "Found: $path.php"
done
```

## SIEM detection

- Splunk: `index=web_logs (uri="*../*" OR uri="*%2e%2e%2f*") | stats count by src_ip`
- ELK / Sentinel: wildcards on `request.uri` for path traversal indicators
- ModSecurity rules: `id:950001` Path Traversal Attack

## Frameworks landscape

- Apache `mod_security` rules tagged information_disclosure
- nginx `error_page` custom mappings
- Express `express-rate-limit`, `helmet` for headers
- Spring `server.error.whitelabel.enabled=false`
- Django `DEBUG = False` in production

## Defensive references

- Suppress `Server`, `X-Powered-By`, `X-AspNet-Version`
- Custom error pages (4xx, 5xx)
- HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy
- Cache-Control: no-store on sensitive responses
- Pre-commit hooks for secret scanning
- CI/CD secret-detection (gitleaks, trufflehog)

## Compliance

- PCI DSS 6.5.5 (Improper error handling)
- GDPR Art 32 (security of processing)
- SOC 2 (logging, monitoring)
- HIPAA (164.312 — audit controls)

## Bug bounty programs

- HackerOne — most programs accept info-disclosure (low-medium severity)
- Bugcrowd — `info-disclosure` tag
- Intigriti — `out-of-scope` for trivial; `in-scope` for high-impact (config leaks, .git)

## Cheat-sheet companions in this repo

- `scenarios/info-disclosure/error-messages.md`
- `scenarios/info-disclosure/debug-pages-and-cms-apis.md`
- `scenarios/info-disclosure/javascript-source-review.md`
- `scenarios/info-disclosure/backups-and-version-control.md`
- `scenarios/info-disclosure/http-method-disclosure.md`
- `scenarios/info-disclosure/security-headers-audit.md`
- `scenarios/info-disclosure/client-side-storage-audit.md`
- `scenarios/info-disclosure/multi-port-and-storage-discovery.md`
