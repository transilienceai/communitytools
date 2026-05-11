# Access Control — Resources

## OWASP

- A01:2021 Broken Access Control — https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- OWASP API Security API1 (BOLA) and API3 (BOPLA) — https://owasp.org/API-Security/
- OWASP Authorization Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- OWASP Mass Assignment Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- OWASP Web Security Testing Guide — Authorization Testing — https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS V4 (Authorization)

## CWE

- CWE-200 — Information Exposure
- CWE-201 — Information Through Sent Data
- CWE-284 — Improper Access Control
- CWE-285 — Improper Authorization
- CWE-352 — CSRF
- CWE-359 — Private Information Exposure
- CWE-639 — Authorization Bypass via User-Controlled Key (IDOR)
- CWE-22 — Path Traversal
- CWE-425 — Forced Browsing
- CWE-915 — Improperly Controlled Modification of Dynamically-Determined Object Attributes (mass assignment)

## Notable CVE / disclosure cases

- Trello (2024) — IDOR exposing 15M users
- Cox Communications (2024) — admin function without auth
- Dell (2024) — IDOR mass enumeration of 49M records
- DeepSeek (2025) — public ClickHouse DB
- Coinbase (2025) — business-logic IDOR ($250K bounty)
- GitHub Enterprise SSH key disclosure
- Facebook access-token via IDOR
- Uber `.git` repository exposure
- Capital One AWS metadata IDOR (2019)

## Tools

### Burp extensions

- **Autorize** — auto cross-role authorization testing
- **AuthMatrix** — role-based testing matrix
- **Auth Analyzer** — session analysis
- **Auto Repeater** — automated retesting on every request
- **Param Miner** — discover hidden parameters and headers
- **Logger++** — request log + filtering

### Standalone

- **ffuf** — endpoint discovery
- **dirsearch / gobuster** — admin path brute force
- **nuclei** — broken-access-control templates (`-t broken-access-control/`)
- **arjun** — hidden parameter discovery
- **kiterunner** — API endpoint discovery from OpenAPI

### Custom scripts

- ID enumeration: Python + `concurrent.futures` for parallel GET/POST sweeps
- HTTP method fuzzer (curl `-X $METHOD`)
- Header fuzzer (curl `-H "$HEADER: $VAL"`)

## PortSwigger / labs

- Web Security Academy — Access Control labs — https://portswigger.net/web-security/access-control
- Web Security Academy — Authentication labs
- Web Security Academy — IDOR labs
- TryHackMe — Broken Access Control rooms

## Wordlists

- SecLists `Discovery/Web-Content/api/`
- SecLists `Discovery/Web-Content/CMS/admin-paths.txt`
- SecLists `Fuzzing/role-names.txt`
- Common admin paths: `/admin`, `/administrator`, `/admin-panel`, `/admin.php`, `/manage`, `/control-panel`, `/dashboard`, `/cpanel`

## Header collections (for header-bypass)

- X-Original-URL, X-Rewrite-URL, X-Override-URL
- X-Forwarded-Host, X-Forwarded-For, X-Real-IP, X-Client-IP
- X-Custom-IP-Authorization, True-Client-IP, CF-Connecting-IP
- X-UserId, X-User-Id, X-User, X-Auth-User, X-Account-Id, X-Auth-Token, X-Api-User, X-Backend-User

## Attack technique writeups

- PortSwigger — "Server-Side Request Forgery" (related)
- HackTricks — Access Control bypasses
- HackerOne disclosed reports — `idor`, `bola`, `mass-assignment` tags
- PayloadsAllTheThings — Insecure Direct Object References
- Bishop Fox — "Broken Access Control" reports
- NCC Group — "Authentication and Authorization Patterns"

## Detection / SIEM

- Splunk queries for sequential ID enumeration:
  - `sourcetype=apache stats count by src_ip, uri | where count > 50`
- ELK / Sentinel — same patterns
- AWS CloudTrail — IAM action enumeration

## Best-practice resources

- Indirect references (not raw IDs)
- Centralize authorization in middleware / decorators (`@require_role`)
- Deny by default, opt-in privilege grants
- Treat every request as fresh — no implicit trust from prior requests
- Use UUIDs for object identifiers (not sequential ints)

## Frameworks reference

- Spring Security — `@PreAuthorize`, `@Secured`
- Django — `@login_required`, `@permission_required`
- Express — `casl`, `accesscontrol`
- Rails — `cancancan`, `pundit`
- ASP.NET — `[Authorize(Policy="...")]`
- Laravel — Policies + Gates

## Bug bounty programs with high IDOR yield

- HackerOne — Shopify, GitLab, Slack, Twitter (X), GitHub, Atlassian
- Bugcrowd — Tesla, Netflix
- Intigriti — European SaaS

## Cheat-sheet companions in this repo

- `scenarios/access-control/idor-read.md`
- `scenarios/access-control/idor-action.md`
- `scenarios/access-control/parameter-based-controls.md`
- `scenarios/access-control/method-bypass.md`
- `scenarios/access-control/header-bypass.md`
- `scenarios/access-control/multi-step-bypass.md`
- `scenarios/access-control/unprotected-functionality.md`
- `scenarios/access-control/mass-assignment.md`
- `scenarios/access-control/referer-bypass.md`
- `scenarios/access-control/data-leakage-redirect.md`
