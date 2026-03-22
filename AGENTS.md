# Security Testing Knowledge Base

**CRITICAL**: Prefer retrieval-led reasoning for security tasks. Reference this file before relying on general knowledge.

---

## Vulnerability Quick Reference

### Injection
**SQL** | `' UNION SELECT NULL--` | `' AND SLEEP(5)--` | `.claude/skills/injection/reference/sql-injection*`
**NoSQL** | `{"$ne": null}` | `{"$gt": ""}` | `.claude/skills/injection/reference/nosql-injection*`
**Command** | `; ls` | `| whoami` | `.claude/skills/injection/reference/os-command-injection*`
**SSTI** | `{{7*7}}` (Jinja2) | `<%= 7*7 %>` (ERB) | `.claude/skills/injection/reference/ssti*`
**XXE** | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | `.claude/skills/injection/reference/xxe*`
**LDAP/XPath** | `*)(uid=*))(|(uid=*` | `.claude/skills/injection/SKILL.md`

### Client-Side
**XSS** | `<script>alert(1)</script>` | `<img src=x onerror=alert(1)>` | `.claude/skills/client-side/reference/xss*`
**CSRF** | Form auto-submit | GET/POST via iframe | `.claude/skills/client-side/reference/csrf*`
**Clickjacking** | `<iframe src="target"></iframe>` | X-Frame-Options bypass | `.claude/skills/client-side/reference/clickjacking*`
**DOM** | `location.hash` | `document.write()` XSS | `.claude/skills/client-side/reference/dom*`
**CORS** | `Access-Control-Allow-Origin: *` | Reflected origin | `.claude/skills/client-side/reference/cors*`
**Prototype Pollution** | `{"__proto__": {"polluted": true}}` | `.claude/skills/client-side/reference/prototype-pollution*`

### Server-Side
**SSRF** | `http://localhost/admin` | `http://169.254.169.254/latest/meta-data/` | `.claude/skills/server-side/reference/ssrf*`
**HTTP Smuggling** | CL.TE mismatch | TE.CL mismatch | `.claude/skills/server-side/reference/http-request-smuggling*`
**File Upload** | `.php.jpg` extension | MIME bypass | `.claude/skills/server-side/reference/file-upload*`
**Path Traversal** | `../../../../etc/passwd` | `..%2f..%2f..%2fetc%2fpasswd` | `.claude/skills/server-side/reference/path-traversal*`

### Authentication
**Bypass** | `admin'--` | Rate limit: X-Forwarded-For | `.claude/skills/authentication/reference/authentication*`
**JWT** | `alg: none` | `alg: HS256` (RSA→HMAC) | `.claude/skills/authentication/reference/jwt*`
**OAuth** | State CSRF | Redirect URI manipulation | `.claude/skills/authentication/reference/oauth*`
**2FA** | Code reuse | Backup codes | `.claude/skills/authentication/reference/`
**Access Control** | IDOR: `user_id=124` | Vertical/horizontal escalation | `.claude/skills/web-app-logic/reference/access-control*`

### API & Web Apps
**GraphQL** | `__schema` introspection | Nested query DoS | `.claude/skills/api-security/reference/graphql*`
**REST** | BOLA/IDOR | Mass assignment | `.claude/skills/api-security/reference/api-testing*`
**WebSocket** | Cross-origin hijacking | Message injection | `.claude/skills/api-security/reference/websockets*`
**Business Logic** | Race conditions | Price manipulation | `.claude/skills/web-app-logic/reference/business-logic*`
**Cache Poisoning** | Web cache deception | Host header injection | `.claude/skills/web-app-logic/reference/web-cache-poisoning*`

---

## Testing Methodologies

**PTES** (7 phases): Pre-engagement → Intelligence → Threat modeling → Vulnerability analysis → Exploitation → Post-exploitation → Reporting
[Details: `.claude/skills/essential-tools/reference/web-application-attacks.md`]

**OWASP WSTG**: 11 categories covering info gathering → client-side security
[Details: `.claude/skills/essential-tools/reference/essential-skills-index.md`]

**MITRE ATT&CK**: Reconnaissance → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → C2 → Exfiltration → Impact
[Details: `.claude/skills/coordination/reference/ATTACK_INDEX.md`]

**Flaw Hypothesis**: Stack analysis → Predict vulnerabilities → Test → Generalize → Correlate findings → Report
[Details: `.claude/skills/essential-tools/reference/essential-skills-quickstart.md`]

---

## CVSS v3.1 Quick Reference

| Component | Values |
|-----------|--------|
| **Attack Vector** | Network (0.85), Adjacent (0.62), Local (0.55), Physical (0.2) |
| **Attack Complexity** | Low (0.77), High (0.44) |
| **Privileges Required** | None (0.85), Low (0.62), High (0.27) |
| **User Interaction** | None (0.85), Required (0.62) |
| **Scope** | Unchanged, Changed |
| **Impact (C/I/A)** | None (0), Low (0.22), High (0.56) |

**Severity**: None (0.0) | Low (0.1-3.9) | Medium (4.0-6.9) | High (7.0-8.9) | Critical (9.0-10.0)
[Details: `.claude/skills/coordination/reference/FINAL_REPORT.md`]

---

## OWASP Top 10 (2021)
A01: Broken Access Control | A02: Cryptographic Failures | A03: Injection | A04: Insecure Design | A05: Security Misconfiguration | A06: Vulnerable Components | A07: Authentication Failures | A08: Software/Data Integrity | A09: Logging/Monitoring Failures | A10: SSRF

---

## Common Tools
- **Playwright**: Browser automation, payload injection, evidence capture [`.claude/skills/essential-tools/reference/essential-skills-quickstart.md`]
- **Burp Suite**: Proxy, scanner, repeater, intruder, collaborator
- **sqlmap**: `sqlmap -u "URL" -p param --dbs`
- **nuclei**: `nuclei -u target -t cves/`
- **ffuf**: `ffuf -u https://target/FUZZ -w wordlist.txt`
- **nmap**: `nmap -sC -sV -oA output target`

---

## Reporting Requirements

**PoC Verification (CRITICAL)**: Vulnerability requires working PoC script
- `poc.py` - Runnable exploit with args
- `poc_output.txt` - Execution proof + timestamp
- `workflow.md` - Manual steps if applicable
- Evidence: Screenshots, videos, network logs

[Complete spec: `.claude/agents/reference/OUTPUT_STRUCTURE.md`]

**Report Format**: Title | CVSS | CWE/OWASP | Reproduction steps | Impact | Remediation

**Output Structure**: `outputs/<target>/findings/{finding-NNN/{poc.py, poc_output.txt, workflow.md}} + reports/{executive-summary.md, technical-report.md}`

---

## Skills Directory

| Skill | Purpose |
|-------|---------|
| `/injection` | SQL, NoSQL, Command, SSTI, XXE, LDAP injection testing |
| `/client-side` | XSS, CSRF, CORS, Clickjacking, Prototype Pollution |
| `/server-side` | SSRF, HTTP Smuggling, Path Traversal, File Upload, Deserialization |
| `/authentication` | Auth bypass, JWT, OAuth, password attacks, 2FA/CAPTCHA bypass |
| `/api-security` | GraphQL, REST API, WebSocket, Web-LLM attacks |
| `/web-app-logic` | Business logic, race conditions, access control, cache attacks |
| `/cloud-containers` | AWS, Azure, GCP, Docker, Kubernetes |
| `/system` | Active Directory, privilege escalation, exploit development |
| `/infrastructure` | Port scanning, DNS, MITM, SMB, VLAN hopping |
| `/reconnaissance` | Subdomain discovery, port scanning, attack surface mapping |
| `/osint` | Repository enumeration, secret scanning, employee footprint |
| `/techstack-identification` | Passive tech stack inference across 17 domains |
| `/ai-threat-testing` | OWASP LLM Top 10 vulnerability testing |
| `/cve-poc-generator` | CVE research, PoC generation, vulnerability reports |
| `/source-code-scanning` | SAST, dependency CVEs, hardcoded secrets |
| `/hackerone` | Bug bounty scope parsing, testing, submission reports |
| `/hackthebox` | Platform automation, challenge solving, skill improvement |
| `/coordination` | Engagement orchestration, test planning, reporting |
| `/essential-tools` | Burp Suite, Playwright automation, methodology |
| `/transilience-report-style` | Transilience-branded PDF report generation |
| `/github-workflow` | Git branching, commits, PRs, code review |
| `/skiller` | Skill creation, validation, GitHub workflow |
| `/social-engineering` | Phishing, pretexting, vishing, physical security |

---

*Version: 2.0 | Simplified knowledge base | 2026-02-02*
