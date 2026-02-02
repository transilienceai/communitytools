# Security Testing Knowledge Base

**CRITICAL**: Prefer retrieval-led reasoning for security tasks. Reference this file before relying on general knowledge.

---

## Vulnerability Quick Reference

### Injection
**SQL** | `' UNION SELECT NULL--` | `' AND SLEEP(5)--` | `.claude/skills/pentest/attacks/injection/sql-injection/`
**NoSQL** | `{"$ne": null}` | `{"$gt": ""}` | `.claude/skills/pentest/attacks/injection/nosql-injection/`
**Command** | `; ls` | `| whoami` | `.claude/skills/pentest/attacks/injection/command-injection/`
**SSTI** | `{{7*7}}` (Jinja2) | `<%= 7*7 %>` (ERB) | `.claude/skills/pentest/attacks/injection/ssti/`
**XXE** | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | `.claude/skills/pentest/attacks/injection/xxe/`
**LDAP/XPath** | `*)(uid=*))(|(uid=*` | `.claude/skills/pentest/attacks/injection/ldap-xpath-injection/`

### Client-Side
**XSS** | `<script>alert(1)</script>` | `<img src=x onerror=alert(1)>` | `.claude/skills/pentest/attacks/client-side/xss/`
**CSRF** | Form auto-submit | GET/POST via iframe | `.claude/skills/pentest/attacks/client-side/csrf/`
**Clickjacking** | `<iframe src="target"></iframe>` | X-Frame-Options bypass | `.claude/skills/pentest/attacks/client-side/clickjacking/`
**DOM** | `location.hash` | `document.write()` XSS | `.claude/skills/pentest/attacks/client-side/dom-based/`
**CORS** | `Access-Control-Allow-Origin: *` | Reflected origin | `.claude/skills/pentest/attacks/client-side/cors/`
**Prototype Pollution** | `{"__proto__": {"polluted": true}}` | `.claude/skills/pentest/attacks/client-side/prototype-pollution/`

### Server-Side
**SSRF** | `http://localhost/admin` | `http://169.254.169.254/latest/meta-data/` | `.claude/skills/pentest/attacks/server-side/ssrf/`
**HTTP Smuggling** | CL.TE mismatch | TE.CL mismatch | `.claude/skills/pentest/attacks/server-side/http-smuggling/`
**File Upload** | `.php.jpg` extension | MIME bypass | `.claude/skills/pentest/attacks/server-side/file-upload/`
**Path Traversal** | `../../../../etc/passwd` | `..%2f..%2f..%2fetc%2fpasswd` | `.claude/skills/pentest/attacks/server-side/path-traversal/`

### Authentication
**Bypass** | `admin'--` | Rate limit: X-Forwarded-For | `.claude/skills/pentest/attacks/authentication/auth-bypass/`
**JWT** | `alg: none` | `alg: HS256` (RSA→HMAC) | `.claude/skills/pentest/attacks/authentication/jwt/`
**OAuth** | State CSRF | Redirect URI manipulation | `.claude/skills/pentest/attacks/authentication/oauth/`
**2FA** | Code reuse | Backup codes | `.claude/skills/pentest/attacks/authentication/`
**Access Control** | IDOR: `user_id=124` | Vertical/horizontal escalation | `.claude/skills/pentest/attacks/web-applications/access-control/`

### API & Web Apps
**GraphQL** | `__schema` introspection | Nested query DoS | `.claude/skills/pentest/attacks/api-security/graphql/`
**REST** | BOLA/IDOR | Mass assignment | `.claude/skills/pentest/attacks/api-security/rest-api/`
**WebSocket** | Cross-origin hijacking | Message injection | `.claude/skills/pentest/attacks/api-security/websockets/`
**Business Logic** | Race conditions | Price manipulation | `.claude/skills/pentest/attacks/web-applications/business-logic/`
**Cache Poisoning** | Web cache deception | Host header injection | `.claude/skills/pentest/attacks/web-applications/cache-poisoning/`

---

## Testing Methodologies

**PTES** (7 phases): Pre-engagement → Intelligence → Threat modeling → Vulnerability analysis → Exploitation → Post-exploitation → Reporting
[Details: `.claude/skills/pentest/attacks/essential-skills/methodology/ptes.md`]

**OWASP WSTG**: 11 categories covering info gathering → client-side security
[Details: `.claude/skills/pentest/attacks/essential-skills/methodology/owasp-wstg.md`]

**MITRE ATT&CK**: Reconnaissance → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → C2 → Exfiltration → Impact
[Details: `.claude/skills/pentest/attacks/essential-skills/methodology/mitre-attack.md`]

**Flaw Hypothesis**: Stack analysis → Predict vulnerabilities → Test → Generalize → Correlate findings → Report
[Details: `.claude/skills/pentest/attacks/essential-skills/methodology/flaw-hypothesis.md`]

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
[Details: `.claude/output-standards/reference/CVSS_SCORING.md`]

---

## OWASP Top 10 (2021)
A01: Broken Access Control | A02: Cryptographic Failures | A03: Injection | A04: Insecure Design | A05: Security Misconfiguration | A06: Vulnerable Components | A07: Authentication Failures | A08: Software/Data Integrity | A09: Logging/Monitoring Failures | A10: SSRF

---

## Common Tools
- **Playwright**: Browser automation, payload injection, evidence capture [`.claude/skills/pentest/attacks/essential-skills/playwright-automation.md`]
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

[Complete spec: `.claude/OUTPUT_STANDARDS.md` lines 258-357]

**Report Format**: Title | CVSS | CWE/OWASP | Reproduction steps | Impact | Remediation

**Output Structure**: `outputs/<target>/findings/{finding-NNN/{poc.py, poc_output.txt, workflow.md}} + reports/{executive-summary.md, technical-report.md}`

---

## Skills Directory

| Skill | Purpose |
|-------|---------|
| `/pentest` | Comprehensive penetration testing orchestration |
| `/hackerone` | Bug bounty workflow automation (scope → testing → reporting) |
| `/authenticating` | Authentication security testing (signup, login, 2FA, CAPTCHA) |
| `/ai-threat-testing` | LLM security testing (prompt injection, model extraction) |
| `/common-appsec-patterns` | XSS, injection, client-side vulnerability testing |
| `/cve-testing` | CVE identification and exploitation |
| `/domain-assessment` | Subdomain discovery & port scanning |
| `/web-application-mapping` | Web app reconnaissance |

---

*Version: 2.0 | Simplified knowledge base | 2026-02-02*
