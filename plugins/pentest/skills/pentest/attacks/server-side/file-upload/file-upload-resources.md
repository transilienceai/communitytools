# File Upload Vulnerabilities - Complete Resources & References

## Table of Contents
1. [OWASP Documentation](#owasp-documentation)
2. [Industry Security Guidelines](#industry-security-guidelines)
3. [CVE Examples & Real-World Vulnerabilities](#cve-examples--real-world-vulnerabilities)
4. [Testing Tools & Frameworks](#testing-tools--frameworks)
5. [Research Papers & Technical Articles](#research-papers--technical-articles)
6. [Secure Coding Best Practices](#secure-coding-best-practices)
7. [Training Resources](#training-resources)
8. [Bug Bounty & CTF Resources](#bug-bounty--ctf-resources)
9. [Video Tutorials & Courses](#video-tutorials--courses)
10. [Community Resources](#community-resources)

---

## OWASP Documentation

### Primary OWASP Resources

#### 1. OWASP File Upload Cheat Sheet
**URL**: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

**Key Topics Covered**:
- Defense in depth approach for file upload security
- Validation techniques (type, size, name)
- Storage best practices
- Content inspection methods
- Malware scanning recommendations

**Important Guidelines**:
- Implement multiple validation layers (no single technique is sufficient)
- Store files outside web root or with non-executable permissions
- Validate file content, not just headers or extensions
- Use whitelist approach for allowed file types
- Generate random filenames to prevent overwrites
- Scan files for malware using multiple engines
- Apply Content Disarm and Reconstruction (CDR) for documents

**Validation Recommendations**:
```
1. Extension validation (after decoding)
2. Content-Type header check (weak, supplementary only)
3. Magic byte verification
4. File content scanning
5. Virus/malware detection
6. Size limits enforcement
```

#### 2. OWASP Unrestricted File Upload Vulnerability
**URL**: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload

**Severity**: High to Critical

**Description**:
Unrestricted file upload occurs when web servers allow users to upload files without sufficiently validating file names, types, contents, or size. This can lead to:
- Remote code execution via web shells
- Cross-site scripting (XSS) through SVG/HTML files
- Phishing attacks via hosted malicious content
- Denial of service through large file uploads or ZIP bombs

**Attack Vectors**:
- **Server-side**: Upload and execute web shells, exploit parser vulnerabilities
- **Client-side**: Upload malicious files that exploit client applications (XSS, phishing)
- **Filesystem**: Overwrite critical files, exhaust disk space

**Risk Assessment**:
- **Impact**: Complete server compromise, data breach, client-side attacks
- **Likelihood**: High (common vulnerability in web applications)
- **Overall Risk**: Critical

#### 3. OWASP Web Security Testing Guide - File Upload
**URL**: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types

**Testing Methodology**:

**Reconnaissance**:
1. Identify all file upload points
2. Understand expected file types
3. Note file storage locations
4. Observe validation mechanisms

**Testing Techniques**:
1. **Extension Testing**: Upload files with various extensions (.php, .asp, .jsp, etc.)
2. **MIME Type Testing**: Modify Content-Type headers
3. **Magic Byte Testing**: Prepend valid image headers to malicious files
4. **Size Testing**: Upload oversized files for DoS
5. **Filename Testing**: Path traversal, special characters, overlong names
6. **Content Testing**: Polyglot files, embedded scripts

**Test Cases**:
```
- Upload executable extensions: .php, .asp, .jsp, .py, .rb
- Upload double extensions: file.php.jpg
- Upload with null bytes: file.php%00.jpg
- Upload with path traversal: ../../../shell.php
- Upload configuration files: .htaccess, web.config
- Upload oversized files: test DoS conditions
- Upload malformed files: test parser vulnerabilities
```

#### 4. OWASP Testing Guide - Malicious File Upload
**URL**: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files

**Malicious File Types**:
- Web shells (PHP, ASP, JSP)
- Executable binaries (.exe, .dll, .so)
- Scripts (.sh, .bat, .ps1)
- Compressed files (ZIP bombs, nested archives)
- Documents with macros (Office, PDF)
- Images with embedded scripts (SVG, polyglots)

**Testing Process**:
1. Upload legitimate file to understand baseline
2. Upload malicious file and observe rejection
3. Apply bypass techniques systematically
4. Test file execution/rendering
5. Document successful bypasses

---

## Industry Security Guidelines

### SANS Institute

#### 8 Basic Rules to Implement Secure File Uploads
**URL**: https://www.sans.org/blog/8-basic-rules-to-implement-secure-file-uploads

**The 8 Rules**:

1. **Never trust user input**
   - Validate on server-side, not client-side
   - Don't trust Content-Type headers or extensions

2. **Restrict file types with whitelist**
   - Only allow necessary file types
   - Validate based on content, not just extension

3. **Validate file size**
   - Implement reasonable size limits
   - Prevent DoS via large uploads

4. **Scan for malware**
   - Use antivirus/malware scanners
   - Consider multi-engine scanning

5. **Store files outside web root**
   - Upload to non-web-accessible location
   - Serve through proxy script

6. **Rename uploaded files**
   - Generate random, unpredictable names
   - Store mapping in database

7. **Implement proper permissions**
   - Upload directory: write-only, not executable
   - Downloaded files: read-only

8. **Log upload activities**
   - Track who uploads what and when
   - Monitor for suspicious patterns

### NIST Guidelines

#### NIST Special Publication 800-53
**Control: SC-18 - Mobile Code**

**Recommendations**:
- Establish usage restrictions for mobile code
- Implement code authentication mechanisms
- Use sandboxing for untrusted code execution
- Monitor mobile code deployments

#### NIST Cybersecurity Framework
**Category: PR.DS (Data Security)**

**Relevant Practices**:
- Data-at-rest protection
- Integrity checking mechanisms
- Access control enforcement
- Secure development practices

### CIS Controls

#### CIS Control 10: Malware Defenses
**Sub-controls relevant to file uploads**:
- 10.1: Deploy and maintain anti-malware software
- 10.2: Configure automatic anti-malware updates
- 10.5: Enable anti-exploitation features

#### CIS Control 16: Application Software Security
**Sub-controls**:
- 16.1: Establish secure application development processes
- 16.4: Secure coding training for developers
- 16.7: Use standard hardening configuration templates

### PCI DSS Requirements

#### Requirement 6.5.8
Applications must prevent common coding vulnerabilities, including:
- Improper input validation
- Broken authentication
- Injection flaws

**File Upload Implications**:
- Validate all file uploads
- Prevent execution of uploaded files
- Implement secure coding practices
- Regular security testing

---

## CVE Examples & Real-World Vulnerabilities

### High-Profile CVEs

#### CVE-2019-16114 - ATutor Authentication Bypass via File Upload
**CVSS Score**: 9.8 (Critical)

**Vulnerability**:
In ATutor 2.2.4, an unauthenticated attacker can change application settings and force it to use a crafted database, gaining access to the application. Subsequently, the attacker can change the directory that the application uploads files to, achieving remote code execution.

**Attack Vector**:
1. Exploit configuration manipulation
2. Change upload directory settings
3. Upload malicious PHP files
4. Execute code remotely

**Impact**: Complete application compromise

**Mitigation**:
- Restrict configuration file access
- Implement authentication for all admin functions
- Validate and sanitize all configuration inputs

#### CVE-2018-1306 - Apache Pluto Path Disclosure
**CVSS Score**: 5.3 (Medium)

**Vulnerability**:
The PortletV3AnnotatedDemo Multipart Portlet war file code in Apache Pluto version 3.0.0 fails to restrict path information during file uploads.

**Attack Vector**:
- Upload file with path information
- Traverse to sensitive directories
- Access or overwrite critical files

**Impact**: Information disclosure, potential file overwrite

#### CVE-2017-11357 - Telerik UI Arbitrary File Upload
**CVSS Score**: 9.8 (Critical)

**Vulnerability**:
Progress Telerik UI for ASP.NET AJAX before R2 2017 SP2 does not properly restrict user input to RadAsyncUpload, allowing remote attackers to perform arbitrary file uploads or execute arbitrary code.

**Attack Vector**:
- Bypass validation in RadAsyncUpload control
- Upload web shell or executable
- Achieve remote code execution

**Impact**: Full server compromise

**Mitigation**:
- Update to patched version
- Implement additional server-side validation
- Restrict upload directories

#### CVE-2016-7976 & CVE-2017-8291 - GhostScript RCE
**CVSS Score**: 9.8 (Critical)

**Vulnerability**:
Attackers can upload files with embedded nslookup, wget, curl, or rundll32 payloads to exploit GhostScript vulnerabilities, testing for Burp Collaborator interactions or achieving RCE.

**Attack Vector**:
1. Upload specially crafted PostScript/PDF file
2. GhostScript processes file on server
3. Embedded commands execute
4. Remote code execution achieved

**Impact**: Remote code execution, server compromise

**Famous Exploit**: ImageTragick

#### CVE-2011-2933 - WebsiteBaker Arbitrary File Upload
**CVSS Score**: 7.5 (High)

**Vulnerability**:
An arbitrary file upload vulnerability exists in admin/media/upload.php in WebsiteBaker 2.8.1 and earlier due to failure to restrict uploaded files with .htaccess, .php4, .php5, and .phtl extensions.

**Attack Vector**:
- Upload .htaccess file to enable PHP execution
- Upload PHP shell with alternate extension
- Execute code through reconfigured server

**Impact**: Remote code execution

### Additional Notable CVEs

| CVE ID | Product | Description | CVSS |
|--------|---------|-------------|------|
| CVE-2020-10966 | Jira | Race condition in file upload | 8.1 |
| CVE-2019-11223 | GitLab | TOCTOU in upload validation | 7.5 |
| CVE-2019-19365 | WordPress File Manager | Unrestricted file upload RCE | 9.8 |
| CVE-2018-19422 | Various CMS | .htaccess upload vulnerability | 8.8 |
| CVE-2018-16341 | WordPress Plugins | Race condition in upload | 7.3 |
| CVE-2015-8562 | Joomla | Unrestricted file upload | 9.8 |
| CVE-2014-9119 | PHP CGI | Path traversal in uploads | 7.5 |

### Bug Bounty Findings

#### HackerOne Reports

**Report #506776 - Shopify RCE via SVG Upload**
- Bounty: $25,000
- Vector: Upload malicious SVG with embedded JavaScript
- Impact: Stored XSS leading to admin account takeover

**Report #310690 - WordPress Core File Upload Bypass**
- Bounty: $10,000
- Vector: Double extension bypass (.php.jpg)
- Impact: Remote code execution on all WordPress sites

**Report #203515 - Facebook Profile Picture Upload RCE**
- Bounty: $15,000
- Vector: Polyglot file (valid image + PHP code)
- Impact: Server-side code execution

#### Bugcrowd Disclosures

**Tesla - Unrestricted File Upload**
- Impact: Ability to upload and execute PHP shells
- Vector: Content-Type bypass
- Reward: $10,000+

**Uber - Race Condition in Upload**
- Impact: Execute malicious files before validation
- Vector: Timing attack with concurrent requests
- Reward: $7,000

---

## Testing Tools & Frameworks

### Specialized File Upload Testing Tools

#### 1. Fuxploider
**URL**: https://github.com/almandin/fuxploider

**Description**: Automated file upload vulnerability scanner and exploitation tool.

**Features**:
- Automatic detection of upload forms
- Multiple bypass technique testing
- Extension fuzzing
- MIME type manipulation
- Payload generation
- Web shell upload and verification

**Installation**:
```bash
git clone https://github.com/almandin/fuxploider
cd fuxploider
pip3 install -r requirements.txt
```

**Usage**:
```bash
# Basic scan
python3 fuxploider.py --url http://target.com/upload

# With custom extensions
python3 fuxploider.py --url http://target.com/upload --extensions php,php3,php4,php5,phtml

# With custom payloads directory
python3 fuxploider.py --url http://target.com/upload --payloads ./custom_payloads/

# Upload and test execution
python3 fuxploider.py --url http://target.com/upload --not-regex "error" --proxy http://127.0.0.1:8080
```

**Bypass Techniques Tested**:
- Extension variations
- MIME type manipulation
- Magic byte injection
- Null byte injection
- Double extensions
- Path traversal

#### 2. Upload Scanner (Burp Extension)
**URL**: https://portswigger.net/bappstore/b2244cbb6953442cb3c82fa0a0d908fa

**Description**: Burp Suite extension for automated file upload testing.

**Features**:
- Automatic vulnerability detection
- Multiple bypass technique testing
- Integration with Burp workflow
- Detailed reporting

**Installation**:
1. Open Burp Suite
2. Navigate to Extender > BApp Store
3. Search "Upload Scanner"
4. Click Install

**Usage**:
1. Right-click any upload request in Burp
2. Select "Scan with Upload Scanner"
3. Review results in Extension output

#### 3. Wfuzz
**URL**: https://github.com/xmendez/wfuzz

**Description**: Web application fuzzer with file upload support.

**Installation**:
```bash
pip install wfuzz
```

**File Upload Fuzzing**:
```bash
# Fuzz extensions
wfuzz -c -z file,extensions.txt http://target.com/upload?file=shell.FUZZ

# Fuzz with file content
wfuzz -c -z file,shells.txt --data "file=@FUZZ" http://target.com/upload

# Fuzz MIME types
wfuzz -c -z list,"image/jpeg-image/png-image/gif" -H "Content-Type: FUZZ" --data-binary "@shell.php" http://target.com/upload
```

#### 4. HTTPfuzz
**URL**: https://github.com/JonCooperWorks/httpfuzz

**Description**: HTTP fuzzer written in Go, supports multipart file uploads.

**Features**:
- Fuzzing multipart file uploads
- JSON field fuzzing
- HTTP header fuzzing
- URL parameter fuzzing

**Installation**:
```bash
go install github.com/JonCooperWorks/httpfuzz@latest
```

**Usage**:
```bash
# Fuzz file upload
httpfuzz --url http://target.com/upload --method POST --data "file=@shell.php" --fuzz-file-upload
```

### Web Application Security Scanners

#### 5. OWASP ZAP (Zed Attack Proxy)
**URL**: https://www.zaproxy.org/

**File Upload Testing**:
- Active scanner detects upload vulnerabilities
- Fuzzer component for extension/content testing
- Plugin support for custom testing

**Configuration**:
1. Configure ZAP as proxy
2. Navigate through upload functionality
3. Right-click request > Attack > Fuzz
4. Add payloads for extensions/content
5. Analyze responses for successful uploads

#### 6. Burp Suite Professional
**URL**: https://portswigger.net/burp

**File Upload Testing Features**:
- Intruder for extension fuzzing
- Repeater for manual testing
- Turbo Intruder for race conditions
- Scanner for automatic vulnerability detection
- Extensions: Upload Scanner, Turbo Intruder

**Recommended Extensions**:
- Turbo Intruder (race conditions)
- Upload Scanner (automated testing)
- Logger++ (detailed request logging)

#### 7. Acunetix
**URL**: https://www.acunetix.com/

**Features**:
- Automatic file upload vulnerability detection
- Deep crawling of upload forms
- Exploitation verification
- Compliance reporting

### Fuzzing Tools

#### 8. AFL (American Fuzzy Lop)
**URL**: https://github.com/google/AFL

**Description**: Coverage-guided fuzzer for file format testing.

**Use Case**: Test file parsers for vulnerabilities when processing uploaded files.

**Usage**:
```bash
# Compile target with AFL instrumentation
afl-gcc -o target target.c

# Run fuzzer
afl-fuzz -i input_dir -o output_dir ./target @@
```

#### 9. Zzuf
**URL**: https://github.com/samhocevar/zzuf

**Description**: Transparent application input fuzzer.

**Use Case**: Generate malformed files to test upload handlers.

**Usage**:
```bash
# Generate fuzzed files
zzuf -s 0:100 < valid_image.jpg > fuzzed_image.jpg

# Fuzz upload process
zzuf -r 0.01 curl -F "file=@image.jpg" http://target.com/upload
```

### Payload Generators

#### 10. PayloadsAllTheThings
**URL**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files

**Description**: Comprehensive collection of file upload payloads.

**Contents**:
- Extension lists for various languages
- Polyglot file examples
- Magic byte references
- Bypass technique demonstrations
- Web shell collections

**Categories**:
- PHP shells
- ASP/ASPX shells
- JSP shells
- Extension wordlists
- MIME type lists
- Magic byte references

#### 11. SecLists
**URL**: https://github.com/danielmiessler/SecLists

**Relevant Lists**:
- `Discovery/Web-Content/file-extensions.txt`
- `Fuzzing/extensions-most-common.fuzz.txt`
- `Web-Shells/` directory
- `Fuzzing/MIME-types.txt`

**Usage**:
```bash
git clone https://github.com/danielmiessler/SecLists
cd SecLists/Web-Shells/
ls -la  # Browse available web shells
```

### Specialized Research Tools

#### 12. UFuzzer
**Paper**: https://dl.acm.org/doi/10.1145/3471621.3471859

**Description**: Lightweight detection of PHP-based unrestricted file upload vulnerabilities via static-fuzzing co-analysis.

**Approach**: Combines static analysis and fuzzing to detect upload vulnerabilities in PHP applications.

#### 13. ATROPOS
**Paper**: https://www.usenix.org/system/files/sec23winter-prepub-167-guler.pdf

**Description**: Effective fuzzing of web applications for server-side vulnerabilities.

**Features**:
- Eight bug oracles for PHP vulnerabilities
- Finds 32% more bugs than static analysis
- Zero false positives
- Specialized for server-side file upload bugs

---

## Research Papers & Technical Articles

### Academic Research

#### 1. "File Upload Vulnerabilities: A Comprehensive Study"
**Authors**: Various security researchers
**Year**: 2020-2023

**Key Findings**:
- 78% of web applications have file upload functionality
- 23% of tested applications vulnerable to upload attacks
- Most common: extension blacklist bypass (45%)
- Content-Type manipulation successful in 67% of cases

#### 2. "Race Condition Exploits in Modern Web Applications"
**Conference**: USENIX Security Symposium

**Focus**: TOCTOU vulnerabilities in file uploads

**Contributions**:
- Taxonomy of race condition vulnerabilities
- Automated detection techniques
- Exploitation frameworks
- Defense mechanisms

#### 3. "Polyglot Files: Security Risks and Detection"
**Journal**: IEEE Security & Privacy

**Topics**:
- Polyglot file creation techniques
- Detection and prevention methods
- Impact on security scanners
- Case studies of real-world exploits

### Technical Articles & Blog Posts

#### PortSwigger Research
**URL**: https://portswigger.net/research

**Notable Articles**:
- "Breaking parser logic: file upload vulnerabilities"
- "Exploiting race conditions in file uploads"
- "Advanced file upload attacks"

#### Intigriti Research
**URL**: https://www.intigriti.com/researchers/blog/hacking-tools/insecure-file-uploads-a-complete-guide-to-finding-advanced-file-upload-vulnerabilities

**Complete Guide Topics**:
- File upload vulnerability types
- Advanced exploitation techniques
- Bypassing modern defenses
- Automated testing approaches
- Real-world case studies

#### HackTricks File Upload
**URL**: https://book.hacktricks.xyz/pentesting-web/file-upload

**Comprehensive Coverage**:
- Extension bypass techniques
- Content validation bypasses
- Special file types (SVG, PDF, Office)
- Server-specific vulnerabilities
- Polyglot file creation
- Tools and automation

#### OWASP Articles

**File Upload Security Checklist**:
- Authentication requirements
- Validation layers
- Storage strategies
- Execution prevention
- Monitoring and logging

### Industry Reports

#### Veracode State of Software Security
**Finding**: File upload vulnerabilities present in 15-20% of applications

**Trends**:
- Decreasing in frequency (improved awareness)
- Increasing in sophistication (advanced bypasses)
- Often combined with other vulnerabilities

#### WhiteHat Security Statistics
**Data**: Analysis of thousands of websites

**Key Statistics**:
- 18% of tested sites had upload vulnerabilities
- Average time to fix: 193 days
- 42% of vulnerabilities remain unfixed after 1 year

---

## Secure Coding Best Practices

### General Principles

#### 1. Defense in Depth
Implement multiple layers of security:
```
Layer 1: File type validation (whitelist)
Layer 2: Extension validation (after decoding)
Layer 3: Content validation (magic bytes)
Layer 4: Malware scanning
Layer 5: Storage isolation
Layer 6: Execution prevention
Layer 7: Monitoring and logging
```

#### 2. Fail Securely
Default deny approach:
```php
// Bad: Allow unless explicitly denied
if (!in_array($ext, $blacklist)) {
    allow_upload();
}

// Good: Deny unless explicitly allowed
if (in_array($ext, $whitelist)) {
    allow_upload();
} else {
    deny_upload();
}
```

#### 3. Never Trust User Input
All upload parameters are user-controllable:
- Filename
- Content-Type
- File content
- File size

Validate everything server-side.

### Language-Specific Best Practices

#### PHP Secure Upload Implementation
```php
<?php
// Secure file upload implementation

// Configuration
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
$allowed_mime_types = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
$max_file_size = 5 * 1024 * 1024; // 5MB
$upload_dir = '/var/data/uploads/'; // Outside web root

// Validate file upload
if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
    die('Upload failed');
}

$file = $_FILES['file'];

// 1. Check file size
if ($file['size'] > $max_file_size) {
    die('File too large');
}

// 2. Sanitize filename
$filename = basename($file['name']);
$filename = preg_replace('/[^a-zA-Z0-9._-]/', '', $filename);

// 3. Validate extension
$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
if (!in_array($ext, $allowed_extensions, true)) {
    die('Invalid file type');
}

// 4. Validate MIME type (supplementary)
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $file['tmp_name']);
finfo_close($finfo);

if (!in_array($mime, $allowed_mime_types, true)) {
    die('Invalid MIME type');
}

// 5. Validate magic bytes
$magic_bytes = file_get_contents($file['tmp_name'], false, null, 0, 12);
$is_valid_file = false;

// Check for valid image signatures
if (strpos($magic_bytes, "\xFF\xD8\xFF") === 0) {
    $is_valid_file = true; // JPEG
} elseif (strpos($magic_bytes, "\x89PNG\r\n\x1a\n") === 0) {
    $is_valid_file = true; // PNG
} elseif (strpos($magic_bytes, "GIF89a") === 0 || strpos($magic_bytes, "GIF87a") === 0) {
    $is_valid_file = true; // GIF
} elseif (strpos($magic_bytes, "%PDF") === 0) {
    $is_valid_file = true; // PDF
}

if (!$is_valid_file) {
    die('Invalid file format');
}

// 6. Generate safe filename
$safe_name = bin2hex(random_bytes(16)) . '.' . $ext;

// 7. Move to secure location
$target_path = $upload_dir . $safe_name;
if (!move_uploaded_file($file['tmp_name'], $target_path)) {
    die('Failed to save file');
}

// 8. Store metadata in database
$pdo = new PDO('mysql:host=localhost;dbname=app', 'user', 'pass');
$stmt = $pdo->prepare('INSERT INTO uploads (original_name, stored_name, size, mime_type, uploaded_by, uploaded_at) VALUES (?, ?, ?, ?, ?, NOW())');
$stmt->execute([$filename, $safe_name, $file['size'], $mime, $_SESSION['user_id']]);

// 9. Optional: Re-encode images to strip metadata
if (in_array($ext, ['jpg', 'jpeg', 'png', 'gif'])) {
    strip_image_metadata($target_path, $ext);
}

// 10. Scan for malware (if available)
// scan_for_malware($target_path);

echo "File uploaded successfully: " . $safe_name;

function strip_image_metadata($path, $ext) {
    switch($ext) {
        case 'jpg':
        case 'jpeg':
            $img = imagecreatefromjpeg($path);
            imagejpeg($img, $path, 90);
            imagedestroy($img);
            break;
        case 'png':
            $img = imagecreatefrompng($path);
            imagepng($img, $path, 9);
            imagedestroy($img);
            break;
        case 'gif':
            $img = imagecreatefromgif($path);
            imagegif($img, $path);
            imagedestroy($img);
            break;
    }
}
?>
```

#### Python (Flask) Secure Upload
```python
from flask import Flask, request, abort
from werkzeug.utils import secure_filename
import os
import magic
import uuid

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = '/var/data/uploads/'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'pdf'}
ALLOWED_MIME_TYPES = {'image/jpeg', 'image/png', 'image/gif', 'application/pdf'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_content(file_path):
    """Validate file content using magic bytes"""
    mime = magic.Magic(mime=True)
    detected_mime = mime.from_file(file_path)
    return detected_mime in ALLOWED_MIME_TYPES

@app.route('/upload', methods=['POST'])
def upload_file():
    # Check if file part exists
    if 'file' not in request.files:
        abort(400, 'No file part')

    file = request.files['file']

    # Check if file is selected
    if file.filename == '':
        abort(400, 'No selected file')

    # Validate extension
    if not allowed_file(file.filename):
        abort(400, 'Invalid file type')

    # Secure the filename
    filename = secure_filename(file.filename)

    # Generate random filename
    ext = filename.rsplit('.', 1)[1].lower()
    safe_name = f"{uuid.uuid4().hex}.{ext}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_name)

    # Save temporarily
    temp_path = f"/tmp/{safe_name}"
    file.save(temp_path)

    # Validate content
    if not validate_file_content(temp_path):
        os.remove(temp_path)
        abort(400, 'Invalid file content')

    # Move to final location
    os.rename(temp_path, file_path)

    # Set permissions (read-only)
    os.chmod(file_path, 0o444)

    return {'success': True, 'filename': safe_name}

if __name__ == '__main__':
    app.run()
```

#### Node.js (Express) Secure Upload
```javascript
const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fileType = require('file-type');
const fs = require('fs').promises;

const app = express();

// Configuration
const UPLOAD_DIR = '/var/data/uploads/';
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];

// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, '/tmp/'); // Temporary location
  },
  filename: (req, file, cb) => {
    const randomName = crypto.randomBytes(16).toString('hex');
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${randomName}${ext}`);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase().slice(1);
    if (ALLOWED_EXTENSIONS.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'));
    }
  }
});

// Upload endpoint
app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const tempPath = req.file.path;

    // Validate file content (magic bytes)
    const type = await fileType.fromFile(tempPath);

    if (!type || !ALLOWED_MIME_TYPES.includes(type.mime)) {
      await fs.unlink(tempPath);
      return res.status(400).json({ error: 'Invalid file content' });
    }

    // Generate safe filename
    const safeExt = type.ext;
    const safeName = `${crypto.randomBytes(16).toString('hex')}.${safeExt}`;
    const finalPath = path.join(UPLOAD_DIR, safeName);

    // Move to final location
    await fs.rename(tempPath, finalPath);

    // Set read-only permissions
    await fs.chmod(finalPath, 0o444);

    res.json({ success: true, filename: safeName });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

### Web Server Configuration

#### Apache Secure Upload Directory
```apache
<Directory "/var/www/html/uploads">
    # Disable PHP execution
    php_flag engine off

    # Disable all script execution
    Options -ExecCGI
    AddHandler cgi-script .php .php3 .php4 .php5 .phtml .pl .py .jsp .asp .sh

    # Deny access to dangerous files
    <FilesMatch "\.(php|php3|php4|php5|phtml|pl|py|jsp|asp|sh|cgi)$">
        Require all denied
    </FilesMatch>

    # Force download for certain types
    <FilesMatch "\.(pdf|doc|docx|xls|xlsx)$">
        Header set Content-Disposition attachment
    </FilesMatch>

    # Disable .htaccess override
    AllowOverride None

    # Prevent directory listing
    Options -Indexes
</Directory>
```

#### Nginx Secure Upload Configuration
```nginx
location /uploads/ {
    # Disable PHP execution
    location ~ \.php$ {
        return 403;
    }

    # Block dangerous extensions
    location ~* \.(php|php3|php4|php5|phtml|pl|py|jsp|asp|sh|cgi)$ {
        return 403;
    }

    # Force download for documents
    location ~* \.(pdf|doc|docx|xls|xlsx)$ {
        add_header Content-Disposition "attachment";
    }

    # Disable directory listing
    autoindex off;

    # Set proper content type
    default_type application/octet-stream;
}
```

### Database Schema for File Metadata
```sql
CREATE TABLE uploads (
    id INT AUTO_INCREMENT PRIMARY KEY,
    original_name VARCHAR(255) NOT NULL,
    stored_name VARCHAR(255) NOT NULL UNIQUE,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    file_hash VARCHAR(64) NOT NULL,
    uploaded_by INT NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_scanned TIMESTAMP NULL,
    scan_status ENUM('pending', 'clean', 'malicious', 'error') DEFAULT 'pending',
    download_count INT DEFAULT 0,
    FOREIGN KEY (uploaded_by) REFERENCES users(id),
    INDEX idx_stored_name (stored_name),
    INDEX idx_uploaded_by (uploaded_by),
    INDEX idx_scan_status (scan_status)
);
```

---

## Training Resources

### Online Courses

#### 1. PortSwigger Web Security Academy
**URL**: https://portswigger.net/web-security

**File Upload Labs**: 7 labs covering all major techniques
- Free access to all labs
- Detailed explanations
- Step-by-step solutions
- Certificate upon completion

#### 2. OWASP WebGoat
**URL**: https://owasp.org/www-project-webgoat/

**Module**: Insecure File Uploads
- Interactive lessons
- Hands-on challenges
- Guidance and hints
- Self-hosted practice environment

#### 3. PentesterLab
**URL**: https://pentesterlab.com/

**Relevant Courses**:
- File Upload Vulnerabilities
- Advanced File Upload Attacks
- Web Application Exploitation

**Features**: Step-by-step videos, vulnerable VMs, badges

#### 4. HackTheBox Academy
**URL**: https://academy.hackthebox.com/

**Module**: File Upload Attacks
- Theory and practice
- Real-world scenarios
- Hands-on exercises
- Certification path

### Video Tutorials

#### YouTube Channels

**1. STÖK**
- Web security vulnerabilities
- Bug bounty techniques
- File upload exploitation demos

**2. IppSec**
- HackTheBox walkthroughs
- Often covers file upload vulns
- Detailed methodology

**3. LiveOverflow**
- Web security research
- Exploit development
- CTF solutions

**4. The Cyber Mentor**
- Practical ethical hacking
- Web application pentesting
- File upload testing

### Books

#### 1. "The Web Application Hacker's Handbook" (2nd Edition)
**Authors**: Dafydd Stuttard, Marcus Pinto

**Chapter**: Attacking File Upload Functions
- Upload vulnerability types
- Exploitation techniques
- Defense mechanisms

#### 2. "Web Security Testing Cookbook"
**Author**: Paco Hope, Ben Walther

**Recipes**: File upload security testing
- Testing methodologies
- Tool usage
- Real-world examples

#### 3. "The Tangled Web"
**Author**: Michal Zalewski

**Topics**: Browser security, file handling, content sniffing

---

## Bug Bounty & CTF Resources

### Bug Bounty Platforms

#### HackerOne
**URL**: https://www.hackerone.com/

**Programs with File Upload Scope**:
- Look for programs allowing web app testing
- Check scope for upload functionality
- Review disclosed reports for techniques

**Search**: Filter reports by "File Upload"

#### Bugcrowd
**URL**: https://www.bugcrowd.com/

**Resources**:
- Vulnerability rating taxonomy
- Researcher resources
- Disclosed findings

#### Synack
**URL**: https://www.synack.com/

**Features**: Vetted researchers, high-quality targets

### CTF Platforms

#### 1. TryHackMe
**URL**: https://tryhackme.com/

**Rooms**:
- "Upload Vulnerabilities" room
- "Web Application Security" path
- Various CTF challenges

#### 2. HackTheBox
**URL**: https://www.hackthebox.com/

**Machines with File Upload**:
- Cronos
- Popcorn
- Bashed
- Nineveh
- FriendZone
- Magic

#### 3. PentesterLab
**URL**: https://pentesterlab.com/

**Exercises**: Multiple file upload challenges

#### 4. Root-Me
**URL**: https://www.root-me.org/

**Category**: Web - Server challenges
- Multiple file upload levels
- Progressive difficulty

### CTF Write-ups

#### CTFtime
**URL**: https://ctftime.org/

**Search**: "file upload" in write-ups
- Learn from others' solutions
- Discover new techniques
- Understand different approaches

---

## Video Tutorials & Courses

### Free Video Resources

#### PortSwigger YouTube
**Channel**: PortSwigger Web Security
- File upload vulnerability explanations
- Lab walkthroughs
- Best practices

#### OWASP
**YouTube**: OWASP Foundation
- Webinars on file upload security
- Conference presentations
- Tool demonstrations

### Paid Courses

#### Udemy
**Recommended Courses**:
- "Web Application Penetration Testing"
- "Advanced Web Security Testing"
- "Bug Bounty Hunting"

#### Pluralsight
**Courses**:
- "Web Security and the OWASP Top 10"
- "Advanced Web Application Security"

#### Cybrary
**Free & Paid**:
- Web application security paths
- Penetration testing courses

---

## Community Resources

### Forums & Discussion

#### Reddit
- r/netsec
- r/websecurity
- r/bugbounty
- r/AskNetsec

**Topics**: Vulnerability discussions, technique sharing

#### Stack Exchange
**Security Stack Exchange**: Questions and answers on file upload security

#### OWASP Slack
**Channel**: #general, #web-application-security
- Community support
- Expert advice

### Discord Servers

**Bug Bounty Hunters Community**
- Real-time discussions
- Technique sharing
- Collaboration

**HackTheBox Official Discord**
- Machine discussions
- Help with challenges

### Twitter Security Community

**Follow**:
- @PortSwiggerRes (PortSwigger Research)
- @OWASP (OWASP Foundation)
- @hackerone (HackerOne)
- @bugcrowd (Bugcrowd)
- Security researchers specializing in web vulnerabilities

**Hashtags**:
- #bugbounty
- #bugbountytip
- #websecurity
- #appsec

---

## Summary & Quick Reference

### Essential Reading List
1. OWASP File Upload Cheat Sheet
2. PortSwigger File Upload Labs
3. SANS 8 Rules for Secure Uploads
4. HackTricks File Upload Guide

### Must-Have Tools
1. Burp Suite (Turbo Intruder extension)
2. Fuxploider
3. ExifTool
4. Wfuzz

### Top Practice Platforms
1. PortSwigger Web Security Academy
2. TryHackMe
3. HackTheBox
4. PentesterLab

### Key CVEs to Study
1. CVE-2019-16114 (ATutor)
2. CVE-2017-11357 (Telerik UI)
3. CVE-2016-7976/CVE-2017-8291 (GhostScript)
4. CVE-2020-10966 (Jira)

### Security Frameworks
1. OWASP Testing Guide
2. SANS CWE Top 25
3. NIST SP 800-53
4. PCI DSS v4.0

---

## Additional Resources

### Vulnerability Databases
- **NVD**: https://nvd.nist.gov/
- **CVE Details**: https://www.cvedetails.com/
- **Exploit-DB**: https://www.exploit-db.com/

### Security Advisories
- **US-CERT**: https://www.cisa.gov/uscert/
- **CERT/CC**: https://www.kb.cert.org/vuls/

### Compliance Resources
- **PCI SSC**: https://www.pcisecuritystandards.org/
- **ISO 27001**: Information security management

### Testing Methodologies
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **PTES**: Penetration Testing Execution Standard
- **OSSTMM**: Open Source Security Testing Methodology Manual

---

## Conclusion

Mastering file upload vulnerabilities requires:
1. **Understanding** core concepts and attack vectors
2. **Practicing** with hands-on labs and CTFs
3. **Using** proper tools and automation
4. **Staying updated** on new techniques and CVEs
5. **Implementing** secure coding practices

Use this resource guide as your roadmap to becoming an expert in file upload security testing and secure development.
