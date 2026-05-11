# Unprotected Functionality / Forced Browsing

## When this applies

- Admin pages exist but rely on "security through obscurity" (random URLs, hidden links).
- Admin URL discoverable via `robots.txt`, JavaScript, page source, or directory brute-force.
- Common in legacy applications and frameworks where developers forgot to add an `@RequireAdmin` annotation.

## Technique

Find the unprotected admin URL through reconnaissance, then access it directly with a non-admin (or no) session.

**Discovery:**
```bash
/robots.txt
/admin
/administrator
/admin.php
/admin-panel
/control-panel
/.git/config
/backup
```

| Path | Description |
|------|-------------|
| /admin | Standard admin panel |
| /administrator | Alternative admin panel |
| /admin-panel | Common naming |
| /admin.php | PHP admin |
| /admin.asp | ASP admin |
| /administrator-panel | Extended name |
| /control-panel | Alternative |
| /cpanel | Control panel |
| /manage | Management interface |
| /dashboard | Admin dashboard |

## Steps

Lab — Unprotected Admin (robots.txt):
```bash
# Navigate to
/robots.txt
# Then access
/administrator-panel
# Delete carlos
```

Lab — Unprotected Admin (Hidden URL):
```bash
# View page source, search for "admin"
# Find admin URL in JavaScript
# Navigate to discovered URL (e.g., /admin-abc123)
```

Brute-force discovery:
```bash
ffuf -w /usr/share/wordlists/dirb/big.txt \
     -u https://target.com/FUZZ \
     -mc 200,301,302 -fc 404
```

Source code analysis:
```bash
# Inspect every JS bundle for hard-coded admin paths
curl -s https://target.com/main.js | grep -E '/(admin|manage|panel)[^"]*'
```

## Verifying success

- Admin UI renders (admin-only links, "all users" tables, system controls).
- Privileged actions (delete user, view configuration, list all accounts) execute without 403.
- No redirect to login when accessing the discovered URL.

## Common pitfalls

- The admin URL may appear in `robots.txt` precisely to be excluded — check it first.
- JavaScript may reference admin URLs only in code paths gated by frontend role checks (which you don't trigger). Read every bundle.
- Some apps return `200` with an empty/generic page when unauthorized — diff response sizes against known-good admin views.

## Tools

- ffuf, dirsearch, gobuster
- Burp Site Map (passive crawl)
- `wget --spider --recursive`
- View source / browser DevTools (Network tab)
