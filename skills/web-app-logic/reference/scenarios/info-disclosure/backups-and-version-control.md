# Backup Files, Version Control, Source Code Exposure

## When this applies

- App is hosted directly out of a deployment directory that includes editor swap files, deploy scripts, or VCS metadata.
- `robots.txt` references backup directories; admin panels reference `/backup/`.
- Misconfigured Apache/nginx serves `.git/`, `.svn/`, or `.hg/` directories.

## Technique

Probe known backup extensions and VCS metadata paths. If `.git/HEAD` returns 200, dump the entire repository with `git-dumper` and grep history for secrets.

## Steps

### Backup file extensions

```
.bak
.backup
.old
.orig
.copy
.save
.tmp
~
.swp
.swo
_backup
-old
.1
.2
```

```bash
# Check robots.txt
curl https://target.com/robots.txt

# Test backup files
curl https://target.com/index.php.bak
curl https://target.com/config.php.old
curl https://target.com/backup/

# Directory listing
curl https://target.com/backup/
```

### Backup directory wordlist

```
backup
backups
old
bak
archive
temp
tmp
_backup
.backup
site-backup
www-backup
backup-2023
backup-2024
```

### Version control exposure

```
□ Test for .git directory
□ Check for .svn, .hg
□ Download repository if accessible
□ Scan commit history
□ Search for secrets in old commits
```

```bash
# Check for .git
curl https://target.com/.git/config
curl https://target.com/.git/HEAD

# Download repository
git-dumper https://target.com/.git/ output/

# Search history
git log -S "password" --all
git log -p | grep -i "secret"
```

### Configuration files

```
/.env
/config.php
/configuration.php
/settings.py
/web.config
/app/config/database.yml
/config/database.yml
/.config
/application.properties
```

### Source code discovery — quick recon

**Trigger**: Initial reconnaissance on any web application.

```bash
curl -I https://target.com/static/source_code.tar.gz
curl -I https://target.com/backup.zip
curl -I https://target.com/.git/HEAD
```

**Common Paths**:
- `/static/source_code.*`
- `/backup/`
- `/.git/`
- `/.env`
- `/app.zip`
- `/config.php.bak`

**Quick Script**:
```bash
#!/bin/bash
TARGET="$1"
for path in /static/source_code.tar.gz /backup.zip /.git/HEAD /.env /app.zip /config.php.bak; do
  echo "[*] Testing: $TARGET$path"
  curl -I -s "$TARGET$path" | head -1
done
```

### Information to extract

From backup files:
- Source code logic
- Hard-coded credentials
- API endpoints
- Database schema
- Business logic
- Authentication mechanisms
- Encryption keys

From version control:
- Complete source code history
- Removed secrets
- Developer information
- Commit messages
- Deleted files
- Configuration history
- Team structure

## Verifying success

- `.git/config` returns 200 with origin URL.
- `git-dumper` successfully reconstructs the repository.
- `git log -p | grep -i password` reveals hard-coded credentials.

## Common pitfalls

- Apache may have `mod_disclosure` or similar protection — try `/.git/HEAD` (smaller) before assuming `.git` is closed.
- Some apps put `.git` in the parent of the web root — try `../.git/HEAD` (where path traversal is possible).
- `.bak` extensions may be served as plain text by Apache (good); some servers may execute them — check `Content-Type`.

## Tools

- git-dumper, GitTools (`gitdumper.sh`)
- truffleHog, gitleaks, git-secrets
- ffuf with backup-extension wordlists
- nuclei `-t exposures/configs/`
