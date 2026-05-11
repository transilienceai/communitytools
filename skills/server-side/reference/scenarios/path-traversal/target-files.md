# Path Traversal — Target Files (Linux / Windows / macOS / Cloud)

## When this applies

- Path traversal confirmed working — you can read arbitrary files.
- Goal: enumerate the most valuable files for credentials, config, network data.
- Adapt to the target's OS and stack.

## Technique

Sweep platform-specific files in priority order: credentials, config (DB / cloud), application source, logs, command history, cloud / container metadata.

## Steps

### Linux/Unix critical files

**Authentication & Users:**
```
/etc/passwd                    # User accounts (world-readable)
/etc/shadow                    # Password hashes (requires root)
/etc/group                     # Group information
/etc/sudoers                   # Sudo configuration
/etc/security/opasswd          # Old passwords
/root/.ssh/id_rsa             # Root SSH private key
/root/.ssh/authorized_keys    # Root SSH authorized keys
/home/[user]/.ssh/id_rsa      # User SSH private key
/home/[user]/.ssh/authorized_keys
```

**System Information:**
```
/etc/hostname                  # System hostname
/etc/hosts                     # DNS hosts file
/etc/resolv.conf              # DNS resolver configuration
/etc/network/interfaces       # Network configuration
/proc/version                 # Kernel version
/proc/self/environ            # Process environment variables
/proc/self/cmdline            # Process command line
/proc/self/status             # Process status
/proc/self/fd/[0-9]           # File descriptors
/proc/net/tcp                 # TCP connections
/proc/net/udp                 # UDP connections
/proc/net/arp                 # ARP table
```

**Application Configuration:**
```
/var/www/html/.env            # Laravel/Node environment
/var/www/.env                 # Alternative location
/etc/apache2/apache2.conf     # Apache configuration
/etc/apache2/sites-enabled/000-default.conf
/etc/nginx/nginx.conf         # Nginx configuration
/etc/nginx/sites-enabled/default
/etc/php/[version]/apache2/php.ini  # PHP configuration
/usr/local/etc/php.ini        # Alternative PHP config
```

**Database Configuration:**
```
/etc/mysql/my.cnf             # MySQL configuration
/var/lib/mysql/my.cnf         # Alternative MySQL config
/etc/postgresql/[version]/main/postgresql.conf
/var/lib/pgsql/data/postgresql.conf
```

**Application Files:**
```
/var/www/html/config.php      # Common config location
/var/www/html/wp-config.php   # WordPress
/var/www/html/configuration.php  # Joomla
/var/www/html/sites/default/settings.php  # Drupal
/var/www/html/.git/config     # Git repository config
/var/www/html/.git/HEAD       # Git HEAD
/var/log/apache2/access.log   # Apache access logs
/var/log/apache2/error.log    # Apache error logs
/var/log/nginx/access.log     # Nginx access logs
/var/log/nginx/error.log      # Nginx error logs
```

**Cloud & Container:**
```
/run/secrets/kubernetes.io/serviceaccount/token  # K8s token
/run/secrets/kubernetes.io/serviceaccount/namespace
/proc/self/cgroup             # Container detection
/proc/1/environ               # Init process environment
/.dockerenv                   # Docker environment marker
```

**Sensitive Data:**
```
/root/.bash_history           # Root command history
/home/[user]/.bash_history    # User command history
/root/.mysql_history          # MySQL command history
/root/.aws/credentials        # AWS credentials
/root/.aws/config             # AWS configuration
/home/[user]/.aws/credentials
/home/[user]/.ssh/known_hosts # SSH known hosts
```

### Windows target files

**System Information:**
```
C:\windows\win.ini            # Windows initialization (PoC)
C:\windows\system32\drivers\etc\hosts  # Hosts file
C:\windows\system32\license.rtf        # License (PoC)
C:\windows\system.ini         # System configuration
```

**Authentication & Credentials:**
```
C:\windows\repair\sam         # Backup SAM database
C:\windows\repair\system      # Backup system hive
C:\windows\system32\config\sam        # SAM database
C:\windows\system32\config\system     # System hive
C:\windows\system32\config\security   # Security hive
C:\Users\[user]\NTUSER.DAT    # User registry hive
```

**IIS Configuration:**
```
C:\inetpub\wwwroot\web.config # IIS application config
C:\windows\system32\inetsrv\config\applicationHost.config
C:\windows\system32\inetsrv\metabase.xml
C:\inetpub\logs\LogFiles\W3SVC1\  # IIS logs
```

**Application Configuration:**
```
C:\Program Files\[App]\config.xml
C:\Program Files (x86)\[App]\config.xml
C:\xampp\apache\conf\httpd.conf
C:\xampp\mysql\bin\my.ini
C:\wamp\bin\apache\apache[version]\conf\httpd.conf
```

**Sensitive Files:**
```
C:\Users\[user]\.aws\credentials
C:\Users\[user]\.ssh\id_rsa
C:\Users\Administrator\.ssh\id_rsa
C:\pagefile.sys               # Windows page file
C:\hiberfil.sys               # Hibernation file
```

### MacOS target files

```
/etc/passwd                   # User accounts
/etc/master.passwd           # Password hashes (requires root)
/private/etc/hosts           # Hosts file
/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist
/Users/[user]/.ssh/id_rsa    # SSH private key
/Users/[user]/.bash_history  # Command history
/Users/[user]/.aws/credentials
```

### OpenBSD target files

OpenBSD diverges from Linux for nearly every system-level config; default-named Linux files often don't exist. The high-value paths for arbitrary-read primitives:

```
/etc/relayd.conf                       # Native reverse-proxy config — reveals hidden vhosts (this is the one that matters)
/etc/httpd.conf                        # OpenBSD httpd(8) — NOT Apache
/etc/php-fpm.conf                      # PHP-FPM (when PHP is installed via pkg_add)
/etc/php-X.Y.ini                       # X.Y is the pkg version (e.g., /etc/php-7.4.ini)
/etc/mail/smtpd.conf                   # OpenSMTPD relay/auth — frequently leaks SMTP creds
/var/unbound/etc/unbound.conf          # Chrooted DNS resolver (NOT /etc/named.conf)
/var/unbound/etc/tls/control.pem       # unbound-control client certificate
/var/unbound/etc/tls/control.key       # ⚠ key — exfil enables remote DNS poisoning
/var/unbound/etc/tls/server.pem        # unbound-control server cert (validation chain)
/etc/pf.conf                           # Packet filter — firewall rules
/etc/doas.conf                         # doas (sudo replacement) policy — see linux-privesc/sudo-symlink.md
/etc/rc.conf.local                     # Service overrides (which daemons are enabled)
/var/cron/tabs/<user>                  # Per-user crontabs (different from /etc/crontab path on Linux)
```

The `/var/unbound/etc/tls/` cert+key pair is the gold ticket: combined they let you authenticate to the unbound-control TLS socket (default `localhost:8953`, occasionally exposed in lab setups) and inject DNS records (`local_data`) or re-route recursion (`forward_add`). Pairs with host-header-injection chains where a bot dereferences DNS-resolved URLs.

## Verifying success

- File content matches the expected format (`root:x:` for /etc/passwd, `[fonts]` for win.ini).
- Credentials extracted authenticate against the system.
- Configuration file reveals further attack surface (DB hosts, API keys).

## Common pitfalls

- `/etc/shadow` requires root; the web-app user typically can't read it.
- Windows `C:\windows\system32\config\sam` is locked at runtime — use VSS / NTBackup variants.
- Some files are not present in containers (e.g., no `/proc/net/arp` in lightweight images).

## Tools

- Burp Suite Repeater (per-file probe)
- Custom wordlists (filenames + paths)
- ffuf for path enumeration
