# HTTP Request Smuggling — HTTP/2 Downgrade (H2.CL / H2.TE / H2 Tunneling)

## When this applies

- Front-end speaks HTTP/2; back-end speaks HTTP/1.1; the front-end downgrades requests.
- The downgrade serializer mishandles `Content-Length` (H2.CL) or injected `Transfer-Encoding` (H2.TE).
- HTTP/2 binary headers can carry CRLF for request tunneling.

## Technique

Inject `Content-Length: 0` (H2.CL) or `Transfer-Encoding: chunked` (H2.TE) at the HTTP/2 layer. After downgrade, the back-end sees the headers and acts on them — desync ensues. CRLF in HTTP/2 header names can carry a complete second request.

## Steps

### H2.CL — inject Content-Length in HTTP/2

Use Burp Repeater with HTTP/2 + Inspector to inject raw header:

```
:method POST
:path /
content-length: 0
```

Then add smuggled request in the body.

### H2.TE — inject Transfer-Encoding

```
:method POST
:path /
transfer-encoding: chunked
```

Then in the body:
```
0

GET /admin HTTP/1.1
Host: localhost
```

### H2 request tunneling (CRLF injection in header name)

```
foo: bar
Transfer-Encoding: chunked
```

The CRLF inside the HTTP/2 header value/name escapes when the front-end serializes to HTTP/1.1, smuggling a complete request.

### Mechanism

- HTTP/2 front-end downgrades to HTTP/1.1
- The downgrade fails to sanitize headers per RFC 7540
- Content-Length, Transfer-Encoding, or CRLF in headers leak through
- Back-end sees an unintended frame boundary

### Impact

- Particularly dangerous for modern infrastructures using HTTP/2 at the edge with HTTP/1.1 backends
- Often the first viable smuggling primitive on modern stacks (Cloudflare, AWS ALB, GCP)
- Bypasses front-end security entirely

## Verifying success

- Burp HTTP Request Smuggler reports H2.CL / H2.TE viable.
- Smuggled request returns response intended for `/admin` (or other restricted endpoint).
- Subsequent users' responses contain leaked content.

## Common pitfalls

- Many libraries (HTTP/2 stacks) refuse CRLF in header names — test against the specific server.
- Burp 2023.9+ supports the single-packet attack, which combines smuggling with race conditions.
- Some front-ends terminate HTTP/2 entirely and re-parse — the downgrade window may not exist.

## H2C upgrade smuggling — bypass front-end ACLs entirely

When the front is an HTTP/1.1 proxy (HAProxy ≤ 2.0.13, nginx without explicit `Connection close`, older Traefik / Apache mod_proxy) AND the backend speaks HTTP/2 cleartext (h2c), an attacker can request an HTTP/1.1 → HTTP/2 upgrade. The proxy returns `101 Switching Protocols` and stops inspecting subsequent bytes — every HTTP/2 frame after the upgrade flows raw to the backend, bypassing the proxy's `path_beg` / `path_end` / Host-header / authentication ACLs entirely.

```
GET / HTTP/1.1
Host: target
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
```

`101 Switching Protocols` ⇒ vulnerable. After the upgrade, send any HTTP/2 frames (including requests for ACL-denied paths).

Tooling: BishopFox `h2csmuggler.py` (https://github.com/BishopFox/h2csmuggler). When the target requires a specific `Host: <vhost>` without an /etc/hosts entry, patch the script to inject a hostname-override map.

Patched in HAProxy 2.0.14, 2.1+. nginx with `proxy_http_version 1.1` + `proxy_set_header Connection close` is safe. Modern envoy/traefik refuse h2c upgrades by default.

## Tools

- Burp Suite Repeater (HTTP/2 mode + Inspector)
- Burp HTTP Request Smuggler BApp
- h2spacex (raw HTTP/2 socket attacks)
- BishopFox h2csmuggler.py (h2c upgrade smuggling)
