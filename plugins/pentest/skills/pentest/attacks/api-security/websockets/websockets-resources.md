# WebSockets Security - Complete Resources Guide

**Comprehensive collection of resources for mastering WebSocket security testing**

---

## Table of Contents
1. [Official Standards & Documentation](#official-standards--documentation)
2. [OWASP Resources](#owasp-resources)
3. [Industry Standards & Guidelines](#industry-standards--guidelines)
4. [CVE Database & Advisories](#cve-database--advisories)
5. [Tools & Frameworks](#tools--frameworks)
6. [Research Papers & Articles](#research-papers--articles)
7. [Training Platforms](#training-platforms)
8. [Bug Bounty Programs](#bug-bounty-programs)
9. [Vulnerable Applications](#vulnerable-applications)
10. [Community & Forums](#community--forums)

---

## Official Standards & Documentation

### RFC 6455 - The WebSocket Protocol
- **URL:** https://datatracker.ietf.org/doc/html/rfc6455
- **Description:** Official IETF specification for the WebSocket protocol
- **Key Sections:**
  - Section 1.3: Opening Handshake
  - Section 4: Opening Handshake (Detailed)
  - Section 5: Data Framing
  - Section 7: Closing the Connection
  - Section 10: Security Considerations

**Key Security Highlights:**
- Origin-based security model limitations
- Masking requirement for client-to-server messages
- Authentication challenges
- Privacy considerations

### MDN Web Docs - WebSocket API
- **URL:** https://developer.mozilla.org/en-US/docs/Web/API/WebSocket
- **Description:** Comprehensive JavaScript WebSocket API documentation
- **Coverage:**
  - Constructor and properties
  - Methods (send, close)
  - Events (open, message, error, close)
  - Security considerations
  - Examples and best practices

### W3C WebSocket API Specification
- **URL:** https://websockets.spec.whatwg.org/
- **Description:** Living standard for WebSocket API
- **Focus:** Client-side implementation requirements

---

## OWASP Resources

### OWASP WebSocket Security Cheat Sheet
- **URL:** https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html
- **Description:** Comprehensive security guide for WebSocket implementation
- **Topics Covered:**
  - Handshake security
  - Authentication and authorization
  - Input validation
  - Transport layer security
  - Origin validation
  - Error handling
  - Rate limiting

**Key Recommendations:**
1. Validate Origin header during handshake
2. Implement CSRF tokens or equivalent
3. Use authentication beyond just cookies
4. Validate and sanitize all input
5. Use wss:// (WebSocket Secure) in production
6. Implement rate limiting
7. Set message size limits
8. Log security events

### OWASP Testing Guide - WebSocket Testing
- **URL:** https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/10-Testing_WebSockets
- **Description:** Methodology for testing WebSocket security
- **Testing Areas:**
  - Origin validation testing
  - Input validation testing
  - Authentication testing
  - Authorization testing
  - Confidentiality testing

### OWASP Top 10
- **Relevant Categories:**
  - **A01:2021 - Broken Access Control**: Authorization bypass via WebSockets
  - **A03:2021 - Injection**: XSS, SQLi, Command Injection via WebSocket messages
  - **A07:2021 - Identification and Authentication Failures**: Weak WebSocket authentication
  - **A08:2021 - Software and Data Integrity Failures**: Message tampering

---

## Industry Standards & Guidelines

### NIST Guidelines

#### NIST SP 800-63B - Digital Identity Guidelines
- **URL:** https://pages.nist.gov/800-63-3/sp800-63b.html
- **Relevance:** Authentication requirements for WebSocket connections
- **Key Sections:**
  - Section 4: Authenticator Assurance Levels
  - Section 5: Authenticator and Verifier Requirements
  - Section 6: Authenticator Lifecycle Management

#### NIST Cybersecurity Framework
- **URL:** https://www.nist.gov/cyberframework
- **Functions Relevant to WebSockets:**
  - **Identify**: Asset management, risk assessment
  - **Protect**: Access control, data security
  - **Detect**: Anomaly detection, security monitoring
  - **Respond**: Incident response
  - **Recover**: Recovery planning

### PCI DSS (Payment Card Industry Data Security Standard)

**Relevant Requirements:**
- **Requirement 6.5.1**: Injection flaws (XSS, SQLi via WebSockets)
- **Requirement 6.5.7**: Cross-site request forgery (CSWSH)
- **Requirement 6.5.10**: Broken authentication
- **Requirement 4**: Encrypt transmission of cardholder data (wss://)

**Testing Considerations:**
- Ensure WebSocket connections transmitting payment data use TLS
- Validate CSWSH protections for payment-related WebSocket endpoints
- Test input validation for all WebSocket messages handling cardholder data

### ISO/IEC 27001 - Information Security Management

**Relevant Controls:**
- **A.9**: Access Control
- **A.13**: Communications Security
- **A.14**: System Acquisition, Development and Maintenance
- **A.16**: Information Security Incident Management

### CWE (Common Weakness Enumeration)

**WebSocket-Related CWEs:**
- **CWE-79**: Improper Neutralization of Input During Web Page Generation (XSS)
- **CWE-89**: Improper Neutralization of Special Elements used in an SQL Command (SQLi)
- **CWE-352**: Cross-Site Request Forgery (CSWSH)
- **CWE-287**: Improper Authentication
- **CWE-284**: Improper Access Control
- **CWE-306**: Missing Authentication for Critical Function
- **CWE-345**: Insufficient Verification of Data Authenticity
- **CWE-400**: Uncontrolled Resource Consumption (DoS)
- **CWE-770**: Allocation of Resources Without Limits or Throttling

### CAPEC (Common Attack Pattern Enumeration and Classification)

**WebSocket Attack Patterns:**
- **CAPEC-18**: XSS Targeting Non-Script Elements
- **CAPEC-63**: Cross-Site Scripting (XSS)
- **CAPEC-66**: SQL Injection
- **CAPEC-111**: JSON Hijacking
- **CAPEC-384**: Application API Message Manipulation
- **CAPEC-385**: Transaction or Event Tampering via Application API Manipulation

---

## CVE Database & Advisories

### Critical WebSocket Vulnerabilities

#### CVE-2024-55591: Node.js WebSocket Authentication Bypass (FortiOS/FortiProxy)
- **CVSS:** 9.8 (Critical)
- **Description:** Authentication bypass in Node.js WebSocket module
- **Impact:** Remote attackers can escalate privileges to super-admin
- **Affected:** FortiOS, FortiProxy, Node.js `ws` module
- **Advisory:** https://www.fortiguard.com/psirt/FG-IR-25-001
- **Exploitation:** Crafted WebSocket handshake exploits alternate authentication path
- **Remediation:** Update to patched versions
- **Detection:** Monitor for anomalous WebSocket handshake patterns

#### CVE-2018-1270: Spring Framework RCE via STOMP WebSocket
- **CVSS:** 9.8 (Critical)
- **Description:** Remote Code Execution via crafted STOMP messages over WebSocket
- **Impact:** Complete server compromise
- **Affected:** Spring Framework 5.0 to 5.0.4, 4.3 to 4.3.14
- **Advisory:** https://spring.io/security/cve-2018-1270
- **Exploitation:** Send malicious serialized objects via STOMP messages
- **Remediation:** Upgrade to Spring Framework 5.0.5+ or 4.3.15+
- **Prevention:** Validate and sanitize WebSocket message content, use safe deserialization

#### Gitpod Cross-Site WebSocket Hijacking (2023)
- **CVSS:** 8.1 (High)
- **Description:** Missing CSRF protection and origin validation on WebSocket handshake
- **Impact:** Full account takeover, access to all user workspaces and code
- **Affected:** Gitpod cloud development platform
- **Exploitation:** Host malicious page that hijacks victim's WebSocket connection
- **Remediation:** Implement CSRF tokens, validate Origin header
- **Resources:** https://pentest-tools.com/blog/cross-site-websocket-hijacking-cswsh

#### WebSocket Data Exposure via Wildcard Injection
- **CVSS:** 7.5 (High)
- **Description:** Applications accept wildcard (*) in WebSocket parameters, exposing all data
- **Impact:** Unauthorized access to all users' data, privacy breach
- **Example:** Sending `{"userId":"*","projectId":"*"}` returns all notifications
- **Exploitation:** Replace specific IDs with wildcards in WebSocket messages
- **Prevention:** Validate all input parameters, implement strict access controls
- **Real-World:** Multiple SaaS platforms affected in 2023-2024

### CVE Databases

#### National Vulnerability Database (NVD)
- **URL:** https://nvd.nist.gov/
- **Search:** "WebSocket" or specific product names
- **Features:** CVSS scores, CPE identifiers, references

#### CVE Details
- **URL:** https://www.cvedetails.com/
- **Search:** https://www.cvedetails.com/vulnerability-search.php
- **Filters:** Search for "WebSocket", "ws", "Socket.IO"

#### Exploit Database
- **URL:** https://www.exploit-db.com/
- **Search:** WebSocket, STOMP, Socket.IO
- **Features:** Proof-of-concept exploits, vulnerable code examples

#### VulnDB
- **URL:** https://vulndb.cyberriskanalytics.com/
- **Description:** Commercial vulnerability database with detailed advisories

---

## Tools & Frameworks

### Burp Suite
- **Website:** https://portswigger.net/burp
- **Type:** Commercial (Pro) and Free (Community)
- **Features:**
  - WebSocket message interception
  - WebSocket history
  - Repeater for message manipulation
  - Collaborator for out-of-band testing
  - Scanner (Pro only)
- **Extensions:**
  - **SocketSleuth**: Enhanced WebSocket testing
  - **WebSocket Turbo Intruder**: Automated fuzzing
  - **Autorize**: Authorization testing
  - **Logger++**: Advanced logging

**Download:** https://portswigger.net/burp/releases/community

### OWASP ZAP (Zed Attack Proxy)
- **Website:** https://www.zaproxy.org/
- **Type:** Free and Open Source
- **Features:**
  - WebSocket message interception
  - Automated scanning
  - Fuzzing capabilities
  - Python API for scripting
  - Active community
- **Add-ons:**
  - WebSocket Passive Scanner
  - Advanced Active Scan Rules
  - Fuzzer

**Download:** https://www.zaproxy.org/download/
**Documentation:** https://www.zaproxy.org/docs/desktop/addons/websockets/

### wscat
- **Repository:** https://github.com/websockets/wscat
- **Type:** Free CLI tool (npm package)
- **Features:**
  - Connect to WebSocket endpoints
  - Send/receive messages interactively
  - Custom headers support
  - Proxy support
- **Installation:** `npm install -g wscat`
- **Usage:** `wscat -c wss://target.com/chat`

### websocat
- **Repository:** https://github.com/vi/websocat
- **Type:** Free CLI tool
- **Features:**
  - Advanced WebSocket client
  - Binary data support
  - Port forwarding
  - SOCKS proxy support
  - Logging capabilities
- **Installation:** Via cargo, brew, or binary download
- **Usage:** `websocat wss://target.com/chat`

### Python websockets Library
- **Repository:** https://github.com/python-websockets/websockets
- **Type:** Free Python library
- **Features:**
  - Async/await support
  - Client and server implementations
  - Custom headers
  - Binary support
- **Installation:** `pip install websockets`
- **Documentation:** https://websockets.readthedocs.io/

### Socket.IO Tester
- **Repository:** https://github.com/socketio/socket.io-client
- **Type:** JavaScript library for Socket.IO testing
- **Usage:** Test Socket.IO (WebSocket + fallbacks) implementations
- **Installation:** `npm install socket.io-client`

### Nuclei Templates
- **Repository:** https://github.com/projectdiscovery/nuclei-templates
- **WebSocket Templates:** `websockets/` directory
- **Features:** Automated vulnerability scanning with YAML templates
- **Example Templates:**
  - WebSocket message manipulation
  - CSWSH detection
  - Authentication bypass
- **Usage:** `nuclei -u wss://target.com -t websockets/`

### Chrome/Firefox DevTools
- **Type:** Built-in browser developer tools
- **Features:**
  - Network tab with WebSocket filter
  - View WebSocket frames
  - Inspect messages
  - Monitor connection status
- **Access:** F12 → Network → Filter: WS

### Wireshark
- **Website:** https://www.wireshark.org/
- **Type:** Free network protocol analyzer
- **Features:**
  - Capture WebSocket traffic
  - Decode WebSocket frames
  - Filter: `websocket`
  - TLS decryption (with keys)

---

## Research Papers & Articles

### Black Hat & DEF CON Presentations

#### "Cross-Site WebSocket Hijacking (CSWSH)"
- **Author:** Christian Schneider
- **Conference:** OWASP
- **Year:** 2013
- **URL:** https://www.christian-schneider.net/CrossSiteWebSocketHijacking.html
- **Topics:** Discovery and exploitation of CSWSH vulnerabilities
- **Key Findings:** Most WebSocket implementations lack CSRF protection

#### "Real-Time Web Application Security: WebSocket Testing"
- **Authors:** Various security researchers
- **Conferences:** Black Hat, DEF CON (multiple years)
- **Topics:** WebSocket-specific attack vectors, tooling, real-world exploits

### Academic Papers

#### "Security Analysis of WebSocket Protocol Implementation"
- **Authors:** Harri Kuosmanen
- **Institution:** Theseus University of Applied Sciences
- **Year:** 2016
- **URL:** https://www.theseus.fi/bitstream/handle/10024/113390/Harri+Kuosmanen+-+Masters+thesis+-+Security+Testing+of+WebSockets+-+Final.pdf
- **Topics:**
  - Comprehensive security testing methodology
  - Tool analysis (ZAP, Burp)
  - Vulnerability case studies

#### "WebSocket Security: An Analysis of WebSocket Security"
- **Topic:** Authentication, authorization, and session management in WebSockets
- **Focus:** Comparison with traditional HTTP security models

### Industry Blog Posts

#### PortSwigger Research
- **URL:** https://portswigger.net/research
- **Topics:**
  - Testing for WebSocket vulnerabilities
  - Manipulating WebSocket traffic
  - Cross-site WebSocket hijacking techniques
  - Real-world vulnerability discoveries

#### ULTRA RED Blog - "The Dark Side of WebSockets"
- **URL:** https://www.ultrared.ai/blog/the-dark-side-of-websockets
- **Topics:**
  - CVE-2024-55591 analysis
  - Real-time communication risks
  - Common WebSocket vulnerabilities
  - Exploitation techniques

#### Bright Security - "WebSocket Security: Top 8 Vulnerabilities"
- **URL:** https://brightsec.com/blog/websocket-security-top-vulnerabilities/
- **Topics:**
  - CSWSH
  - Authentication flaws
  - Injection attacks
  - DoS vulnerabilities
  - Prevention strategies

#### Snyk Labs - "SocketSleuth: Improving Security Testing for WebSocket Applications"
- **URL:** https://snyk.io/blog/socketsleuth-improving-security-testing-for-websocket-applications/
- **Topics:**
  - Burp Suite extension development
  - Automated WebSocket testing
  - Tool demonstration

#### Pentest-Tools Blog - "Cross-Site WebSocket Hijacking (CSWSH)"
- **URL:** https://pentest-tools.com/blog/cross-site-websocket-hijacking-cswsh
- **Topics:**
  - Understanding CSWSH
  - Exploitation methodology
  - Real-world examples (Gitpod)
  - Prevention techniques

#### HackTricks - WebSocket Attacks
- **URL:** https://book.hacktricks.xyz/pentesting-web/websocket-attacks
- **Topics:**
  - Pentesting methodology
  - Common attack vectors
  - Tool usage examples
  - Payload collections

---

## Training Platforms

### PortSwigger Web Security Academy
- **URL:** https://portswigger.net/web-security/websockets
- **Cost:** Free
- **Labs:**
  - Manipulating WebSocket messages to exploit vulnerabilities
  - Manipulating the WebSocket handshake to exploit vulnerabilities
  - Cross-site WebSocket hijacking
- **Features:**
  - Interactive labs
  - Video solutions
  - Community discussions
  - Certificates upon completion
- **Recommended Path:**
  1. Learn WebSocket fundamentals
  2. Complete all 3 WebSocket labs
  3. Review related topics (XSS, CSRF)

### HackTheBox
- **URL:** https://www.hackthebox.com/
- **Cost:** Free tier + Paid VIP
- **WebSocket Challenges:**
  - Multiple boxes and challenges featuring WebSocket vulnerabilities
  - Real-world scenario simulations
- **Skills Developed:**
  - Reconnaissance
  - Exploitation
  - Post-exploitation

### TryHackMe
- **URL:** https://tryhackme.com/
- **Cost:** Free tier + Paid subscription
- **WebSocket Content:**
  - Web security rooms
  - API security modules
  - Real-time application testing
- **Learning Path:** Guided paths from beginner to advanced

### PentesterLab
- **URL:** https://pentesterlab.com/
- **Cost:** Paid subscription
- **WebSocket Exercises:**
  - Dedicated WebSocket security exercises
  - Progressive difficulty levels
  - Detailed writeups
- **Focus:** Practical, hands-on learning

### OWASP WebGoat
- **URL:** https://owasp.org/www-project-webgoat/
- **Repository:** https://github.com/WebGoat/WebGoat
- **Cost:** Free
- **Features:**
  - Self-hosted vulnerable application
  - WebSocket security lessons
  - Hints and solutions provided

### Damn Vulnerable Web Application (DVWA)
- **URL:** https://github.com/digininja/DVWA
- **Cost:** Free
- **WebSocket Support:** Via extensions and modifications
- **Usage:** Self-hosted practice environment

---

## Bug Bounty Programs

### Platforms with WebSocket Scope

#### HackerOne
- **URL:** https://www.hackerone.com/
- **WebSocket Programs:** Many programs include WebSocket endpoints
- **Notable Programs:**
  - GitLab (wss://gitlab.com)
  - Slack (WebSocket in real-time messaging)
  - Shopify (WebSocket in admin interfaces)
  - Automattic (WordPress.com)
- **Search:** Filter programs by "WebSocket" or "wss://"

#### Bugcrowd
- **URL:** https://www.bugcrowd.com/
- **WebSocket Programs:** Real-time chat, collaboration tools
- **Notable Programs:**
  - Tesla
  - Dropbox
  - Mozilla
- **Typical Payouts:** $500-$10,000 for critical WebSocket vulnerabilities

#### Synack
- **URL:** https://www.synack.com/
- **Type:** Invite-only platform
- **Focus:** Enterprise applications often using WebSockets
- **Payouts:** Competitive rates for validated vulnerabilities

#### Intigriti
- **URL:** https://www.intigriti.com/
- **Region:** Europe-focused
- **Programs:** Many European SaaS companies with WebSocket endpoints

#### YesWeHack
- **URL:** https://www.yeswehack.com/
- **Programs:** International companies
- **WebSocket Focus:** Chat applications, real-time dashboards

### WebSocket Vulnerability Bounty Examples

#### Real Payouts
- **CSWSH in Gitpod:** $5,000+
- **XSS via WebSocket in major SaaS:** $2,000-$8,000
- **Authentication bypass via WebSocket:** $10,000+
- **SQL Injection via WebSocket:** $5,000-$15,000

#### Typical Severity Ratings
| Vulnerability | Severity | Typical Payout |
|--------------|----------|----------------|
| CSWSH with data exfiltration | High | $1,000-$5,000 |
| Stored XSS via WebSocket | High | $2,000-$8,000 |
| Authentication bypass | Critical | $5,000-$20,000 |
| SQL Injection | Critical | $5,000-$15,000 |
| Authorization bypass | High | $1,000-$7,000 |

### Tips for WebSocket Bug Bounty Hunting

1. **Reconnaissance:**
   - Use browser DevTools to identify WebSocket endpoints
   - Check `wss://` and `ws://` URLs in JavaScript source
   - Look for real-time features (chat, notifications, collaboration)

2. **Low-Hanging Fruit:**
   - Test for missing CSRF tokens (CSWSH)
   - Test basic XSS payloads in messages
   - Check for authentication/authorization bypasses

3. **Documentation:**
   - Include proof-of-concept code
   - Demonstrate impact clearly
   - Provide remediation recommendations

4. **Communication:**
   - Be professional and detailed
   - Respond quickly to triage questions
   - Offer to help verify fixes

---

## Vulnerable Applications

### Intentionally Vulnerable WebSocket Apps

#### WebSocket Security Testing Tool by OWASP
- **Purpose:** Practice environment for WebSocket testing
- **Features:**
  - Multiple vulnerability types
  - Progressive difficulty
  - Educational content

#### Custom Vulnerable WebSocket Server
```python
# Simple vulnerable WebSocket server for practice
# pip install websockets

import asyncio
import websockets

async def handler(websocket, path):
    async for message in websocket:
        # Vulnerable: No input validation
        response = f"<div>You said: {message}</div>"
        await websocket.send(response)

start_server = websockets.serve(handler, "localhost", 8765)
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
```

#### Socket.IO Vulnerable Demo
- **Repository:** Create custom vulnerable Socket.IO apps
- **Common Vulnerabilities:**
  - Missing authentication
  - No input validation
  - CSWSH vulnerabilities

---

## Community & Forums

### Security Communities

#### Reddit
- **r/netsec:** https://www.reddit.com/r/netsec/
- **r/websec:** https://www.reddit.com/r/websec/
- **r/bugbounty:** https://www.reddit.com/r/bugbounty/
- **Topics:** WebSocket vulnerability discussions, tool recommendations, writeups

#### Discord Servers
- **HackerOne Discord:** Community discussions on bug bounty
- **TryHackMe Discord:** Learning and help with WebSocket labs
- **Bugcrowd Discord:** Researcher community

#### Stack Overflow
- **URL:** https://stackoverflow.com/questions/tagged/websocket+security
- **Tags:** `websocket`, `websocket-security`, `burp-suite`
- **Usage:** Technical questions about WebSocket security

### Twitter (X) Security Researchers
- **Follow hashtags:** #WebSocket, #BugBounty, #InfoSec
- **Notable researchers:** Search for WebSocket vulnerability disclosures

### YouTube Channels

#### John Hammond
- **URL:** https://www.youtube.com/@JohnHammond
- **Content:** CTF walkthroughs, sometimes featuring WebSocket challenges

#### IppSec
- **URL:** https://www.youtube.com/@ippsec
- **Content:** HackTheBox walkthroughs, occasional WebSocket content

#### LiveOverflow
- **URL:** https://www.youtube.com/@LiveOverflow
- **Content:** Web security, binary exploitation, occasionally WebSocket topics

#### Nahamsec
- **URL:** https://www.youtube.com/@NahamSec
- **Content:** Bug bounty methodology, may cover WebSocket testing

---

## Secure Development Resources

### Secure Coding Guides

#### OWASP Secure Coding Practices
- **URL:** https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/
- **WebSocket Sections:**
  - Input Validation
  - Authentication and Password Management
  - Session Management
  - Error Handling and Logging

#### Node.js Security Best Practices
- **URL:** https://nodejs.org/en/docs/guides/security/
- **WebSocket Libraries:**
  - `ws`: https://github.com/websockets/ws#usage-examples
  - `socket.io`: https://socket.io/docs/v4/
- **Security Considerations:**
  - Authentication
  - Input validation
  - Rate limiting

#### Django Channels Security
- **URL:** https://channels.readthedocs.io/en/stable/
- **Security Guide:** https://channels.readthedocs.io/en/stable/topics/security.html
- **Topics:**
  - Authentication with channels
  - Origin validation
  - CSRF protection

#### Spring WebSocket Security
- **URL:** https://docs.spring.io/spring-security/reference/servlet/integrations/websocket.html
- **Topics:**
  - CSRF protection with WebSockets
  - Authentication configuration
  - Authorization rules

### Security Libraries

#### DOMPurify (JavaScript)
- **URL:** https://github.com/cure53/DOMPurify
- **Purpose:** Sanitize HTML to prevent XSS
- **Usage:** `const clean = DOMPurify.sanitize(userInput);`

#### bleach (Python)
- **URL:** https://github.com/mozilla/bleach
- **Purpose:** HTML sanitization for Python
- **Usage:** `clean = bleach.clean(user_input, tags=[], strip=True)`

#### OWASP ESAPI
- **URL:** https://owasp.org/www-project-enterprise-security-api/
- **Purpose:** Enterprise security API for input validation, encoding, etc.

---

## Compliance & Audit Resources

### PCI DSS WebSocket Testing
- **Requirement 6.5.7:** Test for CSWSH vulnerabilities
- **Requirement 6.5.1:** Test for injection via WebSocket messages
- **Testing Guide:** Include WebSocket endpoints in application security assessment

### GDPR Considerations
- **Data Protection:** Ensure WebSocket messages containing personal data are encrypted (wss://)
- **Access Control:** Implement proper authorization for WebSocket data access
- **Audit Logging:** Log all WebSocket connections and sensitive actions

### SOC 2 Compliance
- **Security Criteria:** WebSocket authentication, encryption, logging
- **Audit Requirements:** Document WebSocket security controls

---

## Quick Reference

### Most Useful Resources (Top 10)

1. **PortSwigger Web Security Academy** - Best labs for learning
2. **OWASP WebSocket Security Cheat Sheet** - Comprehensive security guide
3. **Burp Suite** - Essential testing tool
4. **wscat** - Quick CLI testing
5. **HackTricks WebSocket Section** - Pentesting methodology
6. **CVE Database (NVD)** - Real-world vulnerabilities
7. **HackerOne** - Bug bounty opportunities
8. **Python websockets library** - Automation scripting
9. **GitHub** - Search for "WebSocket vulnerability" for PoCs
10. **YouTube** - Video walkthroughs and tutorials

### Bookmarks to Save
```
□ PortSwigger Labs: https://portswigger.net/web-security/websockets
□ OWASP Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html
□ Burp Extensions: https://portswigger.net/bappstore
□ HackerOne Programs: https://hackerone.com/directory/programs
□ CVE Search: https://nvd.nist.gov/
□ wscat GitHub: https://github.com/websockets/wscat
□ HackTricks: https://book.hacktricks.xyz/pentesting-web/websocket-attacks
```

---

**Document Version:** 1.0
**Last Updated:** January 2026
**Maintained By:** Penetration Testing Skill - WebSockets Mastery Module
