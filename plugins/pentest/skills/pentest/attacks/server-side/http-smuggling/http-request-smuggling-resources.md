# HTTP Request Smuggling - Resources and Tools

## Research Papers and Publications

### James Kettle's Black Hat Series

#### 1. HTTP Desync Attacks: Smashing into the Cell Next Door (2019)
**Presented:** Black Hat USA 2019 & DEF CON 27

**Key Contributions:**
- Revitalized request smuggling research after 14-year dormancy
- Demonstrated practical exploitation against major platforms
- Earned $60,000+ in bug bounties
- Discovered vulnerabilities in PayPal, New Relic, multi-layer CDNs

**Downloads:**
- White Paper: https://i.blackhat.com/USA-19/Wednesday/us-19-Kettle-HTTP-Desync-Attacks-Smashing-Into-The-Cell-Next-Door-wp.pdf
- Presentation: https://i.blackhat.com/USA-19/Wednesday/us-19-Kettle-HTTP-Desync-Attacks-Smashing-Into-The-Cell-Next-Door.pdf
- Video: https://www.youtube.com/watch?v=w-eJM2Pc0KI

**Impact:**
- 79% of all request smuggling CVEs issued post-2019
- Created HTTP Request Smuggler Burp extension
- Established detection methodology: Detect → Confirm → Explore → Exploit

---

#### 2. Browser-Powered Desync Attacks: A New Frontier (2022)
**Presented:** Black Hat USA 2022

**Key Innovations:**
- First demonstration of browser-based request smuggling
- Turned victim browsers into desync delivery platforms
- Combined cross-domain requests with server flaws
- Compromised Apache, Akamai, Varnish, Amazon, web VPNs

**Downloads:**
- White Paper: https://i.blackhat.com/USA-22/Wednesday/us-22-Kettle-Browser-Powered-Desync-Attacks-wp.pdf
- Presentation: https://i.blackhat.com/USA-22/Wednesday/us-22-Kettle-Browser-Powered-Desync-Attacks.pdf
- Video: https://www.youtube.com/watch?v=gzM4wWA7RFo

**Techniques Introduced:**
- Client-side desync attacks via JavaScript Fetch API
- CL.0 vulnerability discovery
- Connection pool poisoning
- Browser-powered SSRF chains

---

#### 3. HTTP/1.1 Must Die: The Desync Endgame (2025)
**Presented:** Black Hat USA 2025

**Key Achievements:**
- Novel classes of HTTP desync attack
- Mass credential compromise techniques
- Exposed tens of millions of websites
- Subverted Akamai, Cloudflare, Netlify infrastructure
- Earned $200,000+ in bug bounties in two-week period

**Downloads:**
- White Paper: https://i.blackhat.com/BH-USA-25/Presentations/US-25-Kettle-HTTP1-Must-Die-The-Desync-Endgame-wp.pdf
- Presentation: https://i.blackhat.com/BH-USA-25/Presentations/US-25-Kettle-HTTP1-Must-Die-The-Desync-Endgame-Wednesday.pdf

**Techniques Introduced:**
- Advanced HTTP/2 downgrade exploitation
- Pause-based request smuggling (Apache 2.4.52)
- HTTP/2 request tunnelling
- Response queue poisoning

---

### Academic Research

#### "HTTP Request Smuggling" (2005) - Original Discovery
**Authors:** Chaim Linhart, Amit Klein, Ronen Heled, Steve Orrin (Watchfire)
**Significance:** First documented HTTP request smuggling vulnerability

**Document:** https://trimstray.github.io/assets/pdfs/HTTP-Request-Smuggling.pdf

**Key Concepts:**
- Introduced CL.TE and TE.CL variants
- Demonstrated cache poisoning
- Web cache poisoning via request smuggling
- Firewall/IPS bypass techniques

---

#### "T-Reqs: HTTP Request Smuggling with Differential Fuzzing" (2021)
**Authors:** Bahruz Jabiyev, Steven Sprecher, Kaan Onarlioglu, Engin Kirda
**Published:** ACM SIGSAC Conference on Computer and Communications Security (CCS 2021)

**Key Innovations:**
- Differential fuzzing techniques for detecting request smuggling
- Automated detection methodology
- Novel fuzzing approaches for HTTP/1.1 and HTTP/2

**References:**
- ACM Digital Library: https://dl.acm.org/doi/10.1145/3460120.3485384
- Full Paper: https://swsprec.com/papers/treqs.pdf

---

#### "Attacking Websites: Detecting and Preventing HTTP Request Smuggling Attacks" (2022)
**Authors:** Huang et al.
**Published:** Security and Communication Networks - Wiley Online Library

**Key Contributions:**
- Analysis of Black Hat 2019 techniques
- Transfer-Encoding structure modifications
- Flask-based reverse proxy detection method

**Reference:** https://onlinelibrary.wiley.com/doi/10.1155/2022/3121177

---

#### "HTTP Request Smuggling in 2020 – New Variants, New Defenses and New Challenges"
**Author:** Amit Klein
**Presented:** Black Hat USA 2020

**Document:** https://i.blackhat.com/USA-20/Wednesday/us-20-Klein-HTTP-Request-Smuggling-In-2020-New-Variants-New-Defenses-And-New-Challenges-wp.pdf

**Focus:**
- Evolution of smuggling techniques
- New defense mechanisms
- Emerging challenges

---

#### "Exploration of browser-powered desync attacks via HTTP/3"
**Institution:** Northeastern University
**Year:** 2022

**Document:** https://repository.library.northeastern.edu/files/neu:4f236k59w/fulltext.pdf

**Focus:**
- HTTP/3 protocol analysis
- Browser-based attack vectors
- Future of desync attacks

---

## Tools and Frameworks

### Burp Suite Extensions

#### 1. HTTP Request Smuggler ⭐ ESSENTIAL
**Author:** James Kettle (PortSwigger Research)
**Type:** Free BApp Store extension

**Features:**
- Automated detection of CL.TE, TE.CL, TE.TE, HTTP/2 variants
- Payload generation and optimization
- Content-Length calculation automation
- Multiple smuggling technique support
- Integration with Burp Scanner

**Installation:**
1. Burp Suite → Extender → BApp Store
2. Search "HTTP Request Smuggler"
3. Click "Install"

**Usage:**
- Right-click any request → Extensions → HTTP Request Smuggler → Smuggle probe
- Automated scanning with configurable detection methods
- Manual payload crafting assistance

**Repository:** https://github.com/PortSwigger/http-request-smuggler

**Latest Version Features:**
- HTTP/2 downgrade detection
- Response queue poisoning detection
- Request tunnelling support
- Pause-based attack detection

---

#### 2. Turbo Intruder ⭐ ADVANCED
**Author:** James Kettle (PortSwigger Research)
**Type:** Free BApp Store extension

**Features:**
- High-speed HTTP request sending
- Python-based scripting
- Pause-based attack support (61-second pause for Apache)
- Connection pool control
- Custom attack patterns

**Usage for Request Smuggling:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=500,
        pipeline=False
    )
    # Pause-based smuggling for Apache 2.4.52
    engine.queue(target.req, pauseMarker=['\r\n\r\n'], pauseTime=61000)
    engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

**Repository:** https://github.com/PortSwigger/turbo-intruder

---

### Open Source Scanners

#### 1. Smuggler (defparam) ⭐ POPULAR
**Language:** Python 3
**Author:** defparam

**Features:**
- CL.TE and TE.CL detection
- Multiple payload support
- Domain scanning capabilities
- Time-based detection
- Verbose output for debugging

**Installation:**
```bash
git clone https://github.com/defparam/smuggler.git
cd smuggler
pip3 install -r requirements.txt
```

**Usage:**
```bash
# Basic scan
python3 smuggler.py -u https://target.com

# Verbose mode
python3 smuggler.py -u https://target.com -v

# Custom headers
python3 smuggler.py -u https://target.com -H "Authorization: Bearer TOKEN"

# Specific technique
python3 smuggler.py -u https://target.com -t cl.te
```

**Repository:** https://github.com/defparam/smuggler

---

#### 2. http2smugl (Wallarm)
**Language:** Go
**Author:** Emil Lerner (Wallarm)

**Features:**
- HTTP/2 specific testing
- Downgrade vulnerability detection
- Infrastructure validation
- AppSec/DevSecOps friendly

**Installation:**
```bash
go install github.com/assetnote/http2smugl@latest
```

**Usage:**
```bash
# Detect HTTP/2 smuggling
http2smugl detect --url https://target.com

# Test specific endpoint
http2smugl test --url https://target.com/api --type h2.cl
```

**Reference:** https://lab.wallarm.com/http2smugl-http2-request-smuggling-security-testing-tool/

**Repository:** https://github.com/assetnote/http2smugl

---

#### 3. smuggles (danielthatcher)
**Language:** Rust
**Focus:** Scale-optimized for thousands of hosts

**Features:**
- High-performance scanning
- CL.TE detection using time-based techniques
- TE.CL detection using time-based techniques
- Batch processing support

**Installation:**
```bash
cargo install smuggles
```

**Usage:**
```bash
# Scan single host
smuggles https://target.com

# Scan multiple hosts
smuggles -f hosts.txt -o results.json
```

**Repository:** https://github.com/danielthatcher/smuggles

---

#### 4. request_smuggler (Sh1Yo)
**Language:** Rust
**Based on:** James Kettle's research

**Features:**
- Multiple detection methods
- Configurable payloads
- JSON output support
- Fast scanning

**Installation:**
```bash
cargo install request_smuggler
```

**Usage:**
```bash
request_smuggler -u https://target.com -t cl.te
```

**Repository:** https://github.com/Sh1Yo/request_smuggler

---

#### 5. h2csmuggler
**Language:** Python
**Focus:** HTTP/2 Cleartext (h2c) protocol

**Features:**
- h2c upgrade mechanism testing
- HTTP/1.1 to HTTP/2 upgrade smuggling
- Protocol downgrade testing

**Installation:**
```bash
git clone https://github.com/BishopFox/h2csmuggler.git
cd h2csmuggler
pip install -r requirements.txt
```

**Usage:**
```bash
python h2csmuggler.py https://target.com
```

**Repository:** https://github.com/BishopFox/h2csmuggler

---

#### 6. http-desync-guardian (AWS)
**Language:** Java
**Author:** AWS Security
**Type:** Analysis and mitigation tool

**Features:**
- HTTP request analysis
- Desync risk assessment
- Request normalization
- AWS-maintained and supported

**Usage:**
```java
// Analyze request for desync risk
HttpDesynchGuardian guardian = new HttpDesynchGuardian();
HttpRequest request = parseRequest(rawRequest);
AnalysisResult result = guardian.analyze(request);

if (result.isVulnerable()) {
    // Block or normalize request
}
```

**Repository:** https://github.com/aws/http-desync-guardian

**Blog Post:** https://aws.amazon.com/blogs/security/protect-your-application-from-http-desync-attacks/

---

### Commercial Tools

#### 1. Qualys WAS (Web Application Scanning)
**Vendor:** Qualys
**Type:** Enterprise vulnerability scanner

**Features:**
- HTTP Request Smuggling detection module
- Automated testing
- Compliance reporting
- Integration with Qualys VMDR

**Reference:** https://blog.qualys.com/product-tech/2020/10/02/detecting-http-request-smuggling-with-qualys-was

---

#### 2. Tenable WAS
**Vendor:** Tenable
**Type:** Enterprise web application scanner

**Features:**
- Request smuggling vulnerability detection
- Plugin ID: 114223
- Automated remediation guidance

**Reference:** https://www.tenable.com/plugins/was/114223

---

#### 3. Acunetix
**Vendor:** Invicti Security
**Type:** Web vulnerability scanner

**Features:**
- HTTP Request Smuggling detection
- Proof-of-concept generation
- Integration with CI/CD

**Website:** https://www.acunetix.com/

---

#### 4. Netsparker (Invicti)
**Vendor:** Invicti Security
**Type:** Automated security scanner

**Features:**
- Smuggling detection
- False positive elimination
- SDLC integration

**Website:** https://www.invicti.com/

---

## Practice Environments

### PortSwigger Web Security Academy ⭐ RECOMMENDED
**URL:** https://portswigger.net/web-security/request-smuggling

**Features:**
- 20 free interactive labs
- No registration required
- Safe practice environment
- Difficulty: Apprentice → Expert
- Covers all attack variants

**Lab Categories:**
- Basic smuggling (CL.TE, TE.CL, TE.TE)
- Detection confirmation
- Exploitation (bypass, capture, XSS, cache)
- HTTP/2 downgrade attacks
- Browser-powered attacks

**Benefits:**
- Hands-on experience
- Immediate feedback
- No risk to production systems
- Guided solutions available

---

### HackTheBox Labs
**URL:** https://www.hackthebox.com/

**Features:**
- Real-world vulnerable systems
- Request smuggling challenges
- Community-driven content

---

### TryHackMe Rooms
**URL:** https://tryhackme.com/

**Features:**
- Guided learning paths
- HTTP protocol rooms
- Request smuggling modules

---

### OWASP Juice Shop
**URL:** https://owasp.org/www-project-juice-shop/

**Features:**
- Open-source vulnerable application
- Can be configured with request smuggling vulnerabilities
- Docker deployment

---

## Curated Resource Collections

### Awesome-HTTPRequestSmuggling ⭐ COMPREHENSIVE
**Repository:** https://github.com/chenjj/Awesome-HTTPRequestSmuggling

**Contents:**
- Tool listings (20+ tools)
- Research papers
- Blog posts and articles
- Conference presentations
- CVE references
- Detection techniques
- Remediation guides

**Categories:**
- Detection Tools
- Exploitation Tools
- Academic Research
- Industry Whitepapers
- Conference Talks
- Blog Posts
- CVE Database

---

### GoSecure Request Smuggling Workshop
**URL:** https://gosecure.github.io/request-smuggling-workshop/

**Features:**
- Hands-on workshop materials
- Realistic applications and infrastructures
- Four attack variants covered
- Lab environment setup guides

**Workshop Content:**
- CL.TE exploitation
- TE.CL exploitation
- TE.TE obfuscation
- Real-world scenarios

---

## Documentation and Standards

### RFC Specifications

#### RFC 9112 - HTTP/1.1 Message Parsing
**URL:** https://www.rfc-editor.org/rfc/rfc9112.html

**Relevant Sections:**
- Section 2.2: Message Parsing (CRLF handling)
- Section 6.3.3: Transfer-Encoding vs Content-Length
- Section 6.1: Chunked Transfer Coding

**Key Requirements:**
- CR without LF must be rejected or replaced with space
- Transfer-Encoding MUST override Content-Length
- Multiple Content-Length headers MUST result in 400 Bad Request

---

#### RFC 7230 - HTTP/1.1 Message Syntax and Routing
**URL:** https://www.rfc-editor.org/rfc/rfc7230.html

**Relevant Sections:**
- Section 3.3.3: Message Body Length determination
- Section 4.1: Chunked Transfer Coding

**Requirements:**
- Strict parsing of HTTP messages
- Header field processing
- Connection management

---

#### RFC 7540 - HTTP/2 Protocol
**URL:** https://www.rfc-editor.org/rfc/rfc7540.html

**Relevant Sections:**
- Section 8.1.2: HTTP Header Fields
- Section 8.1.2.6: Malformed Requests and Responses

**Requirements:**
- Transfer-Encoding header forbidden in HTTP/2
- Connection-specific headers forbidden
- Header downgrading requirements

---

### OWASP Resources

#### OWASP Testing Guide
**URL:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling

**Content:**
- Testing procedures
- Detection methods
- Remediation guidance

---

#### OWASP Cheat Sheet Series
**URL:** https://cheatsheetseries.owasp.org/

**Relevant Cheat Sheets:**
- Input Validation Cheat Sheet
- REST Security Cheat Sheet
- HTTP Strict Transport Security Cheat Sheet

---

### MITRE Resources

#### CWE-444: Inconsistent Interpretation of HTTP Requests
**URL:** https://cwe.mitre.org/data/definitions/444.html

**Description:**
- HTTP Request/Response Smuggling weakness
- Causes and consequences
- Detection methods
- Potential mitigations

**Related CWEs:**
- CWE-436: Interpretation Conflict
- CWE-444: HTTP Request Smuggling
- CWE-113: Improper Neutralization of CRLF Sequences

---

#### CAPEC-33: HTTP Request Smuggling
**URL:** https://capec.mitre.org/data/definitions/33.html

**Content:**
- Attack pattern description
- Prerequisites
- Attack execution flow
- Mitigations

**Related CAPEC:**
- CAPEC-273: HTTP Response Smuggling
- CAPEC-220: Client-Server Protocol Manipulation

---

### NIST Resources

#### National Vulnerability Database (NVD)
**URL:** https://nvd.nist.gov/

**Search Terms:**
- "HTTP request smuggling"
- CWE-444
- Specific vendor/product names

**Notable CVE Listings:**
- CVE-2025-55315 (.NET Core - CVSS 9.9)
- CVE-2025-32094 (Akamai)
- CVE-2023-46747 (F5 BIG-IP)
- CVE-2023-25690 (Apache)

---

## Blog Posts and Articles

### PortSwigger Research Blog
**URL:** https://portswigger.net/research

**Notable Posts:**
- "HTTP Desync Attacks: Request Smuggling Reborn"
- "Browser-Powered Desync Attacks"
- "HTTP Request Smuggling Explained" (with NahamSec)

---

### Akamai Security Research Blog
**URL:** https://www.akamai.com/blog/security

**Notable Posts:**
- "HTTP/2 Request Smuggling"
- "CVE-2025-32094 Disclosure"

---

### The Daily Swig (PortSwigger)
**URL:** https://portswigger.net/daily-swig

**Notable Articles:**
- "Ancient technique tears a hole through modern web stacks at Black Hat 2019"
- Coverage of major CVE disclosures
- Security researcher interviews

---

### Security Innovation Blog
**URL:** https://blog.securityinnovation.com/

**Notable Post:**
- "Testing Servers for Vulnerability to HTTP Desync Request Smuggling Attacks"

---

### Praetorian Security Blog
**URL:** https://www.praetorian.com/blog/

**Notable Post:**
- "Compromising F5 BIG-IP with Request Smuggling CVE-2023-46747"

---

## Video Resources

### Conference Talks

#### Black Hat USA Presentations
1. **James Kettle 2019** - "HTTP Desync Attacks: Smashing into the Cell Next Door"
   - YouTube: https://www.youtube.com/watch?v=w-eJM2Pc0KI
   - Duration: 50 minutes
   - Level: Intermediate to Advanced

2. **James Kettle 2022** - "Browser-Powered Desync Attacks"
   - YouTube: https://www.youtube.com/watch?v=gzM4wWA7RFo
   - Duration: 45 minutes
   - Level: Advanced

3. **Amit Klein 2020** - "HTTP Request Smuggling in 2020"
   - Black Hat archives
   - Duration: 40 minutes
   - Level: Advanced

---

#### DEF CON Presentations
1. **James Kettle DEF CON 27** - "HTTP Desync Attacks"
   - YouTube: DEF CON channel
   - Duration: 50 minutes
   - Level: Advanced

2. **James Kettle DEF CON 29** - "HTTP/2: The Sequel is Always Worse"
   - Focus: HTTP/2 vulnerabilities
   - Duration: 45 minutes
   - Level: Expert

---

### Educational Videos

#### PortSwigger Web Security Academy
**Channel:** PortSwigger YouTube
**Playlists:**
- HTTP Request Smuggling tutorial series
- Burp Suite extension demonstrations
- Lab walkthroughs

---

#### NahamSec YouTube Channel
**Content:**
- Bug bounty hunting techniques
- HTTP Request Smuggling practical exploitation
- Interview with James Kettle

---

## Books and Publications

### Web Application Security
1. **"Web Application Hacker's Handbook" (2nd Edition)**
   - Authors: Dafydd Stuttard, Marcus Pinto
   - Publisher: Wiley
   - Relevant Chapters: HTTP mechanics, proxy exploitation

2. **"Bug Bounty Bootcamp"**
   - Author: Vickie Li
   - Publisher: No Starch Press
   - Chapter: HTTP Request Smuggling

3. **"Real-World Bug Hunting"**
   - Author: Peter Yaworski
   - Publisher: No Starch Press
   - Case studies including request smuggling

---

## Community and Forums

### Discussion Forums
- **PortSwigger Research Forum**: https://forum.portswigger.net/
- **HackerOne Hacktivity**: Request smuggling disclosures
- **Bugcrowd Crowdstream**: Public vulnerability reports
- **Reddit /r/netsec**: Security research discussions
- **Reddit /r/bugbounty**: Bug bounty findings

---

## Bug Bounty Programs

### Platforms with Request Smuggling Reports
1. **HackerOne** - Major platforms accepting reports
2. **Bugcrowd** - Enterprise bug bounty programs
3. **Synack** - Private program network
4. **YesWeHack** - European platforms

### Notable Programs
- Akamai (reported by James Kettle)
- Cloudflare
- Amazon AWS
- Microsoft Azure
- Google Cloud
- PayPal (historical)
- New Relic (historical)

---

## Training and Certification

### Security Certifications
- **OSCP** (Offensive Security Certified Professional)
- **OSWE** (Offensive Security Web Expert)
- **GWAPT** (GIAC Web Application Penetration Tester)
- **CEH** (Certified Ethical Hacker)

### Online Courses
- **PortSwigger Web Security Academy** (Free)
- **PentesterAcademy** - HTTP Protocol Security
- **Cybrary** - Web Application Pentesting
- **INE Security** - Advanced Web Attacks

---

## Quick Reference Links

### Essential Bookmarks
- PortSwigger Labs: https://portswigger.net/web-security/request-smuggling
- HTTP Request Smuggler: https://github.com/PortSwigger/http-request-smuggler
- Awesome List: https://github.com/chenjj/Awesome-HTTPRequestSmuggling
- CWE-444: https://cwe.mitre.org/data/definitions/444.html
- RFC 9112: https://www.rfc-editor.org/rfc/rfc9112.html

### James Kettle's Research
- PortSwigger Profile: https://portswigger.net/research/james-kettle
- Personal Site: https://jameskettle.com/
- Twitter: @albinowax

---

**Last Updated:** January 2026
**Maintained By:** Pentest Skill Documentation Team
