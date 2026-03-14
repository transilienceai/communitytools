# Web Cache Poisoning - Complete Resources Guide

## Table of Contents
1. [Official Documentation](#official-documentation)
2. [Research Papers](#research-papers)
3. [CVE Database](#cve-database)
4. [Industry Standards](#industry-standards)
5. [Tools and Frameworks](#tools-and-frameworks)
6. [Training Platforms](#training-platforms)
7. [Bug Bounty Programs](#bug-bounty-programs)
8. [Books and Publications](#books-and-publications)
9. [Community Resources](#community-resources)
10. [Secure Coding Guidelines](#secure-coding-guidelines)

---

## Official Documentation

### PortSwigger Web Security Academy

**Main Resources**:
- [Web Cache Poisoning](https://portswigger.net/web-security/web-cache-poisoning) - Complete tutorial and labs
- [Exploiting Cache Design Flaws](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws) - Unkeyed inputs exploitation
- [Exploiting Cache Implementation Flaws](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws) - Advanced techniques
- [Web Cache Deception](https://portswigger.net/web-security/web-cache-deception) - Related attack vector

**Lab Access**:
- 8 hands-on labs covering Apprentice to Expert difficulty
- Interactive browser-based exploitation
- Automated solution checking
- Free access, no registration required

---

## Research Papers

### James Kettle - PortSwigger Research

**1. Practical Web Cache Poisoning (2018)**
- **URL**: https://portswigger.net/research/practical-web-cache-poisoning
- **Presentation**: Black Hat USA 2018
- **Key Contributions**:
  - First comprehensive research on practical cache poisoning
  - Introduced unkeyed input discovery methodology
  - Demonstrated real-world exploitation
  - Developed Param Miner tool
- **Impact**: Earned $60,000+ in bug bounties
- **Notable Findings**:
  - Vulnerabilities in Red Hat, Mozilla SHIELD, Cloudflare
  - Drupal framework vulnerabilities affecting thousands of sites
  - X-Forwarded-Host exploitation techniques

**2. Web Cache Entanglement: Novel Pathways to Poisoning (2020)**
- **URL**: https://portswigger.net/research/web-cache-entanglement
- **Presentation**: Black Hat USA 2020
- **PDF**: https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf
- **Key Contributions**:
  - Cache key transformation attacks
  - Targeting Host header and request line
  - Gadget chaining methodologies
  - Cache oracle techniques
- **Notable Exploits**:
  - Persistent poisoning of major newspaper site
  - DoD intelligence website compromise
  - Firefox update system global disruption
- **Advanced Techniques**:
  - Cache normalization exploitation
  - Multi-stage attack chains
  - Internal vs external cache targeting

**3. Gotta Cache 'em All (2024)**
- **URL**: https://portswigger.net/research/gotta-cache-em-all
- **PDF**: https://portswigger.net/kb/papers/kapvrid/gotta-cache-em-all.pdf
- **Presentation**: Black Hat USA 2024
- **Key Contributions**:
  - Latest cache poisoning research
  - New attack vectors and techniques
  - Updated tooling and methodologies
  - Modern CDN exploitation

---

### Academic Papers

**CPDoS: Cache Poisoned Denial of Service**
- **Authors**: Hoai Viet Nguyen, Luigi Lo Iacono, Hannes Federrath
- **Conference**: USENIX Security Symposium 2019
- **URL**: https://cpdos.org/
- **Key Contributions**:
  - Cache poisoning for DoS attacks
  - HTTP Header Oversize (HHO) attacks
  - HTTP Meta Character (HMC) attacks
  - HTTP Method Override (HMO) attacks
- **Practical Impact**:
  - Affects major CDNs and caching proxies
  - Low-resource DoS attacks
  - Persistent denial of service

**Cache Security Papers**:
- "Web Cache Deception Attack" - Omer Gil (2017)
- "Cached and Confused: Web Cache Deception in the Wild" - Seyed Ali Mirheidari et al. (2020)
- "Timing Attacks on Web Privacy" - Edward W. Felten, Michael A. Schneider (2000)

---

## CVE Database

### Recent Web Cache Poisoning CVEs

**CVE-2020-4896 - IBM Emptoris Sourcing**
- **CVSS**: 6.1 (Medium)
- **Affected**: IBM Emptoris Sourcing 10.1.0, 10.1.1, 10.1.3
- **Description**: Web cache poisoning via improper HTTP header validation
- **URL**: https://nvd.nist.gov/vuln/detail/CVE-2020-4896

**CVE-2020-4828 - IBM API Connect**
- **CVSS**: 6.1 (Medium)
- **Affected**: IBM API Connect 10.0.0.0-10.0.1.0, 2018.4.1.0-2018.4.1.13
- **Description**: Cache poisoning through unvalidated proxy headers
- **URL**: https://nvd.nist.gov/vuln/detail/CVE-2020-4828

**CVE-2021-29479 - Ratpack**
- **CVSS**: 5.3 (Medium)
- **Affected**: Ratpack < 1.9.0
- **Description**: X-Forwarded-Host header cache poisoning, redirect exploitation
- **URL**: https://nvd.nist.gov/vuln/detail/CVE-2021-29479
- **Fix**: Version 1.9.0+ includes X-Forwarded-Host in cache key

**CVE-2020-28473 - Bottle Python Framework**
- **CVSS**: 5.3 (Medium)
- **Affected**: Bottle < 0.12.19
- **Description**: Parameter cloaking via semicolon separator
- **URL**: https://nvd.nist.gov/vuln/detail/CVE-2020-28473
- **Impact**: JSONP callback manipulation, XSS attacks

**CVE-2021-23336 - Python cpython**
- **CVSS**: 5.9 (Medium)
- **Affected**: Python < 3.9.2, < 3.8.8, < 3.7.10, < 3.6.13
- **Description**: parse_qsl() semicolon separator enables cache poisoning
- **URL**: https://nvd.nist.gov/vuln/detail/CVE-2021-23336
- **Impact**: Affects Tornado, Django, Flask applications

**CVE-2020-5401 - CloudFoundry Gorouter**
- **CVSS**: 7.5 (High)
- **Affected**: CloudFoundry Gorouter
- **Description**: Cache-Poisoned Denial of Service (CPDoS)
- **URL**: https://nvd.nist.gov/vuln/detail/CVE-2020-5401

**CVE-2020-29022 - Secomea GateManager**
- **CVSS**: 6.1 (Medium)
- **Affected**: Secomea GateManager < 9.7
- **Description**: Host header injection leading to cache poisoning
- **URL**: https://nvd.nist.gov/vuln/detail/CVE-2020-29022

**CVE-2021-41267 - Symfony/Http-Kernel**
- **CVSS**: 5.3 (Medium)
- **Affected**: Symfony 5.2.0-5.3.14
- **Description**: X-Forwarded-Prefix header bypass in SubRequest
- **URL**: https://nvd.nist.gov/vuln/detail/CVE-2021-41267
- **Fix**: Symfony 5.3.15+ properly validates trusted_headers

### CVE Search Resources
- [National Vulnerability Database](https://nvd.nist.gov/)
- [CVE Details](https://www.cvedetails.com/)
- [Snyk Vulnerability Database](https://snyk.io/vuln/)
- [GitHub Security Advisories](https://github.com/advisories)

---

## Industry Standards

### OWASP Resources

**OWASP Cache Poisoning**
- **URL**: https://owasp.org/www-community/attacks/Cache_Poisoning
- **Content**: Attack description, examples, prevention

**OWASP Testing Guide**
- **URL**: https://owasp.org/www-project-web-security-testing-guide/
- **Relevant Sections**:
  - WSTG-INPV-17: Testing for Host Header Injection
  - WSTG-INPV-12: Testing for HTTP Parameter Pollution
  - WSTG-ATHN-02: Testing for Default Credentials

**OWASP Cheat Sheets**
- [HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)

**OWASP Top 10 (2021)**
- A03:2021 - Injection (includes header injection)
- A05:2021 - Security Misconfiguration (improper cache config)
- A07:2021 - Identification and Authentication Failures

---

### MITRE Standards

**CWE - Common Weakness Enumeration**
- **CWE-644**: Improper Neutralization of HTTP Headers for Scripting Syntax
  - URL: https://cwe.mitre.org/data/definitions/644.html
  - Related to cache poisoning via header injection
- **CWE-113**: Improper Neutralization of CRLF Sequences in HTTP Headers
  - URL: https://cwe.mitre.org/data/definitions/113.html
- **CWE-444**: Inconsistent Interpretation of HTTP Requests
  - URL: https://cwe.mitre.org/data/definitions/444.html

**CAPEC - Common Attack Pattern Enumeration**
- **CAPEC-33**: HTTP Request Smuggling
  - URL: https://capec.mitre.org/data/definitions/33.html
  - Related to cache poisoning through request manipulation
- **CAPEC-31**: Accessing/Intercepting/Modifying HTTP Cookies
  - URL: https://capec.mitre.org/data/definitions/31.html

**MITRE ATT&CK Framework**
- **T1190**: Exploit Public-Facing Application
- **T1189**: Drive-by Compromise (via cached XSS)

---

### NIST Guidelines

**NIST SP 800-53 (Security and Privacy Controls)**
- **SI-10**: Information Input Validation
  - Validate all HTTP headers
  - Sanitize reflected inputs
- **SI-3**: Malicious Code Protection
  - Content Security Policy implementation
- **SC-5**: Denial of Service Protection
  - Protection against CPDoS attacks

**NIST Cybersecurity Framework**
- PR.DS-2: Data-in-transit is protected
- DE.CM-1: The network is monitored
- RS.MI-3: Newly identified vulnerabilities are mitigated

---

### PCI DSS Requirements

**Requirement 6**: Develop and maintain secure systems and applications
- 6.5.1: Injection flaws (including header injection)
- 6.5.7: Cross-site scripting (XSS)
- 6.5.10: Broken authentication and session management

**Requirement 11**: Regularly test security systems and processes
- 11.3: Implement penetration testing methodology
- 11.3.1: External penetration testing at least annually

---

### ISO/IEC 27001

**Relevant Controls**:
- A.14.2.1: Secure development policy
- A.14.2.5: Secure system engineering principles
- A.14.2.8: System security testing
- A.12.6.1: Management of technical vulnerabilities

---

## Tools and Frameworks

### Burp Suite Extensions

**1. Param Miner**
- **Developer**: PortSwigger / James Kettle
- **BApp Store**: https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943
- **GitHub**: https://github.com/PortSwigger/param-miner
- **Features**:
  - Guess unkeyed headers
  - Guess GET/POST parameters
  - Guess cookies
  - Rails parameter cloaking scan
  - Dynamic cache-buster generation
  - Automatic reflection detection
- **Requirements**: Burp Suite Professional or Community Edition
- **Documentation**: https://github.com/PortSwigger/param-miner/wiki

**2. Turbo Intruder**
- **Developer**: PortSwigger / James Kettle
- **BApp Store**: https://portswigger.net/bappstore/9abaa233088242e8be2abf26cc352f9d
- **Use Case**: High-speed request sending for cache poisoning maintenance
- **Features**:
  - Python scripting for custom attack logic
  - Rate control and timing
  - Concurrent connections
  - Request pipelining

**3. HTTP Request Smuggler**
- **Developer**: PortSwigger / James Kettle
- **BApp Store**: https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646
- **Relevance**: Detect request smuggling that can lead to cache poisoning
- **Features**:
  - Automatic detection of CL.TE, TE.CL, TE.TE
  - HTTP/2 smuggling detection

**4. Additional Useful Extensions**
- **Logger++**: Enhanced logging for cache behavior tracking
- **Autorize**: Test authorization with poisoned caches
- **Content-Type Converter**: Test different content types
- **Collaborator Everywhere**: Out-of-band interaction testing

---

### Standalone Tools

**1. Nuclei**
- **Developer**: ProjectDiscovery
- **GitHub**: https://github.com/projectdiscovery/nuclei
- **Description**: Fast vulnerability scanner with templates
- **Cache Poisoning Templates**: Community-contributed
- **Installation**:
  ```bash
  go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
  ```
- **Usage**:
  ```bash
  nuclei -u https://target.com/ -t cache-poisoning/
  ```

**2. OWASP ZAP**
- **URL**: https://www.zaproxy.org/
- **Features**:
  - Passive scanner for cache issues
  - Active scanner for header injection
  - Script support for custom tests
- **Add-ons**:
  - Cache Control Scanner
  - Header Injection Scanner

**3. HTTPie**
- **URL**: https://httpie.io/
- **Description**: User-friendly HTTP client
- **Usage**:
  ```bash
  http https://target.com/ X-Forwarded-Host:evil.com
  ```

**4. Postman**
- **URL**: https://www.postman.com/
- **Use Case**: Manual testing and automation
- **Features**:
  - Collection runner for repeated requests
  - Environment variables
  - Test scripting

**5. Arjun**
- **GitHub**: https://github.com/s0md3v/Arjun
- **Description**: HTTP parameter discovery tool
- **Usage**:
  ```bash
  arjun -u https://target.com/
  ```

---

### Custom Scripts and Automation

**Python Requests**
```python
import requests

# Library: https://pypi.org/project/requests/
# Install: pip install requests
```

**cURL**
```bash
# Built-in on Linux/macOS
# Windows: https://curl.se/windows/
```

**PowerShell**
```powershell
# Invoke-WebRequest (built-in)
# Invoke-RestMethod (built-in)
```

---

## Training Platforms

### PortSwigger Web Security Academy
- **URL**: https://portswigger.net/web-security
- **Cost**: FREE
- **Content**:
  - 8 web cache poisoning labs
  - Interactive browser-based exploitation
  - Automated solution checking
  - Complete learning path
- **Difficulty**: Apprentice to Expert
- **Certificate**: Burp Suite Certified Practitioner (BSCP)

---

### HackTheBox
- **URL**: https://www.hackthebox.com/
- **Cost**: Free tier + VIP subscription
- **Relevant Machines**:
  - Machines with caching layers
  - CDN exploitation scenarios
  - Web application challenges
- **Practice**: Retired machines with writeups

---

### TryHackMe
- **URL**: https://tryhackme.com/
- **Cost**: Free tier + Premium
- **Relevant Rooms**:
  - Web Fundamentals
  - Web Application Security
  - OWASP Top 10
  - Burp Suite rooms
- **Guided Learning**: Step-by-step instructions

---

### PentesterLab
- **URL**: https://pentesterlab.com/
- **Cost**: Subscription-based
- **Relevant Exercises**:
  - Web for Pentester
  - HTTP Header Injection
  - Cache exploitation exercises
- **Approach**: Hands-on exploitation practice

---

### Hack The Box Academy
- **URL**: https://academy.hackthebox.com/
- **Cost**: Free modules + Premium
- **Modules**:
  - Web Attacks
  - Bug Bounty Hunter path
  - Penetration Testing path
- **Certification**: HTB Certified Penetration Testing Specialist (CPTS)

---

### CTF Platforms
- **picoCTF**: https://picoctf.org/
- **CTFtime**: https://ctftime.org/ (CTF event listings)
- **HackerOne CTF**: https://ctf.hacker101.com/
- **Google CTF**: https://capturetheflag.withgoogle.com/

---

## Bug Bounty Programs

### Major Platforms

**HackerOne**
- **URL**: https://www.hackerone.com/
- **Notable Programs**:
  - GitHub
  - GitLab
  - PayPal
  - Shopify
  - U.S. Department of Defense
- **Typical Payouts**: $500 - $10,000+ for cache poisoning
- **Notable Findings**: James Kettle earned $260,000+ from cache poisoning research

**Bugcrowd**
- **URL**: https://www.bugcrowd.com/
- **Programs**: 500+ organizations
- **Focus**: Web applications, APIs, mobile apps

**Intigriti**
- **URL**: https://www.intigriti.com/
- **Region**: Europe-focused
- **Programs**: European companies

**YesWeHack**
- **URL**: https://www.yeswehack.com/
- **Region**: Europe + global
- **Language**: Multi-language support

**Open Bug Bounty**
- **URL**: https://www.openbugbounty.org/
- **Focus**: Responsible disclosure
- **Cost**: Free coordination

---

### Vulnerability Disclosure Programs

**Google Vulnerability Reward Program (VRP)**
- Cache poisoning findings accepted
- Typical range: $500 - $5,000

**Microsoft Bug Bounty Program**
- Azure, Office 365, Microsoft services
- Up to $250,000 for critical findings

**Apple Security Bounty**
- iCloud, Apple services
- Up to $1,000,000 for critical vulnerabilities

---

### Notable Bug Bounty Findings

**James Kettle (PortSwigger)**
- Over $260,000 earned from cache poisoning research
- Vulnerabilities in major CDNs and platforms
- Groundbreaking research presented at Black Hat

**Successful Cache Poisoning Reports**:
- Red Hat: XSS via X-Forwarded-Host
- Mozilla SHIELD: Global Firefox user redirection
- Cloudflare Blog: Cache poisoning leading to XSS
- Drupal: Framework-wide X-Original-URL vulnerability

---

## Books and Publications

### Web Application Security Books

**1. The Web Application Hacker's Handbook (2nd Edition)**
- **Authors**: Dafydd Stuttard, Marcus Pinto
- **Publisher**: Wiley
- **ISBN**: 978-1118026472
- **Relevance**: Foundational web security knowledge
- **Chapter**: HTTP Request Smuggling and Cache Poisoning

**2. Real-World Bug Hunting**
- **Author**: Peter Yaworski
- **Publisher**: No Starch Press
- **ISBN**: 978-1593278618
- **Relevance**: Practical bug bounty examples
- **Content**: Real-world vulnerability findings and writeups

**3. Bug Bounty Bootcamp**
- **Author**: Vickie Li
- **Publisher**: No Starch Press
- **ISBN**: 978-1718501546
- **Relevance**: Modern bug bounty methodology
- **Content**: Includes web cache poisoning techniques

**4. Web Security Testing Cookbook**
- **Authors**: Paco Hope, Ben Walther
- **Publisher**: O'Reilly Media
- **ISBN**: 978-0596514839
- **Relevance**: Practical testing recipes

---

### Research Publications

**Conference Proceedings**:
- Black Hat USA (2018, 2020, 2024) - James Kettle presentations
- USENIX Security Symposium - CPDoS research
- OWASP AppSec conferences

**Security Journals**:
- IEEE Security & Privacy Magazine
- ACM Transactions on Privacy and Security
- Journal of Computer Security

---

## Community Resources

### Forums and Discussion

**PortSwigger Community**
- **URL**: https://forum.portswigger.net/
- **Topics**:
  - Web Security Academy discussions
  - Burp Suite support
  - Research discussions
  - Lab solutions (spoiler-tagged)

**Reddit**
- r/netsec: https://www.reddit.com/r/netsec/
- r/websecurity: https://www.reddit.com/r/websecurity/
- r/bugbounty: https://www.reddit.com/r/bugbounty/
- r/AskNetsec: https://www.reddit.com/r/AskNetsec/

**Stack Exchange**
- Information Security Stack Exchange: https://security.stackexchange.com/
- Stack Overflow (programming): https://stackoverflow.com/

**Discord Servers**
- Bugcrowd Discord
- HackerOne Community
- TryHackMe Discord
- Hack The Box Discord

---

### Security Blogs

**PortSwigger Research Blog**
- **URL**: https://portswigger.net/research
- **Content**: Latest security research, tool releases

**Cobalt Blog**
- **URL**: https://www.cobalt.io/blog
- **Content**: Pentester insights, web security deep dives

**Pentest-Tools Blog**
- **URL**: https://pentest-tools.com/blog
- **Content**: Practical exploitation guides

**Detectify Labs**
- **URL**: https://labs.detectify.com/
- **Content**: Security research and findings

**Cloudflare Blog**
- **URL**: https://blog.cloudflare.com/
- **Content**: CDN security, DDoS protection, cache behavior

---

### Twitter/X Accounts

**Security Researchers**:
- @albinowax (James Kettle - PortSwigger)
- @Rhynorater (Justin Gardner - bug bounty)
- @TomNomNom (Tom Hudson - security tools)
- @NahamSec (Ben Sadeghipour - bug bounty)
- @stokfredrik (Fredrik Alexandersson - security research)

**Organizations**:
- @PortSwiggerNet
- @HackerOne
- @Bugcrowd
- @OWASP
- @ProjectDiscovery

---

### YouTube Channels

**Security Education**:
- [LiveOverflow](https://www.youtube.com/c/LiveOverflow)
- [IppSec](https://www.youtube.com/c/IppSec) - HackTheBox walkthroughs
- [John Hammond](https://www.youtube.com/c/JohnHammond010)
- [STÖK](https://www.youtube.com/c/STOKfredrik)
- [Nahamsec](https://www.youtube.com/c/Nahamsec)
- [PwnFunction](https://www.youtube.com/c/PwnFunction) - Web security concepts

**Conference Talks**:
- [Black Hat](https://www.youtube.com/c/BlackHatOfficialYT)
- [DEF CON](https://www.youtube.com/user/DEFCONConference)
- [OWASP](https://www.youtube.com/c/OWASPGLOBAL)

---

## Secure Coding Guidelines

### Language-Specific Resources

**Python**
- [Django Security](https://docs.djangoproject.com/en/stable/topics/security/)
- [Flask Security](https://flask.palletsprojects.com/en/stable/security/)
- [OWASP Python Security](https://owasp.org/www-community/vulnerabilities/Python_Security)

**Node.js**
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Express Security](https://expressjs.com/en/advanced/best-practice-security.html)
- [Helmet.js](https://helmetjs.github.io/) - Security middleware

**Ruby**
- [Ruby on Rails Security Guide](https://guides.rubyonrails.org/security.html)
- [Brakeman Scanner](https://brakemanscanner.org/) - Rails security scanner

**PHP**
- [PHP Security Guide](https://www.php.net/manual/en/security.php)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)

**Java**
- [Spring Security](https://spring.io/projects/spring-security)
- [OWASP Java Security](https://owasp.org/www-community/vulnerabilities/Java_Security)

---

### Framework Documentation

**Django (Python)**
- Trusted proxy configuration: `USE_X_FORWARDED_HOST`
- Security middleware
- Content Security Policy

**Express.js (Node.js)**
- Trust proxy settings
- Helmet security headers
- Input validation middleware

**Ruby on Rails**
- ActionDispatch configuration
- Trusted proxy settings
- Security headers

**Spring Boot (Java)**
- ForwardedHeaderFilter
- Security configuration
- Header validation

**ASP.NET Core**
- Forwarded Headers Middleware
- Security headers
- Input validation

---

### Cache Server Documentation

**Nginx**
- **URL**: https://nginx.org/en/docs/
- **Relevant Modules**:
  - ngx_http_proxy_module
  - ngx_http_headers_module
  - ngx_http_cache_module

**Varnish**
- **URL**: https://varnish-cache.org/docs/
- **Documentation**: VCL (Varnish Configuration Language) guide

**Apache**
- **URL**: https://httpd.apache.org/docs/
- **Modules**:
  - mod_cache
  - mod_proxy
  - mod_headers

---

### CDN Documentation

**Cloudflare**
- **URL**: https://developers.cloudflare.com/
- **Topics**:
  - Cache configuration
  - Page Rules
  - Workers for custom logic
  - Transform Rules
  - Security settings

**AWS CloudFront**
- **URL**: https://docs.aws.amazon.com/cloudfront/
- **Topics**:
  - Cache behaviors
  - Origin request policies
  - Cache key policies
  - Security headers

**Akamai**
- **URL**: https://www.akamai.com/resources
- **Topics**:
  - Edge Side Includes
  - Cache configuration
  - Security policies

---

### WAF Rules and Detection

**ModSecurity Core Rule Set (CRS)**
- **URL**: https://coreruleset.org/
- **Rules**: Header injection detection, cache poisoning prevention

**Cloudflare WAF**
- **URL**: https://developers.cloudflare.com/waf/
- **Managed Rules**: OWASP Core Ruleset, Cloudflare Managed Ruleset

**AWS WAF**
- **URL**: https://docs.aws.amazon.com/waf/
- **Rules**: Custom rules for header validation

**Imperva (Incapsula) WAF**
- **URL**: https://docs.imperva.com/
- **Protection**: Application layer attacks, cache poisoning

---

### SIEM and Monitoring

**Splunk**
- **URL**: https://www.splunk.com/
- **Use Case**: Log analysis, cache behavior monitoring
- **Apps**: Security Essentials, Enterprise Security

**Elastic Stack (ELK)**
- **URL**: https://www.elastic.co/
- **Components**: Elasticsearch, Logstash, Kibana
- **Use Case**: Log aggregation and analysis

**Azure Sentinel**
- **URL**: https://azure.microsoft.com/en-us/services/microsoft-sentinel/
- **Use Case**: Cloud-native SIEM

**Datadog**
- **URL**: https://www.datadoghq.com/
- **Use Case**: Application monitoring, cache metrics

---

## Additional Resources

### Vulnerability Disclosure Platforms

**Open Bug Bounty**
- **URL**: https://www.openbugbounty.org/
- **Purpose**: Responsible disclosure coordination

**HackerOne Directory**
- **URL**: https://hackerone.com/directory/programs
- **Content**: List of all active bug bounty programs

---

### Security Newsletters

**Portswigger Daily Swig**
- Cybersecurity news and research

**TLDR Security**
- Weekly security newsletter

**Risky Business Podcast**
- Weekly security podcast and newsletter

---

### Practice Applications

**OWASP WebGoat**
- **URL**: https://owasp.org/www-project-webgoat/
- **Description**: Deliberately insecure application

**DVWA (Damn Vulnerable Web Application)**
- **URL**: https://github.com/digininja/DVWA
- **Description**: PHP/MySQL vulnerable web application

**Juice Shop**
- **URL**: https://owasp.org/www-project-juice-shop/
- **Description**: Modern vulnerable web application

---

## Summary

This comprehensive resource guide provides:
- **Official Documentation**: PortSwigger, OWASP, NIST, PCI DSS
- **Research Papers**: James Kettle's groundbreaking research (2018, 2020, 2024)
- **CVE Database**: 8+ real-world vulnerabilities with details
- **Tools**: Burp Suite extensions, standalone tools, custom scripts
- **Training**: Free and paid platforms (PortSwigger, HTB, TryHackMe)
- **Bug Bounty**: Major platforms and successful findings
- **Books**: Essential reading for web security
- **Community**: Forums, blogs, Twitter, YouTube
- **Secure Coding**: Framework-specific guidelines and best practices

**For Beginners**: Start with PortSwigger Web Security Academy (FREE)
**For Practitioners**: Use Burp Suite + Param Miner + Custom Scripts
**For Researchers**: Read James Kettle's papers + Attend Black Hat talks
**For Developers**: Follow OWASP guidelines + Framework documentation

---

**Resource Guide Version**: 1.0
**Last Updated**: 2026-01-09
**Total Resources**: 100+ links and references

For lab walkthroughs, see:
- `web-cache-poisoning-portswigger-labs-complete.md`
- `web-cache-poisoning-quickstart.md`
- `web-cache-poisoning-cheat-sheet.md`
