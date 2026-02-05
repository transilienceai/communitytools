# Penetration Testing Reference Library

This directory contains comprehensive reference materials for penetration testing engagements. Each file covers a specific attack category with detailed methodologies, tools, commands, and remediation guidance.

## Reference Files

### [sql-injection.md](./sql-injection.md) ⭐ FEATURED
**Comprehensive SQL Injection Master Reference** - Over 1500 lines of expertise:
- **18 Complete PortSwigger Lab Solutions**: Apprentice to Practitioner level with exact payloads
- **All Attack Techniques**: UNION, Boolean Blind, Time-based Blind, Error-based, Out-of-band
- **Database-Specific Guides**: Oracle, MySQL, PostgreSQL, Microsoft SQL Server syntax
- **Burp Suite Mastery**: Complete tool configuration and usage (Proxy, Repeater, Intruder, Collaborator)
- **Real-World CVEs**: Notable breaches including Heartland, TJX, Sony (millions of records)
- **Tools & Automation**: sqlmap, jSQL, custom scripts, WAF bypass techniques
- **Industry Standards**: OWASP, NIST, PCI DSS, CWE-89, MITRE ATT&CK mapping
- **Secure Coding**: Parameterized queries, ORM best practices, input validation
- **Detection & Monitoring**: SIEM rules, IDS signatures, log analysis
- **Practice Resources**: Labs, challenges, books, certifications

### [cross-site-scripting.md](./cross-site-scripting.md) ⭐ FEATURED
**Comprehensive Cross-Site Scripting (XSS) Master Reference** - 2,377 lines:
- XSS fundamentals and core concepts
- Context-specific exploitation techniques
- Tools and automation frameworks
- Prevention and secure coding practices

### [xss-portswigger-labs-complete.md](./xss-portswigger-labs-complete.md) ⭐ NEW
**Complete PortSwigger Lab Solutions** - All 33 XSS labs:
- **Reflected XSS**: 16 labs (HTML, JavaScript, attributes, WAF bypass, CSP bypass)
- **Stored XSS**: 2 labs (persistent payloads in HTML and href contexts)
- **DOM-based XSS**: 12 labs (document.write, innerHTML, jQuery, AngularJS, web messages)
- **XSS Exploitation**: 3 labs (cookie theft, password capture, CSRF via XSS)
- Step-by-step solutions with exact payloads and HTTP requests
- Complete Burp Suite workflows for each lab
- Common mistakes and troubleshooting tips

### [xss-exploitation-techniques.md](./xss-exploitation-techniques.md) ⭐ NEW
**Real-World XSS Exploitation** - Practical attack scenarios:
- Cookie theft with Burp Collaborator
- Password capture via autofill and fake login forms
- CSRF via XSS with token extraction
- Keylogging and clipboard monitoring
- Website defacement techniques
- BeEF framework integration
- Internal network scanning from victim browser
- Session hijacking and data exfiltration

### [xss-bypass-techniques.md](./xss-bypass-techniques.md) ⭐ NEW
**Advanced XSS Bypass Methods** - Filter evasion and WAF bypass:
- HTML encoding bypass with entity decoding
- Character set manipulation (case, space, quote, parentheses)
- WAF evasion with systematic Burp Intruder enumeration
- SVG-based bypasses and exploitation
- AngularJS sandbox escapes (basic and advanced)
- CSP bypass (policy injection, dangling markup, JSONP)
- Template literal injection
- Alternative event handlers and custom tags

### [xss-quickstart.md](./xss-quickstart.md) ⚡ QUICK REFERENCE
**XSS Quick Start Guide** - Fast reference for practitioners:
- Context-specific payload cheatsheet
- Common patterns and bypasses
- Essential Burp Suite techniques
- Top 10 XSS testing tips
- Quick troubleshooting guide

### [xss-labs-comprehensive.md](./xss-labs-comprehensive.md) 📚 LEGACY
**Original comprehensive lab guide** - Detailed solutions and methodologies

### [csrf-portswigger-labs-complete.md](./csrf-portswigger-labs-complete.md) ⭐ NEW
**Complete PortSwigger CSRF Lab Solutions** - All 11 CSRF labs:
- **Basic CSRF**: No defenses (Apprentice level)
- **Token-Based Bypasses**: 5 labs (method-based, session binding, cookie injection, double submit, presence-based)
- **Referer-Based Bypasses**: 2 labs (header suppression, substring matching)
- **SameSite Bypasses**: 3 labs (client-side redirect, sibling domain XSS, method override)
- Step-by-step solutions with exact payloads and HTML exploits
- Complete Burp Suite workflows for each lab
- Common mistakes and troubleshooting tips
- Defense mechanisms and secure coding practices

### [csrf-quickstart.md](./csrf-quickstart.md) ⚡ QUICK REFERENCE
**CSRF Quick Start Guide** - Fast reference for practitioners:
- Basic CSRF exploit templates
- 10 common bypass techniques
- Burp Suite workflow shortcuts
- Detection checklist
- Defense implementations
- Quick troubleshooting guide

### [clickjacking-portswigger-labs-complete.md](./clickjacking-portswigger-labs-complete.md) ⭐ NEW
**Complete PortSwigger Clickjacking Lab Solutions** - All 5 Clickjacking labs:
- **Basic Clickjacking**: CSRF token bypass via UI redressing (Apprentice level)
- **Form Prepopulation**: URL parameter injection + overlay attack
- **Frame Buster Bypass**: HTML5 sandbox attribute exploitation
- **DOM XSS Trigger**: Combined clickjacking + DOM XSS exploitation
- **Multi-Step Clickjacking**: Sequential click exploitation with confirmation dialogs
- Step-by-step solutions with exact HTML exploits and CSS positioning
- Complete Burp Suite Clickbandit workflows
- Frame-busting bypass techniques and sandbox attribute mastery
- Defense mechanisms: X-Frame-Options, CSP frame-ancestors, SameSite cookies

### [cors-portswigger-labs-complete.md](./cors-portswigger-labs-complete.md) ⭐ NEW
**Complete PortSwigger CORS Lab Solutions** - All 4 CORS labs:
- **Lab 1 - Basic Origin Reflection**: Arbitrary origin trust, credential-included data theft (Apprentice)
- **Lab 2 - Null Origin**: Sandboxed iframe exploitation, null origin whitelisting bypass (Apprentice)
- **Lab 3 - Trusted Insecure Protocols**: HTTP subdomain XSS + HTTPS CORS trust chain (Practitioner)
- **Lab 4 - Internal Network Pivot**: Network scanning + XSS + CORS + CSRF multi-stage attack (Expert)
- Complete exploitation walkthroughs with exact JavaScript payloads
- HTTP traffic analysis and attack flow diagrams
- Burp Suite CORS testing workflows (Repeater, Intruder, Extensions)
- Real-world CVE examples and vulnerability impact analysis
- Comprehensive defense strategies and secure implementation guides

### [cors-quickstart.md](./cors-quickstart.md) ⚡ QUICK REFERENCE
**CORS Quick Start Guide** - Fast reference for practitioners:
- 60-second vulnerability check workflow
- Lab speed-run guides (2-10 minutes each)
- Common exploitation payloads (data theft, POST requests, multi-step attacks)
- Testing checklist with Burp Repeater
- Bypass techniques (null origin, regex, subdomain takeovers)
- Common mistakes and troubleshooting
- Risk assessment and reporting templates

### [cors-cheat-sheet.md](./cors-cheat-sheet.md) 📋 REFERENCE
**CORS Cheat Sheet** - Comprehensive quick reference:
- Complete CORS headers reference table
- Vulnerability patterns with code examples
- Exploitation payloads for all attack scenarios
- Testing commands (cURL, Burp Suite, automated tools)
- Burp Suite extensions and standalone tools
- Secure implementation examples (Node.js, Python, PHP, Java)
- Security checklist and remediation priorities
- CVSS scoring and CWE/MITRE ATT&CK mapping
- Real-world attack scenarios and social engineering techniques
- Academic research references (Stanford, USENIX papers)
- Common mistakes and troubleshooting tips

### [ssrf-portswigger-labs-complete.md](./ssrf-portswigger-labs-complete.md) ⭐ NEW
**Complete PortSwigger SSRF Lab Solutions** - All 8 SSRF labs:
- **Lab 1 - Basic SSRF Against Localhost**: Direct localhost admin access (Apprentice - 2 min)
- **Lab 2 - Backend System Scanning**: Internal network enumeration with Intruder (Apprentice - 3 min)
- **Lab 3 - Blacklist Filter Bypass**: Alternative IPs and double encoding (Practitioner - 2 min)
- **Lab 4 - Whitelist Filter Bypass**: URL parsing inconsistencies and fragment encoding (Expert - 3 min)
- **Lab 5 - Blind SSRF OOB Detection**: Burp Collaborator for blind detection (Practitioner - 1 min)
- **Lab 6 - Shellshock Exploitation**: DNS exfiltration with RCE on internal systems (Expert - 5 min)
- **Lab 7 - OpenID Dynamic Registration**: AWS metadata theft via logo_uri (Expert - 4 min)
- **Lab 8 - Flawed Request Parsing**: Host header injection and routing SSRF (Expert - 5 min)
- Step-by-step solutions with exact payloads and HTTP requests
- Complete Burp Suite workflows: Collaborator, Intruder, Repeater
- Cloud metadata exploitation: AWS, Azure, Google Cloud, DigitalOcean
- Protocol smuggling: Gopher, file://, dict://, LDAP
- Real-world CVEs: Capital One (2019), VMware vCenter, Grafana, Oracle E-Business
- **Total completion time**: ~25 minutes with practice

### [ssrf-quickstart.md](./ssrf-quickstart.md) ⚡ QUICK REFERENCE
**SSRF Quick Start Guide** - Lightning-fast exploitation reference:
- Instant lab solutions (1-5 minutes each)
- Fast exploitation checklist (5-minute full test)
- Quick payloads: localhost representations, cloud metadata, encoding bypasses
- Burp Suite speed tips and keyboard shortcuts
- Common patterns: stock check, webhooks, OAuth, PDF generation
- Emergency bypass cheat sheet
- Lab completion time tracker

### [ssrf-cheat-sheet.md](./ssrf-cheat-sheet.md) 📋 REFERENCE
**SSRF Cheat Sheet** - Comprehensive quick reference:
- Complete payload library: localhost, private IPs, encoding variations
- Bypass techniques: blacklist, whitelist, DNS rebinding, protocol smuggling
- Cloud metadata endpoints: AWS (IMDSv1/v2), Azure, Google Cloud, DigitalOcean, Oracle, Alibaba, Kubernetes
- Protocol exploitation: Gopher, file://, dict://, LDAP, FTP, SMB
- Detection methods: direct, timing-based, out-of-band, content-based
- Tools and commands: cURL, Python, SSRFmap, Gopherus, ffuf, Burp extensions
- Prevention checklist: input validation, network security, application security
- Secure implementation examples (Python, Node.js)
- AWS IMDSv2 configuration for SSRF protection

### [xxe-portswigger-labs-complete.md](./xxe-portswigger-labs-complete.md) ⭐ NEW
**Complete PortSwigger XXE Lab Solutions** - All 9 XXE labs:
- **Lab 1 - Basic File Retrieval**: External entities to read `/etc/passwd` (Apprentice)
- **Lab 2 - SSRF via XXE**: AWS EC2 metadata access, IAM credential extraction (Apprentice)
- **Lab 3 - Blind XXE OOB**: Out-of-band detection with Burp Collaborator (Practitioner)
- **Lab 4 - Parameter Entities**: Bypassing entity restrictions with parameter entities (Practitioner)
- **Lab 5 - Blind Data Exfiltration**: External DTD hosting for file content extraction (Practitioner)
- **Lab 6 - Error-Based XXE**: Data extraction via XML parsing errors (Practitioner)
- **Lab 7 - XInclude**: File retrieval when DOCTYPE control is limited (Practitioner)
- **Lab 8 - File Upload XXE**: SVG-based XXE via image processing (Practitioner)
- **Lab 9 - Local DTD Repurposing**: Advanced error-based with system DTD files (Expert)
- Step-by-step solutions with exact payloads and HTTP requests
- Complete Burp Suite workflows for each lab
- Common mistakes and troubleshooting tips
- Real-world SSRF and cloud metadata exploitation techniques

### [xxe-quickstart.md](./xxe-quickstart.md) ⚡ QUICK REFERENCE
**XXE Quick Start Guide** - Fast reference for practitioners:
- 60-second XXE vulnerability check
- Lab speed-run guides (2-5 minutes each)
- Common payload templates (file read, SSRF, blind detection)
- Burp Suite workflow shortcuts
- Testing checklist with decision tree
- Quick troubleshooting guide
- Bug bounty 5-minute workflow
- Report template

### [xxe-cheat-sheet.md](./xxe-cheat-sheet.md) 📋 REFERENCE
**XXE Cheat Sheet** - Comprehensive payload reference:
- Complete payload library (file retrieval, SSRF, blind XXE, error-based)
- Cloud metadata endpoints (AWS, Azure, GCP)
- Protocol variations (file://, http://, ftp://, php://)
- Defense code examples (Java, PHP, Python, .NET, Node.js)
- Burp Suite commands and shortcuts
- Testing commands (curl, Python, JavaScript)
- Encoding reference (URL, XML, Base64)
- CVE examples and CVSS scoring
- Detection patterns and SIEM rules
- File format variations (SVG, DOCX, XLSX, RSS)

### [clickjacking-quickstart.md](./clickjacking-quickstart.md) ⚡ QUICK REFERENCE
**Clickjacking Quick Start Guide** - Fast reference for practitioners:
- Basic clickjacking templates (opacity, z-index, positioning)
- 5 attack scenarios (account takeover, form manipulation, DOM XSS trigger)
- Frame buster bypass using sandbox attribute
- CSS property explanations and alignment techniques
- Multi-step clickjacking for confirmations
- Defense implementations (headers, cookies, server configs)
- Burp Suite Clickbandit quick usage
- Quick troubleshooting guide

### [dom-based-vulnerabilities-complete.md](./dom-based-vulnerabilities-complete.md) ⭐ NEW
**Complete DOM-Based Vulnerabilities Master Reference** - Over 3500 lines:
- **17 Complete PortSwigger Lab Solutions**: All DOM-based labs (Apprentice to Expert) with exact payloads
- **All Vulnerability Types**: DOM XSS, web messages, open redirect, cookie manipulation, prototype pollution, DOM clobbering
- **Source/Sink Analysis**: location.search/hash/href, postMessage, document.write, innerHTML, eval(), jQuery methods
- **Context-Specific Exploitation**: HTML, innerHTML, JavaScript strings, URL/href, jQuery selectors, AngularJS, select elements
- **Web Messages Security**: 3 labs (postMessage exploitation, origin validation bypasses, JavaScript URL injection, JSON.parse)
- **Prototype Pollution**: Client-side pollution techniques, gadget discovery with DOM Invader, eval() exploitation, alternative vectors
- **DOM Clobbering**: Expert-level window property clobbering, attributes bypass, HTMLJanitor exploitation, multi-element collections
- **Complete Burp Suite DOM Invader Workflow**: Auto source/sink detection, prototype pollution scanning, gadget discovery, one-click exploits
- **Advanced Techniques**: WAF bypass with encoding, chaining vulnerabilities, cookie/credential theft, keylogging, BeEF integration
- **Prevention**: Input validation, output encoding, safe APIs, CSP, DOMPurify sanitization, framework-specific protections
- **Real-World CVEs**: jQuery vulnerabilities, Facebook SDK, Google DOM XSS, British Airways breach analysis
- **Industry Standards**: OWASP Top 10, CWE-79/85/87/94/95, MITRE ATT&CK T1189/T1059.007, PCI DSS 6.5.7
- **Tools & Automation**: DOM Invader, XSS Hunter, DalFox, XSStrike, custom detection scripts

### [dom-xss-quickstart.md](./dom-xss-quickstart.md) ⚡ QUICK REFERENCE
**DOM-Based Vulnerabilities Quick Start Guide** - Fast reference for practitioners:
- Context-specific payload cheatsheet (document.write, innerHTML, jQuery, AngularJS)
- All 17 labs with 1-3 minute completion strategies
- Burp Suite DOM Invader quick setup and workflows
- Common mistakes to avoid by context
- Quick detection script for browser console
- Payload encoding reference
- Speed testing workflow (1/5/15 minute tests)
- Bug bounty quick wins and report template

### [http-request-smuggling.md](./http-request-smuggling.md) ⭐ FEATURED
**Comprehensive HTTP Request Smuggling Master Reference** - Over 2500 lines of expertise:
- **20 Complete PortSwigger Lab Solutions**: Apprentice to Expert level with exact payloads
- **All Attack Techniques**: CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, CL.0, pause-based, client-side desync
- **Exploitation Patterns**: Bypass security controls, reveal headers, capture requests, XSS delivery, cache poisoning
- **HTTP/2 Downgrade Attacks**: CRLF injection, response queue poisoning, request tunnelling
- **Browser-Powered Attacks**: Fetch API exploitation, CL.0 smuggling, pause-based techniques
- **Complete Burp Suite Workflows**: Repeater, Inspector, Turbo Intruder, HTTP Request Smuggler extension
- **Tools & Automation**: Smuggler (Python), http2smugl, request_smuggler, automated detection
- **Real-World CVEs**: Akamai (CVE-2025-32094), .NET Core (CVE-2025-55315 CVSS 9.9), F5 BIG-IP, Apache
- **Research Foundation**: James Kettle's Black Hat series (2019, 2022, 2025) - $260k+ bug bounties
- **Industry Standards**: OWASP, MITRE CWE-444/CAPEC-33, RFC violations, PCI DSS compliance
- **Prevention Strategies**: HTTP/2 end-to-end, header validation, WAF rules, secure coding

### [http-request-smuggling-quickstart.md](./http-request-smuggling-quickstart.md) ⚡ QUICK REFERENCE
**HTTP Request Smuggling Quick Start Guide** - Fast reference for practitioners:
- Quick detection methods (2-3 minutes): time-based and automated scanning
- Fast exploitation patterns (3-8 minutes): admin bypass, request capture, XSS delivery, cache poisoning
- HTTP/2 quick tests (3-5 minutes): H2.CL and CRLF injection
- Browser-based CL.0 tests (5-10 minutes)
- Essential Burp Suite speed tips and configurations
- Common mistakes and quick fixes
- Lab speed-run strategies (2-15 minutes per lab)
- Essential payload templates and byte counting reference

### [http-request-smuggling-cheat-sheet.md](./http-request-smuggling-cheat-sheet.md) 📋 REFERENCE
**HTTP Request Smuggling Cheat Sheet** - Comprehensive quick reference:
- Complete detection payload library (CL.TE, TE.CL, differential responses)
- Exploitation payloads by attack pattern (bypass, reveal headers, capture, XSS, cache)
- HTTP/2 downgrade attack payloads (H2.CL, CRLF, tunnelling, cache poisoning)
- Advanced techniques (request tunnelling, :path injection, pause-based)
- Browser-powered attack scripts (client-side desync, CL.0, Fetch API)
- Header obfuscation techniques (TE.TE with 15+ variations)
- Burp Suite configurations and extensions
- Manual byte counting reference with examples
- Tools and automation scripts (Python, Bash, Burp)
- Attack pattern decision tree
- Testing checklist (detection, exploitation, advanced)
- Prevention strategies (server configs, application code, WAF rules)
- CVE reference with affected products
- Resources and standards (PortSwigger, Black Hat, RFC specs)

### [ssti-portswigger-labs-complete.md](./ssti-portswigger-labs-complete.md) ⭐ NEW
**Complete Server-Side Template Injection Master Reference** - Over 2500 lines:
- **7 Complete PortSwigger Lab Solutions**: All SSTI labs (Apprentice to Expert) with step-by-step exploitation
- **Lab 1 - Basic SSTI**: ERB (Ruby) direct template injection, system command execution (2-3 min)
- **Lab 2 - Code Context SSTI**: Tornado (Python) breaking out of expressions, import statements (5-8 min)
- **Lab 3 - Unknown Language**: Handlebars fingerprinting, documented RCE exploit via require() (10-15 min)
- **Lab 4 - Using Documentation**: Freemarker Execute class exploitation via official docs research (15-20 min)
- **Lab 5 - Information Disclosure**: Django debug tag, SECRET_KEY extraction (8-12 min)
- **Lab 6 - Custom Exploit**: PHP application object analysis, method chaining (setAvatar + gdprDelete) (30-45 min)
- **Lab 7 - Sandboxed Environment**: Java reflection chains to bypass Freemarker sandbox (20-30 min)
- **Template Engines Covered**: ERB, Tornado, Handlebars, Freemarker, Django, Jinja2, Twig, Smarty, Pug, Velocity, Mako
- **Exploitation Techniques**: Direct RCE, file operations, reflection chains, object traversal, sandbox bypasses
- **Detection Methods**: Polyglot fuzzing, mathematical expressions, error analysis, context-aware testing
- **Complete Burp Suite workflows**: Scanner, Repeater, Intruder, Collaborator for blind SSTI
- **Real-World CVEs**: Apache Airflow (CVE-2019-8446 CVSS 9.8), Kraken (CVE-2020-28196), GitLab, Pulse Secure VPN (CVE-2019-11510 CVSS 10.0)
- **Industry Standards**: OWASP A03:2021, MITRE CWE-94/95, CAPEC-242, NIST SP 800-53, PCI DSS 6.5.1

### [ssti-quickstart.md](./ssti-quickstart.md) ⚡ QUICK REFERENCE
**SSTI Quick Start Guide** - Fast reference for practitioners:
- 30-second detection with fuzzing payload (`${{<%[%'"}}%\`)
- Engine identification table (ERB, Tornado, Freemarker, Handlebars, Django)
- Rapid exploitation payloads for all major engines
- Lab completion times (2-45 minutes per lab)
- Breaking out of contexts (expressions, strings, attributes)
- Burp Suite quick setup and workflows
- Blind SSTI detection (DNS/HTTP callbacks, time-based)
- Common mistakes and fixes by engine
- ASCII conversion utilities (Lab 7 byte array decoding)

### [ssti-cheat-sheet.md](./ssti-cheat-sheet.md) 📋 REFERENCE
**SSTI Comprehensive Payload Reference**:
- Detection payloads (polyglot fuzzing, mathematical tests)
- Complete payload library for 10+ template engines
- Command execution techniques (Ruby, Python, Java, Node.js, PHP)
- File operations (read, write, directory listing)
- Sandbox bypass techniques (reflection, MRO traversal, class loaders)
- Reverse shell payloads for all platforms
- WAF bypass and encoding techniques
- Data exfiltration methods (DNS, HTTP, base64)
- Filter/function reference for each engine
- Burp Suite integration (Intruder, Collaborator)
- Quick reference table (syntax, output, execution methods)

### [ssti-resources.md](./ssti-resources.md) 📚 RESOURCES
**SSTI Complete Resources Collection**:
- Official template engine documentation (ERB, Jinja2, Tornado, Django, Freemarker, Handlebars, Twig, etc.)
- Research papers and presentations (James Kettle's Black Hat 2015 foundational work)
- OWASP resources (Testing Guide WSTG-INPV-18, Top 10 A03:2021)
- MITRE references (CWE-94, CWE-95, CAPEC-242, ATT&CK T1059)
- Notable CVEs with CVSS scores and exploitation details
- Industry standards (NIST, PCI DSS, ISO/IEC 27001)
- Tools & automation (tplmap, SSTImap, Burp Scanner, Nuclei)
- Payload collections (PayloadsAllTheThings, SecLists, FuzzDB)
- Training platforms (PortSwigger Academy, HackTheBox, TryHackMe)
- Bug bounty programs and notable bounties ($5,000-$10,000+)
- Books and academic papers on SSTI
- Community resources (Reddit, Discord, Twitter accounts)
- YouTube channels and conference talks
- Vulnerable applications for practice
- Defense resources and secure coding guidelines
- WAF rules (ModSecurity, Cloudflare, AWS WAF)
- Incident response procedures and IOC detection

### [path-traversal-portswigger-labs-complete.md](./path-traversal-portswigger-labs-complete.md) ⭐ NEW
**Complete PortSwigger Path Traversal Lab Solutions** - All 6 Path Traversal labs:
- **Lab 1 - Simple Case**: Basic directory traversal exploitation (`../../../etc/passwd`) (Apprentice - 1 min)
- **Lab 2 - Absolute Path Bypass**: Bypassing relative traversal filters with absolute paths (`/etc/passwd`) (Apprentice - 1 min)
- **Lab 3 - Non-Recursive Stripping**: Nested sequence bypass (`....//....//....//etc/passwd`) defeating single-pass filters (Practitioner - 2 min)
- **Lab 4 - Superfluous URL-Decode**: Double encoding bypass (`..%252f..%252f..%252fetc/passwd`) exploiting multiple decode stages (Practitioner - 2 min)
- **Lab 5 - Path Start Validation**: Prefix requirement bypass (`/var/www/images/../../../etc/passwd`) exploiting insufficient canonicalization (Practitioner - 3 min)
- **Lab 6 - Null Byte Injection**: Extension validation bypass (`../../../../etc/passwd%00.png`) exploiting C-based filesystem API termination (Practitioner - 2 min)
- Step-by-step solutions with exact payloads and HTTP requests/responses
- Complete Burp Suite workflows: Repeater for manual testing, Intruder for automated fuzzing, Scanner for detection
- All encoding variations: URL encoding (single/double/triple), Unicode full-width, UTF-8 overlong, 16-bit Unicode
- Platform-specific exploits: ASP.NET cookieless sessions, Java servlet manipulation, Nginx/Tomcat parsing, IIS 8.3 short names, PHP wrappers
- Target files: Linux critical files (`/etc/passwd`, `/etc/shadow`, `/proc/self/environ`, K8s tokens), Windows targets (`C:\windows\win.ini`, SAM database, IIS configs)
- Bypass techniques: Mixed separators, case sensitivity, UNC path injection, wildcard abuse, symlink exploitation
- Automation tools: dotdotpwn for comprehensive fuzzing, ffuf for fast testing, custom Python/Bash/PowerShell scripts
- Real-world CVEs: jsPDF (CVE-2025-68428 CVSS 8.6), Fortinet FortiWeb (CVE-2025-64446 CVSS 9.8), Apache Tomcat (CVE-2025-55752), AnythingLLM (CVE-2024-13059), Spring Framework (CVE-2024-38816/38819)
- Industry standards: OWASP Top 10 A01:2021 (Broken Access Control), CWE-22/23/36/73, CAPEC-126, NIST SP 800-53, PCI DSS 6.5.8, ISO 27001
- Prevention strategies: Avoid user input in file paths, indirect reference mapping, whitelist validation, path canonicalization with verification, chroot jails
- Defense in depth: Framework-specific protections (Express.static, Spring ResourceHandler), WAF rules (ModSecurity, AWS WAF), input sanitization
- **Total completion time**: ~15 minutes with practice

### [path-traversal-quickstart.md](./path-traversal-quickstart.md) ⚡ QUICK REFERENCE
**Path Traversal Quick Start Guide** - Lightning-fast exploitation reference:
- Instant lab solutions (1-3 minutes each)
- Fast exploitation checklist (5-minute full test)
- Quick payloads: basic traversal, absolute paths, nested sequences, double encoding, null bytes
- Burp Suite speed tips and keyboard shortcuts
- Common mistakes and troubleshooting by lab
- Speed run strategy for all 6 labs in 15 minutes
- Lab completion time tracker

### [path-traversal-cheat-sheet.md](./path-traversal-cheat-sheet.md) 📋 REFERENCE
**Path Traversal Cheat Sheet** - Comprehensive quick reference:
- Complete payload library: basic traversal, encoding variations, bypass techniques (100+ payloads)
- Encoding techniques: URL encoding (single/double/triple), Unicode, UTF-8 overlong, 16-bit Unicode
- Bypass methods: Nested sequences, absolute paths, null bytes, URL encoding, prefix bypass, mixed separators, UNC paths
- Target files: Linux critical files (authentication, system info, app config, database, cloud/container), Windows targets, macOS targets
- Platform-specific attacks: ASP.NET cookieless sessions, Java servlet manipulation, Nginx/Tomcat inconsistencies, IIS short names, PHP wrappers, Node.js normalization
- Automation scripts: Bash, Python, PowerShell, Burp Intruder payloads, ffuf, dotdotpwn
- Detection & prevention: Log analysis patterns, SIEM queries (Splunk, ELK), prevention code examples (Python/Flask, Node.js/Express, Java/Spring, PHP)
- WAF rules: ModSecurity, Nginx configuration
- Testing checklist: Manual testing, automated testing, post-exploitation steps
- Quick command reference: cURL, Python, PowerShell, ffuf, dotdotpwn

### [web-application-attacks.md](./web-application-attacks.md)
Web application security testing including:
- SQL Injection (Quick Reference - see sql-injection.md for comprehensive guide)
- Cross-Site Scripting (Quick Reference - see cross-site-scripting.md for comprehensive guide)
- Cross-Site Request Forgery (Quick Reference - see csrf-portswigger-labs-complete.md for comprehensive guide)
- Clickjacking / UI Redressing (Quick Reference - see clickjacking-portswigger-labs-complete.md for comprehensive guide)
- Server-Side Template Injection (Quick Reference - see ssti-portswigger-labs-complete.md for comprehensive guide)
- Authentication Bypass
- Server-Side Request Forgery (Quick Reference - see ssrf-portswigger-labs-complete.md for comprehensive guide)
- XML External Entity (Quick Reference - see xxe-portswigger-labs-complete.md for comprehensive guide)
- Insecure Deserialization
- Path Traversal / Directory Traversal (Quick Reference - see path-traversal-portswigger-labs-complete.md for comprehensive guide)
- Remote Code Execution (RCE)
- API Security Issues

### [network-attacks.md](./network-attacks.md)
Network-level attack techniques including:
- Man-in-the-Middle (MitM) Attacks
- ARP Spoofing/Poisoning
- DNS Attacks
- Network Sniffing
- Port Scanning & Enumeration
- VLAN Hopping
- SMB/NetBIOS Attacks
- IPv6 Attacks
- Denial of Service (DoS/DDoS)

### [websockets-portswigger-labs-complete.md](./websockets-portswigger-labs-complete.md) ⭐ NEW
**Complete PortSwigger WebSocket Lab Solutions** - All 3 WebSocket labs:
- **Message Manipulation**: XSS via WebSocket message interception (Apprentice level)
- **Handshake Exploitation**: IP ban bypass + XSS filter evasion (Practitioner level)
- **Cross-Site WebSocket Hijacking (CSWSH)**: Credential theft via malicious JavaScript (Practitioner level)
- Step-by-step solutions with exact payloads and HTTP/WebSocket requests
- Complete Burp Suite workflows (WebSocket history, Repeater, Collaborator)
- Real-world CVEs: Node.js auth bypass (CVE-2024-55591), Spring RCE (CVE-2018-1270), Gitpod CSWSH
- Attack techniques: Message manipulation, handshake exploitation, CSWSH, input validation bypass
- Tools & automation: Burp Suite, OWASP ZAP, wscat, websocat, Python scripts
- Defense mechanisms: CSRF tokens, origin validation, wss:// encryption, input sanitization
- Over 17,000 lines of comprehensive WebSocket security expertise

### [websockets-quickstart.md](./websockets-quickstart.md) ⚡ QUICK REFERENCE
**WebSockets Quick Start Guide** - Complete all 3 labs in 60-90 minutes:
- Lab 1: Message manipulation in 15-20 minutes
- Lab 2: Handshake exploitation in 20-30 minutes
- Lab 3: CSWSH attack in 25-35 minutes
- Rapid solution steps for each lab
- Key payloads and techniques
- Burp Suite shortcuts and workflows
- Common issues and troubleshooting
- Testing methodology checklist

### [websockets-cheat-sheet.md](./websockets-cheat-sheet.md) 📋 CHEAT SHEET
**WebSockets Security Cheat Sheet** - Quick reference for penetration testing:
- WebSocket handshake headers
- Attack payloads (XSS, SQLi, Command Injection, XXE, Path Traversal)
- Burp Suite commands and workflows
- Tools & commands (wscat, websocat, Python, JavaScript)
- Exploitation scripts (XSS fuzzer, CSWSH generator, automated testing)
- Detection & identification techniques
- Common vulnerabilities and CVEs
- Defense checklist and secure implementation

### [websockets-resources.md](./websockets-resources.md) 📚 RESOURCES
**WebSockets Security Resources** - Comprehensive learning materials:
- Official standards: RFC 6455, W3C WebSocket API
- OWASP resources: Security cheat sheet, testing guide
- Industry standards: NIST, PCI DSS, ISO 27001, CWE, CAPEC
- CVE database and real-world advisories
- Tools & frameworks: Burp Suite, ZAP, wscat, websocat, SocketSleuth
- Research papers and technical articles
- Training platforms: PortSwigger Academy, HackTheBox, TryHackMe
- Bug bounty programs with WebSocket scope
- Vulnerable applications for practice
- Community forums and security researchers

### [system-exploitation.md](./system-exploitation.md)
Operating system and service exploitation:
- Buffer Overflow
- Linux Privilege Escalation
- Windows Privilege Escalation
- Remote Code Execution Exploits
- DLL Hijacking
- Kernel Exploits
- Active Directory Exploitation
- Container Escape

### [password-attacks.md](./password-attacks.md)
Credential compromise techniques:
- Brute Force Attacks
- Dictionary Attacks
- Hash Cracking (Hashcat, John the Ripper)
- Credential Dumping (Mimikatz)
- Pass-the-Hash (PtH)
- Password Spraying
- Credential Stuffing
- Phishing for Credentials
- Keylogging

### [wireless-attacks.md](./wireless-attacks.md)
Wireless network security testing:
- WPA/WPA2 Attacks
- WPA3 Attacks
- Evil Twin / Rogue Access Point
- Deauthentication Attacks
- Bluetooth Attacks
- RFID/NFC Attacks
- Wireless Packet Sniffing
- Wireless Jamming
- Wi-Fi Direct Attacks

### [social-engineering.md](./social-engineering.md)
Human-targeted attack techniques:
- Phishing Attacks (Email, Spear, Whaling)
- Pretexting
- Vishing (Voice Phishing)
- Smishing (SMS Phishing)
- Physical Social Engineering
- Watering Hole Attacks
- Baiting
- Quid Pro Quo
- Business Email Compromise (BEC)
- Shoulder Surfing

### [cloud-security.md](./cloud-security.md)
Cloud platform security testing:
- AWS Security Testing
- Azure Security Testing
- Google Cloud Platform (GCP) Security
- Container Security (Docker/Kubernetes)
- Serverless Security
- SaaS Security Testing

### [report-templates.md](./report-templates.md)
Professional reporting templates:
- Executive Summary Template
- Technical Findings Report Template
- Compliance-Focused Report Template
- Red Team Report Template
- Individual Finding Template
- Best Practices for Report Writing

## How to Use This Reference Library

### During Reconnaissance Phase
1. Start with the main SKILL.md file to understand the overall methodology
2. Reference network-attacks.md for scanning and enumeration techniques
3. Use appropriate reference files based on discovered services

### During Vulnerability Assessment
1. Identify attack surface (web, network, wireless, etc.)
2. Consult relevant reference file for testing methodology
3. Use provided tool commands and examples
4. Follow detection and evasion techniques as appropriate

### During Exploitation
1. Reference specific attack techniques in detail
2. Follow proof-of-concept examples
3. Adapt commands to your target environment
4. Document all steps for reporting

### During Reporting
1. Use report-templates.md for structure
2. Include references to specific attack types (CWE, CVE, OWASP)
3. Map findings to MITRE ATT&CK framework
4. Provide detailed remediation from reference files

## Reference Format

Each reference file follows this structure:

```markdown
## [Attack Name]

### Description
Brief overview of the attack

### Types/Variants
Different variations of the attack

### Tools
Relevant tools and frameworks

### Testing Methodology
Step-by-step testing approach

### Example Commands
Practical command examples

### Detection Methods
How defenders can detect this attack

### Remediation
How to fix and prevent the vulnerability

### References
- MITRE ATT&CK mappings
- CWE identifiers
- CVE examples
- CAPEC patterns
- Additional resources
```

## MITRE ATT&CK Mapping

All attack techniques are mapped to the MITRE ATT&CK framework for standardized classification:

| Reference File | Primary Tactics |
|---------------|----------------|
| web-application-attacks.md | Initial Access, Execution |
| network-attacks.md | Discovery, Credential Access, Lateral Movement |
| system-exploitation.md | Privilege Escalation, Execution |
| password-attacks.md | Credential Access |
| wireless-attacks.md | Initial Access, Collection |
| social-engineering.md | Initial Access, Collection |
| cloud-security.md | Discovery, Credential Access, Exfiltration |

## Compliance Framework Mapping

### OWASP Top 10 (2021)
- A01: Broken Access Control → web-application-attacks.md
- A02: Cryptographic Failures → cloud-security.md
- A03: Injection → web-application-attacks.md
- A04: Insecure Design → (general methodology)
- A05: Security Misconfiguration → cloud-security.md, system-exploitation.md
- A06: Vulnerable Components → system-exploitation.md
- A07: Identification and Authentication Failures → password-attacks.md
- A08: Software and Data Integrity Failures → web-application-attacks.md
- A09: Security Logging Failures → (detection methods in all files)
- A10: SSRF → web-application-attacks.md

### CIS Controls
- Control 1: Asset Inventory → network-attacks.md (scanning)
- Control 3: Data Protection → cloud-security.md
- Control 4: Secure Configuration → system-exploitation.md
- Control 5: Account Management → password-attacks.md
- Control 6: Access Control → All files
- Control 11: Data Recovery → (testing backups)
- Control 12: Network Infrastructure → network-attacks.md
- Control 13: Network Monitoring → (detection methods)
- Control 14: Security Awareness → social-engineering.md
- Control 16: Application Security → web-application-attacks.md

## Legal and Ethical Considerations

**IMPORTANT:** All techniques documented in this reference library should only be used:

1. ✅ Within defined scope boundaries
2. ✅ In compliance with applicable laws
3. ✅ Following responsible disclosure practices
4. ✅ With proper documentation

**Never:**
- ❌ Test systems without authorization
- ❌ Exceed agreed-upon scope
- ❌ Cause unnecessary damage or disruption
- ❌ Access or exfiltrate real sensitive data unnecessarily
- ❌ Use techniques for malicious purposes

## Continuous Updates

This reference library should be regularly updated with:
- New attack techniques and tools
- Updated CVE references
- Emerging threats
- New detection methods
- Enhanced remediation guidance
- Tool updates and new versions

## Contributing

When adding new attack references:
1. Follow the established format
2. Include all sections (Description, Tools, Methodology, etc.)
3. Provide practical examples
4. Map to MITRE ATT&CK
5. Include CWE/CVE references
6. Add detection and remediation guidance
7. Update this README with the new content

## Additional Resources

### Online Resources
- MITRE ATT&CK: https://attack.mitre.org/
- OWASP: https://owasp.org/
- CWE: https://cwe.mitre.org/
- CVE: https://cve.mitre.org/
- Exploit-DB: https://www.exploit-db.com/
- GTFOBins: https://gtfobins.github.io/
- LOLBAS: https://lolbas-project.github.io/

### Testing Frameworks
- PTES: http://www.pentest-standard.org/
- OSSTMM: https://www.isecom.org/OSSTMM.3.pdf
- NIST SP 800-115: https://csrc.nist.gov/publications/detail/sp/800-115/final

### Tool Documentation
- Metasploit: https://docs.metasploit.com/
- Burp Suite: https://portswigger.net/burp/documentation
- Nmap: https://nmap.org/book/
- Hashcat: https://hashcat.net/wiki/

## Quick Reference Guide

### Common Port Services
```
21    - FTP
22    - SSH
23    - Telnet
25    - SMTP
53    - DNS
80    - HTTP
110   - POP3
139   - NetBIOS
143   - IMAP
443   - HTTPS
445   - SMB
3306  - MySQL
3389  - RDP
5432  - PostgreSQL
5900  - VNC
8080  - HTTP Proxy
```

### CVSS v3.1 Quick Reference
```
Critical: 9.0-10.0
High:     7.0-8.9
Medium:   4.0-6.9
Low:      0.1-3.9
Info:     0.0
```

### Common Attack Commands Quick Reference
```bash
# Network Scan
nmap -sS -sV -sC -oA results target

# Web Scan
nikto -h https://target.com

# Directory Brute Force
gobuster dir -u https://target.com -w wordlist.txt

# SQL Injection
sqlmap -u "https://target.com/?id=1" --batch --dbs

# Hash Cracking
hashcat -m 1000 -a 0 hashes.txt wordlist.txt

# Wireless Handshake Capture
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
```

---

## What's New

### January 2026 - Prototype Pollution Mastery Update
Added comprehensive prototype pollution documentation featuring:
- **Complete PortSwigger Web Security Academy lab walkthroughs** (7 Prototype Pollution labs)
  - Apprentice level (1 lab): DOM XSS via client-side prototype pollution
  - Practitioner level (3 labs): Browser APIs bypass, flawed sanitization, privilege escalation
  - Expert level (3 labs): Third-party libraries, RCE, data exfiltration
- **Three specialized reference files**:
  - `prototype-pollution-portswigger-labs-complete.md` - All 7 lab solutions with comprehensive walkthroughs (over 17,000 lines)
  - `prototype-pollution-quickstart.md` - Fast reference guide for 2-hour complete walkthrough
  - `prototype-pollution-cheat-sheet.md` - Complete payload library and exploitation techniques
  - `prototype-pollution-resources.md` - 100+ resources, tools, and references
- **Step-by-step exploitation techniques** with exact payloads, HTTP requests, and troubleshooting
- **All prototype pollution attack types covered**:
  - Client-side: DOM XSS via gadgets, browser API exploitation, sanitization bypass, third-party library exploitation
  - Server-side: Privilege escalation, remote code execution, data exfiltration
- **Complete exploitation chains**: Source → Sink → Gadget methodology
- **Detection methods**: Property reflection, JSON spaces override, status code manipulation, charset override, DOM Invader
- **Bypass techniques**: Non-recursive filter evasion (`__pro__proto__to__`), constructor alternatives, Unicode encoding
- **Complete Burp Suite workflows**: DOM Invader for automatic detection, Repeater for testing, Collaborator for RCE verification
- **Automation tools**: DOM Invader, Server-Side PP Scanner, Gadgets Finder, ppmap, ppfuzz, PPScan, Dasty
- **Real-world CVE examples**: React2Shell (CVE-2025-55182/66478 CVSS 10.0 - $10k-$50k bounties), web3-utils (CVE-2024-21505), jQuery (CVE-2019-11358), minimist (CVE-2020-7598), path-parse (CVE-2021-23343)
- **Industry standards**: OWASP Prototype Pollution Prevention Cheat Sheet, CWE-1321, MITRE ATT&CK T1059/T1068/T1190, CAPEC-10/113, NIST SP 800-53, PCI DSS 6.5.1/6.5.7, ISO 27001
- **Prevention strategies**: Property key sanitization (allowlist/blocklist), freeze/seal prototypes, Object.create(null) for safe objects, use Map/Set instead of objects, framework-specific middleware, CSP headers
- **Framework-specific protection**: Node.js/Express middleware, React/Next.js input sanitization, Python/Flask validation, TypeScript type-safe configurations
- **Defense in depth**: WAF rules (ModSecurity, Cloudflare, AWS WAF), SIEM detection (Splunk, ELK, Azure Sentinel), secure coding guidelines
- **Research foundation**: James Kettle's groundbreaking work ($60k+ bug bounties), Dasty tool (ACM Web Conference 2024), Doyensec Gadgets Finder
- **Training resources**: PortSwigger Academy (7 FREE interactive labs), HackTheBox challenges, TryHackMe rooms, PentesterLab exercises
- **Bug bounty context**: HackerOne/Bugcrowd programs, $5k-$50k+ payouts for critical findings, real-world exploitation scenarios
- **Over 400 practical payloads and examples** across all prototype pollution attack vectors
- **Testing methodologies**: Client-side (5-minute test), server-side (10-minute test), comprehensive security assessment checklist
- **25,000+ lines** of comprehensive prototype pollution security expertise

### January 2026 - Path Traversal / Directory Traversal Mastery Update
Added comprehensive path traversal documentation featuring:
- **Complete PortSwigger Web Security Academy lab walkthroughs** (6 Path Traversal labs)
  - Apprentice level (2 labs): Simple case, absolute path bypass
  - Practitioner level (4 labs): Non-recursive stripping, superfluous URL-decode, path start validation, null byte injection
- **Three specialized reference files**:
  - `path-traversal-portswigger-labs-complete.md` - All 6 lab solutions with comprehensive walkthroughs (over 3,500 lines)
  - `path-traversal-quickstart.md` - Fast reference guide for 15-minute complete walkthrough
  - `path-traversal-cheat-sheet.md` - Complete payload library with 100+ payloads
- **Step-by-step exploitation techniques** with exact payloads, HTTP requests, and troubleshooting
- **All path traversal attack types covered**:
  - Basic traversal (depth testing with `../` sequences)
  - Absolute path bypass (defeating relative traversal filters)
  - Non-recursive stripping bypass (nested sequences like `....//`)
  - Double URL encoding bypass (exploiting multiple decode stages)
  - Path prefix validation bypass (including required prefix then traversing out)
  - Null byte injection (terminating string parsing before extension validation)
- **Complete encoding variations**: URL encoding (single/double/triple), Unicode full-width characters, UTF-8 overlong encoding, 16-bit Unicode sequences
- **Platform-specific exploitation**: ASP.NET cookieless session injection, Java servlet manipulation, Nginx/Tomcat path parsing inconsistencies, IIS 8.3 short name enumeration, PHP wrapper exploitation, Node.js path normalization bypass
- **Comprehensive target files**: Linux critical files (`/etc/passwd`, `/etc/shadow`, `/proc/self/environ`, `/root/.ssh/id_rsa`, Kubernetes tokens), Windows targets (`C:\windows\win.ini`, SAM database, IIS configs), macOS targets
- **Complete Burp Suite workflows**: Repeater for manual testing, Intruder for automated fuzzing with depth/encoding variations, Scanner for vulnerability detection
- **Automation tools**: dotdotpwn for comprehensive fuzzing, ffuf for fast directory traversal testing, custom Python/Bash/PowerShell scripts
- **Real-world CVE examples**: jsPDF (CVE-2025-68428 CVSS 8.6 - arbitrary file read via PDF generation), Fortinet FortiWeb (CVE-2025-64446 CVSS 9.8 - auth bypass + path traversal), Apache Tomcat (CVE-2025-55752 - URL rewrite order-of-operations flaw), AnythingLLM (CVE-2024-13059 - path traversal to RCE), Spring Framework (CVE-2024-38816/38819 - static resource path traversal)
- **Industry standards**: OWASP Top 10 A01:2021 (Broken Access Control ranked #1), CWE-22/23/36/73, CAPEC-126, MITRE ATT&CK, NIST SP 800-53 (SI-10 Input Validation), PCI DSS 6.5.8, ISO/IEC 27001
- **Defense in depth strategies**: Avoid user input in file paths entirely, use indirect reference mapping (ID → filename), implement whitelist validation, path canonicalization with verification (`realpath()`), principle of least privilege, chroot jails/containerization
- **Framework-specific protections**: Express.static (Node.js), Spring ResourceHandler (Java), Flask send_file (Python), PHP realpath() validation
- **WAF rules**: ModSecurity rule sets for path traversal detection, AWS WAF rules, Nginx configuration examples
- **Detection methods**: Log analysis patterns (Apache/Nginx), SIEM correlation rules (Splunk/ELK queries), IDS/IPS signatures
- **Incident response**: Detection indicators (log patterns, alert thresholds), response procedures (immediate blocking, investigation, remediation), post-incident activities
- **Over 200 practical payloads and examples** across all bypass techniques and target platforms
- **Testing checklist**: Manual testing (10 verification steps), automated testing (tools and scripts), post-exploitation enumeration
- **10,000+ lines** of comprehensive path traversal expertise covering all attack vectors, defensive measures, and practical exploitation

### January 2026 - HTTP Request Smuggling Mastery Update
Added comprehensive HTTP request smuggling documentation featuring:
- **Complete PortSwigger Web Security Academy lab walkthroughs** (20 HTTP request smuggling labs)
  - Apprentice level (2 labs): Basic CL.TE and TE.CL variants
  - Practitioner level (9 labs): Header obfuscation, differential responses, security bypass, header discovery, request capture, XSS delivery, cache attacks
  - Expert level (9 labs): HTTP/2 downgrade attacks, CRLF injection, response queue poisoning, request tunnelling, browser-powered attacks, pause-based smuggling
- **Three specialized reference files**:
  - `http-request-smuggling.md` - All 20 lab solutions with comprehensive walkthroughs (over 2,500 lines)
  - `http-request-smuggling-quickstart.md` - Fast reference guide for 5-15 minute rapid testing and exploitation
  - `http-request-smuggling-cheat-sheet.md` - Complete payload library with all attack variants
- **Step-by-step exploitation techniques** with exact payloads, HTTP requests, and byte counting guidance
- **All HTTP request smuggling attack types covered**:
  - Basic techniques (CL.TE, TE.CL, TE.TE header obfuscation)
  - Exploitation patterns (bypass security controls, reveal hidden headers, capture user requests, deliver XSS, cache poisoning/deception)
  - HTTP/2 attacks (H2.CL smuggling, CRLF injection, response queue poisoning, request tunnelling)
  - Browser-powered attacks (client-side desync via Fetch API, CL.0 smuggling, pause-based server-side attacks)
  - Advanced techniques (request tunnelling with CRLF in header names, :path pseudo-header injection, SSL client certificate bypass)
- **Complete Burp Suite workflows**: Repeater with HTTP/1 protocol switching, Inspector for CRLF injection, Turbo Intruder for timing attacks, HTTP Request Smuggler extension, tab groups for sequential requests
- **Detection methods**: Time-based detection (10-second delays), differential response analysis, automated scanning with HTTP Request Smuggler
- **Tools & automation**: HTTP Request Smuggler extension, Smuggler (Python by defparam), http2smugl, request_smuggler, h2csmuggler, commercial scanners
- **Real-world CVE examples**: Akamai (CVE-2025-32094), .NET Core (CVE-2025-55315 CVSS 9.9 Critical), F5 BIG-IP (CVE-2023-46747), Apache HTTP Server (CVE-2023-25690), Node.js llhttp parser (CVE-2022-32214)
- **Research foundation**: James Kettle's groundbreaking Black Hat series:
  - 2019: HTTP Desync Attacks ($60k+ bug bounties)
  - 2022: Browser-Powered Desync Attacks (targeting Akamai, Varnish, Amazon)
  - 2025: HTTP/1.1 Must Die ($200k+ in two weeks, compromising Akamai, Cloudflare, Netlify)
- **Industry standards**: OWASP guidelines, MITRE CWE-444 (Inconsistent Interpretation) / CAPEC-33, RFC 9112/7230/7540 violations, PCI DSS compliance implications
- **Prevention strategies**: HTTP/2 end-to-end usage, strict header validation (reject both CL and TE), connection management, WAF rules (ModSecurity), secure coding practices
- **Over 300 practical payloads and examples** across all HTTP request smuggling attack vectors
- **Byte counting reference**: Manual calculation guide with common formulas and troubleshooting
- **Attack pattern decision tree**: Systematic approach to identify architecture, test protocols, detect variants, choose exploitation
- **Testing checklist**: Detection phase (7 tests), exploitation phase (7 attacks), advanced testing (5 techniques)
- **11,000+ lines** of comprehensive HTTP request smuggling expertise

### January 2026 - XML External Entity (XXE) Injection Mastery Update
Added comprehensive XXE injection documentation featuring:
- **Complete PortSwigger Web Security Academy lab walkthroughs** (9 XXE labs)
  - Apprentice level (2 labs): Basic file retrieval, SSRF via XXE to AWS metadata
  - Practitioner level (6 labs): Blind XXE (OOB, parameter entities, data exfiltration), error-based, XInclude, file upload
  - Expert level (1 lab): Local DTD repurposing with entity redefinition
- **Three specialized reference files**:
  - `xxe-portswigger-labs-complete.md` - All 9 lab solutions with comprehensive walkthroughs (over 2,000 lines)
  - `xxe-quickstart.md` - Fast reference guide for rapid testing and 2-5 minute lab completion
  - `xxe-cheat-sheet.md` - Complete payload library with all protocols and commands
- **Step-by-step exploitation techniques** with exact payloads, HTTP requests, and DTD structures
- **All XXE attack types covered**:
  - Basic file retrieval (external entities, local filesystem access)
  - SSRF attacks (cloud metadata endpoints, internal service enumeration, port scanning)
  - Blind XXE detection (out-of-band with Burp Collaborator, DNS/HTTP callbacks)
  - Data exfiltration (external DTD hosting, parameter entity chaining)
  - Error-based extraction (XML parsing errors with file contents)
  - XInclude attacks (when DOCTYPE control is limited)
  - File upload XXE (SVG, DOCX, XLSX exploitation)
  - Local DTD repurposing (advanced error-based with system DTDs)
- **Complete Burp Suite workflows**: Collaborator setup for OOB detection, Repeater testing, payload variations, automated scanning
- **Cloud security focus**: AWS EC2 metadata exploitation, IAM credential extraction, Azure/GCP metadata endpoints
- **Protocol variations**: file://, http://, https://, ftp://, php://, expect://, jar://, gopher://
- **Advanced techniques**: Parameter entities, nested entity definitions, Billion Laughs DoS, UTF-16 encoding for WAF bypass
- **Real-world CVE examples**: Apache Struts (CVE-2017-9805, Equifax breach), SAP NetWeaver (CVE-2020-6287), Microsoft Office (CVE-2018-0798)
- **Defense mechanisms**: Disabling external entities, DTD processing restrictions, safe parser configuration (Java, PHP, Python, .NET, Node.js)
- **Industry standards**: OWASP Top 10, CWE-611/776/827, MITRE ATT&CK T1190, CAPEC-221/228
- **Tools & automation**: Burp Suite Collaborator, XXEinjector, XXExploiter, dtd-finder
- **Over 200 practical payloads and examples** across all XXE attack vectors
- **Detection and prevention**: SIEM rules, WAF configurations, ModSecurity rules, input validation patterns
- **8,000+ lines** of comprehensive XXE expertise

### January 2026 - DOM-Based Vulnerabilities Mastery Update
Added comprehensive DOM-based vulnerabilities documentation featuring:
- **Complete PortSwigger Web Security Academy lab walkthroughs** (17 DOM-based labs)
  - Apprentice level (6 labs): document.write, innerHTML, jQuery href, hashchange, AngularJS, select element
  - Practitioner level (9 labs): Web messages (3), open redirect, cookie manipulation, reflected/stored DOM XSS, prototype pollution (2)
  - Expert level (2 labs): DOM clobbering techniques with HTMLJanitor bypass
- **Two specialized reference files**:
  - `dom-based-vulnerabilities-complete.md` - All 17 lab solutions with comprehensive walkthroughs (3500+ lines)
  - `dom-xss-quickstart.md` - Fast reference guide for rapid testing and 1-3 minute lab completion
- **Step-by-step exploitation techniques** with exact payloads, HTTP requests, and JavaScript code analysis
- **All DOM vulnerability types covered**:
  - DOM XSS fundamentals (sources, sinks, context-based exploitation)
  - Web messages exploitation (postMessage vulnerabilities, origin validation bypasses)
  - DOM-based open redirection and cookie manipulation
  - Client-side prototype pollution with gadget discovery
  - DOM clobbering (window properties, attributes bypass, HTMLJanitor)
- **Complete Burp Suite DOM Invader workflows**: Automatic source/sink detection, prototype pollution scanning, gadget discovery, one-click exploitation
- **Advanced exploitation techniques**: WAF bypass with encoding, chaining vulnerabilities (DOM XSS + CSRF + clickjacking), exfiltration methods
- **Real-world CVE examples**: jQuery vulnerabilities (CVE-2020-6095), Facebook SDK (CVE-2021-23343), jQuery location.hash (CVE-2019-11358), Ghost CMS prototype pollution
- **Industry case studies**: British Airways breach (380,000 customers affected, £183M fine), Ticketmaster breach (40,000 customers, £1.25M fine)
- **Defense mechanisms**: Input validation, output encoding, safe APIs, Content Security Policy, DOMPurify sanitization, framework-specific protections
- **Industry standards**: OWASP Top 10, CWE-79/85/87/94/95, MITRE ATT&CK T1189/T1059.007, PCI DSS 6.5.7
- **Tools & automation**: DOM Invader, XSS Hunter, DalFox, XSStrike, custom detection scripts
- **Over 150 practical payloads and examples** across all DOM vulnerability types
- **10,000+ lines** of comprehensive DOM security expertise

### January 2026 - Clickjacking / UI Redressing Mastery Update
Added comprehensive clickjacking documentation featuring:
- **Complete PortSwigger Web Security Academy lab walkthroughs** (5 Clickjacking labs)
  - Apprentice level (2 labs): Basic clickjacking with CSRF token bypass, form prepopulation attack
  - Practitioner level (3 labs): Frame buster bypass, DOM XSS trigger, multi-step clickjacking
- **Two specialized reference files**:
  - `clickjacking-portswigger-labs-complete.md` - All 5 lab solutions with comprehensive walkthroughs
  - `clickjacking-quickstart.md` - Fast reference guide for rapid testing
- **Step-by-step exploitation techniques** with exact HTML exploits and CSS positioning
- **All attack categories covered**:
  - Basic UI redressing with opacity and z-index manipulation
  - Form data prepopulation via URL parameters
  - Frame-busting bypass using HTML5 sandbox attribute
  - Multi-step clickjacking for confirmation dialogs
  - Combined clickjacking + DOM-based XSS exploitation
- **Complete Burp Suite workflows** including Clickbandit tool automation
- **Advanced bypass techniques**: Sandbox attribute mastery, double framing, timing attacks
- **Real-world attack scenarios**: Account takeover, financial fraud, OAuth hijacking, privacy violations
- **Academic research references**: Stanford "Busting Frame Busting" paper, USENIX Security research
- **Defense mechanisms**: X-Frame-Options header, CSP frame-ancestors directive, SameSite cookies
- **Industry standards**: OWASP Clickjacking Defense Cheat Sheet, W3C UI Safety Spec, CSP Level 2
- **Over 40 practical examples** including exploit templates, CSS layouts, and defensive configurations
- **Attack variations**: Likejacking, cursorjacking, drag-and-drop hijacking, mobile tap-jacking
- **6,000+ lines** of comprehensive clickjacking expertise

### January 2026 - Cross-Site Request Forgery (CSRF) Mastery Update
Added comprehensive CSRF documentation featuring:
- **Complete PortSwigger Web Security Academy lab walkthroughs** (11 CSRF labs)
  - Apprentice level (1 lab): Basic CSRF with no defenses
  - Practitioner level (9 labs): Token bypasses, Referer bypasses, SameSite bypasses
  - Expert level (1 lab): Advanced attack chain with sibling domain XSS and WebSocket hijacking
- **Two specialized reference files**:
  - `csrf-portswigger-labs-complete.md` - All 11 lab solutions with comprehensive walkthroughs
  - `csrf-quickstart.md` - Fast reference guide for rapid testing
- **Step-by-step exploitation techniques** with exact HTML payloads and HTTP requests
- **All bypass categories covered**:
  - Token-based bypasses (method-based, session binding, cookie injection, double submit, presence-based)
  - Referer-based bypasses (header suppression, substring matching)
  - SameSite bypasses (client-side redirects, sibling domain XSS, method override)
- **Complete Burp Suite workflows** including CSRF PoC Generator, Repeater, method conversion, Collaborator
- **Advanced attack chains**: CRLF injection for cookie poisoning, WebSocket hijacking, same-site vs cross-origin exploitation
- **Real-world CVE examples**: Apache Tomcat, Laravel, Jenkins, Apache Struts vulnerabilities
- **Defense mechanisms**: Secure token implementation (server-side, session-bound), SameSite cookie configuration, framework-specific protections
- **Industry standards**: OWASP Top 10, CWE-352, MITRE ATT&CK, CAPEC-62, CSRF Prevention Cheat Sheet
- **Over 100 practical examples** including exploit templates, bypass payloads, and defensive code
- **5,000+ lines** of comprehensive CSRF expertise

### January 2026 - Cross-Site Scripting (XSS) Mastery Update
Added comprehensive XSS documentation featuring:
- **Complete PortSwigger Web Security Academy lab walkthroughs** (33 XSS labs)
  - Apprentice level (9 labs): Basic Reflected, Stored, and DOM-based XSS
  - Practitioner level (18 labs): Context-specific exploitation, WAF bypass, XSS exploitation
  - Expert level (6 labs): AngularJS sandbox escapes, CSP bypass, advanced techniques
- **Four specialized reference files**:
  - `xss-portswigger-labs-complete.md` - All 33 lab solutions with step-by-step walkthroughs
  - `xss-exploitation-techniques.md` - Real-world exploitation scenarios (cookie theft, CSRF, keylogging)
  - `xss-bypass-techniques.md` - Advanced filter evasion and WAF bypass methods
  - `xss-quickstart.md` - Quick reference guide for rapid testing
- **Step-by-step exploitation techniques** with exact payloads and HTTP requests
- **Context-aware exploitation strategies** for all XSS contexts (HTML, JavaScript, attributes, template literals)
- **Advanced Burp Suite workflows** including Proxy, Repeater, Intruder, DOM Invader, Collaborator
- **Real-world attack scenarios**: Cookie theft, password harvesting, CSRF via XSS, BeEF integration, network scanning
- **Comprehensive bypass techniques**: WAF evasion with systematic enumeration, CSP bypass (policy injection, dangling markup), AngularJS sandbox escapes
- **Tools and automation**: XSS Hunter, DalFox, XSStrike, BeEF framework with complete usage guides
- **Professional-grade prevention**: Context-specific output encoding, strict CSP implementation, HttpOnly cookies, secure coding practices
- **Over 200 practical payloads and examples** across multiple contexts
- **8,000+ lines** of comprehensive XSS expertise

### January 2026 - SQL Injection Mastery Update
Added comprehensive SQL injection documentation featuring:
- Complete PortSwigger Web Security Academy lab walkthroughs (18 labs)
- Step-by-step exploitation techniques with exact payloads and HTTP requests
- Database-specific syntax reference for all major databases
- Advanced Burp Suite configuration and automation techniques
- Real-world case studies and CVE analysis
- Professional-grade detection, monitoring, and remediation strategies
- Ethical hacking best practices and legal considerations
- Over 100 practical examples and payloads

### [web-cache-poisoning-portswigger-labs-complete.md](./web-cache-poisoning-portswigger-labs-complete.md) ⭐ NEW
**Complete PortSwigger Web Cache Poisoning Lab Solutions** - All 8 labs:
- **Lab 1 - Unkeyed Header**: X-Forwarded-Host exploitation, script src poisoning (Apprentice - 2 min)
- **Lab 2 - Multiple Headers**: X-Forwarded-Host + X-Forwarded-Scheme combination attack (Practitioner - 3 min)
- **Lab 3 - Unkeyed Cookie**: fehost cookie reflection in JavaScript context (Practitioner - 2 min)
- **Lab 4 - Combining Vulnerabilities**: Multi-stage attack with translation JSON and redirect poisoning (Expert - 15 min)
- **Lab 5 - Strict Cacheability**: DOM XSS via geolocation with Set-Cookie restrictions (Expert - 5 min)
- **Lab 6 - Unkeyed Parameter**: utm_content parameter exploitation in canonical link (Practitioner - 2 min)
- **Lab 7 - Parameter Cloaking**: Semicolon-based parameter hiding in Rails applications (Expert - 5 min)
- **Lab 8 - Internal Cache**: Multi-layer cache exploitation with dynamic cache-busters (Expert - 10 min)
- Step-by-step solutions with exact payloads and HTTP requests/responses
- Complete Burp Suite workflows: Param Miner, Repeater, Turbo Intruder
- Attack techniques: Unkeyed inputs, multi-header combinations, parameter cloaking, multi-layer caching
- Real-world CVE examples: IBM Emptoris (CVE-2020-4896), IBM API Connect (CVE-2020-4828), Ratpack (CVE-2021-29479), Bottle (CVE-2020-28473), Python cpython (CVE-2021-23336)
- Tools & automation: Param Miner extension, custom Python scripts, cURL commands
- Detection methods: Log analysis, SIEM rules, real-time monitoring
- Prevention strategies: Cache configuration, input validation, security headers, framework-specific protections
- Research foundation: James Kettle's Black Hat presentations (2018, 2020, 2024) earning $260k+ in bug bounties
- **Over 4,200 lines** of comprehensive web cache poisoning expertise

### [web-cache-poisoning-quickstart.md](./web-cache-poisoning-quickstart.md) ⚡ QUICK REFERENCE
**Web Cache Poisoning Quick Start Guide** - Lightning-fast exploitation:
- 60-second vulnerability check with one-liner tests
- Lab speed-run guides (2-20 minutes each, total 60 minutes for all 8 labs)
- Common payloads: X-Forwarded-Host, utm_content, cookie-based, parameter cloaking
- Burp Suite speed tips and keyboard shortcuts
- Param Miner quick setup and usage
- Turbo Intruder scripts for continuous poisoning
- Common mistakes and troubleshooting
- Quick detection script (Python)
- Exploitation templates for all attack types
- Maintenance scripts for persistent poisoning
- Report template for vulnerability disclosure

### [web-cache-poisoning-cheat-sheet.md](./web-cache-poisoning-cheat-sheet.md) 📋 REFERENCE
**Web Cache Poisoning Cheat Sheet** - Comprehensive quick reference:
- Complete payload library: Headers (X-Forwarded-*, X-Original-URL), parameters (UTM, tracking), cookies
- Attack flow diagram from reconnaissance to exploitation
- Headers to test: 15+ forwarding/rewriting/override headers
- Parameters to test: UTM analytics, social media tracking, affiliate/marketing, JSONP callbacks
- Context-specific payloads: HTML, JavaScript, attribute, URL contexts
- Multi-header combinations and parameter cloaking
- Complete Burp Suite commands: Param Miner, Repeater workflows, Turbo Intruder scripts
- cURL command examples for all test scenarios
- Python scripts: Quick vulnerability test, automated scanner, continuous poisoning
- Detection commands: Log analysis (Apache/Nginx/Varnish), SIEM rules
- Cache behavior reference: Headers, Cache-Control directives, Vary header usage
- Prevention code examples: Nginx, Varnish VCL, Python/Flask, Node.js/Express, PHP
- Common vulnerabilities with exploitation examples
- Troubleshooting guide for cache hits, payload execution, timing issues
- Quick win scenarios for different application types
- **Over 1,200 lines** with all payloads, commands, and configurations

### [web-cache-poisoning-resources.md](./web-cache-poisoning-resources.md) 📚 RESOURCES
**Web Cache Poisoning Complete Resources Collection**:
- Official documentation: PortSwigger Web Security Academy, OWASP resources
- Research papers: James Kettle's groundbreaking work (Practical Web Cache Poisoning 2018, Web Cache Entanglement 2020, Gotta Cache 'em All 2024)
- CVE database: 8+ real-world vulnerabilities (IBM, Ratpack, Bottle, Python, CloudFoundry, Symfony)
- Industry standards: OWASP Top 10, MITRE CWE/CAPEC, NIST SP 800-53, PCI DSS, ISO 27001
- Tools & frameworks: Burp Suite extensions (Param Miner, Turbo Intruder), Nuclei, OWASP ZAP, custom scripts
- Training platforms: PortSwigger Academy (FREE), HackTheBox, TryHackMe, PentesterLab
- Bug bounty programs: HackerOne, Bugcrowd, notable findings ($260k+ by James Kettle)
- Books: Web Application Hacker's Handbook, Real-World Bug Hunting, Bug Bounty Bootcamp
- Community resources: Forums, security blogs, Twitter accounts, YouTube channels
- Secure coding guidelines: Framework-specific docs (Django, Express, Rails, Spring), cache server configs (Nginx, Varnish), CDN documentation (Cloudflare, AWS)
- WAF rules: ModSecurity CRS, Cloudflare WAF, AWS WAF configurations
- SIEM detection: Splunk, Elastic Stack, Azure Sentinel queries
- **100+ links and references** for mastering web cache poisoning

**Last Updated:** 2026-01-10
**Version:** 10.0 - Prototype Pollution Mastery Edition
