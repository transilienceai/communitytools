# Prototype Pollution - Complete Resources Collection

## Official Documentation

### PortSwigger Web Security Academy

**Main Topics:**
- [What is Prototype Pollution?](https://portswigger.net/web-security/prototype-pollution)
  - Comprehensive introduction to prototype pollution
  - JavaScript prototype inheritance explained
  - Attack requirements (source, sink, gadget)
  - Impact assessment (client-side vs server-side)

- [Client-Side Prototype Pollution](https://portswigger.net/web-security/prototype-pollution/client-side)
  - URL-based attack vectors (query string, hash)
  - JSON input exploitation
  - Manual and automated detection methods
  - DOM Invader usage guide

- [Prototype Pollution via Browser APIs](https://portswigger.net/web-security/prototype-pollution/browser-apis)
  - fetch() API exploitation
  - Object.defineProperty() bypass techniques
  - Browser-specific gadget chains
  - Header injection via prototype pollution

- [Server-Side Prototype Pollution](https://portswigger.net/web-security/prototype-pollution/server-side)
  - Detection challenges and techniques
  - Non-destructive testing methods
  - RCE via child_process manipulation
  - Node.js-specific vulnerabilities

- [Preventing Prototype Pollution](https://portswigger.net/web-security/prototype-pollution/preventing)
  - Sanitizing property keys (allowlist/blocklist)
  - Freezing prototype objects
  - Using safe data structures (Map, Set)
  - Framework-specific protection

**Interactive Labs:**
- [Prototype Pollution Learning Path](https://portswigger.net/web-security/learning-paths/prototype-pollution)
  - 7 hands-on labs (APPRENTICE to EXPERT)
  - Client-side: DOM XSS, Browser APIs, Sanitization Bypass, Third-Party Libraries
  - Server-side: Privilege Escalation, RCE, Data Exfiltration
  - Estimated time: 2-3 hours total

---

### OWASP Resources

**Cheat Sheets:**
- [Prototype Pollution Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
  - Best practices for prevention
  - Secure coding patterns
  - Framework-specific guidance
  - Code examples in multiple languages

- [GitHub Repository](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.md)
  - Source code for cheat sheet
  - Community contributions
  - Regular updates

**Testing Guide:**
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
  - Web application security testing methodology
  - Includes prototype pollution testing sections
  - Best practices for security assessments

**OWASP Top 10:**
- [A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
  - Prototype pollution as injection variant
  - Prevention strategies
  - Real-world examples

---

### Standards and Classifications

**CWE (Common Weakness Enumeration):**
- [CWE-1321: Improperly Controlled Modification of Object Prototype Attributes](https://cwe.mitre.org/data/definitions/1321.html)
  - Official weakness definition
  - Technical description
  - Mitigation strategies
  - Related CWEs

- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
  - Broader category including prototype pollution
  - Common consequences
  - Detection methods

**MITRE ATT&CK:**
- [T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
  - Relevant for RCE via prototype pollution
  - Real-world attack examples
  - Detection and mitigation

- [T1068: Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
  - Privilege escalation attacks
  - Server-side prototype pollution scenarios

- [T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
  - Initial access via web vulnerabilities
  - Prototype pollution as entry point

**CAPEC (Common Attack Pattern Enumeration and Classification):**
- [CAPEC-10: Buffer Overflow via Environment Variables](https://capec.mitre.org/data/definitions/10.html)
  - Related attack patterns
  - Execution environment manipulation

- [CAPEC-113: Interface Manipulation](https://capec.mitre.org/data/definitions/113.html)
  - API and interface exploitation
  - Prototype pollution as interface manipulation

**NIST Guidelines:**
- [NIST SP 800-53: Security and Privacy Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
  - SI-10: Information Input Validation
  - SI-11: Error Handling
  - SC-3: Security Function Isolation

- [NIST SP 800-115: Technical Guide to Information Security Testing](https://csrc.nist.gov/publications/detail/sp/800-115/final)
  - Web application testing methodology
  - Vulnerability assessment procedures

**PCI DSS (Payment Card Industry Data Security Standard):**
- Requirement 6.5.1: Injection flaws (including prototype pollution)
- Requirement 6.5.7: Cross-site scripting (XSS resulting from PP)
- Requirement 11.3: Regular penetration testing including PP assessment

**ISO/IEC 27001:**
- A.14.2.1: Secure development policy
- A.14.2.5: Secure system engineering principles
- A.14.2.8: System security testing

---

## Research Papers and Technical Articles

### Academic Research

**1. "Unveiling the Invisible: Detection and Evaluation of Prototype Pollution Gadgets with Dynamic Taint Analysis"**
- **Authors:** Academic researchers from KTH Royal Institute of Technology
- **Conference:** ACM Web Conference 2024
- **Links:**
  - [arXiv:2311.03919](https://arxiv.org/abs/2311.03919)
  - [ACM Digital Library](https://dl.acm.org/doi/10.1145/3589334.3645579)
  - [PDF Direct](https://people.kth.se/~musard/research/pubs/www24.pdf)
- **Key Contributions:**
  - Introduces Dasty: First semi-automated pipeline for gadget identification
  - Dynamic taint analysis with AST-level instrumentation
  - Targets Node.js applications and supply chain
  - Evaluation on real-world npm packages
- **Abstract:** Proposes dynamic taint analysis technique to automatically detect prototype pollution gadgets in JavaScript applications, addressing the challenge of identifying exploitable code paths in complex applications.

**2. "Prototype Pollution Detection for Node.js Applications: A Review"**
- **Journal:** Journal of Cyber Security, Privacy Issues and Challenges
- **Links:**
  - [ResearchGate](https://www.researchgate.net/publication/382648784_Prototype_Pollution_Detection_for_NodeJs_Applications_A_Review)
  - [Journal Article](https://matjournals.net/engineering/index.php/JCSPIC/article/view/682)
- **Key Topics:**
  - Overview of detection techniques (static, dynamic, symbolic/concolic)
  - Comparison of existing tools (DAPP, ppmap, proto-find)
  - Challenges in Node.js ecosystem
  - Future research directions
- **Abstract:** Comprehensive review of prototype pollution detection methods for Node.js applications, analyzing strengths and weaknesses of various approaches.

---

### Industry Research

**James Kettle's Groundbreaking Work:**

**1. "Server-Side Prototype Pollution: Black-box Detection Without the DoS" (2022)**
- **Author:** James Kettle, PortSwigger Director of Research
- **Link:** [PortSwigger Research](https://portswigger.net/research/server-side-prototype-pollution)
- **Key Contributions:**
  - Non-destructive detection techniques
  - JSON spaces method
  - Status code override technique
  - Charset override exploitation
  - Real-world case studies and exploitation
- **Impact:** Revolutionized server-side PP detection, making it safer and more practical
- **Notable Finding:** Earned $60,000+ in bug bounties using these techniques

**2. "HTTP Desync Attacks: Request Smuggling Reborn" (2019)**
- While primarily about request smuggling, this research laid groundwork for understanding complex web vulnerabilities including prototype pollution in HTTP processing

**3. Client-Side Prototype Pollution Research**
- Numerous blog posts and presentations on DOM-based PP
- DOM Invader tool development
- Gadget discovery methodologies

---

### Security Blogs and Articles

**PortSwigger Research Blog:**
- [Server-Side Prototype Pollution Research](https://portswigger.net/research/server-side-prototype-pollution)
- Regular updates on new techniques
- Case studies from real-world assessments
- Tool releases and methodologies

**Doyensec Security Blog:**
- [Unveiling the Prototype Pollution Gadgets Finder](https://blog.doyensec.com/2024/02/17/server-side-prototype-pollution-Gadgets-scanner.html)
  - Introduction to PP Gadgets Finder tool
  - Automated gadget discovery
  - Burp Suite extension development
  - Real-world application analysis

**IBM Security:**
- [Prototype Pollution Deep Dive](https://medium.com/@ibm_ptc_security/prototype-pollution-df29453f015c)
  - Technical analysis of prototype pollution
  - Attack scenarios and mitigation
  - Enterprise security perspective

**HackTricks:**
- [Client-Side Prototype Pollution](https://book.hacktricks.wiki/en/pentesting-web/deserialization/nodejs-proto-prototype-pollution/client-side-prototype-pollution.html)
  - Comprehensive pentesting guide
  - Payload collections
  - Exploitation techniques
  - Real-world examples

---

## CVE Database and Real-World Vulnerabilities

### Critical Recent Vulnerabilities

**CVE-2025-55182 & CVE-2025-66478: React2Shell**
- **Severity:** CRITICAL (CVSS 10.0)
- **Affected:** React Server Components, Next.js
- **Disclosure Date:** December 3, 2025
- **Technical Resources:**
  - [Datadog Security Labs Analysis](https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/)
  - [Picus Security Explanation](https://www.picussecurity.com/resource/blog/react-flight-protocol-rce-vulnerability-cve-2025-55182-and-cve-2025-66478-explained)
  - [OX Security Deep Technical Analysis](https://www.ox.security/blog/react2shell-going-granular-a-deep-deep-deep-technical-analysis-of-cve-2025-55182/)
  - [Praetorian Working Exploit](https://www.praetorian.com/blog/critical-advisory-remote-code-execution-in-next-js-cve-2025-66478-with-working-exploit/)
  - [Trend Micro ITW Analysis](https://www.trendmicro.com/en_us/research/25/l/CVE-2025-55182-analysis-poc-itw.html)
  - [GitHub Research Repository](https://github.com/ejpir/CVE-2025-55182-research/blob/main/TECHNICAL-ANALYSIS.md)
  - [Akamai Analysis](https://www.akamai.com/blog/security-research/cve-2025-55182-react-nextjs-server-functions-deserialization-rce)
- **Impact:** 1.97 billion React downloads, 20M+ weekly, 82% of JS developers use React
- **Real-World:** 145+ PoC exploits published within 24 hours, active exploitation observed

### npm Package Vulnerabilities

**CVE-2024-21505: web3-utils**
- **Link:** [Snyk Advisory](https://security.snyk.io/vuln/SNYK-JS-WEB3UTILS-6229337)
- **Part of:** Shai-Hulud supply chain attack (September 2025)
- **Impact:** Widespread in web3 ecosystem

**CVE-2021-23343: path-parse**
- **Severity:** HIGH
- **Affected Versions:** < 1.0.7
- **Link:** [CVE Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23343)

**CVE-2020-7598: minimist**
- **Severity:** HIGH
- **Affected Versions:** < 1.2.2
- **Link:** [CVE Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7598)
- **Impact:** CLI argument parsing vulnerability

**CVE-2019-11358: jQuery**
- **Severity:** MEDIUM
- **Affected Versions:** < 3.4.0
- **Link:** [CVE Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11358)
- **Impact:** jQuery.extend() prototype pollution

### CVE Search Resources
- [MITRE CVE Database - Prototype Pollution](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=prototype+pollution)
- [NVD Search](https://nvd.nist.gov/vuln/search/results?query=prototype+pollution)
- [Snyk Vulnerability DB](https://security.snyk.io/)
- [GitHub Security Advisories](https://github.com/advisories?query=prototype+pollution)

---

## Tools and Frameworks

### Burp Suite Tools

**1. DOM Invader (Built-in)**
- **Purpose:** Client-side prototype pollution detection and exploitation
- **Documentation:** [PortSwigger DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution)
- **Features:**
  - Automatic source detection (query string, hash, postMessage)
  - Gadget chain discovery
  - One-click exploitation
  - Works with minified code
- **Usage Guide:** [Testing with DOM Invader](https://portswigger.net/burp/documentation/desktop/testing-workflow/input-validation/prototype-pollution)

**2. Server-Side Prototype Pollution Scanner (BApp)**
- **Purpose:** Automated server-side PP detection
- **Installation:** Burp → Extender → BApp Store
- **Features:**
  - Multiple detection techniques
  - Batch scanning of proxy history
  - JSON spaces, status code, charset methods
  - Low false-positive rate

**3. Prototype Pollution Gadgets Finder (BApp)**
- **Developer:** Doyensec
- **Link:** [BApp Store](https://portswigger.net/bappstore/fcbc58b33fc1486d9a795dedba2ccbbb)
- **Blog:** [Doyensec Announcement](https://blog.doyensec.com/2024/02/17/server-side-prototype-pollution-Gadgets-scanner.html)
- **Features:**
  - Server-side gadget chain identification
  - Dynamic taint analysis integration
  - Gadget database with known chains
  - Automatic exploit generation
- **Use Case:** Finding exploitable gadgets after confirming pollution

**4. BChecks Example**
- **Purpose:** Custom security checks for Burp Scanner
- **Documentation:** [Server-Side PP Check Example](https://portswigger.net/burp/documentation/scanner/bchecks/worked-examples/server-side-prototype-pollution)
- **Usage:** Create custom detection rules for specific applications

---

### Standalone CLI Tools

**1. ppmap**
- **Installation:** `npm install -g ppmap`
- **Purpose:** Command-line prototype pollution scanner
- **Features:**
  - URL scanning
  - Parameter testing
  - Gadget enumeration
  - CI/CD integration
- **Usage:**
  ```bash
  ppmap scan https://target.com
  ppmap test https://target.com/?param=value
  ppmap gadgets https://target.com
  ```

**2. ppfuzz**
- **Purpose:** Automated fuzzing for prototype pollution
- **Features:**
  - Multiple payload templates
  - Custom payload generation
  - Integration with ffuf
- **Usage:**
  ```bash
  ppfuzz -u https://target.com/?FUZZ
  ppfuzz -u https://target.com/api -d '{"FUZZ":"value"}'
  ```

**3. proto-find**
- **Purpose:** Prototype pollution vulnerability finder
- **GitHub:** Search for "proto-find" on GitHub
- **Features:**
  - Static code analysis
  - Dynamic testing
  - Report generation

---

### Browser Extensions

**PPScan**
- **Platforms:** Chrome, Firefox
- **Purpose:** Automatic page scanning for client-side PP
- **Features:**
  - Real-time detection during browsing
  - Visual indicators for vulnerable inputs
  - Export findings
- **Installation:** Browser extension store

---

### Research Tools

**Dasty**
- **Purpose:** Semi-automated gadget identification pipeline
- **Technology:** Dynamic taint analysis with AST instrumentation
- **Target:** Node.js applications and npm packages
- **Research Paper:** [arXiv:2311.03919](https://arxiv.org/abs/2311.03919)
- **Key Features:**
  - Identifies gadgets in software supply chain
  - Traces data flow from pollution to sinks
  - Evaluates exploitability of chains

**UOPF (Undefined-Oriented Programming Framework)**
- **Purpose:** Automate detection and chaining of PP gadgets
- **Target:** Node.js template engines
- **Features:**
  - Gadget chain construction
  - Exploitation automation

**Silent Spring**
- **Purpose:** Static analysis for prototype pollution
- **Features:**
  - AST-based analysis
  - Control flow graph construction
  - Automated vulnerability detection

**DAPP**
- **Purpose:** Automatic static analysis tool for npm modules
- **Features:**
  - Package-level analysis
  - Dependency chain evaluation
  - Vulnerability scoring

---

### OWASP ZAP

**Prototype Pollution Scripts:**
- Community-contributed scripts for ZAP
- Active scan rules for PP detection
- **GitHub:** [zaproxy/community-scripts](https://github.com/zaproxy/community-scripts)

---

## Training Platforms

### PortSwigger Web Security Academy
- **Link:** [Prototype Pollution Labs](https://portswigger.net/web-security/prototype-pollution)
- **Cost:** FREE
- **Content:**
  - 7 interactive labs (APPRENTICE to EXPERT)
  - Theory and practical exercises
  - Automated feedback and hints
  - Certificate of completion
- **Difficulty Levels:**
  - APPRENTICE: Basic concepts (Labs 1, 5)
  - PRACTITIONER: Intermediate techniques (Labs 2, 3)
  - EXPERT: Advanced exploitation (Labs 4, 6, 7)
- **Estimated Time:** 2-3 hours for all labs

### HackTheBox
- **Link:** [https://www.hackthebox.com](https://www.hackthebox.com)
- **Relevant Content:**
  - Challenges featuring prototype pollution
  - Web application pentesting tracks
  - Real-world-like scenarios
- **Cost:** Free tier available, VIP subscription for full access
- **Skill Levels:** Easy, Medium, Hard, Insane

### TryHackMe
- **Link:** [https://tryhackme.com](https://tryhackme.com)
- **Relevant Rooms:**
  - JavaScript security
  - Node.js vulnerabilities
  - Web exploitation paths
- **Cost:** Free and premium content
- **Features:**
  - Guided learning paths
  - Interactive virtual machines
  - Community challenges

### PentesterLab
- **Link:** [https://pentesterlab.com](https://pentesterlab.com)
- **Relevant Exercises:**
  - JavaScript vulnerabilities
  - Web security fundamentals
  - Advanced web attacks
- **Cost:** Subscription-based
- **Features:**
  - Downloadable VMs
  - Video walkthroughs
  - Certification preparation

---

## Bug Bounty Programs

### Platforms with Prototype Pollution Scope

**HackerOne:**
- [https://www.hackerone.com](https://www.hackerone.com)
- Many programs accept prototype pollution reports
- Notable bounties: $5,000 - $20,000+ for critical PP vulnerabilities
- Search programs with "JavaScript" or "Node.js" in scope

**Bugcrowd:**
- [https://www.bugcrowd.com](https://www.bugcrowd.com)
- Web application security programs
- Server-side and client-side PP in scope
- Public and private programs

**Intigriti:**
- [https://www.intigriti.com](https://www.intigriti.com)
- European focus
- Web security programs
- Educational content on PP

**Synack:**
- [https://www.synack.com](https://www.synack.com)
- Invitation-only platform
- Enterprise targets
- High-value payouts

### Notable Bug Bounty Findings

**James Kettle (PortSwigger):**
- $60,000+ from prototype pollution findings
- Multiple critical vulnerabilities in major platforms
- Pioneered detection techniques

**React2Shell Bounties:**
- $10,000 - $50,000 range for React/Next.js findings
- Active bounty programs post-CVE-2025-55182

---

## Books and Publications

### Web Application Security

**"The Web Application Hacker's Handbook" (2nd Edition)**
- **Authors:** Dafydd Stuttard, Marcus Pinto
- **Publisher:** Wiley
- **ISBN:** 978-1118026472
- **Relevant Chapters:** JavaScript security, client-side attacks
- **Link:** [Wiley](https://www.wiley.com/en-us/The+Web+Application+Hacker%27s+Handbook%3A+Finding+and+Exploiting+Security+Flaws%2C+2nd+Edition-p-9781118026472)

**"Real-World Bug Hunting"**
- **Author:** Peter Yaworski
- **Publisher:** No Starch Press
- **ISBN:** 978-1593278618
- **Content:** Prototype pollution case studies from bug bounties
- **Link:** [No Starch Press](https://nostarch.com/bughunting)

**"Bug Bounty Bootcamp"**
- **Author:** Vickie Li
- **Publisher:** No Starch Press
- **ISBN:** 978-1718501546
- **Content:** Modern web vulnerabilities including PP
- **Link:** [No Starch Press](https://nostarch.com/bug-bounty-bootcamp)

### JavaScript Security

**"Eloquent JavaScript" (3rd Edition)**
- **Author:** Marijn Haverbeke
- **Publisher:** No Starch Press
- **Relevant Chapters:** Objects, prototypes, inheritance
- **Free Online:** [eloquentjavascript.net](https://eloquentjavascript.net/)

**"You Don't Know JS: this & Object Prototypes"**
- **Author:** Kyle Simpson
- **Publisher:** O'Reilly Media
- **Free on GitHub:** [github.com/getify/You-Dont-Know-JS](https://github.com/getify/You-Dont-Know-JS)
- **Deep dive into JavaScript prototypes**

---

## Community Resources

### Forums and Discussion

**Reddit:**
- [r/netsec](https://www.reddit.com/r/netsec/) - Network security discussions
- [r/websecurity](https://www.reddit.com/r/websecurity/) - Web application security
- [r/bugbounty](https://www.reddit.com/r/bugbounty/) - Bug bounty hunters community
- [r/javascript](https://www.reddit.com/r/javascript/) - JavaScript security topics

**Discord Servers:**
- **Bug Bounty Discord** - Active community of security researchers
- **HackTheBox Official Discord** - CTF and pentesting discussions
- **TryHackMe Discord** - Learning-focused security community

**Stack Exchange:**
- [Security Stack Exchange](https://security.stackexchange.com/) - Q&A on security topics
- [Stack Overflow - [prototype-pollution] tag](https://stackoverflow.com/questions/tagged/prototype-pollution)

### Twitter/X Security Researchers

Key accounts to follow for PP research:
- @PortSwiggerRes (PortSwigger Research)
- @albinowax (James Kettle)
- @Doyensec (Doyensec Security)
- @InsiderPhD (Bug bounty researcher)
- @NahamSec (Security researcher)
- @stokfredrik (Security researcher)

### YouTube Channels

**Security:**
- **LiveOverflow** - Technical security content
- **IppSec** - HackTheBox walkthroughs
- **John Hammond** - CTF and security challenges
- **PwnFunction** - Animated security concepts

**JavaScript:**
- **Traversy Media** - JavaScript fundamentals
- **Fireship** - Modern JS concepts
- **The Coding Train** - JavaScript deep dives

---

## Vulnerable Applications for Practice

### Intentionally Vulnerable Apps

**DVWA (Damn Vulnerable Web Application)**
- **Link:** [https://github.com/digininja/DVWA](https://github.com/digininja/DVWA)
- Can be modified to include PP vulnerabilities

**NodeGoat**
- **Link:** [https://github.com/OWASP/NodeGoat](https://github.com/OWASP/NodeGoat)
- Vulnerable Node.js application
- Includes various web vulnerabilities

**Juice Shop**
- **Link:** [https://github.com/juice-shop/juice-shop](https://github.com/juice-shop/juice-shop)
- OWASP's modern vulnerable web application
- JavaScript-heavy application
- May include PP challenges

---

## Defense and Secure Coding Resources

### Framework Documentation

**Node.js:**
- [Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [npm Security](https://docs.npmjs.com/about-security-audits)

**Express.js:**
- [Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- Middleware recommendations

**React:**
- [Security Considerations](https://react.dev/learn/escape-hatches#security-pitfalls)
- Post-CVE-2025-55182 security updates

**Next.js:**
- [Security Documentation](https://nextjs.org/docs/pages/building-your-application/configuring/environment-variables#security)
- Server Actions security

### Secure Coding Guidelines

**OWASP Secure Coding Practices:**
- [Quick Reference Guide](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- Input validation
- Output encoding
- Secure configuration

**Node.js Security Working Group:**
- [GitHub Repository](https://github.com/nodejs/security-wg)
- Security best practices
- Vulnerability disclosures

---

## WAF and Detection Rules

### ModSecurity

**Core Rule Set (CRS):**
- [https://github.com/coreruleset/coreruleset](https://github.com/coreruleset/coreruleset)
- Includes prototype pollution detection rules
- Regular updates for new attack patterns

**Custom Rules:**
```apache
# Block __proto__ in request bodies
SecRule REQUEST_BODY "@rx __proto__" \
    "id:1001,phase:2,deny,status:403,msg:'Prototype Pollution Attempt'"

# Block constructor in JSON
SecRule REQUEST_BODY "@rx \"constructor\"" \
    "id:1002,phase:2,deny,status:403,msg:'Constructor Pollution Attempt'"
```

### Cloudflare WAF
- [https://developers.cloudflare.com/waf/](https://developers.cloudflare.com/waf/)
- Managed rules for prototype pollution
- Custom rule expressions

### AWS WAF
- [https://aws.amazon.com/waf/](https://aws.amazon.com/waf/)
- Managed rule groups
- Custom rule creation guide

---

## SIEM and Detection

### Splunk
**Detection Queries:**
```spl
index=web_logs sourcetype=access_combined
| search "proto" OR "constructor" OR "prototype"
| rex field=_raw "__proto__\[(?<polluted_property>[^\]]+)\]"
| stats count by polluted_property, clientip
```

### Elastic Stack (ELK)
**Detection Queries:**
```json
{
  "query": {
    "bool": {
      "should": [
        {"match": {"request.body": "__proto__"}},
        {"match": {"request.body": "constructor"}},
        {"match": {"request.query": "__proto__"}}
      ]
    }
  }
}
```

### Azure Sentinel
- KQL queries for prototype pollution detection
- Workbooks for visualization
- Playbooks for automated response

---

## Conferences and Talks

### Black Hat
- James Kettle's presentations on web vulnerabilities
- HTTP Request Smuggling (2019, 2022, 2025)
- Server-side prototype pollution techniques

### DEF CON
- Web security village talks
- JavaScript security presentations
- Bug bounty researcher insights

### OWASP AppSec Conferences
- Regional and global conferences
- Web application security tracks
- Prototype pollution workshops

---

## Summary

This comprehensive resource collection provides:

1. **Official Documentation** - PortSwigger, OWASP, standards
2. **Research Papers** - Academic and industry research
3. **CVE Database** - Real-world vulnerabilities
4. **Tools** - Burp Suite extensions, CLI tools, browser extensions
5. **Training** - Interactive labs and learning platforms
6. **Bug Bounty** - Programs and notable findings
7. **Books** - Security and JavaScript publications
8. **Community** - Forums, Discord, social media
9. **Practice** - Vulnerable applications
10. **Defense** - Secure coding, WAF rules, SIEM detection

**Total Resources:** 100+ links, tools, and references
**Coverage:** Complete prototype pollution security lifecycle
**Skill Levels:** Beginner to expert

---

**Last Updated:** 2026-01-10
**Version:** 1.0 - Complete Resources Collection
**Maintained By:** Pentest Skill - Prototype Pollution Module
