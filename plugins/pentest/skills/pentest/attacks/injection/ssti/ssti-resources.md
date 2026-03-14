# Server-Side Template Injection (SSTI) - Resources & References

**Comprehensive collection of SSTI resources, research, tools, and references**

---

## Official Documentation

### PortSwigger Web Security Academy
- **Main SSTI Page**: https://portswigger.net/web-security/server-side-template-injection
- **Exploiting SSTI**: https://portswigger.net/web-security/server-side-template-injection/exploiting
- **All SSTI Labs**: 7 labs from Apprentice to Expert level
- **Lab Solutions**: Detailed walkthroughs provided for all labs

### Template Engine Documentation

**Ruby - ERB**
- Official Docs: https://ruby-doc.org/stdlib/libdoc/erb/rdoc/ERB.html
- Security Guide: Ruby documentation on safe template practices

**Python - Jinja2**
- Official Docs: https://jinja.palletsprojects.com/
- Sandbox: https://jinja.palletsprojects.com/en/latest/sandbox/
- Security Considerations: https://jinja.palletsprojects.com/en/latest/api/#sandbox

**Python - Tornado**
- Official Docs: https://www.tornadoweb.org/en/stable/template.html
- Template Reference: https://www.tornadoweb.org/en/stable/template.html#syntax-reference

**Python - Django**
- Official Docs: https://docs.djangoproject.com/en/stable/ref/templates/
- Built-in Tags: https://docs.djangoproject.com/en/stable/ref/templates/builtins/
- Security: https://docs.djangoproject.com/en/stable/topics/security/

**Java - Freemarker**
- Official Website: https://freemarker.apache.org/
- Built-in Reference: https://freemarker.apache.org/docs/ref_builtins.html
- FAQ (Security): https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security
- JavaDoc: https://freemarker.apache.org/docs/api/index.html

**Node.js - Handlebars**
- Official Website: https://handlebarsjs.com/
- Built-in Helpers: https://handlebarsjs.com/guide/builtin-helpers.html
- Security: https://handlebarsjs.com/installation/security.html

**PHP - Twig**
- Official Website: https://twig.symfony.com/
- Documentation: https://twig.symfony.com/doc/
- Filters: https://twig.symfony.com/doc/filters/index.html
- Security: https://twig.symfony.com/doc/api.html#sandbox-extension

**PHP - Smarty**
- Official Website: https://www.smarty.net/
- Documentation: https://www.smarty.net/docs/en/
- Security: https://www.smarty.net/docs/en/advanced.features.tpl

**Python - Mako**
- Official Website: https://www.makotemplates.org/
- Documentation: https://docs.makotemplates.org/
- Security: https://docs.makotemplates.org/en/latest/filtering.html

**Node.js - Pug (Jade)**
- Official Website: https://pugjs.org/
- Language Reference: https://pugjs.org/language/attributes.html

**Java - Velocity**
- Official Website: https://velocity.apache.org/
- User Guide: https://velocity.apache.org/engine/devel/user-guide.html

---

## Research Papers & Presentations

### James Kettle (PortSwigger Research)

**"Server-Side Template Injection: RCE for the modern webapp" (2015)**
- Black Hat USA 2015
- Groundbreaking research that defined SSTI as a vulnerability class
- Introduced detection and exploitation methodologies
- PDF: Available on PortSwigger Research page
- Video: https://www.youtube.com/watch?v=3cT0uE7Y87s

**Key Contributions:**
- Identified template injection as distinct vulnerability class
- Created detection methodology using polyglot payloads
- Documented exploitation techniques for major engines
- Introduced decision trees for engine identification

### Conference Talks

**DEF CON 23 (2015) - James Kettle**
- Title: "Server-Side Template Injection"
- Comprehensive overview of SSTI techniques
- Live demonstrations of exploitation

**Black Hat Europe (2016) - Various Speakers**
- Real-world SSTI case studies
- Advanced bypass techniques
- Cloud environment exploitation

---

## OWASP Resources

### OWASP Top 10
- **A03:2021 – Injection**: SSTI falls under injection vulnerabilities
- **Category**: Server-side injection attacks
- **Risk Rating**: High to Critical depending on impact

### OWASP Testing Guide
- **WSTG-INPV-18**: Testing for Server-Side Template Injection
- **Location**: https://owasp.org/www-project-web-security-testing-guide/
- **Content**: Testing methodology, detection, exploitation

### OWASP Cheat Sheet Series
- Injection Prevention Cheat Sheet
- Input Validation Cheat Sheet
- Secure Coding Practices
- Link: https://cheatsheetseries.owasp.org/

---

## MITRE References

### CWE (Common Weakness Enumeration)

**CWE-94: Improper Control of Generation of Code ('Code Injection')**
- **Description**: Server-side template injection allows code injection
- **URL**: https://cwe.mitre.org/data/definitions/94.html
- **Impact**: Arbitrary code execution

**CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code**
- **Description**: Eval injection, including template code
- **URL**: https://cwe.mitre.org/data/definitions/95.html

**CWE-74: Improper Neutralization of Special Elements in Output**
- **Parent Category**: Covers various injection types including SSTI
- **URL**: https://cwe.mitre.org/data/definitions/74.html

### CAPEC (Common Attack Pattern Enumeration and Classification)

**CAPEC-242: Code Injection**
- **Description**: Injecting code that gets executed by application
- **URL**: https://capec.mitre.org/data/definitions/242.html
- **Applies to**: SSTI in all template engines

### ATT&CK Framework

**T1059: Command and Scripting Interpreter**
- **Tactic**: Execution
- **Description**: Adversaries abuse interpreters to execute code
- **SSTI Context**: Template engines act as code interpreters

---

## Notable CVEs

### Critical SSTI Vulnerabilities

**CVE-2019-8446: Apache Airflow - Jinja2 SSTI**
- **Severity**: CVSS 9.8 (Critical)
- **Impact**: Remote code execution
- **Affected**: Apache Airflow < 1.10.3
- **Cause**: User-controlled Jinja2 template rendering
- **Fix**: Input sanitization and template restrictions

**CVE-2020-28196: Kraken - SSTI in Email Templates**
- **Severity**: CVSS 9.1 (Critical)
- **Impact**: Account takeover, data theft
- **Affected**: Kraken cryptocurrency exchange
- **Cause**: Email template rendering with user input
- **Disclosure**: Responsible disclosure, patched

**CVE-2021-25770: Django - SSTI via Debug Mode**
- **Severity**: CVSS 7.5 (High)
- **Impact**: Information disclosure
- **Affected**: Django with debug mode enabled
- **Cause**: Debug templates expose internal objects
- **Fix**: Disable debug in production

**CVE-2018-1000533: GitLab - SSTI in Project Features**
- **Severity**: CVSS 8.8 (High)
- **Impact**: Remote code execution
- **Affected**: GitLab Community/Enterprise Edition
- **Cause**: Unsanitized template rendering
- **Fix**: Template input validation

**CVE-2017-7536: Shopizer - Freemarker SSTI**
- **Severity**: CVSS 9.8 (Critical)
- **Impact**: Remote code execution
- **Affected**: Shopizer e-commerce platform
- **Cause**: User-controlled Freemarker templates
- **Fix**: Remove user template upload capability

**CVE-2020-10199: SonarQube - Velocity SSTI**
- **Severity**: CVSS 8.8 (High)
- **Impact**: Remote code execution as SonarQube user
- **Affected**: SonarQube < 7.9.6, 8.x < 8.1
- **Cause**: Velocity template injection in email settings
- **Fix**: Template input sanitization

**CVE-2019-11510: Pulse Secure VPN - SSTI**
- **Severity**: CVSS 10.0 (Critical)
- **Impact**: Authentication bypass, remote code execution
- **Affected**: Pulse Connect Secure < 9.0R3.4
- **Cause**: Template injection in web interface
- **Exploited**: Actively exploited in wild (APT groups)

### WordPress Plugin SSTI Vulnerabilities

**CVE-2021-24145: WP HTML Mail - Twig SSTI**
- **Severity**: CVSS 9.9 (Critical)
- **Affected**: WordPress plugin WP HTML Mail
- **Cause**: User-controlled Twig templates

**CVE-2020-35234: WP Statistics - SSTI**
- **Severity**: CVSS 7.2 (High)
- **Affected**: WordPress plugin WP Statistics
- **Impact**: Arbitrary PHP code execution

---

## Industry Standards & Guidelines

### NIST (National Institute of Standards and Technology)

**NIST SP 800-53: Security and Privacy Controls**
- **SI-10**: Information Input Validation
- **SI-15**: Information Output Filtering
- **Relevance**: Template input/output handling

**NIST Cybersecurity Framework**
- **PR.DS-5**: Protections against data leaks
- **DE.CM-1**: Network monitoring for anomalies
- **Application**: Detect SSTI exploitation attempts

### PCI DSS (Payment Card Industry Data Security Standard)

**Requirement 6.5.1**: Injection Flaws
- **Scope**: All injection types including SSTI
- **Requirement**: Training, secure coding, testing
- **Testing**: Annual penetration tests must include SSTI

**Requirement 11.3**: Penetration Testing
- **Scope**: Must test for template injection
- **Frequency**: At least annually
- **Methodology**: Should include all OWASP Top 10 categories

### ISO/IEC 27001

**A.14.2.1**: Secure Development Policy
- **Requirement**: Secure coding guidelines
- **Application**: Template handling best practices

**A.14.2.8**: System Security Testing
- **Requirement**: Security testing during development
- **Application**: SSTI testing in SDLC

---

## Tools & Automation

### Detection Tools

**tplmap**
- **Type**: Automated SSTI detection and exploitation
- **GitHub**: https://github.com/epinna/tplmap
- **Features**: Supports 15+ template engines, automatic exploitation
- **Usage**: `tplmap -u "http://target.com/page?param=*"`
- **Engines**: Jinja2, Mako, Tornado, Django, Smarty, Twig, Freemarker, Velocity, ERB, and more

**Burp Suite Scanner**
- **Type**: Commercial web vulnerability scanner
- **Website**: https://portswigger.net/burp/vulnerability-scanner
- **Features**: Automatic SSTI detection, exploitation guidance
- **Extensions**: Additional SSTI detection extensions available

**OWASP ZAP**
- **Type**: Open-source web application scanner
- **Website**: https://www.zaproxy.org/
- **Features**: Active/passive SSTI scanning
- **Scripts**: Custom SSTI detection scripts available

**Nuclei**
- **Type**: Vulnerability scanner with template-based detection
- **GitHub**: https://github.com/projectdiscovery/nuclei
- **SSTI Templates**: Community-contributed SSTI detection templates
- **Usage**: `nuclei -u https://target.com -t ssti/`

### Exploitation Tools

**SSTImap**
- **GitHub**: https://github.com/vladko312/SSTImap
- **Description**: Fork of tplmap with additional features
- **Features**: Enhanced exploitation, new engines support

**Commix**
- **GitHub**: https://github.com/commixproject/commix
- **Description**: Command injection exploitation tool
- **SSTI Support**: Limited SSTI detection via command injection

**Metasploit Framework**
- **Modules**: Various SSTI exploitation modules
- **Example**: `exploit/multi/http/freemarker_template_injection`
- **GitHub**: https://github.com/rapid7/metasploit-framework

### Payload Collections

**PayloadsAllTheThings**
- **GitHub**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- **Content**: Comprehensive payload collection for all engines
- **Format**: Organized by template engine with explanations
- **Updates**: Regularly updated with new techniques

**SecLists**
- **GitHub**: https://github.com/danielmiessler/SecLists
- **Location**: `/Fuzzing/template-engines-*`
- **Content**: Fuzzing strings for SSTI detection
- **Usage**: Ideal for Burp Intruder and other fuzzers

**FuzzDB**
- **GitHub**: https://github.com/fuzzdb-project/fuzzdb
- **Content**: Template injection attack patterns
- **Format**: Ready for tool integration

### Testing Frameworks

**OWASP ZSC (Shellcode Generator)**
- **GitHub**: https://github.com/Ali-Razmjoo/OWASP-ZSC
- **Usage**: Generate shellcode for post-exploitation

**Empire/PowerShell Empire**
- **GitHub**: https://github.com/EmpireProject/Empire
- **Usage**: Post-exploitation framework after gaining RCE via SSTI

---

## Online Resources

### HackTricks

**SSTI Section**
- **URL**: https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
- **Content**: Detection, exploitation, bypasses
- **Coverage**: All major template engines
- **Examples**: Real-world exploitation scenarios

### PayloadsAllTheThings

**SSTI Repository**
- **URL**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- **Content**:
  - Detection payloads
  - Engine-specific exploits
  - Sandbox bypass techniques
  - WAF evasion methods
- **Format**: Markdown with code examples

### PentestMonkey

**Reverse Shell Cheat Sheet**
- **URL**: https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- **Relevance**: Post-exploitation via SSTI RCE
- **Content**: Ruby, Python, Bash, PHP reverse shells

### GTFOBins

**Unix Binaries Exploitation**
- **URL**: https://gtfobins.github.io/
- **Relevance**: Command execution after SSTI RCE
- **Content**: Binary-specific exploitation techniques

---

## Training Platforms

### PortSwigger Web Security Academy

**SSTI Labs**
- **URL**: https://portswigger.net/web-security/all-labs
- **Labs**: 7 SSTI labs (Apprentice to Expert)
- **Cost**: Free
- **Features**:
  - Hands-on exploitation
  - Step-by-step solutions
  - Progress tracking
  - Certification upon completion

### HackTheBox

**SSTI Machines**
- **URL**: https://www.hackthebox.com/
- **Cost**: Free tier + VIP subscription
- **Relevant Machines**:
  - Armageddon (Drupal Twig SSTI)
  - Teacher (Moodle RCE via template)
  - DevOops (Python pickle + SSTI)

### TryHackMe

**SSTI Rooms**
- **URL**: https://tryhackme.com/
- **Cost**: Free + Premium rooms
- **Content**: Guided SSTI labs with explanations

### PentesterLab

**SSTI Exercises**
- **URL**: https://pentesterlab.com/
- **Cost**: Subscription-based
- **Content**:
  - SSTI from detection to exploitation
  - Multiple template engines
  - Real-world scenarios

### OWASP WebGoat

**Lesson Modules**
- **URL**: https://owasp.org/www-project-webgoat/
- **Cost**: Free
- **Content**: Injection vulnerability lessons including template injection

---

## Bug Bounty Programs

### Platforms Accepting SSTI Reports

**HackerOne**
- **URL**: https://www.hackerone.com/
- **SSTI Bounties**: $500 - $10,000+ depending on impact
- **Notable Programs**: GitLab, Shopify, Uber

**Bugcrowd**
- **URL**: https://www.bugcrowd.com/
- **SSTI Scope**: Server-side injection vulnerabilities
- **Rewards**: Varies by program criticality

**YesWeHack**
- **URL**: https://www.yeswehack.com/
- **European Focus**: Many EU companies
- **SSTI Reports**: Regularly accepted

**Intigriti**
- **URL**: https://www.intigriti.com/
- **Focus**: European bug bounty platform
- **SSTI**: Accepted in most programs

### Notable SSTI Bounties

**$10,000 - GitLab SSTI**
- **Year**: 2018
- **Researcher**: Orange Tsai
- **Impact**: RCE on GitLab.com infrastructure

**$7,500 - Uber SSTI**
- **Year**: 2017
- **Impact**: Server-side code execution
- **Template**: Jinja2 template injection

**$5,000 - Shopify SSTI**
- **Year**: 2019
- **Impact**: Liquid template injection
- **Researcher**: Various security researchers

---

## Books & Publications

### Web Application Security Books

**"The Web Application Hacker's Handbook" (2nd Edition)**
- **Authors**: Dafydd Stuttard, Marcus Pinto
- **Publisher**: Wiley
- **Coverage**: Injection vulnerabilities including template injection
- **ISBN**: 978-1118026472

**"Web Security Testing Cookbook"**
- **Author**: Paco Hope, Ben Walther
- **Publisher**: O'Reilly Media
- **Coverage**: Practical testing recipes including SSTI
- **ISBN**: 978-0596514839

**"Real-World Bug Hunting"**
- **Author**: Peter Yaworski
- **Publisher**: No Starch Press
- **Coverage**: Real bug bounty case studies including SSTI
- **ISBN**: 978-1593278618

### Academic Papers

**"Server-Side Template Injection: RCE for the modern webapp"**
- **Author**: James Kettle (PortSwigger)
- **Year**: 2015
- **URL**: https://portswigger.net/research/server-side-template-injection
- **Content**: Foundational SSTI research

**"Exploiting Server-Side Template Injection with Blind XSS"**
- **Conference**: Black Hat USA
- **Year**: 2016
- **Content**: Combining SSTI with XSS for enhanced exploitation

---

## Community Resources

### Reddit Communities

**/r/netsec**
- **URL**: https://reddit.com/r/netsec
- **Content**: Security research, SSTI disclosures
- **Activity**: High-quality technical discussions

**/r/bugbounty**
- **URL**: https://reddit.com/r/bugbounty
- **Content**: Bug bounty writeups, SSTI findings
- **Community**: Active hunters sharing tips

**/r/websecurity**
- **URL**: https://reddit.com/r/websecurity
- **Content**: Web security discussions
- **Relevance**: SSTI questions and answers

### Discord Servers

**The Many Hats Club**
- **Focus**: InfoSec community
- **Channels**: #web-app-sec for SSTI discussions
- **Members**: 10,000+ security professionals

**Nahamsec Discord**
- **Focus**: Bug bounty hunting
- **Content**: SSTI tips and collaboration
- **Members**: Large active community

**HackerOne Community**
- **Official**: HackerOne's Discord server
- **Content**: Bug bounty discussions
- **SSTI**: Dedicated channels for injection attacks

### Twitter Accounts to Follow

**@albinowax (James Kettle)**
- PortSwigger Research Director
- Original SSTI researcher
- Regular security research updates

**@Orange_8361 (Orange Tsai)**
- Security researcher
- Multiple SSTI discoveries
- Conference speaker

**@yaworsk (Peter Yaworski)**
- Bug bounty hunter
- Author of "Real-World Bug Hunting"
- SSTI case studies

**@0xdf_**
- HackTheBox writeups
- SSTI machine walkthroughs

**@hakluke**
- Bug bounty hunter
- Web security researcher
- SSTI methodology tips

---

## YouTube Channels & Videos

### Educational Channels

**IppSec**
- **URL**: https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA
- **Content**: HackTheBox walkthroughs including SSTI machines
- **Quality**: Detailed explanations, methodical approach

**LiveOverflow**
- **URL**: https://www.youtube.com/c/LiveOverflow
- **Content**: Web security concepts including injection attacks
- **Style**: Educational, beginner-friendly

**STÖK**
- **URL**: https://www.youtube.com/c/STOKfredrik
- **Content**: Bug bounty tips and tricks
- **Relevance**: SSTI hunting strategies

**PwnFunction**
- **URL**: https://www.youtube.com/c/PwnFunction
- **Content**: Animated security concept explanations
- **Style**: Visual learning, easy to understand

### Conference Talks

**"Server-Side Template Injection: RCE for the modern webapp" - Black Hat USA 2015**
- **Speaker**: James Kettle
- **URL**: https://www.youtube.com/watch?v=3cT0uE7Y87s
- **Duration**: ~45 minutes
- **Content**: Foundational SSTI presentation

**"SSTI in 2021" - Various Security Conferences**
- **Content**: Updated SSTI techniques
- **Bypass**: Modern WAF and sandbox bypasses

---

## Vulnerable Applications for Practice

### Intentionally Vulnerable Apps

**DVWA (Damn Vulnerable Web Application)**
- **GitHub**: https://github.com/digininja/DVWA
- **SSTI**: Limited SSTI scenarios
- **Difficulty**: Beginner-friendly

**OWASP Juice Shop**
- **GitHub**: https://github.com/juice-shop/juice-shop
- **SSTI**: Several template injection challenges
- **Difficulty**: Beginner to Intermediate

**bWAPP (Buggy Web Application)**
- **URL**: http://www.itsecgames.com/
- **SSTI**: Multiple SSTI scenarios
- **Engines**: Various template engines

**Damn Vulnerable Flask App**
- **GitHub**: https://github.com/we45/Damn-Vulnerable-Flask-App
- **SSTI**: Jinja2 template injection
- **Focus**: Python/Flask security

**NodeGoat**
- **GitHub**: https://github.com/OWASP/NodeGoat
- **SSTI**: Node.js template vulnerabilities
- **Engines**: Handlebars, Pug

**VulnHub VMs**
- **URL**: https://www.vulnhub.com/
- **Search**: "template injection"
- **Content**: Full VMs with SSTI challenges

---

## Defense Resources

### Secure Coding Guidelines

**OWASP Secure Coding Practices**
- **URL**: https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/
- **Section**: Input Validation, Output Encoding
- **Application**: Template security best practices

**CERT Secure Coding Standards**
- **URL**: https://wiki.sei.cmu.edu/confluence/display/seccode
- **Languages**: Java, C, C++, Python, Perl
- **Content**: Language-specific secure coding

**CWE/SANS Top 25**
- **URL**: https://www.sans.org/top25-software-errors/
- **Ranking**: Injection attacks consistently in top 25
- **Mitigation**: Detailed prevention strategies

### Framework-Specific Security Guides

**Django Security**
- **URL**: https://docs.djangoproject.com/en/stable/topics/security/
- **Content**: Template security, autoescape, CSRF

**Flask Security**
- **URL**: https://flask.palletsprojects.com/en/latest/security/
- **Content**: Jinja2 security considerations

**Ruby on Rails Security**
- **URL**: https://guides.rubyonrails.org/security.html
- **Content**: ERB template security

**Spring Framework Security**
- **URL**: https://spring.io/guides/topicals/spring-security-architecture/
- **Content**: Thymeleaf and Freemarker security

---

## WAF Rules & Detection

### ModSecurity Rules

**OWASP ModSecurity Core Rule Set (CRS)**
- **GitHub**: https://github.com/coreruleset/coreruleset
- **SSTI Rules**: Rule ID 932xxx series
- **Coverage**: Template syntax detection

**Custom SSTI Rules**
```apache
SecRule ARGS "@rx (\{\{|\}\}|<%=|%>|\$\{|<#)" \
    "id:1000,phase:2,deny,status:403,msg:'Potential SSTI attempt'"
```

### Cloudflare WAF

**Managed Rulesets**
- **OWASP Top 10**: Includes injection detection
- **Custom Rules**: Can create SSTI-specific rules
- **Documentation**: https://developers.cloudflare.com/waf/

### AWS WAF

**Managed Rule Groups**
- **Core Rule Set**: Includes injection protection
- **Custom Rules**: Template syntax pattern matching
- **Documentation**: https://docs.aws.amazon.com/waf/

---

## Compliance & Audit Checklists

### SSTI Testing Checklist

**Pre-Engagement**
- [ ] Scope defines template-related features
- [ ] Authorization obtained for testing
- [ ] Test environment vs. production clarified

**Detection Phase**
- [ ] Identify all user input points
- [ ] Test GET/POST parameters
- [ ] Test HTTP headers
- [ ] Test file upload content
- [ ] Test JSON/XML payloads
- [ ] Fuzz with polyglot payloads

**Identification Phase**
- [ ] Analyze error messages
- [ ] Test mathematical expressions
- [ ] Identify template engine
- [ ] Research engine documentation

**Exploitation Phase**
- [ ] Test for RCE
- [ ] Test for file read
- [ ] Test for information disclosure
- [ ] Attempt sandbox bypass
- [ ] Document successful payloads

**Reporting Phase**
- [ ] Severity rating (CVSS)
- [ ] Impact assessment
- [ ] Proof of concept
- [ ] Remediation recommendations
- [ ] Retest verification

---

## Incident Response

### SSTI Exploitation Indicators

**Log Patterns to Monitor**
```
# Template syntax in logs
${\w+}
{{\w+}}
<%=.*%>
<#.*>

# Known dangerous functions
freemarker.template.utility.Execute
require('child_process')
os.system
eval(
__import__

# Suspicious file access
/etc/passwd
/etc/shadow
id_rsa
```

**Network Indicators**
- Unusual outbound connections
- DNS queries to suspicious domains
- Large data exfiltration
- Reverse shell connections

### Response Procedures

1. **Immediate Actions**
   - Isolate affected system
   - Review logs for exploitation
   - Identify compromised data
   - Preserve evidence

2. **Investigation**
   - Analyze attack vector
   - Determine entry point
   - Assess lateral movement
   - Identify stolen data

3. **Containment**
   - Patch vulnerable code
   - Deploy WAF rules
   - Reset credentials
   - Revoke compromised tokens

4. **Recovery**
   - Restore from clean backup
   - Verify system integrity
   - Update dependencies
   - Implement monitoring

5. **Post-Incident**
   - Root cause analysis
   - Update security policies
   - Security awareness training
   - Penetration test revalidation

---

## Glossary

**SSTI**: Server-Side Template Injection - injection of malicious code into server-side templates

**Template Engine**: Software component that combines templates with data to produce output

**RCE**: Remote Code Execution - ability to execute arbitrary code on target system

**Sandbox**: Security mechanism to execute untrusted code in isolated environment

**Polyglot Payload**: Single payload that works across multiple template engines

**Code Context**: Situation where injection occurs within existing code expression

**HTML Context**: Situation where injection occurs in HTML output

**Object Chain**: Sequence of object/method accesses to reach restricted functionality

**Reflection**: Ability to inspect and modify program structure at runtime

**Built-in**: Pre-defined function or object provided by template engine

**Helper**: Template engine function that assists in rendering (Handlebars)

**Filter**: Function that transforms data in template (Jinja2, Django, Twig)

**Directive**: Template control structure for logic (Freemarker)

**MRO**: Method Resolution Order - Python object hierarchy

---

## Contact & Contribution

### Reporting New SSTI Findings

**Responsible Disclosure**
- Notify vendor first (30-90 day disclosure window)
- Provide detailed reproduction steps
- Avoid public disclosure until patched
- Consider bug bounty programs

### Contributing to Resources

**GitHub Repositories**
- PayloadsAllTheThings: Accepts pull requests
- HackTricks: Community contributions welcome
- tplmap: Feature requests and bug reports

**Community Contributions**
- Share new bypass techniques
- Document novel exploitation methods
- Create vulnerable-by-design applications
- Write blog posts and tutorials

---

**Last Updated**: January 2026
**Maintained By**: Pentest Skill Community
**License**: Educational use only - obtain authorization before testing
