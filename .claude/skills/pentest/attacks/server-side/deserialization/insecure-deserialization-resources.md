# Insecure Deserialization - Resources & References

## Comprehensive Resource Guide

This document provides curated resources for mastering insecure deserialization vulnerabilities, including OWASP documentation, research papers, tools, real-world case studies, and secure coding practices.

---

## Table of Contents

1. [OWASP Resources](#owasp-resources)
2. [Exploitation Tools](#exploitation-tools)
3. [Research Papers & Publications](#research-papers--publications)
4. [Real-World CVE Examples](#real-world-cve-examples)
5. [Framework-Specific Guides](#framework-specific-guides)
6. [Secure Coding Practices](#secure-coding-practices)
7. [Training & Practice Platforms](#training--practice-platforms)
8. [Community & Forums](#community--forums)
9. [Books & In-Depth Guides](#books--in-depth-guides)
10. [Video Content & Presentations](#video-content--presentations)

---

## OWASP Resources

### Primary Documentation

**OWASP Deserialization Cheat Sheet**
- URL: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- Content: Comprehensive prevention and detection guidance
- Languages Covered: Java, .NET, PHP, Python, Ruby
- Key Topics:
  - Language-agnostic deserialization risks
  - Whitelisting/blacklisting strategies
  - Integrity checking mechanisms
  - Safe alternatives to deserialization

**OWASP Top 10 2017: A8 - Insecure Deserialization**
- URL: https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization
- Impact: Remote code execution, privilege escalation, DoS
- Detection Difficulty: Difficult (requires code review or specialized tools)
- Exploitability: Difficult (requires understanding of serialization formats)
- Prevalence: Uncommon (but high impact when present)

**OWASP Vulnerability: Insecure Deserialization**
- URL: https://owasp.org/www-community/vulnerabilities/Insecure_Deserialization
- Technical Details:
  - Object injection attacks
  - Deserialization of untrusted data
  - Remote code execution mechanisms
  - Attack vectors and scenarios

**OWASP Vulnerability: Deserialization of Untrusted Data**
- URL: https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data
- Focus: Language-specific implementations
- Examples: Java, .NET, PHP, Python, Ruby code samples
- Prevention: Specific mitigation strategies per language

### OWASP Projects

**OWASP Dependency-Check**
- URL: https://owasp.org/www-project-dependency-check/
- Purpose: Identify project dependencies with known vulnerabilities
- Supports: Java, .NET, Ruby, Node.js, Python
- Use Case: Detect vulnerable serialization libraries

**OWASP ModSecurity Core Rule Set**
- URL: https://coreruleset.org/
- Includes: Deserialization attack detection rules
- Protection: WAF-level defenses
- Rules: Java, PHP, Python deserialization patterns

---

## Exploitation Tools

### ysoserial (Java)

**Official Repository:**
- URL: https://github.com/frohoff/ysoserial
- Description: Proof-of-concept tool for generating Java deserialization payloads
- Author: Chris Frohoff (@frohoff)
- Stars: 6.3k+ (as of 2024)

**Key Features:**
- 40+ pre-built gadget chains
- Support for major frameworks (Commons Collections, Spring, Groovy, etc.)
- JNDI exploitation payloads
- DNS/HTTP out-of-band testing payloads

**Supported Payloads:**
```
AspectJWeaver, BeanShell1, C3P0, Click1,
Clojure, CommonsBeanutils1, CommonsCollections1-7,
FileUpload1, Groovy1, Hibernate1-2, JBossInterceptors1,
JRMPClient, JRMPListener, JSON1, JavassistWeld1,
Jdk7u21, Jython1, MozillaRhino1-2, Myfaces1-2,
ROME, Spring1-2, URLDNS, Vaadin1, Wicket1
```

**Installation:**
```bash
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
```

**Documentation:**
```bash
java -jar ysoserial-all.jar --help
java -jar ysoserial-all.jar [payload] '[command]'
```

**Related Projects:**
- ysoserial.net: .NET equivalent (https://github.com/pwntester/ysoserial.net)
- marshalsec: Java unmarshaller vulnerabilities (https://github.com/mbechler/marshalsec)

### PHPGGC (PHP)

**Official Repository:**
- URL: https://github.com/ambionics/phpggc
- Description: PHP Generic Gadget Chains library and generator
- Author: Ambionics Security (Charles Fol @cfreal_)
- Stars: 3.1k+ (as of 2024)

**Key Features:**
- 140+ gadget chains across 30+ frameworks
- Multiple exploitation types (RCE, File Write, File Read, etc.)
- Encoder support (Base64, URL, JSON)
- PHAR file generation
- Programmatic usage support

**Supported Frameworks:**
```
Symfony, Laravel, Monolog, SwiftMailer, Doctrine,
Guzzle, Slim, CodeIgniter, CakePHP, Yii, Magento,
WordPress, Joomla, Drupal, phpBB, vBulletin, and more
```

**Installation:**
```bash
git clone https://github.com/ambionics/phpggc.git
cd phpggc
chmod +x phpggc
```

**Documentation:**
```bash
./phpggc -l                          # List all chains
./phpggc -l [framework]              # List framework chains
./phpggc -i [chain]                  # Chain information
./phpggc [chain] [parameters]        # Generate payload
./phpggc [chain] [params] -b         # Base64 encode
```

**Research Papers:**
- "PHP Generic Gadget Chains" by Charles Fol (2018)
- URL: https://www.ambionics.io/blog/php-generic-gadget-chains

### Burp Suite Extensions

**Java Deserialization Scanner**
- BApp Store: https://portswigger.net/bappstore/228336544ebe4e68824b5146dbbd93ae
- Features:
  - Automatic detection of Java serialization
  - Active and passive scanning
  - Integration with ysoserial
  - Custom payload support

**Freddy, Deserialization Bug Finder**
- GitHub: https://github.com/nccgroup/freddy
- Features:
  - Multi-language support (Java, .NET, Python, Ruby, PHP)
  - Multiple serialization formats
  - Active scanning
  - Passive detection

**.NET Beautifier and Minifier**
- BApp Store: https://portswigger.net/bappstore/e88cdf2f35c04f38abd49c4c458fa09f
- Features:
  - ViewState decoding
  - .NET remoting deserialization detection

**Active Scan++**
- BApp Store: https://portswigger.net/bappstore/3123d5b5f25c4128894d97ea1acc4976
- Features: Includes deserialization checks

### Additional Tools

**SerialKiller (Java Defense)**
- GitHub: https://github.com/ikkisoft/SerialKiller
- Purpose: Java deserialization firewall
- Type: Java agent for runtime protection
- Features: Whitelist/blacklist class filtering

**java-deserialization-scanner (Burp)**
- GitHub: https://github.com/federicodotta/Java-Deserialization-Scanner
- Purpose: All-in-one Java deserialization scanner
- Features: Detection and exploitation

**gadgetinspector (Research Tool)**
- GitHub: https://github.com/JackOfMostTrades/gadgetinspector
- Purpose: Automated gadget chain discovery
- Technique: Static analysis of Java bytecode

**ysoserial.net (.NET)**
- GitHub: https://github.com/pwntester/ysoserial.net
- Purpose: .NET deserialization payload generator
- Formatters: BinaryFormatter, SoapFormatter, NetDataContractSerializer, etc.

---

## Research Papers & Publications

### Foundational Research

**1. "Marshalling Pickles: How Deserializing Objects Can Ruin Your Day" (2015)**
- Authors: Chris Frohoff, Gabriel Lawrence
- Conference: AppSecCali 2015
- URL: https://frohoff.github.io/appseccali-marshalling-pickles/
- Significance: Introduced ysoserial, demonstrated widespread Java deserialization vulnerabilities
- Impact: Led to CVE-2015-4852 (Oracle WebLogic) and many others

**2. "Java Unmarshaller Security: Turning Your Data Into Code Execution" (2015)**
- Author: Moritz Bechler (@mbechler)
- Conference: OWASP AppSec EU 2015
- URL: https://github.com/mbechler/marshalsec
- Content: Analysis of Java unmarshalling libraries beyond native serialization
- Covers: JAXB, XStream, JSON processors, YAML

**3. "Surviving the Java Serialization Apocalypse" (2015)**
- Authors: Alvaro Muñoz, Christian Schneider
- Conference: OWASP AppSec USA 2015
- Topics: Detection, exploitation, defense mechanisms
- Tool: Serial Whitelist Application Firewall (SWAF)

**4. "PHP Generic Gadget Chains: Exploiting Unserialize in Unknown Environments" (2018)**
- Author: Charles Fol (@cfreal_)
- URL: https://www.ambionics.io/blog/php-generic-gadget-chains
- Contribution: Demonstrated portable PHP gadget chains
- Impact: Led to development of PHPGGC tool

**5. "Ruby 2.x Universal RCE Deserialization Gadget Chain" (2021)**
- Author: Luke Jahnke (vakzz)
- URL: https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html
- Alternative: https://www.elttam.com/blog/ruby-deserialization/
- Significance: Universal gadget chain for Ruby 2.x-3.x

### In-Depth Technical Analysis

**6. "An In-depth Study of Java Deserialization Remote-Code Execution Exploits and Vulnerabilities" (2022)**
- Authors: Multiple researchers
- Journal: ACM Transactions on Software Engineering and Methodology
- URL: https://dl.acm.org/doi/10.1145/3554732
- Content: Comprehensive academic study of Java deserialization
- Statistics: Analysis of 1,194 vulnerabilities across 597 projects

**7. "Gadget Chains in Java: How Unsafe Deserialization Leads to RCE?" (2023)**
- Author: PVS-Studio Team
- URL: https://pvs-studio.com/en/blog/posts/java/1296/
- Content: Detailed explanation of gadget chain mechanics
- Examples: Commons Collections chain analysis

**8. "Exploiting Deserialization Vulnerabilities in Recent Java Versions" (2024)**
- Conference: OWASP Stuttgart
- URL: https://owasp.org/www-chapter-stuttgart/
- Content: Modern Java exploitation techniques
- Focus: Java 11-21 specific challenges

### Language-Specific Research

**Python Pickle:**
- "Sour Pickles: A serialised exploitation guide" by Marco Slaviero (2011)
- Conference: Black Hat USA 2011

**.NET Deserialization:**
- "Friday the 13th: JSON Attacks" by Alvaro Muñoz (2017)
- "Are You My Type?" by James Forshaw (2017)

**Node.js:**
- "Untrusted Data Deserialization in Node.js" research
- node-serialize vulnerabilities

---

## Real-World CVE Examples

### Critical Java Deserialization Vulnerabilities

**CVE-2015-4852: Oracle WebLogic RCE**
- Severity: Critical (CVSS 10.0)
- Impact: Unauthenticated remote code execution
- Affected: WebLogic Server 10.3.6, 12.1.2, 12.1.3, 12.2.1
- Exploit: T3 protocol deserialization
- ysoserial: Multiple payloads (CommonsCollections1, Jdk7u21)
- References:
  - https://www.cvedetails.com/cve/CVE-2015-4852/
  - https://www.oracle.com/security-alerts/cpuoct2015.html

**CVE-2017-5638: Apache Struts 2 RCE (Equifax Breach)**
- Severity: Critical (CVSS 10.0)
- Impact: Remote code execution via Content-Type header
- Affected: Struts 2.3.5 - 2.3.31, 2.5 - 2.5.10
- Real-World Impact: Equifax data breach (143 million records)
- Exploit: Jakarta Multipart parser deserialization
- References:
  - https://www.cvedetails.com/cve/CVE-2017-5638/
  - https://www.exploit-db.com/exploits/41570

**CVE-2017-3066: Adobe ColdFusion RCE**
- Severity: Critical (CVSS 10.0)
- Impact: Unauthenticated RCE
- Affected: ColdFusion 2016 Update 3, ColdFusion 11 Update 11
- Exploit: Java deserialization via JMX
- ysoserial: Multiple payloads

**CVE-2019-2725/CVE-2019-2729: Oracle WebLogic (Continued)**
- Severity: Critical (CVSS 9.8)
- Impact: Unauthenticated RCE
- Affected: WebLogic 10.x, 12.x
- Exploit: wls9_async and wls-wsat components
- Real-World: Actively exploited by ransomware groups

**CVE-2020-2555: Oracle Coherence RCE**
- Severity: Critical (CVSS 9.8)
- Impact: Network-accessible RCE
- Affected: Oracle Coherence 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0
- Exploit: Deserialization in Coherence cluster service
- ysoserial: Coherence payloads

**CVE-2021-21345: XStream RCE**
- Severity: Critical (CVSS 9.8)
- Impact: Remote code execution
- Affected: XStream < 1.4.16
- Exploit: JNDI injection via deserialization
- Real-World: Widespread use in Java applications

### PHP Deserialization Vulnerabilities

**CVE-2015-8562: Joomla RCE**
- Severity: Critical
- Impact: Unauthenticated remote code execution
- Affected: Joomla 1.5.0 - 3.4.5
- Exploit: PHP object injection via session cookie
- Payload: Custom gadget chain

**CVE-2017-12932: WordPress REST API Unauthorized Access**
- Severity: High (CVSS 7.5)
- Impact: Object injection via REST API
- Affected: WordPress 4.8.1 and prior
- Exploit: PHP deserialization in REST API requests

**CVE-2018-19296: phpMyAdmin Arbitrary File Read**
- Severity: High (CVSS 7.5)
- Impact: File read via object injection
- Affected: phpMyAdmin 4.8.x
- Exploit: Transformations feature deserialization

**CVE-2019-16759: vBulletin RCE**
- Severity: Critical (CVSS 9.8)
- Impact: Pre-auth remote code execution
- Affected: vBulletin 5.x
- Exploit: unserialize() in AJAX API
- Real-World: Exploited in the wild within hours

**CVE-2019-18889: Symfony Secret Token Exposure**
- Severity: High
- Impact: Secret key disclosure leading to RCE
- Affected: Symfony 4.x
- Exploit: PHPInfo exposure + PHPGGC gadget chains

**CVE-2020-11651: SaltStack RCE**
- Severity: Critical (CVSS 10.0)
- Impact: Unauthenticated RCE
- Affected: SaltStack < 3000.2
- Exploit: Salt Master deserialization (Python pickle)
- Real-World: Mass exploitation by cryptocurrency miners

### Ruby/Rails Deserialization Vulnerabilities

**CVE-2013-0156: Ruby on Rails YAML/XML Deserialization**
- Severity: Critical
- Impact: Remote code execution
- Affected: Rails 3.2.x, 3.1.x, 3.0.x, 2.3.x
- Exploit: YAML deserialization in XML parameters
- Real-World: Metasploit module available

**CVE-2019-5420: Rails Development Mode RCE**
- Severity: Critical
- Impact: RCE via crafted file names
- Affected: Rails 4.0.x - 6.0.x (development mode)
- Exploit: Deserialization in sprockets

**CVE-2020-8163: Rails Code Execution**
- Severity: Critical
- Impact: Remote code execution
- Affected: Rails < 5.2.4.3, < 6.0.3
- Exploit: Untrusted data deserialization

### .NET Deserialization Vulnerabilities

**CVE-2017-5638: Microsoft Exchange**
- Severity: Critical
- Impact: Remote code execution
- Exploit: .NET BinaryFormatter deserialization

**CVE-2019-0604: Microsoft SharePoint**
- Severity: Critical
- Impact: RCE via deserialization
- Affected: SharePoint Server 2019, 2016, 2013
- Exploit: ViewState deserialization

**CVE-2019-1306: Microsoft .NET Framework**
- Severity: High
- Impact: RCE via deserialization
- Affected: .NET Framework 2.0-4.8
- Exploit: BinaryFormatter vulnerabilities

### 2024-2025 Recent Vulnerabilities

**CVE-2025-55182: React2Shell (React Server Components)**
- Severity: Critical (CVSS 10.0)
- Impact: Unauthenticated RCE
- Affected: React, Next.js, React Router
- Exploit: Flight protocol unsafe deserialization
- Disclosure: December 2025
- Status: Actively scanned in the wild

**CVE-2025-53770: ToolShell (SharePoint)**
- Severity: Critical
- Impact: Unauthenticated RCE
- Affected: SharePoint Server (on-premises)
- Exploit: Insecure deserialization
- Status: Exploited by ransomware groups

**CVE-2025-10035: Fortra GoAnywhere MFT**
- Severity: Critical
- Impact: Pre-auth RCE
- Exploit: Unsafe deserialization in License Servlet
- Attribution: Medusa ransomware (Storm-1175)

**CVE-2025-68664: LangGrinch (LangChain)**
- Severity: Critical (CVSS 9.3)
- Impact: Secret exfiltration, potential RCE
- Affected: langchain-core
- Exploit: Serialization injection in AI agents
- Type: Prompt injection → deserialization

**CVE-2024-27322: R Statistical Language**
- Severity: High
- Impact: RCE via RDS files
- Affected: R 1.4.0 - 4.3.x
- Exploit: Malicious .rds file deserialization

---

## Framework-Specific Guides

### Java Frameworks

**Spring Framework:**
- Official Security Guide: https://spring.io/security-advisories
- Deserialization: Avoid using Spring Remoting with Java serialization
- Safe Alternatives: Spring REST, Spring HATEOAS

**Apache Struts:**
- Security Guide: https://struts.apache.org/security/
- Known Issues: Multiple deserialization vulnerabilities
- Recommendations: Keep updated, disable dynamic method invocation

**Hibernate:**
- Security: https://hibernate.org/security/
- Gadget Chains: Hibernate1, Hibernate2 in ysoserial
- Mitigation: Validate entity graphs before deserialization

### PHP Frameworks

**Symfony:**
- Security Advisories: https://symfony.com/security
- Deserialization: Avoid unserialize() on user input
- Safe Alternatives: JSON, signed encrypted cookies

**Laravel:**
- Security: https://laravel.com/docs/security
- Cookie Encryption: Built-in encrypted session cookies
- Signed URLs: Integrity protection

**WordPress:**
- Security Best Practices: https://developer.wordpress.org/apis/security/
- Plugin Development: Never unserialize user input
- Nonces: Use for request validation

### Ruby/Rails Frameworks

**Ruby on Rails:**
- Security Guide: https://guides.rubyonrails.org/security.html
- Marshal: Never use Marshal.load on untrusted data
- Safe Alternatives: JSON, encrypted cookies

**Sinatra:**
- Security: Use signed session cookies
- Avoid: Marshal.load on user input

### Python Frameworks

**Django:**
- Security: https://docs.djangoproject.com/en/stable/topics/security/
- Sessions: Use signed cookies, not pickle
- Deserialization: Avoid pickle module on untrusted data

**Flask:**
- Security: https://flask.palletsprojects.com/en/stable/security/
- Sessions: Uses signed cookies by default
- Serialization: Use JSON, not pickle

---

## Secure Coding Practices

### General Principles

**1. Avoid Deserializing Untrusted Data**
```
The best defense is to never deserialize untrusted data.
```

**2. Use Safe Data Formats**
- ✅ JSON (ensure safe parsing)
- ✅ Protocol Buffers
- ✅ MessagePack
- ✅ Apache Avro
- ❌ Native serialization (Java, PHP, Python pickle)
- ❌ YAML (without safe loading)
- ❌ XML (without XXE protection)

**3. Implement Integrity Checks**
- HMAC signatures
- Digital signatures
- Encrypted + signed data

**4. Use Allowlists**
- Whitelist expected classes
- Validate class types before deserialization
- Reject unexpected types

### Language-Specific Best Practices

**Java:**
```java
// Bad
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();

// Better: Use ObjectInputFilter (Java 9+)
ObjectInputStream ois = new ObjectInputStream(input);
ois.setObjectInputFilter(info -> {
    if (info.serialClass() != null) {
        String className = info.serialClass().getName();
        if (className.startsWith("com.myapp.safe.")) {
            return ObjectInputFilter.Status.ALLOWED;
        }
    }
    return ObjectInputFilter.Status.REJECTED;
});
Object obj = ois.readObject();

// Best: Use JSON
ObjectMapper mapper = new ObjectMapper();
User user = mapper.readValue(jsonString, User.class);
```

**PHP:**
```php
// Bad
$obj = unserialize($_COOKIE['session']);

// Better: Use allowed_classes (PHP 7.0+)
$obj = unserialize($data, ['allowed_classes' => ['User', 'Session']]);

// Best: Use JSON
$obj = json_decode($jsonString, true, 512, JSON_THROW_ON_ERROR);

// Or use signed encrypted cookies
$encryptor = new MessageEncryptor($key);
$data = $encryptor->decrypt_and_verify($cookie);
```

**Ruby:**
```ruby
# Bad
obj = Marshal.load(data)

# Good: Use JSON
obj = JSON.parse(data)

# Or MessagePack
obj = MessagePack.unpack(data)

# Rails: Use encrypted cookies (automatic)
# config.action_dispatch.cookies_serializer = :json
```

**Python:**
```python
# Bad
import pickle
obj = pickle.loads(data)

# Good: Use JSON
import json
obj = json.loads(data)

# Or use restricted unpickler
import pickletools
# Analyze pickle opcodes before loading
pickletools.dis(data)
```

**.NET:**
```csharp
// Bad
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(stream);

// Better: Use SerializationBinder
BinaryFormatter formatter = new BinaryFormatter();
formatter.Binder = new SafeSerializationBinder();
object obj = formatter.Deserialize(stream);

// Best: Use JSON
string json = JsonSerializer.Serialize(data);
var obj = JsonSerializer.Deserialize<MyClass>(json);
```

### Defense-in-Depth Strategies

**1. Network Segmentation**
- Limit outbound connections from application servers
- Prevent deserialization exploitation from reaching external systems

**2. Runtime Protection**
- SerialKiller (Java)
- RASP solutions
- Agent-based monitoring

**3. Static Analysis**
- Find-Sec-Bugs (Java)
- Snyk
- SonarQube

**4. Dynamic Analysis**
- Fuzzing with serialized data
- Automated scanning (Burp, OWASP ZAP)

**5. Monitoring & Logging**
- Log all deserialization operations
- Alert on unexpected class names
- Monitor for known gadget chain patterns

---

## Training & Practice Platforms

### Official Training

**PortSwigger Web Security Academy**
- URL: https://portswigger.net/web-security/deserialization
- Content: 9 interactive labs (Apprentice to Expert)
- Coverage: PHP, Java, Ruby deserialization
- Features: Free, browser-based, detailed solutions

### CTF Platforms

**HackTheBox**
- Machines with deserialization: Arkham, JSON, Teacher, etc.
- Challenges: Various difficulties

**TryHackMe**
- Rooms: Java Deserialization, PHP Deserialization
- Interactive: Guided learning

**PentesterLab**
- Specific Exercises: Ruby deserialization, PHP object injection
- Levels: Beginner to Advanced

### Vulnerable Applications

**WebGoat (Java)**
- GitHub: https://github.com/WebGoat/WebGoat
- Lessons: Insecure deserialization modules

**DVWA (PHP)**
- GitHub: https://github.com/digininja/DVWA
- Custom Modules: Add deserialization challenges

**Node-Goat (Node.js)**
- GitHub: https://github.com/OWASP/NodeGoat
- Lessons: node-serialize vulnerabilities

**Damn Vulnerable GraphQL**
- Includes: Serialization issues in GraphQL

---

## Community & Forums

### Security Communities

**PortSwigger Forum**
- URL: https://forum.portswigger.net/
- Topics: Burp extensions, lab discussions, research

**r/netsec (Reddit)**
- Deserialization research discussions
- CVE analysis and exploitation techniques

**Security Stack Exchange**
- URL: https://security.stackexchange.com/
- Q&A: Technical questions and solutions

### GitHub Communities

**ysoserial Issues/Discussions**
- New gadget chain proposals
- Exploitation techniques
- Tool improvements

**PHPGGC Issues/Discussions**
- Framework-specific chains
- Payload development

### Twitter/X Security Researchers

- @frohoff (Chris Frohoff - ysoserial author)
- @cfreal_ (Charles Fol - PHPGGC author)
- @mbechler (Moritz Bechler - marshalsec)
- @pwntester (Alvaro Muñoz - .NET research)
- @orange_8361 (Orange Tsai - researcher)

---

## Books & In-Depth Guides

### Recommended Books

**"Web Application Security" by Andrew Hoffman**
- Publisher: O'Reilly
- Chapter: Deserialization vulnerabilities
- Coverage: Multi-language perspective

**"The Web Application Hacker's Handbook (2nd Edition)"**
- Authors: Dafydd Stuttard, Marcus Pinto
- Chapter: Logic Flaws (includes deserialization)
- Publisher: Wiley

**"Gray Hat Python" by Justin Seitz**
- Publisher: No Starch Press
- Relevant: Python pickle exploitation

**"Bug Bounty Bootcamp" by Vickie Li**
- Publisher: No Starch Press
- Chapter 13: Insecure Deserialization

### Technical Guides

**Java Deserialization Deep Dive**
- GitHub: https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet
- Comprehensive: Tools, techniques, defenses

**PHP Object Injection Guide**
- OWASP: Detailed PHP deserialization exploitation
- Examples: Real-world applications

---

## Video Content & Presentations

### Conference Talks

**"Marshalling Pickles" (AppSecCali 2015)**
- Presenters: Chris Frohoff, Gabriel Lawrence
- URL: https://frohoff.github.io/appseccali-marshalling-pickles/
- Duration: ~45 minutes
- Content: Introduction to Java deserialization exploitation

**"Surviving the Java Deserialization Apocalypse" (2015)**
- Presenters: Alvaro Muñoz, Christian Schneider
- Conference: OWASP AppSec USA
- Topics: Detection, exploitation, defense

**"Exploiting Java Deserialization Vulnerabilities" (DEF CON)**
- Various years and presenters
- Advanced techniques and new research

**"PHP Unserialization Vulnerabilities" (Black Hat)**
- Framework-specific exploitation
- Gadget chain development

### YouTube Channels

**IppSec**
- HackTheBox walkthroughs with deserialization
- Detailed exploitation techniques

**John Hammond**
- CTF writeups including deserialization challenges
- Educational content

**LiveOverflow**
- Deserialization exploitation videos
- Research and analysis

**PwnFunction**
- Animated explanations of vulnerabilities
- Includes deserialization basics

### Online Courses

**Pluralsight: "Advanced Web Application Security"**
- Module: Insecure Deserialization
- Hands-on: Lab exercises

**Udemy: "Burp Suite for Penetration Testing"**
- Includes: Deserialization testing

**Offensive Security: OSWE**
- Advanced: Source code review for deserialization

---

## Additional Resources

### Checklists

**Deserialization Testing Checklist:**
1. [ ] Identify serialization format (Base64 decode, check magic bytes)
2. [ ] Determine language/framework
3. [ ] Test for basic manipulation (privilege escalation)
4. [ ] Attempt pre-built gadget chains (ysoserial, PHPGGC)
5. [ ] Analyze source code if available
6. [ ] Develop custom gadget chains
7. [ ] Chain with other vulnerabilities (SQLi, XXE, SSRF)
8. [ ] Document findings with PoC

**Defense Implementation Checklist:**
1. [ ] Inventory all deserialization usage
2. [ ] Replace with safe alternatives (JSON)
3. [ ] Implement integrity checks (HMAC)
4. [ ] Add class allowlisting where necessary
5. [ ] Deploy runtime protection (SerialKiller, RASP)
6. [ ] Enable monitoring and alerting
7. [ ] Regular dependency updates
8. [ ] Security code reviews

### Toolkits

**Pentester's Deserialization Toolkit:**
- Burp Suite Professional
- ysoserial (latest version)
- PHPGGC (git clone)
- Python3 with pickle module
- Ruby with Marshal
- Text editor with hex view
- Base64 encoder/decoder
- Hex editor
- HTTP proxy client

---

## Stay Updated

### Security Advisories

- Oracle Security Alerts: https://www.oracle.com/security-alerts/
- Apache Security: https://apache.org/security/
- PHP Security: https://www.php.net/security/
- Ruby Security: https://www.ruby-lang.org/en/security/
- Python Security: https://www.python.org/dev/security/

### CVE Databases

- CVE Details: https://www.cvedetails.com/
- NVD: https://nvd.nist.gov/
- Snyk Vulnerability Database: https://security.snyk.io/
- GitHub Security Advisories: https://github.com/advisories

### Mailing Lists

- oss-security mailing list
- Full Disclosure
- Bugtraq
- Framework-specific security lists

---

## Conclusion

Insecure deserialization remains a critical vulnerability class with severe impact potential. Continuous learning, staying updated with latest research, and practicing secure coding are essential for both offensive and defensive security professionals.

**Key Takeaways:**
1. Deserialization of untrusted data is inherently dangerous
2. Multiple languages and frameworks are affected
3. Pre-built tools (ysoserial, PHPGGC) make exploitation accessible
4. Defense requires avoiding deserialization or strong integrity checks
5. Real-world exploitation is common and ongoing
6. Continuous learning is essential in this evolving field

---

*This resource guide is continuously updated. Last update: January 2026*
