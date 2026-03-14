# Race Conditions - Comprehensive Resources & References

## Table of Contents
- [PortSwigger Official Resources](#portswigger-official-resources)
- [OWASP Documentation](#owasp-documentation)
- [CWE & CVE References](#cwe--cve-references)
- [Research Papers & Presentations](#research-papers--presentations)
- [Tools & Extensions](#tools--extensions)
- [Secure Coding Guidelines](#secure-coding-guidelines)
- [Real-World Vulnerabilities](#real-world-vulnerabilities)
- [Testing Frameworks](#testing-frameworks)
- [Community Resources](#community-resources)
- [Books & Publications](#books--publications)
- [Video Tutorials](#video-tutorials)
- [Practice Labs](#practice-labs)

---

## PortSwigger Official Resources

### Primary Documentation

**1. Race Conditions Tutorial**
- **URL:** https://portswigger.net/web-security/race-conditions
- **Description:** Comprehensive guide covering fundamentals, exploitation techniques, and prevention
- **Topics Covered:**
  - Limit overrun race conditions
  - Multi-endpoint race conditions
  - Single-endpoint race conditions
  - Partial construction race conditions
  - Time-sensitive vulnerabilities
  - Sub-state exploitation
- **Features:** Interactive examples, code snippets, best practices

**2. Race Conditions Learning Path**
- **URL:** https://portswigger.net/web-security/learning-paths/race-conditions
- **Description:** Structured progression from basics to advanced exploitation
- **Format:** 7 hands-on labs with increasing difficulty
- **Prerequisites:** Burp Suite Professional 2023.9+
- **Time Investment:** 2-4 hours for complete path

**3. All Labs Listing**
- **URL:** https://portswigger.net/web-security/all-labs#race-conditions
- **Labs Included:**
  - Limit overrun race conditions (Apprentice)
  - Bypassing rate limits via race conditions (Practitioner)
  - Multi-endpoint race conditions (Practitioner)
  - Single-endpoint race conditions (Practitioner)
  - Partial construction race conditions (Expert)
  - Exploiting time-sensitive vulnerabilities (Expert)
  - Web shell upload via race condition (Practitioner)

### Research & Blog Posts

**4. "Smashing the State Machine" Research**
- **URL:** https://portswigger.net/research/smashing-the-state-machine
- **Authors:** James Kettle (@albinowax)
- **Published:** Black Hat USA 2023
- **Key Contributions:**
  - Introduction of partial construction race conditions
  - HTTP/2 single-packet attack technique
  - Sub-state exploitation methodology
  - Turbo Intruder enhancements
- **Impact:** Discovered race conditions in major frameworks and applications

**5. New Techniques and Tools for Web Race Conditions**
- **URL:** https://portswigger.net/blog/new-techniques-and-tools-for-web-race-conditions
- **Topics:**
  - Single-packet attack implementation
  - Last-byte synchronization
  - Connection warming techniques
  - Burp Suite 2023.9 features
- **Release Date:** 2023

### Burp Suite Documentation

**6. Burp Suite Professional Documentation**
- **URL:** https://portswigger.net/burp/documentation
- **Relevant Sections:**
  - HTTP/2 support configuration
  - Repeater tab groups and parallel sending
  - Single-packet attack feature
  - Performance optimization

**7. Turbo Intruder Extension Guide**
- **URL:** https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988
- **Repository:** https://github.com/PortSwigger/turbo-intruder
- **Documentation:**
  - Python scripting API
  - Template examples
  - Engine configuration
  - Gate mechanism usage
- **Requirements:** Jython 2.7+

---

## OWASP Documentation

### Primary Resources

**8. Business Logic Abuse - BLA9:2025: Race Condition and Concurrency Issues**
- **URL:** https://owasp.org/www-project-top-10-for-business-logic-abuse/docs/the-top-10/race-condition-and-concurrency-issues
- **Status:** Official OWASP Top 10 Business Logic Abuse entry
- **Coverage:**
  - Check-and-act race conditions (TOCTOU)
  - Unsynchronized shared-resource access
  - Event-driven workflow failures
  - Concurrent state change synchronization
- **Impact Assessment:** CWE-362, CWE-367, CWE-366
- **Exploitation Techniques:** Parallel request attacks, timing manipulation
- **Prevention:** Atomic operations, locking mechanisms, transaction isolation

**9. OWASP Top 10:2021 - Next Steps**
- **URL:** https://owasp.org/Top10/A11_2021-Next_Steps/
- **Section:** Code Quality Issues
- **Mentions:** TOCTOU race conditions as detectable via static analysis
- **Recommendations:**
  - Enable static code analysis in editors
  - Use SAST tools for detection
  - Implement compiler warnings
  - Employ linter IDE plugins

**10. Session Management Cheat Sheet**
- **URL:** https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- **Relevant Topics:**
  - Session locking mechanisms
  - Concurrent session handling
  - Token generation best practices
  - Session state synchronization
- **Security Controls:** Prevention of session-based race conditions

### Additional OWASP Resources

**11. OWASP Testing Guide**
- **URL:** https://owasp.org/www-project-web-security-testing-guide/
- **Chapter:** Testing for Race Conditions (WSTG-BUSL-01)
- **Testing Procedures:**
  - Identification methodology
  - Concurrent request testing
  - Response analysis
  - Impact assessment
- **Tools Recommended:** Burp Suite, custom scripts, load testing tools

---

## CWE & CVE References

### Common Weakness Enumeration

**12. CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')**
- **URL:** https://cwe.mitre.org/data/definitions/362.html
- **Description:** Primary CWE entry for race conditions
- **Extended Description:**
  - Violation of exclusivity principle
  - Atomicity failures
  - TOCTOU patterns
  - Shared resource conflicts
- **Consequences:**
  - Availability: Resource exhaustion, DoS
  - Confidentiality/Integrity: Data overwrites, unauthorized access
  - Access Control: Privilege escalation, security bypass
- **Mitigations:**
  - Synchronization primitives (mutexes, locks)
  - Atomic operations
  - Minimized shared resource usage
  - Least privilege execution
- **Detection Methods:**
  - Stress testing with concurrent threads
  - Dynamic analysis with intentional delays
  - Static code analysis
  - White-box review of TOCTOU patterns
- **Real Examples:**
  - CVE-2022-29527: Privilege escalation via world-writable sudoers file
  - CVE-2021-0920: Mobile platform race condition → use-after-free
  - CVE-2020-6819: Race condition enabling use-after-free

**13. CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition**
- **URL:** https://cwe.mitre.org/data/definitions/367.html
- **Focus:** Specific variant focusing on validation gaps
- **Classic Pattern:**
  ```c
  if (access(filename, W_OK) == 0) {  // Check
      // Gap!
      fd = open(filename, O_WRONLY);  // Use
  }
  ```
- **Attack Vectors:**
  - Symbolic link manipulation
  - File system race windows
  - Permission check bypasses

**14. CWE-366: Race Condition within a Thread**
- **URL:** https://cwe.mitre.org/data/definitions/366.html
- **Focus:** Multi-threaded application vulnerabilities
- **Common Scenarios:**
  - Shared variable access
  - Global state manipulation
  - Resource allocation conflicts

### Notable CVE Examples

**15. CVE-2024-6387: OpenSSH Race Condition RCE**
- **URL:** https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6387
- **Description:** Critical vulnerability in OpenSSH's SIGALRM signal manager
- **Affected:** OpenSSH servers on glibc-based Linux systems
- **Impact:** Remote code execution via race condition
- **CVSS:** 9.8 (Critical)
- **Discovery:** 2024
- **Article:** https://medium.com/@yanivx32/the-chase-for-time-race-condition-vulnerabilities-and-how-to-exploit-them-a-live-example-from-c1cc66086617
- **Exploitation:** Timing manipulation of signal handlers during authentication
- **Patch:** Fixed in OpenSSH 9.8p1

**16. CVE-2025-32463: sudo Privilege Escalation**
- **Description:** Critical timing issue in sudo allowing local privilege escalation
- **Impact:** Low-privileged users can escalate to root
- **Attack Vector:** Race condition in configuration file handling
- **Exploitation:** Malicious configuration file insertion during validation window
- **CVSS:** 8.8 (High)
- **Year:** 2025
- **Status:** Patched

**17. CVE-2025-68287: USB dwc3 Driver Race Condition**
- **URL:** https://thewindowsupdate.com/2026/01/07/cve-2025-68287-usb-dwc3-fix-race-condition-between-concurrent-dwc3_remove_requests-call-paths/
- **Component:** USB dwc3 driver
- **Issue:** Race condition between concurrent dwc3_remove_requests() call paths
- **Year:** 2025
- **Type:** Kernel-level race condition

**18. CVE-2023-29325: Microsoft Windows OLE Race Condition**
- **Description:** Race condition in OLE object handling
- **Impact:** Arbitrary code execution or system crash
- **Affected:** Microsoft Windows OLE feature
- **Year:** 2023
- **Type:** Object manipulation race condition

**19. CVE-2023-24042: LightFTP Path Traversal via Race Condition**
- **Description:** Race condition enables path traversal in LightFTP
- **Version:** Through 2.2
- **Impact:** Unauthorized file access
- **Year:** 2023

**20. CVE Database Search**
- **URL:** https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=race+condition
- **Use:** Search for latest race condition CVEs
- **Filter Options:** By year, severity, product

---

## Research Papers & Presentations

### Black Hat & DEF CON

**21. "Smashing the State Machine: The True Potential of Web Race Conditions"**
- **Conference:** Black Hat USA 2023
- **Speaker:** James Kettle (PortSwigger)
- **Slides:** Available on PortSwigger Research portal
- **Video:** Black Hat USA 2023 recordings
- **Key Innovations:**
  - Partial construction race conditions
  - HTTP/2 single-packet technique
  - Sub-state exploitation framework
  - Real-world case studies
- **Impact:** Changed how security professionals approach race condition testing

**22. "Time-of-Check to Time-of-Use: From Research to Reality"**
- **Multiple conferences:** DEF CON, CCC, Security BSides
- **Topics:** Historical evolution of TOCTOU research
- **Case Studies:** File system races, authentication bypasses

### Academic Papers

**23. "Understanding and Detecting Race Conditions in Web Applications"**
- **Authors:** Various academic institutions
- **Repositories:** ACM Digital Library, IEEE Xplore
- **Topics:**
  - Formal verification methods
  - Automated detection techniques
  - Static analysis approaches
  - Dynamic testing methodologies

**24. "Concurrency Attacks on Web Applications"**
- **Focus:** Database transaction races
- **Methodologies:** Model checking, symbolic execution
- **Tools:** Research prototypes for automated detection

---

## Tools & Extensions

### Burp Suite Extensions

**25. Turbo Intruder**
- **BApp Store:** https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988
- **GitHub:** https://github.com/PortSwigger/turbo-intruder
- **Author:** James Kettle (PortSwigger)
- **Capabilities:**
  - HTTP/2 single-packet attacks
  - Last-byte synchronization
  - Python scripting engine
  - High-speed request generation
  - Gate-based synchronization
- **Requirements:** Burp Suite Pro, Jython
- **Templates:**
  - `race-single-packet-attack.py`
  - `race-last-byte-sync.py`
  - `examples/default.py`

**26. BurpAPISecuritySuite**
- **GitHub:** https://github.com/Teycir/BurpAPISecuritySuite
- **Description:** API security testing with race condition support
- **Features:**
  - 15 attack types including race conditions
  - 108+ payload templates
  - Intelligent fuzzing
  - BOLA/IDOR detection
  - Nuclei integration
  - Turbo Intruder integration
- **Coverage:** OWASP API Top 10

**27. Logger++**
- **BApp Store:** Search "Logger++"
- **Use Case:** Detailed request/response logging for race condition analysis
- **Features:**
  - Timing analysis
  - Pattern matching
  - Response comparison
  - Custom filters

### Command-Line Tools

**28. GNU Parallel**
- **Installation:** `apt-get install parallel` or `brew install parallel`
- **Use Case:** Parallel curl requests
- **Example:**
  ```bash
  parallel -j 20 curl -X POST https://target.com/api \
    -H "Cookie: session=TOKEN" \
    -d "param=value" ::: {1..20}
  ```

**29. Apache Bench (ab)**
- **Installation:** Included with Apache
- **Use Case:** Concurrent request generation
- **Example:**
  ```bash
  ab -n 100 -c 20 -H "Cookie: session=TOKEN" \
    -p payload.txt https://target.com/api
  ```

**30. wrk - HTTP Benchmarking Tool**
- **GitHub:** https://github.com/wg/wrk
- **Use Case:** High-performance concurrent requests
- **Scripting:** Lua-based for complex scenarios

### Static Analysis Tools

**31. Coverity Static Analysis**
- **URL:** https://scan.coverity.com/
- **Capabilities:** Detects concurrency issues in C/C++, Java, C#
- **Race Condition Detection:** TOCTOU patterns, deadlocks, data races

**32. ThreadSanitizer (TSan)**
- **Part of:** LLVM/Clang, GCC
- **Use Case:** Runtime race condition detection
- **Language Support:** C, C++, Go
- **Integration:** Compile with `-fsanitize=thread`

**33. FindBugs / SpotBugs**
- **URL:** https://spotbugs.github.io/
- **Language:** Java
- **Detection:** Concurrency bugs, race conditions
- **Integration:** Maven, Gradle, IDE plugins

**34. SonarQube**
- **URL:** https://www.sonarqube.org/
- **Coverage:** Multiple languages
- **Rules:** Concurrency pattern detection
- **CI/CD Integration:** Available

---

## Secure Coding Guidelines

### General Best Practices

**35. "Race Condition Vulnerability: A Detailed Technical Guide"**
- **URL:** https://www.uprootsecurity.com/blog/race-condition-vulnerabilities-an-ultimate-guide
- **Topics:**
  - Vulnerability identification
  - Code review techniques
  - Secure coding patterns
  - Testing methodologies
- **Examples:** Language-specific code samples

**36. "How to Prevent Race Conditions in Web Applications"**
- **URL:** https://www.kroll.com/en/insights/publications/cyber/race-condition-web-applications
- **Author:** Kroll Cyber Risk
- **Coverage:**
  - Prevention strategies
  - Architecture-level defenses
  - Code-level mitigations
  - Testing approaches
- **Case Studies:** Real-world implementation examples

**37. "Race Condition Explained: What You Need to Know"**
- **URL:** https://www.veracode.com/security/race-condition/
- **Publisher:** Veracode
- **Format:** Developer-focused guide
- **Topics:**
  - Race condition types
  - Detection methods
  - Prevention techniques
  - Code examples in multiple languages

**38. "How to Mitigate Race Conditions Vulnerabilities"**
- **URL:** https://www.infosecinstitute.com/resources/secure-coding/how-to-mitigate-race-conditions-vulnerabilities/
- **Publisher:** Infosec Institute
- **Focus:** Practical mitigation strategies
- **Content:**
  - Atomic operations
  - Locking mechanisms
  - Transaction isolation
  - Best practices by language

### Apple Secure Coding Guide

**39. "Secure Coding Guide: Avoiding Race Conditions and Insecure File Operations"**
- **URL:** https://leopard-adc.pepas.com/documentation/Security/Conceptual/SecureCodingGuide/Articles/RaceConditions.html
- **Publisher:** Apple Developer
- **Topics:**
  - File system race conditions
  - Temporary file handling
  - Secure file operations
  - TOCTOU prevention
- **Platform:** macOS, iOS specific but generally applicable
- **Code Examples:** Objective-C, Swift

### Language-Specific Guidelines

**40. Java Concurrency in Practice**
- **Topic:** Thread safety, synchronization
- **Resources:** Oracle Java documentation
- **Key Classes:** `synchronized`, `ReentrantLock`, `AtomicInteger`

**41. Python Threading Documentation**
- **URL:** https://docs.python.org/3/library/threading.html
- **Topics:** Locks, conditions, semaphores
- **Best Practices:** GIL considerations, thread-safe operations

**42. Go Concurrency Patterns**
- **Resources:** Official Go blog
- **Topics:** Goroutines, channels, mutexes
- **Philosophy:** "Do not communicate by sharing memory; share memory by communicating"

---

## Testing Frameworks

### Web Application Testing

**43. "The Ultimate Guide to Race Condition Testing in Web Applications"**
- **URL:** https://momentic.ai/resources/the-ultimate-guide-to-race-condition-testing-in-web-applications
- **Publisher:** Momentic
- **Coverage:**
  - Testing methodologies
  - Tool selection
  - Automation approaches
  - CI/CD integration
- **Frameworks:** Selenium, Playwright, custom scripts

**44. OWASP ZAP (Zed Attack Proxy)**
- **URL:** https://www.zaproxy.org/
- **Race Condition Support:** Via custom scripts
- **Scripting:** Python, JavaScript
- **Use Case:** Automated security testing

### Load Testing Tools

**45. Locust**
- **URL:** https://locust.io/
- **Use Case:** Concurrent user simulation
- **Scripting:** Python-based
- **Features:** Distributed testing, real-time monitoring

**46. JMeter**
- **URL:** https://jmeter.apache.org/
- **Use Case:** Load testing with concurrent threads
- **Features:** Thread groups, synchronization timers
- **GUI:** Visual test plan creation

---

## Community Resources

### Bug Bounty Platforms

**47. HackerOne Race Condition Reports**
- **URL:** https://hackerone.com/hacktivity?querystring=race%20condition
- **Examples:**
  - Staging.every.org race condition disclosure (Report #927384)
  - Multiple public reports demonstrating exploitation
- **Learning Value:** Real-world impact, disclosure timelines, bounty amounts

**48. Bugcrowd Researcher Resources**
- **URL:** https://www.bugcrowd.com/resources/
- **Topics:** Race condition hunting tips
- **Community:** Active forums and Discord

### GitHub Repositories

**49. Web-Race-Conditions Research**
- **URL:** https://github.com/Jake-Schoellkopf/Web-Race-Conditions
- **Author:** Jake Schoellkopf
- **Content:**
  - Research overview
  - Code review techniques
  - Manual exploitation methods
  - PortSwigger lab walkthroughs
- **Based On:** Black Hat USA 2023 research

**50. Race Condition Exploitation Scripts**
- **Search:** GitHub for "race condition web"
- **Languages:** Python, Go, JavaScript
- **Use Cases:** Custom testing automation

### Medium & Blog Posts

**51. "The Chase for Time: Race Condition Vulnerabilities and How to Exploit Them — A Live Example from CVE-2024-6387"**
- **URL:** https://medium.com/@yanivx32/the-chase-for-time-race-condition-vulnerabilities-and-how-to-exploit-them-a-live-example-from-c1cc66086617
- **Author:** Yaniv Azran
- **Content:** Detailed OpenSSH vulnerability walkthrough
- **Format:** Step-by-step exploitation guide

**52. "PortSwigger Web Security Academy | Race Conditions Lab #1"**
- **URL:** https://medium.com/@booruledie/portswigger-web-security-academy-race-conditions-lab-1-ab379b081a40
- **Author:** BooRuleDie
- **Content:** Lab walkthrough with screenshots
- **Target Audience:** Beginners

### Security Knowledge Bases

**53. "Race Condition Vulnerability" - SecureFlag**
- **URL:** https://knowledge-base.secureflag.com/vulnerabilities/use_of_dangerous_function/race_condition_vulnerability.html
- **Format:** Structured knowledge base entry
- **Content:**
  - Definition and examples
  - Exploitation techniques
  - Mitigation strategies
  - Code samples

**54. "Race Condition" - Application Security Cheat Sheet**
- **URL:** https://0xn3va.gitbook.io/cheat-sheets/web-application/race-condition
- **Format:** Quick reference guide
- **Content:**
  - Attack vectors
  - Payloads
  - Tool commands
  - Tips and tricks

### Forums & Communities

**55. Reddit - r/netsec**
- **URL:** https://reddit.com/r/netsec
- **Search:** "race condition"
- **Content:** News, discussions, tool releases

**56. Stack Overflow**
- **URL:** https://stackoverflow.com/questions/tagged/race-condition
- **Use:** Technical Q&A, code debugging
- **Tags:** `race-condition`, `concurrency`, `thread-safety`

---

## Books & Publications

### Security Books

**57. "The Web Application Hacker's Handbook" (2nd Edition)**
- **Authors:** Dafydd Stuttard, Marcus Pinto
- **Publisher:** Wiley
- **Chapter:** Race Conditions in Web Applications
- **ISBN:** 978-1118026472
- **Relevance:** Foundational concepts, still highly relevant

**58. "Real-World Bug Hunting"**
- **Author:** Peter Yaworski
- **Publisher:** No Starch Press
- **Content:** Bug bounty case studies including race conditions
- **ISBN:** 978-1593278618

**59. "Bug Bounty Bootcamp"**
- **Author:** Vickie Li
- **Publisher:** No Starch Press
- **Chapter:** Finding Race Conditions
- **ISBN:** 978-1718501546
- **Release:** 2021

### Concurrency Books

**60. "Java Concurrency in Practice"**
- **Authors:** Brian Goetz, et al.
- **Publisher:** Addison-Wesley
- **ISBN:** 978-0321349606
- **Relevance:** Deep dive into thread safety, race conditions
- **Language:** Java-specific but concepts broadly applicable

**61. "The Art of Multiprocessor Programming"**
- **Authors:** Maurice Herlihy, Nir Shavit
- **Publisher:** Morgan Kaufmann
- **ISBN:** 978-0123973375
- **Topics:** Concurrent algorithms, race condition theory

---

## Video Tutorials

### YouTube Channels

**62. Rana Khalil - PortSwigger Academy Walkthroughs**
- **Channel:** Rana Khalil
- **Content:** Complete lab walkthroughs with explanations
- **Search:** "Rana Khalil race conditions"

**63. STÖK - Bug Bounty & Web Security**
- **Channel:** STÖK
- **Content:** Real-world hunting techniques
- **Search:** "STÖK race condition"

**64. PwnFunction - Security Animation Series**
- **Channel:** PwnFunction
- **Format:** Animated explainers
- **Topics:** TOCTOU, concurrency vulnerabilities

### Conference Recordings

**65. Black Hat USA 2023 - Smashing the State Machine**
- **Platform:** YouTube, Black Hat website
- **Length:** ~45 minutes
- **Content:** Research presentation by James Kettle

**66. DEF CON Talks on Race Conditions**
- **Platform:** YouTube DEF CON channel
- **Search:** "DEF CON race condition"
- **Multiple Years:** Various perspectives and techniques

---

## Practice Labs

### PortSwigger Web Security Academy

**67. Free Labs**
- Limit overrun race conditions
- Bypassing rate limits via race conditions
- Multi-endpoint race conditions

**68. Practitioner Labs**
- Single-endpoint race conditions
- Web shell upload via race condition

**69. Expert Labs**
- Partial construction race conditions
- Exploiting time-sensitive vulnerabilities

### Other Platforms

**70. HackTheBox**
- **URL:** https://www.hackthebox.com/
- **Search:** Boxes/challenges involving race conditions
- **Difficulty:** Varies

**71. TryHackMe**
- **URL:** https://tryhackme.com/
- **Search:** "race condition" or "concurrency"
- **Format:** Guided learning paths

**72. PentesterLab**
- **URL:** https://pentesterlab.com/
- **Exercises:** Web security including race conditions
- **Badge:** Concurrency badge

---

## Standards & Compliance

### Industry Standards

**73. NIST Secure Software Development Framework (SSDF)**
- **URL:** https://csrc.nist.gov/projects/ssdf
- **Relevance:** Secure development practices including race condition prevention

**74. OWASP ASVS (Application Security Verification Standard)**
- **URL:** https://owasp.org/www-project-application-security-verification-standard/
- **Section:** Business Logic Verification Requirements
- **Coverage:** Concurrent operation handling

---

## Additional Resources

### Cheat Sheets

**75. "One Bug, Many Faces: Understanding Every Type of Race Condition Vulnerability"**
- **URL:** https://dev.to/deoxys/one-bug-many-faces-understanding-every-type-of-race-condition-vulnerability-4po3
- **Platform:** DEV Community
- **Format:** Comprehensive overview
- **Content:** Type taxonomy, examples, mitigations

**76. "Ultimate Bug Bounty Guide to Race Condition Vulnerabilities"**
- **URL:** https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-race-condition-vulnerabilities
- **Platform:** YesWeHack
- **Target Audience:** Bug bounty hunters
- **Content:** Hunting methodology, tools, reporting

### Vulnerability Databases

**77. Vulners.com**
- **URL:** https://vulners.com/
- **Search:** Race condition CVEs
- **Features:** Aggregated vulnerability data

**78. ExploitDB**
- **URL:** https://www.exploit-db.com/
- **Search:** Race condition exploits
- **Content:** PoCs, papers, code

---

## Tool Installation & Setup

### Quick Setup Guide

**79. Installing Burp Suite Professional**
```bash
# Download from PortSwigger
wget https://portswigger.net/burp/releases/download
chmod +x burpsuite_pro_linux_*.sh
./burpsuite_pro_linux_*.sh
```

**80. Installing Turbo Intruder**
```
1. Open Burp Suite
2. Extender → BApp Store
3. Search "Turbo Intruder"
4. Click Install
5. Wait for Jython installation
```

**81. Python Race Condition Testing Script**
```python
# Save as race_tester.py
import concurrent.futures
import requests

def test_race(url, data, headers, count=20):
    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
        futures = [executor.submit(requests.post, url, data=data, headers=headers)
                  for _ in range(count)]
        results = [f.result() for f in futures]

    successes = sum(1 for r in results if r.status_code == 200)
    print(f"Successes: {successes}/{count}")
    if successes > 1:
        print("⚠️  POTENTIAL RACE CONDITION")

# Usage:
test_race("https://target.com/api", {"param": "value"}, {"Cookie": "session=TOKEN"})
```

---

## Staying Updated

### RSS Feeds & Newsletters

**82. PortSwigger Research Blog RSS**
- **URL:** https://portswigger.net/research/rss
- **Content:** Latest research, tool updates

**83. OWASP Newsletter**
- **URL:** https://owasp.org/
- **Subscribe:** Monthly security updates

**84. CVE Alerts**
- **URL:** https://cve.mitre.org/
- **Setup:** Email alerts for "race condition" keyword

### Twitter/X Accounts to Follow

**85. @albinowax** (James Kettle - PortSwigger)
**86. @PortSwiggerNet** (PortSwigger official)
**87. @OWASP** (OWASP Foundation)
**88. Security researchers focusing on web vulnerabilities

---

## Conclusion

This comprehensive resource list provides everything needed to master race condition vulnerabilities in web applications, from basic concepts to advanced exploitation techniques. Regular consultation of these resources will keep skills current as the field evolves.

**Recommended Learning Path:**
1. Start with PortSwigger tutorials and labs
2. Study OWASP documentation for theory
3. Practice with real CVE examples
4. Use Burp Suite and Turbo Intruder
5. Follow latest research and presentations
6. Participate in bug bounty programs
7. Contribute to the community

**Key Bookmarks:**
- PortSwigger Race Conditions: https://portswigger.net/web-security/race-conditions
- OWASP BLA9:2025: https://owasp.org/www-project-top-10-for-business-logic-abuse/
- CWE-362: https://cwe.mitre.org/data/definitions/362.html
- Turbo Intruder: https://github.com/PortSwigger/turbo-intruder

---

**Last Updated:** January 2026
**Maintained By:** Pentest Skill Contributors
**Contributions:** Welcome via pull requests
