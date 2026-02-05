# Insecure Deserialization - Documentation Index

## Complete Guide to Insecure Deserialization Exploitation

This comprehensive documentation covers all aspects of insecure deserialization vulnerabilities across multiple programming languages and frameworks, with complete PortSwigger Web Security Academy lab walkthroughs.

---

## Documentation Structure

### 📚 Core Documentation

1. **[Complete Lab Guide](insecure-deserialization-portswigger-labs-complete.md)**
   - All 9 PortSwigger Web Security Academy labs
   - Step-by-step solutions with detailed explanations
   - HTTP requests/responses examples
   - Burp Suite workflows
   - Common mistakes and troubleshooting

2. **[Quick Start Guide](insecure-deserialization-quickstart.md)**
   - Rapid testing methodologies
   - Speed-run techniques
   - One-liner exploits
   - Lab completion time estimates
   - Emergency cheat commands

3. **[Cheat Sheet](insecure-deserialization-cheat-sheet.md)**
   - All serialization format signatures
   - Language-specific exploitation techniques
   - Tool usage references
   - Payload library
   - CVE references

4. **[Resources & References](insecure-deserialization-resources.md)**
   - OWASP documentation
   - Research papers
   - Tool documentation
   - Framework-specific guides
   - Real-world case studies

---

## Lab Coverage Overview

### 9 Total Labs

**Difficulty Breakdown:**
- **Apprentice:** 1 lab
- **Practitioner:** 6 labs
- **Expert:** 2 labs

**Language Breakdown:**
- **PHP:** 5 labs
- **Java:** 2 labs
- **Ruby:** 1 lab
- **Language-agnostic:** 1 lab

### Lab Index

| Lab # | Name | Difficulty | Language | Time | Doc Link |
|-------|------|------------|----------|------|----------|
| 1 | Modifying serialized objects | Apprentice | PHP | 10 min | [Lab 1](#) |
| 2 | Modifying serialized data types | Practitioner | PHP | 15 min | [Lab 2](#) |
| 3 | Using application functionality | Practitioner | Any | 20 min | [Lab 3](#) |
| 4 | Arbitrary object injection in PHP | Practitioner | PHP | 25 min | [Lab 4](#) |
| 5 | Java deserialization with Apache Commons | Practitioner | Java | 35 min | [Lab 5](#) |
| 6 | PHP deserialization with pre-built gadget chain | Practitioner | PHP | 50 min | [Lab 6](#) |
| 7 | Ruby deserialization using documented gadget chain | Practitioner | Ruby | 35 min | [Lab 7](#) |
| 8 | Custom gadget chain for PHP | Expert | PHP | 75 min | [Lab 8](#) |
| 9 | Custom gadget chain for Java | Expert | Java | 105 min | [Lab 9](#) |

---

## Learning Path

### Beginner Path (Start Here)

1. **Read:** Complete Lab Guide - Introduction
2. **Practice:** Lab 1 - Modifying serialized objects
3. **Understand:** PHP serialization format basics
4. **Practice:** Lab 2 - Type juggling attacks
5. **Review:** Quick Start Guide - PHP section

**Skills Acquired:**
- Detecting serialized data
- Base64 encoding/decoding
- PHP serialization format
- Basic Burp Suite usage
- Simple object manipulation

### Intermediate Path

1. **Practice:** Lab 3 - Application functionality abuse
2. **Practice:** Lab 4 - Arbitrary object injection
3. **Read:** Cheat Sheet - Magic methods
4. **Practice:** Lab 5 - Java deserialization with ysoserial
5. **Practice:** Lab 7 - Ruby documented gadget chain
6. **Review:** Quick Start Guide - Tools section

**Skills Acquired:**
- Magic method exploitation
- Source code analysis
- ysoserial tool usage
- Ruby Marshal format
- Pre-built gadget chains

### Advanced Path

1. **Practice:** Lab 6 - PHP framework exploitation with PHPGGC
2. **Read:** Complete Lab Guide - Gadget chain theory
3. **Study:** Resources - Research papers on gadget chains
4. **Review:** Cheat Sheet - All language techniques

**Skills Acquired:**
- PHPGGC usage
- HMAC signature forgery
- Information disclosure exploitation
- Framework identification
- Complex exploitation chains

### Expert Path

1. **Practice:** Lab 8 - Custom PHP gadget chain development
2. **Practice:** Lab 9 - Custom Java gadget chain with SQL injection
3. **Read:** Resources - Advanced research papers
4. **Study:** Real-world CVE analysis
5. **Create:** Your own gadget chain discovery methodology

**Skills Acquired:**
- Custom gadget chain development
- Source code review for vulnerabilities
- Multi-vulnerability chaining
- Advanced exploitation techniques
- Research and discovery skills

---

## Quick Navigation

### By Topic

**Detection & Identification:**
- [Quick Start - Detection](insecure-deserialization-quickstart.md#quick-identification)
- [Cheat Sheet - Format Signatures](insecure-deserialization-cheat-sheet.md#detection--identification)

**PHP Exploitation:**
- [Complete Labs - PHP Labs](insecure-deserialization-portswigger-labs-complete.md#lab-1-modifying-serialized-objects)
- [Cheat Sheet - PHP Section](insecure-deserialization-cheat-sheet.md#php-deserialization)
- [Quick Start - PHP 5 Minute Exploitation](insecure-deserialization-quickstart.md#php-deserialization---5-minute-exploitation)

**Java Exploitation:**
- [Complete Labs - Java Labs](insecure-deserialization-portswigger-labs-complete.md#lab-5-exploiting-java-deserialization-with-apache-commons)
- [Cheat Sheet - Java Section](insecure-deserialization-cheat-sheet.md#java-deserialization)
- [Quick Start - Java 10 Minute Exploitation](insecure-deserialization-quickstart.md#java-deserialization---10-minute-exploitation)

**Ruby Exploitation:**
- [Complete Labs - Ruby Lab](insecure-deserialization-portswigger-labs-complete.md#lab-7-exploiting-ruby-deserialization-using-a-documented-gadget-chain)
- [Cheat Sheet - Ruby Section](insecure-deserialization-cheat-sheet.md#ruby-deserialization)
- [Quick Start - Ruby 10 Minute Exploitation](insecure-deserialization-quickstart.md#ruby-deserialization---10-minute-exploitation)

**Tools & Automation:**
- [Cheat Sheet - Exploitation Tools](insecure-deserialization-cheat-sheet.md#exploitation-tools)
- [Quick Start - Tool Installation](insecure-deserialization-quickstart.md#tool-installation-one-time-setup)
- [Resources - Tool Documentation](insecure-deserialization-resources.md#exploitation-tools)

**Defense & Prevention:**
- [Cheat Sheet - Defense Section](insecure-deserialization-cheat-sheet.md#defense--prevention)
- [Resources - Secure Coding](insecure-deserialization-resources.md#secure-coding-practices)
- [Complete Labs - Defense Mechanisms (each lab)](insecure-deserialization-portswigger-labs-complete.md)

---

## Key Concepts Covered

### Fundamental Concepts

- **Serialization vs Deserialization**
  - What is serialization and why is it used
  - How deserialization works
  - Where deserialization is commonly found

- **Vulnerability Types**
  - Object manipulation
  - Type confusion/juggling
  - Arbitrary object injection
  - Remote code execution via gadget chains
  - Multi-stage exploitation

- **Attack Surface**
  - Cookies and session tokens
  - API parameters
  - File uploads
  - WebSocket messages
  - Database stored procedures

### Advanced Concepts

- **Gadget Chains**
  - What are gadget chains
  - How to identify potential gadgets
  - Building custom chains
  - Property-Oriented Programming (POP)

- **Magic Methods**
  - PHP magic methods and exploitation
  - Java readObject() vulnerabilities
  - Ruby Marshal hooks
  - Python __reduce__() exploitation

- **Framework-Specific Attacks**
  - Symfony exploitation
  - Laravel vulnerabilities
  - Ruby on Rails deserialization
  - Spring Framework exploits

- **Tool Development**
  - Using ysoserial for Java
  - Using PHPGGC for PHP
  - Creating custom payloads
  - Automating exploitation

---

## Tools Required

### Essential Tools

| Tool | Purpose | Documentation Link |
|------|---------|-------------------|
| **Burp Suite** | Proxy, testing, inspection | [Burp Documentation](https://portswigger.net/burp/documentation) |
| **ysoserial** | Java gadget chain generation | [GitHub](https://github.com/frohoff/ysoserial) |
| **PHPGGC** | PHP gadget chain generation | [GitHub](https://github.com/ambionics/phpggc) |
| **PHP CLI** | Testing PHP payloads | [PHP Manual](https://www.php.net/manual/en/) |
| **Java JDK** | Compiling Java exploits | [Oracle JDK](https://www.oracle.com/java/technologies/downloads/) |
| **Ruby** | Testing Ruby payloads | [Ruby-lang.org](https://www.ruby-lang.org/) |

### Burp Suite Extensions

- Java Deserialization Scanner
- Freddy (Deserialization Bug Finder)
- .NET Beautifier and Minifier
- Active Scan++

### Optional Tools

- ysoserial.net (for .NET)
- marshalsec (Java deserialization scanner)
- SerialKiller (Java deserialization firewall)
- python pickle-exploit

---

## Skill Progression

### Level 1: Novice (Hours 0-5)
- [ ] Complete Lab 1
- [ ] Understand Base64 encoding
- [ ] Learn basic PHP serialization
- [ ] Use Burp Proxy and Repeater

### Level 2: Beginner (Hours 5-15)
- [ ] Complete Labs 2-3
- [ ] Understand type juggling
- [ ] Learn magic methods
- [ ] Perform source code analysis

### Level 3: Intermediate (Hours 15-30)
- [ ] Complete Labs 4-5
- [ ] Use ysoserial effectively
- [ ] Understand gadget chains conceptually
- [ ] Exploit Java applications

### Level 4: Advanced (Hours 30-50)
- [ ] Complete Labs 6-7
- [ ] Use PHPGGC effectively
- [ ] Exploit multiple frameworks
- [ ] Perform information disclosure + deserialization

### Level 5: Expert (Hours 50-100)
- [ ] Complete Labs 8-9
- [ ] Build custom gadget chains
- [ ] Chain multiple vulnerabilities
- [ ] Perform advanced code review

### Level 6: Master (Hours 100+)
- [ ] Discover new gadget chains
- [ ] Contribute to tools (ysoserial, PHPGGC)
- [ ] Research novel exploitation techniques
- [ ] Teach others

---

## Study Plan

### Week 1: Foundations
- **Day 1-2:** Read introduction, understand serialization concepts
- **Day 3:** Complete Lab 1 multiple times for speed
- **Day 4:** Complete Lab 2, study type juggling
- **Day 5:** Review PHP serialization format in depth
- **Day 6-7:** Practice and experiment with Burp Suite

### Week 2: Intermediate Skills
- **Day 1-2:** Complete Labs 3-4
- **Day 3:** Study PHP magic methods extensively
- **Day 4-5:** Install and learn ysoserial, complete Lab 5
- **Day 6-7:** Study Java serialization format and gadget chains

### Week 3: Advanced Techniques
- **Day 1-3:** Install PHPGGC, complete Lab 6
- **Day 4-5:** Study Ruby Marshal format, complete Lab 7
- **Day 6-7:** Review all previous labs for speed optimization

### Week 4: Expert Level
- **Day 1-3:** Complete Lab 8, study POP chain development
- **Day 4-6:** Complete Lab 9, study multi-vulnerability chains
- **Day 7:** Review all materials, practice speed runs

---

## Assessment & Practice

### Self-Assessment Questions

**Beginner:**
1. What are the magic bytes for Java serialization?
2. How do you identify PHP serialized data?
3. What does `b:0` represent in PHP serialization?
4. What Burp Suite tool is best for modifying cookies?

**Intermediate:**
5. What is PHP type juggling and how does it work?
6. Name three PHP magic methods and when they're called
7. What is ysoserial and what does it generate?
8. How do you detect Ruby Marshal serialization?

**Advanced:**
9. Explain how a POP chain works
10. What is PHPGGC and when would you use it?
11. How do you sign a cookie with HMAC-SHA1?
12. What is the Universal Ruby 2.x-3.x gadget chain?

**Expert:**
13. How do you build a custom PHP gadget chain?
14. Explain readObject() exploitation in Java
15. How can you chain SQL injection with deserialization?
16. How would you discover a new gadget chain?

### Practice Challenges

1. **Speed Challenge:** Complete all 9 labs in under 3 hours
2. **Blind Challenge:** Complete labs without referring to documentation
3. **Tool-Free Challenge:** Complete Labs 1-4 without automated tools
4. **Custom Chain Challenge:** Find a gadget chain in a new PHP application
5. **Multi-Language Challenge:** Exploit deserialization in PHP, Java, and Ruby in one session

---

## Additional Resources

### Official Documentation
- PortSwigger Web Security Academy
- OWASP Deserialization Cheat Sheet
- Tool GitHub repositories

### Research Papers
- "Marshalling Pickles" by Chris Frohoff
- "Java Unmarshaller Security" by Moritz Bechler
- "Ruby Deserialization" by Luke Jahnke

### Video Content
- PortSwigger Web Security Academy videos
- Conference talks (DEF CON, Black Hat)
- Tool demonstration videos

### Community
- PortSwigger forums
- Security Stack Exchange
- GitHub issues and discussions

---

## Updates and Maintenance

**Last Updated:** January 2026

**Version:** 1.0

**Changelog:**
- Initial comprehensive documentation release
- All 9 PortSwigger labs documented
- Complete tool references
- Real-world CVE examples included

**Future Updates:**
- Additional language support (Node.js, Go, Rust)
- More framework-specific exploits
- Automated exploitation scripts
- Defense implementation examples
- Real-world case study deep dives

---

## Contributing

Found an error or want to add content? Contributions welcome:
- Additional payload examples
- Tool usage tips
- Real-world exploitation scenarios
- Defense mechanisms
- CVE analysis

---

## License & Usage

This documentation is provided for educational and authorized security testing purposes only. Unauthorized access to computer systems is illegal.

**Proper Usage:**
- ✅ Authorized penetration testing
- ✅ Bug bounty programs
- ✅ Educational purposes
- ✅ Security research
- ✅ Defensive security implementation

**Prohibited Usage:**
- ❌ Unauthorized system access
- ❌ Malicious activities
- ❌ Violating computer fraud laws
- ❌ Attacking systems without permission

---

*Happy hacking (responsibly)!*
