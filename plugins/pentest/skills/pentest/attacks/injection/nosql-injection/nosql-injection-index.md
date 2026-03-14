# NoSQL Injection - Master Reference Index

## Overview

This comprehensive NoSQL injection resource covers exploitation techniques, prevention strategies, and hands-on lab walkthroughs. All content is organized to build expertise through practical application.

**Last Updated:** 2026-01-11
**Lab Source:** PortSwigger Web Security Academy
**Focus Database:** MongoDB (with coverage of other NoSQL systems)

---

## Quick Start Guide

**New to NoSQL Injection?** Start here:

1. **Read:** [NoSQL Injection Quickstart Guide](./nosql-injection-quickstart.md)
   - 10-minute primer on attack basics
   - Essential payloads and techniques
   - Quick detection methods

2. **Practice:** PortSwigger Lab 1
   - https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-detection
   - Difficulty: Apprentice (15-30 minutes)
   - Skills: Basic syntax injection

3. **Reference:** [NoSQL Injection Cheat Sheet](./nosql-injection-cheat-sheet.md)
   - Quick payload reference
   - MongoDB operators
   - Python scripts

---

## Core Documentation

### 1. Complete Lab Walkthroughs

**File:** [nosql-injection-portswigger-labs-complete.md](./nosql-injection-portswigger-labs-complete.md)

**Contents:**
- **Lab 1:** Detecting NoSQL Injection (Apprentice)
  - Syntax injection techniques
  - Boolean logic manipulation
  - Always-true payload construction

- **Lab 2:** Bypass Authentication (Apprentice)
  - Operator injection ($ne, $regex, $gt)
  - JSON vs URL-encoded formats
  - Multiple bypass methods

- **Lab 3:** Extract Data (Practitioner)
  - Boolean-based blind injection
  - Character-by-character extraction
  - Burp Intruder automation
  - Password length determination

- **Lab 4:** Extract Unknown Fields (Practitioner)
  - Schema enumeration (Object.keys())
  - Field discovery techniques
  - Reset token extraction
  - Multi-stage exploitation

**Key Features:**
- Step-by-step solutions with screenshots conceptually described
- Exact payloads with URL encoding
- Burp Suite configuration details
- Common mistakes and troubleshooting
- Alternative attack methods
- Real-world impact analysis

**Recommended For:**
- Penetration testers
- Security researchers
- Bug bounty hunters
- CTF participants

---

### 2. Quickstart Guide

**File:** [nosql-injection-quickstart.md](./nosql-injection-quickstart.md)

**Contents:**
- What is NoSQL injection?
- Attack types (syntax vs operator)
- Quick detection tests
- Essential payloads
- Prevention quick guide
- Common mistakes
- Lab practice recommendations

**Read Time:** 10-15 minutes

**Recommended For:**
- Beginners
- Quick reference during assessments
- Pre-assessment preparation

---

### 3. Comprehensive Cheat Sheet

**File:** [nosql-injection-cheat-sheet.md](./nosql-injection-cheat-sheet.md)

**Contents:**
- Detection payloads
- Authentication bypass techniques
- Data extraction methods
- Schema enumeration
- URL encoding reference
- MongoDB operators
- Burp Suite configuration
- Python automation scripts
- cURL commands
- Prevention checklist
- WAF rules
- Detection signatures

**Use Cases:**
- During active assessments
- Payload reference
- Quick automation
- Tool configuration

**Recommended For:**
- Active penetration testing
- Bug bounty hunting
- Security assessments

---

### 4. Additional Resources

**File:** [nosql-injection-resources.md](./nosql-injection-resources.md)

**Contents:**
- Official documentation (OWASP, MongoDB)
- Academic research papers
- CVE examples and advisories
- Tools and frameworks
- Online labs and practice platforms
- Video tutorials and courses
- Community forums
- Bug bounty platforms
- Books and publications
- Certifications

**Use Cases:**
- Deep learning
- Tool discovery
- Community engagement
- Career development

**Recommended For:**
- Continuous learning
- Advanced techniques
- Security professionals

---

## Learning Paths

### Path 1: Absolute Beginner (4-6 hours)

1. **Read:** [Quickstart Guide](./nosql-injection-quickstart.md) (15 min)
2. **Watch:** PortSwigger NoSQL injection tutorial video
3. **Practice:** Lab 1 - Detection (30 min)
4. **Practice:** Lab 2 - Bypass (45 min)
5. **Review:** [Cheat Sheet](./nosql-injection-cheat-sheet.md) detection section (15 min)
6. **Read:** OWASP NoSQL Security Cheat Sheet
7. **Practice:** Repeat labs for speed

**Skills Gained:**
- Basic NoSQL injection detection
- Authentication bypass
- Using Burp Suite basics
- Understanding MongoDB operators

---

### Path 2: Intermediate Practitioner (8-10 hours)

**Prerequisites:** Completed Path 1

1. **Practice:** Lab 3 - Data Extraction (2 hours)
   - Manual extraction
   - Burp Intruder automation
   - Python script creation

2. **Practice:** Lab 4 - Field Extraction (2 hours)
   - Schema enumeration
   - Token extraction
   - Multi-stage attacks

3. **Study:** [Complete Labs Guide](./nosql-injection-portswigger-labs-complete.md) (2 hours)
   - Alternative techniques
   - Common mistakes
   - Real-world scenarios

4. **Code:** Automation scripts (2 hours)
   - Boolean extraction
   - Binary search optimization
   - Field enumeration

5. **Read:** Security vendor resources (1 hour)
   - Imperva, Bright Security, Acunetix

**Skills Gained:**
- Advanced data extraction
- Burp Intruder mastery
- Python automation
- Schema discovery

---

### Path 3: Advanced Exploitation (15-20 hours)

**Prerequisites:** Completed Paths 1 & 2

1. **Research:** CVE case studies (3 hours)
   - CVE-2025-23061 (Mongoose)
   - CVE-2023-28359 (Rocket.Chat)
   - Historical breaches

2. **Practice:** HackTheBox machines (6 hours)
   - Book (MongoDB injection)
   - Health (NoSQL bypass)
   - Travel (Redis injection)

3. **Development:** Custom tooling (4 hours)
   - Automated scanner
   - Payload generator
   - Report generator

4. **Study:** Academic papers (2 hours)
   - MongoDB injection dataset research
   - Novel attack vectors

5. **Practice:** Bug bounty targets (Ongoing)
   - Real-world applications
   - Responsible disclosure

**Skills Gained:**
- Advanced exploitation techniques
- Tool development
- Vulnerability research
- Professional reporting

---

### Path 4: Defense & Prevention (6-8 hours)

**Focus:** Secure Development & Defense

1. **Read:** Prevention sections in all docs (2 hours)
   - Secure coding practices
   - Input validation
   - ODM/ORM usage

2. **Code:** Secure implementations (3 hours)
   - Mongoose with validation
   - Express middleware
   - Input sanitization

3. **Configure:** Security controls (2 hours)
   - WAF rules (ModSecurity)
   - MongoDB security settings
   - Monitoring and logging

4. **Test:** Defensive measures (1 hour)
   - Vulnerability scanning
   - Code review
   - Penetration testing your code

**Skills Gained:**
- Secure coding practices
- WAF configuration
- Security architecture
- Code review

---

## Lab Difficulty Progression

### Apprentice Level (Entry)

**Lab 1: Detection**
- **Time:** 30 minutes
- **Complexity:** Low
- **Techniques:** Basic syntax injection
- **Prerequisites:** None

**Lab 2: Authentication Bypass**
- **Time:** 45 minutes
- **Complexity:** Low-Medium
- **Techniques:** Operator injection
- **Prerequisites:** Lab 1

### Practitioner Level (Intermediate)

**Lab 3: Data Extraction**
- **Time:** 2 hours
- **Complexity:** Medium
- **Techniques:** Boolean-based blind, automation
- **Prerequisites:** Labs 1-2, Burp Suite knowledge

**Lab 4: Unknown Field Extraction**
- **Time:** 2-3 hours
- **Complexity:** Medium-High
- **Techniques:** Schema enumeration, multi-stage
- **Prerequisites:** Labs 1-3, JavaScript knowledge

---

## Skills Matrix

| Skill | Quickstart | Labs 1-2 | Labs 3-4 | Resources |
|-------|-----------|----------|----------|-----------|
| Detection | ✅ | ✅ | ✅ | ✅ |
| Auth Bypass | ✅ | ✅ | ⬜ | ⬜ |
| Data Extraction | ⬜ | ⬜ | ✅ | ⬜ |
| Automation | ⬜ | ⬜ | ✅ | ✅ |
| Prevention | ✅ | ⬜ | ⬜ | ✅ |
| Tool Dev | ⬜ | ⬜ | ⬜ | ✅ |
| Research | ⬜ | ⬜ | ⬜ | ✅ |

---

## Tool References

### Essential Tools

**Burp Suite**
- **Purpose:** Manual testing, automation
- **Labs Used:** All
- **Setup Guide:** Labs complete document
- **Skills:** Proxy, Repeater, Intruder

**Python**
- **Purpose:** Automation, scripting
- **Labs Used:** 3, 4
- **Scripts:** Cheat sheet
- **Libraries:** requests, string

**NoSQLMap**
- **Purpose:** Automated testing
- **Installation:** Resources document
- **Use Case:** Large-scale assessments

**MongoDB**
- **Purpose:** Understanding database
- **Setup:** Docker container
- **Use Case:** Local testing

### Defensive Tools

**mongo-sanitize**
- **Purpose:** Input sanitization
- **Language:** Node.js
- **Use Case:** MEAN/MERN stacks

**Mongoose**
- **Purpose:** ODM with security
- **Language:** Node.js
- **Use Case:** Schema validation

**ModSecurity**
- **Purpose:** WAF
- **Rules:** Cheat sheet
- **Use Case:** Defense

---

## Attack Taxonomy

```
NoSQL Injection
├── Syntax Injection
│   ├── String Breaking (')||1||')
│   ├── Boolean Logic (AND/OR)
│   └── Comment Injection (--, #, //)
│
├── Operator Injection
│   ├── Comparison ($ne, $gt, $gte)
│   ├── Pattern ($regex)
│   ├── Logic ($or, $and, $not)
│   └── Element ($exists, $type)
│
├── JavaScript Injection
│   ├── $where Operator
│   ├── mapReduce
│   └── $function (MongoDB 4.4+)
│
├── Blind Injection
│   ├── Boolean-based
│   │   ├── True/False testing
│   │   └── Character extraction
│   └── Time-based (Limited in NoSQL)
│
└── Schema Enumeration
    ├── Field Discovery (Object.keys())
    ├── Type Detection (typeof)
    └── Value Extraction
```

---

## Database Coverage

### Primary Focus: MongoDB
- **Labs:** All 4 PortSwigger labs
- **Documentation:** Complete
- **Operators:** Comprehensive
- **Tools:** Multiple

### Secondary Coverage
- **CouchDB:** Resources document
- **Redis:** Resources document
- **Cassandra:** Resources document

---

## Quick Reference Links

### PortSwigger Labs
1. [Detection Lab](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-detection)
2. [Bypass Lab](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-bypass-authentication)
3. [Extract Data Lab](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-data)
4. [Unknown Fields Lab](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-unknown-fields)

### OWASP
- [Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
- [Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html)
- [Top 10:2025 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)

### MongoDB
- [Security Manual](https://docs.mongodb.com/manual/security/)
- [Atlas Security](https://www.mongodb.com/cloud/atlas/security)

---

## Assessment Checklists

### Penetration Testing Checklist

**Pre-Assessment:**
- [ ] Authorization obtained
- [ ] Scope defined
- [ ] Tools configured (Burp Suite, NoSQLMap)
- [ ] Lab practice completed

**Detection Phase:**
- [ ] Identify NoSQL database (MongoDB, CouchDB, etc.)
- [ ] Test for syntax injection (', ", $, {, })
- [ ] Test for operator injection ($ne, $regex)
- [ ] Test for $where injection
- [ ] Document all injection points

**Exploitation Phase:**
- [ ] Authentication bypass attempted
- [ ] Data extraction performed
- [ ] Schema enumeration conducted
- [ ] Privilege escalation tested
- [ ] Impact documented

**Post-Assessment:**
- [ ] All findings documented
- [ ] Remediation recommendations provided
- [ ] Report generated
- [ ] Client briefed

### Code Review Checklist

**Input Validation:**
- [ ] All user inputs validated
- [ ] Type checking implemented
- [ ] Whitelisting used (not blacklisting)
- [ ] Length limits enforced

**Query Construction:**
- [ ] No string concatenation
- [ ] Parameterized queries used
- [ ] ODM/ORM framework utilized
- [ ] Schema validation enforced

**Security Controls:**
- [ ] MongoDB JavaScript disabled
- [ ] $where operator blocked
- [ ] Error messages sanitized
- [ ] Rate limiting implemented
- [ ] Logging enabled

**Testing:**
- [ ] SAST scan completed
- [ ] DAST scan performed
- [ ] Penetration test conducted
- [ ] All vulnerabilities remediated

---

## Glossary

**NoSQL:** Non-relational database systems (MongoDB, CouchDB, Redis, Cassandra)

**Syntax Injection:** Breaking query syntax to inject code

**Operator Injection:** Using database operators ($ne, $regex) to manipulate queries

**$where:** MongoDB operator that executes JavaScript (DANGEROUS)

**Boolean Blind:** Extracting data by observing true/false responses

**Schema Enumeration:** Discovering database structure and field names

**Object.keys():** JavaScript method to extract object property names

**ODM/ORM:** Object Document/Relational Mapper (Mongoose, Sequelize)

**Sanitization:** Removing or escaping dangerous characters from input

**Parameterized Query:** Query with placeholders for safe data insertion

---

## Contribution & Updates

This documentation is maintained as part of the pentest skill repository. Updates focus on:

- New PortSwigger labs
- CVE disclosures
- Tool updates
- Technique developments
- Community feedback

---

## Support & Questions

**Questions about labs?**
- Review [Complete Labs Guide](./nosql-injection-portswigger-labs-complete.md)
- Check "Common Mistakes" sections
- Search PortSwigger forums

**Need payload help?**
- Reference [Cheat Sheet](./nosql-injection-cheat-sheet.md)
- Try [Quickstart Guide](./nosql-injection-quickstart.md)
- Review automation scripts

**Want to learn more?**
- Explore [Resources](./nosql-injection-resources.md)
- Join community forums
- Practice on additional platforms

---

## Legal & Ethical Notice

**Note:** Unauthorized access is illegal and can result in:
- Criminal prosecution
- Civil liability
- Imprisonment
- Financial penalties

**Always:**
- Define scope clearly
- Follow responsible disclosure
- Respect boundaries
- Document everything

**When in doubt, ask first.**

---

## Version History

**v1.0 (2026-01-11)**
- Initial release
- All 4 PortSwigger labs documented
- Comprehensive resources compiled
- Automation scripts provided
- Prevention strategies included

---

**Document Maintainer:** Security Research Team
**Last Review:** 2026-01-11
**Next Review:** 2026-04-11 (Quarterly)
