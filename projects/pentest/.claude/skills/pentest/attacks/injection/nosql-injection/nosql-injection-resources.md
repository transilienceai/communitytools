# NoSQL Injection - Additional Resources

## Official Documentation & Standards

### OWASP Resources

**OWASP Web Security Testing Guide (WSTG)**
- **URL:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
- **Topics:** Testing methodologies, detection techniques, exploitation procedures
- **Key Sections:**
  - NoSQL vs SQL injection differences
  - MongoDB-specific testing
  - CouchDB injection techniques
  - Testing tools and frameworks

**OWASP NoSQL Security Cheat Sheet**
- **URL:** https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html
- **Topics:** Prevention techniques, secure coding practices, input validation strategies
- **Key Recommendations:**
  - Disable client-controlled query operators
  - Use high-level APIs (ODM/ORM)
  - Sanitize and validate user input
  - Implement allowlist validation

**OWASP NodeGoat Tutorial**
- **URL:** https://ckarande.gitbooks.io/owasp-nodegoat-tutorial/content/tutorial/a1_-_sql_and_nosql_injection.html
- **Topics:** Practical Node.js + MongoDB injection examples
- **Features:**
  - Hands-on vulnerable application
  - Step-by-step exploitation guides
  - Remediation examples

**OWASP Top 10:2025 - A05 Injection**
- **URL:** https://owasp.org/Top10/2025/A05_2025-Injection/
- **Topics:** Injection vulnerabilities including NoSQL
- **Context:** NoSQL injection ranks #5 in most critical web application risks
- **Coverage:**
  - Risk factors and impact
  - Prevention strategies
  - Detection methods

### MongoDB Official Security Documentation

**MongoDB Security Manual**
- **URL:** https://docs.mongodb.com/manual/security/
- **Topics:** Authentication, authorization, encryption, auditing
- **Key Features:**
  - Role-based access control (RBAC)
  - Network isolation
  - Encryption at rest and in transit
  - Audit logging

**Disable Server-Side JavaScript**
- **Command:** `mongod --noscripting`
- **Config File:**
  ```yaml
  security:
    javascriptEnabled: false
  ```
- **Purpose:** Prevents $where and mapReduce JavaScript injection

**MongoDB Atlas Security**
- **URL:** https://www.mongodb.com/cloud/atlas/security
- **Features:**
  - Built-in encryption
  - Network isolation
  - Automated backups
  - Real-time monitoring

### Database-Specific Documentation

**CouchDB Security**
- **URL:** https://docs.couchdb.org/en/stable/intro/security.html
- **Topics:** Authentication, authorization, validation functions
- **NoSQL Injection:** Query parameter validation

**Redis Security**
- **URL:** https://redis.io/topics/security
- **Topics:** Authentication, command renaming, network security
- **NoSQL Injection:** Limited risk due to key-value nature

**Cassandra Security**
- **URL:** https://cassandra.apache.org/doc/latest/operating/security.html
- **Topics:** Authentication, authorization, encryption
- **NoSQL Injection:** CQL injection prevention

## Industry Publications & Research

### Academic Papers

**"The MongoDB Injection Dataset"**
- **Source:** PMC (PubMed Central)
- **URL:** https://pmc.ncbi.nlm.nih.gov/articles/PMC10997947/
- **Authors:** Various security researchers
- **Published:** 2024
- **Content:** Comprehensive collection of MongoDB NoSQL injection attempts and vulnerabilities
- **Key Contributions:**
  - Large-scale dataset for research
  - Attack pattern analysis
  - Machine learning applications for detection

**"NoSQL Injection: Analysis and Prevention"**
- **Topics:** Attack vectors, exploitation techniques, defense mechanisms
- **Findings:** NoSQL injection often more dangerous than SQL injection due to JavaScript execution

### Security Vendor Resources

**Imperva Learning Center**
- **URL:** https://www.imperva.com/learn/application-security/nosql-injection/
- **Topics:** Attack overview, real-world examples, prevention strategies
- **Features:**
  - Interactive diagrams
  - Video explanations
  - Case studies

**Bright Security (NeuraLegion)**
- **URL:** https://brightsec.com/blog/nosql-injection-explained-what-it-is-and-how-to-prevent-it/
- **Topics:** MongoDB SQL injection, secure coding practices
- **Features:**
  - Code examples in multiple languages
  - Testing methodologies
  - Automated scanning recommendations

**Acunetix Blog**
- **URL:** https://www.acunetix.com/blog/web-security-zone/nosql-injections/
- **Topics:** NoSQL injection prevention and testing
- **Features:**
  - Vulnerability assessment tips
  - Mitigation strategies
  - Scanner recommendations

**Invicti (Netsparker)**
- **URL:** https://www.invicti.com/learn/nosql-injection
- **Topics:** Comprehensive NoSQL injection guide
- **Features:**
  - Attack taxonomy
  - Prevention checklist
  - Real-world examples

**Indusface**
- **URL:** https://www.indusface.com/learning/nosql-injection/
- **Topics:** Risks, mechanisms, prevention
- **Features:**
  - Detailed attack flow diagrams
  - Prevention best practices
  - WAF configuration guidance

### Penetration Testing Guides

**HackTricks - NoSQL Injection**
- **URL:** https://book.hacktricks.xyz/pentesting-web/nosql-injection
- **Content:** Comprehensive exploitation techniques
- **Databases Covered:**
  - MongoDB
  - CouchDB
  - Cassandra
  - Redis
- **Features:**
  - Payload collections
  - Tool recommendations
  - Bypass techniques

**Pentest Wizard**
- **URL:** https://pentestwizard.com/pentesting-databases-nosql-injection-prevention/
- **Topics:** Database penetration testing, NoSQL injection prevention
- **Features:**
  - Testing methodologies
  - Tool walkthroughs
  - Prevention techniques

**Cybersecurity Decoder**
- **URL:** https://cybersecuritydecoder.com/threats/sql-injection/preventing-nosql-injection-attacks-best-practices-1159/
- **Topics:** Best practices for preventing NoSQL injection
- **Features:**
  - Input validation strategies
  - WAF configuration
  - Monitoring techniques

## CVE Database & Vulnerability Advisories

### Recent Critical CVEs

**CVE-2025-23061 - Mongoose RCE**
- **Product:** Mongoose ≤ 8.8.2
- **Severity:** Critical
- **Vulnerability:** $where operator execution in populate() despite server-side JS disabled
- **Impact:** Remote code execution
- **Patch:** Mongoose 8.8.3+
- **Reference:** https://github.com/Automattic/mongoose/security/advisories/GHSA-4g84-wjcf-9v5c

**CVE-2023-28359 - Rocket.Chat NoSQL Injection**
- **Product:** Rocket.Chat ≤ 6.0.0
- **Severity:** High
- **Vulnerability:** Unauthenticated NoSQL injection via Meteor method
- **Impact:** Data exfiltration of 11 million user records
- **Attack Vector:** `{"$where":"sleep(2000)||true"}`
- **Patch:** Rocket.Chat 6.0.1
- **Reference:** https://nvd.nist.gov/vuln/detail/CVE-2023-28359

**CVE-2021-22911 - Rocket.Chat Authentication Bypass**
- **Product:** Rocket.Chat < 3.11.3
- **Severity:** Critical
- **Vulnerability:** NoSQL injection in password reset
- **Impact:** Authentication bypass, account takeover
- **Patch:** Rocket.Chat 3.11.3

### Historical Breaches

**Yahoo Data Breach (2018)**
- **Impact:** 11 million user records stolen
- **Database:** MongoDB
- **Attack Vector:** NoSQL injection combined with other vulnerabilities
- **Lesson Learned:** Defense in depth required

**Cosmos DB Vulnerability (2021)**
- **Product:** Microsoft Azure Cosmos DB
- **Vulnerability:** Jupyter Notebook feature allowed unauthorized access
- **Impact:** Full read/write access to databases
- **Lesson Learned:** Default security configurations are critical

## Tools & Frameworks

### Automated Testing Tools

**NoSQLMap**
- **URL:** https://github.com/codingo/NoSQLMap
- **Description:** Automated NoSQL injection and database takeover tool
- **Supported Databases:** MongoDB, CouchDB, Redis, Cassandra
- **Features:**
  - Automated injection detection
  - Data extraction
  - Authentication bypass
  - Report generation
- **Installation:**
  ```bash
  git clone https://github.com/codingo/NoSQLMap.git
  cd NoSQLMap
  python nosqlmap.py
  ```
- **Usage:**
  ```bash
  python nosqlmap.py -u "http://target.com/login" -p username,password --attack=1
  ```

**NoSQL-Exploitation-Framework**
- **URL:** https://github.com/torque59/Nosql-Exploitation-Framework
- **Description:** Framework for testing NoSQL databases
- **Features:**
  - Multiple attack vectors
  - Payload generation
  - Automated exploitation
- **Usage:**
  ```bash
  git clone https://github.com/torque59/Nosql-Exploitation-Framework
  cd Nosql-Exploitation-Framework
  python nosqlpwn.py
  ```

**Burp Suite**
- **URL:** https://portswigger.net/burp
- **Editions:** Professional, Community
- **Features:**
  - Proxy for traffic interception
  - Repeater for manual testing
  - Intruder for automated attacks
  - Extensions marketplace
- **NoSQL Extensions:**
  - NoSQLi Scanner
  - JSON Beautifier
  - Hackvertor (encoding)

**OWASP ZAP**
- **URL:** https://www.zaproxy.org/
- **Description:** Free, open-source web app scanner
- **Features:**
  - Automated scanning
  - Manual testing tools
  - NoSQL injection detection
- **Usage:**
  ```bash
  zap.sh -daemon -port 8080
  ```

**sqlmap (with NoSQL support)**
- **URL:** https://sqlmap.org/
- **Description:** Primarily SQL injection tool, limited NoSQL support
- **Usage:**
  ```bash
  sqlmap -u "http://target.com/page?id=1" --dbms=MongoDB
  ```

### Defensive Tools

**mongo-sanitize (npm)**
- **URL:** https://www.npmjs.com/package/mongo-sanitize
- **Description:** Sanitize MongoDB queries in Node.js
- **Installation:**
  ```bash
  npm install mongo-sanitize
  ```
- **Usage:**
  ```javascript
  const sanitize = require('mongo-sanitize');
  const username = sanitize(req.body.username);
  ```

**express-mongo-sanitize**
- **URL:** https://www.npmjs.com/package/express-mongo-sanitize
- **Description:** Express middleware to prevent NoSQL injection
- **Installation:**
  ```bash
  npm install express-mongo-sanitize
  ```
- **Usage:**
  ```javascript
  const mongoSanitize = require('express-mongo-sanitize');
  app.use(mongoSanitize());
  ```

**Mongoose with Schema Validation**
- **URL:** https://mongoosejs.com/
- **Description:** MongoDB ODM for Node.js with built-in security
- **Features:**
  - Schema validation
  - Type casting
  - Query building
- **Usage:**
  ```javascript
  const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
  });
  ```

**validator.js**
- **URL:** https://github.com/validatorjs/validator.js
- **Description:** String validation and sanitization library
- **Features:**
  - Input validation
  - Sanitization
  - Type checking
- **Usage:**
  ```javascript
  const validator = require('validator');
  if (!validator.isAlphanumeric(username)) {
    throw new Error('Invalid username');
  }
  ```

### WAF Solutions

**ModSecurity**
- **URL:** https://github.com/SpiderLabs/ModSecurity
- **Description:** Open-source web application firewall
- **Features:**
  - Rule-based filtering
  - NoSQL injection detection
  - Custom rule creation
- **Configuration:** See cheat sheet for NoSQL rules

**AWS WAF**
- **URL:** https://aws.amazon.com/waf/
- **Description:** Cloud-based web application firewall
- **Features:**
  - Managed rule groups
  - Rate limiting
  - Custom rules
- **NoSQL Protection:** Built-in injection detection

**Cloudflare WAF**
- **URL:** https://www.cloudflare.com/waf/
- **Description:** Cloud-based WAF with NoSQL protection
- **Features:**
  - OWASP rule sets
  - DDoS protection
  - Bot management

**Imperva WAF**
- **URL:** https://www.imperva.com/products/web-application-firewall-waf/
- **Description:** Enterprise-grade WAF
- **Features:**
  - NoSQL injection prevention
  - API protection
  - Advanced threat analytics

## Online Labs & Practice Platforms

### PortSwigger Web Security Academy

**Main Portal:**
- **URL:** https://portswigger.net/web-security
- **Free:** Yes
- **Labs:** 4 NoSQL injection labs
- **Features:**
  - Interactive learning
  - Guided solutions
  - Progress tracking

**Lab 1: Detecting NoSQL Injection**
- **URL:** https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-detection
- **Difficulty:** Apprentice
- **Objective:** Display unreleased products

**Lab 2: Bypass Authentication**
- **URL:** https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-bypass-authentication
- **Difficulty:** Apprentice
- **Objective:** Login as administrator

**Lab 3: Extract Data**
- **URL:** https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-data
- **Difficulty:** Practitioner
- **Objective:** Extract admin password

**Lab 4: Extract Unknown Fields**
- **URL:** https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-unknown-fields
- **Difficulty:** Practitioner
- **Objective:** Extract reset token

### HackTheBox

**Platform URL:** https://www.hackthebox.com
- **Type:** CTF-style challenges and machines
- **NoSQL Content:** Multiple machines with MongoDB vulnerabilities
- **Difficulty:** Varies (Easy to Insane)
- **Cost:** Free tier available, VIP for full access

**Relevant Machines:**
- **Book** - MongoDB injection
- **Health** - NoSQL authentication bypass
- **Travel** - Redis injection

### TryHackMe

**Platform URL:** https://tryhackme.com
- **Type:** Guided learning paths and rooms
- **NoSQL Content:** Dedicated NoSQL injection rooms
- **Difficulty:** Beginner-friendly
- **Cost:** Free tier available, Premium for advanced content

**Relevant Rooms:**
- **NoSQL Injection Basics**
- **Web Application Security**
- **OWASP Top 10**

### PentesterLab

**Platform URL:** https://pentesterlab.com
- **Type:** White-box and black-box exercises
- **NoSQL Content:** MongoDB and CouchDB injection exercises
- **Difficulty:** Progressive
- **Cost:** Subscription-based

### DVWA (Damn Vulnerable Web Application)

**URL:** https://github.com/digininja/DVWA
- **Type:** Self-hosted vulnerable application
- **NoSQL Content:** Limited, but extensible
- **Difficulty Levels:** Low, Medium, High, Impossible
- **Installation:**
  ```bash
  docker pull vulnerables/web-dvwa
  docker run -d -p 80:80 vulnerables/web-dvwa
  ```

### WebGoat

**URL:** https://github.com/WebGoat/WebGoat
- **Type:** OWASP educational platform
- **NoSQL Content:** Injection lessons and challenges
- **Features:**
  - Built-in hints
  - Progress tracking
  - Multi-language support
- **Installation:**
  ```bash
  docker pull webgoat/webgoat-8.0
  docker run -p 8080:8080 -t webgoat/webgoat-8.0
  ```

## Video Tutorials & Courses

### YouTube Channels

**PortSwigger Web Security**
- **URL:** https://www.youtube.com/c/PortSwiggerTV
- **Content:** Lab walkthroughs, exploitation techniques
- **Quality:** Professional, expert-led

**Rana Khalil**
- **URL:** https://www.youtube.com/c/RanaKhalil101
- **Content:** Detailed PortSwigger lab walkthroughs
- **Features:** Step-by-step explanations, beginner-friendly

**The Cyber Mentor**
- **URL:** https://www.youtube.com/c/TheCyberMentor
- **Content:** Practical ethical hacking, including NoSQL injection
- **Features:** Real-world pentesting scenarios

**IppSec**
- **URL:** https://www.youtube.com/c/ippsec
- **Content:** HackTheBox machine walkthroughs
- **Features:** In-depth exploitation techniques

**John Hammond**
- **URL:** https://www.youtube.com/c/JohnHammond010
- **Content:** CTF walkthroughs, security challenges
- **Features:** Entertaining, educational

### Paid Courses

**PentesterAcademy**
- **URL:** https://www.pentesteracademy.com/
- **Courses:** Web Application Penetration Testing
- **Topics:** NoSQL injection, exploitation techniques
- **Cost:** Subscription-based

**Offensive Security (OSWE)**
- **URL:** https://www.offensive-security.com/awae-oswe/
- **Course:** Advanced Web Attacks and Exploitation
- **Topics:** Advanced injection techniques, including NoSQL
- **Certification:** OSWE

**Udemy Courses**
- **Search:** "NoSQL injection" or "MongoDB security"
- **Popular:**
  - "The Complete Web Security Course"
  - "Advanced Web Hacking"
- **Cost:** Varies ($10-$200)

**Pluralsight**
- **URL:** https://www.pluralsight.com/
- **Courses:** Web security, application security
- **Topics:** NoSQL injection prevention and testing
- **Cost:** Subscription

## Community & Forums

### Reddit Communities

**r/netsec**
- **URL:** https://www.reddit.com/r/netsec/
- **Topics:** Network security, vulnerability research
- **Activity:** High

**r/websecurity**
- **URL:** https://www.reddit.com/r/websecurity/
- **Topics:** Web application security
- **Activity:** Medium

**r/AskNetsec**
- **URL:** https://www.reddit.com/r/AskNetsec/
- **Topics:** Security questions, career advice
- **Activity:** High

**r/mongodb**
- **URL:** https://www.reddit.com/r/mongodb/
- **Topics:** MongoDB-specific discussions, security
- **Activity:** High

### Discord Servers

**TryHackMe Discord**
- **Invite:** https://discord.gg/tryhackme
- **Channels:** Web exploitation, help channels
- **Members:** 100K+

**HackTheBox Discord**
- **Invite:** https://discord.gg/hackthebox
- **Channels:** Machine discussions, hints
- **Members:** 200K+

**OWASP Discord**
- **Invite:** https://owasp.org/slack/invite
- **Channels:** #appsec, #testing, #coders
- **Members:** 10K+

**The Cyber Mentor Discord**
- **Invite:** https://discord.gg/tcm
- **Channels:** Web hacking, tool discussions
- **Members:** 50K+

### Stack Overflow

**Main Site:** https://stackoverflow.com
- **Tags:** [mongodb-injection], [nosql], [security]
- **Use:** Technical questions, code reviews
- **Activity:** High

**Security Stack Exchange**
- **URL:** https://security.stackexchange.com/
- **Topics:** Security concepts, best practices
- **Activity:** High

### Blogs & News

**PortSwigger Research**
- **URL:** https://portswigger.net/research
- **Topics:** Latest web security research
- **Frequency:** Regular updates

**The Hacker News**
- **URL:** https://thehackernews.com/
- **Topics:** Security news, vulnerability disclosures
- **Frequency:** Daily

**Krebs on Security**
- **URL:** https://krebsonsecurity.com/
- **Topics:** Security investigations, breaches
- **Frequency:** Regular

**Medium Security Publications**
- **Tag:** [cybersecurity], [web-security]
- **Popular:** InfoSec Write-ups, Bug Bounty Write-ups
- **Frequency:** Daily

## Bug Bounty Platforms

### HackerOne

**URL:** https://www.hackerone.com/
- **Programs:** 1000+ active programs
- **Scope:** Often includes NoSQL injection
- **Payouts:** Varies ($100-$10,000+ for critical)
- **Features:**
  - Responsible disclosure
  - Private programs
  - Mediation support

### Bugcrowd

**URL:** https://www.bugcrowd.com/
- **Programs:** 500+ active programs
- **Scope:** Web application vulnerabilities
- **Features:**
  - Crowdsourced security testing
  - Researcher resources
  - Bug bounty tips

### Synack

**URL:** https://www.synack.com/
- **Type:** Invite-only platform
- **Features:**
  - Pre-vetted researchers
  - Higher-quality targets
  - Better payouts

### YesWeHack

**URL:** https://www.yeswehack.com/
- **Region:** European focus
- **Programs:** 300+ active programs
- **Features:**
  - GDPR compliant
  - Multiple languages

## Books & Publications

### Essential Reading

**"The Web Application Hacker's Handbook" (2nd Edition)**
- **Authors:** Dafydd Stuttard, Marcus Pinto
- **Publisher:** Wiley
- **ISBN:** 978-1118026472
- **Topics:** Comprehensive web security including NoSQL injection
- **Why Read:** Industry standard reference

**"Web Application Security: Exploitation and Countermeasures for Modern Web Applications"**
- **Author:** Andrew Hoffman
- **Publisher:** O'Reilly
- **ISBN:** 978-1492053118
- **Topics:** Modern web security practices
- **Coverage:** NoSQL injection prevention

**"The Database Hacker's Handbook"**
- **Author:** David Litchfield et al.
- **Publisher:** Wiley
- **ISBN:** 978-0764578014
- **Topics:** Database security across platforms
- **Coverage:** SQL and NoSQL injection

**"Securing Node.js"**
- **Author:** Chetan Karande
- **Topics:** Node.js + MongoDB security
- **Coverage:** NoSQL injection prevention in MEAN stack

### Research Papers

**"NoSQL Databases: New Attack Opportunities"**
- **Conference:** Black Hat USA
- **Year:** 2015
- **Authors:** Various
- **Content:** Novel attack vectors against NoSQL databases

**"Exploring NoSQL Injection"**
- **Conference:** DEFCON
- **Year:** 2017
- **Content:** Advanced exploitation techniques

## Secure Coding Resources

### Style Guides

**OWASP Secure Coding Practices**
- **URL:** https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/
- **Topics:** Input validation, output encoding
- **Languages:** Multiple

**Node.js Security Checklist**
- **URL:** https://nodejs.org/en/docs/guides/security/
- **Topics:** Dependency management, input validation
- **Features:** Best practices for MEAN/MERN stacks

### Code Review Checklists

**NoSQL Injection Prevention Checklist:**
- [ ] No string concatenation in queries
- [ ] Type validation on all inputs
- [ ] Use of ODM/ORM frameworks
- [ ] Input sanitization implemented
- [ ] MongoDB JavaScript disabled
- [ ] No $where operator with user input
- [ ] Schema validation enforced
- [ ] Error messages don't leak information
- [ ] Rate limiting implemented
- [ ] Logging and monitoring enabled

## Certifications

**CEH (Certified Ethical Hacker)**
- **Provider:** EC-Council
- **Topics:** Web application hacking, including NoSQL injection
- **Cost:** ~$1,200

**OSCP (Offensive Security Certified Professional)**
- **Provider:** Offensive Security
- **Topics:** Practical penetration testing
- **Cost:** ~$1,000

**OSWE (Offensive Security Web Expert)**
- **Provider:** Offensive Security
- **Topics:** Advanced web exploitation
- **Cost:** ~$1,600

**GWAPT (GIAC Web Application Penetration Tester)**
- **Provider:** SANS/GIAC
- **Topics:** Web application security testing
- **Cost:** ~$2,000

---

**Document Version:** 1.0
**Last Updated:** 2026-01-11
**Maintainer:** Security Research Team
