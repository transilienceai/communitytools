# Race Conditions - Knowledge Base Index

## Overview

This comprehensive knowledge base covers race condition vulnerabilities in web applications, from fundamentals to advanced exploitation techniques. Based on PortSwigger Web Security Academy labs and original research presented at Black Hat USA 2023.

**Last Updated:** January 2026
**Status:** Complete - All 7 PortSwigger Labs Documented
**Skill Level:** Beginner to Expert

---

## Quick Start

**New to race conditions?** → Start here:
1. [Quick Start Guide](race-conditions-quickstart.md) - 5-minute introduction
2. [Lab 1: Limit Overrun](race-conditions-portswigger-labs-complete.md#lab-1-limit-overrun-race-conditions) - Easiest exploitation
3. [Cheat Sheet](race-conditions-cheat-sheet.md) - Quick reference

**Ready to practice?** → [All Labs](race-conditions-portswigger-labs-complete.md#lab-walkthroughs)

**Need specific technique?** → [Cheat Sheet](race-conditions-cheat-sheet.md#complete-payload-reference)

---

## Knowledge Base Structure

### 1. Complete Lab Guide
**File:** `race-conditions-portswigger-labs-complete.md`
**Purpose:** Comprehensive walkthrough of all PortSwigger labs
**Content:**
- All 7 lab solutions with step-by-step instructions
- HTTP request/response examples
- Burp Suite configuration details
- Troubleshooting guidance
- Prevention techniques

**Labs Covered:**
1. Limit Overrun Race Conditions (Apprentice)
2. Bypassing Rate Limits via Race Conditions (Practitioner)
3. Multi-Endpoint Race Conditions (Practitioner)
4. Single-Endpoint Race Conditions (Practitioner)
5. Partial Construction Race Conditions (Expert)
6. Exploiting Time-Sensitive Vulnerabilities (Expert)
7. Web Shell Upload via Race Condition (Practitioner)

**Best For:** Detailed exploitation techniques, lab completion

---

### 2. Cheat Sheet
**File:** `race-conditions-cheat-sheet.md`
**Purpose:** Quick reference for payloads and techniques
**Content:**
- Ready-to-use payload templates
- Burp Suite commands
- Python scripts for Turbo Intruder
- Common patterns and signatures
- Troubleshooting checklist

**Sections:**
- Complete Payload Reference
- Advanced Exploitation Techniques
- Detection Techniques (PREDICT → PROBE → PROVE)
- Burp Suite Workflows
- Common Mistakes & Troubleshooting

**Best For:** Quick lookups during testing, payload copying

---

### 3. Quick Start Guide
**File:** `race-conditions-quickstart.md`
**Purpose:** Get started in 5 minutes
**Content:**
- What are race conditions?
- 5-minute quick test methodology
- Common attack scenarios
- Essential Burp Suite setup
- Success indicators
- Real-world impact examples

**Target Audience:** Beginners, quick orientation

**Best For:** First-time learners, rapid testing

---

### 4. Resources & References
**File:** `race-conditions-resources.md`
**Purpose:** Comprehensive external resource collection
**Content:**
- PortSwigger official documentation
- OWASP guidelines
- CWE/CVE references
- Research papers and presentations
- Tools and extensions
- Secure coding guidelines
- Books and video tutorials
- Practice labs

**Categories:**
- Official documentation (PortSwigger, OWASP)
- Vulnerability databases (CWE, CVE)
- Research and presentations
- Tools and frameworks
- Community resources
- Educational materials

**Best For:** Deep learning, staying updated, research

---

## Learning Path by Skill Level

### Beginner (0-2 hours)

**Start Here:**
1. [Quick Start Guide](race-conditions-quickstart.md) - Read entire document (15 min)
2. [What are Race Conditions?](race-conditions-portswigger-labs-complete.md#race-condition-fundamentals) - Understand concepts (20 min)
3. [Lab 1: Limit Overrun](race-conditions-portswigger-labs-complete.md#lab-1-limit-overrun-race-conditions) - First practical lab (30 min)
4. [Lab 2: Rate Limit Bypass](race-conditions-portswigger-labs-complete.md#lab-2-bypassing-rate-limits-via-race-conditions) - Turbo Intruder introduction (30 min)

**Goals:**
- ✓ Understand TOCTOU concept
- ✓ Complete first lab
- ✓ Use Burp Repeater for parallel requests
- ✓ Recognize exploitation indicators

**Time Investment:** 2 hours

---

### Intermediate (2-6 hours)

**Continue With:**
1. [Lab 3: Multi-Endpoint](race-conditions-portswigger-labs-complete.md#lab-3-multi-endpoint-race-conditions) - Connection warming (45 min)
2. [Lab 4: Single-Endpoint](race-conditions-portswigger-labs-complete.md#lab-4-single-endpoint-race-conditions) - Async collisions (30 min)
3. [Lab 7: File Upload](race-conditions-portswigger-labs-complete.md#lab-7-web-shell-upload-via-race-condition) - Timing attacks (45 min)
4. [Cheat Sheet Review](race-conditions-cheat-sheet.md) - Memorize patterns (30 min)
5. [Detection Techniques](race-conditions-portswigger-labs-complete.md#detection-methodology) - PREDICT → PROBE → PROVE (45 min)

**Goals:**
- ✓ Master Turbo Intruder
- ✓ Understand multi-endpoint timing
- ✓ Exploit file upload races
- ✓ Use detection methodology

**Time Investment:** 4 hours (cumulative: 6 hours)

---

### Advanced (6-10 hours)

**Advanced Labs:**
1. [Lab 5: Partial Construction](race-conditions-portswigger-labs-complete.md#lab-5-partial-construction-race-conditions) - Sub-state exploitation (1 hour)
2. [Lab 6: Time-Sensitive](race-conditions-portswigger-labs-complete.md#lab-6-exploiting-time-sensitive-vulnerabilities) - Timestamp collision (1 hour)
3. [Attack Techniques](race-conditions-portswigger-labs-complete.md#attack-techniques) - Master all methods (1 hour)
4. [Prevention & Defense](race-conditions-portswigger-labs-complete.md#prevention--defense) - Understand mitigations (1 hour)

**Real-World Practice:**
- Bug bounty programs
- CTF challenges
- Personal research projects

**Goals:**
- ✓ Complete all 7 labs
- ✓ Write custom Turbo Intruder scripts
- ✓ Identify vulnerabilities in real applications
- ✓ Understand prevention techniques

**Time Investment:** 4 hours (cumulative: 10 hours)

---

### Expert (10+ hours)

**Mastery Goals:**
1. Research original vulnerabilities
2. Develop custom exploitation tools
3. Contribute to security community
4. Present findings at conferences

**Resources:**
- [Research Papers](race-conditions-resources.md#research-papers--presentations)
- [CVE Examples](race-conditions-resources.md#notable-cve-examples)
- [Secure Coding](race-conditions-resources.md#secure-coding-guidelines)

---

## Quick Reference by Use Case

### I Want To...

**Learn race conditions from scratch**
→ [Quick Start Guide](race-conditions-quickstart.md)

**Practice with hands-on labs**
→ [Lab Walkthroughs](race-conditions-portswigger-labs-complete.md#lab-walkthroughs)

**Find specific payloads**
→ [Cheat Sheet - Payload Reference](race-conditions-cheat-sheet.md#complete-payload-reference)

**Test an endpoint quickly**
→ [5-Minute Quick Test](race-conditions-quickstart.md#5-minute-quick-test)

**Configure Burp Suite**
→ [Burp Suite Workflows](race-conditions-cheat-sheet.md#burp-suite-workflows)

**Write Turbo Intruder scripts**
→ [Cheat Sheet - Script Templates](race-conditions-cheat-sheet.md#turbo-intruder---advanced-attacks)

**Understand detection methodology**
→ [Detection Techniques](race-conditions-cheat-sheet.md#detection-techniques)

**Fix vulnerabilities in my code**
→ [Prevention & Defense](race-conditions-portswigger-labs-complete.md#prevention--defense)

**Learn about real CVEs**
→ [CVE References](race-conditions-resources.md#notable-cve-examples)

**Stay updated on research**
→ [Resources](race-conditions-resources.md#staying-updated)

---

## Lab Difficulty Matrix

| Lab Name | Difficulty | Time | Prerequisites | Tools |
|----------|-----------|------|---------------|-------|
| Limit Overrun | ⭐ Apprentice | 10 min | Basic Burp | Repeater |
| Rate Limit Bypass | ⭐⭐ Practitioner | 15 min | Python basics | Turbo Intruder |
| Multi-Endpoint | ⭐⭐ Practitioner | 15 min | Timing concepts | Repeater |
| Single-Endpoint | ⭐⭐ Practitioner | 10 min | Async understanding | Repeater |
| File Upload | ⭐⭐ Practitioner | 12 min | File ops | Turbo Intruder |
| Partial Construction | ⭐⭐⭐ Expert | 20 min | PHP knowledge | Turbo Intruder |
| Time-Sensitive | ⭐⭐⭐ Expert | 15 min | Session handling | Repeater |

---

## Technique Index

### Exploitation Techniques

**HTTP/2 Single-Packet Attack**
- [Theory](race-conditions-portswigger-labs-complete.md#1-http2-single-packet-attack)
- [Implementation](race-conditions-cheat-sheet.md#http2-single-packet-attack)
- [Labs Using It](race-conditions-portswigger-labs-complete.md#lab-summary-table)

**Last-Byte Synchronization**
- [Theory](race-conditions-portswigger-labs-complete.md#2-last-byte-synchronization)
- [HTTP/1.1 Usage](race-conditions-cheat-sheet.md#last-byte-synchronization-http11)

**Connection Warming**
- [Purpose](race-conditions-portswigger-labs-complete.md#3-connection-warming)
- [Implementation](race-conditions-cheat-sheet.md#connection-warming)
- [Lab 3 Example](race-conditions-portswigger-labs-complete.md#lab-3-multi-endpoint-race-conditions)

**Session Locking Bypass**
- [Problem Description](race-conditions-portswigger-labs-complete.md#5-session-based-locking-bypass)
- [Solution](race-conditions-cheat-sheet.md#session-locking-bypass)
- [Lab 6 Example](race-conditions-portswigger-labs-complete.md#lab-6-exploiting-time-sensitive-vulnerabilities)

**Gate Mechanism**
- [Usage](race-conditions-portswigger-labs-complete.md#6-gate-mechanism-for-synchronization)
- [Script Examples](race-conditions-cheat-sheet.md#gate-mechanism)

**Sub-State Exploitation**
- [Theory](race-conditions-portswigger-labs-complete.md#7-sub-state-exploitation)
- [Lab 5 Example](race-conditions-portswigger-labs-complete.md#lab-5-partial-construction-race-conditions)

**Time-Sensitive Collision**
- [Theory](race-conditions-portswigger-labs-complete.md#8-time-sensitive-collision)
- [Lab 6 Example](race-conditions-portswigger-labs-complete.md#lab-6-exploiting-time-sensitive-vulnerabilities)

---

## Attack Pattern Index

### By Vulnerability Type

**Limit Overrun (TOCTOU)**
- [Fundamentals](race-conditions-portswigger-labs-complete.md#1-limit-overrun-race-conditions)
- [Lab 1](race-conditions-portswigger-labs-complete.md#lab-1-limit-overrun-race-conditions)
- [Payloads](race-conditions-cheat-sheet.md#1-limit-overrun-discount-code-reuse)

**Multi-Endpoint**
- [Fundamentals](race-conditions-portswigger-labs-complete.md#2-multi-endpoint-race-conditions)
- [Lab 3](race-conditions-portswigger-labs-complete.md#lab-3-multi-endpoint-race-conditions)
- [Payloads](race-conditions-cheat-sheet.md#2-multi-endpoint-cart-manipulation)

**Single-Endpoint**
- [Fundamentals](race-conditions-portswigger-labs-complete.md#3-single-endpoint-race-conditions)
- [Lab 4](race-conditions-portswigger-labs-complete.md#lab-4-single-endpoint-race-conditions)
- [Payloads](race-conditions-cheat-sheet.md#3-single-endpoint-email-change-collision)

**Partial Construction**
- [Fundamentals](race-conditions-portswigger-labs-complete.md#5-partial-construction-race-conditions)
- [Lab 5](race-conditions-portswigger-labs-complete.md#lab-5-partial-construction-race-conditions)
- [Payloads](race-conditions-cheat-sheet.md#4-partial-construction-registration-bypass)

**Time-Sensitive**
- [Theory](race-conditions-portswigger-labs-complete.md#the-race-window)
- [Lab 6](race-conditions-portswigger-labs-complete.md#lab-6-exploiting-time-sensitive-vulnerabilities)
- [Payloads](race-conditions-cheat-sheet.md#5-time-sensitive-password-reset-token)

**File Upload**
- [Lab 7](race-conditions-portswigger-labs-complete.md#lab-7-web-shell-upload-via-race-condition)
- [Payloads](race-conditions-cheat-sheet.md#6-file-upload-validation-bypass)

---

## Tool Setup Index

### Burp Suite

**Installation**
- [Resources Guide](race-conditions-resources.md#quick-setup-guide)

**Repeater Usage**
- [Basic Workflow](race-conditions-cheat-sheet.md#burp-repeater---quick-testing)
- [Lab Examples](race-conditions-portswigger-labs-complete.md#burp-repeater---basic-race-condition-testing)

**Turbo Intruder**
- [Installation](race-conditions-resources.md#quick-setup-guide)
- [Basic Usage](race-conditions-cheat-sheet.md#turbo-intruder---advanced-attacks)
- [Script Templates](race-conditions-cheat-sheet.md#script-templates)
- [Advanced Scripts](race-conditions-portswigger-labs-complete.md#turbo-intruder---advanced-attacks)

### Command-Line Tools

**Python Scripts**
- [Race Tester](race-conditions-cheat-sheet.md#python-race-condition-tester)
- [Installation Guide](race-conditions-resources.md#tool-installation--setup)

**Bash Scripts**
- [Simple Tester](race-conditions-cheat-sheet.md#bash-race-condition-tester)

**GNU Parallel**
- [Usage](race-conditions-resources.md#gnu-parallel)

---

## Troubleshooting Index

### Common Problems

**No Collision Detected**
- [Cheat Sheet](race-conditions-cheat-sheet.md#problem-no-collision-detected)
- [Complete Guide](race-conditions-portswigger-labs-complete.md#no-collision-detected)

**Session Locking**
- [Cheat Sheet](race-conditions-cheat-sheet.md#problem-session-locking)
- [Complete Guide](race-conditions-portswigger-labs-complete.md#session-locking)

**Timing Issues**
- [Cheat Sheet](race-conditions-cheat-sheet.md#problem-inconsistent-results)
- [Complete Guide](race-conditions-portswigger-labs-complete.md#timing-issues)

**Rate Limiting**
- [Cheat Sheet](race-conditions-cheat-sheet.md#problem-rate-limiting)
- [Complete Guide](race-conditions-portswigger-labs-complete.md#rate-limiting)

**Common Mistakes**
- [Cheat Sheet](race-conditions-cheat-sheet.md#common-mistakes)
- [Complete Guide](race-conditions-portswigger-labs-complete.md#common-mistakes--troubleshooting)

---

## Prevention Index

### Developer Resources

**Code-Level Mitigations**
- [Atomic Operations](race-conditions-portswigger-labs-complete.md#1-atomic-operations)
- [Database Constraints](race-conditions-portswigger-labs-complete.md#2-database-constraints)
- [Pessimistic Locking](race-conditions-portswigger-labs-complete.md#3-pessimistic-locking)
- [Optimistic Locking](race-conditions-portswigger-labs-complete.md#4-optimistic-locking)
- [Distributed Locks](race-conditions-portswigger-labs-complete.md#5-distributed-locks)
- [Idempotency Keys](race-conditions-portswigger-labs-complete.md#6-idempotency-keys)

**Architecture-Level Defenses**
- [Single-Threaded Processing](race-conditions-portswigger-labs-complete.md#1-single-threaded-processing)
- [Event Sourcing](race-conditions-portswigger-labs-complete.md#2-event-sourcing)
- [Immutable Infrastructure](race-conditions-portswigger-labs-complete.md#3-immutable-infrastructure)

**Testing for Vulnerabilities**
- [Static Analysis](race-conditions-portswigger-labs-complete.md#static-analysis)
- [Dynamic Testing](race-conditions-portswigger-labs-complete.md#dynamic-testing)
- [Monitoring](race-conditions-portswigger-labs-complete.md#monitoring)

**External Resources**
- [Secure Coding Guidelines](race-conditions-resources.md#secure-coding-guidelines)
- [Prevention Best Practices](race-conditions-resources.md#general-best-practices)

---

## External Resources by Category

### Official Documentation
- [PortSwigger Tutorial](race-conditions-resources.md#portswigger-official-resources)
- [OWASP Guidelines](race-conditions-resources.md#owasp-documentation)
- [CWE-362](race-conditions-resources.md#common-weakness-enumeration)

### Research & Papers
- [Black Hat 2023 Presentation](race-conditions-resources.md#black-hat--def-con)
- [Academic Papers](race-conditions-resources.md#academic-papers)

### Tools & Extensions
- [Burp Suite](race-conditions-resources.md#burp-suite-extensions)
- [Command-Line Tools](race-conditions-resources.md#command-line-tools)
- [Static Analysis](race-conditions-resources.md#static-analysis-tools)

### Community
- [Bug Bounty Platforms](race-conditions-resources.md#bug-bounty-platforms)
- [GitHub Repositories](race-conditions-resources.md#github-repositories)
- [Blogs & Articles](race-conditions-resources.md#medium--blog-posts)

### Education
- [Books](race-conditions-resources.md#books--publications)
- [Video Tutorials](race-conditions-resources.md#video-tutorials)
- [Practice Labs](race-conditions-resources.md#practice-labs)

---

## Lab Solutions Quick Links

### By Difficulty

**Apprentice (Start Here):**
- [Lab 1: Limit Overrun](race-conditions-portswigger-labs-complete.md#lab-1-limit-overrun-race-conditions)

**Practitioner:**
- [Lab 2: Rate Limit Bypass](race-conditions-portswigger-labs-complete.md#lab-2-bypassing-rate-limits-via-race-conditions)
- [Lab 3: Multi-Endpoint](race-conditions-portswigger-labs-complete.md#lab-3-multi-endpoint-race-conditions)
- [Lab 4: Single-Endpoint](race-conditions-portswigger-labs-complete.md#lab-4-single-endpoint-race-conditions)
- [Lab 7: File Upload](race-conditions-portswigger-labs-complete.md#lab-7-web-shell-upload-via-race-condition)

**Expert:**
- [Lab 5: Partial Construction](race-conditions-portswigger-labs-complete.md#lab-5-partial-construction-race-conditions)
- [Lab 6: Time-Sensitive](race-conditions-portswigger-labs-complete.md#lab-6-exploiting-time-sensitive-vulnerabilities)

### By Attack Type

**Business Logic:**
- [Lab 1: Limit Overrun](race-conditions-portswigger-labs-complete.md#lab-1-limit-overrun-race-conditions)
- [Lab 3: Multi-Endpoint](race-conditions-portswigger-labs-complete.md#lab-3-multi-endpoint-race-conditions)

**Authentication:**
- [Lab 2: Rate Limit Bypass](race-conditions-portswigger-labs-complete.md#lab-2-bypassing-rate-limits-via-race-conditions)
- [Lab 6: Time-Sensitive](race-conditions-portswigger-labs-complete.md#lab-6-exploiting-time-sensitive-vulnerabilities)

**Account Takeover:**
- [Lab 4: Single-Endpoint](race-conditions-portswigger-labs-complete.md#lab-4-single-endpoint-race-conditions)
- [Lab 5: Partial Construction](race-conditions-portswigger-labs-complete.md#lab-5-partial-construction-race-conditions)

**File Operations:**
- [Lab 7: File Upload](race-conditions-portswigger-labs-complete.md#lab-7-web-shell-upload-via-race-condition)

---

## Glossary of Terms

**Race Condition:** Vulnerability occurring when multiple code paths access shared resources simultaneously without proper synchronization

**Race Window:** The exploitable timeframe between validation and action, potentially lasting only milliseconds

**TOCTOU:** Time-of-Check to Time-of-Use - pattern where validation and action are not atomic

**Sub-States:** Temporary intermediate states during request processing with uninitialized or incomplete values

**Single-Packet Attack:** HTTP/2 technique sending all requests in one TCP packet to maximize timing precision

**Last-Byte Sync:** HTTP/1.1 technique withholding final byte to synchronize request completion

**Connection Warming:** Sending preliminary requests to reduce latency variance

**Gate Mechanism:** Turbo Intruder feature for synchronized request release

**Partial Construction:** Race condition exploiting object creation before complete initialization

**Limit Overrun:** Exceeding imposed restrictions by exploiting TOCTOU flaws

---

## Statistics

**Knowledge Base Metrics:**
- **Total Labs Documented:** 7
- **Total Pages:** 4 comprehensive documents
- **Word Count:** ~45,000 words
- **Code Examples:** 100+ payloads and scripts
- **External Resources:** 80+ references
- **Time to Complete All Labs:** 10-12 hours
- **Skill Levels Covered:** Beginner to Expert

---

## Version History

**v1.0 (January 2026)**
- Complete documentation of all 7 PortSwigger labs
- Comprehensive cheat sheet with payloads
- Quick start guide for beginners
- 80+ external resources catalogued
- Prevention and defense strategies
- Troubleshooting guides

---

## Contributors

**Primary Author:** Pentest Skill Development Team
**Based On:** PortSwigger Web Security Academy Labs
**Original Research:** James Kettle (@albinowax) - Black Hat USA 2023
**Community Contributors:** Bug bounty researchers, security practitioners

---

## Contributing

To suggest improvements or report errors:
1. Review existing documentation
2. Verify against PortSwigger labs
3. Submit detailed feedback
4. Include supporting evidence

---

## License & Attribution

**Content Source:** PortSwigger Web Security Academy (https://portswigger.net/web-security)
**Usage:** Educational and research purposes
**Attribution Required:** When using techniques or content from this knowledge base

---

## Quick Navigation

**Documents:**
- [Complete Lab Guide →](race-conditions-portswigger-labs-complete.md)
- [Cheat Sheet →](race-conditions-cheat-sheet.md)
- [Quick Start →](race-conditions-quickstart.md)
- [Resources →](race-conditions-resources.md)

**Start Learning:**
- [What are Race Conditions? →](race-conditions-quickstart.md#what-are-race-conditions)
- [5-Minute Quick Test →](race-conditions-quickstart.md#5-minute-quick-test)
- [First Lab →](race-conditions-portswigger-labs-complete.md#lab-1-limit-overrun-race-conditions)

**Need Help?**
- [Troubleshooting →](race-conditions-cheat-sheet.md#troubleshooting-guide)
- [Common Mistakes →](race-conditions-portswigger-labs-complete.md#common-mistakes--troubleshooting)
- [External Resources →](race-conditions-resources.md)

---

**Ready to Start?** → [Quick Start Guide](race-conditions-quickstart.md)
