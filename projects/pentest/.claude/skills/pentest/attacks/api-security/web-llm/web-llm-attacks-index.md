# Web LLM Attacks - Documentation Index

**Complete guide to mastering Web LLM attack techniques for penetration testing and security research**

---

## Quick Navigation

### 🚀 Start Here
- **New to Web LLM attacks?** → Start with [Quick Start Guide](#quick-start-guide)
- **Want hands-on practice?** → Go to [PortSwigger Labs Guide](#portswigger-labs-guide)
- **Need specific payloads?** → Check [Cheat Sheet](#cheat-sheet)
- **Looking for tools/CVEs?** → Browse [Resources](#resources)

---

## Documentation Files

### Quick Start Guide
**File**: `web-llm-attacks-quickstart.md`
**Purpose**: Rapid testing and lab completion
**Best for**: Time-limited environments, CTFs, certifications

**Contents**:
- ✅ 60-second vulnerability check
- ⏱️ Lab speed run guide (5-15 min per lab)
- 🚨 Emergency cheat commands
- 📚 Common payloads library
- 🔧 Burp Suite quick configuration
- 🌳 Troubleshooting decision tree

**Use when**:
- Taking BSCP exam
- Competing in CTF
- Quick assessment needed
- Stuck on a lab

---

### Cheat Sheet
**File**: `web-llm-attacks-cheat-sheet.md`
**Purpose**: Complete payload and command reference
**Best for**: Quick lookup during testing

**Contents**:
- 💉 Prompt injection payloads (direct & indirect)
- 🔍 API enumeration techniques
- 💾 SQL injection via LLM
- 💻 OS command injection via LLM
- 📝 Indirect prompt injection variants
- 🎯 XSS via insecure output handling
- 🛡️ Bypass techniques (encoding, obfuscation)
- 🔨 Burp Suite commands
- 🚨 Detection signatures
- ✅ Prevention controls

**Use when**:
- Need specific payload
- Testing different bypass methods
- Configuring monitoring
- Implementing defenses

---

### PortSwigger Labs Guide
**File**: `web-llm-attacks-portswigger-labs-complete.md`
**Purpose**: Comprehensive lab solutions with theory
**Best for**: Learning and understanding

**Contents**:
- 📖 Lab 1: Exploiting LLM APIs with Excessive Agency
- 📖 Lab 2: Exploiting Vulnerabilities in LLM APIs
- 📖 Lab 3: Indirect Prompt Injection
- 📖 Lab 4: Exploiting Insecure Output Handling in LLMs
- 🎓 Attack techniques summary
- 🌐 Real-world application guidance

**Each lab includes**:
- Difficulty and time estimate
- Vulnerability description
- Step-by-step solution
- Alternative payloads
- HTTP request examples
- Burp Suite workflow
- Common mistakes
- Troubleshooting tips
- Attack variations

**Use when**:
- Learning Web LLM attacks
- Understanding exploitation flow
- Preparing for certifications
- Teaching others

---

### Resources
**File**: `web-llm-attacks-resources.md`
**Purpose**: Comprehensive reference material
**Best for**: Research and professional development

**Contents**:

#### 📘 Standards & Documentation
- OWASP Top 10 for LLM Applications (2025)
- OWASP Top 10 for Agentic Applications (2026)
- OWASP LLM Prevention Cheat Sheet
- NIST AI Risk Management Framework
- Industry standards (ISO, IEEE, PCI DSS)

#### 🐛 CVE Examples (10+ detailed)
- CVE-2025-53773: GitHub Copilot RCE (CVSS 9.0)
- CVE-2025-54135/54136: Cursor IDE
- CVE-2024-5565: Vanna.AI RCE (CVSS 9.8)
- CVE-2023-29374: LangChain RCE
- LangChain vulnerabilities (SSRF, SQLi, RCE)
- ZombieAgent attack on ChatGPT
- *Full exploitation details included*

#### 🛠️ Testing Tools
**Commercial**:
- Mindgard (AI red teaming platform)
- Giskard (automated testing)
- Lasso Security LLM Guardian
- WhyLabs LLM Security

**Open-Source**:
- Garak (vulnerability scanner)
- LLMFuzzer (API fuzzing)
- Adversarial Robustness Toolbox
- Plexiglass, PurpleLlama

#### 📄 Research Papers (2023-2026)
- "The Attacker Moves Second" (2025)
- "Agents Rule of Two" (Meta)
- "Prompt Injection Attacks" comprehensive review
- Microsoft research papers
- Academic conference papers

#### 💻 Secure Coding Practices
- Python examples (input validation, output sanitization)
- JavaScript/Node.js examples
- Framework-specific (Django, Express.js)
- API authorization patterns
- Monitoring and detection

#### 🎓 Training Platforms
- PortSwigger Web Security Academy
- HackTheBox
- TryHackMe
- SANS courses
- DEF CON AI Village

#### 💰 Bug Bounty Programs
- OpenAI ($10k-$20k range)
- GitHub ($5k-$15k range)
- Microsoft ($500-$15k+)
- Google, Meta, Anthropic
- Submission templates

**Use when**:
- Researching CVEs
- Selecting testing tools
- Implementing defenses
- Bug bounty hunting
- Academic research

---

## Learning Paths

### 🎯 Beginner (1-2 days)
**Goal**: Understand basics and complete labs

1. **Read**: Quick Start Guide (30 min)
2. **Practice**: Lab 1 - Excessive Agency (15 min)
3. **Practice**: Lab 2 - LLM API Vulnerabilities (15 min)
4. **Read**: OWASP LLM Top 10 overview in Resources (30 min)
5. **Practice**: Lab 3 - Indirect Injection (20 min)
6. **Practice**: Lab 4 - Insecure Output Handling (20 min)
7. **Review**: Complete Labs Guide for deeper understanding (2 hours)

**Outcome**: Can identify and exploit basic Web LLM vulnerabilities

---

### 🔥 Intermediate (1 week)
**Goal**: Master all techniques and variations

**Week Plan**:
- **Day 1**: Complete all 4 labs twice (practice)
- **Day 2**: Study Complete Labs Guide in detail
- **Day 3**: Review CVEs in Resources file
- **Day 4**: Practice bypass techniques from Cheat Sheet
- **Day 5**: Set up testing tools (Garak, LLMFuzzer)
- **Day 6**: Study research papers
- **Day 7**: Attempt bug bounty submissions

**Outcome**: Can find and exploit Web LLM vulnerabilities in real applications

---

### 🚀 Advanced (1 month)
**Goal**: Become expert-level practitioner

**Month Plan**:

**Week 1**: Mastery
- Complete labs 5+ times each
- Time yourself (target: all 4 in 30 minutes)
- Try every payload variation
- Document your own techniques

**Week 2**: Research
- Read all papers in Resources
- Study latest CVEs
- Join OWASP working group
- Follow security researchers

**Week 3**: Tools & Automation
- Set up all testing tools
- Create custom scripts
- Build payload generator
- Configure monitoring/detection

**Week 4**: Real-World Practice
- Bug bounty hunting
- Responsible disclosure
- Write blog posts
- Present findings

**Outcome**: Expert-level Web LLM security researcher

---

## Usage Scenarios

### Scenario 1: Taking BSCP Exam
**Files to use**:
1. Quick Start Guide (memorize speed runs)
2. Cheat Sheet (quick payload reference)

**Preparation**:
- Complete each lab 5+ times
- Practice until all 4 labs done in <45 min
- Memorize key payloads
- Know troubleshooting steps

---

### Scenario 2: Bug Bounty Hunting
**Files to use**:
1. Resources (find programs accepting LLM vulns)
2. Complete Labs Guide (understand exploitation)
3. Cheat Sheet (payload variations)

**Approach**:
1. Target selection from Resources
2. Use 60-second check from Quick Start
3. Deep exploitation with Complete Labs Guide
4. Submit using templates in Resources

---

### Scenario 3: Security Assessment
**Files to use**:
1. Quick Start Guide (rapid testing)
2. Resources (detection signatures for client)
3. Complete Labs Guide (detailed findings)

**Workflow**:
1. Quick vulnerability scan
2. Deep exploitation if found
3. Document with examples from Labs Guide
4. Provide prevention controls from Resources

---

### Scenario 4: Implementing Defenses
**Files to use**:
1. Resources (secure coding practices)
2. Cheat Sheet (prevention controls)
3. Complete Labs Guide (understand attacks)

**Implementation**:
1. Review OWASP standards in Resources
2. Copy secure code examples
3. Configure monitoring (detection signatures)
4. Test with payloads from Cheat Sheet

---

### Scenario 5: Research & Learning
**Files to use**:
1. Complete Labs Guide (theory)
2. Resources (papers, CVEs)
3. Cheat Sheet (techniques)

**Learning Path**:
1. Read Labs Guide cover-to-cover
2. Study papers in Resources
3. Practice with Cheat Sheet payloads
4. Experiment with tools from Resources

---

## Quick Reference Matrix

### Finding Information Fast

| I need to... | File | Section |
|--------------|------|---------|
| Complete a lab quickly | Quick Start | Lab Speed Run Guide |
| Find a specific payload | Cheat Sheet | Common Payloads Library |
| Understand a vulnerability | Complete Labs | Lab 1-4 sections |
| Research a CVE | Resources | CVE Examples |
| Set up testing tools | Resources | Testing Tools |
| Implement defenses | Resources | Secure Coding Practices |
| Learn OWASP standards | Resources | OWASP Documentation |
| Configure Burp Suite | Quick Start | Burp Suite Quick Config |
| Troubleshoot lab | Quick Start | Troubleshooting Decision Tree |
| Find bug bounty programs | Resources | Bug Bounty Programs |

---

### Payload Quick Finder

| Attack Type | File | Section |
|-------------|------|---------|
| API Enumeration | Cheat Sheet | API Enumeration |
| SQL Injection via LLM | Cheat Sheet | SQL Injection via LLM |
| Command Injection via LLM | Cheat Sheet | OS Command Injection |
| Direct Prompt Injection | Cheat Sheet | Prompt Injection Payloads |
| Indirect Injection | Cheat Sheet | Indirect Prompt Injection |
| XSS via LLM Output | Cheat Sheet | XSS via Insecure Output |
| Bypass Techniques | Cheat Sheet | Bypass Techniques |

---

## Skill Progression Checklist

### ✅ Beginner
- [ ] Understand what Web LLM attacks are
- [ ] Complete Lab 1 (Excessive Agency)
- [ ] Complete Lab 2 (LLM API Vulnerabilities)
- [ ] Complete Lab 3 (Indirect Injection)
- [ ] Complete Lab 4 (Insecure Output Handling)
- [ ] Read OWASP LLM Top 10 overview

### ✅ Intermediate
- [ ] Complete all labs 3+ times each
- [ ] Understand all attack techniques
- [ ] Can explain indirect injection
- [ ] Know common bypass methods
- [ ] Read 5+ CVEs in detail
- [ ] Set up at least one testing tool
- [ ] Configure Burp Suite properly

### ✅ Advanced
- [ ] Complete all labs in <45 minutes total
- [ ] Create custom payloads
- [ ] Found vulnerability in bug bounty
- [ ] Read latest research papers
- [ ] Implemented secure coding practices
- [ ] Can teach others
- [ ] Contributing to community

---

## Additional Resources

### 📖 Related Documentation in This Repo
- SQL Injection: `reference/sql-injection.md`
- XSS: `reference/cross-site-scripting.md`
- Command Injection: `reference/os-command-injection-portswigger-labs-complete.md`
- API Security: `reference/api-testing-comprehensive-guide.md`

### 🌐 External Links
- PortSwigger Labs: https://portswigger.net/web-security/llm-attacks
- OWASP LLM Top 10: https://genai.owasp.org/llmrisk/
- OWASP Agentic Apps: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

### 👥 Community
- Twitter: @simonw, @llm_sec
- Reddit: r/LLMSecurity
- Discord: AI Village
- GitHub: awesome-llm-security

---

## Document Statistics

| File | Lines | Words | Focus |
|------|-------|-------|-------|
| Quick Start | 1,000+ | 12,000+ | Speed & efficiency |
| Cheat Sheet | 1,200+ | 15,000+ | Payloads & commands |
| Complete Labs | 1,800+ | 28,000+ | Detailed exploitation |
| Resources | 2,000+ | 30,000+ | Reference material |
| **TOTAL** | **6,000+** | **85,000+** | **Complete mastery** |

---

## Version History

**Version 1.0** (2026-01-11)
- Initial release
- 4 PortSwigger labs covered
- OWASP LLM Top 10 2025 integrated
- OWASP Agentic Apps 2026 added
- 10+ CVEs documented
- 25+ tools catalogued
- 50+ research papers referenced

---

## Feedback & Contributions

This documentation is part of the pentest skill for Claude agents.

**Found an error?** Update the relevant file.
**New technique discovered?** Add to Cheat Sheet.
**Latest CVE?** Document in Resources.

---

## Quick Start

**Right now, do this**:

1. **Want to complete labs fast?**
   ```
   Open: web-llm-attacks-quickstart.md
   Go to: Lab Speed Run Guide
   ```

2. **Need a payload?**
   ```
   Open: web-llm-attacks-cheat-sheet.md
   Search: Your attack type
   ```

3. **Learning from scratch?**
   ```
   Open: web-llm-attacks-portswigger-labs-complete.md
   Read: Overview section
   Start: Lab 1
   ```

4. **Researching a CVE?**
   ```
   Open: web-llm-attacks-resources.md
   Go to: CVE Examples section
   ```

---

**Last Updated**: 2026-01-11
**Maintained by**: Claude Agent Skill System
**License**: Educational use for security research and authorized testing only
