# Bug Bounty Hunting Skill

**Skill Name**: `bugbounty`
**Domain**: Bug Bounty Programs, Responsible Disclosure, HackerOne Platform
**Purpose**: Provide specialized knowledge for successful bug bounty hunting including program selection, report quality, and platform-specific best practices

---

## Skill Overview

This skill provides comprehensive guidance for bug bounty hunting activities across platforms like HackerOne, Bugcrowd, Intigriti, and others. It covers program selection strategies, vulnerability research techniques, report writing best practices, and responsible disclosure procedures.

## When to Use This Skill

Invoke this skill when:
- 🎯 Selecting bug bounty programs to target
- 📝 Writing vulnerability reports for submission
- 🏆 Optimizing for bounty payouts
- 🤝 Collaborating with security teams
- ⚖️ Understanding disclosure policies and timelines
- 🚫 Avoiding common pitfalls and rejection reasons
- 💰 Negotiating bounty amounts
- 📊 Tracking and managing multiple programs

## Core Concepts

### 1. Bug Bounty Program Types

#### Public Programs
**Characteristics**:
- Open to all researchers
- Higher competition
- Faster payouts (usually)
- More documentation available
- Disclosed reports for learning

**Pros**: Easy to start, learn from others' reports
**Cons**: Higher competition, lower chances of unique finds

#### Private Programs
**Characteristics**:
- Invitation-only
- Lower competition
- Often higher bounties
- Direct communication with security team
- Less public information

**Pros**: Higher success rate, better bounties
**Cons**: Need reputation/invitation to access

#### Vulnerability Disclosure Programs (VDP)
**Characteristics**:
- No monetary rewards
- Recognition only
- Good for building reputation
- Often precursor to paid programs

**Pros**: Build reputation, practice reporting
**Cons**: No financial compensation

### 2. Program Selection Strategy

#### High-Value Indicators
✅ **New Programs** (< 30 days old)
- Lower competition
- More low-hanging fruit
- Eager security teams
- Higher chances of critical findings

✅ **Fast Response Times**
- First response: < 4 hours
- Triage: < 1 day
- Bounty: < 1 week
- Resolution: < 2 weeks

✅ **High Bounty Ranges**
- Critical: $5,000+
- High: $1,000+
- Medium: $500+
- Good signal of program maturity

✅ **Large Attack Surface**
- Multiple domains/subdomains
- Multiple APIs
- Mobile applications
- Cloud infrastructure

✅ **Technology Complexity**
- Modern frameworks (GraphQL, gRPC)
- Microservices architecture
- Cloud-native applications
- Real-time features (WebSockets)

#### Red Flags (Avoid These Programs)
❌ **Poor Response Times**
- First response: > 1 week
- Triage: > 1 month
- Bounties delayed/unpaid

❌ **Low Bounty Ranges**
- Critical: < $500
- High: < $100
- Signals low program budget/commitment

❌ **Overly Restrictive Scope**
- Very limited in-scope assets
- Many vulnerability types out of scope
- Extensive testing restrictions

❌ **Poor Security Team Interaction**
- Unprofessional communication
- Frequent report rejections
- Low disclosure rates

❌ **Known Issues**
- Search for program name + "bug bounty issues"
- Check researcher forums/Twitter
- Look for complaint patterns

### 3. Vulnerability Research Methodology

#### The Bug Bounty Mindset

**Think Like an Attacker**:
1. What's the business impact of this app?
2. What data is most valuable?
3. Where do users interact with sensitive operations?
4. What would an attacker want to achieve?

**Focus on High-Impact Areas**:
- Authentication & authorization
- Payment/financial operations
- Admin panels & privileged functions
- User data access
- API endpoints
- File upload functionality

#### Vulnerability Prioritization for Bug Bounties

**Critical/High Priorities** (Best ROI):
1. **Authentication Bypass** - Direct account takeover
2. **SQL Injection** - Database access, data theft
3. **RCE (Remote Code Execution)** - Server compromise
4. **SSRF to Cloud Metadata** - Credential theft
5. **Insecure Deserialization** - RCE potential
6. **JWT Vulnerabilities** - Authentication bypass
7. **IDOR (Insecure Direct Object References)** - Data access
8. **Stored XSS in Admin Panel** - Admin compromise

**Medium Priorities** (Good ROI):
1. **Reflected XSS** - User compromise
2. **CSRF on Sensitive Operations** - Unauthorized actions
3. **Privilege Escalation** - Vertical/horizontal
4. **Open Redirects** (if chained with OAuth)
5. **CORS Misconfiguration** - Data exfiltration
6. **GraphQL Introspection + IDOR**

**Low Priorities** (Low ROI, often rejected):
1. Self XSS
2. Clickjacking on non-sensitive pages
3. Missing security headers (without PoC)
4. SSL/TLS configuration issues
5. SPF/DMARC/DKIM issues
6. Rate limiting (unless leading to account takeover)

### 4. Report Quality Framework

#### The Perfect Bug Bounty Report Structure

**1. Executive Summary** (2-3 sentences)
```markdown
## Summary
SQL Injection vulnerability in the search endpoint allows unauthenticated attackers to extract sensitive data from the database, including user credentials and payment information.
```

**2. Severity Assessment** (CVSS + Business Impact)
```markdown
## Severity Assessment
**CVSS Score**: 9.8 (Critical)
**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

**Business Impact**:
- Confidentiality: Full database access (user data, payment info)
- Integrity: Ability to modify records (price manipulation)
- Availability: Potential for complete database deletion
```

**3. Vulnerability Details** (Technical depth)
```markdown
## Vulnerability Details
**Type**: SQL Injection (CWE-89)
**Location**: https://example.com/search
**Parameter**: `q` (GET)
**Database**: MySQL 8.0.25

### Root Cause Analysis
The application constructs SQL queries using string concatenation without proper sanitization...
```

**4. Proof of Concept** (Crystal clear reproduction)
```markdown
## Steps to Reproduce
1. Navigate to https://example.com/search
2. Enter the following payload in the search box:
   ```
   ' UNION SELECT username,password,email FROM users--
   ```
3. Submit the search
4. Observe database records in the response

### Proof of Concept Request
[Include full HTTP request]

### Proof of Concept Response
[Include relevant response excerpt]
```

**5. Visual Evidence** (Screenshots/video)
- Screenshot of the vulnerable page
- Screenshot of payload injection
- Screenshot of successful exploitation
- Video demonstration (for complex exploits)

**6. Impact Demonstration** (Realistic attack scenario)
```markdown
## Impact
An attacker can exploit this vulnerability to:
1. Extract all user credentials from the database
2. Access payment information
3. Modify product prices
4. Gain administrative access by stealing admin credentials

### Realistic Attack Scenario
1. Attacker discovers SQL injection via automated scanning
2. Attacker extracts admin username and password hash
3. Attacker cracks password offline (weak hashing detected)
4. Attacker logs in as administrator
5. Complete system compromise achieved
```

**7. Remediation** (Actionable guidance)
```markdown
## Remediation
### Immediate Actions
1. Deploy parameterized queries (prepared statements)
2. Implement input validation with whitelist approach
3. Apply principle of least privilege to database user

### Long-term Improvements
1. Implement Web Application Firewall (WAF)
2. Regular security code reviews
3. Automated SAST/DAST in CI/CD pipeline
```

**8. References** (Industry standards)
- OWASP guidelines
- CWE references
- Security research papers
- Similar vulnerabilities (if applicable)

#### Report Quality Checklist

**Before Submitting**:
- ✅ Clear, concise title (under 100 characters)
- ✅ Executive summary (2-3 sentences)
- ✅ Accurate severity assessment (CVSS score)
- ✅ Step-by-step reproduction instructions
- ✅ Proof of concept included (requests/responses)
- ✅ Visual evidence (screenshots or video)
- ✅ Impact analysis (business + technical)
- ✅ Remediation recommendations
- ✅ No real sensitive data included (sanitize!)
- ✅ Grammar and spelling checked
- ✅ Professional tone throughout
- ✅ References to industry standards

### 5. Common Rejection Reasons & How to Avoid

#### Rejection Reason #1: "Out of Scope"
**Why**: Testing was performed on excluded assets or vulnerability types

**How to Avoid**:
- ✅ Read program policy thoroughly before testing
- ✅ Double-check asset is in-scope
- ✅ Verify vulnerability type is eligible
- ✅ Check severity caps for specific assets

#### Rejection Reason #2: "Duplicate"
**Why**: Vulnerability already reported by another researcher

**How to Avoid**:
- ✅ Search disclosed reports before testing
- ✅ Check if vulnerability was recently patched
- ✅ Test on latest version of application
- ✅ Submit quickly after finding (don't sit on findings)

#### Rejection Reason #3: "Insufficient Impact"
**Why**: Vulnerability exists but has no realistic security impact

**How to Avoid**:
- ✅ Demonstrate realistic attack scenario
- ✅ Show business impact, not just technical issue
- ✅ Chain vulnerabilities for greater impact
- ✅ Provide evidence of exploitability

#### Rejection Reason #4: "Cannot Reproduce"
**Why**: Steps to reproduce are unclear or incomplete

**How to Avoid**:
- ✅ Provide exact, step-by-step instructions
- ✅ Include full HTTP requests/responses
- ✅ Test reproduction steps yourself before submitting
- ✅ Include environment details (browser, OS, etc.)
- ✅ Provide video demonstration for complex issues

#### Rejection Reason #5: "Informational"
**Why**: Finding is a configuration issue, not exploitable vulnerability

**How to Avoid**:
- ✅ Demonstrate actual exploitation, not just detection
- ✅ Show how finding leads to security compromise
- ✅ Provide proof of concept that achieves impact
- ✅ Avoid submitting "missing security headers" without demonstrated XSS

#### Rejection Reason #6: "Known Issue"
**Why**: Program team is already aware of the vulnerability

**How to Avoid**:
- ✅ Check program's "known issues" section
- ✅ Ask program team if unsure before extensive testing
- ✅ Monitor program updates and patch notes

### 6. Bounty Optimization Strategies

#### Maximizing Bounty Amounts

**Strategy 1: Vulnerability Chaining**
Combine multiple vulnerabilities for greater impact:
- CSRF + XSS = Account takeover
- SSRF + Cloud metadata = Credential theft
- IDOR + Business logic flaw = Financial fraud
- Open redirect + OAuth = Authentication bypass

**Example**:
```
Individual bounties:
- CSRF: $500
- XSS: $300

Chained exploitation (account takeover): $3,000
```

**Strategy 2: Demonstrate Maximum Impact**
Don't stop at proof of concept - show full impact:
- SQL Injection: Don't just show error - extract data
- XSS: Don't just alert() - show session theft
- SSRF: Don't just access localhost - show cloud credential theft

**Strategy 3: Multiple Vulnerable Instances**
If same vulnerability exists across multiple assets:
- Document all instances
- Calculate cumulative impact
- Request bounty adjustment for severity

**Strategy 4: Quality Over Quantity**
Submit fewer, high-quality reports rather than many low-quality:
- 1 Critical finding: $5,000+
- 10 Low findings: $500 total (and reputation damage)

**Strategy 5: Timing**
- Submit findings as soon as validated (race against duplicates)
- Target new programs (less competition)
- Monitor for program updates (new features = new bugs)

#### Negotiating Bounties

**When to Negotiate**:
- ✅ Impact is significantly higher than initial assessment
- ✅ Multiple instances found (cumulative risk)
- ✅ Chained vulnerabilities (greater impact)
- ✅ Extensive remediation required
- ✅ Critical business function affected

**How to Negotiate**:
1. **Be Professional**: Respectful, data-driven approach
2. **Provide Evidence**: Demonstrate greater impact
3. **Reference Precedent**: Point to similar bounties
4. **Be Flexible**: Accept reasonable counter-offers
5. **Build Relationships**: Long-term reputation matters

**Example Negotiation**:
```
Subject: Bounty Adjustment Request - Report #H1_12345678

Hi Security Team,

Thank you for triaging report #H1_12345678 (SQL Injection).

I'd like to request a bounty adjustment based on the following:

1. Impact Severity: The vulnerability allows full database access,
   including payment information (PCI-DSC scope), significantly
   higher than typical SQL injection findings.

2. Multiple Instances: The same vulnerability pattern exists across
   3 other endpoints (detailed in updated report), indicating a
   systemic issue requiring extensive remediation.

3. Business Impact: Exploitation could lead to significant financial
   and reputational damage, as well as regulatory compliance issues.

4. Comparable Bounties: Similar findings on your program have been
   awarded $8,000-$10,000 (Report #H1_87654321).

Based on these factors, I believe a bounty of $8,500 would be
appropriate. I'm open to discussing this further.

Best regards,
[Your Name]
```

### 7. Platform-Specific Guidelines

#### HackerOne Best Practices

**Reputation Building**:
- Signal: 0-100+ (quality indicator)
- Impact: 0-10,000+ (total bounties earned)
- Reputation affects private program invitations

**Disclosure**:
- Limited disclosure after 30 days (default)
- Full disclosure after fix + 30 days
- Respect program's disclosure preferences

**Communication**:
- Professional at all times
- Respond promptly to questions
- Provide additional PoC if requested
- Accept rejection gracefully (build long-term relationship)

**Metrics**:
- Time to first response (affects Signal)
- Report quality (affects Signal)
- Invalid report ratio (hurts Signal)
- Duplicate ratio (hurts Signal)

#### Bugcrowd Best Practices

**Kudos System**:
- Earn kudos for quality reports
- Kudos unlock private programs
- Kudos reflect researcher skill

**Submission Guidelines**:
- Use Bugcrowd VRT (Vulnerability Rating Taxonomy)
- Clear priority classification (P1-P5)
- Detailed technical analysis

#### Intigriti Best Practices

**Tipping**:
- Additional rewards for exceptional reports
- High-quality PoC
- Novel exploitation techniques

**Community**:
- Active Discord community
- Researcher collaboration
- Learning resources

### 8. Responsible Disclosure Principles

#### Core Tenets

**1. Minimize Harm**
- Stop at proof of concept
- Don't access more data than necessary
- Don't pivot to production systems unnecessarily
- Avoid service disruption

**2. Respect Privacy**
- Sanitize all evidence (remove real user data)
- Don't share findings publicly before fix
- Handle discovered data responsibly

**3. Coordinate Disclosure**
- Give reasonable time to fix (30-90 days standard)
- Negotiate disclosure timeline if needed
- Respect program's disclosure policy

**4. Professional Communication**
- Maintain professional tone
- No threats or ultimatums
- Constructive feedback on security posture
- Acknowledge program team efforts

#### Disclosure Timeline

**Standard Timeline**:
- Day 0: Vulnerability discovered and reported
- Day 0-7: Initial triage and confirmation
- Day 7-30: Patch development and testing
- Day 30-60: Patch deployment
- Day 60+: Public disclosure (if appropriate)

**Coordinated Disclosure**:
- Negotiate timeline with security team
- Consider complexity of fix
- Balance transparency with security risk
- Respect confidentiality agreements

### 9. Multi-Program Management

#### Tracking Multiple Programs

**Recommended Tools**:
- Spreadsheet: Track programs, assets, findings
- Burp Suite: Organize testing projects
- Note-taking: Obsidian, Notion, OneNote
- Time tracking: Monitor ROI per program

**Program Tracking Template**:
```
| Program | Assets | Tested | Findings | Submitted | Bounty | ROI |
|---------|--------|--------|----------|-----------|--------|-----|
| TechCorp| 12     | 12     | 5        | 5         | $8,500 | 2.1 |
| Finance | 8      | 6      | 2        | 2         | $2,000 | 0.8 |
```

**Prioritization**:
- High ROI programs (more testing)
- New programs (early opportunity)
- Programs nearing payout (complete testing)
- Programs with pending reports (follow up)

### 10. Continuous Learning

#### Staying Updated

**Follow Top Researchers**:
- HackerOne leaderboard
- Twitter/X security community
- YouTube pentest channels
- Blog posts and write-ups

**Study Disclosed Reports**:
- HackerOne Hacktivity
- Bugcrowd researcher resources
- Public vulnerability databases

**Practice Platforms**:
- PortSwigger Web Security Academy
- HackTheBox
- PentesterLab
- OWASP WebGoat

**Community Engagement**:
- Security conferences (DEF CON, Black Hat)
- Bug bounty forums
- Discord/Slack communities
- Local security meetups

## Common Pitfalls to Avoid

### Technical Pitfalls

❌ **Testing Without Authorization**
- Always confirm scope before testing
- Verify asset ownership
- Check for explicit authorization

❌ **Causing Service Disruption**
- Respect rate limits
- Avoid resource exhaustion
- No destructive testing

❌ **Over-Exploitation**
- Stop at proof of concept
- Don't extract excessive data
- Don't pivot unnecessarily

### Report Pitfalls

❌ **Poor Report Quality**
- Vague descriptions
- Missing reproduction steps
- No proof of concept
- Unclear impact

❌ **Unprofessional Communication**
- Demanding high bounties
- Threatening public disclosure
- Rude or aggressive tone

❌ **Rushing Submissions**
- Not validating findings
- Incomplete testing
- Copy-paste errors
- Typos and grammatical errors

### Business Pitfalls

❌ **Ignoring Program Rules**
- Testing out-of-scope assets
- Violating rate limits
- Public disclosure before resolution

❌ **Poor Time Management**
- Spending too long on low-value programs
- Not tracking ROI
- Chasing duplicates

❌ **Reputation Damage**
- High invalid report rate
- Frequent duplicates
- Unprofessional behavior

## Success Metrics

### Individual Report Success
✅ **High Quality**: Signal boost, team praise
✅ **Fast Triage**: < 24 hours
✅ **Fair Bounty**: Matches or exceeds expectation
✅ **Positive Collaboration**: Good team relationship

### Program Success
✅ **High ROI**: Bounty earned vs. time invested
✅ **Multiple Findings**: Consistent discovery rate
✅ **Fast Payouts**: Quick bounty awards
✅ **Invitation to Private Programs**: Reputation growth

### Career Success
✅ **Growing Reputation**: Signal/Kudos increasing
✅ **Higher Bounties**: Average bounty trending up
✅ **Private Invitations**: Access to better programs
✅ **Community Recognition**: Respected in community

## Resources

### Essential Reading
- OWASP Web Security Testing Guide
- PortSwigger Web Security Academy
- HackerOne Resources (Hacktivity, Blog)
- Bug Bounty Hunting Essentials (book)

### Tools
- Burp Suite Professional
- OWASP ZAP
- Nuclei (vulnerability scanner)
- ffuf (fuzzing)
- sqlmap (SQL injection)

### Communities
- HackerOne Discord
- Bugcrowd Forum
- Twitter/X #bugbounty
- Reddit r/bugbounty

---

**Remember**: Bug bounty hunting is a marathon, not a sprint. Focus on quality over quantity, build strong relationships with security teams, and continuously improve your skills. Success comes from consistent, professional, high-quality work combined with strategic program selection and efficient time management.
