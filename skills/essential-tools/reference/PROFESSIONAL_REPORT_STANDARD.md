# Professional Penetration Testing Report Standard

**Industry-standard finding quality requirements following PTES, OWASP, and SANS guidelines.**

> For report structure, document layout, and DOCX generation, see the coordination skill: `coordination/reference/FINAL_REPORT.md`.
> This document covers **finding quality**, **pre-delivery checks**, **compliance mapping**, and **references**.

---

## 1. Finding Quality Requirements

Every finding in the report MUST include all sections below. Incomplete findings are not acceptable for delivery.

### 1.1 Finding Header (Metadata Table)

```markdown
### Finding F-{NNN}: {Vulnerability Title}

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL |
| **CVSS v3.1** | {score} -- `CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_` |
| **CWE** | CWE-{ID} ({Name}) |
| **OWASP** | A{NN}:2021 -- {Category Name} |
| **MITRE ATT&CK** | T{NNNN} ({Technique Name}) |
| **Location** | `{URL/endpoint/system}` |
```

**CVSS Vector Components** (all required):
- **AV** (Attack Vector): Network / Adjacent / Local / Physical
- **AC** (Attack Complexity): Low / High
- **PR** (Privileges Required): None / Low / High
- **UI** (User Interaction): None / Required
- **S** (Scope): Unchanged / Changed
- **C** (Confidentiality Impact): None / Low / High
- **I** (Integrity Impact): None / Low / High
- **A** (Availability Impact): None / Low / High

### 1.2 Technical Description

- Root cause explanation (why the vulnerability exists)
- Affected code pattern or configuration (if visible)
- Attack type classification
- Authentication requirements

### 1.3 Proof of Concept

**Requirements**:
- Step-by-step reproduction instructions (numbered)
- Full HTTP requests and relevant response excerpts
- Automated PoC script (Python preferred) in `reports/appendix/finding-{id}/poc.py`
- PoC execution output in `reports/appendix/finding-{id}/poc_output.txt`
- PoC MUST be verified (tested and confirmed working)

**PoC Script Template**:
```python
#!/usr/bin/env python3
"""
PoC for {Vulnerability Title}
Finding ID: F-{NNN}
CVSS: {score} ({severity})
"""
import requests
import sys

def exploit(target: str) -> bool:
    print(f"[*] Testing {target}")
    # ... exploitation logic ...
    if vulnerable:
        print("[+] VULNERABLE: {description}")
        return True
    print("[-] Not vulnerable")
    return False

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://target.com"
    sys.exit(0 if exploit(target) else 1)
```

### 1.4 Impact Analysis

- **Confidentiality**: HIGH / MEDIUM / LOW -- {specific data at risk}
- **Integrity**: HIGH / MEDIUM / LOW -- {what can be modified}
- **Availability**: HIGH / MEDIUM / LOW -- {service disruption potential}
- **Business Impact**: {regulatory violations, financial loss, reputational damage}

**Attack Scenarios** (at least one):
1. {Scenario}: {Actor} exploits {vulnerability} to {action}, resulting in {impact}

### 1.5 Remediation

**Priority**: Immediate / Short-term / Medium-term / Long-term

**Code fix** (when applicable):

```python
# Before (vulnerable)
{vulnerable code}

# After (secure)
{fixed code}
```

**Additional measures**:
- {WAF rules, configuration changes, architecture improvements}
- {Monitoring and detection recommendations}

**Validation steps**:
1. Apply fix
2. Re-test with original PoC
3. Attempt bypass techniques
4. Regression test functionality

### 1.6 Evidence

Every finding must have supporting evidence in `reports/appendix/finding-{id}/`:
- Screenshots (annotated, highlighting the vulnerability)
- HTTP request/response captures
- PoC script and output
- Video recording (for complex multi-step exploits)

---

## 2. Quality Checklist

Run this checklist before report delivery:

- [ ] Every finding has a unique ID (F-NNN)
- [ ] Every finding has correct CVSS v3.1 score AND full vector string
- [ ] Every finding has CWE and OWASP Top 10 mapping
- [ ] Every finding has a verified, working PoC script
- [ ] Every finding has visual evidence (screenshots or video)
- [ ] Every finding has specific, actionable remediation with code examples
- [ ] Every finding has business impact analysis
- [ ] Executive summary is 2 pages maximum
- [ ] No emoji in the markdown source (text labels only)
- [ ] Severity labels use exact terms: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
- [ ] Finding metadata uses tables (not bullet lists)
- [ ] All evidence paths are correct and files exist
- [ ] Sensitive data is redacted where appropriate
- [ ] Report has been proofread for accuracy and consistency
- [ ] DOCX generated with `--reference-doc` and post-processed

---

## 3. Compliance Mapping Reference

When the engagement scope includes compliance requirements, map findings to relevant frameworks.

### PCI DSS v4.0

| Requirement | Description | Common Finding Types |
|-------------|-------------|---------------------|
| 6.2 | Protect from known vulnerabilities | Unpatched software, outdated components |
| 6.5.1 | Injection flaws | SQL injection, command injection |
| 6.5.4 | Insecure direct object references | IDOR, broken access control |
| 6.5.7 | Cross-site scripting | Reflected, stored, DOM XSS |
| 6.5.10 | Broken authentication | Weak passwords, session issues |
| 8.2 | User identification | Default credentials, weak auth |
| 11.3 | Penetration testing | Overall assessment findings |

### HIPAA

| Section | Description | Common Finding Types |
|---------|-------------|---------------------|
| 164.308(a)(1) | Security management | Risk assessment gaps |
| 164.308(a)(5) | Security awareness | Training gaps, phishing |
| 164.312(a)(1) | Access control | Authorization bypass |
| 164.312(e)(1) | Transmission security | Weak TLS, missing encryption |

### GDPR

| Article | Description | Common Finding Types |
|---------|-------------|---------------------|
| Art. 25 | Data protection by design | Insecure architecture |
| Art. 32 | Security of processing | Encryption, access control gaps |
| Art. 33 | Breach notification | Logging and monitoring gaps |

---

## 4. Industry References

- **PTES** (Penetration Testing Execution Standard): http://www.pentest-standard.org/
- **OWASP WSTG** v4.2: https://owasp.org/www-project-web-security-testing-guide/
- **OWASP OPTRS**: https://owasp.org/www-project-penetration-test-reporting-standard/
- **SANS Penetration Testing**: https://www.sans.org/white-papers/33343
- **NIST SP 800-115**: https://csrc.nist.gov/publications/detail/sp/800-115/final
- **CVSS v3.1 Calculator**: https://www.first.org/cvss/calculator/3.1
- **CWE List**: https://cwe.mitre.org/data/definitions/
- **MITRE ATT&CK**: https://attack.mitre.org/

---

**Version**: 2.0
**Last Updated**: 2026-02-20
**Status**: Production Standard
