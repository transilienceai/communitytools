# Report Templates

Standard formats for executive and technical reports.

## Executive Summary Template

```markdown
# Executive Summary: [Target]

**Assessment Date**: YYYY-MM-DD
**Skill**: skill-name
**Target**: target-name

---

## Overview

[2-3 sentence summary of assessment and key findings]

---

## Findings Summary

| Severity | Count | Examples |
|----------|-------|----------|
| Critical | N | Vulnerability 1, Vulnerability 2 |
| High | N | Vulnerability 3, Vulnerability 4 |
| Medium | N | Vulnerability 5, Vulnerability 6 |
| Low | N | Vulnerability 7 |
| **Total** | **N** | |

---

## Business Impact

### Critical Risks

1. **[Finding Title]** - [One sentence impact]
2. **[Finding Title]** - [One sentence impact]

### Recommended Priorities

1. [Action] - Critical/High severity
2. [Action] - High severity
3. [Action] - Medium severity

---

## Next Steps

1. Review detailed technical report
2. Prioritize remediation by severity
3. Validate fixes after implementation

---

*Full details in technical-report.md*
```

## Technical Report Template

```markdown
# Technical Security Assessment: [Target]

**Assessment Date**: YYYY-MM-DD
**Duration**: N hours
**Skill**: skill-name
**Agent(s)**: agent-name(s)
**Target**: target-name

---

## Assessment Summary

[Paragraph describing scope, methodology, and key findings]

---

## Findings Overview

### By Severity

- **Critical**: N findings
- **High**: N findings
- **Medium**: N findings
- **Low**: N findings
- **Total**: N findings

### By Category

- **Injection**: N findings
- **Authentication**: N findings
- **Authorization**: N findings
- [etc.]

---

## Detailed Findings

### Finding 001: [Title] [Severity]

**Location**: https://example.com/path
**CVSS**: X.X (Vector)
**CWE**: CWE-XX
**OWASP**: AXX:2021

**Description**:
[Technical description]

**Reproduction**:
1. Step 1
2. Step 2

**Evidence**:
- Screenshot: [path]
- Video: [path]

**Impact**:
[Technical and business impact]

**Remediation**:
[Specific fix with code example]

**References**:
- [Link 1]
- [Link 2]

---

[Repeat for each finding]

---

## Testing Coverage

**Scope**:
- Parameters tested: N
- Endpoints tested: N
- Authentication states: N

**Methodology**:
- Framework: OWASP WSTG, PTES
- Tools: [List]
- Duration: N hours

**Out of Scope**:
- [Item 1]
- [Item 2]

---

## Recommendations

### Immediate Actions (24-48 hours)

1. [Action for critical/high findings]
2. [Action for critical/high findings]

### Short-Term (1-2 weeks)

1. [Mitigation action]
2. [Configuration change]

### Long-Term (Next quarter)

1. [Architecture change]
2. [Process improvement]

---

## Conclusion

[Summary paragraph with overall security posture assessment]

---

## Appendices

### A. Evidence Files

[List of all evidence with paths]

### B. Tool Outputs

[Location of raw tool outputs]

### C. References

[List of all external references]

---

*Assessment conducted by [skill-name] | Report version: 2.0*
```
