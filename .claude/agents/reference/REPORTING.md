# Professional Report Generation

Guide for generating industry-standard penetration testing reports.

## Required Deliverables

### 1. Executive Report (`reports/executive-summary.md`)

**Audience**: C-level, Board, Management
**Length**: 1-2 pages MAXIMUM
**Focus**: Business impact, strategic recommendations

**Sections**:
- Cover page (engagement details, date, classification)
- Executive summary (2-3 paragraphs max)
- Key findings (bullet list, severity counts)
- Business impact (financial, operational, reputational)
- Strategic recommendations (high-level)

**Template**: See `.claude/skills/pentest/attacks/essential-skills/reporting/PROFESSIONAL_REPORT_STANDARD.md`

### 2. Technical Report (`reports/technical-report.md`)

**Audience**: Security teams, Developers
**Length**: Comprehensive (no limit)
**Focus**: Technical details, remediation, PoCs

**Sections**:
- Scope and methodology
- Executive summary
- Findings summary (table format)
- Detailed findings (each with CVSS, CWE, PoC)
- Exploit chains
- Remediation roadmap (P0: 0-7d, P1: 7-30d, P2: 30-60d, P3: 60-90d)
- Appendices (tools, standards, references)

**Template**: See `.claude/skills/pentest/attacks/essential-skills/reporting/PROFESSIONAL_REPORT_STANDARD.md`

### 3. JSON Output (`findings/findings.json`)

**Purpose**: Machine-readable for automation

**Schema**:
```json
{
  "engagement": {
    "name": "Example Corp Web App Test",
    "date": "2025-01-16",
    "scope": ["https://example.com", "https://api.example.com"],
    "tester": "Pentester Orchestrator"
  },
  "summary": {
    "total_findings": 15,
    "critical": 3,
    "high": 5,
    "medium": 4,
    "low": 2,
    "informational": 1
  },
  "findings": [
    {
      "id": "finding-001",
      "title": "SQL Injection in search parameter",
      "severity": "Critical",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cwe": "CWE-89",
      "owasp": "A03:2021 - Injection",
      "location": {...},
      "evidence": {...},
      "poc": {...},
      "remediation": {...}
    }
  ]
}
```

## Report Generation Workflow

```
1. Collect all verified findings from agents
    ↓
2. Validate PoCs (check poc_output.txt exists and shows success)
    ↓
3. Deduplicate findings (same vuln + location = duplicate)
    ↓
4. Identify exploit chains
    ↓
5. Calculate metrics (severity counts, OWASP categories)
    ↓
6. Generate findings.json
    ↓
7. Generate executive report (use metrics)
    ↓
8. Generate technical report (use detailed findings)
    ↓
9. Validate all reports follow standards
```

## Metrics Calculation

**From findings.json**:
```python
total_findings = len(findings)
critical = len([f for f in findings if f['severity'] == 'Critical'])
high = len([f for f in findings if f['severity'] == 'High'])
medium = len([f for f in findings if f['severity'] == 'Medium'])
low = len([f for f in findings if f['severity'] == 'Low'])

owasp_categories = count_by_owasp(findings)
cwe_breakdown = count_by_cwe(findings)
```

## Remediation Timeline

**Priority-based**:
- **P0 (Critical)**: 0-7 days - Immediate action required
- **P1 (High)**: 7-30 days - Priority fix
- **P2 (Medium)**: 30-60 days - Scheduled fix
- **P3 (Low)**: 60-90 days - Future improvement

Include in technical report as Gantt chart or table.

## Industry Standards Mapping

All findings must map to:
- **OWASP Top 10** (2021)
- **CWE** (Common Weakness Enumeration)
- **CVSS v3.1** (severity scoring)
- **MITRE ATT&CK** (tactics and techniques)
- **NIST** (SP 800-115, Cybersecurity Framework)

## Validation Checklist

Before finalizing reports:

- [ ] All findings have verified PoCs
- [ ] All CVSS scores calculated accurately
- [ ] Remediation timeline provided
- [ ] Business impact clearly explained
- [ ] All sensitive data redacted
- [ ] Executive report is 1-2 pages max
- [ ] Technical report includes all required sections
- [ ] JSON output validates against schema
- [ ] All references to industry standards included
- [ ] Report follows professional standard template

## Complete Template

See: `.claude/skills/pentest/attacks/essential-skills/reporting/PROFESSIONAL_REPORT_STANDARD.md`

This file contains:
- Executive report template
- Technical report template
- Finding template
- Examples
- Best practices
