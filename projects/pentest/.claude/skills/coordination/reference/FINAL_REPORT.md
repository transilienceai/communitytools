# Final Pentest Report Format

**Source**: `reports/pentest-report-source.md` + `data/pentest-report.json`
**Output**: `reports/Penetration-Test-Report.pdf` (required, Transilience branded)

## Generation — Transilience Branded PDF

After aggregating validated findings into `data/pentest-report.json` and writing the markdown source to `reports/pentest-report-source.md`, generate the final PDF report using the **transilience-report-style** skill.

### Step 1: Prepare report data

The orchestrator writes `data/pentest-report.json` (see JSON Export section below) containing all validated findings with severity, CVSS, CWE, OWASP mapping, PoC status, and remediation.

### Step 2: Generate branded PDF

Use the `/transilience-report-style` skill to generate the PDF. Provide:
- The `data/pentest-report.json` as the data source
- The `reports/pentest-report-source.md` as supplementary content (executive summary, methodology, scope)
- Transilience logo: `.claude/skills/transilience-report-style/transilience-logo.png`
- Client logo: provide if available, or omit

```
Generate a Transilience branded PDF penetration test report.

Data source: outputs/data/pentest-report.json
Supplementary content: outputs/reports/pentest-report-source.md
Transilience logo: .claude/skills/transilience-report-style/transilience-logo.png
Output: outputs/reports/Penetration-Test-Report.pdf

Report type: Penetration Test Report (not threat intelligence)
Map findings to advisory cards by severity.
Include: executive summary with severity metrics, findings grouped by severity (CRITICAL → HIGH → MEDIUM → LOW → INFO), remediation roadmap, methodology, OWASP/CWE mapping.
```

### Step 3: Adapt the design system for pentest reports

The transilience-report-style skill is designed for threat intelligence reports. When generating a pentest report, adapt the section blueprint:

| Threat Intel Section | Pentest Adaptation |
|---------------------|-------------------|
| 01 Executive Summary | Executive Summary — severity counts, risk rating, priority recommendations |
| 02 Threat Landscape Overview | Findings Overview — by category (Injection, Auth, Config, etc.) + OWASP mapping |
| 03 Threat Radar | Attack Surface Radar — plot findings by attack surface sector + severity ring |
| 04-06 Severity Advisories | Finding Cards — grouped CRITICAL → HIGH → MEDIUM, each finding as an advisory card |
| 07 Attack Surface Analysis | Scope & Infrastructure — tested systems, open ports, tech stack |
| 08 Asset Inventory | Not applicable (omit or replace with tested endpoints inventory) |
| 09 Technology Stack | Technology Stack — detected frameworks, servers, libraries |
| 10 Security Posture | Security Posture — positive controls observed + overall rating |
| 11 Strategic Recommendations | Remediation Roadmap — Immediate/Short/Medium-term phased actions |
| 12 Methodology & Data Sources | Methodology — PTES, OWASP WSTG, tools used, testing phases |

### Finding → Advisory Card Mapping

Each validated finding maps to an advisory card. **Every card MUST include its own Remediation & Suggestions section** — readers should not need to cross-reference a separate section to understand how to fix a finding.

| Finding Field | Card Element |
|--------------|-------------|
| `title` | Card title |
| `severity` | AccentBar color + SeverityBadge |
| `cvss_score` | Severity score bar (normalize: score/10) |
| `cwe` + `owasp` | TECHNICAL DETAILS section |
| `affected_url` | Metadata row (Surface field) |
| `description` (from description.md) | Summary text |
| `poc` steps | TECHNICAL DETAILS body |
| `impact` | IMPACT CONTEXT section |
| `remediation` | **REMEDIATION** section (per-card, see below) |
| `suggestions` | **SUGGESTIONS** section (per-card, see below) |
| `poc_verified` | Status in metadata row ("VERIFIED" / "UNVERIFIED") |
| Evidence files | DETECTION EVIDENCE section |

### Per-Finding Remediation & Suggestions (MANDATORY)

Each advisory card includes two additional sections after IMPACT CONTEXT:

**REMEDIATION** (header color: `AE` emerald green `#10B981`) — Concrete fix for this specific finding:
- Priority timeline (Immediate / Short-term / Medium-term)
- Before/After code example showing the vulnerable pattern and the secure replacement
- Specific configuration changes, patches, or library upgrades needed
- Relevant security standard references (CWE fix, OWASP recommendation)

**SUGGESTIONS** (header color: `AB` blue `#3B82F6`) — Broader defensive improvements related to this finding class:
- Architectural improvements (e.g., "implement parameterized queries across all data access layers")
- Defense-in-depth measures (WAF rules, input validation, output encoding)
- Testing recommendations (e.g., "add SAST rules for CWE-89", "include in regression test suite")
- Monitoring/detection guidance (e.g., "alert on SQL syntax in user input fields")

**Card layout update** (extends Section 7.1 of the design system):

| # | Section | Spacing After |
|---|---|---|
| 1-7 | (same as base design) | (same) |
| 7b | DETECTION EVIDENCE | 6pt gap |
| 7c | **REMEDIATION** (emerald header) — priority, code fix, config changes | 4pt per item + 6pt gap |
| 7d | **SUGGESTIONS** (blue header) — defense-in-depth, testing, monitoring | 4pt per item + 6pt gap |
| 8-10 | (same as base design) | (same) |

### Severity → Score Mapping for ScoreRow

| CVSS Range | Severity Score | Priority Score |
|-----------|---------------|---------------|
| 9.0-10.0 (CRITICAL) | 0.95 | 0.95 |
| 7.0-8.9 (HIGH) | 0.75 | 0.75 |
| 4.0-6.9 (MEDIUM) | 0.50 | 0.50 |
| 0.1-3.9 (LOW) | 0.25 | 0.25 |
| 0.0 (INFO) | 0.10 | 0.10 |

Set relevance score to 1.0 for all pentest findings (all are directly relevant to the target).

## Template System

The `reference.docx` provides:
- **Paragraph styles**: Title (28pt navy), Heading 1 (18pt navy, bottom border), Heading 2 (14pt blue), Heading 3 (12pt gray), Normal (11pt Calibri)
- **Code blocks**: 10pt Consolas on #F5F5F5 background
- **Page setup**: 1" margins, "CONFIDENTIAL" header, page number footer
- **Severity character styles**: Severity-Critical (#C00000), Severity-High (#ED7D31), Severity-Medium (#BF8F00), Severity-Low (#548235), Severity-Info (#808080)

The post-processor adds:
- Navy header rows on all tables (white bold text)
- Alternating row shading (#F2F6FA)
- Thin gray borders (#D0D0D0)
- Automatic severity keyword coloring in cells and paragraphs

To regenerate the template: `python3 tools/generate_reference_docx.py`

## Report Structure

The markdown source follows a **summary-first** structure. Executives read Parts I-II; technical staff read Part III; remediation teams read Part IV.

```markdown
---
title: "Penetration Test Report"
subtitle: "{Target} Security Assessment"
date: "{Month Year}"
version: "1.0"
---

\newpage

# Part I -- Summary & Overview

## Cover Page

| Field | Value |
|-------|-------|
| **Client** | {Organization Name} |
| **Assessment Period** | {Start Date} -- {End Date} |
| **Report Date** | {Publication Date} |
| **Report Version** | 1.0 |
| **Classification** | CONFIDENTIAL |
| **Prepared By** | {Team/Firm} |
| **Prepared For** | {Client Contact, Title} |

\newpage

## Executive Summary

{2 pages maximum. Written for C-level executives and board members.}

### Assessment Overview

{1-2 paragraphs: what was tested, why, and overall result.}

### Key Findings

{3-5 most critical findings with one-line business impact each.}

| # | Finding | Severity | Business Impact |
|---|---------|----------|-----------------|
| 1 | {Title} | CRITICAL | {Impact} |
| 2 | {Title} | HIGH | {Impact} |
| 3 | {Title} | HIGH | {Impact} |

### Overall Risk Rating

**Security Posture: {CRITICAL / HIGH / MEDIUM / LOW}**

{1-2 sentences on overall risk and urgency.}

### Priority Recommendations

1. **Immediate** (0-7 days): {Action}
2. **Short-term** (7-30 days): {Action}
3. **Long-term** (30-90 days): {Action}

\newpage

## Findings Dashboard

### Severity Summary

| Severity | Count | Percentage |
|----------|-------|------------|
| CRITICAL | {n} | {%} |
| HIGH | {n} | {%} |
| MEDIUM | {n} | {%} |
| LOW | {n} | {%} |
| INFORMATIONAL | {n} | {%} |
| **TOTAL** | **{n}** | **100%** |

### Findings by Category

| Category | Critical | High | Medium | Low | Info | Total |
|----------|----------|------|--------|-----|------|-------|
| Injection | {n} | {n} | {n} | {n} | {n} | {n} |
| Authentication | {n} | {n} | {n} | {n} | {n} | {n} |
| Authorization | {n} | {n} | {n} | {n} | {n} | {n} |
| Configuration | {n} | {n} | {n} | {n} | {n} | {n} |
| Cryptography | {n} | {n} | {n} | {n} | {n} | {n} |
| **TOTAL** | **{n}** | **{n}** | **{n}** | **{n}** | **{n}** | **{n}** |

### OWASP Top 10 Mapping

| OWASP Category | Findings | Severity |
|----------------|----------|----------|
| A01: Broken Access Control | {n} | {highest} |
| A02: Cryptographic Failures | {n} | {highest} |
| A03: Injection | {n} | {highest} |
| A04: Insecure Design | {n} | {highest} |
| A05: Security Misconfiguration | {n} | {highest} |
| A06: Vulnerable Components | {n} | {highest} |
| A07: Authentication Failures | {n} | {highest} |
| A08: Software & Data Integrity | {n} | {highest} |
| A09: Logging Failures | {n} | {highest} |
| A10: SSRF | {n} | {highest} |

### Findings Index

| ID | Title | Severity | CVSS | OWASP | CWE |
|----|-------|----------|------|-------|-----|
| F-001 | {Title} | CRITICAL | 9.8 | A03 | CWE-89 |
| F-002 | {Title} | HIGH | 8.1 | A01 | CWE-79 |
| ... | ... | ... | ... | ... | ... |

\newpage

# Part II -- Scope & Methodology

## Scope of Assessment

### In-Scope Systems

| System/Application | Description | URL/IP | Testing Type |
|-------------------|-------------|--------|--------------|
| {App 1} | {Desc} | {URL} | External Black Box |
| {App 2} | {Desc} | {URL} | Internal Gray Box |

### Out-of-Scope

- {Excluded system/network} -- {Reason}
- Denial of Service attacks
- Physical security testing

### Testing Constraints

- Testing window: {dates and hours}
- Access level: {Black Box / Gray Box / White Box}
- Limitations: {Any access restrictions, network issues}

\newpage

## Methodology

### Testing Standards

- **PTES** (Penetration Testing Execution Standard) -- 7-phase lifecycle
- **OWASP WSTG** v4.2 -- Web Security Testing Guide
- **NIST SP 800-115** -- Technical Guide to Information Security Testing

### Testing Phases

1. **Reconnaissance** -- OSINT, DNS enumeration, technology fingerprinting, attack surface mapping
2. **Vulnerability Assessment** -- Automated scanning, manual OWASP Top 10 testing, configuration review
3. **Exploitation** -- PoC development, privilege escalation, lateral movement
4. **Post-Exploitation** -- Impact assessment, data access verification
5. **Reporting** -- Finding documentation, risk assessment, remediation planning

### CVSS v3.1 Rating System

| Rating | CVSS Score | Description |
|--------|------------|-------------|
| CRITICAL | 9.0 -- 10.0 | Immediate exploitation possible, severe business impact |
| HIGH | 7.0 -- 8.9 | Exploitation likely, significant impact |
| MEDIUM | 4.0 -- 6.9 | Exploitation possible under certain conditions |
| LOW | 0.1 -- 3.9 | Exploitation difficult, limited impact |
| INFORMATIONAL | 0.0 | No direct security impact, best practice recommendation |

## Infrastructure Overview

### Technology Stack

| Component | Technology | Version | Notes |
|-----------|------------|---------|-------|
| Frontend | {tech} | {ver} | {notes} |
| Backend | {tech} | {ver} | {notes} |
| Database | {tech} | {ver} | {notes} |
| Web Server | {tech} | {ver} | {notes} |
| CDN/WAF | {tech} | {ver} | {notes} |

### Open Ports & Services

| Port | Service | Version | State |
|------|---------|---------|-------|
| 80 | HTTP | {ver} | Open |
| 443 | HTTPS | {ver} | Open |
| ... | ... | ... | ... |

### SSL/TLS Configuration

- Protocol versions: {TLS 1.2, 1.3}
- Certificate: {Issuer, expiry}
- Key findings: {Weak ciphers, HSTS missing, etc.}

\newpage

# Part III -- Detailed Findings

{Findings grouped by severity: CRITICAL, then HIGH, then MEDIUM, then LOW, then INFORMATIONAL.}

## Critical Findings

### Finding F-001: {Vulnerability Title}

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **CVSS v3.1** | 9.8 -- `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-89 (SQL Injection) |
| **OWASP** | A03:2021 -- Injection |
| **Location** | `https://target.com/search?q=` |

#### Description

{Detailed technical explanation of the vulnerability and its root cause.}

#### Proof of Concept

**Step 1**: {Action}

```http
GET /search?q=test' UNION SELECT NULL,database(),NULL-- HTTP/1.1
Host: target.com
```

**Response**:
```
{Relevant response excerpt showing exploitation}
```

**Automated PoC**: See `reports/appendix/finding-001/poc.py`

#### Impact

- **Confidentiality**: HIGH -- {Specific data exposed}
- **Integrity**: HIGH -- {What can be modified}
- **Availability**: MEDIUM -- {Service disruption potential}
- **Business Impact**: {Regulatory violations, financial loss, reputational damage}

#### Remediation

**Priority**: Immediate (0-7 days)

**Before** (vulnerable):
```python
query = "SELECT * FROM products WHERE name = '" + user_input + "'"
```

**After** (secure):
```python
query = "SELECT * FROM products WHERE name = ?"
cursor.execute(query, (user_input,))
```

**Additional measures**: {WAF rules, input validation, code review}

#### Evidence

- `reports/appendix/finding-001/screenshot-exploit.png`
- `reports/appendix/finding-001/http-request.txt`
- `reports/appendix/finding-001/poc.py`

---

{Repeat for each Critical finding, then High, Medium, Low, Informational.}

## High Findings

### Finding F-002: {Title}

{Same table + section structure as above.}

## Medium Findings

### Finding F-003: {Title}

{Same structure.}

## Low Findings

### Finding F-004: {Title}

{Same structure.}

## Informational Findings

### Finding F-005: {Title}

{Same structure.}

\newpage

# Part IV -- Remediation & Controls

## Positive Security Controls

{Acknowledge what the organization does well. Examples:}

- Strong TLS configuration with HSTS enforcement
- Multi-factor authentication on admin interfaces
- Regular patching cadence for infrastructure
- {Other positive controls observed}

## Remediation Roadmap

### Phase 1: Immediate (0-7 days)

| Finding | Action | Owner | Effort |
|---------|--------|-------|--------|
| F-001 | Implement parameterized queries | Dev Team | 4h |
| F-002 | {Action} | {Owner} | {Effort} |

### Phase 2: Short-Term (7-30 days)

| Finding | Action | Owner | Effort |
|---------|--------|-------|--------|
| F-003 | {Action} | {Owner} | {Effort} |
| F-004 | {Action} | {Owner} | {Effort} |

### Phase 3: Medium-Term (30-90 days)

| Finding | Action | Owner | Effort |
|---------|--------|-------|--------|
| F-005 | {Action} | {Owner} | {Effort} |

### Phase 4: Ongoing

- Regular penetration testing (quarterly recommended)
- Security awareness training
- Vulnerability management program
- {Additional long-term recommendations}

### Retest Recommendations

- Critical/High findings: retest after 30 days
- Medium findings: retest after 60 days
- Full reassessment: recommended after 90 days

\newpage

# Part V -- Appendices

## Finding Cross-Reference Table

| ID | Title | Severity | CVSS | CWE | OWASP | Status |
|----|-------|----------|------|-----|-------|--------|
| F-001 | {Title} | CRITICAL | 9.8 | CWE-89 | A03 | Open |
| ... | ... | ... | ... | ... | ... | ... |

## Compliance Mapping

{Include only if relevant to the engagement.}

| Finding | PCI DSS | HIPAA | GDPR | ISO 27001 |
|---------|---------|-------|------|-----------|
| F-001 | 6.5.1 | 164.308 | Art. 32 | A.14.2 |
| ... | ... | ... | ... | ... |

## Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| Burp Suite Professional | {ver} | Web application testing |
| Nmap | {ver} | Port scanning and service detection |
| Playwright | {ver} | Browser automation and evidence capture |
| {Tool} | {ver} | {Purpose} |

## Glossary

| Term | Definition |
|------|-----------|
| CVSS | Common Vulnerability Scoring System |
| CWE | Common Weakness Enumeration |
| OWASP | Open Web Application Security Project |
| PTES | Penetration Testing Execution Standard |
| PoC | Proof of Concept |
| SSRF | Server-Side Request Forgery |
| SQLi | SQL Injection |
| XSS | Cross-Site Scripting |

## Evidence References

Evidence files are organized per finding in the appendix directory:

```
reports/appendix/
├── finding-001/
│   ├── screenshot-exploit.png
│   ├── http-request.txt
│   └── poc.py
├── finding-002/
│   └── ...
```

**Reconnaissance data**: `data/reconnaissance/` (JSON)
**Machine-readable report**: `data/pentest-report.json`
**Activity logs**: `logs/` (NDJSON)

---

**Generated**: {timestamp} | **By**: Claude Code Pentester
```

## JSON Export

Alongside the PDF report, generate `data/pentest-report.json`:

```json
{
  "engagement": {
    "name": "{name}",
    "target": "{target}",
    "dates": "{start} to {end}",
    "status": "complete"
  },
  "findings": [
    {
      "id": "F-001",
      "title": "{title}",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "affected_url": "{url}",
      "description": "{Detailed technical explanation of the vulnerability}",
      "impact": {
        "confidentiality": "HIGH",
        "integrity": "HIGH",
        "availability": "MEDIUM",
        "business_impact": "{Regulatory violations, financial loss, reputational damage}"
      },
      "poc_verified": true,
      "poc_steps": [
        "Navigate to {url}",
        "Enter payload: {payload}",
        "Observe: {result}"
      ],
      "remediation": {
        "priority": "Immediate (0-7 days)",
        "fix_description": "{Specific fix: implement parameterized queries}",
        "vulnerable_code": "{Before code example}",
        "secure_code": "{After code example}",
        "references": ["CWE-89", "OWASP A03:2021"]
      },
      "suggestions": [
        "{Implement parameterized queries across all data access layers}",
        "{Deploy WAF rules to detect SQL injection patterns}",
        "{Add SAST rules for CWE-89 to CI/CD pipeline}",
        "{Enable query logging and alert on SQL syntax in user input}"
      ],
      "remediation_status": "open"
    }
  ],
  "statistics": {
    "total": "{n}",
    "critical": "{n}",
    "high": "{n}",
    "medium": "{n}",
    "low": "{n}",
    "informational": "{n}"
  }
}
```

## Severity Calibration (MANDATORY)

CVSS base scores provide initial severity, but the final report severity MUST be adjusted for environmental context. Do NOT blindly use the base CVSS score — consider mitigating and aggravating factors.

### Mitigating factors that REDUCE severity
- **Missing HSTS but HTTP port closed**: if port 80 is not open/reachable, the SSL stripping attack vector is reduced (downgrade from High to Medium)
- **Information disclosure behind authentication**: if disclosed info requires valid credentials to access, severity is lower than unauthenticated disclosure
- **Vulnerability blocked by another control**: e.g., SQLi exists but WAF blocks exploitation in practice (note: still a finding, but lower effective severity)
- **Internal-only exposure**: if the vulnerable endpoint is IP-restricted or VPN-only, the attack surface is reduced

### Aggravating factors that INCREASE severity
- **Financial/payment context**: input validation bypass on monetary fields is higher severity than on non-financial fields
- **PII/sensitive data involved**: cache-control missing on responses containing card numbers or personal data is higher than on public content
- **Chained impact**: a "Low" info disclosure that enables a "High" attack chain should be documented with the chain impact
- **Regulatory requirements**: findings that cause compliance failures (PCI DSS, HIPAA, GDPR) may warrant severity increase

### Practical guidelines
- Always explain the severity rationale in the finding description — why this score, what factors were considered
- If a finding's practical risk differs from the CVSS base score, state both: "CVSS Base: 6.5 (Medium) — Adjusted: Medium due to [mitigating factor]" or "CVSS Base: 5.3 — Adjusted: High in this context due to [aggravating factor]"
- Never inflate severity to pad findings count — this damages report credibility
- Never deflate severity to minimize apparent risk — this fails the client

## Rules

1. **No emoji** in the markdown source -- use text severity labels (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)
2. **Summary first** -- executives should not scroll past page 5 to find the risk picture
3. **Finding metadata in tables** -- not bullet lists; tables render cleanly in DOCX
4. **`\newpage`** between major parts (I, II, III, IV, V)
5. **Source file**: `reports/pentest-report-source.md` (not `intermediate-reports/`)
6. **Evidence paths**: always relative to engagement root (`reports/appendix/finding-{id}/`)
7. **Deliverables**: `reports/Penetration-Test-Report.pdf` (required, Transilience branded), `data/pentest-report.json`
8. **PDF generation**: always use the `transilience-report-style` skill — do NOT generate DOCX or use pandoc
