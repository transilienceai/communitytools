# Report Generation Standards for Pentest Agents

**MANDATORY**: Every specialized pentest agent MUST generate detailed reports during testing and save them to an organized folder structure.

## Quick Reference

**Directory Structure**:
```
findings/
├── TESTING_PROCESS.md          # Overview of all testing done
├── EXPERIMENTATION_LOG.md      # Detailed log of all experiments
├── HYPOTHESES_AND_RESULTS.md   # All hypotheses tested with results
├── METHODOLOGY.md               # Testing methodology used
├── summary/
│   ├── findings-summary.md      # Executive summary of all findings
│   └── statistics.md             # Statistics and metrics
├── finding-001/
│   ├── report.md
│   ├── poc.py
│   ├── poc_output.txt
│   ├── workflow.md
│   └── description.md
├── finding-002/
│   └── [same structure]
└── evidence/
    ├── screenshots/
    ├── http-captures/
    └── videos/
```

## CRITICAL REQUIREMENT

Every agent execution MUST produce these files in the findings directory:

1. **TESTING_PROCESS.md** - High-level overview of testing phases
2. **EXPERIMENTATION_LOG.md** - Detailed log of every test attempted
3. **HYPOTHESES_AND_RESULTS.md** - All hypotheses with pass/fail results
4. **METHODOLOGY.md** - Structured methodology applied
5. **summary/findings-summary.md** - Executive summary of findings
6. **summary/statistics.md** - Test statistics and metrics

Plus individual vulnerability folders with PoCs and reports.

---

## 1. TESTING_PROCESS.md

**Purpose**: High-level overview of what was tested and when.

**Template**:
```markdown
# Testing Process Overview

## Executive Summary
- **Agent**: [Agent Name]
- **Target**: [Target URL/System]
- **Testing Date**: [Date Range]
- **Total Tests**: [Number]
- **Vulnerabilities Found**: [Number with severity breakdown]
- **Duration**: [Approximate time]

## Testing Phases

### Phase 1: Reconnaissance
**Objective**: Identify attack surface

**Actions Performed**:
- [Action 1]
- [Action 2]
- [Action 3]

**Key Findings**:
- Attack surface identified: [Description]
- Entry points discovered: [Number and types]
- Technologies identified: [Stack info]

**Time**: [Duration]

### Phase 2: Hypothesis Generation
**Objective**: Predict potential vulnerabilities based on tech stack

**Hypotheses Formed**:
1. [Hypothesis 1] - Based on [evidence]
2. [Hypothesis 2] - Based on [evidence]
3. [Hypothesis 3] - Based on [evidence]

**Total Hypotheses**: [Count]

**Time**: [Duration]

### Phase 3: Experimentation
**Objective**: Test each hypothesis with targeted payloads

**Payloads Tested**: [Count]
**Techniques Tried**: [Count]
**Attack Vectors**: [Count]

**Successful Experiments**: [Count]
**Failed Experiments**: [Count]

**Time**: [Duration]

### Phase 4: Verification
**Objective**: Confirm findings with PoC and evidence

**Vulnerabilities Verified**: [Count]
**PoC Scripts Created**: [Count]
**Screenshots Captured**: [Count]
**HTTP Captures**: [Count]

**Time**: [Duration]

### Phase 5: Documentation
**Objective**: Create professional reports and evidence

**Reports Generated**:
- Executive summary ✓
- Technical analysis ✓
- PoC scripts ✓
- Workflows ✓

**Time**: [Duration]

## Overall Statistics

| Metric | Value |
|--------|-------|
| Total Testing Time | [Duration] |
| Tests Executed | [Count] |
| Hypotheses Tested | [Count] |
| Success Rate | [Percentage] |
| Findings | [Count] |
| Critical/High | [Count] |
| Medium | [Count] |
| Low/Info | [Count] |

## Key Achievements

1. [Finding 1] - CVSS [Score]
2. [Finding 2] - CVSS [Score]
3. [Finding 3] - CVSS [Score]

## Recommendations

**Immediate Actions** (0-24 hours):
- [Action 1]
- [Action 2]

**Short-term** (1-7 days):
- [Action 1]
- [Action 2]

**Long-term** (30+ days):
- [Action 1]
- [Action 2]

---
```

## 2. EXPERIMENTATION_LOG.md

**Purpose**: Detailed record of every test performed, what was tried, and the result.

**Template**:
```markdown
# Experimentation Log

**Agent**: [Agent Name]
**Target**: [Target]
**Start Time**: [Timestamp]
**End Time**: [Timestamp]

---

## Experiment 001: [Test Name]

**Time**: [Timestamp]
**Hypothesis**: [What we're testing]
**Attack Vector**: [Where we're testing]
**Payload/Technique**: [What we used]

**Expected Behavior**: [What should happen if vulnerable]
**Actual Behavior**: [What actually happened]

**Result**: ✓ SUCCESS / ✗ FAILED / ⚠ PARTIAL

**Evidence**:
- Screenshot: [filename or N/A]
- HTTP Request/Response: [filename or N/A]
- Error Messages: [Details if any]

**Analysis**: [Why it succeeded/failed]

**Next Steps**: [What to try next]

---

## Experiment 002: [Test Name]
[Same structure as above]

---

## Summary Statistics

| Category | Count |
|----------|-------|
| Total Experiments | [N] |
| Successful | [N] |
| Failed | [N] |
| Partial Success | [N] |
| Success Rate | [%] |

---
```

## 3. HYPOTHESES_AND_RESULTS.md

**Purpose**: Structured list of all hypotheses tested and their outcomes.

**Template**:
```markdown
# Hypotheses and Testing Results

## Overview
- **Total Hypotheses**: [Count]
- **Verified**: [Count with percentage]
- **Disproven**: [Count with percentage]
- **Partially Verified**: [Count with percentage]

---

## Hypothesis 001: [Hypothesis Title]

**Category**: [SQLi/XSS/SSRF/etc.]
**Severity (if exploited)**: CRITICAL/HIGH/MEDIUM/LOW

**Description**:
Detailed explanation of the hypothesis.

**Technical Basis**:
- Why we believe this vulnerability exists
- Based on [evidence]

**Testing Approach**:
1. Step 1: [Test description]
2. Step 2: [Test description]
3. Step 3: [Test description]

**Results**:
- [ ] **VERIFIED** - Finding-NNN created
- [ ] **DISPROVEN** - No vulnerability found
- [ ] **PARTIALLY VERIFIED** - Requires further investigation

**Evidence**:
- [Link to screenshots, HTTP captures, or PoC output]

**Analysis**:
[Detailed explanation of what we learned from this hypothesis test]

**Impact (if true)**:
- Confidentiality: [HIGH/MEDIUM/LOW]
- Integrity: [HIGH/MEDIUM/LOW]
- Availability: [HIGH/MEDIUM/LOW]

---

## Hypothesis 002: [Next Hypothesis]
[Same structure]

---

## Hypotheses Summary Table

| ID | Category | Result | CVSS | Finding |
|----|----------|--------|------|---------|
| H001 | SQLi | ✓ VERIFIED | 9.8 | F-001 |
| H002 | XSS | ✗ DISPROVEN | - | - |
| H003 | SSRF | ✓ VERIFIED | 8.6 | F-002 |
| H004 | Auth Bypass | ⚠ PARTIAL | - | Needs review |

---
```

## 4. METHODOLOGY.md

**Purpose**: Document the systematic approach used for testing.

**Template**:
```markdown
# Testing Methodology

## Framework Used

- **Primary**: [PTES / OWASP WSTG / MITRE ATT&CK / FHM / Custom]
- **Approach**: [Hypothesis-driven testing / Vulnerability-focused / etc.]

## Testing Phases

### 1. Reconnaissance (Passive & Active)

**Objective**: Identify attack surface and information gathering

**Techniques Used**:
- [ ] HTTP header analysis
- [ ] Technology fingerprinting
- [ ] Directory enumeration
- [ ] Parameter discovery
- [ ] Input vector identification

**Tools Used**:
- [Tool 1]
- [Tool 2]

**Duration**: [Time]

**Output**: [summary/findings from this phase]

### 2. Threat Modeling

**Objective**: Prioritize targets and predict vulnerabilities

**Approach**:
- Analyzed tech stack: [Technologies]
- Identified high-risk components: [Components]
- Mapped common vulnerabilities: [List]

**Priority Ranking**:
1. [Highest priority test]
2. [Second priority]
3. [Third priority]

### 3. Vulnerability Analysis

**Objective**: Systematically test for vulnerabilities

**Categories Tested**:
1. **Injection Attacks**
   - SQL Injection: [Methods]
   - Command Injection: [Methods]
   - Template Injection: [Methods]

2. **Client-Side Attacks**
   - XSS: [Methods]
   - CSRF: [Methods]
   - DOM-based: [Methods]

3. **Server-Side Attacks**
   - SSRF: [Methods]
   - Path Traversal: [Methods]
   - File Upload: [Methods]

4. **Authentication & Access Control**
   - Auth Bypass: [Methods]
   - JWT Attacks: [Methods]
   - Access Control: [Methods]

5. **API Security**
   - GraphQL: [Methods]
   - REST API: [Methods]
   - WebSockets: [Methods]

**Duration**: [Time]

### 4. Exploitation & Validation

**Objective**: Verify findings with working PoCs

**Verification Process**:
1. Develop PoC script
2. Test against target
3. Capture proof of execution
4. Document workflow
5. Create comprehensive report

**Duration**: [Time]

### 5. Post-Exploitation (if applicable)

**Objective**: Assess impact and demonstrate severity

**Actions Performed**:
- [Action 1]
- [Action 2]

**Data Accessed**: [Description]
**Impact Demonstrated**: [Description]

### 6. Documentation & Reporting

**Reports Generated**:
- [ ] TESTING_PROCESS.md
- [ ] EXPERIMENTATION_LOG.md
- [ ] HYPOTHESES_AND_RESULTS.md
- [ ] METHODOLOGY.md (this file)
- [ ] Executive summary
- [ ] Individual vulnerability reports
- [ ] PoC scripts and evidence

## Tools & Techniques

### Tools Used

| Tool | Purpose | Status |
|------|---------|--------|
| [Tool 1] | [Purpose] | ✓ Used |
| [Tool 2] | [Purpose] | ✓ Used |

### Payloads & Techniques

**SQL Injection**:
- Union-based: [Variants tested]
- Time-based blind: [Variants tested]
- Error-based: [Variants tested]

**XSS**:
- HTML context: [Payloads tested]
- JavaScript context: [Payloads tested]
- DOM-based: [Techniques tested]

**SSRF**:
- Internal network: [IPs tested]
- Localhost: [Ports tested]
- Cloud metadata: [Services tested]

## Metrics & Statistics

| Metric | Value |
|--------|-------|
| Total Tests Performed | [N] |
| Test Duration | [Time] |
| Vulnerabilities Found | [N] |
| False Positives | [N] |
| Testing Efficiency | [%] |

## Compliance & Standards

**Frameworks Followed**:
- OWASP Testing Guide v4.2
- PTES - 7-phase testing lifecycle
- CVSS v3.1 scoring

**Standards Applied**:
- CWE mapping: Applied to all findings
- CVSS scoring: Applied to all vulnerabilities
- OWASP Top 10: Categorized findings

## Limitations & Assumptions

**Assumptions Made**:
- [Assumption 1]
- [Assumption 2]

**Limitations**:
- [Limitation 1]
- [Limitation 2]

**Out of Scope**:
- [Item 1]
- [Item 2]

---
```

## 5. summary/findings-summary.md

**Purpose**: Executive summary of all findings discovered.

**Template**:
```markdown
# Findings Summary

**Generated**: [Date/Time]
**Agent**: [Agent Name]
**Target**: [Target]

## Overview

| Metric | Count |
|--------|-------|
| **Total Findings** | [N] |
| **Critical** | [N] |
| **High** | [N] |
| **Medium** | [N] |
| **Low** | [N] |
| **Info** | [N] |

## Risk Heat Map

```
CRITICAL: ■■■■■ [N findings]
HIGH:     ■■■■  [N findings]
MEDIUM:   ■■■   [N findings]
LOW:      ■■    [N findings]
INFO:     ■     [N findings]
```

## Key Findings (Top 5)

### 1. [Finding Title] - CRITICAL (CVSS 9.8)
- **ID**: finding-001
- **Category**: [SQLi/XSS/SSRF/etc.]
- **Impact**: [Description]
- **Remediation**: [Urgent action required]

### 2. [Finding Title] - HIGH (CVSS 8.6)
[Same structure]

### 3. [Finding Title] - HIGH (CVSS 7.5)
[Same structure]

### 4. [Finding Title] - MEDIUM (CVSS 6.1)
[Same structure]

### 5. [Finding Title] - MEDIUM (CVSS 5.3)
[Same structure]

## Findings by Category

### SQL Injection: [N findings]
- finding-001: Union-based SQLi
- finding-003: Time-based blind SQLi

### Cross-Site Scripting (XSS): [N findings]
- finding-004: Reflected XSS
- finding-005: Stored XSS

### Server-Side Request Forgery (SSRF): [N findings]
- finding-002: SSRF to internal service

[Continue for other categories]

## Findings by OWASP Top 10

- **A01: Broken Access Control**: [N findings]
- **A02: Cryptographic Failures**: [N findings]
- **A03: Injection**: [N findings]
- **A04: Insecure Design**: [N findings]
- **A05: Security Misconfiguration**: [N findings]
- **A06: Vulnerable Components**: [N findings]
- **A07: Authentication Failures**: [N findings]
- **A08: Data Integrity Failures**: [N findings]
- **A09: Logging Failures**: [N findings]
- **A10: SSRF**: [N findings]

## Complete Findings Index

| ID | Title | Category | CVSS | Status |
|----|-------|----------|------|--------|
| F-001 | [Title] | SQLi | 9.8 | ✓ Verified |
| F-002 | [Title] | SSRF | 8.6 | ✓ Verified |
| F-003 | [Title] | XSS | 7.5 | ✓ Verified |
[Continue for all findings]

## Business Impact Summary

**If All Critical/High Issues Exploited**:
- Data exposure risk: [Description]
- Compliance impact: [Description]
- Operational impact: [Description]
- Financial risk: [Estimated range]

## Remediation Priority

**Immediate (0-24 hours)**:
- F-001: [Quick fix required]
- F-002: [Urgent action]

**Short-term (1-7 days)**:
- F-003: [Fix within week]
- F-004: [Fix within week]

**Long-term (30+ days)**:
- F-005: [Architectural improvement]
- F-006: [Process change]

## Next Steps

1. Review findings with [Team]
2. Prioritize remediation efforts
3. Assign remediation tasks
4. Schedule follow-up testing
5. Implement security improvements

---

See individual finding reports in `/findings/finding-NNN/` for complete details, PoC scripts, and remediation guidance.
```

## 6. summary/statistics.md

**Purpose**: Detailed metrics and statistics from testing.

**Template**:
```markdown
# Testing Statistics

**Report Generated**: [Date/Time]
**Agent**: [Agent Name]
**Target**: [Target]

## Executive Metrics

| Metric | Value |
|--------|-------|
| Total Testing Time | [Duration] |
| Tests Performed | [Count] |
| Hypotheses Tested | [Count] |
| Success Rate | [Percentage] |
| Findings Discovered | [Count] |
| Verified Exploits | [Count] |
| PoC Scripts | [Count] |

## Severity Distribution

```
Critical:  ██████████ 3 (30%)
High:      ████████   2 (20%)
Medium:    ██████     2 (20%)
Low:       ████       2 (20%)
Info:      ██         1 (10%)
```

## Vulnerability Type Distribution

| Type | Count | Percentage |
|------|-------|-----------|
| SQL Injection | [N] | [%] |
| Cross-Site Scripting | [N] | [%] |
| Server-Side Request Forgery | [N] | [%] |
| Authentication Bypass | [N] | [%] |
| Information Disclosure | [N] | [%] |
| [Other Type] | [N] | [%] |

## OWASP Top 10 Coverage

| Category | Findings | Impact |
|----------|----------|--------|
| A01: Broken Access Control | [N] | HIGH |
| A02: Cryptographic Failures | [N] | MEDIUM |
| A03: Injection | [N] | CRITICAL |
| A04: Insecure Design | [N] | MEDIUM |
| A05: Security Misconfiguration | [N] | HIGH |
| A06: Vulnerable Components | [N] | MEDIUM |
| A07: Authentication Failures | [N] | HIGH |
| A08: Data Integrity Failures | [N] | MEDIUM |
| A09: Logging & Monitoring Failures | [N] | LOW |
| A10: SSRF | [N] | HIGH |

## CWE Distribution

| CWE | Title | Count |
|-----|-------|-------|
| CWE-89 | SQL Injection | [N] |
| CWE-79 | Cross-site Scripting | [N] |
| CWE-918 | SSRF | [N] |
[Continue for relevant CWEs]

## Testing Coverage by Category

### Input Validation
- Tests Performed: [N]
- Vulnerabilities Found: [N]
- Coverage: [Percentage]

### Authentication & Session Management
- Tests Performed: [N]
- Vulnerabilities Found: [N]
- Coverage: [Percentage]

### Access Control
- Tests Performed: [N]
- Vulnerabilities Found: [N]
- Coverage: [Percentage]

### Injection
- Tests Performed: [N]
- Vulnerabilities Found: [N]
- Coverage: [Percentage]

### Sensitive Data Protection
- Tests Performed: [N]
- Vulnerabilities Found: [N]
- Coverage: [Percentage]

## Time Allocation

| Phase | Time | Percentage |
|-------|------|-----------|
| Reconnaissance | [Time] | [%] |
| Hypothesis Generation | [Time] | [%] |
| Experimentation | [Time] | [%] |
| Verification | [Time] | [%] |
| Documentation | [Time] | [%] |
| **Total** | **[Time]** | **100%** |

## Payload Statistics

**SQL Injection Payloads Tested**: [N]
- Union-based: [N] tested, [N] successful
- Time-based: [N] tested, [N] successful
- Error-based: [N] tested, [N] successful
- Boolean-based: [N] tested, [N] successful

**XSS Payloads Tested**: [N]
- HTML Context: [N] tested, [N] successful
- JavaScript Context: [N] tested, [N] successful
- DOM-based: [N] tested, [N] successful
- Attribute Context: [N] tested, [N] successful

**SSRF Requests Tested**: [N]
- Internal IPs: [N] tested, [N] successful
- Localhost ports: [N] tested, [N] successful
- Cloud metadata: [N] tested, [N] successful
- Protocol schemes: [N] tested, [N] successful

## Hypothesis Verification Rate

| Category | Total | Verified | Rate |
|----------|-------|----------|------|
| SQL Injection | [N] | [N] | [%] |
| XSS | [N] | [N] | [%] |
| SSRF | [N] | [N] | [%] |
| Auth Bypass | [N] | [N] | [%] |
| Other | [N] | [N] | [%] |
| **Overall** | **[N]** | **[N]** | **[%]** |

## PoC Success Rate

| Type | Attempts | Success | Success Rate |
|------|----------|---------|--------------|
| SQL Injection PoCs | [N] | [N] | [%] |
| XSS PoCs | [N] | [N] | [%] |
| SSRF PoCs | [N] | [N] | [%] |
| Auth PoCs | [N] | [N] | [%] |
| **Total** | **[N]** | **[N]** | **[%]** |

## False Positive Rate

| Category | Reported | Verified | False Positives | Rate |
|----------|----------|----------|-----------------|------|
| SQL Injection | [N] | [N] | [N] | [%] |
| XSS | [N] | [N] | [N] | [%] |
| SSRF | [N] | [N] | [N] | [%] |
| **Total** | **[N]** | **[N]** | **[N]** | **[%]** |

## Key Metrics for Improvement

**Areas of Strength**:
1. [Strength 1] - [Metric/Data]
2. [Strength 2] - [Metric/Data]

**Areas for Improvement**:
1. [Area 1] - [Suggestion]
2. [Area 2] - [Suggestion]

---
```

## Implementation for Agent Developers

### Step 1: Initialize Reporting Structure

At the START of your agent execution, create the findings directory:

```python
import os
import json
from datetime import datetime

def initialize_reporting():
    """Create findings directory structure"""

    base_dir = "findings"
    os.makedirs(base_dir, exist_ok=True)
    os.makedirs(f"{base_dir}/summary", exist_ok=True)
    os.makedirs(f"{base_dir}/evidence/screenshots", exist_ok=True)
    os.makedirs(f"{base_dir}/evidence/http-captures", exist_ok=True)
    os.makedirs(f"{base_dir}/evidence/videos", exist_ok=True)

    # Initialize log files
    return {
        'start_time': datetime.now(),
        'experiments': [],
        'hypotheses': [],
        'findings': []
    }
```

### Step 2: Log All Experiments

After EACH test, log the experiment:

```python
def log_experiment(state, test_name, hypothesis, payload, result, evidence=None):
    """Log a single experiment"""

    experiment = {
        'timestamp': datetime.now().isoformat(),
        'test_name': test_name,
        'hypothesis': hypothesis,
        'payload': payload,
        'result': result,  # 'success', 'failed', 'partial'
        'evidence_files': evidence or []
    }

    state['experiments'].append(experiment)

    # Save immediately to avoid losing data
    with open('findings/EXPERIMENTATION_LOG.md', 'w') as f:
        f.write(generate_experimentation_log(state))
```

### Step 3: Record Hypotheses

Track each hypothesis and its result:

```python
def record_hypothesis(state, hypothesis_id, category, description, result, cvss=None, finding_id=None):
    """Record hypothesis test result"""

    hyp = {
        'id': hypothesis_id,
        'category': category,
        'description': description,
        'result': result,  # 'verified', 'disproven', 'partial'
        'cvss': cvss,
        'finding_id': finding_id
    }

    state['hypotheses'].append(hyp)

    # Update HYPOTHESES_AND_RESULTS.md
    with open('findings/HYPOTHESES_AND_RESULTS.md', 'w') as f:
        f.write(generate_hypotheses_report(state))
```

### Step 4: Generate Reports at Completion

When testing is complete:

```python
def generate_all_reports(state):
    """Generate all required reports"""

    # 1. Testing Process Overview
    with open('findings/TESTING_PROCESS.md', 'w') as f:
        f.write(generate_testing_process(state))

    # 2. Methodology Used
    with open('findings/METHODOLOGY.md', 'w') as f:
        f.write(generate_methodology(state))

    # 3. Findings Summary
    with open('findings/summary/findings-summary.md', 'w') as f:
        f.write(generate_findings_summary(state))

    # 4. Statistics
    with open('findings/summary/statistics.md', 'w') as f:
        f.write(generate_statistics(state))

    print("[+] All reports generated successfully")
    print(f"[+] Reports saved to: findings/")
```

---

## Agent Documentation Template Update

Add this section to EVERY specialized agent markdown file:

```markdown
## Report Generation

This agent generates comprehensive testing reports in the `findings/` directory:

### Generated Files

**Overview Documents**:
- `TESTING_PROCESS.md` - High-level overview of all testing phases
- `EXPERIMENTATION_LOG.md` - Detailed log of every test attempted
- `HYPOTHESES_AND_RESULTS.md` - All hypotheses with pass/fail results
- `METHODOLOGY.md` - Systematic methodology applied

**Summary Reports**:
- `summary/findings-summary.md` - Executive summary of all findings
- `summary/statistics.md` - Testing metrics and statistics

**Vulnerability Details**:
- `finding-NNN/report.md` - Comprehensive vulnerability report
- `finding-NNN/poc.py` - Verified, tested exploit script
- `finding-NNN/poc_output.txt` - Proof of successful execution
- `finding-NNN/workflow.md` - Manual exploitation steps
- `finding-NNN/description.md` - Technical attack details

**Evidence**:
- `evidence/screenshots/` - Screenshot evidence
- `evidence/http-captures/` - HTTP request/response pairs
- `evidence/videos/` - Video recordings of exploitation

### Directory Structure

```
findings/
├── TESTING_PROCESS.md
├── EXPERIMENTATION_LOG.md
├── HYPOTHESES_AND_RESULTS.md
├── METHODOLOGY.md
├── summary/
│   ├── findings-summary.md
│   └── statistics.md
├── finding-001/
│   ├── report.md
│   ├── poc.py
│   ├── poc_output.txt
│   ├── workflow.md
│   └── description.md
├── finding-002/
│   └── [same structure]
└── evidence/
    ├── screenshots/
    ├── http-captures/
    └── videos/
```
```

---

## Validation Checklist

Before completing an agent execution, verify:

- [ ] `findings/` directory created
- [ ] `TESTING_PROCESS.md` generated
- [ ] `EXPERIMENTATION_LOG.md` generated
- [ ] `HYPOTHESES_AND_RESULTS.md` generated
- [ ] `METHODOLOGY.md` generated
- [ ] `summary/findings-summary.md` generated
- [ ] `summary/statistics.md` generated
- [ ] All vulnerability finding folders created (finding-NNN)
- [ ] Each finding has `report.md`
- [ ] Each finding has `poc.py` (tested)
- [ ] Each finding has `poc_output.txt` (with proof)
- [ ] Each finding has `workflow.md`
- [ ] Each finding has `description.md`
- [ ] Evidence captured in `evidence/` subdirectories
- [ ] All reports are clean, organized, and professional

---

## Automation Scripts

Agents can use these helper functions to automate report generation:

```python
# Generate YAML frontmatter for finding report
def create_finding_folder(finding_id, title, cvss, cwe, owasp):
    """Create finding folder with standard structure"""
    path = f"findings/finding-{finding_id:03d}"
    os.makedirs(path, exist_ok=True)

    # Create metadata file
    metadata = {
        'id': finding_id,
        'title': title,
        'cvss': cvss,
        'cwe': cwe,
        'owasp': owasp,
        'created': datetime.now().isoformat()
    }

    with open(f"{path}/metadata.json", 'w') as f:
        json.dump(metadata, f, indent=2)

    return path

# Copy evidence files
def add_evidence(finding_id, evidence_type, filepath):
    """Add evidence file to finding"""
    import shutil

    evidence_dir = f"findings/evidence/{evidence_type}"
    os.makedirs(evidence_dir, exist_ok=True)

    filename = os.path.basename(filepath)
    dest = f"{evidence_dir}/{finding_id}-{filename}"
    shutil.copy(filepath, dest)

    return dest
```

---

## Summary

**Every pentest agent MUST**:
1. ✓ Log every experiment performed
2. ✓ Track all hypotheses tested
3. ✓ Generate clean, organized reports
4. ✓ Save reports in structured `findings/` folder
5. ✓ Include summary documents (process, methodology, findings, statistics)
6. ✓ Create individual finding folders with complete documentation
7. ✓ Capture and organize evidence
8. ✓ Provide clear, actionable insights

This ensures that pentesters can easily review:
- What was tested (TESTING_PROCESS.md)
- How it was tested (METHODOLOGY.md)
- What was discovered (findings-summary.md)
- Technical details (HYPOTHESES_AND_RESULTS.md)
- Detailed statistics (statistics.md)
- Complete vulnerability reports (individual finding-NNN/ folders)

---
