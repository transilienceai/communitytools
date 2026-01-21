# Implementation Guide: Pentest Agent Reporting Standards

**Status**: Ready for implementation across all 30+ specialized pentest agents

**Purpose**: Ensure every pentest agent generates comprehensive, organized, professional testing reports

---

## Quick Summary

This implementation adds structured report generation to all pentest agents with these key deliverables:

### New Files Created

1. **REPORT_GENERATION.md** - Complete reporting standards and templates
2. **AGENT_UPDATE_TEMPLATE.md** - Template for updating agent definitions
3. **EXAMPLE_REPORT_OUTPUT.md** - Real-world example of agent output
4. **IMPLEMENTATION_GUIDE.md** - This document

### Updated Files

1. **CLAUDE.md** - Added Report Generation Requirements section

---

## What Gets Generated

Every agent execution now produces a comprehensive `findings/` directory structure:

```
findings/
├── TESTING_PROCESS.md           # Phase-by-phase overview
├── EXPERIMENTATION_LOG.md       # Detailed log of ALL tests
├── HYPOTHESES_AND_RESULTS.md    # All hypotheses tested
├── METHODOLOGY.md               # Testing methodology applied
├── summary/
│   ├── findings-summary.md      # Executive summary
│   └── statistics.md             # Metrics and KPIs
├── finding-NNN/                 # Individual vulnerabilities
│   ├── report.md                # Comprehensive report
│   ├── poc.py                   # Exploit script (tested)
│   ├── poc_output.txt           # Proof of execution
│   ├── workflow.md              # Manual steps
│   └── description.md           # Technical details
└── evidence/
    ├── screenshots/
    ├── http-captures/
    └── videos/
```

---

## Phase 1: Update Agent Files

### Overview

Each of the 30+ specialized agents needs the "Report Generation & Documentation" section added to their markdown definition.

### Step-by-Step Process

**For each agent file** (e.g., `xss-agent.md`, `sql-injection-agent.md`, etc.):

1. Open the agent markdown file
2. Locate a good insertion point (typically after workflow sections)
3. Add the Report Generation section from `AGENT_UPDATE_TEMPLATE.md`
4. Customize for the specific agent if needed
5. Ensure consistency with other agents

### Affected Agents (30+)

**Access Control** (2):
- [ ] `access-control-agent.md`
- [ ] `authentication-bypass-agent.md`

**Injection Attacks** (6):
- [ ] `sql-injection-agent.md`
- [ ] `nosql-injection-agent.md`
- [ ] `command-injection-agent.md`
- [ ] `ssti-agent.md`
- [ ] `xxe-agent.md`
- [ ] `ldap-xpath-injection-agent.md`

**Client-Side Attacks** (6):
- [ ] `xss-agent.md`
- [ ] `csrf-agent.md`
- [ ] `cors-agent.md`
- [ ] `clickjacking-agent.md`
- [ ] `dom-based-agent.md`
- [ ] `prototype-pollution-agent.md`

**Server-Side Attacks** (6):
- [ ] `ssrf-agent.md`
- [ ] `http-smuggling-agent.md`
- [ ] `file-upload-agent.md`
- [ ] `path-traversal-agent.md`
- [ ] `deserialization-agent.md`
- [ ] `host-header-agent.md`

**API Security** (5):
- [ ] `graphql-agent.md`
- [ ] `rest-api-agent.md`
- [ ] `jwt-agent.md`
- [ ] `oauth-agent.md`
- [ ] `websocket-agent.md`

**Application Logic** (6):
- [ ] `business-logic-agent.md`
- [ ] `race-condition-agent.md`
- [ ] `password-attack-agent.md`
- [ ] `cache-poisoning-agent.md`
- [ ] `cache-deception-agent.md`
- [ ] `information-disclosure-agent.md`

**Emerging Threats** (1):
- [ ] `web-llm-agent.md`

---

## Phase 2: Update Supporting Documentation

### Key Files to Review/Update

1. **CLAUDE.md** (specialized/CLAUDE.md)
   - ✓ ALREADY UPDATED with Report Generation section

2. **POC_REQUIREMENTS.md** (specialized/POC_REQUIREMENTS.md)
   - Status: Complete - No changes needed
   - Reason: Already comprehensive and referenced by new reporting standards

3. **README.md** (specialized/README.md)
   - Consider adding note about new reporting standards
   - Cross-link to REPORT_GENERATION.md

---

## Phase 3: Agent Implementation

### For Agent Developers

When updating agents to use the new reporting standards:

#### 1. Initialize Reporting at Startup

```python
def initialize_reporting(agent_name):
    """Initialize findings directory and tracking"""
    import os
    from datetime import datetime

    base_dir = "findings"
    os.makedirs(f"{base_dir}/summary", exist_ok=True)
    os.makedirs(f"{base_dir}/evidence/screenshots", exist_ok=True)
    os.makedirs(f"{base_dir}/evidence/http-captures", exist_ok=True)

    state = {
        'agent_name': agent_name,
        'start_time': datetime.now(),
        'experiments': [],
        'hypotheses': [],
        'findings': []
    }
    return state
```

#### 2. Log Every Experiment

```python
def log_experiment(state, test_number, test_name, hypothesis,
                   payload, result, notes=""):
    """Log a single experimentation"""
    experiment = {
        'number': test_number,
        'timestamp': datetime.now().isoformat(),
        'test_name': test_name,
        'hypothesis': hypothesis,
        'payload': payload,
        'result': result,  # 'success', 'failed', 'partial'
        'notes': notes
    }
    state['experiments'].append(experiment)

    # Save immediately
    update_experimentation_log(state)
```

#### 3. Track Hypotheses

```python
def add_hypothesis(state, hyp_id, category, description,
                   result, finding_id=None, cvss=None):
    """Record hypothesis and result"""
    hypothesis = {
        'id': hyp_id,
        'category': category,
        'description': description,
        'result': result,  # 'verified', 'disproven', 'partial'
        'finding_id': finding_id,
        'cvss': cvss
    }
    state['hypotheses'].append(hypothesis)

    # Update report
    update_hypotheses_report(state)
```

#### 4. Create Finding with PoC

```python
def create_finding(state, finding_id, title, cvss, cwe, owasp,
                   poc_script, poc_output, workflow, description):
    """Create complete vulnerability finding"""
    import os
    import json

    finding_dir = f"findings/finding-{finding_id:03d}"
    os.makedirs(finding_dir, exist_ok=True)

    # Save all finding files
    with open(f"{finding_dir}/report.md", 'w') as f:
        f.write(generate_report(title, cvss, cwe, owasp))

    with open(f"{finding_dir}/poc.py", 'w') as f:
        f.write(poc_script)

    with open(f"{finding_dir}/poc_output.txt", 'w') as f:
        f.write(poc_output)

    with open(f"{finding_dir}/workflow.md", 'w') as f:
        f.write(workflow)

    with open(f"{finding_dir}/description.md", 'w') as f:
        f.write(description)

    # Add to state
    state['findings'].append({
        'id': finding_id,
        'title': title,
        'cvss': cvss,
        'cwe': cwe,
        'owasp': owasp
    })
```

#### 5. Generate Final Reports

```python
def generate_final_reports(state):
    """Generate all final reports upon completion"""

    with open('findings/TESTING_PROCESS.md', 'w') as f:
        f.write(generate_testing_process(state))

    with open('findings/EXPERIMENTATION_LOG.md', 'w') as f:
        f.write(generate_experimentation_log(state))

    with open('findings/HYPOTHESES_AND_RESULTS.md', 'w') as f:
        f.write(generate_hypotheses_results(state))

    with open('findings/METHODOLOGY.md', 'w') as f:
        f.write(generate_methodology(state))

    with open('findings/summary/findings-summary.md', 'w') as f:
        f.write(generate_findings_summary(state))

    with open('findings/summary/statistics.md', 'w') as f:
        f.write(generate_statistics(state))

    print("\n[+] All reports generated successfully")
    print(f"[+] Location: findings/")
```

---

## Phase 4: Testing & Validation

### Validation Checklist

Before an agent is considered "complete," verify:

- [ ] Agent markdown includes "Report Generation & Documentation" section
- [ ] Section references REPORT_GENERATION.md
- [ ] Directory structure matches template
- [ ] All file types documented (TESTING_PROCESS, METHODOLOGY, etc.)
- [ ] Evidence organization explained
- [ ] Integration with POC_REQUIREMENTS.md mentioned

### Quality Standards

All agents must meet these standards:

**Organization**:
- [ ] `findings/` directory created
- [ ] Subdirectories for summary/ and evidence/
- [ ] Individual finding-NNN/ folders

**Documentation**:
- [ ] All 6 primary reports generated
- [ ] Clear, professional writing
- [ ] Complete technical details
- [ ] Proper formatting

**Evidence**:
- [ ] Screenshots captured
- [ ] HTTP captures included
- [ ] Videos if applicable
- [ ] Organized in subdirectories

---

## Implementation Timeline

### Week 1: Setup
- [x] Create REPORT_GENERATION.md
- [x] Create AGENT_UPDATE_TEMPLATE.md
- [x] Create EXAMPLE_REPORT_OUTPUT.md
- [x] Update CLAUDE.md
- [ ] Create this implementation guide

### Week 2: Update Agents
- [ ] Injection agents (6)
- [ ] Client-side agents (6)
- [ ] Server-side agents (6)

### Week 3: Update Agents (continued)
- [ ] Authentication & access control agents (2)
- [ ] API security agents (5)
- [ ] Application logic agents (6)
- [ ] Emerging threats agents (1)

### Week 4: Testing & Documentation
- [ ] Test updated agents
- [ ] Validate report generation
- [ ] Fix any issues
- [ ] Final review

---

## Key Features

### 1. Comprehensive Experimentation Log
Every test performed is logged with:
- Timestamp
- Hypothesis being tested
- Payload/technique used
- Result (success/failed/partial)
- Evidence references

### 2. Hypothesis Tracking
All hypotheses documented with:
- Hypothesis ID and category
- Description and technical basis
- Testing approach used
- Result (verified/disproven/partial)
- Impact analysis

### 3. Professional Reporting
Multiple levels of reporting:
- Executive summary for stakeholders
- Detailed technical reports for teams
- Individual vulnerability reports with PoCs
- Statistical analysis of testing

### 4. Evidence Organization
All evidence organized in clear directory structure:
- Screenshots of exploitations
- HTTP request/response pairs
- Network traffic captures
- Video evidence

### 5. PoC Verification
Every finding includes:
- Tested, working exploit script
- Proof of execution (poc_output.txt)
- Manual exploitation workflow
- Technical attack description

---

## Benefits

**For Security Teams**:
- Clear understanding of what was tested
- Detailed evidence for every finding
- Actionable remediation guidance
- Professional reporting for clients

**For Developers**:
- Comprehensive testing documentation
- Evidence of thorough assessment
- Clear findings index
- Business impact analysis

**For Management**:
- Executive summaries for stakeholders
- Risk prioritization guidance
- Remediation timelines
- Compliance mapping (OWASP, CWE, CVSS)

---

## Troubleshooting

### Issue: Agent not creating findings directory

**Solution**: Ensure `initialize_reporting()` is called at agent startup, before any testing begins.

### Issue: Reports not generating

**Solution**: Verify state tracking is enabled. Ensure `generate_final_reports()` is called at completion, after all findings are recorded.

### Issue: Missing PoC output evidence

**Solution**: Ensure `poc_output.txt` is captured immediately after PoC execution. Use subprocess.run() with capture_output=True.

### Issue: Inconsistent directory structure

**Solution**: Reference REPORT_GENERATION.md template. Use provided helper functions to create directories and files.

---

## Support & Questions

For questions about implementation:

1. **Reporting Standards**: See `REPORT_GENERATION.md`
2. **Agent Templates**: See `AGENT_UPDATE_TEMPLATE.md`
3. **Example Output**: See `EXAMPLE_REPORT_OUTPUT.md`
4. **PoC Requirements**: See `POC_REQUIREMENTS.md`

---

## Next Steps

1. Review all documentation (especially REPORT_GENERATION.md)
2. Begin updating agent files according to checklist
3. Test updated agents to verify report generation
4. Iterate and improve based on real-world testing
5. Document lessons learned

---

## Version Info

- **Document**: Implementation Guide
- **Version**: 1.0
- **Created**: 2025-01-16
- **Status**: Ready for Implementation

---
