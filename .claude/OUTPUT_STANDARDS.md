# Output Standards

Standardized output formats for all security testing skills and agents.

## Quick Reference

**Directory structure**:
```
outputs/<skill>/<target>/
├── findings/      # Vulnerability findings (JSON + MD)
├── evidence/      # Screenshots, videos, HTTP captures
├── reports/       # Executive + technical reports
├── raw/           # Tool outputs
└── metadata.json  # Testing metadata
```

**Output types**:
- **Reconnaissance**: Inventory + analysis → testing checklist
- **Vulnerability testing**: Findings + evidence → actionable reports
- **Bug bounty**: Platform-ready submissions (HackerOne, Bugcrowd)

**Key files**:
- `findings.json` - Machine-readable findings (CVSS, CWE, OWASP)
- `finding-NNN.md` - Human-readable individual reports
- `executive-summary.md` - Business impact summary
- `technical-report.md` - Complete technical details

## Three Output Categories

### 1. Reconnaissance (domain-assessment, web-application-mapping)

**Structure**:
```
outputs/<skill>/<target>/
├── inventory/          # JSON: subdomains, ports, endpoints, tech stack
├── analysis/           # MD: attack-surface, testing-checklist
├── evidence/screenshots/
├── raw/<tool-name>/
└── metadata.json
```

**Purpose**: Map attack surface → feed into vulnerability testing

### 2. Vulnerability Testing (pentest, common-appsec-patterns, cve-testing)

**Structure**:
```
outputs/<skill>/<target>/
├── findings/
│   ├── findings.json    # All findings
│   ├── finding-NNN/     # Individual vulnerability folders
│   │   ├── report.md    # Vulnerability report
│   │   ├── workflow.md  # Step-by-step exploit workflow
│   │   ├── poc.py       # Verified Python PoC script
│   │   ├── poc_output.txt # PoC execution output (proof of verification)
│   │   └── description.md  # Attack description and context
├── evidence/
│   ├── screenshots/
│   ├── videos/
│   ├── requests/        # HTTP req/resp pairs
│   └── logs/
├── reports/
│   ├── executive-summary.md
│   ├── technical-report.md
│   └── submission.md    # Bug bounty (optional)
├── raw/<tool-name>/
└── metadata.json
```

**Purpose**: Document vulnerabilities with complete evidence

### 3. Bug Bounty (pentest-csv, bugbounty)

**Structure**:
```
outputs/<program>/
├── <asset1>/findings/
├── <asset2>/findings/
├── reports/
│   ├── FINDINGS_SUMMARY.md
│   ├── executive-summary.md
│   ├── technical-report.md
│   └── submissions/
│       └── finding-NNN-hackerone.md
├── SCOPE_AND_GUIDELINES.md
└── HACKERONE_SUBMISSION_GUIDE.md
```

**Purpose**: Ready-to-submit vulnerability reports

## Required Fields

**Every finding MUST have**:
- Unique ID (finding-NNN)
- Title (<100 chars)
- CVSS v3.1 score + vector
- CWE + OWASP mapping
- Reproduction steps
- Visual evidence
- Impact analysis
- Remediation guidance
- **Verified PoC Script**: Tested Python/Bash script that successfully exploits the vulnerability
- **PoC Execution Output**: Proof that PoC was tested and validated
- **Exploit Workflow**: Step-by-step documentation of how to execute the exploit

**Every report MUST have**:
- Executive summary (1-2 pages for executives)
- Technical report (comprehensive for security teams)
- Severity breakdown table
- Complete technical details
- Evidence references
- Remediation recommendations with timeline
- CVSS v3.1 scoring
- OWASP and CWE mappings

**Professional Report Standard**:
For penetration testing, follow the industry-standard format in:
- `.claude/skills/pentest/attacks/essential-skills/reporting/PROFESSIONAL_REPORT_STANDARD.md`

This standard includes:
- Executive Report (1-2 pages) - For C-level stakeholders
- Technical Report (Comprehensive) - For security teams
- JSON output for automation
- Individual finding reports with verified PoCs

See [FINDING_TEMPLATE.md](output-standards/reference/FINDING_TEMPLATE.md) for complete schema.

## Workflows

### Finding Generation Workflow

1. **During testing**: Collect findings in memory
2. **On discovery**: Capture evidence immediately (screenshots, HTTP)
3. **Develop and test PoC**: Create verified exploit script, capture output
4. **On completion**:
   - Generate findings.json
   - Create individual finding-NNN/ folders with all required files
   - Generate reports/executive-summary.md (1-2 pages)
   - Generate reports/technical-report.md (comprehensive)
   - Generate submission.md (if bug bounty)

### Professional Report Generation Workflow (Penetration Testing)

**For Pentester Orchestrator** - Follow this workflow after all agents complete:

1. **Collect Findings** from all specialized agents
   - SQL injection findings
   - XSS findings
   - SSRF findings
   - All other vulnerability findings

2. **Verify PoC Quality**
   - Each finding MUST have working poc.py
   - Each finding MUST have poc_output.txt (proof of execution)
   - Each finding MUST have workflow.md (manual steps)
   - Each finding MUST have description.md (technical details)
   - Reject findings without verified PoCs

3. **Deduplicate & Correlate**
   - Remove duplicate findings
   - Identify exploit chains (SQLi → Admin Access → Data Breach)
   - Group related findings

4. **Calculate Metrics**
   - Count by severity (Critical/High/Medium/Low/Info)
   - Count by OWASP category (A01-A10)
   - Count by vulnerability type
   - Calculate percentages

5. **Generate Executive Report** (`reports/executive-summary.md`)
   - Cover page with engagement details
   - Executive summary (1 page max)
     - Assessment overview
     - Scope
     - Methodology
     - Overall risk rating
     - Findings summary table
     - Top 3-5 critical/high findings only
   - Business impact analysis (1 page)
     - Financial impact
     - Compliance/regulatory impact
     - Operational impact
     - Reputational risk
     - Attack scenarios
     - Risk heat map
   - Strategic recommendations
     - Immediate actions (0-30 days)
     - Short-term (30-90 days)
     - Long-term (90+ days)
   - Conclusion

6. **Generate Technical Report** (`reports/technical-report.md`)
   - Cover page and table of contents
   - Introduction
   - Scope of assessment (detailed)
   - Methodology (PTES, OWASP, NIST)
   - Assessment timeline
   - Tools & techniques used
   - Executive summary (technical brief)
   - Findings summary
     - Vulnerability breakdown table
     - Findings by category
     - Findings by OWASP Top 10
     - Findings index
   - Detailed technical findings (all findings)
     - For each finding: F-001, F-002, etc.
     - Use standardized finding format
     - Include PoC, evidence, remediation
   - Remediation recommendations
     - Prioritization matrix
     - Remediation roadmap (phased)
     - Security improvements
     - Retest recommendations
   - Conclusion
   - Appendices (CVSS guide, OWASP ref, glossary, contacts)

7. **Generate JSON Output** (`findings/findings.json`)
   - Machine-readable format
   - All findings with metadata
   - For integration with SIEM/vulnerability management

8. **Validate Report Quality**
   - [ ] Executive summary is 1-2 pages
   - [ ] All findings have verified PoCs
   - [ ] CVSS scores calculated correctly
   - [ ] Evidence captured for all findings
   - [ ] Remediation timeline provided
   - [ ] Business impact explained clearly
   - [ ] Technical details are accurate
   - [ ] Sensitive data redacted

**Template Location**: `.claude/skills/pentest/attacks/essential-skills/reporting/PROFESSIONAL_REPORT_STANDARD.md`

### Aggregation Workflow (Coordinators)

1. **Deploy agents** in parallel
2. **Collect** findings.json from each agent
3. **Deduplicate** by location + type
4. **Identify** exploit chains
5. **Generate** master findings.json
6. **Create** consolidated reports

See [WORKFLOWS.md](output-standards/reference/WORKFLOWS.md) for details.

## Agent Responsibilities

**Specialized agents** (XSS, SQLi, SSRF, etc.):
- Generate findings.json for discovered vulnerabilities
- Capture all evidence files
- Save raw tool outputs

**Coordinator agents** (pentester, hackerone-bounty-hunter):
- Aggregate findings from multiple agents
- Deduplicate vulnerabilities
- Generate executive and technical reports
- Create platform submissions (if bug bounty)

## PoC Verification Requirements

**CRITICAL**: A vulnerability is NOT considered verified unless it has a tested, working PoC script.

### PoC Script Requirements

Each vulnerability folder (`findings/finding-NNN/`) MUST contain:

1. **poc.py** (or poc.sh for bash-based exploits)
   - Self-contained, runnable script
   - Clear command-line arguments for target, parameters
   - Proper error handling and output messages
   - Comments explaining each step
   - Example: `python3 poc.py --target https://target.com --param search`

2. **poc_output.txt**
   - Complete terminal output showing successful execution
   - Timestamp of when PoC was tested
   - Proof of exploitation (extracted data, command execution output, etc.)
   - Must demonstrate the vulnerability is real and exploitable

3. **workflow.md**
   - Step-by-step manual exploitation process
   - Each step with explanation
   - Expected output at each step
   - Troubleshooting tips for common issues

4. **description.md**
   - Overview of the attack type
   - Technical details of the vulnerability
   - Why the vulnerability exists
   - Potential impact scenarios

### PoC Verification Process

1. **Agent discovers potential vulnerability**
2. **Agent develops PoC script** (Python preferred, Bash acceptable)
3. **Agent tests PoC against target** - MUST execute successfully
4. **Agent captures output** - Save to poc_output.txt with timestamp
5. **If PoC fails** - Vulnerability is NOT verified, continue testing/refining
6. **If PoC succeeds** - Vulnerability is verified, create folder structure
7. **Agent documents workflow** - Write workflow.md with manual steps
8. **Agent writes description** - Create description.md with attack details

### Acceptable PoC Evidence

✅ **VERIFIED** (vulnerability confirmed):
- PoC script executes successfully
- poc_output.txt shows exploitation proof
- Data extracted, command executed, or unauthorized access achieved

❌ **NOT VERIFIED** (do NOT report as vulnerability):
- Theoretical vulnerability without working PoC
- PoC script exists but doesn't work
- No poc_output.txt demonstrating success
- Manual steps only without automated script

### PoC Script Template Structure

```python
#!/usr/bin/env python3
"""
PoC for [VULNERABILITY NAME]
Target: [TARGET URL/IP]
Vulnerability Type: [SQLi/XSS/SSRF/etc.]
Severity: [CVSS Score]
"""

import requests
import sys
import argparse
from urllib.parse import quote

def exploit(target, parameter, payload):
    """Execute the exploit"""
    print(f"[*] Testing {vulnerability_type} on {target}")
    print(f"[*] Parameter: {parameter}")
    print(f"[*] Payload: {payload}")

    # Exploitation logic here
    response = requests.get(f"{target}?{parameter}={payload}")

    if "success_indicator" in response.text:
        print(f"[+] VULNERABLE! Exploit successful")
        print(f"[+] Evidence: {response.text[:200]}")
        return True
    else:
        print(f"[-] Exploit failed")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='PoC for [VULN]')
    parser.add_argument('--target', required=True, help='Target URL')
    parser.add_argument('--param', required=True, help='Vulnerable parameter')
    args = parser.parse_args()

    success = exploit(args.target, args.param, "exploit_payload")
    sys.exit(0 if success else 1)
```

## Validation

**Before completing, verify**:
- [ ] Directory structure created
- [ ] findings.json follows standard schema
- [ ] Individual vulnerability folders created (findings/finding-NNN/)
- [ ] Each vulnerability has verified PoC script (poc.py)
- [ ] Each PoC has been tested and output captured (poc_output.txt)
- [ ] Each vulnerability has workflow documentation (workflow.md)
- [ ] Each vulnerability has description (description.md)
- [ ] All evidence captured with proper naming
- [ ] Executive summary created
- [ ] Technical report created
- [ ] All sensitive data sanitized
- [ ] Metadata.json complete

## Quality Standards

**Professional**:
- Clear, concise writing
- Actionable remediation
- Complete evidence
- No real credentials/PII

**Technical**:
- Accurate CVSS scores
- Correct CWE/OWASP mappings
- Reproducible steps
- Root cause analysis

**Complete**:
- Business + technical impact
- Realistic attack scenarios
- Code examples (vulnerable + fixed)
- Industry references

## Reference

**Templates**:
- [FINDING_TEMPLATE.md](output-standards/reference/FINDING_TEMPLATE.md) - Complete finding schema
- [REPORT_TEMPLATES.md](output-standards/reference/REPORT_TEMPLATES.md) - Executive, technical, submission
- [EXAMPLES.md](output-standards/reference/EXAMPLES.md) - Complete examples

**Workflows**:
- [WORKFLOWS.md](output-standards/reference/WORKFLOWS.md) - Detailed generation workflows
- [AGGREGATION.md](output-standards/reference/AGGREGATION.md) - Multi-agent aggregation

**Platform-Specific**:
- [HACKERONE.md](output-standards/reference/HACKERONE.md) - HackerOne submission format
- [BUGCROWD.md](output-standards/reference/BUGCROWD.md) - Bugcrowd submission format

## Version

- **Current**: 2.0
- **Updated**: 2025-01-15
- **Format**: JSON + Markdown

---

*Concise by design. See reference/ for detailed templates and examples.*
