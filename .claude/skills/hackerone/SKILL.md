# HackerOne Bug Bounty Hunting Skill

Comprehensive bug bounty hunting skill for HackerOne platform - automates program analysis, scope testing, vulnerability validation, and submission preparation.

## Quick Start

```
Workflow:
- [ ] Extract program scope (URL or CSV file)
- [ ] Parse program guidelines and rules
- [ ] Deploy pentest agents for all assets
- [ ] Validate PoCs and experiments
- [ ] Generate HackerOne submission reports
```

## When to Use

Invoke via `/hackerone` command when:
- Testing HackerOne bug bounty programs
- Processing scope CSV files from HackerOne
- Automating multi-asset testing workflows
- Generating HackerOne-ready vulnerability reports
- Validating PoCs before submission

## Core Workflows

**Steps**:

- Depending from the input choose to start from Step 1 using the HackerOne URL provided as input or directly from Step 2 to proceed CSVs files

1. **Fetch program data** from HackerOne URL
   - Extract program guidelines and policy from the program guideline section
   - Identify in-scope/out-of-scope items from the scope section
   - Download scope CSV file from the scope section
   - Parse bounty ranges and response metrics
   - Create necessary credentials or other that are required to particpate to the challange. Ask for user help if blocked here

2. **Parse scope CSV**
   - Extract all eligible assets
   - Identify asset types (URL, WILDCARD, API, etc.)
   - Note testing restrictions per asset
   - Organize by priority (PRIMARY vs SECONDARY)

3. **Deploy pentest agents** (parallel execution)
   - Launch Pentester agent for each asset
   - Pass program-specific guidelines
   - Monitor progress and discoveries
   - Collect findings in real-time

4. **Validate and experiment**
   - Verify all PoCs execute successfully
   - Test edge cases and variations
   - Confirm vulnerability impact
   - Generate poc_output.txt with timestamps

5. **Generate submissions**
   - Create HackerOne-formatted reports
   - Calculate CVSS scores
   - Add remediation guidance
   - Prepare submission guide

## Program Analysis

### Program Selection Criteria

**High-Value Indicators**:
- ✅ New programs (< 30 days old)
- ✅ Fast response times (< 24 hours)
- ✅ High bounty ranges (Critical: $5,000+)
- ✅ Large attack surface (multiple assets)
- ✅ Modern tech stack (GraphQL, microservices)

**Red Flags to Avoid**:
- ❌ Poor response times (> 1 week)
- ❌ Low bounties (Critical: < $500)
- ❌ Overly restrictive scope
- ❌ High invalid report ratio

## Scope CSV Format

Expected CSV format (HackerOne export):

```csv
identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,max_severity
example.com,URL,,true,true,critical
api.example.com,URL,,true,true,critical
*.example.com,WILDCARD,,true,true,high
```

**Required columns**:
- `identifier` - Asset URL/domain
- `asset_type` - URL, WILDCARD, API, CIDR, etc.
- `eligible_for_submission` - Must be "true" to test
- `max_severity` - Maximum severity allowed
- `instruction` - Asset-specific testing notes

## Agent Deployment

### Pentester Agent Integration

For each asset, deploy Pentester orchestration agent:

```python
Task(
    subagent_type="Pentester",
    description=f"Test {asset_identifier}",
    prompt=f"""
    Execute penetration testing for: {asset_identifier}

    Program Guidelines:
    {program_guidelines}

    Asset Type: {asset_type}
    Max Severity: {max_severity}
    Instructions: {asset_instructions}

    Generate HackerOne-ready reports with:
    - CVSS scoring
    - Step-by-step reproduction
    - Visual evidence
    - Impact analysis
    - Remediation guidance
    """
)
```

### Parallel Testing

Deploy all agents in parallel for efficiency:
- 10 assets = 10 parallel Pentester agents
- Each agent spawns 30+ specialized vulnerability agents
- Total: 300+ concurrent testing agents
- Estimated time: 2-4 hours (vs 20-40 hours sequential)

## PoC Validation

**CRITICAL**: Every vulnerability MUST have validated PoC.

### Validation Requirements

**1. Executable PoC Script**:
```python
# poc_sqli_endpoint.py
import requests

def exploit():
    url = "https://example.com/search"
    payload = "' UNION SELECT username,password FROM users--"

    response = requests.get(url, params={"q": payload})

    if "admin:" in response.text:
        print("[+] SQLi successful! Admin credentials extracted.")
        return True
    return False

if __name__ == "__main__":
    exploit()
```

**2. Tested Output**:
```
# poc_output.txt
[2026-01-20 15:42:13] Running PoC: SQLi in search endpoint
[2026-01-20 15:42:14] [+] SQLi successful! Admin credentials extracted.
[2026-01-20 15:42:14] Extracted: admin:$2y$10$...
[2026-01-20 15:42:14] PoC validated and working.
```

**3. Manual Workflow**:
- Document manual steps in workflow.md
- Include screenshots in evidence/
- Record video for complex exploits

### Experimentation

Before finalizing reports:
1. **Test edge cases** - Different payloads, encodings, bypass techniques
2. **Verify impact** - Confirm actual security impact, not just detection
3. **Check variations** - Test on multiple endpoints if applicable
4. **Document failures** - Note what didn't work and why

## Report Generation

### HackerOne Report Format

**Required sections**:
1. **Summary** (2-3 sentences)
   - What is the vulnerability?
   - What is the impact?

2. **Severity Assessment**
   - CVSS score and vector
   - Business impact analysis

3. **Vulnerability Details**
   - Type (CWE mapping)
   - Location (URL, parameter, header)
   - Root cause analysis

4. **Steps to Reproduce**
   - Numbered, clear steps
   - Include HTTP requests/responses
   - Visual evidence (screenshots/video)

5. **Impact**
   - Realistic attack scenario
   - Data at risk
   - Potential damage

6. **Remediation**
   - Immediate fixes
   - Long-term improvements
   - Code examples

### Report Quality Checklist

Before submission:
- [ ] Clear, concise title (< 100 chars)
- [ ] Accurate CVSS score
- [ ] Step-by-step reproduction
- [ ] Working PoC included
- [ ] Visual evidence attached
- [ ] Impact analysis provided
- [ ] Remediation guidance included
- [ ] All sensitive data sanitized
- [ ] Grammar and spelling checked
- [ ] Professional tone maintained

## Output Structure

Following `.claude/OUTPUT_STANDARDS.md` - Bug Bounty format:

```
outputs/<program_name>/
├── findings/
│   ├── findings.json                 # All vulnerabilities
│   ├── finding-001/
│   │   ├── report.md                 # HackerOne report
│   │   ├── poc.py                    # Validated PoC
│   │   ├── poc_output.txt            # Execution proof
│   │   ├── workflow.md               # Manual steps
│   │   └── description.md            # Attack details
│   └── finding-002/
│       └── ...
├── reports/
│   ├── submissions/
│   │   ├── H1_CRITICAL_001.md        # Ready to submit
│   │   ├── H1_HIGH_001.md
│   │   └── H1_MEDIUM_001.md
│   ├── FINDINGS_SUMMARY.md           # Executive overview
│   └── SUBMISSION_GUIDE.md           # How to submit
└── evidence/
    ├── screenshots/
    ├── http-logs/
    └── videos/
```

## Tools

### CSV Parser

```python
# tools/csv_parser.py
from pathlib import Path
import csv

def parse_scope_csv(csv_path):
    """Parse HackerOne scope CSV and extract eligible assets"""
    assets = []
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('eligible_for_submission') == 'true':
                assets.append({
                    'identifier': row['identifier'],
                    'asset_type': row['asset_type'],
                    'max_severity': row.get('max_severity', 'critical'),
                    'instruction': row.get('instruction', ''),
                    'eligible_for_bounty': row.get('eligible_for_bounty') == 'true'
                })
    return assets
```

### Report Validator

```python
# tools/report_validator.py
def validate_report(report_path):
    """Validate HackerOne report has all required sections"""
    required = [
        "## Summary",
        "## Severity",
        "## Steps to Reproduce",
        "## Impact",
        "## Remediation"
    ]
    with open(report_path, 'r') as f:
        content = f.read()

    missing = [s for s in required if s not in content]

    if missing:
        return False, f"Missing sections: {', '.join(missing)}"

    return True, "Report validated"
```

## Best Practices

### Do's
- ✅ Read program policy thoroughly before testing
- ✅ Validate all PoCs before reporting
- ✅ Sanitize all sensitive data in reports
- ✅ Follow responsible disclosure practices
- ✅ Maintain professional communication
- ✅ Submit high-quality, unique findings
- ✅ Respect rate limits and testing windows

### Don'ts
- ❌ Test out-of-scope assets
- ❌ Cause service disruption
- ❌ Extract excessive data for PoC
- ❌ Rush submissions without validation
- ❌ Submit duplicate findings
- ❌ Include real user data in reports
- ❌ Threaten public disclosure

## Common Pitfalls

**Rejection Reason: "Out of Scope"**
- Solution: Double-check asset is in CSV with `eligible_for_submission=true`

**Rejection Reason: "Cannot Reproduce"**
- Solution: Validate PoC executes successfully, include poc_output.txt

**Rejection Reason: "Duplicate"**
- Solution: Search disclosed reports before testing, submit quickly

**Rejection Reason: "Insufficient Impact"**
- Solution: Demonstrate realistic attack scenario, show business impact

## Integration

This skill integrates with:
- **`/pentest`** - Core penetration testing skill
- **Pentester agent** - Orchestrates vulnerability testing
- **30+ specialized agents** - Test specific vulnerability types
- **Playwright MCP** - Browser automation for client-side testing
- **OUTPUT_STANDARDS.md** - Standardized report formatting

## Troubleshooting

**Skill not activating**: Use `/hackerone` command explicitly

**CSV parsing fails**: Verify CSV has required columns and UTF-8 encoding

**Agents not deploying**: Check that `/pentest` skill is available

**PoCs failing**: Run validation locally before including in reports

**Reports rejected**: Review report quality checklist and validation

---

**Ready to start? Run:**
```
/hackerone <program_url_or_csv_path>
```
