---
model: sonnet
---

Execute HackerOne bug bounty hunting workflows: parse scope, test assets in parallel, validate PoCs, and generate submission-ready reports.

**CRITICAL WORKFLOW:**

1. **Invoke the hackerone skill immediately** to load bug bounty knowledge base:
```
/hackerone skill loaded
```

2. **Deploy the HackerOne Hunter Agent** using the Task tool:

The HackerOne Hunter agent orchestrates the complete bug bounty workflow from scope analysis to submission-ready reports.

```
Deploy HackerOne Hunter agent from: .claude/agents/hackerone-hunter.md

The agent will:
- Parse HackerOne scope (CSV file or program URL)
- Extract and validate program guidelines
- Deploy Pentester agents for all assets in PARALLEL
- Validate all PoCs (working poc.py + poc_output.txt)
- Generate HackerOne submission-ready reports
- Create findings summary and submission guide
```

3. **Agent Deployment Pattern:**

```python
Task(
    subagent_type="HackerOne Hunter",
    description="HackerOne bug bounty orchestration",
    prompt="""
    Execute HackerOne bug bounty hunting workflow.

    Agent location: .claude/agents/hackerone-hunter.md
    Skill: /hackerone (already loaded)

    User request: [PASS THE USER'S ORIGINAL REQUEST HERE]

    The HackerOne Hunter agent will:
    1. Identify input type (CSV file or H1 URL)
    2. Parse scope and extract eligible assets
    3. Collect program guidelines and rules
    4. Deploy Pentester agents in PARALLEL for all assets:
       - 10 assets = 10 Pentester agents
       - Each Pentester spawns 30+ specialized agents
       - Total: 300+ concurrent vulnerability tests
    5. Monitor findings and agent progress
    6. Validate ALL PoCs (execute poc.py, verify output)
    7. Generate HackerOne submission reports
    8. Create findings summary and submission guide

    CRITICAL: All PoCs must be validated before report generation.
    """
)
```

4. **What the HackerOne Hunter Agent Does:**

**✅ Orchestration Responsibilities:**
- Parse HackerOne scope CSVs (or fetch from H1 URL)
- Extract program guidelines and testing rules
- Deploy Pentester agents for ALL assets in parallel
- Monitor agent progress and collect findings
- Validate PoC scripts (execute and verify output)
- Aggregate and deduplicate findings
- Generate HackerOne-formatted reports with CVSS
- Create submission guide with priority order

**❌ What HackerOne Hunter NEVER Does:**
- Run security testing tools directly
- Test vulnerabilities itself
- Skip PoC validation
- Generate theoretical vulnerability reports

5. **Input Methods:**

**Method 1: CSV File**
```
User: /hackerone scopes_for_program.csv
```

**Method 2: HackerOne URL**
```
User: /hackerone https://hackerone.com/example-corp
```

**Method 3: With Guidelines**
```
User: /hackerone scopes.csv --guidelines "Test: XSS, SQLi, SSRF, IDOR. Out of scope: Clickjacking, Rate limiting"
```

6. **Expected CSV Format:**

HackerOne scope CSV export format:
```csv
identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,max_severity
example.com,URL,,true,true,critical
api.example.com,URL,,true,true,critical
*.example.com,WILDCARD,,true,true,high
```

**Required columns:**
- `identifier` - Asset URL/domain
- `asset_type` - URL, WILDCARD, API, CIDR, etc.
- `eligible_for_submission` - Must be "true" to test
- `max_severity` - Maximum severity allowed
- `instruction` - Asset-specific testing notes

7. **Output Structure:**

Following `.claude/OUTPUT_STANDARDS.md` - Bug Bounty format:

```
outputs/<program_name>/
├── findings/
│   ├── findings.json                    # All vulnerabilities
│   ├── finding-001/
│   │   ├── report.md                    # HackerOne report
│   │   ├── poc.py                       # VALIDATED, TESTED PoC
│   │   ├── poc_output.txt              # Proof of execution
│   │   ├── workflow.md                  # Manual steps
│   │   └── description.md               # Attack details
│   └── finding-002/...
├── reports/
│   ├── submissions/
│   │   ├── H1_CRITICAL_001.md          # Ready to copy/paste
│   │   ├── H1_HIGH_001.md
│   │   └── H1_MEDIUM_001.md
│   ├── FINDINGS_SUMMARY.md             # Executive overview
│   └── SUBMISSION_GUIDE.md             # How to submit
└── evidence/
    ├── screenshots/
    ├── http-logs/
    └── videos/
```

8. **Report Standards:**

**CRITICAL**: All reports follow HackerOne submission standards.

**Deliverables:**
- **HackerOne Reports**: Complete with CVSS, PoC, impact, remediation
- **Findings Summary**: Count by severity, estimated bounty ranges
- **Submission Guide**: Priority order, submission tips

9. **PoC Validation Requirements:**

**MANDATORY**: Every vulnerability MUST have:
- ✅ Working PoC script (poc.py or poc.sh)
- ✅ Tested output (poc_output.txt with timestamp)
- ✅ Manual workflow (workflow.md)
- ✅ Validation passed (tools/report_validator.py)

**Reject findings without validated PoCs** - theoretical vulnerabilities are NOT confirmed.

10. **Parallel Testing Benefits:**

**Sequential Testing** (old way):
- 10 assets × 2 hours each = 20 hours total

**Parallel Testing** (this workflow):
- 10 assets tested simultaneously = 2-4 hours total
- 300+ concurrent vulnerability agents
- 6-10x faster completion

**Example Usage:**

```
User: Test scopes_for_example.csv

HackerOne Hunter Agent:
1. Parses CSV: 12 eligible assets
2. Collects program guidelines
3. Deploys 12 Pentester agents (parallel)
4. Monitors progress (2-4 hours)
5. Validates 9 findings with PoCs
6. Generates HackerOne reports
7. Creates submission guide

Output:
- 2 Critical findings ($10,000 estimated)
- 3 High findings ($6,000 estimated)
- 4 Medium findings ($2,000 estimated)
Total estimated: $18,000-$35,000
```

**Key Principle:**

The `/hackerone` command loads the bug bounty knowledge base AND deploys the HackerOne Hunter orchestrator, which coordinates all testing agents, validates PoCs, and generates professional HackerOne submission reports.

**Tools Provided:**

The skill includes Python tools for automation:
- `tools/csv_parser.py` - Parse HackerOne scope CSVs
- `tools/report_validator.py` - Validate report quality and PoCs

**Validation:**

Before completion, the agent verifies:
- [ ] All assets tested
- [ ] All PoCs validated and working
- [ ] All reports have required sections
- [ ] CVSS scores calculated
- [ ] Evidence collected
- [ ] Sensitive data sanitized
- [ ] Summary and guide generated
