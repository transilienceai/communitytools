# HackerOne Skill - Claude Context

Auto-loaded context when working with HackerOne bug bounty hunting.

## Purpose

Automate HackerOne bug bounty workflows: program analysis → scope testing → PoC validation → report generation.

## Key Files

- **SKILL.md** - Complete workflows and methodology
- **README.md** - User documentation
- **tools/csv_parser.py** - Parse HackerOne scope CSVs
- **tools/report_validator.py** - Validate report quality

## Core Workflows

**Workflow 1: HackerOne URL → Reports**
1. Fetch program data and guidelines
2. Download scope CSV
3. Deploy Pentester agents (parallel)
4. Validate PoCs
5. Generate HackerOne reports

**Workflow 2: CSV File → Reports**
1. Parse CSV scope file
2. Collect program guidelines
3. Deploy agents
4. Validate and generate reports

**Workflow 3: Manual Testing**
1. Define scope manually
2. Execute testing
3. Generate reports

## Critical Rules

**MUST DO**:
- ✅ Validate ALL PoCs before reporting (working poc.py + poc_output.txt)
- ✅ Sanitize all sensitive data in reports
- ✅ Test only assets with `eligible_for_submission=true`
- ✅ Follow program-specific guidelines and restrictions
- ✅ Generate HackerOne-formatted reports with CVSS scores
- ✅ Deploy Pentester agents in parallel for efficiency

**NEVER DO**:
- ❌ Report theoretical vulnerabilities without validated PoCs
- ❌ Test out-of-scope assets
- ❌ Include real user data in reports
- ❌ Skip PoC validation step
- ❌ Cause service disruption

## Agent Integration

**Pentester Agent**: Deploy for each asset using Task tool
- Passes program-specific guidelines
- Handles all vulnerability testing
- Returns validated findings with PoCs

**Parallel Execution**:
- 10 assets = 10 Pentester agents
- Each spawns 30+ specialized vulnerability agents
- Total: 300+ concurrent tests
- Time: 2-4 hours (vs 20-40 sequential)

## Output Format

**Bug Bounty Submissions** (see `.claude/OUTPUT_STANDARDS.md`):

```
outputs/<program>/
├── findings/
│   ├── finding-001/
│   │   ├── report.md           # HackerOne report
│   │   ├── poc.py              # Validated PoC
│   │   ├── poc_output.txt      # Execution proof
│   │   └── workflow.md         # Manual steps
├── reports/
│   ├── submissions/            # Ready to submit
│   │   ├── H1_CRITICAL_001.md
│   │   └── H1_HIGH_001.md
│   └── SUBMISSION_GUIDE.md
└── evidence/
    ├── screenshots/
    └── http-logs/
```

## CSV Parsing

Expected columns:
- `identifier` - Asset URL/domain
- `asset_type` - URL, WILDCARD, API, CIDR
- `eligible_for_submission` - Must be "true"
- `max_severity` - critical, high, medium, low
- `instruction` - Asset-specific notes

Parse with: `tools/csv_parser.py`

## Report Quality

**Required sections**:
1. Summary (2-3 sentences)
2. Severity (CVSS + business impact)
3. Steps to Reproduce (numbered, clear)
4. Visual Evidence (screenshots/video)
5. Impact (realistic attack scenario)
6. Remediation (actionable fixes)

**Validation**: Use `tools/report_validator.py`

## Common Tasks

**Parse CSV scope**: Read file, extract eligible assets, organize by type

**Deploy testing**: Launch Pentester agents in parallel with program guidelines

**Validate PoCs**: Run all poc.py scripts, verify poc_output.txt exists with timestamps

**Generate reports**: Create HackerOne markdown reports with all required sections

**Quality check**: Validate reports have PoCs, evidence, CVSS scores, remediation

## Quick Reference

**Skill location**: `.claude/skills/hackerone/`
**Command**: `/hackerone`
**Agent**: `.claude/agents/hackerone-hunter.md`
**Integration**: Uses `/pentest` skill and Pentester agent

## Success Criteria

Ready to submit when:
- [ ] All PoCs validated and working
- [ ] Reports have all required sections
- [ ] CVSS scores calculated
- [ ] Evidence collected (screenshots/videos)
- [ ] Sensitive data sanitized
- [ ] Remediation guidance included
