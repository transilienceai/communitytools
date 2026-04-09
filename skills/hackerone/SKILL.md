---
name: hackerone
description: HackerOne bug bounty automation - parses scope CSVs, deploys parallel pentesting agents for each asset, validates PoCs, and generates platform-ready submission reports. Use when testing HackerOne programs or preparing professional vulnerability submissions.
---

# HackerOne Bug Bounty Hunting

Automates HackerOne workflows: scope parsing → parallel testing → PoC validation → submission reports.

## Quick Start

```
1. Input: HackerOne program URL or CSV file
2. Parse scope and program guidelines
3. Deploy Pentester agents in parallel (one per asset)
4. Validate PoCs (poc.py + poc_output.txt required)
5. Generate HackerOne-formatted reports
```

## Workflows

**Option 1: HackerOne URL**
```
- [ ] Fetch program data and guidelines
- [ ] Download scope CSV
- [ ] Parse eligible assets
- [ ] Deploy agents in parallel
- [ ] Validate PoCs
- [ ] Generate submissions
```

**Option 2: CSV File**
```
- [ ] Parse CSV scope file
- [ ] Extract eligible_for_submission=true assets
- [ ] Collect program guidelines
- [ ] Deploy agents
- [ ] Validate and generate reports
```

## Scope CSV Format

Expected columns:
- `identifier` - Asset URL/domain
- `asset_type` - URL, WILDCARD, API, CIDR
- `eligible_for_submission` - Must be "true"
- `max_severity` - critical, high, medium, low
- `instruction` - Asset-specific notes

Use `tools/csv_parser.py` to parse.

## Agent Deployment

**Coordinator per asset** — spawned inline using role prompts:
```python
coordinator_role = Read("skills/coordination/SKILL.md")
Agent(prompt=f"{coordinator_role}\n\nTARGET: {asset_url}\nSCOPE: {program_guidelines}\nOUTPUT_DIR: ...",
      run_in_background=True)
```

**Parallel Execution**:
- 10 assets = 10 coordinator agents in parallel
- Each spawns executor agents from `skills/coordination/reference/executor-role.md`
- Time: 2-4 hours vs 20-40 sequential

## PoC Validation (CRITICAL)

**Every finding MUST have**:
1. `poc.py` - Executable exploit script
2. `poc_output.txt` - Timestamped execution proof
3. `workflow.md` - Manual steps (if applicable)
4. Evidence screenshots/videos

**Experimentation**: Test edge cases, verify impact, document failures.

## Report Format

Required sections (HackerOne standard):
1. Summary (2-3 sentences)
2. Severity (CVSS + business impact)
3. Steps to Reproduce (numbered, clear)
4. Visual Evidence (screenshots/video)
5. Impact (realistic attack scenario)
6. Remediation (actionable fixes)

Use `tools/report_validator.py` to validate.

## Output Structure

Per OUTPUT.md - Bug Bounty format:

```
{OUTPUT_DIR}/
├── findings/
│   ├── finding-001/
│   │   ├── report.md           # HackerOne report
│   │   ├── poc.py              # Validated PoC
│   │   ├── poc_output.txt      # Proof
│   │   └── workflow.md         # Manual steps
├── reports/
│   ├── submissions/
│   │   ├── H1_CRITICAL_001.md  # Ready to submit
│   │   └── H1_HIGH_001.md
│   └── SUBMISSION_GUIDE.md
└── evidence/
    ├── screenshots/
    └── http-logs/
```

## Program Selection

**High-Value**:
- New programs (< 30 days)
- Fast response (< 24 hours)
- High bounties (Critical: $5,000+)
- Large attack surface

**Avoid**:
- Slow response (> 1 week)
- Low bounties (Critical: < $500)
- Overly restrictive scope

## Critical Rules

**MUST DO**:
- Validate ALL PoCs before reporting
- Sanitize sensitive data
- Test only `eligible_for_submission=true` assets
- Follow program-specific guidelines
- Generate CVSS scores

**NEVER**:
- Report without validated PoC
- Test out-of-scope assets
- Include real user data
- Cause service disruption

## Quality Checklist

Before submission:
- [ ] Working PoC with poc_output.txt
- [ ] Accurate CVSS score
- [ ] Step-by-step reproduction
- [ ] Visual evidence
- [ ] Impact analysis
- [ ] Remediation guidance
- [ ] Sensitive data sanitized

## Tools

- `tools/csv_parser.py` - Parse HackerOne scope CSVs
- `tools/report_validator.py` - Validate report completeness
- `skills/coordination/SKILL.md` — Coordinator skill (spawns executors/validators)

## Integration

Uses `skills/coordination/SKILL.md` for coordination workflow. Follows OUTPUT.md for submission format.

## Common Rejections

**Out of Scope**: Check `eligible_for_submission=true`
**Cannot Reproduce**: Validate PoC, include poc_output.txt
**Duplicate**: Search disclosed reports, submit quickly
**Insufficient Impact**: Show realistic attack scenario

## Usage

```bash
/hackerone <program_url_or_csv_path>
```
