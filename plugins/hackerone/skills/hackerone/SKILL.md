---
name: hackerone
description: HackerOne bug bounty automation - parses scope CSVs, validates PoCs, tracks sensitive data, and generates platform-ready submission reports.
---

# HackerOne Bug Bounty Skill

Scope parsing, PoC validation, sensitive data tracking, and HackerOne report generation.

## Scope CSV Format

Expected columns (use `tools/csv_parser.py` to parse):

| Column | Required | Description |
|--------|----------|-------------|
| `identifier` | Yes | Asset URL/domain |
| `asset_type` | Yes | URL, WILDCARD, API, CIDR |
| `eligible_for_submission` | Yes | Must be `true` to test |
| `max_severity` | Yes | critical, high, medium, low |
| `instruction` | No | Asset-specific notes/restrictions |

Only assets with `eligible_for_submission=true` are tested.

## HackerOne Report Format

**Title**: `[Vulnerability Type] in [Location]`

Required sections:

```markdown
# [Title]

**Severity**: Critical/High/Medium/Low (CVSS X.X)
**Asset**: [Full URL or identifier]

## Summary
[2-3 sentence description of the vulnerability]

## Steps to Reproduce
1. [Numbered, clear, reproducible steps]
2. ...

## Proof of Concept
[Code blocks, HTTP requests, screenshots]

## Impact
[Realistic business impact and attack scenario]

## Remediation
[Specific, actionable fix recommendations]
```

**Attachments**: Screenshots, HTTP logs, poc.py, poc_output.txt

## Sensitive Data Tracking

All discovered credentials, keys, and PII must be tracked using `tools/sensitive_data_tracker.py`.
See `reference/sensitive-data-tracking.md` for categories, detection patterns, and redaction rules.

## Tools

| Tool | Purpose |
|------|---------|
| `tools/csv_parser.py` | Parse HackerOne scope CSVs, filter eligible assets |
| `tools/report_validator.py` | Validate report completeness (sections, CVSS, PoC, sensitive data) |
| `tools/sensitive_data_tracker.py` | Track and document all sensitive data discoveries |

## PoC Requirements

Every finding MUST have:
1. `poc.py` - Executable exploit script
2. `poc_output.txt` - Timestamped execution proof
3. Evidence screenshots/HTTP logs
4. `workflow.md` - Manual reproduction steps (if applicable)

## Critical Rules

- Only test `eligible_for_submission=true` assets
- Validate ALL PoCs before reporting
- Sanitize sensitive data in reports (use redaction rules)
- Follow program-specific guidelines and restrictions
- Generate accurate CVSS scores
- Never include real user data in submissions
- Never cause service disruption

## Usage

```
/hackerone <program_url_or_csv_path>
```
