# HackerOne Bug Bounty Hunting Skill

Automate bug bounty hunting workflows on HackerOne platform - from program discovery to submission-ready vulnerability reports.

## Overview

This skill combines bug bounty expertise with automated penetration testing to streamline HackerOne workflows:

- 🎯 **Program Analysis** - Evaluate programs and extract scope
- 🔍 **Automated Testing** - Deploy security agents across all assets in parallel
- ✅ **PoC Validation** - Verify all exploits work before submission
- 📝 **Report Generation** - Create HackerOne-ready vulnerability reports

## Quick Start

### Option 1: Test from CSV File

```bash
/hackerone scope_file.csv
```

The skill will:
1. Parse the CSV scope file
2. Ask for program guidelines
3. Test all eligible assets in parallel
4. Generate HackerOne submission reports

### Option 2: Test from HackerOne URL

```bash
/hackerone https://hackerone.com/program-name
```

The skill will:
1. Fetch program data and guidelines
2. Download scope CSV
3. Test all assets
4. Generate reports

### Option 3: Manual Asset Testing

```bash
/hackerone --assets "example.com,api.example.com" --guidelines "Test XSS, SQLi, SSRF"
```

## Features

### 🚀 Parallel Testing

- Deploy Pentester agents for all assets simultaneously
- 10 assets = 10 parallel agents = 300+ concurrent vulnerability tests
- Complete testing in 2-4 hours (vs 20-40 hours sequential)

### ✅ PoC Validation

Every vulnerability includes:
- Executable PoC script (Python/Bash)
- Tested output with timestamps
- Manual workflow documentation
- Visual evidence (screenshots/videos)

**No theoretical vulnerabilities** - everything is validated and working.

### 📊 Professional Reports

HackerOne-ready reports with:
- CVSS scoring and severity assessment
- Step-by-step reproduction instructions
- HTTP request/response evidence
- Impact analysis and business risk
- Remediation guidance with code examples
- Industry standard mappings (CWE, OWASP)

### 🎯 Program Intelligence

Built-in guidance for:
- Program selection criteria
- High-value vs low-value programs
- Common rejection reasons
- Bounty optimization strategies
- Report quality best practices

## Installation

No installation required - this skill is part of the Claude Code security skills repository.

## Usage

### Basic Usage

```bash
# Test from CSV file
/hackerone scopes_for_program.csv

# Test from HackerOne URL
/hackerone https://hackerone.com/example-corp

# Test specific assets
/hackerone --assets "api.example.com,web.example.com"
```

### With Program Guidelines

```bash
/hackerone scopes.csv --guidelines "Test: XSS, SQLi, SSRF, JWT, IDOR. Out of scope: Clickjacking, Rate limiting. Required: X-HackerOne-Research header"
```

### Custom Output Directory

```bash
/hackerone scopes.csv --output ./my-reports/
```

## CSV Format

The skill expects HackerOne scope CSV export format:

```csv
identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,max_severity
example.com,URL,,true,true,critical
api.example.com,URL,,true,true,critical
*.example.com,WILDCARD,,true,true,high
10.0.0.0/8,CIDR,Internal network,true,true,medium
```

**Required columns:**
- `identifier` - The asset (URL, domain, IP range)
- `asset_type` - Type of asset
- `eligible_for_submission` - Must be "true" to test
- `max_severity` - Maximum allowed severity
- `instruction` - Optional asset-specific notes

## Output Structure

```
outputs/<program_name>/
├── findings/
│   ├── findings.json              # Machine-readable findings
│   ├── finding-001/
│   │   ├── report.md              # HackerOne report
│   │   ├── poc.py                 # Validated PoC
│   │   ├── poc_output.txt         # Proof of execution
│   │   ├── workflow.md            # Manual steps
│   │   └── description.md         # Attack details
│   └── finding-002/...
├── reports/
│   ├── submissions/
│   │   ├── H1_CRITICAL_001.md     # Ready to copy/paste
│   │   ├── H1_HIGH_001.md
│   │   └── H1_MEDIUM_001.md
│   ├── FINDINGS_SUMMARY.md        # Executive summary
│   └── SUBMISSION_GUIDE.md        # Submission instructions
└── evidence/
    ├── screenshots/
    ├── http-logs/
    └── videos/
```

## Workflows

### Workflow 1: HackerOne URL → Reports

1. Provide HackerOne program URL
2. Skill fetches program policy and scope
3. Downloads scope CSV automatically
4. Tests all assets in parallel
5. Validates PoCs and experiments
6. Generates submission-ready reports

### Workflow 2: CSV File → Reports

1. Provide CSV scope file path
2. Provide program guidelines (or be prompted)
3. Tests all assets in parallel
4. Validates PoCs
5. Generates reports

### Workflow 3: Ad-hoc Testing

1. Specify assets manually
2. Provide testing guidelines
3. Execute testing
4. Generate reports

## Examples

### Example 1: New Program Discovery

```bash
# You found a new HackerOne program
/hackerone https://hackerone.com/new-startup

# The skill will:
# - Fetch program details
# - Download scope CSV
# - Test all 15 assets in parallel
# - Generate 8 vulnerability reports
# - Estimated bounty: $12,000-$28,000
```

### Example 2: Weekly Testing

```bash
# You have a CSV from your favorite program
/hackerone my_favorite_program_scope.csv

# The skill will:
# - Parse 20 assets from CSV
# - Deploy 20 Pentester agents
# - Complete testing in 3 hours
# - Generate reports for 5 new findings
```

### Example 3: Focused Testing

```bash
# You want to test specific functionality
/hackerone --assets "api.example.com" \
           --guidelines "Focus on authentication: JWT, OAuth, session management" \
           --focus "authentication"

# The skill will:
# - Deploy authentication-focused agents
# - Test JWT vulnerabilities
# - Test OAuth flows
# - Test session management
# - Generate targeted reports
```

## Integration

This skill works with:
- **`/pentest` skill** - Core penetration testing knowledge base
- **Pentester agent** - Orchestration agent
- **30+ specialized agents** - Vulnerability-specific testing
- **Playwright MCP** - Browser automation
- **OUTPUT.md** - Standardized reporting

## Best Practices

### Program Selection

✅ **Target programs with:**
- Fast response times (< 24 hours)
- High bounty ranges (Critical: $5,000+)
- Large attack surface (10+ assets)
- New programs (< 30 days)

❌ **Avoid programs with:**
- Slow responses (> 1 week)
- Low bounties (Critical: < $500)
- Very restrictive scope
- Poor reputation

### Report Quality

✅ **Always include:**
- Working PoC with output
- Step-by-step reproduction
- Visual evidence
- Impact analysis
- Remediation guidance

❌ **Never include:**
- Real user data (sanitize!)
- Theoretical vulnerabilities
- Vague descriptions
- Missing reproduction steps

### Testing Ethics

✅ **Do:**
- Read program policy thoroughly
- Respect rate limits
- Stop at proof of concept
- Follow responsible disclosure
- Maintain professional communication

❌ **Don't:**
- Test out-of-scope assets
- Cause service disruption
- Extract excessive data
- Threaten public disclosure
- Rush untested submissions

## Troubleshooting

**Q: CSV parsing fails**
- A: Verify CSV has required columns and UTF-8 encoding

**Q: Agents not deploying**
- A: Ensure `/pentest` skill is available

**Q: PoCs failing**
- A: Run validation locally, check environment

**Q: Reports getting rejected**
- A: Review report quality checklist, validate PoCs

**Q: No findings generated**
- A: Check program scope, verify assets are accessible

## Reference

- [SKILL.md](SKILL.md) - Complete skill documentation
- [CLAUDE.md](CLAUDE.md) - Auto-loaded context
- [tools/csv_parser.py](tools/csv_parser.py) - CSV scope parser
- [tools/report_validator.py](tools/report_validator.py) - Report validator

## Contributing

This skill is part of the [communitytools](https://github.com/anthropics/communitytools) repository.

To contribute:
1. Create an issue describing the improvement
2. Fork and create a feature branch
3. Make changes following skill guidelines
4. Submit PR linking to issue

## License

See repository LICENSE file.

---

**Ready to start hunting bugs?**

```bash
/hackerone <program_url_or_csv_file>
```
