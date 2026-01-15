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
│   └── finding-NNN.md   # Individual reports
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

**Every report MUST have**:
- Executive summary (2-3 sentences)
- Severity breakdown table
- Complete technical details
- Evidence references
- Remediation recommendations

See [FINDING_TEMPLATE.md](output-standards/reference/FINDING_TEMPLATE.md) for complete schema.

## Workflows

### Finding Generation Workflow

1. **During testing**: Collect findings in memory
2. **On discovery**: Capture evidence immediately (screenshots, HTTP)
3. **On completion**:
   - Generate findings.json
   - Create individual finding-NNN.md files
   - Generate executive-summary.md
   - Generate technical-report.md
   - Generate submission.md (if bug bounty)

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

## Validation

**Before completing, verify**:
- [ ] Directory structure created
- [ ] findings.json follows standard schema
- [ ] Individual .md reports generated
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
