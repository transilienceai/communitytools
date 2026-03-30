# Output Structure Specification

Complete folder structure for pentest engagements. Conforms to Component Generation Framework rules.

## Root Structure

**Conforms to Component Generation Framework output standards:**

```
outputs/
├── components/                # TSX components + manifest.json (if generated)
│   ├── manifest.json
│   └── *.tsx                  # Any generated React components
├── data/                      # JSON data files
│   ├── pentest-report.json   # Machine-readable export
│   ├── reconnaissance/       # Phase 2 JSON data
│   │   ├── domains.json
│   │   ├── web-apps.json
│   │   ├── apis.json
│   │   ├── network.json
│   │   └── cloud.json
│   └── findings/             # Finding data (if structured as JSON)
│       └── finding-{NNN}.json
├── reports/                   # Markdown reports and final deliverables
│   ├── Penetration-Test-Report.docx      # Main report (Word document)
│   ├── Penetration-Test-Report.pdf       # Optional PDF export
│   ├── pentest-report-source.md         # Markdown source
│   ├── reconnaissance_report.md          # Phase 2 summary
│   ├── intermediate-reports/            # Drafts and working reports
│   │   ├── technical-analysis.md
│   │   └── executive-summary-draft.md
│   └── appendix/                        # Referenced evidence only
│       └── finding-{id}/
└── logs/                      # Execution logs
    ├── pentester-orchestrator.log       # Orchestrator decisions (NDJSON)
    ├── {executor-name}.log              # Per-executor activity logs (NDJSON)
    └── activity/                        # Alternative location
        └── *.log
```

**Optional working artifacts** (for complex engagements):
```
outputs/
└── processed/                 # Optional: Additional working/testing artifacts
    ├── reconnaissance/        # Phase 2 working files
    ├── findings/              # Phase 4 raw findings
    ├── helpers/               # Testing utilities
    └── test-frameworks/       # Testing scripts
```

## Phase-by-Phase Organization

### Phase 2: Reconnaissance

```
data/reconnaissance/
├── domains.json           # Subdomain enumeration results
├── web-apps.json          # Web application inventory
├── apis.json              # API discovery results
├── network.json           # Port scan results
└── cloud.json             # Cloud infrastructure (if applicable)

reports/
├── reconnaissance_report.md    # Summary report
└── intermediate-reports/
    ├── attack-surface.md      # Risk-prioritized attack vectors
    └── testing-checklist.md   # Executor deployment plan

processed/reconnaissance/  # Optional: Raw tool outputs
└── raw/                   # Tool outputs (nmap, ffuf, ZAP)
```

### Phase 4: Vulnerability Testing

```
data/findings/
└── finding-{NNN}.json    # Structured finding data (if JSON format)

reports/appendix/
└── finding-{id}/         # Evidence per finding
    ├── screenshot-1.png
    └── request.txt

processed/findings/        # Optional: Detailed finding folders
└── finding-{NNN}/         # One folder per finding
    ├── description.md
    ├── poc.py
    ├── poc_output.txt
    ├── workflow.md
    └── evidence/

logs/
├── pentester-orchestrator.log # Orchestrator decisions (NDJSON)
└── {executor-name}.log        # Per-executor activity logs (NDJSON)
```

### Phase 6: Final Reporting

```
reports/
├── Penetration-Test-Report.docx      # Professional Word document
├── Penetration-Test-Report.pdf       # PDF export (if generated)
├── pentest-report-source.md          # Markdown source (before .docx conversion)
├── reconnaissance_report.md          # Phase 2 summary
├── intermediate-reports/             # Drafts and working reports
│   ├── technical-analysis.md
│   └── executive-summary-draft.md
└── appendix/                         # Referenced evidence only
    ├── finding-001/                  # Evidence for finding 1
    │   ├── screenshot-exploit.png
    │   └── http-request.txt
    └── finding-002/                  # Evidence for finding 2

data/
├── pentest-report.json               # Machine-readable export
└── reconnaissance/                   # Phase 2 JSON data
    ├── domains.json
    ├── web-apps.json
    └── ...

logs/
├── pentester-orchestrator.log
└── {executor-name}.log

processed/                             # Optional: Additional working files
├── helpers/                          # Testing utilities
│   ├── auth_token_extractor.py
│   └── user_id_enumerator.py
└── test-frameworks/                  # Testing scripts
    ├── payment_api_tester.py
    └── authorization_tester.py
```

## File Manifest

**Components (if generated):**
- `components/manifest.json` - Component metadata
- `components/*.tsx` - React TSX components

**Data (JSON files):**
- `data/pentest-report.json` - Machine-readable export
- `data/reconnaissance/*.json` - Phase 2 JSON data (domains, web-apps, apis, network, cloud)
- `data/findings/*.json` - Structured finding data (if JSON format)

**Reports (Markdown, DOCX, PDF, evidence):**
- `reports/Penetration-Test-Report.docx` - Primary deliverable
- `reports/Penetration-Test-Report.pdf` - Optional PDF
- `reports/pentest-report-source.md` - Markdown source
- `reports/reconnaissance_report.md` - Phase 2 summary
- `reports/intermediate-reports/*.md` - Drafts and working reports
- `reports/appendix/{finding-id}/` - Evidence per finding

**Logs (Execution logs):**
- `logs/pentester-orchestrator.log` - Orchestrator decisions (NDJSON)
- `logs/{executor-name}.log` - Per-executor activity logs (NDJSON)

**Processed (Optional working artifacts):**
- `processed/reconnaissance/` - Phase 2 working files
- `processed/findings/` - Phase 4 raw findings
- `processed/helpers/` - Testing utilities (optional)
- `processed/test-frameworks/` - Testing scripts (optional)

## File Organization Rules

### What Goes in /components

**TSX components (if generated):**
- React TSX component files
- `manifest.json` - Component metadata

**Organization:**
- `components/manifest.json` - Component metadata
- `components/*.tsx` - Generated React components

### What Goes in /data

**All JSON data files:**
- Machine-readable report exports
- Reconnaissance inventory data
- Structured finding data

**Organization:**
- `data/pentest-report.json` - Machine-readable export
- `data/reconnaissance/*.json` - Phase 2 JSON data (domains, web-apps, apis, network, cloud)
- `data/findings/*.json` - Structured finding data (if JSON format)

### What Goes in /reports

**All markdown reports, DOCX/PDF deliverables, and evidence:**
- Final deliverables (DOCX, PDF)
- Markdown source files
- Intermediate/draft reports
- Evidence appendix

**Organization:**
- `reports/Penetration-Test-Report.docx` - Main report (Word document)
- `reports/Penetration-Test-Report.pdf` - Optional PDF
- `reports/pentest-report-source.md` - Markdown source (before .docx conversion)
- `reports/reconnaissance_report.md` - Phase 2 summary report
- `reports/intermediate-reports/*.md` - Drafts and working reports
- `reports/appendix/{finding-id}/` - Referenced evidence per finding

**CRITICAL: All reports and deliverables go here**
- Final deliverables (.docx, .pdf)
- Markdown source files
- Draft reports
- Evidence appendix

### What Goes in /logs

**All execution logs:**
- Orchestrator activity logs
- Executor activity logs
- NDJSON format logs

**Organization:**
- `logs/pentester-orchestrator.log` - Orchestrator decisions (NDJSON)
- `logs/{executor-name}.log` - Per-executor activity logs (NDJSON)
- `logs/activity/*.log` - Alternative location for activity logs

**CRITICAL: All execution logs go here**
- NDJSON format agent logs
- Activity tracking logs

### What Goes in /processed (Optional)

**Additional working and testing artifacts (for complex engagements):**
- Phase 2 reconnaissance working files
- Phase 4 raw findings folders
- Testing helper scripts
- Test frameworks requiring authentication

**Organization:**
- `processed/reconnaissance/` - Phase 2 working files (analysis, raw tool outputs)
- `processed/findings/` - Phase 4 raw findings (detailed folders with PoCs)
- `processed/helpers/` - Utility scripts
- `processed/test-frameworks/` - Testing frameworks

**CRITICAL: Optional directory for complex engagements**
- Use when detailed working files are needed
- Can be omitted for simpler engagements

## Report Generation

The coordination skill includes a template system for professional DOCX output:

- **Generator**: `tools/generate_reference_docx.py` -- creates/updates the styled reference template
- **Template**: `tools/reference.docx` -- pre-generated pandoc reference document with professional styles
- **Report spec**: `reference/FINAL_REPORT.md` -- summary-first document structure and pandoc commands

**Workflow**:
1. Write markdown source to `reports/pentest-report-source.md` (following FINAL_REPORT.md structure)
2. Convert with pandoc using `--reference-doc=../../.claude/skills/coordination/tools/reference.docx`
3. Post-process with `generate_reference_docx.py --post-process` for table styling and severity coloring

See `reference/FINAL_REPORT.md` for complete generation commands and the report template.

## Critical Rules

1. **Conforms to Component Generation Framework** - Follows standard output structure
2. **`components/`** - TSX components + manifest.json (if generated)
3. **`data/`** - All JSON data files (reports, reconnaissance, findings)
4. **`reports/`** - All markdown reports, DOCX/PDF deliverables, and evidence appendix
5. **`logs/`** - All execution logs (NDJSON agent logs)
6. **`processed/`** - Optional working artifacts for complex engagements
7. **Clean separation** - Data, reports, logs, and components are clearly separated
8. **No clutter** - Each folder has a specific purpose

## Migration (Existing Engagements)

```bash
# Create new structure conforming to Component Generation Framework
mkdir -p components data/reconnaissance data/findings reports/intermediate-reports reports/appendix logs processed/{reconnaissance,findings,helpers,test-frameworks}

# Move JSON data files → data/
mv report/pentest-report.json data/ 2>/dev/null
mv processed/reconnaissance/inventory/*.json data/reconnaissance/ 2>/dev/null
mv processed/findings/*.json data/findings/ 2>/dev/null

# Move reports and deliverables → reports/
mv report/Penetration-Test-Report.docx reports/ 2>/dev/null
mv report/Penetration-Test-Report.pdf reports/ 2>/dev/null
mv report/appendix reports/ 2>/dev/null
mv processed/intermediate-reports/*.md reports/intermediate-reports/ 2>/dev/null
mv processed/reconnaissance/reconnaissance_report.md reports/ 2>/dev/null
mv processed/reconnaissance/analysis/*.md reports/intermediate-reports/ 2>/dev/null

# Move logs → logs/
mv processed/activity/*.log logs/ 2>/dev/null

# Move optional working artifacts → processed/ (if needed)
mv processed/reconnaissance/raw processed/reconnaissance/ 2>/dev/null
mv processed/reconnaissance/analysis processed/reconnaissance/ 2>/dev/null

# Clean up old structure
rmdir report 2>/dev/null
rmdir processed/activity 2>/dev/null
rmdir processed/intermediate-reports 2>/dev/null
```
