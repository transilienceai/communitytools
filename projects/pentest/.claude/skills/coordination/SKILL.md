---
name: coordination
description: Pentest engagement orchestration - workflow management, test planning, reporting, and output structure coordination.
---

# Coordination

Orchestrate penetration testing engagements. Manage 7-phase workflow, deploy executors, validate findings, aggregate results, generate reports.

## Workflow

1. **Initialization** - Gather scope, create `outputs/`
2. **Reconnaissance** - Deploy recon executors, generate inventory (see `reference/RECONNAISSANCE_OUTPUT.md`); **always** run `/osint` skill in parallel for repository and code exposure analysis
3. **Planning** - Create test plan and proceed immediately to testing
4. **Vulnerability Testing** - Deploy executors in parallel with `run_in_background=True`
4.5. **Validation** - Cross-validate findings against raw evidence (see `reference/VALIDATION.md`)
5. **Aggregation** - Collect VALIDATED findings only, deduplicate, identify exploit chains, calculate severity
6. **Reporting** - Generate Transilience branded PDF report using `transilience-report-style` skill + JSON export (see `reference/FINAL_REPORT.md`)

## Output Structure

See `reference/OUTPUT_STRUCTURE.md` for complete specification.

**Conforms to Component Generation Framework:**

```
outputs/
├── components/    # TSX components + manifest.json (if generated)
├── data/          # JSON data files (reports, reconnaissance, findings)
├── reports/       # Transilience branded PDF report, markdown source, evidence appendix
└── logs/          # Execution logs (NDJSON agent logs)
```

**Optional**: `processed/` for additional working artifacts in complex engagements.

**Critical**: Conforms to Component Generation Framework rules - data in `data/`, reports in `reports/`, logs in `logs/`.

## Methodologies

- **PTES** - 7-phase engagement lifecycle
- **OWASP WSTG** - 11 testing categories
- **MITRE ATT&CK** - TTP mapping
- **Flaw Hypothesis** - Stack → Predict → Test → Generalize

## Reference

- `reference/ATTACK_INDEX.md` - 53 attack types with agent mappings
- `reference/OUTPUT_STRUCTURE.md` - Output folder organization
- `reference/RECONNAISSANCE_OUTPUT.md` - Recon output format and JSON schemas
- `reference/FINAL_REPORT.md` - Report structure and Transilience branded PDF generation via `transilience-report-style` skill
- `reference/VALIDATION.md` - Finding validation workflow, anti-hallucination checks

## Tools

- **`transilience-report-style` skill** — Generates the final branded PDF report. See `reference/FINAL_REPORT.md` for the pentest-specific adaptation of the design system (finding → advisory card mapping, severity → score mapping, section blueprint)
- `tools/generate_reference_docx.py` - Legacy DOCX template generator (deprecated — use `transilience-report-style` skill for PDF instead)
- `tools/reference.docx` - Legacy pandoc reference template (deprecated)
- Finding validation is handled by the `pentester-validator` agent (deployed per-finding by orchestrator during Phase 4.5)

## Rules

1. Never execute attacks directly - delegate to specialized executors
2. Always proceed immediately to Phase 4 after plan creation
3. Verified PoCs only - no theoretical findings
4. Clean output structure - verify with `ls -la outputs/`
5. Always deploy pentester-validator agents (Phase 4.5) before aggregation - never include unvalidated findings
