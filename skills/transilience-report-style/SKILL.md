---
name: transilience-report-style
description: Generate a Transilience-branded PDF report (pentest, vuln assessment, compliance, threat intel) from a single findings JSON using the bundled ReportLab generator. Use whenever an engagement needs its final report/deliverable PDF in Transilience house style.
---

# Transilience Report Style

Turns a structured findings JSON into a branded A4 PDF (dark theme, gradient rule, advisory cards, severity metrics) — the standard Transilience deliverable. The generator is data-driven: you assemble one JSON, run one command.

## When to use
- A pentest / vuln-assessment / network-scan / compliance engagement is finished and validated and needs its PDF deliverable.
- You already have findings (ideally validated) with severity + CVSS + evidence + remediation.

## How to use (3 steps)

1. **Write `report_data.json`** matching [`reference/report-data-schema.json`](reference/report-data-schema.json). Only `engagement` and `findings` are required; every other key (executive_summary, metrics, sections, cve_register, coverage_table, ruled_out, tools_used, roadmap, disclaimer) is an **optional section that is skipped if absent**. See [`reference/example-report-data.json`](reference/example-report-data.json) for a minimal working file.

2. **Run the generator:**
   ```bash
   python3 reference/generate_report.py <report_data.json> -o reports/My-Report.pdf
   ```
   Fonts + logo are auto-discovered from `formats/transilience-report-style/`. Override with `--assets <dir>` if running outside the repo. Requires `reportlab` (`pip install reportlab`).

3. **Verify** by rendering a page (`pdftoppm -png -r 100 -f 1 -l 1 out.pdf /tmp/p`) and reading it before delivery.

## What it renders
Cover (logo, title lines, subtitle, metadata) → Executive Summary (auto KPI metric boxes from severity counts + narrative + key risks + positives) → free-form `sections` (Scope/Methodology) → **finding cards grouped Critical→Info** (severity bar, CVSS+vector, CWE/OWASP, status, affected, description, evidence, impact, optional severity-calibration, optional **PoC/test block**, optional per-finding CVE table, remediation) → optional CVE register, coverage table, ruled-out appendix, **Tools & Techniques Used**, remediation roadmap, disclaimer. Section numbers are assigned automatically.

## Finding object (the important fields)
`id, title, severity (Critical|High|Medium|Low|Info), cvss_score, cvss_vector, cwe, owasp, affected[], description, evidence, impact, recommendation` + optional `poc_request, test_method, calibration, needs_live_confirmation, cves[]`. PAN/Aadhaar/card-like values are defensively masked at render time — but redact real secrets/PII in your source text anyway.

## Conventions
- Severity is set by the CVSS band (≥9 Critical, ≥7 High, ≥4 Medium, >0 Low, 0 Info) unless deliberately env-adjusted — state the calibration in the `calibration` field (see [`formats/transilience-report-style/pentest-report.md`](../../formats/transilience-report-style/pentest-report.md) §7).
- No emoji; text severity labels only. Finding metadata as fields, not prose.
- One finding = one validated issue. Group systemic instances rather than repeating near-duplicates.

## References
- Full visual design system (palette, typography, components): [`formats/transilience-report-style/SKILL.md`](../../formats/transilience-report-style/SKILL.md)
- Pentest report structure + finding-quality standard + severity calibration + compliance mapping: [`formats/transilience-report-style/pentest-report.md`](../../formats/transilience-report-style/pentest-report.md)
- Compliance variant: [`formats/transilience-report-style/compliance-report.md`](../../formats/transilience-report-style/compliance-report.md)
- Generator: [`reference/generate_report.py`](reference/generate_report.py) · Schema: [`reference/report-data-schema.json`](reference/report-data-schema.json) · Example: [`reference/example-report-data.json`](reference/example-report-data.json)
