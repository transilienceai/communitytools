---
name: transilience-report-style
description: Generate a Transilience-branded PDF report (pentest, vuln assessment, compliance, threat intel) from a single findings JSON using the bundled ReportLab generator. Use whenever an engagement needs its final report/deliverable PDF in Transilience house style.
---

# Transilience Report Style

Turns a structured findings JSON into a branded A4 PDF (**light theme** by default — modern/minimal; `--theme dark` fallback; brand gradient rule, boxed code/samples, framed screenshots, colour-coded severity + CVSS-score, findings cards, severity metrics) — the standard Transilience deliverable. The generator is data-driven: you assemble one JSON, run one command. Design system: [`formats/transilience-report-style/SKILL.md`](../../formats/transilience-report-style/SKILL.md) §0 (theme/palette).

## When to use
- A pentest / vuln-assessment / network-scan / compliance engagement is finished and validated and needs its PDF deliverable.
- You already have findings (ideally validated) with severity + CVSS + evidence + remediation.

## How to use (3 steps)

1. **Write `report_data.json`** matching [`reference/report-data-schema.json`](reference/report-data-schema.json). Only `engagement` and `findings` are required; every other key (executive_summary, metrics, sections, cve_register, coverage_table, attack_pattern_coverage, ruled_out, tools_used, roadmap, disclaimer) is an **optional section that is skipped if absent**. See [`reference/example-report-data.json`](reference/example-report-data.json) for a minimal working file.
   - **Internal-only sections:** a `sections[]` entry with `"internal": true` is retained in `report_data.json` (kept as the internal record) but is **never rendered into the client PDF**. Use it for internal QA logs such as blind-validation / independent-reproduction verdict tables — these must not appear in any client-facing PDF.

2. **Run the generator:**
   ```bash
   python3 reference/generate_report.py <report_data.json> -o reports/My-Report.pdf
   ```
   Fonts + logo are auto-discovered from `formats/transilience-report-style/`. Override with `--assets <dir>` if running outside the repo. Requires `reportlab` (`pip install reportlab`).

3. **Verify** by rendering a page (`pdftoppm -png -r 100 -f 1 -l 1 out.pdf /tmp/p`) and reading it before delivery.

### Other editions of the same data
- **Executive edition** — `generate_report.py <data.json> --exec-only` renders cover + KPI boxes + narrative + roadmap and **no** finding detail or technical registers, for circulation beyond the security team. The KPI counts still describe the whole engagement.
- **Machine-readable exports** — `python3 ../../tools/report_export.py <data.json> --format csv|xml -o findings.csv` emits the findings register for a vulnerability-management import. Same rows as the PDF register and the xlsx: one projection, three renderings.

## What it renders
Cover (logo, title lines, subtitle, metadata) → Executive Summary (auto KPI metric boxes from severity counts + narrative + key risks + positives) → free-form `sections` (Scope/Methodology) → **finding cards grouped Critical→Info** (severity bar, CVSS+vector, CWE/OWASP, status, affected, description, impact, optional **PoC block** — ordered steps each with prose + code-styled command + embedded screenshot, optional severity-calibration, optional per-finding CVE table, remediation) → optional CVE register, coverage table, **Attack Pattern Coverage** (deterministic surface-unit × attack-class matrix with colour-coded status), ruled-out appendix, **Tools & Techniques Used**, remediation roadmap, disclaimer. Section numbers are assigned automatically.

## Finding object (the important fields)
`id, title, severity (Critical|High|Medium|Low|Info), cvss_score, cvss_vector, cwe, owasp, affected[], description, impact, recommendation` + optional `poc[], calibration, needs_live_confirmation, cves[], attack[]`. **`attack[]`** carries MITRE technique ids — ATT&CK (`T1190`, `T1059.001`) or, for AI/LLM findings that have no ATT&CK technique, ATLAS (`AML.T0051`); it renders beside CWE/OWASP and appears in every export. **`poc`** is an ordered list of steps `{description, command, image_url}` (it merges the former evidence / poc_request / screenshot fields): each renders as a numbered prose description, an optional code-styled command, and an optional embedded image. PAN/Aadhaar/card-like values are defensively masked at render time — but redact real secrets/PII in your source text anyway.

## Conventions
- Severity is set by the CVSS band (≥9 Critical, ≥7 High, ≥4 Medium, >0 Low, 0 Info) unless deliberately env-adjusted — state the calibration in the `calibration` field (see [`formats/transilience-report-style/pentest-report.md`](../../formats/transilience-report-style/pentest-report.md) §7).
- No emoji; text severity labels only. Finding metadata as fields, not prose.
- One finding = one validated issue. Group systemic instances rather than repeating near-duplicates.

## References
- Full visual design system (palette, typography, components): [`formats/transilience-report-style/SKILL.md`](../../formats/transilience-report-style/SKILL.md)
- Pentest report structure + finding-quality standard + severity calibration + compliance mapping: [`formats/transilience-report-style/pentest-report.md`](../../formats/transilience-report-style/pentest-report.md)
- Compliance variant: [`formats/transilience-report-style/compliance-report.md`](../../formats/transilience-report-style/compliance-report.md)
- Generator: [`reference/generate_report.py`](reference/generate_report.py) · Schema: [`reference/report-data-schema.json`](reference/report-data-schema.json) · Example: [`reference/example-report-data.json`](reference/example-report-data.json)
- Preflight lint (hard-fail schema + RAW-field escaping/tag-allowlist gate before rendering): [`../../tools/report_data_lint.py`](../../tools/report_data_lint.py) — run before `generate_report.py`; it (and the generator's own `report_data_shape` guard) block a string-narrative, an invalid severity, or an unsafe `<img>`/`<a href>` from reaching a client PDF.
- In-place revision (append / supersede / `--rescore <disposition.csv>` / `--scope <allowlist>` restrict+renumber / cross-feed; always re-derives KPIs + scrubs narrative finding-counts): [`../../tools/report_data_revise.py`](../../tools/report_data_revise.py) — the incremental-revision entry point, distinct from merge-reports' N→1 consolidation.
- Ingest a finished/foreign report (PDF/xlsx/DOCX/markdown/native JSON) into the canonical finding schema: [`../../tools/report_ingest.py`](../../tools/report_ingest.py) — bootstraps merge / retest / CERT-In from an already-produced deliverable instead of hand re-keying.
