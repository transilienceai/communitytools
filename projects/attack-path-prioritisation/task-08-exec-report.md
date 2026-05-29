# Task 08 — Executive Report Generator

**Project**: attack-path-prioritisation (board-level deliverable)
**Trigger**: Cron weekly (Fridays 14:00 UTC), or prompt-invoked when an analyst wants an out-of-cycle report (typically after task-07 reports a new `immediate` bucket entry).
**Skill**: Reuses `formats/transilience-report-style/pentest-report.md` + ReportLab pipeline.

## Inputs

- `OUTPUT_DIR`
- Requires: `artifacts/attack-paths-ranked.json` (task-07), `artifacts/org-surface.json` (task-05), `artifacts/attack-paths.json` (task-06).
- Optional: `artifacts/regression-{YYYYWww}.json` from attacks-validation task-04. Pulled at step 1 via `tools/fetch-regression-summaries.py` (separate-session model: attacks-validation and attack-path-prioritisation do not share a filesystem). If the attacks-validation project has not yet produced one, the report is rendered without drift annotations.

## Procedure

The base format `formats/transilience-report-style/pentest-report.md` is engagement-scoped. This task runs an **org-wide variant**: the same sections, but the unit of analysis is the *ranked attack path*, not a single engagement's findings.

1. Pull the latest attacks-validation regression summary (optional input — drift annotations only):
   ```
   python3 tools/fetch-regression-summaries.py --output-dir "$OUTPUT_DIR"
   ```

   | Tool status | task-08 action |
   |---|---|
   | `OK` | Continue; reference the pulled `artifacts/regression-{YYYYWww}.json` for drift annotations on each Attack Path Card. |
   | `NOOP` (no attacks-validation session yet, or no regression-*.json produced) | Continue; render the report without drift annotations. |
   | `FAILED` | Continue; render the report without drift annotations. Log the error in the task-08 status emit's `warnings` field but do **not** propagate as task-08 FAILED — the regression summary is optional. |

2. Read `pentest-report.md`'s Section Blueprint Adaptation. The mapping for this org variant:

   | Base section | Org-wide adaptation |
   |---|---|
   | 01 Executive Summary | Top-3 attack paths from `immediate` bucket + total counts per bucket |
   | 02 Findings Overview | Findings by OWASP category, aggregated across all assets |
   | 03 Threat Radar → Attack Surface Radar | Same; populate from `org-surface.json` zones × severity |
   | 04-06 Severity Advisories → **Attack Path Cards** | One card per ranked path in `immediate` + `short_term` |
   | 07 Attack Surface Analysis | Scope = entire asset inventory |
   | 09 Technology Stack | Aggregated from `recon/{asset}/techstack.json` |
   | 11 Strategic Recommendations | Roadmap from bucket assignments (Immediate 0-7d, Short 7-30d, Medium 30-90d) |
   | 12 Methodology | PTES + OWASP WSTG + Transilience multi-agent pipeline (cite tasks 01-07) |

3. Generate `$OUTPUT_DIR/reports/pentest-report-source.md` using the adaptation above.

4. Generate `$OUTPUT_DIR/artifacts/pentest-report.json` (machine-readable summary the design system consumes).

5. Run the ReportLab pipeline per `formats/transilience-report-style/SKILL.md` to produce the PDF.

6. Output path: `$OUTPUT_DIR/reports/Org-Attack-Posture-{YYYYWww}.pdf`.

## Outputs

- `$OUTPUT_DIR/reports/pentest-report-source.md`
- `$OUTPUT_DIR/artifacts/pentest-report.json`
- `$OUTPUT_DIR/reports/Org-Attack-Posture-{YYYYWww}.pdf` — primary deliverable

## Attack Path Card structure

Each card replaces the per-finding "Advisory Card" from the engagement variant:

- **Title**: short path summary (`web01 → app03 → db_finance`)
- **Severity**: bucket name + numeric score
- **Hops**: ordered list, each hop with finding ID + detector
- **Business impact**: destination asset's tier + brief rationale
- **Evidence**: link to validator's `evidence/validation/validation-summary.md` for the limiting finding
- **Remediation focus**: the single asset whose fix breaks the chain (from `risk-prioritiser`'s `remediation_focus` field)
- **CVSS chain max**: max CVSS along the path
- **Feasibility**: product of edge feasibilities

## Constraints

- Do NOT re-validate findings. The report is purely a render of pre-existing artifacts.
- Use the **most recent** `attack-paths-ranked.json`. If it's older than 36 hours, emit `BLOCKED_REASON: ranked artifact stale — fire task-07 first` and exit.
- Page count guideline: 30-50 pages. If the report exceeds 60 pages, truncate `short_term` cards (keep `immediate` and `medium_term` summary table; full cards in appendix).

## Status emit

```json
{"task": "exec-report", "status": "OK",
 "report": "reports/Org-Attack-Posture-2026W19.pdf",
 "pages": 42, "cards_rendered": 15,
 "outputs": ["reports/Org-Attack-Posture-2026W19.pdf"],
 "next": []}
```
