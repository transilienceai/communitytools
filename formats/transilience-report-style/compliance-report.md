# PCI SSS v2.0 Gap-Assessment Report — Transilience Style

Adapts the Transilience design system (SKILL.md) for a PCI Secure Software Standard (SSS) **v2.0** readiness gap-assessment. Produces a per-Test-Requirement verdict report with cited evidence — **not** an official PCI validation.

**Source**: `{OUTPUT_DIR}/reports/compliance-report-source.md` + `{OUTPUT_DIR}/artifacts/compliance-report.json`
**Output**: `{OUTPUT_DIR}/reports/Compliance-Assessment-Report.pdf`
**Design**: `formats/transilience-report-style/SKILL.md`
**Logo**: `formats/transilience-report-style/transilience-logo.png`
**Skill spec**: `skills/pci-secure-software/reference/reporting/gap-report.md`

---

## 0. Mandatory disclaimer (cover + every artifact)

> This is an automated **readiness gap-analysis** against PCI Secure Software Standard v2.0. It is **NOT an official PCI validation**. The PCI SSS defines no In-Place/Not-in-Place marking scheme; official marking occurs solely in the ROV/AOV templates assessed by a qualified PCI Secure Software Assessor.

Render it as a banner on the cover and a footer/intro line in every artifact. Never omit it.

---

## 1. Output Directory

```
{OUTPUT_DIR}/reports/
├── Compliance-Assessment-Report.pdf   # Primary deliverable
├── compliance-report-source.md        # Markdown source
├── build_report.py                    # ReportLab generator (written + run per engagement)
└── tracker.csv                        # Per-requirement tracker
{OUTPUT_DIR}/artifacts/
├── compliance-report.json             # Machine-readable export
├── status-rollup.json                 # Per-objective + overall counts
├── coverage.json                      # Coverage ratio + missing ids
└── quarantined.json                   # Citation-verification failures
```

---

## 2. Generation Workflow

1. Aggregate `artifacts/validated/*.json` + `coverage.json` + `status-rollup.json` + `applicability/decisions.json` into `artifacts/compliance-report.json` (Section 8). Downgraded/false-positive verdicts appear ONLY as REQUIRES_MANUAL_REVIEW in Coverage & Limitations — never as MET.
2. Write `reports/compliance-report-source.md` (Section 4) and `reports/tracker.csv` (Section 9).
3. Read `formats/transilience-report-style/SKILL.md`; write + run `reports/build_report.py` (ReportLab `BaseDocTemplate`, register Carlito/Poppins from `formats/transilience-report-style/fonts/`, footer `TRANSILIENCE AI · PCI SSS v2.0 Gap Assessment · CONFIDENTIAL`) → `reports/Compliance-Assessment-Report.pdf`.

Gates: refuse a COMPLETE report unless `coverage.json.coverage_ratio == 1.0` with empty `missing_ids`, and no MET/NOT_MET row has `citation_verified:false`.

---

## 3. Section Blueprint Adaptation

The base design system targets threat intelligence. Adapt sections for compliance:

| Base Section | Compliance Adaptation |
|---|---|
| 01 Executive Summary | Executive Summary — disclaimer banner, status counts, %MET by objective, applicability summary |
| 02 Threat Landscape | Scope & Applicability — modules/objectives in scope with per-unit evidence |
| 03 Threat Radar | Objective Posture Radar — %MET per Security Objective |
| 04-06 Severity Advisories | Results by Objective — per-requirement verdict tables (status-colored) |
| 07 Attack Surface Analysis | Coverage & Limitations — manual-review / dynamic-not-run / quarantined disclosure |
| 08 Asset Inventory | Declared Sensitive Assets (PAN/SAD/keys/PII) |
| 09 Technology Stack | Technology Stack — languages, frameworks, datastores, crypto libs |
| 10 Security Posture | Prioritized Remediation Roadmap |
| 11 Strategic Recommendations | Remediation Roadmap (Immediate/Short/Medium-term) |
| 12 Methodology & Sources | Methodology & Chain-of-Custody — catalog version+sha, pipeline, citation verifier |

---

## 4. Report Structure (Summary-First)

### Part I — Summary
- Cover page (app, dates, classification CONFIDENTIAL, prepared by/for) + the disclaimer banner.
- Executive summary (≤2 pages): overall status counts (MET / NOT_MET / PARTIALLY_MET / NOT_APPLICABLE / REQUIRES_MANUAL_REVIEW), %MET by objective, applicability summary, top remediation priorities.

### Part II — Scope & Applicability
- App, source/docs/BOM paths, running-instance availability, declared sensitive assets.
- Per-unit APPLICABLE/NOT_APPLICABLE table; each NOT_APPLICABLE row shows the negative-evidence quote that excluded it.

### Part III — Assessment Results by Objective
- One sub-section per applicable Security Objective.
- Per-requirement table (Section 6).

### Part IV — Coverage & Limitations
- Explicit counts + lists of every REQUIRES_MANUAL_REVIEW (with reason), dynamic-not-run, and quarantined (with failed citation) item. The coverage-ratio statement (must be 1.0 for COMPLETE).

### Part V — Remediation & Methodology
- Prioritized remediation roadmap (NOT_MET + PARTIALLY_MET ranked).
- Methodology & chain-of-custody appendix; full disclaimer; PCI SSC reference.

---

## 5. Status Model & Palette

No CVSS. The unit is a **Test Requirement verdict**. Use text labels (no emoji) with the design-system palette repurposed:

| Status | Meaning | Palette |
|---|---|---|
| MET | control present + proven by cited evidence | emerald `#10B981` |
| PARTIALLY_MET | some lettered sub-conditions met, others not | amber `#F59E0B` |
| NOT_MET | control absent/insufficient (gap cited) | red `#EF4444` |
| REQUIRES_MANUAL_REVIEW | could not be honestly proven (dynamic-not-run, ambiguous, quarantined) | blue `#3B82F6` |
| NOT_APPLICABLE | excluded by AppContext, with negative evidence | muted/grey |

Every MET/NOT_MET row carries its `Evidence (file:line)` citation; the deterministic verifier has confirmed it (`citation_verified:true`).

---

## 6. Per-Requirement Table (Results by Objective)

```markdown
#### Security Objective {N} — {Title}   ({pct_met}% MET)

| Req ID | Requirement | Status | Evidence (file:line) | Why | Remediation |
|--------|-------------|--------|----------------------|-----|-------------|
| 5-3.3.1.c | {test_requirement_text, trimmed} | MET | `src/audit.py:88` | {why} | — |
| 5-4.1.b   | {…} | NOT_MET | `src/authz.py:42` | {gap} | {fix} |
```

- `Req ID` is the catalog `id`. `Requirement` is the test-requirement text (or the parent requirement text, trimmed).
- For multi-evidence requirements, show the primary citation; the full set is in `compliance-report.json`.
- Roll the per-letter verdicts up to a per-Security-Requirement status line where helpful (MET/NOT_MET/PARTIALLY_MET), per the schema rollup ladder.

---

## 7. Verdict Calibration

- A status reflects the **root-cause** state of the control, not an incidental condition. A control that is genuinely implemented but happens to be unused in the current build is still MET if the implementation is sound; a control that is absent is NOT_MET even if "not currently exploitable."
- A requirement whose evaluation needs dynamic analysis that was not performed is `REQUIRES_MANUAL_REVIEW` — it is never recorded MET from documentation alone.
- A `NOT_APPLICABLE` requires the negative evidence that excluded its Module/objective; absent that, it is `REQUIRES_MANUAL_REVIEW`.
- Never inflate %MET by omitting hard-to-evaluate requirements — they appear as REQUIRES_MANUAL_REVIEW.

---

## 8. JSON Export Schema

Generate `{OUTPUT_DIR}/artifacts/compliance-report.json` (full schema in `skills/pci-secure-software/reference/reporting/gap-report.md`). Skeleton:

```json
{
  "assessment": { "app_name": "{app}", "standard": "PCI Secure Software Standard v2.0",
                  "catalog_version": "1.0.0", "catalog_sha256": "{sha}", "date": "{YYYY-MM-DD}",
                  "compliance_status": "COMPLETE", "coverage_ratio": 1.0, "disclaimer": "{...}" },
  "applicability": { "modules": ["core","A","C"], "objectives_applicable": ["4","7"],
                     "decisions": [ { "scope_unit": "module:A", "decision": "APPLICABLE",
                       "why": "{...}", "evidence": [ { "file": "{f}", "line": 42, "quote": "{q}", "kind": "positive" } ] } ] },
  "rollup": { "overall": { "applicable": 0, "MET": 0, "NOT_MET": 0, "PARTIALLY_MET": 0,
                           "NOT_APPLICABLE": 0, "REQUIRES_MANUAL_REVIEW": 0, "pct_met": null },
              "by_objective": {} },
  "requirements": [ { "req_id": "5-3.3.1.c", "objective": "5", "requirement_id": "5-3.3.1",
                      "requirement_text": "{...}", "test_requirement_text": "{...}",
                      "test_method": "Examine", "analysis_type": "static", "module": "core",
                      "status": "MET", "evidence": [ { "file": "{f}", "line": 88, "quote": "{q}", "polarity": "supports_met" } ],
                      "why": "{...}", "remediation": "", "citation_verified": true,
                      "downgraded_from": null, "votes": 3, "refuted_count": 0, "proof_dir": "findings/5-3.3.1.c/evidence/" } ],
  "limitations": { "requires_manual_review": [ { "req_id": "{id}", "reason": "dynamic analysis required, no running instance" } ],
                   "dynamic_not_run": [ { "req_id": "{id}" } ],
                   "quarantined": [ { "req_id": "{id}", "failed_citation": { "file": "{f}", "line": 0, "quote": "{q}" } } ] }
}
```

---

## 9. tracker.csv Columns (exact)

```
req_id,objective,requirement_text,status,evidence_file,evidence_line,quoted_evidence,why,remediation,citation_verified
```
One row per applicable Test Requirement.

---

## 10. Quality Checklist

Run before delivery:

- [ ] Cover + every artifact carry the "not an official PCI validation" disclaimer.
- [ ] Coverage ratio is 1.0; no applicable requirement is missing a verdict.
- [ ] No MET/NOT_MET row has empty evidence or `citation_verified:false`.
- [ ] Coverage & Limitations lists every REQUIRES_MANUAL_REVIEW / dynamic-not-run / quarantined item with counts.
- [ ] No emoji — text status labels only.
- [ ] Requirement metadata in tables, not bullet lists.
- [ ] Catalog version + sha recorded in the methodology appendix.
- [ ] Sensitive data (PAN/SAD) redacted in any quoted evidence.

---

## 11. Industry References

- **PCI Secure Software Standard v2.0** — PCI Security Standards Council.
- **PCI Software Security Framework (SSF)** — Secure SLC + Secure Software programs.
- **PCI SSS Sensitive Asset Identification** (companion document).
- **PCI Data Security Standard (latest)** — referenced by Module A.
- **PCI SSS ROV / AOV Templates** — where official marking occurs.

---

## Rules

1. PDF generation: always use `formats/transilience-report-style/SKILL.md` (ReportLab) — no DOCX, no pandoc.
2. Disclaimer on the cover and in every artifact — this is a gap-analysis, not a validation.
3. Summary first — executives should not scroll past page 5.
4. Requirement metadata in tables, not bullet lists.
5. No emoji — text status labels only (MET / NOT_MET / PARTIALLY_MET / NOT_APPLICABLE / REQUIRES_MANUAL_REVIEW).
6. A MET status requires verified cited evidence; a downgraded claim appears only as REQUIRES_MANUAL_REVIEW.
7. Never inflate %MET by omitting requirements — every applicable requirement is in the report.
