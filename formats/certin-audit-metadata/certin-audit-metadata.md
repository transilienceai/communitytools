# CERT-In Audit Metadata Format (v2.3) — export spec

Export format for the **CERT-In Audit Metadata Format, Version 2.3 (July 2026)** — the
structured workbook a CERT-In-empanelled auditing organisation submits (alongside the audit
report) to `auditdata@cert-in.org.in` within 5 days of each first / final audit.

**TLP:AMBER handling.** The master template and the filled deliverable are marked TLP:AMBER by
CERT-In: they must not leave the recipient organisation or traverse public channels. The template is
therefore NOT redistributed in this repository — obtain it from CERT-In and point the builder at it
with `--template <path>` or the `CERTIN_TEMPLATE` environment variable. A *filled*
workbook contains client data — it is written ONLY under an engagement's `reports/` (client zone)
and is carried out-of-band via the engagement's AES-256 `protect_deliverable` flow. This folder
holds only the controlled vocabularies and the intermediate-JSON schema — no template, no filled workbook, no client data.

Produced by:
- `tools/certin_metadata_build.py` — deterministic builder (stdlib only; no LLM authors the bytes).
- `.claude/workflows/certin-export.js` — adds AI judgment (audit-type, sector/sub-sector, standards,
  per-finding Attributing Factor, challenges) then blind-verifies.
- auto-run (placeholders only) by `pentest-engagement` finalize when the scope sets `certin_export: true`.

## Per-sheet field list

The workbook has 6 visible sheets (+ 2 hidden option sheets, left byte-identical):

| Sheet | Rows | Fields |
|---|---|---|
| **1. Auditor Details** | responses C3:C7 | Org name · Data-validated-by (senior mgmt) · Designation · Email · Mobile |
| **2. Audits Completed** | one row/audit (from row 4) | SNO · AMBAK Audit No · Auditee org · Category · Sector · Sub-sector · Audit type · (specify if "Any other") · Infra/app/site details · AI-assisted? + LLM · Reason · Standards used · Challenges · First/Final · #vulns in FIRST audit · patch days · follow-up gap days · open issues · State/UT · completion date · last-audit date |
| **3. Security Issues-Technical** | one row/technical finding (from row 3) | SNO · AMBAK · org · infra · audit type · (specify) · First/Final · vuln name per CVE/CWE · CVE/CWE ref · CVSS severity · occurrence count · Attributing Factor |
| **4. Issues-Compliance** | one row/compliance finding (from row 3) | as sheet 3, but issue = non-compliance name per control-ID and ref = Clause/Control-ID + framework |
| **5. Manpower** | one row/auditor (from row 3) | SNO · AMBAK · name · email · CISSP/CISA/CISM/ISO/DISA/OSCP/CEH (Yes/No) · years experience |

## Pinned enum vocabularies

All controlled-vocabulary values live in **`enums.json`** (the single source of truth, extracted
verbatim from the template's hidden sheets by `tools/certin_extract_enums.py`). The builder
validates every emitted vocabulary value against it; no vocabulary values are re-pinned here or in
the schema. Keys: `category`, `sector` (a `sector → [subsectors]` map; canonical key = spaced
display form), `audit_type`, `reason`, `standards`, `state_ut`, `severity` (incl. `Informational`),
`attributing_factor`, `certifications`, `first_final`, `count_specials`.

## Intermediate-JSON schema

`reports/certin-audit-metadata.json` conforms to **`certin-metadata-schema.json`** (draft 2020-12,
structure only). Top level: `{ auditor_details, audits_completed[], security_issues_technical[],
issues_compliance[], manpower[], meta }`, where `meta = {sha256, source, template_version, tlp,
generated_from}` (clockless / deterministic).

## Field → engagement-artifact source map

- **Findings** are read from `reports/report_data.json` (preferred) or, as a fallback, the recursive
  glob `**/artifacts/validated/*.json` keeping only `verdict ∈ {VALID, REPAIRED}`.
- **Administrative fields** (AMBAK, auditor identity, auditee category/sector, reason, State/UT,
  dates, follow-up counts, manpower roster) come from `input/certin.json`.
- **Derived**: audit type (engagement kind/asset type; overridable); AI-assisted = `"Yes — Claude
  Opus 4.8 …"`; standards (Classify infers from coverage + methodology); severity mapped
  (`Info → Informational`); occurrence = `len(finding.affected)` (≥1); Attributing Factor = a
  CWE-default table (a CVE ⇒ "Vulnerable Software Versions"), overridden by Classify per finding;
  `#vulns in FIRST audit` = number of findings.
- **Routing**: a finding with `control_id` / `clause` / `type=="compliance"` → Issues-Compliance
  (this marker wins over a CWE); otherwise → Security Issues-Technical. Pure pentests leave the
  compliance sheet empty.
- **Manpower**: `certin.json.manpower[]` → rows; if absent, one AI-operator row is emitted and
  `manpower.auditor_name` is flagged in `needs_manual[]` so a named human auditor is added.

## Fill & validation rules

- **Coerce, never reject**: any absent required field, illegal enum value, or sub-sector not under
  its sector becomes the literal placeholder `"<FILL: <field>>"` and is listed in the build
  summary's `needs_manual[]`. Nothing is ever invented.
- **Redaction**: AWS keys, private keys, JWT/Bearer tokens, Indian PAN, Luhn-valid card PANs, and
  Aadhaar numbers are redacted in BOTH the JSON and the xlsx.
- **xlsx fidelity**: the builder copies the master workbook and injects rows via stdlib
  `zipfile` + targeted XML only — CERT-In's example rows are cleared; hidden option sheets,
  `dataValidations`, `mergeCells`, `xl/tables/table1.xml`, styles, and the 67 MB Auditor sheet's
  `<dimension>` are preserved byte-identical (cells are `inlineStr`; every value XML-escaped) so
  CERT-In's automated parser sees an unmodified structure.

## TLP:AMBER handling

The master template and every filled workbook are TLP:AMBER. Keep filled artifacts inside the
engagement `reports/` tree; deliver via the engagement's AES-256 protected package + out-of-band
password. Do not post to public channels.
