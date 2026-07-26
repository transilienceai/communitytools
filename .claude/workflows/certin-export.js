export const meta = {
  name: 'certin-export',
  description: 'Generate the CERT-In Audit Metadata Format (v2.3) deliverables from a finished engagement — an intermediate JSON mirroring the workbook fields plus a filled copy of the official xlsx. Adds AI judgment (per-finding Attributing Factor, sector/sub-sector classification, standards inference, challenges) on top of the deterministic tools/certin_metadata_build.py, then blind-verifies the result. Produced alongside the normal report, never replacing it.',
  whenToUse: 'Run for a CERT-In-empanelled audit deliverable. args: {output_dir (required, the engagement dir), certin? (inline admin config → input/certin.json), first_final?, dryRun?}. The deterministic builder is also auto-run (placeholders-only) by pentest-engagement finalize when certin_export:true — use THIS workflow when you want the judgment fields filled.',
  phases: [
    { title: 'Gather', detail: 'inventory findings, engagement meta, existing certin.json, follow-up counts, coverage matrix' },
    { title: 'Classify', detail: 'one batched agent: audit-type, sector/sub-sector, standards, per-finding Attributing-Factor overrides, challenges → certin-overrides.json' },
    { title: 'Build', detail: 'run tools/certin_metadata_build.py (deterministic) with the overrides; relay facts' },
    { title: 'Verify', detail: 'blind agent re-opens the JSON + xlsx: every finding accounted for, enums legal, xlsx well-formed' },
  ],
}

// ============================================================================
// CERT-IN EXPORT — reusable, client-neutral deliverable workflow.
//
// The structured bytes are owned by tools/certin_metadata_build.py (deterministic,
// stdlib-only, enum-validated against formats/certin-audit-metadata/enums.json). No
// LLM authors the JSON/xlsx. Agents only: inventory files, author the judgment-only
// overrides file, RUN the builder and relay its printed summary, and blind-verify.
//
// Sandbox: no import/require, no Date.now()/Math.random()/new Date() — agents shell
// out. Every agent() is .catch()-wrapped; the workflow returns a status object.
//
// dryRun: runs all four phases (the builder is deterministic with no external side
// effects / cloud spend / Slack), producing the artifacts so Verify can open them —
// a documented deviation from the "short-circuit before agents" convention.
// ============================================================================

const a = (args && typeof args === 'object' && !Array.isArray(args)) ? args : {}
const OUTPUT_DIR = (a.output_dir || a.engagement_dir || '').replace(/\/+$/, '')
const DRY = !!a.dryRun
const FIRST_FINAL = a.first_final || null
const CERTIN_INLINE = (a.certin && typeof a.certin === 'object') ? a.certin : null

if (!OUTPUT_DIR) {
  log('certin-export: no output_dir provided')
  return { status: 'ERROR', reason: 'output_dir is required' }
}

const ENUMS = 'formats/certin-audit-metadata/enums.json'
const OVERRIDES = `${OUTPUT_DIR}/reports/certin-overrides.json`
const CERTIN_JSON = `${OUTPUT_DIR}/reports/certin-audit-metadata.json`
const CERTIN_XLSX = `${OUTPUT_DIR}/reports/CERT-In-Audit-Metadata.xlsx`

const GATHER_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['findings_count', 'findings_source'],
  properties: {
    findings_count: { type: 'number' },
    findings_source: { type: 'string', description: 'report_data.json | artifacts/validated | none' },
    target: { type: ['string', 'null'] },
    engagement_kind: { type: ['string', 'null'], description: 'web | network | unknown' },
    existing_certin: { type: 'boolean', description: 'input/certin.json present' },
    coverage_matrix_present: { type: 'boolean' },
    followup: { type: 'object', additionalProperties: true },
    cwe_defaults: { type: 'array', items: { type: 'object', additionalProperties: true }, description: 'per finding {id,title,cwe,cves,default_factor}' },
  },
}

const CLASSIFY_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['overrides_written'],
  properties: {
    overrides_written: { type: 'boolean' },
    overrides_path: { type: 'string' },
    audit_type: { type: ['string', 'null'] },
    sector: { type: ['string', 'null'] }, subsector: { type: ['string', 'null'] },
    standards: { type: 'array', items: { type: 'string' } },
    attributing_overrides: { type: 'number' },
    challenges: { type: ['string', 'null'] },
    illegal_values_dropped: { type: 'array', items: { type: 'string' } },
  },
}

const BUILD_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['certin_ok', 'technical', 'compliance'],
  properties: {
    certin_ok: { type: 'boolean' },
    out: { type: ['string', 'null'] }, xlsx: { type: ['string', 'null'] },
    technical: { type: 'number' }, compliance: { type: 'number' }, audits: { type: 'number' },
    needs_manual: { type: 'array', items: { type: 'string' } },
    sha256: { type: ['string', 'null'] }, exit_nonzero_reason: { type: ['string', 'null'] },
  },
}

const VERIFY_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['status', 'certin_json', 'certin_xlsx', 'findings_count', 'needs_manual'],
  properties: {
    status: { type: 'string', description: 'OK | ISSUES' },
    certin_json: { type: ['string', 'null'] },
    certin_xlsx: { type: ['string', 'null'] },
    findings_count: { type: 'number' },
    needs_manual: { type: 'array', items: { type: 'string' } },
  },
}

// If inline certin config was supplied, materialize it to input/certin.json first
// (mirrors the pentest-engagement Setup behavior for standalone runs).
if (CERTIN_INLINE) {
  await agent(
    `ROLE: config writer. cwd is repo root. Write this exact JSON to ${OUTPUT_DIR}/input/certin.json (mkdir -p first); do not add or infer any field:\n${JSON.stringify(CERTIN_INLINE, null, 2)}\nReturn {"written":true}.`,
    { label: 'certin:config', phase: 'Gather', schema: { type: 'object', additionalProperties: true, required: ['written'], properties: { written: { type: 'boolean' } } } }
  ).catch(() => null)
}

// ---- Phase 1: Gather -------------------------------------------------------
phase('Gather')
const inv = await agent(
  `ROLE: GATHER (read-only inventory). cwd is repo root. Engagement dir: ${OUTPUT_DIR}.\n` +
  `1. Findings source: if ${OUTPUT_DIR}/reports/report_data.json exists and parses, findings_source="report_data.json" and findings_count=len(.findings); else count ${OUTPUT_DIR}/**/artifacts/validated/*.json with verdict in {VALID,REPAIRED} (findings_source="artifacts/validated"); else 0 and "none".\n` +
  `2. From ${OUTPUT_DIR}/engagement-meta.json and ${OUTPUT_DIR}/engagement-scope.json (either may be absent): target, engagement_kind (network iff scope has targets and no apex_domains, else web), followup = {resume_round, supersedes, first_audit_count?}.\n` +
  `3. existing_certin = ${OUTPUT_DIR}/input/certin.json exists. coverage_matrix_present = ${OUTPUT_DIR}/reports/coverage-matrix.json exists.\n` +
  `4. cwe_defaults: for each finding output {id, title, cwe, cves:[ids], default_factor} where default_factor = "Vulnerable Software Versions" if it has any CVE, else a best-guess Attributing Factor from its CWE (one of: Coding Error, Configuration Error, Deployment Error, Design Error, Operation Error, Vulnerable Software Versions). Cap at 200 rows.\n` +
  `Do NOT modify anything. Return GATHER_SCHEMA.`,
  { label: 'certin:gather', phase: 'Gather', schema: GATHER_SCHEMA }
).catch(() => null)

if (!inv || inv.findings_source === 'none') {
  log('certin-export: no findings source found under ' + OUTPUT_DIR)
  return { status: 'ERROR', reason: 'no findings (report_data.json or artifacts/validated/*.json) under ' + OUTPUT_DIR, output_dir: OUTPUT_DIR }
}

// ---- Phase 2: Classify (one batched agent) ---------------------------------
phase('Classify')
const cls = await agent(
  `ROLE: CERT-IN CLASSIFIER (single batched pass; judgment only — you do NOT write the deliverable). cwd is repo root. Engagement dir: ${OUTPUT_DIR}.\n` +
  `Mount ONLY: ${ENUMS} (the legal CERT-In vocabularies), ${OUTPUT_DIR}/reports/report_data.json (or the validated findings), ${OUTPUT_DIR}/engagement-scope.json, ${OUTPUT_DIR}/reports/coverage-matrix.json (if present), and this inventory: ${JSON.stringify(inv).slice(0, 6000)}.\n` +
  `Produce ONLY judgment fields, EVERY value copied VERBATIM from ${ENUMS} (never invent a value; if unsure, omit the field so the builder emits a <FILL> placeholder):\n` +
  `- audit_type: the single best enums.audit_type for this engagement's scope/kind.\n` +
  `- sector + subsector: classify the AUDITEE org against enums.sector (keys) and its subsector list (spaced display form).\n` +
  `- standards: the subset of enums.standards actually applied (infer from coverage-matrix.json attack classes + the methodology; e.g. OWASP Top 10, the NIST entry). Omit if unknown.\n` +
  `- attributing_factors: an object {finding_id: factor} ONLY for findings where you DISAGREE with cwe_defaults[].default_factor; factor must be in enums.attributing_factor.\n` +
  `- challenges: a one-line factual note, or omit.\n` +
  `Write these as ${OVERRIDES} — a JSON object {audit_type?, sector?, subsector?, standards?[], attributing_factors?{}, challenges?}. Report illegal_values_dropped for anything you discarded as not matching the vocab. Return CLASSIFY_SCHEMA.`,
  { label: 'certin:classify', phase: 'Classify', schema: CLASSIFY_SCHEMA }
).catch(() => null)

const useOverrides = !!(cls && cls.overrides_written)

// ---- Phase 3: Build (deterministic; agent only runs + relays) --------------
phase('Build')
const buildCmd = `python3 tools/certin_metadata_build.py --engagement-dir ${OUTPUT_DIR}` + (useOverrides ? ` --overrides ${OVERRIDES}` : '')
const built = await agent(
  `ROLE: CERT-IN BUILD RUNNER (deterministic; run the command, report facts — do NOT compose the deliverable). cwd is repo root.\n` +
  `Run EXACTLY: \`${buildCmd}\`\n` +
  `It prints a JSON summary on its last stdout line. Set certin_ok iff exit code 0; copy technical, compliance, audits, needs_manual, sha256(->sha256), out, xlsx from that summary. On a non-zero exit set certin_ok=false and exit_nonzero_reason=the stderr tail. Return BUILD_SCHEMA.`,
  { label: 'certin:build', phase: 'Build', schema: BUILD_SCHEMA }
).catch((err) => ({ certin_ok: false, technical: 0, compliance: 0, exit_nonzero_reason: String(err) }))

if (!built || !built.certin_ok) {
  return { status: 'FAILED', reason: (built && built.exit_nonzero_reason) || 'builder failed', output_dir: OUTPUT_DIR, dryRun: DRY }
}

// ---- Phase 4: Verify (blind) ----------------------------------------------
phase('Verify')
const ver = await agent(
  `ROLE: CERT-IN VERIFIER (blind; independent). cwd is repo root. You did not build these files.\n` +
  `Open ${CERTIN_JSON} and ${CERTIN_XLSX} (the xlsx is a zip — inspect its worksheet XML with python3 stdlib zipfile; do NOT use openpyxl, one sheet is 67 MB).\n` +
  `Confirm ALL of: (a) security_issues_technical + issues_compliance row count == the engagement's finding count (${inv.findings_count}); (b) every vocabulary value present in the JSON appears in ${ENUMS} (or is a "<FILL: …>" placeholder); (c) the xlsx opens, contains 8 worksheets with exactly 2 hidden, no "ABC Corp" example rows remain in sheets 3/4/5, and xl/tables/table1.xml is byte-identical to the committed template; (d) list every residual "<FILL: …>" placeholder.\n` +
  `status="OK" iff (a),(b),(c) all hold; else "ISSUES". certin_json=${CERTIN_JSON}; certin_xlsx=${CERTIN_XLSX}; findings_count=the row total; needs_manual=the placeholder field list. Return VERIFY_SCHEMA.`,
  { label: 'certin:verify', phase: 'Verify', schema: VERIFY_SCHEMA }
).catch(() => null)

log(`certin-export: ${built.technical} technical + ${built.compliance} compliance rows; ${(built.needs_manual || []).length} field(s) need manual fill.`)

return {
  status: (ver && ver.status === 'OK') ? 'DONE' : 'DONE_WITH_ISSUES',
  output_dir: OUTPUT_DIR,
  dryRun: DRY,
  certin_json: CERTIN_JSON,
  certin_xlsx: CERTIN_XLSX,
  technical: built.technical, compliance: built.compliance, audits: built.audits,
  needs_manual: built.needs_manual || [],
  overrides_applied: useOverrides,
  verify: ver || { status: 'UNVERIFIED' },
}
