export const meta = {
  name: 'retest-engagement',
  description: 'Retest a PRIOR report\'s findings against the current target: ingest the baseline findings (tools/report_ingest.py), blind-re-validate EACH finding against the live target, assign a standardized verdict from a fixed vocabulary (Closed / Open / Partially-Remediated / Risk-Accepted / Needs-Live-Retest / False-Positive), then produce a canonical retest-status deliverable (baseline-vs-current table + status rollup) via tools/retest_status_build.py -> generate_report.py. Includes a controls-disabled/_SSL_Disabled_ test-build detector that flags affected verdicts as production-re-verification-required, and a multi-engagement portfolio roll-up mode. Deterministic bytes are owned by tools (report_ingest, retest_status_build, generate_report) — no LLM authors the final JSON.',
  whenToUse: 'Retest a prior engagement\'s report against the current target (a follow-up / revalidation assessment), OR roll up several retests into one portfolio matrix. args: {prior_report (a finished report file/dir to ingest) OR baseline (a findings JSON array), target (what to retest against), output_dir? (default projects/pentest/<date>_retest), votes? (adversarial quorum, default 2), min_severity? (retest only findings at or above this band; default 'High' because a re-validation is normally contracted for critical/high — pass 'Low'/'Info'/'all' to widen), build_markers? (filenames/flags for the controls-disabled detector), controls_disabled? (bool), portfolio? ([ ...retest-status docs ] -> roll-up mode)}. One of prior_report/baseline (or portfolio) is required.',
  phases: [
    { title: 'Ingest', detail: 'tools/report_ingest.py parses the prior report into baseline findings' },
    { title: 'Retest', detail: 'per baseline finding: a blind retester probes the CURRENT target -> a fixed-vocabulary verdict + note + evidence' },
    { title: 'Report', detail: 'tools/retest_status_build.py -> report_data -> generate_report.py PDF + status rollup + zip' },
  ],
}

// ============================================================================
// RETEST-ENGAGEMENT — revalidate a prior report against the current target.
// Sandbox rules (mirrors merge-reports.js): NO import/require, NO Date.now()/
// Math.random()/new Date() — agents shell out to `date`. Deterministic tools own
// the bytes: report_ingest.py (baseline), retest_status_build.py (the retest-status
// report_data + rollup + controls-disabled override), generate_report.py (PDF).
// The LLM only ingests, retests each finding to a verdict, and runs the tools.
// Invoked at top level; does not call other workflows (no nesting-limit concern).
// ============================================================================

let __raw = args
if (typeof __raw === 'string') {
  const s = __raw.trim()
  if (s.startsWith('{') || s.startsWith('[')) { try { __raw = JSON.parse(s) } catch (e) { __raw = {} } }
  else { __raw = {} }
}
const input = (__raw && typeof __raw === 'object' && !Array.isArray(__raw)) ? __raw : {}
const OUTPUT_DIR = (input.output_dir || 'projects/pentest/retest').replace(/\/+$/, '')
const VOTES = Number(input.votes) > 0 ? Math.floor(Number(input.votes)) : 2
const TARGET = input.target || '(the current target)'
const RETEST_STATUSES = ['Closed', 'Open', 'Partially-Remediated', 'Risk-Accepted', 'Needs-Live-Retest', 'False-Positive']

// ---------------------------------------------------------------------------
// PORTFOLIO ROLL-UP MODE — merge several retest-status docs into one matrix.
// ---------------------------------------------------------------------------
if (Array.isArray(input.portfolio) && input.portfolio.length) {
  phase('Report')
  const portfolioPath = `${OUTPUT_DIR}/reports/portfolio.json`
  const roll = await agent(
    `ROLE: PORTFOLIO ROLL-UP RUNNER (deterministic tool-runner, no judgment). cwd is repo root.\n` +
    `1. Write this EXACT JSON to ${portfolioPath} (mkdir -p its dir):\n${JSON.stringify(input.portfolio)}\n` +
    `2. Run EXACTLY: \`python3 tools/retest_status_build.py --portfolio ${portfolioPath} -o ${OUTPUT_DIR}/reports/report_data.json\` and relay its JSON summary; set build_ok iff exit 0.\n` +
    `3. Render: \`python3 tools/report_data_lint.py ${OUTPUT_DIR}/reports/report_data.json\` (lint_ok iff exit 0; if it fails do NOT render), then \`python3 skills/transilience-report-style/reference/generate_report.py ${OUTPUT_DIR}/reports/report_data.json -o ${OUTPUT_DIR}/reports/Retest-Portfolio-Report.pdf --assets formats/transilience-report-style --theme light\`; render_ok iff exit 0 and the PDF is non-empty.\n` +
    `Return {build_ok, lint_ok, render_ok, report_path}.`,
    { schema: { type: 'object', additionalProperties: true, required: ['build_ok'], properties: { build_ok: { type: 'boolean' }, lint_ok: { type: 'boolean' }, render_ok: { type: 'boolean' }, report_path: { type: ['string', 'null'] } } }, label: 'portfolio:rollup', phase: 'Report', agentType: 'general-purpose' }
  ).catch((e) => ({ build_ok: false, _error: String(e) }))
  const ok = !!(roll && roll.build_ok && roll.render_ok)
  return { ok, mode: 'portfolio', status: ok ? 'COMPLETE' : 'BLOCKED', report: roll && roll.report_path, engagements: input.portfolio.length }
}

// ---------------------------------------------------------------------------
// SINGLE RETEST — ingest baseline, retest each finding, build the deliverable.
// ---------------------------------------------------------------------------
if (!input.prior_report && !Array.isArray(input.baseline)) {
  return { ok: false, status: 'BLOCKED', blocked_reason: 'no prior_report and no baseline[] (and no portfolio[]) — nothing to retest' }
}

// --- Phase Ingest ----------------------------------------------------------
phase('Ingest')
let baseline = Array.isArray(input.baseline) ? input.baseline : null
if (!baseline) {
  const baselinePath = `${OUTPUT_DIR}/input/baseline.json`
  const ing = await agent(
    `ROLE: BASELINE INGEST RUNNER (deterministic tool-runner, no judgment). cwd is repo root.\n` +
    `1. \`mkdir -p ${OUTPUT_DIR}/input\`. Run EXACTLY: \`python3 tools/report_ingest.py ${input.prior_report} -o ${baselinePath}\` (it parses a finished report — native JSON / xlsx / markdown / best-effort PDF/DOCX — into the canonical finding schema). Relay its ingest.warnings.\n` +
    `2. Read ${baselinePath} and return {findings: its findings[], warnings: its ingest.warnings, count}. Do NOT edit the findings.`,
    { schema: { type: 'object', additionalProperties: true, required: ['findings'], properties: { findings: { type: 'array', items: { type: 'object', additionalProperties: true } }, warnings: { type: 'array', items: { type: 'string' } }, count: { type: ['number', 'null'] } } }, label: 'ingest:baseline', phase: 'Ingest', agentType: 'general-purpose' }
  ).catch(() => null)
  baseline = (ing && Array.isArray(ing.findings)) ? ing.findings : []
  if (ing && ing.warnings && ing.warnings.length) log(`report_ingest warnings: ${JSON.stringify(ing.warnings.slice(0, 8))}`)
}
if (!baseline.length) return { ok: false, status: 'BLOCKED', blocked_reason: 'baseline ingest produced 0 findings' }

// Severity scoping. A re-validation is normally contracted to confirm that CRITICAL
// and HIGH findings were remediated, so retesting every Low and Info by default
// spends the budget on the items nobody asked about. Opt in to a wider sweep with
// min_severity: 'Low' / 'Info', or 'all'.
const SEV_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4, Informational: 4 }
const minSeverity = input.min_severity == null ? 'High' : String(input.min_severity)
const severityCutoff = minSeverity.toLowerCase() === 'all' ? 99 : SEV_RANK[minSeverity]
if (severityCutoff === undefined) {
  return { ok: false, status: 'BLOCKED', blocked_reason: `min_severity ${JSON.stringify(input.min_severity)} is not one of Critical/High/Medium/Low/Info/all` }
}
const baselineAll = baseline
// Rank an unknown/absent severity as most-urgent: dropping a finding because its
// severity did not parse would silently narrow the retest.
const inScope = baselineAll.filter((f) => (SEV_RANK[f && f.severity] ?? 0) <= severityCutoff)
const outOfScope = baselineAll.length - inScope.length
if (!inScope.length) {
  return { ok: false, status: 'BLOCKED', blocked_reason: `no baseline finding is ${minSeverity} or above (${baselineAll.length} below the cutoff) — pass min_severity to widen` }
}
baseline = inScope
// Never silent: the report has to be able to say what was NOT retested, or a
// partial sweep reads as a full one.
const severityScope = { min_severity: minSeverity, retested: inScope.length, deferred: outOfScope, baseline_total: baselineAll.length }
if (outOfScope) log(`Severity scope ${minSeverity}+: retesting ${inScope.length} of ${baselineAll.length}; ${outOfScope} below the cutoff are carried as not-retested.`)
log(`Retesting ${baseline.length} baseline finding(s) against ${TARGET} (${VOTES} vote(s) each).`)

// --- Phase Retest ----------------------------------------------------------
// Per finding: a blind retester probes the CURRENT target and, with VOTES-1
// independent corroborators, assigns a fixed-vocabulary verdict. Kept lean and
// deterministic-verdict at the edges (majority agreement -> the verdict).
phase('Retest')
const VERDICT_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['status'],
  properties: {
    status: { type: 'string', enum: RETEST_STATUSES },
    note: { type: 'string' }, current_severity: { type: ['string', 'null'] },
    retest_evidence: { type: ['string', 'null'] }, controls_disabled_observed: { type: 'boolean' },
  },
}
function retesterPrompt(f, i) {
  return `ROLE: BLIND RETESTER #${i} for a revalidation engagement. cwd is repo root. You are handed ONE baseline finding from a PRIOR report and must decide its CURRENT state against the live target — you did NOT author the original and you assign a verdict on the evidence you can gather NOW.\n\n` +
    `TARGET: ${TARGET}\nBASELINE FINDING: ${JSON.stringify({ id: f.id, title: f.title, severity: f.severity, affected: f.affected, cwe: f.cwe, cvss_vector: f.cvss_vector, description: f.description }).slice(0, 4000)}\n\n` +
    `Reproduce the ORIGINAL condition against the current target (non-destructive; honor RoE). Assign EXACTLY ONE status:\n` +
    `- Closed: the issue is remediated — the original repro no longer works and you evidenced the fix.\n` +
    `- Open: still exploitable/present as before (or re-introduced).\n` +
    `- Partially-Remediated: the root cause is mitigated for some vectors but a residual path remains.\n` +
    `- Risk-Accepted: unchanged but the client formally accepted it (only if that is documented in the inputs).\n` +
    `- Needs-Live-Retest: you could NOT reach/authenticate the surface to decide (MFA/allowlist/credentials) — be honest, do not guess Closed.\n` +
    `- False-Positive: the baseline finding was not a real issue on the evidence.\n` +
    `CONTROLS-DISABLED CHECK: if the artifact under test is a controls-disabled / test build (a filename or marker like \`_SSL_Disabled_\`, \`debug\`, \`pinning-off\`), set controls_disabled_observed=true — a control that looks "Closed" on such a build must be re-verified on production (the deterministic builder will override it to Needs-Live-Retest).\n\n` +
    `Return VERDICT_SCHEMA: status (from the fixed vocabulary), note (what you observed + how you decided), current_severity, retest_evidence (path or a one-line proof), controls_disabled_observed.`
}
const STATUS_RANK = { Open: 0, 'Partially-Remediated': 1, 'Needs-Live-Retest': 2, 'Risk-Accepted': 3, Closed: 4, 'False-Positive': 5 }
const verdicts = {}
const retested = await pipeline(
  baseline,
  (f) => parallel(Array.from({ length: VOTES }, (_, i) => () =>
    agent(retesterPrompt(f, i + 1), { schema: VERDICT_SCHEMA, label: `retest:${f.id}#${i + 1}`, phase: 'Retest', agentType: 'general-purpose' }).catch(() => null)
  )).then((votes) => ({ f, votes: votes.filter(Boolean) })),
  ({ f, votes }) => {
    // Deterministic reconciliation: pick the MOST-actionable status among the votes
    // (Open worst) so a single "still open" is never masked by an optimistic "Closed".
    let best = null
    for (const v of votes) if (v && RETEST_STATUSES.includes(v.status)) {
      if (best === null || STATUS_RANK[v.status] < STATUS_RANK[best.status]) best = v
    }
    if (!best) best = { status: 'Needs-Live-Retest', note: 'no usable retest result', controls_disabled_observed: false }
    verdicts[f.id] = {
      status: best.status, note: best.note || '',
      current_severity: best.current_severity || null,
      retest_evidence: best.retest_evidence || null,
      controls_disabled: !!votes.find((v) => v && v.controls_disabled_observed),
    }
    return { id: f.id, status: best.status }
  }
)
const rollupCounts = retested.filter(Boolean).reduce((acc, r) => { acc[r.status] = (acc[r.status] || 0) + 1; return acc }, {})
log(`Retest verdicts: ${JSON.stringify(rollupCounts)}`)

// --- Phase Report ----------------------------------------------------------
phase('Report')
const baselinePath2 = `${OUTPUT_DIR}/input/baseline.json`
const verdictsPath = `${OUTPUT_DIR}/input/verdicts.json`
const metaObj = { target: TARGET, controls_disabled: !!input.controls_disabled, build_markers: input.build_markers || [], engagement: input.engagement || {}, severity_scope: severityScope }
const genCmd = `python3 skills/transilience-report-style/reference/generate_report.py ${OUTPUT_DIR}/reports/report_data.json -o ${OUTPUT_DIR}/reports/Retest-Report.pdf --assets formats/transilience-report-style --theme light`
const finalize = await agent(
  `ROLE: RETEST FINALIZE RUNNER (deterministic tool-runner, no judgment). cwd is repo root.\n` +
  `1. \`mkdir -p ${OUTPUT_DIR}/input ${OUTPUT_DIR}/reports\`. Write these EXACT JSON files (byte-for-byte):\n` +
  `--- ${baselinePath2} ---\n${JSON.stringify(baseline)}\n--- ${verdictsPath} ---\n${JSON.stringify(verdicts)}\n\n` +
  `2. Build the retest-status report_data: run EXACTLY \`python3 tools/retest_status_build.py --baseline ${baselinePath2} --verdicts ${verdictsPath} --meta '${JSON.stringify(metaObj)}' -o ${OUTPUT_DIR}/reports/report_data.json\`. Set build_ok iff exit 0; copy its printed summary.\n` +
  `3. LINT (hard gate): run \`python3 tools/report_data_lint.py ${OUTPUT_DIR}/reports/report_data.json\`; lint_ok iff exit 0. If it fails, do NOT render.\n` +
  `4. Render: run EXACTLY \`${genCmd}\`; render_ok iff exit 0 and the PDF exists non-empty.\n` +
  `5. Package: \`cd ${OUTPUT_DIR} && rm -f retest_deliverable.zip; zip -r retest_deliverable.zip reports input 2>/dev/null; unzip -l retest_deliverable.zip | tail -1\`; zip_ok iff the zip is non-empty.\n` +
  `Return {build_ok, lint_ok, render_ok, zip_ok, report_path, rollup}.`,
  { schema: { type: 'object', additionalProperties: true, required: ['build_ok'], properties: { build_ok: { type: 'boolean' }, lint_ok: { type: 'boolean' }, render_ok: { type: 'boolean' }, zip_ok: { type: 'boolean' }, report_path: { type: ['string', 'null'] }, rollup: { type: ['object', 'null'], additionalProperties: true } } }, label: 'retest:finalize', phase: 'Report', agentType: 'general-purpose' }
).catch((e) => ({ build_ok: false, _error: String(e) }))

const ok = !!(finalize && finalize.build_ok && finalize.lint_ok !== false && finalize.render_ok)
return {
  ok, status: ok ? 'COMPLETE' : 'BLOCKED',
  blocked_reason: ok ? null : (!finalize || !finalize.build_ok ? 'retest_status_build failed' : finalize.lint_ok === false ? 'report_data lint failed' : 'render failed'),
  mode: 'single', target: TARGET, baseline_count: baseline.length,
  severity_scope: severityScope,
  rollup: rollupCounts, report: finalize && finalize.report_path,
  deliverable_zip: `${OUTPUT_DIR}/retest_deliverable.zip`,
}
