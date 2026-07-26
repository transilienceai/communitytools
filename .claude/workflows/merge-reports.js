export const meta = {
  name: 'merge-reports',
  description: 'Merge several security reports (a folder or an explicit file list) into ONE Transilience-style deliverable. Ingests every source report\'s findings + evidence + logs; RE-VALIDATES each finding against its own evidence and discards false positives (adversarial refutation); recomputes each CVSS from its vector (cvss lib + NVD/KEV) and readjusts the score/severity to the authoritative value; de-duplicates findings that recur across reports under different names/ids (deterministic candidate clustering + LLM adjudication + a cross-cluster sweep); then produces a reorganized final PDF in Transilience house style plus a compressed zip of all references. Deterministic bytes are owned by tools (merge_reports_cluster.py, report_data_build.py, generate_report.py) — no LLM authors the final JSON.',
  whenToUse: 'Consolidate multiple finished reports into one validated, de-duplicated deliverable. args: {sources?[] (files/dirs) | source_dir? (a folder to scan), output_dir? (merged deliverable dir; default projects/pentest/<date>_merged_report), title?, client?, votes? (adversarial quorum, default 3), max_findings? (default 100), threshold? (dedup title-Jaccard, default 0.6)}. At least one of sources/source_dir is required.',
  phases: [
    { title: 'Ingest', detail: 'resolve + copy sources by sha256; one agent per source normalizes its findings and copies its evidence/logs' },
    { title: 'Dedup', detail: 'deterministic candidate clustering (tools/merge_reports_cluster.py) -> per-cluster LLM adjudication -> cross-cluster sweep -> canonical finding set' },
    { title: 'Validate', detail: 'per canonical finding: evidence corroboration + CVSS recompute/reconcile -> N blind adversarial refuters -> deterministic verdict (false positives discarded)' },
    { title: 'Report', detail: 'persist interim verdicts verbatim; author exec summary; report_data_build.py -> generate_report.py PDF -> summary + merge-map -> zip deliverable' },
    { title: 'Verify', detail: 'blind agent re-opens the merged report_data + PDF + zip: every retained finding present, no discarded finding leaked, CVSS bands match, evidence bundled' },
  ],
}

// ============================================================================
// MERGE-REPORTS — consolidate N reports into ONE validated, de-duplicated,
// Transilience-style deliverable.
//
// Design mirrors validate-findings.js (the authoritative validation engine):
//   * Sandbox: NO import/require, NO Date.now()/Math.random()/new Date() — agents
//     shell out to `date`. The pure decision helpers below are an INLINE copy of
//     .claude/workflows/lib/wf-helpers.mjs (kept byte-identical to the tested
//     module for the ones reused; merge-specific verdict/interim added).
//   * Deterministic tools own the bytes: candidate dedup clustering is
//     tools/merge_reports_cluster.py; the final report_data.json is assembled by
//     tools/report_data_build.py (sole-owner merge of the interim verdict JSONs);
//     the PDF is skills/transilience-report-style/reference/generate_report.py.
//     LLM agents only ingest/normalize, adjudicate duplicates, corroborate
//     evidence, refute, author the exec summary, run the tools, and blind-verify.
//   * Verdict is PURE JS (mergeVerdict) — no LLM in the keep/discard/score path.
//
// KEY DIFFERENCE from validate-findings: source findings are historical and carry
// STATIC evidence (screenshots, request/response, logs), not necessarily a
// re-runnable PoC. So the verdict is EVIDENCE-CORROBORATION (does the attached
// evidence actually substantiate the claim?) + adversarial refutation, NOT an
// exploit-rerun gate. CVSS is always recomputed from the vector and readjusted to
// the authoritative value; a finding whose evidence CONTRADICTS it, or that a
// refuter majority refutes, is discarded as a false positive. A plausible finding
// with thin/absent evidence is KEPT but flagged needs_live_confirmation (honest).
//
// GLOB TRAP: report_data_build.py globs <dir>/**/artifacts/validated/*.json
// RECURSIVELY. Ingested source material must NEVER create an artifacts/validated/
// subpath under the merged dir, or source interims get double-counted. Ingest
// copies only evidence FILES + a normalized findings.json into input/sources/…;
// the ONLY things under **/artifacts/validated are this run's own interims.
//
// ATTACHMENT / NESTING: invoked at top level. It does NOT call other workflows,
// so it never trips the one-level workflow() nesting limit.
// ============================================================================

// ---- inputs ----------------------------------------------------------------
// args may arrive as a real object OR a JSON string (the harness serializes it).
// Parse a JSON-string arg so structured {sources,...} is never silently dropped
// to {} (which would fail as "no sources"). A bare non-JSON string is not a valid
// source spec, so it falls through to {} and the explicit no-sources guard below.
let __raw = args
if (typeof __raw === 'string') {
  const s = __raw.trim()
  if (s.startsWith('{') || s.startsWith('[')) { try { __raw = JSON.parse(s) } catch (e) { __raw = {} } }
  else { __raw = {} }
}
const a = (__raw && typeof __raw === 'object' && !Array.isArray(__raw)) ? __raw : {}
const EXPLICIT_SOURCES = Array.isArray(a.sources) ? a.sources.filter((s) => typeof s === 'string' && s.trim()) : []
const SOURCE_DIR = (a.source_dir || '').replace(/\/+$/, '')
let OUTPUT_DIR = (a.output_dir || '').replace(/\/+$/, '')
const TITLE = a.title || 'Consolidated Security Assessment'
const CLIENT = a.client || null
const DEFAULT_VOTES = 3
const VOTES = Number(a.votes) > 0 ? Math.floor(Number(a.votes)) : DEFAULT_VOTES
const MAX_FINDINGS = Number(a.max_findings) > 0 ? Math.floor(Number(a.max_findings)) : 100
const THRESHOLD = Number(a.threshold) > 0 ? Number(a.threshold) : 0.6
const BUSINESS_TIER = a.business_tier || 'unknown'
const PLATFORM = a.platform || 'generic'
// MERGE-ONLY mode: consolidate + de-duplicate + recompute/adjust CVSS, but do NOT
// re-validate to discard false positives (no adversarial refuters, no evidence-
// contradiction REJECT). Every canonical finding is CARRIED THROUGH. CVSS is still
// recomputed from the vector (that is the point of "adjust cvss scores"). Opt in
// with any of {revalidate:false, validate:false, skip_validation:true, merge_only:true}.
const MERGE_ONLY = a.revalidate === false || a.validate === false || a.skip_validation === true || a.merge_only === true
const EFFECTIVE_VOTES = MERGE_ONLY ? 0 : VOTES

if (!EXPLICIT_SOURCES.length && !SOURCE_DIR) {
  log('merge-reports: no sources. Provide args.sources[] (files/dirs) or args.source_dir (a folder).')
  return { status: 'ERROR', reason: 'at least one of {sources[], source_dir} is required' }
}

// ============================================================================
// DETERMINISTIC HELPERS — inline copy of .claude/workflows/lib/wf-helpers.mjs
// (the shared ones kept byte-identical to the tested module) plus the two
// merge-specific ones (mergeVerdict, buildMergeInterim). NO LLM in these paths.
// ============================================================================
const SEVERITY = ['Critical', 'High', 'Medium', 'Low', 'Info']
function severityBand(score) {
  const s = Number(score)
  if (!(s > 0)) return 'Info'
  if (s >= 9.0) return 'Critical'
  if (s >= 7.0) return 'High'
  if (s >= 4.0) return 'Medium'
  return 'Low'
}
const TIER_WEIGHTS = { crown_jewel: 1.0, revenue: 0.7, support: 0.4, dev: 0.2, unknown: 0.3 }
const RISK_THRESHOLDS = { immediate: 0.6, short_term: 0.3, medium_term: 0.1 }
function round4(x) { return Math.round((x + Number.EPSILON) * 1e4) / 1e4 }
function riskBucket(score) {
  if (score >= RISK_THRESHOLDS.immediate) return 'immediate'
  if (score >= RISK_THRESHOLDS.short_term) return 'short_term'
  if (score >= RISK_THRESHOLDS.medium_term) return 'medium_term'
  return 'monitor'
}
function riskScore({ cvss, tier, exposure, feasibility } = {}) {
  const technical = Number(cvss) > 0 ? Number(cvss) / 10 : 0.5
  const weight = TIER_WEIGHTS[tier] != null ? TIER_WEIGHTS[tier] : TIER_WEIGHTS.unknown
  const exp = exposure === 1.0 || exposure === 0.5 ? exposure : (exposure ? 1.0 : 0.5)
  const feas = feasibility == null ? 1.0 : Number(feasibility)
  const score = round4(feas * technical * weight * exp)
  return { risk_score: score, risk_bucket: riskBucket(score), technical_severity: round4(technical), business_impact: weight, entry_exposure: exp, cvss_missing: !(Number(cvss) > 0) }
}
function exposureFor(asset) {
  if (asset && (asset.exposure === 1.0 || asset.exposure === 0.5)) return asset.exposure
  if (asset && typeof asset.external === 'boolean') return asset.external ? 1.0 : 0.5
  return (asset && asset.platform === 'network') ? 0.5 : 1.0
}
function normVector(v) {
  if (!v) return ''
  // Strip any supported version prefix so v4.0/v3.x/v2.0 vectors normalize alike.
  return String(v).replace(/^CVSS:(?:4\.0|3\.[01]|2\.0)\//i, '').split('/').filter(Boolean).sort().join('/').toUpperCase()
}
function cveReconcile({ claimed_score, computed_score, nvd_score, claimed_vector, computed_vector } = {}) {
  const near = (x, y) => x != null && y != null && Math.abs(Number(x) - Number(y)) <= 0.1 + 1e-9
  const haveComputed = computed_score != null
  const vectorOk = !claimed_vector || !computed_vector || normVector(claimed_vector) === normVector(computed_vector)
  const nvdOk = nvd_score == null || near(computed_score, nvd_score)
  const claimOk = claimed_score == null || near(computed_score, claimed_score)
  return { reconciled: !!(haveComputed && vectorOk && nvdOk && claimOk), vectorOk, nvdOk, claimOk, haveComputed }
}
function terminalSubdir(verdict) {
  if (verdict === 'VALID' || verdict === 'REPAIRED') return 'validated'
  if (verdict === 'REJECTED') return 'false-positives'
  return 'dropped'
}
function nvdKevText() {
  return [
    'AUTHORITATIVE CVE SOURCES (do not rely on the finding\'s own claim):',
    '1. NVD: `python3 tools/nvd-lookup.py <CVE-ID>` — parse the final `JSON_SUMMARY: {...}` line (cve_id, score, severity, cvss_version, cvss_vector, cwes[], status) AND the per-version "Vector:" lines. Use the PRIMARY per the v4.0-first ladder: CVSS v4.0 preferred, then v3.1 -> v3.0 -> v2.0 (nvd-lookup already marks the primary and fills cvss_version/cvss_vector).',
    '2. CISA KEV (known-exploited): WebFetch https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json and check whether the CVE is listed. Being on KEV raises real-world priority regardless of base score.',
    '3. Vendor/official advisory: follow the authoritative reference URLs NVD returns and confirm the affected versions + vulnerability class match the finding. Quote the source.',
    'Reconcile: the claimed CVE id, CVSS vector, base score and severity must agree with NVD and with your from-vector recomputation (|delta| <= 0.1 on the score, exact match on the vector and band). Flag KEV status. A divergence means the SCORE is corrected to the authoritative value; a CVE that NVD says does not match the described issue is a CONTRADICTION (mark the evidence contradicted).',
  ]
}

// mergeVerdict — the keep/discard/score decision for a merged finding. PURE JS.
//  REJECTED (false positive, dropped from the report): an adversarial majority
//    refuted it, OR the attached evidence contradicts the claim.
//  DROPPED (audit-only): the corroboration stage failed with an infra error.
//  VALID (kept): everything else. needs_live_confirmation flags any finding whose
//    evidence did not fully substantiate it (thin/absent) — kept but honest.
function mergeVerdict(finding, corr, votes, opts = {}) {
  const votesTotal = opts.votesTotal != null ? opts.votesTotal : (votes || []).length
  const refuteCount = (votes || []).filter((v) => v && v.refuted).length
  const majority = Math.floor(votesTotal / 2) + 1
  const refuted = votesTotal > 0 && refuteCount >= majority
  if (corr == null) return { finding_id: finding.canonical_id, verdict: 'DROPPED', failed_checks: ['corroboration_infra_error'], refuteCount, reason: 'corroboration stage returned null' }
  const c = corr.corroboration || {}
  const status = c.status || 'absent'
  const contradicted = c.evidence_contradicts === true || status === 'contradicted'
  // Evidence that CONTRADICTS the claim is a hard false positive regardless of votes.
  if (contradicted) return { finding_id: finding.canonical_id, verdict: 'REJECTED', failed_checks: ['evidence:contradicts_claim'], refuteCount }
  // Adversarial majority is a DROP only when the evidence does NOT independently
  // substantiate the core claim (thin/absent/plausible-unverified -> genuine false
  // positive). When the evidence IS substantiated, a refuter majority is contesting
  // the SCORE / scope / CVE-applicability — NOT the vulnerability's existence — so the
  // finding is KEPT at its recomputed CVSS but forced to needs_live_confirmation and
  // marked adversarially_contested. This honours the workflow's stated rule ("a
  // plausible finding is KEPT but flagged, honest") and never silently deletes a
  // finding whose evidence the corroborator proved (which would understate real risk).
  if (refuted) {
    if (status !== 'substantiated') return { finding_id: finding.canonical_id, verdict: 'REJECTED', failed_checks: ['adversarial:refuted_unsubstantiated'], refuteCount }
    return { finding_id: finding.canonical_id, verdict: 'VALID', failed_checks: [], refuteCount, needs_live_confirmation: true, adversarially_contested: true }
  }
  return { finding_id: finding.canonical_id, verdict: 'VALID', failed_checks: [], refuteCount, needs_live_confirmation: status !== 'substantiated' }
}

// mergeOnlyVerdict — the keep decision for MERGE_ONLY mode. No refuters ran and we
// never discard as a false positive: every corroborated finding is CARRIED THROUGH
// at its recomputed CVSS. The only non-VALID outcome is a corroboration infra error
// (null corr) -> DROPPED (audit-only), identical to the normal path. Evidence that
// the corroborator judged thin/absent still flags needs_live_confirmation (honest),
// but a contradiction no longer forces a REJECT — the finding is kept and flagged.
function mergeOnlyVerdict(finding, corr) {
  if (corr == null) return { finding_id: finding.canonical_id, verdict: 'DROPPED', failed_checks: ['corroboration_infra_error'], refuteCount: 0, reason: 'corroboration stage returned null' }
  const status = (corr.corroboration || {}).status || 'absent'
  return { finding_id: finding.canonical_id, verdict: 'VALID', failed_checks: [], refuteCount: 0, needs_live_confirmation: status !== 'substantiated' }
}

// buildMergeInterim — the interim validated JSON in the exact contract
// tools/report_data_build.py consumes. Authored in JS; a writer only persists it.
function buildMergeInterim(f, corr, verdict, opts = {}) {
  const tier = opts.tier || 'unknown'
  const platform = opts.platform || 'generic'
  const votes = opts.votes != null ? opts.votes : DEFAULT_VOTES
  const cve = (corr && corr.cve) || {}
  const cvssBlock = (corr && corr.cvss) || {}
  // Authoritative CVSS: from-vector recompute > NVD > the merged claimed score.
  const cvss = cvssBlock.computed_score != null ? cvssBlock.computed_score
    : (cve.computed_score != null ? cve.computed_score
      : (cve.nvd_score != null ? cve.nvd_score
        : (f.cvss_score != null ? f.cvss_score : null)))
  const sev = cvss != null && Number(cvss) > 0
    ? severityBand(cvss)
    : (f.severity && SEVERITY.includes(f.severity) ? f.severity : 'Info')
  const feasibility = verdict.verdict === 'VALID' ? 1.0 : 0.5
  const risk = riskScore({ cvss, tier, exposure: exposureFor({ platform }), feasibility })
  const rf = Object.assign({}, (corr && corr.report_fields) || {})
  // Backfill the human-facing fields from the canonical finding when the
  // corroborator returned terse fields, so every card renders complete.
  rf.title = rf.title || f.title
  if (!Array.isArray(rf.affected) || !rf.affected.length) rf.affected = f.affected || []
  rf.description = rf.description || f.description || ''
  rf.impact = rf.impact || f.impact || ''
  rf.recommendation = rf.recommendation || f.recommendation || ''
  if (!Array.isArray(rf.references) || !rf.references.length) rf.references = f.references || []
  // Honesty note for carried-over findings whose evidence was not fully
  // substantiated. calibration IS a rendered finding field the generator escapes.
  if (verdict.adversarially_contested) {
    const note = `Adversarial re-validation (${verdict.refuteCount || 0}/${votes} refuters) contested this finding's score, scope, or CVE-applicability while its core observation stayed evidence-corroborated during the merge. The CVSS was recomputed to the authoritative value shown; live re-confirmation is recommended before remediation sign-off.`
    rf.calibration = rf.calibration ? (rf.calibration + ' ' + note) : note
  } else if (verdict.needs_live_confirmation) {
    const note = 'Carried over from a source report and re-validated against its supplied evidence, which did not fully substantiate the finding during the merge. Recommend live re-confirmation before remediation sign-off.'
    rf.calibration = rf.calibration ? (rf.calibration + ' ' + note) : note
  }
  const cvector = cvssBlock.vector || cve.vector || f.cvss_vector || null
  // CVEs MUST be objects with an `id` (report_data_build.build_cve_register does
  // cve.get("id")) — normalize any bare-string fallback to {id}.
  const normCves = (arr) => (arr || []).map((c) => (typeof c === 'string' ? { id: c } : c)).filter((c) => c && c.id)
  const cvesOut = (cve.cves && cve.cves.length)
    ? normCves(cve.cves)
    : (cve.primary_cve ? [{ id: cve.primary_cve, score: cve.computed_score, severity: sev }] : normCves(f.cves))
  return {
    finding_id: f.canonical_id,
    verdict: verdict.verdict,
    severity: sev,
    cvss_score: cvss,
    cvss_vector: cvector,
    cwe: rf.cwe || f.cwe || (cve.cwes && cve.cwes[0]) || null,
    owasp: rf.owasp || f.owasp || null,
    cves: cvesOut,
    on_kev: !!cve.on_kev,
    cve_verification: { nvd_score: cve.nvd_score != null ? cve.nvd_score : null, computed_score: cve.computed_score != null ? cve.computed_score : null, vector: cve.vector || null, on_kev: !!cve.on_kev },
    risk,
    report_fields: rf,
    poc: Array.isArray(corr && corr.poc) ? corr.poc : [],
    needs_live_confirmation: !!verdict.needs_live_confirmation,
    merged_from: f.merged_from || [],
    sources: f.sources || [],
    adversarial: { votes, refuted: verdict.refuteCount || 0 },
    proof_dir: (corr && corr.proof_dir) || `${OUTPUT_DIR}/reports/appendix/${f.canonical_id}`,
  }
}

function slugify(s, i) {
  const base = String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40)
  return base || `source-${i + 1}`
}

// ============================================================================
// PHASE: Ingest
// ============================================================================
phase('Ingest')

const RESOLVE_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['output_dir', 'sources'],
  properties: {
    output_dir: { type: 'string' },
    date_tag: { type: ['string', 'null'] },
    sources: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: true, required: ['slug', 'path'],
        properties: {
          slug: { type: 'string' },
          path: { type: 'string', description: 'the stored copy under input/sources/<slug>/raw/ (or the original for a dir)' },
          original: { type: 'string' },
          kind: { type: 'string', description: 'report_data.json | pdf | markdown | csv | xlsx | docx | engagement_dir | unknown' },
          bytes: { type: ['number', 'null'] },
          sha256: { type: ['string', 'null'] },
        },
      },
    },
    notes: { type: 'array', items: { type: 'string' } },
  },
}

const resolve = await agent(
  `ROLE: MERGE INGEST — RESOLVE + STAGE (no judgment on findings yet). cwd is repo root.\n` +
  `Sources given: ${EXPLICIT_SOURCES.length ? 'explicit list ' + JSON.stringify(EXPLICIT_SOURCES) : 'scan the folder ' + JSON.stringify(SOURCE_DIR)}.\n` +
  (OUTPUT_DIR ? `OUTPUT_DIR (use verbatim): ${OUTPUT_DIR}\n` : `OUTPUT_DIR: not given — mint one.\n`) +
  `Do:\n` +
  `1. Compute a date tag: \`date -u +%Y%m%d\`.\n` +
  (OUTPUT_DIR
    ? `2. output_dir = ${OUTPUT_DIR} (verbatim). If it does not exist, create it. Do NOT clobber a non-empty unrelated dir.\n`
    : `2. output_dir = projects/pentest/<date_tag>_merged_report ; if that dir already exists and is non-empty, append -2 (…-3, …) so nothing is clobbered. Create it.\n`) +
  `3. Create the canonical tree: \`mkdir -p <output_dir>/{input/sources,recon,artifacts/merged,artifacts/validated,artifacts/false-positives,artifacts/dropped,logs/activity,reports/appendix}\`.\n` +
  `4. Enumerate the SOURCE reports. A source is a finished report or an engagement dir. Accept: report_data.json, a *.pdf/*.docx/*.md report, a findings register (*.csv/*.xlsx/*.json), or an engagement directory (which may contain reports/report_data.json, findings/finding-*/, artifacts/validated/*.json). ${SOURCE_DIR ? `Scan ${SOURCE_DIR} recursively for these (skip our own <output_dir>).` : 'Use exactly the paths given (a path may be a file OR a directory).'}\n` +
  `5. For EACH source assign a short unique slug (kebab of its filename/dirname). Copy the raw source artifact idempotently by content into <output_dir>/input/sources/<slug>/raw/ (record bytes + sha256; \`sha256sum\`/\`shasum -a 256\`). For an engagement DIR source, you do NOT need to copy the whole tree here — record its original path; the per-source ingest step will pull only the evidence it needs. IMPORTANT: never create an "artifacts/validated" path anywhere under <output_dir>/input (it would be mis-read as a merged verdict).\n` +
  `6. Write <output_dir>/engagement-meta.json = {"engagement_name":"merged_report","kind":"merged","started":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","resume_round":0,"input_manifest":[{original,stored,bytes,sha256} per source],"engagement":{"title":${JSON.stringify(TITLE)},"subtitle":"Consolidated & Re-validated Findings"${CLIENT ? `,"target":${JSON.stringify(CLIENT)}` : ''}}}. (This seeds a minimal engagement block so the PDF always has a title; the Report phase enriches "engagement" and fills "executive_summary" later — preserve these keys.)\n` +
  `Return RESOLVE_SCHEMA. If zero sources are found, return sources:[] with a note.`,
  { schema: RESOLVE_SCHEMA, label: 'ingest:resolve', phase: 'Ingest', agentType: 'general-purpose' }
).catch(() => null)

if (!resolve || !Array.isArray(resolve.sources) || !resolve.sources.length) {
  log('merge-reports: no source reports found.')
  return { status: 'NO_SOURCES', output_dir: OUTPUT_DIR || (resolve && resolve.output_dir) || null }
}
OUTPUT_DIR = (resolve.output_dir || OUTPUT_DIR).replace(/\/+$/, '')
// Assign slugs, guaranteeing uniqueness across sources. slugify() truncates to 40
// chars, so two long same-named files (e.g. Foo….pdf and Foo….xlsx) can collide ->
// duplicate uids -> merge_reports_cluster.py aborts ("uid values must be unique").
// Disambiguate a collision with the file extension, then a numeric suffix.
const _seenSlugs = new Set()
const sources = resolve.sources.map((s, i) => {
  let slug = slugify(s.slug || s.original || s.path, i)
  if (_seenSlugs.has(slug)) {
    const ext = String(s.original || s.path || '').split('.').pop().toLowerCase().replace(/[^a-z0-9]+/g, '').slice(0, 6)
    let cand = ext && !_seenSlugs.has(`${slug}-${ext}`) ? `${slug}-${ext}` : `${slug}-${i + 1}`
    let n = i + 1
    while (_seenSlugs.has(cand)) { n++; cand = `${slug}-${n}` }
    slug = cand
  }
  _seenSlugs.add(slug)
  return { ...s, slug }
})
log(`Ingesting ${sources.length} source report(s) into ${OUTPUT_DIR}.`)

const INGEST_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['slug', 'findings'],
  properties: {
    slug: { type: 'string' },
    source_kind: { type: ['string', 'null'] },
    evidence_copied: { type: ['number', 'null'] },
    findings: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: true, required: ['orig_id', 'title'],
        properties: {
          orig_id: { type: 'string', description: 'the finding id/number AS PRINTED in the source (e.g. F-03, 8.01, VULN-12)' },
          title: { type: 'string' },
          severity: { type: ['string', 'null'], description: 'as claimed by the source' },
          cvss_score: { type: ['number', 'null'] },
          cvss_vector: { type: ['string', 'null'] },
          cwe: { type: ['string', 'null'] },
          owasp: { type: ['string', 'null'] },
          cves: { type: 'array', items: { type: 'string' } },
          affected: { type: 'array', items: { type: 'string' }, description: 'assets/hosts/URLs the finding affects' },
          url: { type: ['string', 'null'] }, param: { type: ['string', 'null'] },
          description: { type: ['string', 'null'] }, impact: { type: ['string', 'null'] },
          recommendation: { type: ['string', 'null'] },
          references: { type: 'array', items: { type: 'string' } },
          evidence_refs: { type: 'array', items: { type: 'string' }, description: 'engagement-root-relative paths of the copied evidence files for this finding' },
          poc: { type: 'array', items: { type: 'object', additionalProperties: true }, description: 'ordered {description,command,image_url} steps if the source has them' },
          claimed_verdict: { type: ['string', 'null'] },
        },
      },
    },
    notes: { type: 'array', items: { type: 'string' } },
  },
}

const ingested = await parallel(sources.map((s) => () =>
  agent(
    `ROLE: MERGE INGEST — NORMALIZE ONE SOURCE (faithful extraction, no re-judgement). cwd is repo root.\n` +
    `SOURCE slug: ${s.slug}\nRAW copy: ${s.path}\nORIGINAL: ${s.original || s.path}\nKIND hint: ${s.kind || 'unknown'}\n` +
    `EVIDENCE DEST: ${OUTPUT_DIR}/input/sources/${s.slug}/evidence/   (mkdir -p it)\n\n` +
    `Do:\n` +
    `1. Open the source and extract EVERY finding faithfully — do NOT invent, merge, drop, or re-score. For a PDF use pdftotext (or python pdfminer); for docx use the python-docx/unzip text; for xlsx/csv read the register rows; for report_data.json read its findings[]; for an engagement DIR read reports/report_data.json AND/OR findings/finding-*/description.md AND artifacts/validated/*.json.\n` +
    `2. For each finding capture: orig_id (the id AS PRINTED), title, severity, cvss_score, cvss_vector, cwe, owasp, cves[], affected[] (hosts/URLs), url, param, description, impact, recommendation, references[], claimed_verdict.\n` +
    `3. COPY that finding's evidence files (screenshots, request/response captures, poc scripts + outputs, raw scan lines, logs) into ${OUTPUT_DIR}/input/sources/${s.slug}/evidence/<orig_id>/… and set evidence_refs[] to the engagement-root-relative stored paths (e.g. ${OUTPUT_DIR}/input/sources/${s.slug}/evidence/F-03/screenshot.png). If the source is a single PDF with inline images, extract the images (pdfimages) and reference them. Carry any ordered PoC steps into poc[] with each step's image_url pointing at a copied image.\n` +
    `4. HARD RULE: do NOT create any "artifacts/validated" directory under ${OUTPUT_DIR}/input — copy evidence only under the evidence/ path above.\n` +
    `5. If the source's logs/activity/*.jsonl exist (engagement dir), copy them to ${OUTPUT_DIR}/logs/activity/${s.slug}-<name>.jsonl (they feed the consolidated activity appendix).\n` +
    `Return INGEST_SCHEMA {slug:"${s.slug}", findings:[…], evidence_copied}. Extract ALL findings — completeness matters more than polish.`,
    { schema: INGEST_SCHEMA, label: `ingest:${s.slug}`, phase: 'Ingest', agentType: 'general-purpose' }
  ).catch(() => ({ slug: s.slug, findings: [] }))
))

// Assemble the global normalized-finding list in JS; uid is unique across sources.
const allFindings = []
for (const res of ingested.filter(Boolean)) {
  const slug = res.slug
  ;(res.findings || []).forEach((f, i) => {
    const orig = String(f.orig_id || `${i + 1}`)
    allFindings.push({
      uid: `${slug}::${orig}`,
      source: slug, orig_id: orig,
      title: f.title || orig,
      severity: (f.severity && SEVERITY.includes(f.severity)) ? f.severity : (f.severity || null),
      cvss_score: f.cvss_score != null ? Number(f.cvss_score) : null,
      cvss_vector: f.cvss_vector || null,
      cwe: f.cwe || null, owasp: f.owasp || null,
      cves: Array.isArray(f.cves) ? f.cves : [],
      affected: Array.isArray(f.affected) ? f.affected : [],
      url: f.url || null, param: f.param || null,
      description: f.description || null, impact: f.impact || null,
      recommendation: f.recommendation || null,
      references: Array.isArray(f.references) ? f.references : [],
      evidence_refs: Array.isArray(f.evidence_refs) ? f.evidence_refs : [],
      poc: Array.isArray(f.poc) ? f.poc : [],
      claimed_verdict: f.claimed_verdict || null,
    })
  })
}
if (!allFindings.length) {
  log('merge-reports: sources ingested but zero findings extracted.')
  return { status: 'NO_FINDINGS', output_dir: OUTPUT_DIR, sources: sources.length }
}
log(`Ingested ${allFindings.length} raw finding(s) across ${sources.length} source(s).`)

// ============================================================================
// PHASE: Dedup — deterministic candidate clustering + LLM adjudication
// ============================================================================
phase('Dedup')

// Persist the normalized list and run the deterministic clusterer (owns the bytes).
const CLUSTER_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['clusters'],
  properties: {
    clusters: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: true, required: ['cluster_id', 'members'],
        properties: { cluster_id: { type: 'string' }, members: { type: 'array', items: { type: 'string' } }, size: { type: ['number', 'null'] }, signals: { type: 'array', items: { type: 'string' } }, titles: { type: 'array', items: { type: 'string' } }, warnings: { type: 'array', items: { type: 'string' } } },
      },
    },
    candidate_pairs: { type: 'array', items: { type: 'object', additionalProperties: true }, description: 'host-overlap candidate dup pairs (CWE-independent) for the sweep to examine' },
    stats: { type: 'object', additionalProperties: true },
  },
}
const allFindingsPath = `${OUTPUT_DIR}/artifacts/merged/all-findings.json`
const clustersPath = `${OUTPUT_DIR}/artifacts/merged/clusters.json`
const clusterRun = await agent(
  `ROLE: DEDUP CLUSTER RUNNER (tool-runner, no judgment). cwd is repo root.\n` +
  `1. Write this EXACT JSON (byte-for-byte) to ${allFindingsPath} (the dir exists):\n${JSON.stringify(allFindings)}\n\n` +
  `2. Run EXACTLY: \`python3 tools/merge_reports_cluster.py --findings ${allFindingsPath} -o ${clustersPath} --threshold ${THRESHOLD}\`\n` +
  `3. Read ${clustersPath} and return CLUSTER_SCHEMA (its clusters[], candidate_pairs[], and stats VERBATIM — include each cluster's warnings[] and the top-level candidate_pairs[] if present). Do NOT edit the clusters.`,
  { schema: CLUSTER_SCHEMA, label: 'dedup:cluster', phase: 'Dedup', agentType: 'general-purpose' }
).catch(() => null)

// Dedup is a best-effort OPTIMISATION; its failure must NEVER drop findings. If the
// clusterer crashed it returns an EMPTY clusters[] (an array, so the old `Array.isArray`
// test passed and silently produced 0 canonical findings). Treat an empty result as a
// failure and fall back to one singleton cluster per finding, so every finding still
// reaches validation.
if (clusterRun && clusterRun.stats && clusterRun.stats.error) {
  log(`dedup:cluster reported an error — ${clusterRun.stats.error}. Falling back to singleton clusters (no findings dropped).`)
}
const clusters = (clusterRun && Array.isArray(clusterRun.clusters) && clusterRun.clusters.length)
  ? clusterRun.clusters
  : allFindings.map((f, i) => ({ cluster_id: `C${String(i + 1).padStart(3, '0')}`, members: [f.uid], size: 1 }))
const byUid = new Map(allFindings.map((f) => [f.uid, f]))
const multi = clusters.filter((c) => (c.members || []).length > 1)
const singles = clusters.filter((c) => (c.members || []).length <= 1)
log(`Clustered ${allFindings.length} finding(s) into ${clusters.length} group(s) (${multi.length} multi-member candidate-dup group(s)).`)
// Surface deterministic clusterer warnings (e.g. divergent cited port for a host —
// a 100-off port divergence that must NOT be silently collapsed) into the finalize notes.
const dedupWarnings = clusters.flatMap((c) => (c.warnings || []).map((w) => `${c.cluster_id}: ${w}`))
const candidatePairs = (clusterRun && Array.isArray(clusterRun.candidate_pairs)) ? clusterRun.candidate_pairs : []
if (dedupWarnings.length) log(`Clusterer warnings (surfaced, not auto-collapsed): ${JSON.stringify(dedupWarnings)}`)
if (candidatePairs.length) log(`${candidatePairs.length} host-overlap candidate pair(s) flagged for the cross-cluster sweep (same host, possibly different CWE labels).`)

const ADJUDICATE_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['canonical'],
  properties: {
    canonical: {
      type: 'array',
      description: 'one or MORE canonical findings this cluster resolves to (a candidate cluster may over-group and split into several)',
      items: {
        type: 'object', additionalProperties: true, required: ['merged_from', 'title', 'severity'],
        properties: {
          merged_from: { type: 'array', items: { type: 'string' }, description: 'the source uids that are the SAME finding' },
          title: { type: 'string' },
          severity: { type: 'string', enum: SEVERITY },
          cvss_score: { type: ['number', 'null'] }, cvss_vector: { type: ['string', 'null'] },
          cwe: { type: ['string', 'null'] }, owasp: { type: ['string', 'null'] },
          cves: { type: 'array', items: { type: 'string' } },
          affected: { type: 'array', items: { type: 'string' } },
          url: { type: ['string', 'null'] }, param: { type: ['string', 'null'] },
          description: { type: ['string', 'null'] }, impact: { type: ['string', 'null'] },
          recommendation: { type: ['string', 'null'] },
          references: { type: 'array', items: { type: 'string' } },
          evidence_refs: { type: 'array', items: { type: 'string' } },
          poc: { type: 'array', items: { type: 'object', additionalProperties: true } },
          rationale: { type: 'string', description: 'why these are the same finding / how the split was made' },
        },
      },
    },
    notes: { type: 'array', items: { type: 'string' } },
  },
}

// Adjudicate each multi-member candidate cluster (parallel). Singletons pass
// through in JS unchanged (nothing to merge).
const adjudicated = await parallel(multi.map((c) => () => {
  const members = (c.members || []).map((u) => byUid.get(u)).filter(Boolean)
  return agent(
    `ROLE: DUPLICATE ADJUDICATOR (merge only TRUE duplicates). cwd is repo root.\n` +
    `A deterministic clusterer grouped the findings below as CANDIDATE duplicates (signals: ${JSON.stringify(c.signals || [])}). Decide which are genuinely THE SAME underlying finding — same root cause on the SAME affected asset — and which are distinct (the clusterer is high-recall and can over-group).\n\n` +
    `MATCHING KEYS (the standard): same affected host/apex/URL + same vulnerability class (CWE) + same CVE ⇒ duplicate. Different asset, or different vulnerability class ⇒ DISTINCT even if titles look alike.\n\n` +
    `CANDIDATE MEMBERS (normalized from their source reports):\n${JSON.stringify(members, null, 1)}\n\n` +
    `Produce canonical[] — one entry PER distinct real finding (a cluster may resolve to 1, or split into several). For each canonical finding:\n` +
    `- merged_from = the uids that are the same finding.\n` +
    `- Choose the CLEAREST title/description/impact/recommendation across the members. UNION their evidence_refs and poc steps. UNION affected[], cves[], references[].\n` +
    `- severity/cvss: take the BEST-EVIDENCED value (do NOT inflate). If the members disagree, prefer the one whose evidence + CVSS vector actually support it; the workflow will still independently recompute the CVSS. Rate the CONFIRMED base severity — do not carry a higher vendor rating into severity (it may go in a calibration note later).\n` +
    `- rationale: one line on why they merge / how you split.\n` +
    `You may read the evidence_refs files to decide. Return ADJUDICATE_SCHEMA. Do NOT drop a member entirely — if one is actually distinct, give it its own canonical entry.`,
    { schema: ADJUDICATE_SCHEMA, label: `dedup:${c.cluster_id}`, phase: 'Dedup', agentType: 'general-purpose' }
  ).catch(() => null)
}))

// Build the canonical set in JS: adjudicated multi-clusters + pass-through singles.
function mergeNormalized(members, over) {
  const uniq = (arr) => Array.from(new Set(arr.filter(Boolean)))
  const firstDef = (arr) => { for (const v of arr) if (v != null) return v; return null }
  const pick = (k) => over[k] != null && over[k] !== '' ? over[k] : (members.map((m) => m[k]).find((v) => v != null && v !== '') || null)
  return {
    merged_from: over.merged_from && over.merged_from.length ? over.merged_from : members.map((m) => m.uid),
    sources: uniq(members.map((m) => m.source)),
    title: over.title || pick('title'),
    severity: (over.severity && SEVERITY.includes(over.severity)) ? over.severity : (members.map((m) => m.severity).find((s) => SEVERITY.includes(s)) || null),
    cvss_score: over.cvss_score != null ? Number(over.cvss_score) : firstDef(members.map((m) => m.cvss_score)),
    cvss_vector: over.cvss_vector || pick('cvss_vector'),
    cwe: over.cwe || pick('cwe'), owasp: over.owasp || pick('owasp'),
    cves: uniq([].concat(over.cves || [], ...members.map((m) => m.cves || []))),
    affected: uniq([].concat(over.affected || [], ...members.map((m) => m.affected || []))),
    url: over.url || pick('url'), param: over.param || pick('param'),
    description: over.description || pick('description'),
    impact: over.impact || pick('impact'),
    recommendation: over.recommendation || pick('recommendation'),
    references: uniq([].concat(over.references || [], ...members.map((m) => m.references || []))),
    evidence_refs: uniq([].concat(over.evidence_refs || [], ...members.map((m) => m.evidence_refs || []))),
    poc: (over.poc && over.poc.length) ? over.poc : [].concat(...members.map((m) => m.poc || [])),
  }
}

let canonical = []
// singletons
for (const c of singles) {
  const m = byUid.get((c.members || [])[0])
  if (m) canonical.push(mergeNormalized([m], { merged_from: [m.uid] }))
}
// adjudicated multi-clusters
multi.forEach((c, idx) => {
  const res = adjudicated[idx]
  const members = (c.members || []).map((u) => byUid.get(u)).filter(Boolean)
  if (res && Array.isArray(res.canonical) && res.canonical.length) {
    for (const over of res.canonical) {
      const mm = (over.merged_from && over.merged_from.length ? over.merged_from : c.members).map((u) => byUid.get(u)).filter(Boolean)
      canonical.push(mergeNormalized(mm.length ? mm : members, over))
    }
  } else {
    // adjudication failed — keep the members as ONE conservative canonical (audit-safe; verify catches it).
    canonical.push(mergeNormalized(members, { merged_from: members.map((m) => m.uid) }))
  }
})

// Cross-cluster sweep (barrier): catch semantic duplicates no structural signal
// linked. Operates on the canonical titles+assets only; merges applied in JS.
const SWEEP_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['merges'],
  properties: {
    merges: { type: 'array', items: { type: 'object', additionalProperties: true, required: ['keep', 'absorb'], properties: { keep: { type: 'number', description: 'index of the canonical to keep' }, absorb: { type: 'array', items: { type: 'number' }, description: 'indices to fold into keep' }, reason: { type: 'string' } } } },
    notes: { type: 'array', items: { type: 'string' } },
  },
}
const sweepList = canonical.map((f, i) => ({ i, title: f.title, affected: f.affected, cwe: f.cwe, cves: f.cves }))
const sweep = canonical.length > 1 ? await agent(
  `ROLE: CROSS-CLUSTER DUP SWEEP (final duplicate pass). cwd is repo root.\n` +
  `Below are the CANONICAL findings after per-cluster merging. Find any that are STILL the same underlying finding (same affected asset + same underlying issue) but were not linked earlier — e.g. described very differently across reports. IMPORTANT: the same issue is frequently given DIFFERENT CWE labels across separate reports (inconsistent labeling), so a CWE mismatch does NOT prove they are distinct — when two findings share the same affected host AND describe the same behaviour, treat them as the same issue even if their CWE (or a cited port that is off-by-100, a typo) differs. Still be conservative: same host + genuinely different vulnerabilities stay separate.\n\n` +
  `CANONICAL (index, title, affected, cwe, cves):\n${JSON.stringify(sweepList, null, 1)}\n\n` +
  (candidatePairs.length ? `DETERMINISTIC HOST-OVERLAP HINT — the clusterer flagged these ORIGINAL findings as sharing a host (examine the corresponding canonicals especially closely; the same issue may carry different CWE labels): ${JSON.stringify(candidatePairs.slice(0, 40))}\n\n` : '') +
  `Return SWEEP_SCHEMA: merges[] where each {keep:<index to keep>, absorb:[indices to fold in], reason}. If there are no further duplicates, return merges:[].`,
  { schema: SWEEP_SCHEMA, label: 'dedup:sweep', phase: 'Dedup', agentType: 'general-purpose' }
).catch(() => null) : { merges: [] }

if (sweep && Array.isArray(sweep.merges) && sweep.merges.length) {
  const absorbed = new Set()
  // Resolve indices through the absorption chain so a pairwise merge chain
  // (e.g. [{keep:0,absorb:[1]},{keep:1,absorb:[2]}]) folds 2 into 0's surviving
  // root instead of into the already-absorbed 1 (which the filter would drop,
  // silently losing 2's provenance). Union-find over canonical indices.
  const redirect = new Map()
  const rootOf = (i) => { let r = i; while (redirect.has(r)) r = redirect.get(r); return r }
  for (const mrg of sweep.merges) {
    const keepIdx = rootOf(mrg.keep)
    const keep = canonical[keepIdx]
    if (!keep) continue
    for (const ai0 of (mrg.absorb || [])) {
      const ai = rootOf(ai0)
      const other = canonical[ai]
      if (!other || ai === keepIdx || absorbed.has(ai)) continue
      keep.merged_from = Array.from(new Set([...(keep.merged_from || []), ...(other.merged_from || [])]))
      keep.sources = Array.from(new Set([...(keep.sources || []), ...(other.sources || [])]))
      keep.evidence_refs = Array.from(new Set([...(keep.evidence_refs || []), ...(other.evidence_refs || [])]))
      keep.affected = Array.from(new Set([...(keep.affected || []), ...(other.affected || [])]))
      keep.cves = Array.from(new Set([...(keep.cves || []), ...(other.cves || [])]))
      keep.poc = (keep.poc && keep.poc.length) ? keep.poc : (other.poc || [])
      absorbed.add(ai)
      redirect.set(ai, keepIdx)
    }
  }
  canonical = canonical.filter((_, i) => !absorbed.has(i))
  log(`Cross-cluster sweep folded ${absorbed.size} additional duplicate(s).`)
}

// Deterministic order (severity desc, then cvss desc, then title) + canonical IDs.
const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 }
const sevRank = (s) => (SEV_ORDER[s] != null ? SEV_ORDER[s] : 5)
canonical.sort((x, y) => sevRank(x.severity) - sevRank(y.severity) || (Number(y.cvss_score) || 0) - (Number(x.cvss_score) || 0) || String(x.title).localeCompare(String(y.title)))
canonical.forEach((f, i) => { f.canonical_id = `MRG-${String(i + 1).padStart(3, '0')}` })

const dupCollapsed = allFindings.length - canonical.length
log(`Dedup complete: ${allFindings.length} raw -> ${canonical.length} canonical finding(s) (${dupCollapsed} duplicate(s) collapsed).`)

let toValidate = canonical
if (canonical.length > MAX_FINDINGS) {
  log(`NOTE: ${canonical.length} canonical findings; re-validating the top ${MAX_FINDINGS} by severity (max_findings). The remaining ${canonical.length - MAX_FINDINGS} are recorded in artifacts/merged/canonical.json but are NOT re-validated or included in the report PDF — raise max_findings to cover them.`)
  toValidate = canonical.slice(0, MAX_FINDINGS)
}

// ============================================================================
// PHASE: Validate — pipeline per canonical finding (corroborate -> refute -> verdict)
// ============================================================================
phase('Validate')
if (MERGE_ONLY) log('MERGE_ONLY mode: skipping adversarial re-validation — no finding will be discarded as a false positive. Per-finding CVSS is still recomputed/adjusted from the vector and duplicates are still collapsed.')
const NVD_KEV = nvdKevText()

const CORROBORATION_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['finding_id', 'corroboration', 'cvss', 'cve', 'report_fields'],
  properties: {
    finding_id: { type: 'string' },
    corroboration: {
      type: 'object', additionalProperties: true,
      properties: {
        evidence_present: { type: 'boolean' }, evidence_readable: { type: 'boolean' },
        status: { type: 'string', enum: ['substantiated', 'plausible_unverified', 'contradicted', 'absent'] },
        evidence_contradicts: { type: 'boolean' },
        independently_reproduced: { type: 'boolean', description: 'true only if a runnable PoC was present and you re-ran it read-only and observed the result' },
        detail: { type: 'string' },
      },
    },
    cvss: {
      type: 'object', additionalProperties: true,
      properties: {
        recomputed: { type: 'boolean' },
        computed_score: { type: ['number', 'null'], description: 'from-vector recompute via tools/cvss_calc.py (v4.0-primary; scores v4.0/v3.1/v3.0/v2.0)' },
        vector: { type: ['string', 'null'], description: 'the vector used/corrected' },
        claimed_score: { type: ['number', 'null'] }, claimed_vector: { type: ['string', 'null'] },
        band_consistent: { type: 'boolean' }, detail: { type: 'string' },
      },
    },
    cve: {
      type: 'object', additionalProperties: true,
      properties: {
        applicable: { type: 'boolean' }, primary_cve: { type: ['string', 'null'] },
        nvd_score: { type: ['number', 'null'] }, computed_score: { type: ['number', 'null'] },
        claimed_score: { type: ['number', 'null'] }, vector: { type: ['string', 'null'] }, claimed_vector: { type: ['string', 'null'] },
        on_kev: { type: 'boolean' }, cwes: { type: 'array', items: { type: 'string' } },
        cves: { type: 'array', items: { type: 'object', additionalProperties: true } },
      },
    },
    is_web: { type: 'boolean' },
    poc: {
      type: 'array',
      description: 'the reproducible PoC as an ordered list of {description, command, image_url} steps (image_url = engagement-root-relative path to a bundled screenshot/output)',
      items: { type: 'object', additionalProperties: true, required: ['description'], properties: { description: { type: 'string' }, command: { type: 'string' }, image_url: { type: 'string' } } },
    },
    report_fields: {
      type: 'object', additionalProperties: true,
      properties: {
        title: { type: 'string' }, affected: { type: 'array', items: { type: 'string' } },
        description: { type: 'string' }, impact: { type: 'string' }, recommendation: { type: 'string' },
        ease_of_exploitation: { type: 'string' }, references: { type: 'array', items: { type: 'string' } },
        cwe: { type: ['string', 'null'] }, owasp: { type: ['string', 'null'] }, calibration: { type: ['string', 'null'] },
      },
    },
    proof_dir: { type: ['string', 'null'] },
    summary: { type: 'string' },
  },
}

const VOTE_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['refuted'],
  properties: { refuted: { type: 'boolean' }, reason: { type: 'string' }, weakest_link: { type: 'string' } },
}

function corroboratePrompt(f) {
  return `ROLE: MERGE-EVIDENCE CORROBORATOR (validate ONE carried-over finding against its own evidence). cwd is repo root. Mount skills/coordination/reference/VALIDATION.md (for the evidentiary standard). Do NOT read other findings.\n\n` +
    `CANONICAL FINDING: ${f.canonical_id}\nMERGED FROM: ${JSON.stringify(f.merged_from)}\nTITLE: ${f.title}\n` +
    `CLAIMED: severity=${f.severity || '?'} cvss=${f.cvss_score != null ? f.cvss_score : '?'} vector=${f.cvss_vector || '?'} cwe=${f.cwe || '?'}\n` +
    `CVE(s): ${JSON.stringify(f.cves || [])}\nAFFECTED: ${JSON.stringify(f.affected || [])}\nURL/param: ${f.url || '-'} / ${f.param || '-'}\n` +
    `EVIDENCE FILES (already copied into the merged tree): ${JSON.stringify(f.evidence_refs || [])}\n` +
    `SOURCE DESCRIPTION: ${(f.description || '').slice(0, 1500)}\nSOURCE IMPACT: ${(f.impact || '').slice(0, 800)}\nSOURCE RECOMMENDATION: ${(f.recommendation || '').slice(0, 800)}\n\n` +
    `Do ALL of:\n` +
    `A) EVIDENCE CORROBORATION — open every evidence_ref file and judge whether it ACTUALLY substantiates the claim (not incidental/ambiguous/self-asserted). Set corroboration.status:\n` +
    `   - "substantiated" — the evidence clearly demonstrates the vulnerability.\n` +
    `   - "plausible_unverified" — consistent with the claim but not conclusive (thin/partial static evidence).\n` +
    `   - "contradicted" — the evidence shows the finding is NOT present / is a false positive (e.g. the response is actually 403, the "secret" is a public value, the CVE does not apply to the observed version).\n` +
    `   - "absent" — no usable evidence was supplied.\n` +
    `   If a runnable PoC command is present and SAFE (read-only, non-destructive, on the stated target), you MAY re-run it once to confirm; set independently_reproduced accordingly. NO brute force, NO DoS, NO destructive writes. If re-running is not possible/safe, do not — rely on the supplied evidence.\n` +
    `B) CVSS RECOMPUTE (always) — compute the base score from the vector with the canonical tool \`python3 tools/cvss_calc.py "<vector>"\` (CVSS v4.0-primary; scores v4.0/v3.1/v3.0/v2.0). Prefer a CVSS v4.0 vector; if only lower-version vectors exist use the highest available (v3.1 -> v3.0 -> v2.0). If no vector is given, derive the most defensible CVSS v4.0 vector from the evidence and compute from it. Report cvss.{recomputed, computed_score, vector, claimed_score, claimed_vector, band_consistent}. This is the ONLY sanctioned score computation — do not hand-roll the math.\n` +
    `C) CVE LANE (if any CVE present) — you are the TOOL that fetches the numbers; the workflow reconciles them:\n${NVD_KEV.join('\n')}\n   Return cve.{applicable, primary_cve, nvd_score, computed_score, claimed_score, vector, claimed_vector, on_kev, cwes[], cves:[{id,score,severity}]}.\n` +
    `D) PROOF PACKAGE — write ${OUTPUT_DIR}/reports/appendix/${f.canonical_id}/ with a corroboration.md (what each evidence file shows, the CVSS recompute, the CVE checks) and COPY the decisive evidence images/files into it. Author the reproducible PoC as poc[] — ordered {description, command, image_url} steps; image_url must be an engagement-root-relative path to a bundled image (e.g. ${OUTPUT_DIR}/reports/appendix/${f.canonical_id}/step1.png). Step 1 is an entry point; the last step is the observed result. proof_dir=${OUTPUT_DIR}/reports/appendix/${f.canonical_id}.\n` +
    `E) report_fields{title, affected[], description, impact, recommendation, ease_of_exploitation, references[], cwe, owasp}: the clean human-facing fields for the merged report. Do NOT include secrets/PII verbatim (redact). Do NOT pre-escape HTML — the generator escapes finding fields.\n\n` +
    `Return CORROBORATION_SCHEMA. Be strict and evidence-bound: if the evidence does not support a claim, say so (status contradicted/absent) — a false positive must be caught here.`
}

function refuterPrompt(f, i) {
  return `ROLE: ADVERSARIAL VALIDATOR #${i} (blind). Decide whether canonical finding ${f.canonical_id} ("${f.title}") is a FALSE POSITIVE that must be DISCARDED from the report. You see ONLY its evidence — not any corroborator's verdict, not other findings. These findings were carried over from FINISHED reports, so their evidence is STATIC (scan output, screenshots, request/response captures, a faithful tester summary) — not necessarily a live re-runnable transcript.\n\n` +
    `Read the evidence files: ${JSON.stringify(f.evidence_refs || [])} and the proof package under ${OUTPUT_DIR}/reports/appendix/${f.canonical_id}/.\n\n` +
    `REFUTE (refuted=true) ONLY IF the finding's CORE security issue is not real — exactly one of:\n` +
    `  (a) CONTRADICTED — the evidence shows the issue is NOT present (e.g. the response is actually 403 / the CVE probe returned patched, the "secret" is a public value, the CVE does not apply to the observed product/version);\n` +
    `  (b) UNSUPPORTED AT ALL — the evidence is absent or so incidental that the underlying issue is not demonstrated in ANY form. NOTE: a faithful prose summary of a standard, reproducible observation (e.g. open DNS recursion, an open TLS port, a rendered login portal) DOES count as evidence — do NOT refute merely because it is a summary rather than a raw pcap/transcript;\n` +
    `  (c) OUT OF SCOPE — the affected asset is not in scope or is unreachable;\n` +
    `  (d) NOT A SECURITY FINDING — it describes a hardening BEST PRACTICE as if it were a weakness (e.g. "version string is hidden" reframed as "missing patch").\n\n` +
    `Apply the common false-High checklist \`skills/coordination/reference/severity-calibration.md\`. These collapse the claim to NOTHING → refute per (a)/(d): an Azure \`AADSTS50126\` (failed auth) read as "MFA disabled" (Entra checks credentials before MFA); a CORS reflected-origin scored as token-theft when there is NO \`Access-Control-Allow-Credentials: true\` + cookie-auth (only missing-hardening); a scanner version-"Critical" that is a CONFIRMED distro-backport / appliance-bundled fix (already patched). But an ENABLER-scored-as-demonstrated, or a CVE-without-its-precondition, where the CORE issue is still real, is NOT a discard — the workflow independently re-scores it; leave it.\n\n` +
    `Do NOT refute for any of these — they are NOT false positives:\n` +
    `  - the CVSS score / severity looks too high: the workflow INDEPENDENTLY RECOMPUTES the score from the vector, so an over-score is CORRECTED, not discarded;\n` +
    `  - a secondary or title detail is imprecise (an exact port count, a product/vendor label, a third-party-cert attribution) while the CORE issue is proven: that is fixed by editing the title/scope, not by discarding the finding;\n` +
    `  - you personally would have rated or worded it differently.\n` +
    `A finding whose core vulnerability is REAL and evidenced must NOT be refuted, even if its score or wording needs adjustment.\n\n` +
    `Return VOTE_SCHEMA: refuted (true ONLY for a genuine false positive per (a)-(d) above), reason (name which of (a)-(d) applies, or why it is real), weakest_link (the single most doubtful element — state it even when you do NOT refute).`
}

const results = await pipeline(
  toValidate,
  // Stage A — evidence corroboration + CVSS recompute + CVE lane (the tool-runner).
  (f) => agent(corroboratePrompt(f), { schema: CORROBORATION_SCHEMA, label: `corroborate:${f.canonical_id}`, phase: 'Validate', agentType: 'general-purpose' }).catch(() => null),
  // Stage B — N blind adversarial refuters (evidence-only). SKIPPED in MERGE_ONLY
  // mode: no refutation runs and nothing is discarded as a false positive.
  (corr, f) => {
    if (!corr) return Promise.resolve({ corr: null, votes: [] })
    if (MERGE_ONLY) return Promise.resolve({ corr, votes: [] })
    return parallel(Array.from({ length: VOTES }, (_, i) => () =>
      agent(refuterPrompt(f, i + 1), { schema: VOTE_SCHEMA, label: `refute:${f.canonical_id}#${i + 1}`, phase: 'Validate', agentType: 'general-purpose' })
    )).then((votes) => ({ corr, votes: votes.filter(Boolean) }))
  },
  // Stage C — PURE JS. Reconcile the CVE numbers, then the deterministic verdict.
  (carry, f) => {
    const corr = carry ? carry.corr : null
    const votes = (carry && carry.votes) || []
    if (corr && corr.cve && corr.cve.applicable) {
      corr.cve.reconciled = cveReconcile({
        claimed_score: corr.cve.claimed_score, computed_score: corr.cve.computed_score, nvd_score: corr.cve.nvd_score,
        claimed_vector: corr.cve.claimed_vector, computed_vector: corr.cve.vector,
      }).reconciled
    }
    const verdict = MERGE_ONLY ? mergeOnlyVerdict(f, corr) : mergeVerdict(f, corr, votes, { votesTotal: VOTES })
    return { finding: f, corr, votes, verdict, interim: buildMergeInterim(f, corr, verdict, { tier: BUSINESS_TIER, platform: PLATFORM, votes: EFFECTIVE_VOTES }) }
  },
)

const clean = results.filter(Boolean)
const isPass = (v) => v === 'VALID' || v === 'REPAIRED'
const kept = clean.filter((r) => isPass(r.verdict.verdict))
const rejected = clean.filter((r) => r.verdict.verdict === 'REJECTED')
const dropped = clean.filter((r) => r.verdict.verdict === 'DROPPED')
const needsLive = kept.filter((r) => r.interim.needs_live_confirmation)
log(`${MERGE_ONLY ? 'Merge (no re-validation)' : 'Validate'} done: ${kept.length} kept (${needsLive.length} flagged needs-live-confirmation), ${rejected.length} discarded as false positive, ${dropped.length} dropped (infra) of ${clean.length}.`)

// ============================================================================
// PHASE: Report — persist verbatim, author exec summary, build PDF + zip
// ============================================================================
phase('Report')

// Build write-plan + dedup map in JS; a writer persists exact bytes (no judgment).
const counts = { raw: allFindings.length, canonical: canonical.length, validated: kept.length, rejected: rejected.length, dropped: dropped.length, duplicates_collapsed: dupCollapsed, needs_live_confirmation: needsLive.length }
const sevCounts = {}
for (const r of kept) sevCounts[r.interim.severity] = (sevCounts[r.interim.severity] || 0) + 1

const writePlan = []
for (const r of clean) {
  const sub = terminalSubdir(r.verdict.verdict)
  writePlan.push({ path: `${OUTPUT_DIR}/artifacts/${sub}/${r.interim.finding_id}.json`, content: JSON.stringify(r.interim, null, 2) })
}
const mergeMap = {
  counts,
  sources: sources.map((s) => ({ slug: s.slug, original: s.original || s.path })),
  findings: clean.map((r) => ({ canonical_id: r.interim.finding_id, verdict: r.verdict.verdict, severity: r.interim.severity, cvss_score: r.interim.cvss_score, title: (r.interim.report_fields || {}).title || r.finding.title, merged_from: r.interim.merged_from, needs_live_confirmation: r.interim.needs_live_confirmation, refuted: r.verdict.refuteCount || 0, failed_checks: r.verdict.failed_checks || [] })),
}
writePlan.push({ path: `${OUTPUT_DIR}/reports/merge-map.json`, content: JSON.stringify(mergeMap, null, 2) })
// Full canonical set (incl. any over the max_findings cap) for the audit record.
writePlan.push({ path: `${OUTPUT_DIR}/artifacts/merged/canonical.json`, content: JSON.stringify(canonical, null, 2) })

const writer = await agent(
  `ROLE: MERGE WRITER (persist verbatim — no judgment, no regeneration). cwd is repo root. Ensure ${OUTPUT_DIR}/{artifacts/validated,artifacts/false-positives,artifacts/dropped,reports} exist.\n` +
  `FIRST, purge any stale per-finding interim from a previous pass so the terminal-verdict dirs are an exact function of THIS run (on a resumed run a finding's verdict can flip, e.g. REJECTED->VALID, and the old copy must not linger in the other dir): run \`rm -f ${OUTPUT_DIR}/artifacts/validated/*.json ${OUTPUT_DIR}/artifacts/false-positives/*.json ${OUTPUT_DIR}/artifacts/dropped/*.json\` (leave ${OUTPUT_DIR}/artifacts/merged/ untouched).\n` +
  `THEN write EACH file below with EXACTLY the given content (byte-for-byte — do not reformat, re-key, or add fields):\n` +
  writePlan.map((w, i) => `--- FILE ${i + 1}: ${w.path} ---\n${w.content}`).join('\n') +
  `\n\nReturn {written:<count>}.`,
  { schema: { type: 'object', additionalProperties: true, required: ['written'], properties: { written: { type: 'number' } } }, label: 'report:writer', phase: 'Report', agentType: 'general-purpose' }
).catch(() => null)

// Author the executive summary (judgment prose) → engagement-meta.json. narrative
// MUST be a LIST; &,<,> in narrative/key_risks/positives are escaped (raw sinks).
const keptBrief = kept.map((r) => ({ id: r.interim.finding_id, title: (r.interim.report_fields || {}).title || r.finding.title, severity: r.interim.severity, cvss: r.interim.cvss_score, cves: (r.interim.cves || []).map((c) => c.id || c), needs_live: r.interim.needs_live_confirmation, sources: r.interim.sources }))
const metaAuthored = await agent(
  `ROLE: MERGED-REPORT META AUTHOR (judgment prose only; you do NOT assemble the report). cwd is repo root.\n` +
  `Read ${OUTPUT_DIR}/reports/merge-map.json for the full picture. This is a CONSOLIDATION of ${sources.length} source report(s) into one register.\n` +
  `MERGE STATS: raw findings ingested=${counts.raw}; canonical after dedup=${counts.canonical}; duplicates collapsed=${counts.duplicates_collapsed}; validated (kept)=${counts.validated}; discarded as false positive=${counts.rejected}; flagged needs-live-confirmation=${counts.needs_live_confirmation}. Severity counts of the KEPT set: ${JSON.stringify(sevCounts)}.\n` +
  `KEPT FINDINGS (brief): ${JSON.stringify(keptBrief).slice(0, 6000)}\n\n` +
  `Update ${OUTPUT_DIR}/engagement-meta.json (PRESERVE its existing keys — engagement_name, started, kind, resume_round, input_manifest) by ADDING two keys:\n` +
  `1. "engagement" = {"title": ${JSON.stringify(TITLE)}, "subtitle": "Consolidated & Re-validated Findings", ${CLIENT ? `"target": ${JSON.stringify(CLIENT)}, ` : ''}"method": "Multi-report consolidation with independent evidence re-validation, CVSS recomputation, and de-duplication", "classification": "Confidential", "report_id": "MERGE-<date_tag>", "date": "$(date -u +%Y-%m-%d)"}. Compute <date_tag> with \`date -u +%Y%m%d\`.\n` +
  `2. "executive_summary" = {"narrative": [<paragraphs>], "key_risks": [<strings>], "positives": [<strings>]}.\n` +
  `   HARD RULES for the executive_summary (the generator feeds these RAW into ReportLab):\n` +
  `   - narrative MUST be a JSON LIST of paragraph strings (never one big string — a string renders one character per line).\n` +
  `   - In narrative/key_risks/positives ONLY, escape every & < > as &amp; &lt; &gt; (they are raw sinks). Do NOT escape anything else.\n` +
  `   - The narrative must state that this is a merge of ${sources.length} reports, how many raw findings were consolidated to ${counts.canonical} canonical (with ${counts.duplicates_collapsed} duplicates removed), how many were discarded as false positives (${counts.rejected}) after independent evidence re-validation and adversarial review, that CVSS scores were recomputed from their vectors and readjusted to authoritative values, and ${counts.needs_live_confirmation} finding(s) are flagged for live re-confirmation. Then summarize the risk posture by severity.\n` +
  `Return {written:true, report_id, date_tag}.`,
  { schema: { type: 'object', additionalProperties: true, required: ['written'], properties: { written: { type: 'boolean' }, report_id: { type: ['string', 'null'] }, date_tag: { type: ['string', 'null'] } } }, label: 'report:meta', phase: 'Report', agentType: 'general-purpose' }
).catch(() => null)

// Deterministic finalize: report_data_build.py -> generate_report.py -> summary + merge-report.md -> zip.
const pdfPath = `${OUTPUT_DIR}/reports/Consolidated-Security-Report.pdf`
const zipName = `merged-report_deliverable.zip`
const FINALIZE_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['report_data_ok', 'render_ok', 'zip_ok'],
  properties: {
    report_data_ok: { type: 'boolean' }, findings: { type: ['number', 'null'] }, severity_counts: { type: 'object', additionalProperties: true },
    report_data_lint_ok: { type: 'boolean', description: 'tools/report_data_lint.py exited 0 (schema + RAW-field escaping gate before render)' },
    report_data_path: { type: ['string', 'null'] }, report_data_sha: { type: ['string', 'null'] },
    render_ok: { type: 'boolean' }, pdf_path: { type: ['string', 'null'] },
    zip_ok: { type: 'boolean' }, deliverable_zip: { type: ['string', 'null'] }, zip_entries: { type: ['number', 'null'] },
    stray_validated_dirs: { type: 'array', items: { type: 'string' }, description: 'any **/artifacts/validated under input/ (should be empty)' },
    notes: { type: 'array', items: { type: 'string' } },
  },
}
const finalize = await agent(
  `ROLE: MERGE FINALIZE RUNNER (deterministic tool-runner; run commands, relay facts — do NOT author the report). cwd is repo root. Engagement dir: ${OUTPUT_DIR}.\n\n` +
  `0. GLOB-TRAP GUARD: run \`find ${OUTPUT_DIR}/input -path '*/artifacts/validated/*.json' 2>/dev/null\`. If it prints ANY path, MOVE each out of the way (rename the enclosing 'validated' dir to 'validated_src') so report_data_build does NOT ingest source interims. Report the list as stray_validated_dirs.\n` +
  `1. Assemble the canonical report_data.json (sole-owner merge — no LLM authoring): run EXACTLY \`python3 tools/report_data_build.py --engagement-dir ${OUTPUT_DIR} -o ${OUTPUT_DIR}/reports/report_data.json\`. It prints a JSON summary — set report_data_ok iff exit 0; copy findings, severity_counts, sha256(->report_data_sha), out(->report_data_path). (It reads ONLY ${OUTPUT_DIR}/**/artifacts/validated/*.json — i.e. this run's VALID interims.)\n` +
  `1b. REPORT-DATA LINT (HARD GATE before render): run EXACTLY \`python3 tools/report_data_lint.py ${OUTPUT_DIR}/reports/report_data.json\`. Set report_data_lint_ok iff exit 0; if non-zero, copy its errors[] into notes and DO NOT render (a bare '&'/disallowed tag in a RAW field, a string-not-list narrative, or a bad severity must never reach the client PDF).\n` +
  `2. Render the PDF: run EXACTLY \`python3 skills/transilience-report-style/reference/generate_report.py ${OUTPUT_DIR}/reports/report_data.json -o ${pdfPath} --assets formats/transilience-report-style --theme light\`. render_ok iff exit 0 AND ${pdfPath} exists and is non-empty. pdf_path=${pdfPath}.\n` +
  `3. Human summaries: write ${OUTPUT_DIR}/reports/summary.md (a short stats block: sources=${sources.length}; raw=${counts.raw}; canonical=${counts.canonical}; duplicates_collapsed=${counts.duplicates_collapsed}; kept=${counts.validated}; false_positives_discarded=${counts.rejected}; needs_live_confirmation=${counts.needs_live_confirmation}; severity_counts from step 1).${dedupWarnings.length ? ` ALSO add a "⚠ Dedup warnings (reviewer must confirm — not auto-collapsed)" section listing: ${JSON.stringify(dedupWarnings)}.` : ''} ALSO write ${OUTPUT_DIR}/reports/merge-report.md from ${OUTPUT_DIR}/reports/merge-map.json — a reconciliation table (canonical_id | title | severity | CVSS | merged_from source ids | verdict) for the KEPT findings, then a "Discarded as false positive" appendix (canonical_id | title | why) and a "Needs live confirmation" list.\n` +
  `4. Package the deliverable (directory-based so empty globs never fail): run EXACTLY \`cd ${OUTPUT_DIR} && rm -f ${zipName}; zip -r ${zipName} reports input logs artifacts -x '*tool-invocations.jsonl' 2>/dev/null; unzip -l ${zipName} | tail -1\`. zip_ok iff the zip exists and is non-empty; deliverable_zip=${OUTPUT_DIR}/${zipName}; zip_entries = the trailing file count from \`unzip -l … | tail -1\`.\n` +
  `Return FINALIZE_SCHEMA.`,
  { schema: FINALIZE_SCHEMA, label: 'report:finalize', phase: 'Report', agentType: 'general-purpose' }
).catch((err) => ({ report_data_ok: false, render_ok: false, zip_ok: false, notes: [String(err)] }))

// ============================================================================
// PHASE: Verify — blind re-open of the merged deliverable
// ============================================================================
phase('Verify')
const VERIFY_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['status', 'findings_in_report', 'issues'],
  properties: {
    status: { type: 'string', description: 'OK | ISSUES' },
    findings_in_report: { type: 'number' },
    no_discarded_leaked: { type: 'boolean' },
    cvss_bands_consistent: { type: 'boolean' },
    evidence_bundled: { type: 'boolean' },
    pdf_present: { type: 'boolean' },
    issues: { type: 'array', items: { type: 'string' } },
  },
}
const verify = await agent(
  `ROLE: MERGED-DELIVERABLE VERIFIER (blind; independent). cwd is repo root. You did not build these files.\n` +
  `Open ${OUTPUT_DIR}/reports/report_data.json, ${pdfPath}, ${OUTPUT_DIR}/reports/merge-map.json, and list ${OUTPUT_DIR}/artifacts/false-positives/.\n` +
  `Confirm ALL of: (a) report_data.findings count == the number of VALID interims in ${OUTPUT_DIR}/artifacts/validated/ == the kept count in merge-map (${counts.validated}); (b) NO finding whose id is under artifacts/false-positives/ or artifacts/dropped/ appears in report_data.findings (no discarded finding leaked); (c) every finding's severity matches its cvss_score band (Critical>=9, High>=7, Medium>=4, else Low; Info when no score); (d) each finding's evidence/proof_dir exists and the PDF is present and non-empty; (e) the deliverable zip ${OUTPUT_DIR}/${zipName} lists reports/, artifacts/ and input/ entries.\n` +
  `status="OK" iff (a),(b),(c),(d) all hold; else "ISSUES" and list each concrete problem in issues[]. Return VERIFY_SCHEMA.`,
  { schema: VERIFY_SCHEMA, label: 'verify', phase: 'Verify', agentType: 'general-purpose' }
).catch(() => null)

const ok = !!(finalize && finalize.report_data_ok && finalize.report_data_lint_ok && finalize.render_ok && finalize.zip_ok && verify && verify.status === 'OK')
log(`merge-reports ${ok ? 'DONE' : 'DONE_WITH_ISSUES'}: ${counts.validated} finding(s) in the merged report; ${counts.rejected} false positive(s) discarded; ${counts.duplicates_collapsed} duplicate(s) collapsed.`)

return {
  status: ok ? 'DONE' : 'DONE_WITH_ISSUES',
  output_dir: OUTPUT_DIR,
  sources: sources.map((s) => s.original || s.path),
  counts,
  severity_counts: sevCounts,
  report_data: (finalize && finalize.report_data_path) || `${OUTPUT_DIR}/reports/report_data.json`,
  pdf: (finalize && finalize.render_ok) ? pdfPath : null,
  deliverable_zip: (finalize && finalize.zip_ok) ? `${OUTPUT_DIR}/${zipName}` : null,
  merge_map: `${OUTPUT_DIR}/reports/merge-map.json`,
  verify: verify || { status: 'UNVERIFIED' },
}
