export const meta = {
  name: 'validate-findings',
  description: 'Authoritatively verify & validate every finding for an asset: CVEs against NVD + recomputed CVSS math + CISA KEV + vendor advisory; exploits/PoCs actually run and emit the evidence that proves the issue (broken scripts are repaired); risk factor recomputed; claims corroborated against raw evidence; adversarial refutation kills false positives. Emits a per-finding verdict + evidence package + asset validation report. Attach to any pentest activity workflow.',
  whenToUse: 'Validate findings for ONE asset. args: {output_dir, target, findings?, repair?, votes?, business_tier?, max_findings?, strict?}. Discovers findings/finding-* (and any ti-ingest queue/ rows) unless given an explicit list.',
  phases: [
    { title: 'Discover', detail: 'inventory findings + ti-ingest queue rows; classify (exploit/cve/info/config)' },
    { title: 'Validate', detail: 'per finding: authoritative checks (NVD+CVSS math+KEV+exploit run/repair+risk) -> adversarial refutation -> verdict' },
    { title: 'Synthesize', detail: 'dedupe, risk-rank, asset validation report + machine-readable outputs' },
  ],
}

// ============================================================================
// VALIDATE-FINDINGS — the authoritative validation engine.
//
// Extends the canonical procedure (skills/coordination/reference/VALIDATION.md:
// 5 checks + evidence package) with the rigor the user requires:
//   * CVE truth      — tools/nvd-lookup.py (authoritative NVD) AND a from-vector
//                      CVSS RECOMPUTATION (no existing tool does the math), cross-
//                      checked against CISA KEV + the vendor advisory.
//   * Exploit truth  — every finding must have a script that RUNS and emits the
//                      evidence proving the issue. Broken/absent scripts are
//                      REPAIRED (regenerated per cve-poc-generator methodology),
//                      re-run, and confirmed deterministic (regression-sweep
//                      diff-normalization + vuln-class signal token).
//   * Risk truth     — severity band == score; risk factor recomputed per the
//                      risk-prioritiser formula.
//   * Adversarial    — N independent refuters (evidence-only, blind) must fail to
//                      refute, else the finding is rejected.
//
// ATTACHMENT / NESTING: this is invoked by an orchestrator at top level (e.g.
// htb-solve runs it as a sibling phase) or standalone. It does NOT call other
// workflows, so it never trips the one-level workflow() nesting limit.
//
// Sandbox: no Date.now()/Math.random()/new Date() — agents shell out to `date`.
// ============================================================================

// ---- inputs ----------------------------------------------------------------
const a = (args && typeof args === 'object' && !Array.isArray(args)) ? args : {}
let OUTPUT_DIR = (a.output_dir || '').replace(/\/+$/, '')
const TARGET = a.target || null
const EXPLICIT = Array.isArray(a.findings) ? a.findings : null
const REPAIR = a.repair !== false            // default true — fix broken/missing scripts
const DEFAULT_VOTES = 3                       // raised adversarial quorum (was 2)
const VOTES = Number(a.votes) > 0 ? Math.floor(Number(a.votes)) : DEFAULT_VOTES
const MAX_FINDINGS = Number(a.max_findings) > 0 ? Math.floor(Number(a.max_findings)) : 50
const BUSINESS_TIER = a.business_tier || 'unknown' // crown_jewel|revenue|support|dev|unknown
const PLATFORM = a.platform || 'generic'
// Frozen-operand paths (C1). When the orchestrator supplies them the CVE/KEV
// numbers are read from the engagement snapshots (deterministic); standalone /
// regression runs omit them (live fetch, fresh drift detection).
const NVD_CACHE_DIR = a.nvd_cache_dir || null
const KEV_SNAPSHOT = a.kev_snapshot || null
// Deterministic replay-cache (C3). When set, an UNCHANGED finding directory
// restores its recorded verdict via tools/validation_cache.py (no LLM lane) —
// a byte-identical re-validation. Omit for a fresh live validation.
const VALIDATION_CACHE_DIR = a.validation_cache_dir || null

if (!OUTPUT_DIR) {
  log('validate-findings: no output_dir provided')
  return { status: 'ERROR', reason: 'output_dir is required' }
}

// ============================================================================
// DETERMINISTIC HELPERS — inline copy of .claude/workflows/lib/wf-helpers.mjs.
// The sandbox has no import; this copy is kept byte-identical to the module
// (helpers.test.mjs is the tested source of truth). These pure functions own
// the verdict/severity/risk/CVE-reconcile decisions — NO LLM in these paths.
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
  // 1e-9 epsilon: one-decimal scores exactly 0.1 apart (the legit 3.0-vs-3.1
  // rounding-step gap) can land at 0.10000000000000009 in IEEE-754 and wrongly
  // fail a bare `<= 0.1`, spuriously demoting a valid CVE finding.
  const near = (x, y) => x != null && y != null && Math.abs(Number(x) - Number(y)) <= 0.1 + 1e-9
  const haveComputed = computed_score != null
  const vectorOk = !claimed_vector || !computed_vector || normVector(claimed_vector) === normVector(computed_vector)
  const nvdOk = nvd_score == null || near(computed_score, nvd_score)
  const claimOk = claimed_score == null || near(computed_score, claimed_score)
  return { reconciled: !!(haveComputed && vectorOk && nvdOk && claimOk), vectorOk, nvdOk, claimOk, haveComputed }
}
function EVIDENCE_MANIFEST(finding) {
  const dir = `${finding.dir}/evidence/validation`
  const files = [
    { path: `${dir}/validation-summary.md`, type: 'file' },
    { path: `${dir}/poc-rerun-output.txt`, type: 'file' },
    { path: `${dir}/verification-script.py`, type: 'file' },
  ]
  if (finding.is_web) files.push({ path: `${dir}/screenshots/*.png`, type: 'glob' })
  if ((finding.cve_ids || []).length) files.push({ path: `${dir}/cve-verification.md`, type: 'file' })
  if (finding.cites_code) files.push({ path: `${dir}/code-references.md`, type: 'file' })
  return files
}
function evidenceComplete(finding, probe) {
  const manifest = EVIDENCE_MANIFEST(finding)
  const got = new Map(((probe && probe.files) || []).map((f) => [f.path, f]))
  const missing = []
  for (const m of manifest) {
    const hit = got.get(m.path)
    if (!hit || !hit.exists || !(Number(hit.bytes) > 0)) missing.push(m.path)
  }
  return { all_present: missing.length === 0, missing }
}
function computeVerdict(finding, checks, votes, probe, repro, opts = {}) {
  const votesTotal = opts.votesTotal != null ? opts.votesTotal : (votes || []).length
  const refuteCount = (votes || []).filter((v) => v && v.refuted).length
  const majority = Math.floor(votesTotal / 2) + 1
  const refuted = votesTotal > 0 && refuteCount >= majority
  if (checks == null) return { finding_id: finding.id, verdict: 'DEMOTED', failed_checks: ['checks_infra_error'], refuteCount, reason: 'checks stage returned null' }
  const failed = []
  const c = checks.canonical || {}
  for (const k of ['cvss_consistency', 'evidence_exists', 'poc_validation', 'claims_vs_raw', 'log_corroboration']) if (!c[k]) failed.push(`canonical:${k}`)
  if (checks.cve && checks.cve.applicable && !checks.cve.reconciled) failed.push('cve:reconcile')
  const ex = checks.exploit || {}
  const exploitNeeded = finding.type !== 'info' && finding.type !== 'config'
  if (exploitNeeded && !(ex.ran && ex.proven && ex.deterministic && ex.signal_token)) failed.push('exploit:not_proven')
  const ev = evidenceComplete(finding, probe)
  if (!ev.all_present) failed.push('evidence:missing_files')
  if (repro == null) failed.push('poc:repro_unavailable')
  else if (!repro.reproduced) failed.push('poc:not_reproduced')
  if (refuted) return { finding_id: finding.id, verdict: 'REJECTED', failed_checks: failed.concat('adversarial:refuted'), refuteCount }
  if (failed.length === 0) return { finding_id: finding.id, verdict: ex.repaired ? 'REPAIRED' : 'VALID', failed_checks: [], refuteCount }
  return { finding_id: finding.id, verdict: 'DEMOTED', failed_checks: failed, refuteCount, missing_evidence: ev.missing }
}
function finalPoc(checks, repro) {
  const authored = Array.isArray(checks && checks.poc) ? checks.poc : []
  if (repro && repro.reproduced && Array.isArray(repro.corrected_steps) && repro.corrected_steps.length) {
    return repro.corrected_steps
  }
  return authored
}
function terminalSubdir(verdict) {
  if (verdict === 'VALID' || verdict === 'REPAIRED') return 'validated'
  if (verdict === 'REJECTED') return 'false-positives'
  return 'dropped'
}
function nvdKevText(P = {}) {
  const nvd = P.nvd_cache_dir ? `python3 tools/nvd-lookup.py --cache-dir ${P.nvd_cache_dir} <CVE-ID>` : `python3 tools/nvd-lookup.py <CVE-ID>`
  const kev = P.nvd_cache_dir ? `python3 tools/kev-lookup.py --cache-dir ${P.nvd_cache_dir} <CVE-ID> (reads the frozen ${P.kev_snapshot || 'kev-snapshot.json'}, create-on-miss)` : `WebFetch https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json and check whether the CVE is listed`
  return [
    'AUTHORITATIVE CVE SOURCES (do not rely on the finding\'s own claim):',
    `1. NVD: \`${nvd}\` — parse the final \`JSON_SUMMARY: {...}\` line (cve_id, score, severity, cvss_version, cvss_vector, cwes[], status) AND the per-version "Vector:" lines. Use the PRIMARY per the v4.0-first ladder: CVSS v4.0 preferred, then v3.1 -> v3.0 -> v2.0 (nvd-lookup already marks the primary and fills cvss_version/cvss_vector).`,
    `2. CISA KEV (known-exploited): ${kev} (records {cveID, dateAdded, requiredAction, knownRansomwareCampaignUse}). Being on KEV raises real-world priority regardless of base score.`,
    '3. Vendor/official advisory: follow the authoritative reference URLs NVD returns (cve.references) and confirm affected versions + the vulnerability class match the finding. Quote the source.',
    'Reconcile: the finding\'s claimed CVE id, CVSS vector, base score, and severity must all agree with NVD and with your from-vector recomputation (|delta| <= 0.1 on the score, exact match on the vector and band). Flag KEV status. Any unreconciled divergence => CVE check FAILS.',
  ]
}

// ---- shared references mounted into validators -----------------------------
// CVSS base-score computation is delegated to tools/cvss_calc.py (v4.0-primary,
// scores v4.0/v3.1/v3.0/v2.0; the checks agent is the tool-runner); reconcile in JS
// (cveReconcile). The NVD/KEV instruction is single-sourced via nvdKevText and
// frozen per-engagement (nvd_cache_dir/kev_snapshot) for deterministic operands.
const P = { OUTPUT_DIR, TARGET, BUSINESS_TIER, REPAIR, nvd_cache_dir: NVD_CACHE_DIR, kev_snapshot: KEV_SNAPSHOT }
P.NVD_KEV = nvdKevText(P)

// ============================================================================
// PHASE: Discover
// ============================================================================
phase('Discover')

const DISCOVER_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['findings'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: true,
        required: ['id', 'dir'],
        properties: {
          id: { type: 'string' },
          dir: { type: 'string', description: 'findings/finding-NNN/ (or queue scope path)' },
          title: { type: 'string' },
          type: { type: 'string', enum: ['exploit', 'cve', 'info', 'config', 'unknown'] },
          cve_ids: { type: 'array', items: { type: 'string' } },
          claimed_severity: { type: ['string', 'null'] },
          claimed_cvss_vector: { type: ['string', 'null'] },
          claimed_score: { type: ['number', 'null'] },
          has_poc: { type: 'boolean' },
          target_refs: { type: 'array', items: { type: 'string' } },
        },
      },
    },
    notes: { type: 'array', items: { type: 'string' } },
  },
}

const discover = await agent(
  `ROLE: validation discovery. cwd is repo root. Inventory every finding to validate for this asset. Do NOT judge them yet.\n` +
  `OUTPUT_DIR: ${OUTPUT_DIR}\nTARGET: ${TARGET || '(read from findings)'}\n` +
  (EXPLICIT ? `EXPLICIT FINDINGS (validate exactly these): ${JSON.stringify(EXPLICIT)}\n` : '') +
  `\nDo:\n` +
  `1. Ensure these dirs exist: ${OUTPUT_DIR}/artifacts/validated, ${OUTPUT_DIR}/artifacts/false-positives, ${OUTPUT_DIR}/validated, ${OUTPUT_DIR}/false-positives (the last two are the de-dup paths skills/ti-ingest + validator-role read).\n` +
  `2. Enumerate finding sources: every ${OUTPUT_DIR}/findings/finding-* directory, AND any ti-ingest scope rows at ${OUTPUT_DIR}/queue/scope-*.json (schema: scope_id, asset, cve, nvd{}, claim, confidence). Merge into one inventory.\n` +
  `3. For each finding, read description.md (and the scope row) to extract: id, dir, a short title, type (exploit | cve | info | config | unknown), cve_ids[] (regex CVE-\\d{4}-\\d{4,}), claimed_severity, claimed_cvss_vector, claimed_score, has_poc (poc.py present?), target_refs[] (URLs/IPs/endpoints it references).\n` +
  `Return DISCOVER_SCHEMA. If there are zero findings, return findings:[] with a note.`,
  { schema: DISCOVER_SCHEMA, label: 'discover', phase: 'Discover', agentType: 'general-purpose' }
)

const inventory = ((discover && discover.findings) || []).slice(0, MAX_FINDINGS)
if (discover && discover.findings && discover.findings.length > MAX_FINDINGS) {
  log(`NOTE: ${discover.findings.length} findings found; deep-validating first ${MAX_FINDINGS} (max_findings). The rest are NOT silently dropped — raise max_findings to cover them.`)
}
if (!inventory.length) {
  log('validate-findings: no findings to validate.')
  return { status: 'NO_FINDINGS', output_dir: OUTPUT_DIR, counts: { total: 0, valid: 0, rejected: 0, repaired: 0 } }
}
log(`Validating ${inventory.length} finding(s) with ${VOTES} adversarial vote(s) each.`)

// ============================================================================
// Prompt builders
// ============================================================================
const CHECKS_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['finding_id', 'canonical', 'cve', 'exploit', 'risk'],
  properties: {
    finding_id: { type: 'string' },
    canonical: {
      type: 'object', additionalProperties: true, description: 'VALIDATION.md 5 checks',
      properties: {
        cvss_consistency: { type: 'boolean' }, evidence_exists: { type: 'boolean' },
        poc_validation: { type: 'boolean' }, claims_vs_raw: { type: 'boolean' }, log_corroboration: { type: 'boolean' },
        detail: { type: 'string' },
      },
    },
    cve: {
      type: 'object', additionalProperties: true,
      properties: {
        applicable: { type: 'boolean' },
        nvd_score: { type: ['number', 'null'] }, computed_score: { type: ['number', 'null'], description: 'from-vector recompute via tools/cvss_calc.py / nvd-lookup (the TOOL computes it, v4.0-primary; JS reconciles)' },
        claimed_score: { type: ['number', 'null'] }, vector: { type: ['string', 'null'], description: 'the authoritative NVD vector' }, claimed_vector: { type: ['string', 'null'] },
        severity: { type: ['string', 'null'] }, on_kev: { type: 'boolean' },
        primary_cve: { type: ['string', 'null'] }, cwes: { type: 'array', items: { type: 'string' } },
        cves: { type: 'array', description: 'per-CVE {id,score,severity}', items: { type: 'object', additionalProperties: true } },
      },
    },
    exploit: {
      type: 'object', additionalProperties: true,
      properties: {
        ran: { type: 'boolean' }, proven: { type: 'boolean', description: 'output contains the evidence proving the issue' },
        deterministic: { type: 'boolean', description: 'consistent across 3 runs after normalization' },
        repaired: { type: 'boolean', description: 'script was regenerated to make it run/emit evidence' },
        signal_token: { type: ['string', 'null'], description: 'the vuln-class proof token observed' },
        detail: { type: 'string' },
      },
    },
    risk: {
      type: 'object', additionalProperties: true,
      properties: {
        band_consistent: { type: 'boolean' },
        risk_score: { type: ['number', 'null'] }, risk_bucket: { type: ['string', 'null'] },
        max_cvss: { type: ['number', 'null'] }, detail: { type: 'string' },
      },
    },
    evidence_package_complete: { type: 'boolean' },
    is_web: { type: 'boolean', description: 'true if the target has an HTTP/HTTPS/browser surface (drives the screenshot requirement)' },
    cites_code: { type: 'boolean', description: 'true if the finding references source/config/logic (drives the code-references.md requirement)' },
    poc: {
      type: 'array',
      description: 'the reproducible PoC as an ORDERED list of steps (a blind reproduction agent re-runs THIS to the stated result). Step 1 is an entry point; the LAST step is the actual observed result that proves the finding. The single canonical step-by-step — not duplicated elsewhere.',
      items: {
        type: 'object', additionalProperties: true, required: ['description'],
        properties: {
          description: { type: 'string', description: 'what this step does / what you observe (prose)' },
          command: { type: 'string', description: 'the EXACT command/URL/click to run at this step — verbatim and runnable; omit for a pure-observation step' },
          image_url: { type: 'string', description: 'optional path (or URL) to a captured screenshot/output image for THIS step' },
        },
      },
    },
    report_fields: {
      type: 'object', additionalProperties: true, description: 'the human-facing fields that render into the report (carried so JS assembles report_data.json without re-reading disk). Evidence/PoC/screenshots live in poc[], NOT here.',
      properties: {
        title: { type: 'string' }, affected: { type: 'array', items: { type: 'string' } },
        description: { type: 'string' }, impact: { type: 'string' },
        recommendation: { type: 'string' },
        ease_of_exploitation: { type: 'string', description: "exploitability rating/rationale, e.g. 'Easy — no auth, remotely reachable'" },
        references: { type: 'array', items: { type: 'string' }, description: 'advisory/standard URLs' },
        cwe: { type: ['string', 'null'] }, owasp: { type: ['string', 'null'] },
      },
    },
    summary: { type: 'string' },
  },
}

const VOTE_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['refuted'],
  properties: {
    refuted: { type: 'boolean' },
    reason: { type: 'string' },
    weakest_link: { type: 'string', description: 'the single most doubtful claim/step' },
  },
}

// The evidence-probe returns REAL on-disk facts (test -f / wc -c) — no judgment.
// JS (evidenceComplete + computeVerdict) decides; the agent only reports existence.
const PROBE_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['files'],
  properties: {
    files: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: true, required: ['path', 'exists', 'bytes'],
        properties: { path: { type: 'string' }, exists: { type: 'boolean' }, bytes: { type: 'number' } },
      },
    },
  },
}

// The blind reproduction agent's result — a SEPARATE agent, no prior context,
// that re-runs the documented PoC steps (each step's command) and confirms (or
// corrects until it) reproduces the finding's stated result. Distinct from the
// refuters (which doubt) and the probe (which stats files): this one FOLLOWS THE RECIPE.
const REPRO_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['reproduced'],
  properties: {
    reproduced: { type: 'boolean', description: 'the PoC steps, run EXACTLY (given or corrected), produced the finding\'s stated result' },
    entry_point_ok: { type: 'boolean', description: 'step 1 is a genuine entry point (terminal/browser/initial connection)' },
    result_matches: { type: 'boolean', description: 'the LAST step\'s observed result matches the finding' },
    observed_result: { type: 'string' },
    corrected_steps: { type: 'array', description: 'the corrected PoC list (same {description, command, image_url} shape) if it did not reproduce as written', items: { type: 'object', additionalProperties: true } },
    notes: { type: 'string' },
  },
}

function checksPrompt(f, P = {}) {
  return `ROLE: AUTHORITATIVE FINDING VALIDATOR. cwd is repo root. You verify ONE finding to an evidentiary standard and produce its proof package. Mount ONLY: skills/coordination/reference/VALIDATION.md (the 5 canonical checks + package layout) and skills/coordination/reference/validator-role.md. Do NOT read attack-chain.md, session-memory.md, or other findings (stay independent).\n\n` +
    `FINDING: ${f.id}\nFINDING_DIR: ${f.dir}\nTYPE: ${f.type || 'unknown'}\nTARGET: ${P.TARGET || '(from finding)'}\nCVE(s): ${JSON.stringify(f.cve_ids || [])}\n` +
    `CLAIMED: severity=${f.claimed_severity || '?'} vector=${f.claimed_cvss_vector || '?'} score=${f.claimed_score != null ? f.claimed_score : '?'}\n` +
    `OUTPUT_DIR: ${P.OUTPUT_DIR}   BUSINESS_TIER: ${P.BUSINESS_TIER}   REPAIR: ${P.REPAIR}\n\n` +
    `Run ALL of the following and write the proof package to ${f.dir}/evidence/validation/ (validation-summary.md per the VALIDATION.md template; plus the files below):\n\n` +
    `A) CANONICAL 5 CHECKS (VALIDATION.md): cvss_consistency (severity band == score), evidence_exists (description.md, poc.py, poc_output.txt, evidence/raw-source.txt), poc_validation (ast.parse + references target), claims_vs_raw (every factual claim corroborated by a raw scan/log file), log_corroboration (recon/experiment/test/verify phases present, verify timestamps >=2s apart). NOTE on log_corroboration: fail it ONLY on genuine bulk-stamping (all verify entries share one identical second, i.e. fabricated) — NOT merely because timestamps are close. When claims_vs_raw already PASSES (every factual claim is corroborated by a raw scan/log file) OR the finding is a fully-evidenced tested-negative, a log-format technicality alone is ADVISORY: pass log_corroboration (note the format issue in detail) rather than demoting a substantively-proven finding on bookkeeping.\n\n` +
    `B) CVE LANE (if CVE(s) present) — you are the TOOL that fetches the numbers; the workflow reconciles them deterministically, so REPORT them, do NOT decide the verdict:\n${(P.NVD_KEV || nvdKevText(P)).join('\n')}\n` +
    `  Compute the base score from the vector with the canonical tool \`python3 tools/cvss_calc.py "<vector>"\` (CVSS v4.0-primary; it scores v4.0/v3.1/v3.0/v2.0). When NVD offers vectors in several versions, prefer the CVSS v4.0 vector and fall back v3.1 -> v3.0 -> v2.0 (\`nvd-lookup.py\` JSON_SUMMARY already exposes cvss_version + cvss_vector for the primary). This is the ONLY sanctioned score computation — do not hand-roll the math or rely on an ad-hoc \`cvss\` install.\n` +
    `  Write ${f.dir}/evidence/validation/cve-verification.md (per CVE: NVD JSON_SUMMARY, the chosen CVSS version + vector, the tools/cvss_calc.py computed score, KEV status, advisory URL + quoted affected-version line).\n` +
    `  Return cve.{applicable, primary_cve, nvd_score, computed_score, claimed_score, vector (the NVD vector), claimed_vector, on_kev, cwes[], cves:[{id,score,severity}]}. Do NOT set a 'verified'/'reconciled' flag — the workflow computes reconciliation from these numbers.\n\n` +
    `C) EXPLOIT/EVIDENCE LANE — EVERY finding must end with a script that RUNS and prints the evidence that proves the issue:\n` +
    `  - ast.parse poc.py; run it against the target read-only (timeout 60s). Capture stdout+stderr to ${f.dir}/evidence/validation/poc-rerun-output.txt. Re-run 3x.\n` +
    `  - Determinism + proof: normalize each run per skills/regression-sweep/reference/diff-normalization.md (strip timestamps/UUIDs/session tokens/nonces/dynamic ports, lowercase, compare as a set) and confirm the runs agree AND that a vuln-class SIGNAL TOKEN is present (SQLi->DB error/column value; RCE/deser->uid=0/hostname; LFI/traversal->/etc/passwd line; SSRF->internal body; XSS->exact payload echo; auth bypass->Set-Cookie/200 after disallowed nav; IDOR->leaked field; info/config->the disclosed secret/value). Record the token.\n` +
    (P.REPAIR
      ? `  - IF poc.py is missing, fails to run, or emits no proof token: REPAIR it. Write a standalone ${f.dir}/poc.py (or fix it) per skills/cve-poc-generator/reference/poc-methodology.md — argparse positional target, TIMEOUT default 10, prefixes [*]/[+]/[-]/[!], exit codes 0=vulnerable/1=not/2=error, a check_vulnerable()->{vulnerable,details,evidence} contract, read-only unless --confirm. Re-run it 3x; if it now proves the issue, set exploit.repaired=true. A finding that cannot be made to emit proof is NOT validatable.\n`
      : `  - Do NOT modify poc.py (repair disabled). If it cannot prove the issue, exploit.proven=false.\n`) +
    `  - Always write ${f.dir}/evidence/validation/verification-script.py — a STANDALONE reproduction (own imports + target refs + output parsing; must NOT import the executor poc.py). A human runs this one script to reproduce.\n` +
    `  - If the target has a WEB/HTTP/browser surface: set is_web=true and capture Playwright evidence into ${f.dir}/evidence/validation/ — a full-page screenshots/<name>.png (playwright_screenshot full_page), plus network-requests.json (playwright_network_requests) and console.json (playwright_console_messages) where relevant. For raw TCP/UDP/DNS/SNMP/SSH-banner findings set is_web=false (no screenshot required). Mount skills/essential-tools/reference/playwright-automation.md.\n\n` +
    `D) AUTHOR THE REPRODUCIBLE PoC (do NOT score risk — the workflow computes risk deterministically). Write ${f.dir}/evidence/validation/poc-steps.md AND return it as poc[] — an ORDERED list of steps:\n` +
    `  - Each step = {description (what you do / what you observe, prose), command (the EXACT command/URL/click to run at this step — verbatim and runnable; omit for a pure-observation step), image_url (optional path to a captured screenshot/output image for THIS step — e.g. the Playwright screenshot from lane C)}.\n` +
    `  - ORDERED and reproducible. Step 1 MUST be an ENTRY POINT — literally "Open a terminal" / "Open a browser to <url>" / "Establish the initial connection" (its command is that entry action). The LAST step MUST be the ACTUAL RESULT that proves the finding (the SQLi row dump, the uid=0 line, the disclosed value) — put the observed proof in its description. A separate blind agent re-runs each step's command EXACTLY, so they must be self-contained and unambiguous. Fold any prerequisites into the first step's description.\n` +
    `  - report_fields{title, affected[], description, impact, recommendation, ease_of_exploitation (e.g. "Easy — no auth, remotely reachable"), references[] (advisory/standard URLs), cwe, owasp}: the human-facing fields — the workflow assembles these into report_data.json (do NOT include secrets/PII verbatim; the workflow also secret-scans). Evidence / PoC / screenshots now live in poc[] above, NOT in report_fields.\n` +
    `  - is_web (per lane C) and cites_code (true when the finding references source/config/logic — then also write code-references.md).\n\n` +
    `Return CHECKS_SCHEMA with each lane's booleans + the reported numbers + poc[] + report_fields. Be strict and evidence-bound: if you cannot corroborate something, mark it false with detail.`
}

function refuterPrompt(f, i, P = {}) {
  return `ROLE: ADVERSARIAL VALIDATOR #${i} (blind). Your job is to REFUTE finding ${f.id}. You see ONLY its evidence package — NOT any validator's verdict, NOT attack-chain/session-memory, NOT other findings. Default to skepticism: if a claim is not independently supported, it is refuted.\n\n` +
    `Read ${f.dir}/description.md, ${f.dir}/poc.py, ${f.dir}/poc_output.txt, ${f.dir}/evidence/ (including evidence/validation/poc-rerun-output.txt, cve-verification.md, verification-script.py). For a CVE, independently sanity-check against the SAME frozen operands the validator used: ${(P.NVD_KEV || nvdKevText(P))[1]} Does the claimed CVSS vector actually yield the claimed score? does NVD agree? For the exploit: does the captured output actually PROVE the vulnerability, or is the "evidence" incidental/ambiguous/self-asserted? Could the output be produced on a non-vulnerable target? Are the factual claims present in raw scan output?\n\n` +
    `COMMON FALSE-HIGH CALIBRATION — apply \`skills/coordination/reference/severity-calibration.md\`. REFUTE (impact not demonstrated/reachable as claimed) and name the unmet precondition as weakest_link if the finding is any of: CORS reflected-origin scored as token-theft WITHOUT \`Access-Control-Allow-Credentials: true\` + ambient-cookie-auth'd sensitive data; Azure \`AADSTS50126\` (failed auth) read as "MFA disabled" (Entra checks credentials BEFORE MFA — a failed login never reaches the MFA prompt); an ENABLER (spray-capability / Golden-SAML or cert template / writable ACL / SSRF reachability) scored as a DEMONSTRATED compromise it never actually performed; a scanner/vulners version-only "Critical" on a backported-distro or appliance-bundled package (version banner ≠ patch level); or a verified CVE scored at base WITHOUT confirming the vulnerable feature is enabled and reachable (e.g. IKEv1 CVE on an IKEv2-only gateway, an inbound-HRS CVE on an outbound-only client).\n\n` +
    `Return VOTE_SCHEMA: refuted (true if you found a real reason to doubt the finding, the score, or the CVE), reason, and weakest_link (the single most doubtful element).`
}

// The evidence-probe: a one-job runner that ONLY reports on-disk facts for the
// finding's mandatory manifest. No judgment — JS gates on the booleans.
function probePrompt(f, manifest, P = {}) {
  return `ROLE: EVIDENCE PROBE (one job, no judgment). cwd is repo root. For EACH path below, run \`test -f\`/\`wc -c\` (for a \`*.png\` glob, count matching files and report the largest as one entry with its byte size; exists=true iff at least one non-empty match). Report ONLY the real on-disk facts — do not create, repair, or judge anything.\n\n` +
    `FINDING: ${f.id}\nPATHS:\n${manifest.map((m) => `  - ${m.path} (${m.type})`).join('\n')}\n\n` +
    `Return PROBE_SCHEMA: files:[{path, exists, bytes}] with one entry per path above (use the exact path string given).`
}

// The blind reproduction agent — SEPARATE, context-free. It gets ONLY the
// ordered PoC steps (each step's command) and the target, follows the recipe
// exactly, and confirms (or minimally corrects) that it reproduces the result.
function reproPrompt(f, poc, P = {}) {
  return `ROLE: BLIND PoC REPRODUCER (context-free, independent). cwd is repo root. You are handed ONLY a finding's ordered PoC STEPS and the target. You did NOT run the original test; you may NOT read the finding's description.md, poc.py, evidence/, attack-chain.md, session-memory.md, other findings, or any validator/refuter output. Reproduce the result as a competent tester with zero prior context would, by following the recipe EXACTLY.\n\n` +
    `FINDING: ${f.id}\nTARGET: ${P.TARGET || '(from the steps)'}\nSTEPS: ${JSON.stringify(Array.isArray(poc) ? poc : [])}\n\n` +
    `Rules: read-only / non-destructive only — NO brute force, NO DoS, NO destructive writes, stay on the given target.\n` +
    `1. ENTRY POINT: confirm step 1 is a genuine starting point (open a terminal / open a browser / establish the initial connection). entry_point_ok accordingly.\n` +
    `2. EXECUTE each step IN ORDER, running its \`command\` exactly as written (timeout ~60s/step). At the LAST step, compare the observed output to the finding's claimed result; put the real observed final output in observed_result; result_matches accordingly.\n` +
    `3. PERFECT IT: if a step is wrong/ambiguous but the finding IS still reproducible, return the minimal corrected_steps (same {description, command, image_url} shape) that DO reproduce it (step 1 still an entry point, LAST step still the actual result). Only set reproduced=true if you ACTUALLY observed the result — with the given OR the corrected recipe.\n` +
    `Write ${f.dir}/evidence/validation/reproduction.md (what you ran, what you observed, any corrections). Return REPRO_SCHEMA. reproduced=true ONLY when you independently observed the finding's result.`
}

// The cure executor — closes EXACTLY the named gates, never re-theorizes. It
// writes evidence/repairs the poc/fixes the vector; the loop then re-validates
// on FRESH blind agents (independence preserved). Returns nothing the verdict trusts.
function curePrompt(f, failedChecks, missingEvidence, P = {}) {
  return `ROLE: FINDING CURE (scoped gap-closer, NOT a re-investigation). cwd is repo root. Mount skills/coordination/reference/executor-role.md. A blind validator DEMOTED finding ${f.id} for the specific gaps below. Close EXACTLY those gaps — do NOT re-theorize, do NOT change the claim, do NOT hunt new vulnerabilities.\n\n` +
    `FINDING: ${f.id}\nFINDING_DIR: ${f.dir}\nTARGET: ${P.TARGET || '(from finding)'}\nOUTPUT_DIR: ${P.OUTPUT_DIR}\n` +
    `UNMET GATES: ${JSON.stringify(failedChecks || [])}\nMISSING EVIDENCE FILES: ${JSON.stringify(missingEvidence || [])}\n\n` +
    `Do ONLY what the gates require:\n` +
    `  - evidence:missing_files / evidence_exists -> produce the named MISSING EVIDENCE FILES with real content (re-run the tool that generates each; never fabricate).\n` +
    `  - poc:not_reproduced / poc_validation -> fix ${f.dir}/poc.py and the step-by-step so a blind tester reproduces the stated result; re-run it read-only to confirm.\n` +
    `  - cve:reconcile / cvss_consistency -> recompute the CVSS from the authoritative NVD vector (${(P.NVD_KEV || nvdKevText(P))[1]}) and correct the finding's vector/score/band to match.\n` +
    `  - claims_vs_raw / log_corroboration -> add the raw scan/log file that corroborates each unsupported factual claim.\n` +
    `Reversible/authorized, non-destructive actions ONLY. Return {cured_gates:[...], notes} — the workflow re-validates on fresh blind agents and recomputes the verdict; your return is NOT trusted as proof.`
}

// Build the interim validated JSON — the deterministic contract report_data_build.py
// consumes. Content is JS-authored; the Synthesize writer only persists it verbatim.
function buildInterim(f, checks, verdict, repro, opts = {}) {
  const tier = opts.tier || 'unknown'
  const platform = opts.platform || 'generic'
  const votes = opts.votes != null ? opts.votes : DEFAULT_VOTES
  const cve = (checks && checks.cve) || {}
  const cvss = cve.computed_score != null ? cve.computed_score : (cve.claimed_score != null ? cve.claimed_score : (f.claimed_score != null ? f.claimed_score : null))
  const sev = cvss != null ? severityBand(cvss) : (f.claimed_severity && SEVERITY.includes(f.claimed_severity) ? f.claimed_severity : 'Info')
  const feasibility = verdict.verdict === 'VALID' || verdict.verdict === 'REPAIRED' ? 1.0 : 0.5
  const risk = riskScore({ cvss, tier, exposure: exposureFor({ platform }), feasibility })
  const rf = (checks && checks.report_fields) || {}
  return {
    finding_id: f.id,
    verdict: verdict.verdict,
    severity: sev,
    cvss_score: cvss,
    cvss_vector: cve.vector || f.claimed_cvss_vector || null,
    cwe: rf.cwe || (cve.cwes && cve.cwes[0]) || null,
    owasp: rf.owasp || null,
    cves: cve.cves || (cve.primary_cve ? [{ id: cve.primary_cve, score: cve.computed_score, severity: sev }] : []),
    on_kev: !!cve.on_kev,
    cve_verification: { nvd_score: cve.nvd_score != null ? cve.nvd_score : null, computed_score: cve.computed_score != null ? cve.computed_score : null, vector: cve.vector || null, on_kev: !!cve.on_kev },
    risk,
    report_fields: rf,
    poc: finalPoc(checks, repro),
    poc_reproduced: !!(repro && repro.reproduced),
    observed_result: (repro && repro.observed_result) || null,
    failed_checks: verdict.failed_checks || [],
    missing_evidence: verdict.missing_evidence || [],
    adversarial: { votes, refuted: verdict.refuteCount || 0 },
    proof_dir: `${f.dir}/evidence/validation`,
  }
}

// ============================================================================
// PHASE: Validate — pipeline per finding (checks -> refute -> verdict)
// ============================================================================
phase('Validate')

// C3 REPLAY-CACHE (deterministic): for an UNCHANGED finding directory, a
// tool-runner restores the recorded interim verdict to disk (validated/dropped/
// false-positives) and we SKIP the non-deterministic LLM lane. The tool
// (validation_cache.py) owns the content-hash + read/write; the agent only
// relays the tool's small JSON verdict — no LLM decides the hit/miss.
const RESTORE_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['restored'],
  properties: { restored: { type: 'boolean' }, hash: { type: ['string', 'null'] }, id: { type: ['string', 'null'] }, verdict: { type: ['string', 'null'] }, title: { type: ['string', 'null'] } },
}
let restoredLite = []
let toValidate = inventory
if (VALIDATION_CACHE_DIR) {
  const probes = await parallel(inventory.map(f => () =>
    agent(
      `ROLE: REPLAY-CACHE RESTORE (tool-runner, no judgment). cwd is repo root. Run EXACTLY this one command and relay its single JSON line verbatim — do NOT validate, judge, or edit anything:\n` +
      `python3 tools/validation_cache.py restore --finding-dir ${f.dir} --cache-dir ${VALIDATION_CACHE_DIR} --output-dir ${OUTPUT_DIR}\n` +
      `Return RESTORE_SCHEMA {restored, hash, id, verdict, title} from the tool's output.`,
      { schema: RESTORE_SCHEMA, label: `cache-restore:${f.id}`, phase: 'Validate', agentType: 'general-purpose' }
    ).catch(() => ({ restored: false }))
  ))
  const hitIds = new Set()
  probes.forEach((p, i) => {
    if (p && p.restored && p.verdict) { hitIds.add(inventory[i].id); restoredLite.push({ id: inventory[i].id, verdict: p.verdict, title: p.title || '' }) }
  })
  toValidate = inventory.filter(f => !hitIds.has(f.id))
  log(`Replay-cache: ${restoredLite.length} finding(s) restored deterministically from cache; ${toValidate.length} to validate live.`)
}

const results = await pipeline(
  toValidate,
  // Stage A — authoritative checks + evidence package (the checks agent is the CVE/exploit tool-runner).
  (f) => agent(checksPrompt(f, P), { schema: CHECKS_SCHEMA, label: `checks:${f.id}`, phase: 'Validate', agentType: 'general-purpose' })
    .catch(() => null),
  // Stage B — three INDEPENDENT blind lanes, all depending only on checks-done:
  //   refuters (doubt) ∥ evidence-probe (stat files) ∥ reproduction (follow the recipe).
  //   The reproduction agent is a SEPARATE, context-free validator of the step-by-step;
  //   it is NOT a duplicate of the refuters or the probe.
  (checks, f) => {
    if (!checks) return Promise.resolve({ checks: null, votes: [], probe: { files: [] }, repro: null })
    const manifest = EVIDENCE_MANIFEST({ ...f, is_web: checks.is_web, cites_code: checks.cites_code })
    return Promise.all([
      parallel(Array.from({ length: VOTES }, (_, i) => () =>
        agent(refuterPrompt(f, i + 1, P), { schema: VOTE_SCHEMA, label: `refute:${f.id}#${i + 1}`, phase: 'Validate', agentType: 'general-purpose' })
      )).then((votes) => votes.filter(Boolean)),
      agent(probePrompt(f, manifest, P), { schema: PROBE_SCHEMA, label: `probe:${f.id}`, phase: 'Validate', agentType: 'general-purpose' }).catch(() => ({ files: [] })),
      agent(reproPrompt(f, checks.poc, P), { schema: REPRO_SCHEMA, label: `repro:${f.id}`, phase: 'Validate', agentType: 'general-purpose' }).catch(() => null),
    ]).then(([votes, probe, repro]) => ({ checks, votes, probe, repro }))
  },
  // Stage C — PURE JS. Reconcile the CVE numbers, then the deterministic verdict. NO agent.
  (carry, f) => {
    const checks = carry ? carry.checks : null
    const votes = (carry && carry.votes) || []
    const probe = (carry && carry.probe) || { files: [] }
    const repro = (carry && carry.repro) || null
    const finding = { ...f, is_web: checks && checks.is_web, cites_code: checks && checks.cites_code }
    if (checks && checks.cve && checks.cve.applicable) {
      checks.cve.reconciled = cveReconcile({
        claimed_score: checks.cve.claimed_score, computed_score: checks.cve.computed_score, nvd_score: checks.cve.nvd_score,
        claimed_vector: checks.cve.claimed_vector, computed_vector: checks.cve.vector,
      }).reconciled
    }
    const verdict = computeVerdict(finding, checks, votes, probe, repro, { votesTotal: VOTES })
    return { finding: f, checks, votes, probe, repro, verdict, interim: buildInterim(finding, checks, verdict, repro, { tier: BUSINESS_TIER, platform: PLATFORM, votes: VOTES }) }
  },
  // Stage D (resume resilience) — persist each verdict to disk + the replay cache AS
  // IT LANDS, so a mid-run provider/rate limit never zeroes out already-earned
  // confirmations (a re-run restores them via the cache-restore stage). No-op unless a
  // cache dir is set; writes are idempotent (write-once cache; the Synthesize writer
  // re-writes the same bytes, and the batched Synthesize store then hits 'exists').
  (res, f) => {
    if (!VALIDATION_CACHE_DIR || !res || !res.interim || !res.verdict) return res
    const sub = terminalSubdir(res.verdict.verdict)
    const path = `${OUTPUT_DIR}/artifacts/${sub}/${res.interim.finding_id}.json`
    return agent(
      `ROLE: INCREMENTAL CACHE-STORE (tool-runner, no judgment). cwd is repo root. Do EXACTLY, nothing else:\n` +
      `1. \`mkdir -p ${OUTPUT_DIR}/artifacts/${sub}\` and write this EXACT JSON (byte-for-byte) to ${path}:\n${JSON.stringify(res.interim, null, 2)}\n` +
      `2. Run: \`python3 tools/validation_cache.py store --cache-dir ${VALIDATION_CACHE_DIR} --interim-file ${path} --root ${OUTPUT_DIR}\` and relay its JSON line.`,
      { label: `cache-store:${f.id}`, phase: 'Validate', agentType: 'general-purpose' }
    ).then(() => res).catch(() => res)
  },
)

const clean = results.filter(Boolean)
const isPass = (v) => v === 'VALID' || v === 'REPAIRED'
const valid = clean.filter(r => isPass(r.verdict.verdict))
const repaired = clean.filter(r => r.verdict.verdict === 'REPAIRED')
const demoted = clean.filter(r => r.verdict.verdict === 'DEMOTED')
const rejected = clean.filter(r => r.verdict.verdict === 'REJECTED')
// Restored-from-cache tallies (their full interims are already on disk via the tool).
const rValid = restoredLite.filter(r => isPass(r.verdict)).length
const rDemoted = restoredLite.filter(r => r.verdict === 'DEMOTED').length
const rRejected = restoredLite.filter(r => r.verdict === 'REJECTED').length
log(`Validate done: ${valid.length} valid (${repaired.length} repaired), ${demoted.length} demoted, ${rejected.length} rejected of ${clean.length} live${restoredLite.length ? ` (+${restoredLite.length} restored from cache: ${rValid} valid, ${rDemoted} dropped, ${rRejected} rejected)` : ''}.`)

// ============================================================================
// PHASE: Synthesize — dedupe, risk-rank, asset report
// ============================================================================
phase('Synthesize')

// Build the write-plan IN JS — the verdict JSON content is authored here; the
// writer agent only persists the exact bytes (no regeneration, no judgment).
// Drop-entirely: terminalSubdir routes VALID/REPAIRED -> validated/ (the report
// body), REJECTED -> false-positives/, and DEMOTED/uncured -> dropped/ (audit
// only). report_data_build.py reads ONLY validated/, so neither leaks.
const counts = { total: clean.length + restoredLite.length, valid: valid.length + rValid, repaired: repaired.length, demoted: demoted.length + rDemoted, rejected: rejected.length + rRejected, restored: restoredLite.length }
const writePlan = []
for (const r of clean) {
  const content = JSON.stringify(r.interim, null, 2)
  const sub = terminalSubdir(r.verdict.verdict)
  writePlan.push({ path: `${OUTPUT_DIR}/artifacts/${sub}/${r.interim.finding_id}.json`, content })
  writePlan.push({ path: `${OUTPUT_DIR}/${sub}/${r.interim.finding_id}.json`, content })
}
const summaryContent = {
  asset: TARGET, counts,
  validated: valid.map(r => ({ id: r.interim.finding_id, severity: r.interim.severity, cvss_score: r.interim.cvss_score, cve: (r.interim.cves[0] || {}).id || null, on_kev: r.interim.on_kev, risk_score: r.interim.risk.risk_score, risk_bucket: r.interim.risk.risk_bucket, proof_dir: r.interim.proof_dir })),
  demoted: demoted.map(r => ({ id: r.interim.finding_id, failed_checks: r.interim.failed_checks, missing_evidence: r.interim.missing_evidence })),
  rejected: rejected.map(r => ({ id: r.interim.finding_id, failed_checks: r.interim.failed_checks })),
}
writePlan.push({ path: `${OUTPUT_DIR}/artifacts/validation-summary.json`, content: JSON.stringify(summaryContent, null, 2) })

const synth = await agent(
  `ROLE: VALIDATION WRITER (persist verbatim + rank). cwd is repo root. You do NOT judge or regenerate anything — you write the EXACT bytes given, then produce a human-readable report and the ranking.\n` +
  `OUTPUT_DIR: ${OUTPUT_DIR}\nTARGET: ${TARGET || '(asset)'}\n\n` +
  `1. Ensure ${OUTPUT_DIR}/{artifacts/validated,artifacts/false-positives,artifacts/dropped,validated,false-positives,dropped,reports} exist. Write each of these files with EXACTLY the given content (byte-for-byte — do not reformat, re-key, or add fields):\n${writePlan.map((w, i) => `--- FILE ${i + 1}: ${w.path} ---\n${w.content}`).join('\n')}\n\n` +
  `2. In ${OUTPUT_DIR}/artifacts/validation-summary.json, set generated_at to the output of \`date -u +%Y-%m-%dT%H:%M:%SZ\` (add the key; change nothing else).\n` +
  `3. If ${OUTPUT_DIR}/artifacts/attack-paths.json exists, run: python3 tools/risk-prioritise.py --output-dir ${OUTPUT_DIR}  (writes artifacts/attack-paths-ranked.json/.md); else write ${OUTPUT_DIR}/artifacts/validated-findings-ranked.json ranking the validated findings by risk_score desc (tie-break CVSS then id).\n` +
  `4. Write ${OUTPUT_DIR}/reports/validation-report.md: a table of the VALIDATED (incl. repaired) findings — id, severity, CVE(+NVD/computed/KEV), risk_score/bucket, proof_dir; then a DROPPED section (id + the unmet gate, from dropped/) and a REJECTED appendix (id + reason). Drop-entirely: DROPPED and REJECTED are audit-only — they NEVER appear in the validated body or counts.\n\n` +
  `Return {report_path, ranked_path, written}.`,
  {
    schema: {
      type: 'object', additionalProperties: true, required: ['report_path'],
      properties: { report_path: { type: 'string' }, ranked_path: { type: ['string', 'null'] }, written: { type: 'number' } },
    },
    label: 'validation-writer', phase: 'Synthesize', agentType: 'general-purpose',
  }
).catch(() => null)

// C3 REPLAY-CACHE STORE: record each live verdict (write-once) keyed by the
// finding's investigation-input hash, so a later re-validation of the UNCHANGED
// directory restores it byte-identically instead of re-running the LLM lane.
// One tool-runner agent runs all store commands; the tool owns hash + write.
if (VALIDATION_CACHE_DIR && clean.length) {
  const storeCmds = clean.map(r => `python3 tools/validation_cache.py store --cache-dir ${VALIDATION_CACHE_DIR} --interim-file ${OUTPUT_DIR}/artifacts/${terminalSubdir(r.verdict.verdict)}/${r.interim.finding_id}.json`)
  await agent(
    `ROLE: REPLAY-CACHE STORE (tool-runner, no judgment). cwd is repo root. Run EACH command below EXACTLY as written and relay its JSON line; do NOT edit, judge, or create anything else:\n${storeCmds.join('\n')}`,
    { label: 'cache-store', phase: 'Synthesize', agentType: 'general-purpose' }
  ).catch(() => null)
  log(`Replay-cache: stored ${clean.length} live verdict(s) for deterministic replay.`)
}

return {
  status: 'VALIDATED',
  output_dir: OUTPUT_DIR,
  target: TARGET,
  counts,
  // Full interim data so the orchestrator assembles report_data.json without re-reading disk.
  validated: valid.map(r => r.interim),
  demoted: demoted.map(r => r.interim),
  rejected: rejected.map(r => ({ id: r.interim.finding_id, failed_checks: r.interim.failed_checks })),
  report_path: (synth && synth.report_path) || `${OUTPUT_DIR}/reports/validation-report.md`,
  ranked_path: (synth && synth.ranked_path) || null,
}
