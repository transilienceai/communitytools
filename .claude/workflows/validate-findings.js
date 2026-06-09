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
const VOTES = Number(a.votes) > 0 ? Math.floor(Number(a.votes)) : 2
const MAX_FINDINGS = Number(a.max_findings) > 0 ? Math.floor(Number(a.max_findings)) : 50
const BUSINESS_TIER = a.business_tier || 'unknown' // crown_jewel|revenue|support|dev|unknown
const STRICT = a.strict !== false            // default true — one failed gate => REJECTED
const PLATFORM = a.platform || 'generic'

if (!OUTPUT_DIR) {
  log('validate-findings: no output_dir provided')
  return { status: 'ERROR', reason: 'output_dir is required' }
}

// ---- shared references mounted into validators -----------------------------
// The from-vector CVSS v3.1 base-score algorithm (FIRST spec) — embedded so the
// math is self-contained even offline. Validators prefer the `cvss` python lib.
const CVSS31_MATH = [
  'CVSS v3.1 BASE SCORE — recompute from the vector string (do NOT trust a cached number):',
  'Preferred: `pip install cvss` then `from cvss import CVSS3; CVSS3(vector).base_score` (exact FIRST roundup). For v4.0 use `from cvss import CVSS4`. If the lib is unavailable, implement v3.1 by hand:',
  'Weights: AV{N:0.85,A:0.62,L:0.55,P:0.20} AC{L:0.77,H:0.44} UI{N:0.85,R:0.62} CIA{H:0.56,L:0.22,N:0.00}',
  'PR (Scope Unchanged){N:0.85,L:0.62,H:0.27}; PR (Scope Changed){N:0.85,L:0.68,H:0.50}',
  'ISC_base = 1 - ((1-C)*(1-I)*(1-A))',
  'Impact = (S==Unchanged) ? 6.42*ISC_base : 7.52*(ISC_base-0.029) - 3.25*(ISC_base-0.02)^15',
  'Exploitability = 8.22 * AV * AC * PR * UI',
  'BaseScore = (Impact<=0) ? 0.0 : (S==Unchanged) ? Roundup(min(Impact+Exploitability,10)) : Roundup(min(1.08*(Impact+Exploitability),10))',
  'Roundup(x) (exact 3.1): i=round(x*100000); return (i%10000==0) ? i/100000 : (floor(i/10000)+1)/10000',
  'Severity band: 9.0-10.0 CRITICAL | 7.0-8.9 HIGH | 4.0-6.9 MEDIUM | 0.1-3.9 LOW | 0.0 NONE.',
].join('\n')

const NVD_KEV = [
  'AUTHORITATIVE CVE SOURCES (do not rely on the finding\'s own claim):',
  '1. NVD: `python3 tools/nvd-lookup.py <CVE-ID>` — parse the final `JSON_SUMMARY: {...}` line (cve_id, score, severity, cwes[], status) AND the per-version "Vector:" lines for the vector string. v3.1 preferred, then v3.0, v2.0; v4.0 if present.',
  '2. CISA KEV (known-exploited): WebFetch https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json and check whether the CVE is listed (records {cveID, dateAdded, requiredAction, knownRansomwareCampaignUse}). Being on KEV raises real-world priority regardless of base score.',
  '3. Vendor/official advisory: follow the authoritative reference URLs NVD returns (cve.references) and confirm affected versions + the vulnerability class match the finding. Quote the source.',
  'Reconcile: the finding\'s claimed CVE id, CVSS vector, base score, and severity must all agree with NVD and with your from-vector recomputation (|delta| <= 0.1 on the score, exact match on the vector and band). Flag KEV status. Any unreconciled divergence => CVE check FAILS.',
]

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
        verified: { type: 'boolean', description: 'NVD + from-vector recompute + advisory all reconcile' },
        nvd_score: { type: ['number', 'null'] }, computed_score: { type: ['number', 'null'] },
        claimed_score: { type: ['number', 'null'] }, vector: { type: ['string', 'null'] },
        severity: { type: ['string', 'null'] }, on_kev: { type: 'boolean' },
        divergence: { type: ['string', 'null'], description: 'description of any mismatch' },
        cwes: { type: 'array', items: { type: 'string' } },
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

const VERDICT_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['finding_id', 'verdict'],
  properties: {
    finding_id: { type: 'string' },
    verdict: { type: 'string', enum: ['VALID', 'REPAIRED', 'REJECTED'] },
    severity: { type: ['string', 'null'] },
    score: { type: ['number', 'null'] },
    cve: { type: ['string', 'null'] },
    on_kev: { type: 'boolean' },
    risk_score: { type: ['number', 'null'] },
    risk_bucket: { type: ['string', 'null'] },
    failed_checks: { type: 'array', items: { type: 'string' } },
    proof_dir: { type: 'string' },
    reason: { type: 'string' },
  },
}

function checksPrompt(f) {
  return `ROLE: AUTHORITATIVE FINDING VALIDATOR. cwd is repo root. You verify ONE finding to an evidentiary standard and produce its proof package. Mount ONLY: skills/coordination/reference/VALIDATION.md (the 5 canonical checks + package layout) and skills/coordination/reference/validator-role.md. Do NOT read attack-chain.md, session-memory.md, or other findings (stay independent).\n\n` +
    `FINDING: ${f.id}\nFINDING_DIR: ${f.dir}\nTYPE: ${f.type || 'unknown'}\nTARGET: ${TARGET || '(from finding)'}\nCVE(s): ${JSON.stringify(f.cve_ids || [])}\n` +
    `CLAIMED: severity=${f.claimed_severity || '?'} vector=${f.claimed_cvss_vector || '?'} score=${f.claimed_score != null ? f.claimed_score : '?'}\n` +
    `OUTPUT_DIR: ${OUTPUT_DIR}   BUSINESS_TIER: ${BUSINESS_TIER}   REPAIR: ${REPAIR}\n\n` +
    `Run ALL of the following and write the proof package to ${f.dir}/evidence/validation/ (validation-summary.md per the VALIDATION.md template; plus the files below):\n\n` +
    `A) CANONICAL 5 CHECKS (VALIDATION.md): cvss_consistency (severity band == score), evidence_exists (description.md, poc.py, poc_output.txt, evidence/raw-source.txt), poc_validation (ast.parse + references target), claims_vs_raw (every factual claim corroborated by a raw scan/log file), log_corroboration (recon/experiment/test/verify phases, verify timestamps >=2s apart).\n\n` +
    `B) CVE LANE (if CVE(s) present):\n${NVD_KEV.join('\n')}\n\n${CVSS31_MATH}\nWrite ${f.dir}/evidence/validation/cve-verification.md: per CVE, the NVD JSON_SUMMARY, the vector, your recomputed base score (show the arithmetic or the cvss-lib output), KEV status, the advisory URL + quoted affected-version line, and the reconcile verdict. On any CVE: this is also where you satisfy CLAUDE.md's nvd-lookup rule.\n\n` +
    `C) EXPLOIT/EVIDENCE LANE — EVERY finding must end with a script that RUNS and prints the evidence that proves the issue:\n` +
    `  - ast.parse poc.py; run it against the target read-only (timeout 60s). Capture stdout+stderr to ${f.dir}/evidence/validation/poc-rerun-output.txt. Re-run 3x.\n` +
    `  - Determinism + proof: normalize each run per skills/regression-sweep/reference/diff-normalization.md (strip timestamps/UUIDs/session tokens/nonces/dynamic ports, lowercase, compare as a set) and confirm the runs agree AND that a vuln-class SIGNAL TOKEN is present (SQLi->DB error/column value; RCE/deser->uid=0/hostname; LFI/traversal->/etc/passwd line; SSRF->internal body; XSS->exact payload echo; auth bypass->Set-Cookie/200 after disallowed nav; IDOR->leaked field; info/config->the disclosed secret/value). Record the token.\n` +
    (REPAIR
      ? `  - IF poc.py is missing, fails to run, or emits no proof token: REPAIR it. Write a standalone ${f.dir}/poc.py (or fix it) per skills/cve-poc-generator/reference/poc-methodology.md — argparse positional target, TIMEOUT default 10, prefixes [*]/[+]/[-]/[!], exit codes 0=vulnerable/1=not/2=error, a check_vulnerable()->{vulnerable,details,evidence} contract, read-only unless --confirm. Re-run it 3x; if it now proves the issue, set exploit.repaired=true. A finding that cannot be made to emit proof is NOT validatable.\n`
      : `  - Do NOT modify poc.py (repair disabled). If it cannot prove the issue, exploit.proven=false.\n`) +
    `  - Always write ${f.dir}/evidence/validation/verification-script.py — a STANDALONE reproduction (own imports + target refs + output parsing; must NOT import the executor poc.py). A human runs this one script to reproduce. Capture screenshots/*.png for web/HTTP targets.\n\n` +
    `D) RISK LANE: confirm severity band == score. Compute risk_score = feasibility(1.0 for a confirmed/reproduced finding) * (max_cvss/10, or 0.5 if no NVD score) * business_impact(tier weight: crown_jewel 1.0, revenue 0.7, support 0.4, dev 0.2, unknown 0.3 — use BUSINESS_TIER) * exposure(1.0 if target is externally reachable else 0.5). Bucket: >=0.6 immediate, >=0.3 short_term, >=0.1 medium_term, else monitor. Write ${f.dir}/evidence/validation/risk-assessment.md. (This mirrors tools/risk-prioritise.py / skills/risk-prioritiser/reference/scoring-formula.md.)\n\n` +
    `Then write code-references.md when the finding cites source/config/logic. Return CHECKS_SCHEMA with each lane's booleans + the computed numbers. Be strict and evidence-bound: if you cannot corroborate something, mark it false with detail.`
}

function refuterPrompt(f, i) {
  return `ROLE: ADVERSARIAL VALIDATOR #${i} (blind). Your job is to REFUTE finding ${f.id}. You see ONLY its evidence package — NOT any validator's verdict, NOT attack-chain/session-memory, NOT other findings. Default to skepticism: if a claim is not independently supported, it is refuted.\n\n` +
    `Read ${f.dir}/description.md, ${f.dir}/poc.py, ${f.dir}/poc_output.txt, ${f.dir}/evidence/ (including evidence/validation/poc-rerun-output.txt, cve-verification.md, verification-script.py). For a CVE, independently sanity-check: does the claimed CVSS vector actually yield the claimed score? does NVD agree? (You MAY run python3 tools/nvd-lookup.py <CVE>.) For the exploit: does the captured output actually PROVE the vulnerability, or is the "evidence" incidental/ambiguous/self-asserted? Could the output be produced on a non-vulnerable target? Are the factual claims present in raw scan output?\n\n` +
    `Return VOTE_SCHEMA: refuted (true if you found a real reason to doubt the finding, the score, or the CVE), reason, and weakest_link (the single most doubtful element).`
}

function verdictPrompt(f, checks, votes) {
  const refuteCount = (votes || []).filter(v => v && v.refuted).length
  return `ROLE: VALIDATION VERDICT. cwd is repo root. Combine the authoritative checks with the adversarial votes and record the verdict for finding ${f.id}.\n\n` +
    `CHECKS: ${JSON.stringify(checks)}\n` +
    `ADVERSARIAL VOTES (${VOTES} total, ${refuteCount} refuted): ${JSON.stringify(votes)}\n\n` +
    `DECISION RULE (strict=${STRICT}): VALID requires ALL of — canonical 5 pass; CVE lane verified (or not applicable); exploit proven (ran + deterministic + proof token); risk band consistent; evidence package complete; AND adversarial refutations < majority (refuted < ${Math.floor(VOTES / 2) + 1}). If the exploit was regenerated to make it prove the issue, the verdict is REPAIRED (still a pass, but flagged). Otherwise REJECTED.${STRICT ? ' Any single failed gate => REJECTED.' : ' (non-strict: you may pass with a documented minor gap.)'}\n\n` +
    `Write the verdict JSON to BOTH ${OUTPUT_DIR}/artifacts/validated/${f.id}.json AND ${OUTPUT_DIR}/validated/${f.id}.json on a pass (VALID or REPAIRED), or to ${OUTPUT_DIR}/artifacts/false-positives/${f.id}.json AND ${OUTPUT_DIR}/false-positives/${f.id}.json on REJECTED. Use the VALIDATION.md verdict schema, EXTENDED with: cve_verification{nvd_score,computed_score,vector,on_kev}, risk{risk_score,risk_bucket}, adversarial{votes:${VOTES},refuted:${refuteCount}}, and verdict in {VALID,REPAIRED,REJECTED}. A REJECTED finding must NOT appear in any report — the false-positives file is its only record.\n\n` +
    `Return VERDICT_SCHEMA (proof_dir = ${f.dir}/evidence/validation/).`
}

// ============================================================================
// PHASE: Validate — pipeline per finding (checks -> refute -> verdict)
// ============================================================================
phase('Validate')

const results = await pipeline(
  inventory,
  // Stage A — authoritative checks + evidence package (+ repair)
  (f) => agent(checksPrompt(f), { schema: CHECKS_SCHEMA, label: `checks:${f.id}`, phase: 'Validate', agentType: 'general-purpose' }),
  // Stage B — adversarial refutation (N blind votes in parallel)
  (checks, f) =>
    parallel(Array.from({ length: VOTES }, (_, i) => () =>
      agent(refuterPrompt(f, i + 1), { schema: VOTE_SCHEMA, label: `refute:${f.id}#${i + 1}`, phase: 'Validate', agentType: 'general-purpose' })
    )).then(votes => ({ checks, votes: votes.filter(Boolean) })),
  // Stage C — verdict
  (carry, f) => {
    const checks = carry ? carry.checks : null
    const votes = carry ? carry.votes : []
    return agent(verdictPrompt(f, checks, votes), { schema: VERDICT_SCHEMA, label: `verdict:${f.id}`, phase: 'Validate', agentType: 'general-purpose' })
      .then(verdict => ({ finding: f, checks, votes, verdict }))
      .catch(() => ({ finding: f, checks, votes, verdict: { finding_id: f.id, verdict: 'REJECTED', reason: 'verdict agent error', failed_checks: ['verdict_error'] } }))
  },
)

const clean = results.filter(Boolean)
const valid = clean.filter(r => r.verdict && (r.verdict.verdict === 'VALID' || r.verdict.verdict === 'REPAIRED'))
const rejected = clean.filter(r => r.verdict && r.verdict.verdict === 'REJECTED')
const repaired = clean.filter(r => r.verdict && r.verdict.verdict === 'REPAIRED')
log(`Validate done: ${valid.length} valid (${repaired.length} repaired), ${rejected.length} rejected of ${clean.length}.`)

// ============================================================================
// PHASE: Synthesize — dedupe, risk-rank, asset report
// ============================================================================
phase('Synthesize')

const synth = await agent(
  `ROLE: ASSET VALIDATION SYNTHESIS. cwd is repo root.\n` +
  `OUTPUT_DIR: ${OUTPUT_DIR}\nTARGET: ${TARGET || '(asset)'}\nBUSINESS_TIER: ${BUSINESS_TIER}\n\n` +
  `Validated (incl. repaired): ${JSON.stringify(valid.map(r => r.verdict))}\n` +
  `Rejected: ${JSON.stringify(rejected.map(r => ({ id: r.verdict.finding_id, reason: r.verdict.reason, failed: r.verdict.failed_checks })))}\n\n` +
  `Do:\n` +
  `1. Read ${OUTPUT_DIR}/artifacts/validated/*.json. Cross-dedupe (same target/URL + same CWE => keep one, note the merge).\n` +
  `2. RISK-RANK the validated findings. If ${OUTPUT_DIR}/artifacts/attack-paths.json exists, run: python3 tools/risk-prioritise.py --output-dir ${OUTPUT_DIR}  (writes artifacts/attack-paths-ranked.json/.md). Otherwise rank by each finding's risk_score (descending; tie-break by CVSS then id) and write ${OUTPUT_DIR}/artifacts/validated-findings-ranked.json + .md yourself, recording the tier weights/thresholds used (risk-prioritiser defaults).\n` +
  `3. Write ${OUTPUT_DIR}/reports/validation-report.md: per validated finding — id, title, CVE (+ NVD score, your recomputed score, KEV status), severity, risk_score/bucket, the proof_dir, and a one-line "how it was proven". List rejected findings separately with the failing gate. Use the Transilience report style (formats/transilience-report-style/pentest-report.md) for severity calibration. Rejected findings appear ONLY in the rejected appendix, never in the validated body or counts.\n` +
  `4. Write ${OUTPUT_DIR}/artifacts/validation-summary.json: {asset, counts{total,valid,repaired,rejected}, validated:[{id,title,cve,severity,score,on_kev,risk_score,risk_bucket,proof_dir}], rejected:[{id,reason}], generated_at}.\n\n` +
  `Return SYNTH_SCHEMA.`,
  {
    schema: {
      type: 'object', additionalProperties: true,
      required: ['report_path', 'counts'],
      properties: {
        report_path: { type: 'string' },
        ranked_path: { type: ['string', 'null'] },
        counts: { type: 'object', additionalProperties: true },
        validated: { type: 'array', items: { type: 'object', additionalProperties: true } },
        rejected: { type: 'array', items: { type: 'object', additionalProperties: true } },
      },
    },
    label: 'synthesize', phase: 'Synthesize', agentType: 'general-purpose',
  }
)

return {
  status: 'VALIDATED',
  output_dir: OUTPUT_DIR,
  target: TARGET,
  counts: {
    total: clean.length,
    valid: valid.length,
    repaired: repaired.length,
    rejected: rejected.length,
  },
  validated: (synth && synth.validated) || valid.map(r => r.verdict),
  rejected: (synth && synth.rejected) || rejected.map(r => ({ id: r.verdict.finding_id, reason: r.verdict.reason })),
  report_path: synth ? synth.report_path : `${OUTPUT_DIR}/reports/validation-report.md`,
  ranked_path: synth ? (synth.ranked_path || null) : null,
}
