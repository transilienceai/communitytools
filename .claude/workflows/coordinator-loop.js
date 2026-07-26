export const meta = {
  name: 'coordinator-loop',
  description: 'The coordinator as a continuous, file-stateful experiment loop: recon -> think (3 hypotheses + wildcard) -> experiment (1-2 executors) -> integrate & write down attack-chain + session-memory -> loop until the goal is solved or the experiment budget (default 1000) is exhausted. Deep pentesting from the skill library, with mandatory creative/intuitive invention when stuck.',
  whenToUse: 'Drive ONE target to a goal autonomously. Pass args: {target, goal, output_dir?, scope?, skills_hint?, platform?, max_experiments?}. Platform-agnostic engine — htb-solve can delegate its Solve stage to this.',
  phases: [
    { title: 'Bootstrap', detail: 'parallel deep recon + read all source -> seed attack-chain.md, experiments.md, session-memory.md' },
    { title: 'Loop', detail: 'think -> (research) -> execute -> integrate -> (skeptic) — one batch per turn, until solved or budget exhausted' },
    { title: 'Validate', detail: 'blind finding-validators (parallel) + blind engagement-validator (P5)' },
    { title: 'Report', detail: 'completion/pentest report + structured summary' },
  ],
}

// ============================================================================
// COORDINATOR-LOOP — the P1->P2->P2b->P3->P4->(P4b)->P5 cycle as a workflow.
//
// Faithful to skills/coordination (principles.md, bookkeeping.md, executor /
// skeptic / validator roles, creative-research.md, VALIDATION.md) but with the
// loop turned inside-out: the script is the stateless conductor; the ENGAGEMENT
// STATE lives in three files under OUTPUT_DIR, re-read and re-written every batch:
//
//   attack-chain.md     working theory (<=50 lines, REWRITTEN each batch)
//   session-memory.md   durable session memory (append-only): access/creds,
//                       confirmed facts, dead-ends (so we never re-try them),
//                       open threads, pivot history, creative leads
//   experiments.md      append-only ledger (E-NNN rows; stats hook counts these)
//
// Why this shape: a 1000-experiment hunt cannot fit one agent's context. Files
// are the memory; each think/execute/integrate agent is a fresh, cheap context
// that loads exactly the state it needs. The INTEGRATE agent is the SOLE writer
// of experiments.md / attack-chain.md / session-memory.md, so parallel executors
// never race on the ledger (a deliberate adaptation of the "executor updates its
// own row" rule for safe concurrency).
//
// AGENT-CAP SAFETY: the runtime caps a run at 1000 agents. A batch spawns
// ~think(1)+research(0-1)+execute(1-2)+integrate(1)+skeptic(0-1) ~= 3-6 agents.
// MAX_BATCHES (default 150) * ~6 < 1000. Experiments climb faster than agents
// because each executor logs a whole escalation ladder as many E-rows.
//
// Sandbox: no Date.now()/Math.random()/new Date() — agents shell out to `date`.
// ============================================================================

// ---- inputs ----------------------------------------------------------------
const a = (args && typeof args === 'object' && !Array.isArray(args)) ? args : {}
const TARGET = a.target || (typeof args === 'string' ? args : null)
const GOAL = a.goal || 'Obtain the engagement objective (e.g. read the protected secret / capture all flags / achieve RCE) with reproducible proof.'
const SCOPE = a.scope || ''
const SKILLS_HINT = a.skills_hint || ''
const PLATFORM = a.platform || 'generic'
const MAX_EXPERIMENTS = Number(a.max_experiments) > 0 ? Math.floor(Number(a.max_experiments)) : 1000
const MAX_BATCHES = Number(a.max_batches) > 0 ? Math.floor(Number(a.max_batches)) : 150
const DRY_LIMIT = Number(a.dry_limit) > 0 ? Math.floor(Number(a.dry_limit)) : 8 // consecutive zero-progress batches (after a reset) -> stop
// COVERAGE-MODE convergence knobs. In coverage mode the loop is NOT bounded by a
// cost-style experiment budget: it runs until every applicable cell is covered AND a
// dry tail of DRY_TAIL empty batches holds ("all techniques plus more"), backstopped
// only by the per-asset agent slice + this absolute runaway ceiling.
const ABSOLUTE_MAX_BATCHES = 1000
const DRY_TAIL = Number(a.dry_tail) > 0 ? Math.floor(Number(a.dry_tail)) : 2 // empty batches past 100% coverage before done
// COVERAGE MODE (web/API/cloud pentest) vs default FLAG mode (CTF/HTB). Every
// coverage block below is guarded by `MODE === 'coverage'`, so flag-mode behavior
// — and htb-solve, which passes no `mode` — is byte-identical to before.
const MODE = a.mode === 'coverage' ? 'coverage' : 'flag'
// STRICT PER-FINDING INTERLEAVE: validate each candidate the instant INTEGRATE
// materializes it, to a terminal verdict, BEFORE the next batch. shouldInlineValidate
// is hoisted from the lane block below (pure function of its args). Explicit
// a.inline_validate wins; else ON for coverage / OFF for flag (htb-solve untouched).
// Frozen-operand paths + tier + cure-rounds + per-batch cap feed the lane;
// HARD_RESERVE (computed after the lane consts init) governs deferral.
const INLINE_VALIDATE = shouldInlineValidate(MODE, a.inline_validate)
const REPAIR = a.repair !== false
const BUSINESS_TIER = a.business_tier || 'unknown'
const MAX_CURE_ROUNDS = Number(a.max_cure_rounds) >= 0 ? Math.floor(Number(a.max_cure_rounds)) : 1
const MAX_VALIDATE_PER_BATCH = Number(a.max_validate_per_batch) > 0 ? Math.floor(Number(a.max_validate_per_batch)) : 4
const NVD_CACHE_DIR = a.nvd_cache_dir || null
const KEV_SNAPSHOT = a.kev_snapshot || null
// E4 validation replay-cache (reuse tools/validation_cache.py; opt-in on resume runs
// so a fresh run never pays a restore/store tax). CACHE_VERSION namespaces verdicts so
// a lane change can't replay a stale one.
const VALIDATION_CACHE_DIR = a.validation_cache_dir || null
const REPLAY_CACHE = !!a.replay_cache && !!VALIDATION_CACHE_DIR
const CACHE_VERSION = 1
// Agent-cap reserve for this run's non-loop overhead (correlate/report/slack; the
// network deep-dive folds in its pre-deep-dive sweep spend). undefined -> assessBudget
// falls back to GLOBAL_RESERVE (which is declared later in this file).
const AGENT_RESERVE = Number.isFinite(Number(a.agent_reserve)) ? Math.max(0, Math.floor(Number(a.agent_reserve))) : undefined
// The per-asset attack-class matrix (from skills/coordination/reference/coverage-matrix.md).
// When the orchestrator (pentest-engagement) supplies it, the coordinator drives the
// THINK loop by it AND skips its own surface-expansion recon (the orchestrator already expanded).
const COVERAGE_MATRIX = Array.isArray(a.coverage_matrix) ? a.coverage_matrix : null
const OUTPUT_BASE = a.output_base || (MODE === 'coverage' ? 'projects/pentest' : 'projects/ctf')
const SEVERITY_RUBRIC = a.severity_rubric === 'root-cause' ? 'root-cause' : 'demonstrated'
// Rules of engagement for active exploitation. {reversible_writes, prohibitions[]}.
const ROE = (a.roe && typeof a.roe === 'object') ? a.roe : { reversible_writes: false, prohibitions: [] }
const REPORT_FORMAT = a.report_format === 'transilience' ? 'transilience' : 'htb'
// OUTPUT_DIR: caller may pass one; otherwise Bootstrap derives it.
let OUTPUT_DIR = a.output_dir || null

// ---- helpers ---------------------------------------------------------------
// Skeptic cadence: mandatory at 5, 15, 25, then every 25. Returns the threshold
// N just crossed (used as the brief filename), or 0.
function skepticDue(prev, cur) {
  for (const t of [5, 15, 25]) if (prev < t && cur >= t) return t
  if (cur >= 50) {
    const curMult = Math.floor(cur / 25) * 25
    const prevMult = Math.floor(prev / 25) * 25
    if (curMult > prevMult && curMult >= 50) return curMult
  }
  return 0
}

// ============================================================================
// DETERMINISTIC VALIDATION LANE — inline copy of .claude/workflows/lib/wf-helpers.mjs
// (verdict/risk/CVE-reconcile helpers + governor + per-finding validation
// prompts/schemas/buildInterim). Sandbox has no import; parity.test.mjs asserts
// this copy is byte-identical to the tested module. NO LLM in these paths.
// ============================================================================
const SEVERITY = ['Critical', 'High', 'Medium', 'Low', 'Info']; // high -> low

function severityBand(score) {
  const s = Number(score);
  if (!(s > 0)) return 'Info';        // 0 / NaN / null / negative -> Info (schema has no "None")
  if (s >= 9.0) return 'Critical';
  if (s >= 7.0) return 'High';
  if (s >= 4.0) return 'Medium';
  return 'Low';
}

// ---------------------------------------------------------------------------
// Risk score — a faithful JS port of tools/risk-prioritise.py's per-finding
// scoring (single-sourced constants; a parity test asserts equality with the
// Python defaults). score = feasibility * (cvss/10 | 0.5) * tier_weight * exposure
// ---------------------------------------------------------------------------
const TIER_WEIGHTS = { crown_jewel: 1.0, revenue: 0.7, support: 0.4, dev: 0.2, unknown: 0.3 };
const RISK_THRESHOLDS = { immediate: 0.6, short_term: 0.3, medium_term: 0.1 };

function round4(x) { return Math.round((x + Number.EPSILON) * 1e4) / 1e4; }

function riskBucket(score) {
  if (score >= RISK_THRESHOLDS.immediate) return 'immediate';
  if (score >= RISK_THRESHOLDS.short_term) return 'short_term';
  if (score >= RISK_THRESHOLDS.medium_term) return 'medium_term';
  return 'monitor';
}

function riskScore({ cvss, tier, exposure, feasibility } = {}) {
  const technical = Number(cvss) > 0 ? Number(cvss) / 10 : 0.5;
  const weight = TIER_WEIGHTS[tier] != null ? TIER_WEIGHTS[tier] : TIER_WEIGHTS.unknown;
  const exp = exposure === 1.0 || exposure === 0.5 ? exposure : (exposure ? 1.0 : 0.5);
  const feas = feasibility == null ? 1.0 : Number(feasibility);
  const score = round4(feas * technical * weight * exp);
  return {
    risk_score: score,
    risk_bucket: riskBucket(score),
    technical_severity: round4(technical),
    business_impact: weight,
    entry_exposure: exp,
    cvss_missing: !(Number(cvss) > 0),
  };
}

// Exposure a finding inherits from its asset: WEB assets are external (1.0),
// NETWORK hosts internal (0.5), unless the asset carries an explicit override.
function exposureFor(asset) {
  if (asset && (asset.exposure === 1.0 || asset.exposure === 0.5)) return asset.exposure;
  if (asset && typeof asset.external === 'boolean') return asset.external ? 1.0 : 0.5;
  return (asset && asset.platform === 'network') ? 0.5 : 1.0;
}

// ---------------------------------------------------------------------------
// CVE reconcile — the CVSS score itself comes from the verified tool-runner
// (tools/cvss_calc.py -> NVD; CVSS v4.0 primary, falling back v3.1 -> v3.0 ->
// v2.0). JS only decides whether the numbers agree.
// Rule: computed (from vector) must exist and agree with NVD and the claim
// within |Δ| <= 0.1, and vectors must match when both present.
// ---------------------------------------------------------------------------
function normVector(v) {
  if (!v) return '';
  return String(v).replace(/^CVSS:3\.[01]\//i, '').split('/').filter(Boolean).sort().join('/').toUpperCase();
}

function cveReconcile({ claimed_score, computed_score, nvd_score, claimed_vector, computed_vector } = {}) {
  // 1e-9 epsilon: one-decimal scores exactly 0.1 apart (the legit 3.0-vs-3.1
  // rounding-step gap) can land at 0.10000000000000009 in IEEE-754 and wrongly
  // fail a bare `<= 0.1`, spuriously demoting a valid CVE finding.
  const near = (x, y) => x != null && y != null && Math.abs(Number(x) - Number(y)) <= 0.1 + 1e-9;
  const haveComputed = computed_score != null;
  const vectorOk = !claimed_vector || !computed_vector || normVector(claimed_vector) === normVector(computed_vector);
  const nvdOk = nvd_score == null || near(computed_score, nvd_score);
  const claimOk = claimed_score == null || near(computed_score, claimed_score);
  return { reconciled: !!(haveComputed && vectorOk && nvdOk && claimOk), vectorOk, nvdOk, claimOk, haveComputed };
}

// ---------------------------------------------------------------------------
// Evidence manifest — the mandatory files for a finding, BRANCHED so a raw
// TCP/DNS/SSH-banner or non-code finding is not falsely demoted for lacking
// screenshots or code-references. Entries: {path, type: 'file'|'glob'}.
// ---------------------------------------------------------------------------
function EVIDENCE_MANIFEST(finding) {
  const dir = `${finding.dir}/evidence/validation`;
  const files = [
    { path: `${dir}/validation-summary.md`, type: 'file' },
    { path: `${dir}/poc-rerun-output.txt`, type: 'file' },
    { path: `${dir}/verification-script.py`, type: 'file' },
  ];
  if (finding.is_web) files.push({ path: `${dir}/screenshots/*.png`, type: 'glob' });
  if ((finding.cve_ids || []).length) files.push({ path: `${dir}/cve-verification.md`, type: 'file' });
  if (finding.cites_code) files.push({ path: `${dir}/code-references.md`, type: 'file' });
  return files;
}

// probe = { files: [{path, exists, bytes}] } from the one-job evidence-probe agent.
function evidenceComplete(finding, probe) {
  const manifest = EVIDENCE_MANIFEST(finding);
  const got = new Map(((probe && probe.files) || []).map((f) => [f.path, f]));
  const missing = [];
  for (const m of manifest) {
    const hit = got.get(m.path);
    if (!hit || !hit.exists || !(Number(hit.bytes) > 0)) missing.push(m.path);
  }
  return { all_present: missing.length === 0, missing };
}

// ---------------------------------------------------------------------------
// The verdict — a pure boolean AND. NO LLM. Distinguishes the three outcomes:
//   REJECTED  = adversarially refuted (majority) -> stays OUT of the report
//   DEMOTED   = real but under-evidenced / not-reproduced / infra error -> gaps
//   VALID/REPAIRED = every gate passed AND the step-by-step PoC reproduced
//
// `repro` is the separate, context-free reproduction agent's structured result
// ({ reproduced }) — a real requirement now: every finding must ship a
// prerequisites + step-by-step PoC that a blind agent re-ran to the stated
// result. No confirmation (repro null / reproduced:false) => DEMOTED, never VALID.
// ---------------------------------------------------------------------------
function computeVerdict(finding, checks, votes, probe, repro, opts = {}) {
  const votesTotal = opts.votesTotal != null ? opts.votesTotal : (votes || []).length;
  const refuteCount = (votes || []).filter((v) => v && v.refuted).length;
  const majority = Math.floor(votesTotal / 2) + 1;
  const refuted = votesTotal > 0 && refuteCount >= majority;

  // Infra error: the checks stage died. Never REJECT (that would hide a real
  // finding); demote so it surfaces in the dropped/ audit trail.
  if (checks == null) return { finding_id: finding.id, verdict: 'DEMOTED', failed_checks: ['checks_infra_error'], refuteCount, reason: 'checks stage returned null' };

  const failed = [];
  const c = checks.canonical || {};
  for (const k of ['cvss_consistency', 'evidence_exists', 'poc_validation', 'claims_vs_raw', 'log_corroboration']) if (!c[k]) failed.push(`canonical:${k}`);
  if (checks.cve && checks.cve.applicable && !checks.cve.reconciled) failed.push('cve:reconcile');
  const ex = checks.exploit || {};
  const exploitNeeded = finding.type !== 'info' && finding.type !== 'config';
  if (exploitNeeded && !(ex.ran && ex.proven && ex.deterministic && ex.signal_token)) failed.push('exploit:not_proven');
  const ev = evidenceComplete(finding, probe);
  if (!ev.all_present) failed.push('evidence:missing_files');
  // Reproducible step-by-step PoC, confirmed by the blind reproduction agent.
  if (repro == null) failed.push('poc:repro_unavailable');
  else if (!repro.reproduced) failed.push('poc:not_reproduced');

  // Adversarial refutation is the ONLY path to REJECTED.
  if (refuted) return { finding_id: finding.id, verdict: 'REJECTED', failed_checks: failed.concat('adversarial:refuted'), refuteCount };

  if (failed.length === 0) return { finding_id: finding.id, verdict: ex.repaired ? 'REPAIRED' : 'VALID', failed_checks: [], refuteCount };
  // Not refuted but a gate failed -> real-but-under-evidenced -> DEMOTED.
  return { finding_id: finding.id, verdict: 'DEMOTED', failed_checks: failed, refuteCount, missing_evidence: ev.missing };
}

// Deterministically pick the FINAL PoC to record: the reproduction agent's
// corrected version wins when it adjusted the steps (that's the "perfected"
// recipe); otherwise the checks agent's authored PoC. Shape: an ordered list of
// {description, command, image_url} steps.
function finalPoc(checks, repro) {
  const authored = Array.isArray(checks && checks.poc) ? checks.poc : [];
  if (repro && repro.reproduced && Array.isArray(repro.corrected_steps) && repro.corrected_steps.length) {
    return repro.corrected_steps;
  }
  return authored;
}

// ---------------------------------------------------------------------------
// STRICT PER-FINDING INTERLEAVE — the decision helpers the coordinator-loop
// convergence loop and its agent-budget governor drive on. All pure: the loop
// is a thin driver, every decision is here (and parity-guarded in both files).
//   cureLoopDecision : verdict -> CONFIRMED | REJECTED | CURE | DROPPED
//   terminalSubdir   : verdict -> which artifacts/<dir> the finding is written to
//   coverageDecision : a class is covered only with a VALID finding / genuine-neg
//   backstopDecision : fixed-quorum + DEFERRAL governor (never shrink the quorum)
//   assessBudget     : partition the 1000-agent lifetime cap across N assets
// ---------------------------------------------------------------------------
const DEFAULT_VOTES = 3;          // adversarial refuter quorum (was 2)
const AGENT_CAP = 1000;           // the runtime's per-run agent lifetime cap
const GLOBAL_RESERVE = 40;        // reserve for correlate + report + slack

// The per-candidate cure/verdict outcome. round is 0-based; a DEMOTED finding is
// cured up to maxCureRounds times before it is DROPPED (drop-entirely). VALID or
// REPAIRED -> CONFIRMED; adversarially REJECTED -> terminal. Use `<` so cap=0
// drops immediately (a caller's strict no-cure single pass).
function cureLoopDecision(round, verdict, maxCureRounds) {
  if (verdict === 'VALID' || verdict === 'REPAIRED') return 'CONFIRMED';
  if (verdict === 'REJECTED') return 'REJECTED';
  if (Number(round) < Number(maxCureRounds)) return 'CURE';
  return 'DROPPED';
}

// Which artifacts/<subdir> a terminal verdict is persisted to. VALID/REPAIRED ->
// the report body; REJECTED -> false-positives (audit only); everything else
// (DEMOTED / unknown) -> dropped (audit only, never the report).
function terminalSubdir(verdict) {
  if (verdict === 'VALID' || verdict === 'REPAIRED') return 'validated';
  if (verdict === 'REJECTED') return 'false-positives';
  return 'dropped';
}

// Coverage-by-VALID: a class is covered only when it has a VALID/REPAIRED finding
// OR a genuine negative (thoroughly tested clean). A class whose only candidates
// were REJECTED/DROPPED stays pending, so the loop keeps searching.
function coverageDecision(findingVerdicts, negativeResult) {
  const vs = findingVerdicts || [];
  if (vs.some((v) => v === 'VALID' || v === 'REPAIRED')) return 'covered';
  if (negativeResult === 'genuine_negative') return 'covered';
  return 'pending';
}

// Inline validation fires when explicitly enabled; else defaults ON for coverage
// mode (preserves the old RUN_VALIDATION default-true for standalone coverage
// runs) and OFF for flag mode (htb-solve is untouched).
function shouldInlineValidate(mode, inlineValidate) {
  if (inlineValidate === true) return true;
  if (inlineValidate === false) return false;
  return mode === 'coverage';
}

// Fixed-quorum + deferral governor: validate in-loop at the FULL quorum while the
// asset is below its hard reserve; once it reaches the reserve, DEFER whole
// candidates to the reserved end-of-loop sweep (still full quorum). Never shrink
// the quorum — that would make the REJECT threshold run-dependent.
function backstopDecision(agentsSpawned, hardReserve) {
  return Number(agentsSpawned) >= Number(hardReserve) ? 'defer' : 'run_now';
}

// Partition the shared 1000-agent lifetime budget across N assets so the worst-
// case total stays under the runtime cap (invariant: perAsset*A + reserve <= cap).
// `reserve` overrides GLOBAL_RESERVE (e.g. the network deep-dive folds in the
// pre-deep-dive sweep spend); omitted -> GLOBAL_RESERVE.
function assessBudget({ assets, reserve } = {}) {
  const A = Math.max(1, Math.floor(Number(assets) || 1));
  const R = Number.isFinite(Number(reserve)) ? Math.max(0, Math.floor(Number(reserve))) : GLOBAL_RESERVE;
  const perAsset = Math.floor((AGENT_CAP - R) / A);
  const hardReserve = Math.max(0, Math.floor(perAsset * 0.85));
  return { assets: A, perAsset, hardReserve, agentCap: AGENT_CAP, globalReserve: R };
}

// Convergence-first completion (coverage mode): done only when every applicable
// (surface-unit x attack-class) cell is covered/negated (coveragePending===0) AND
// the dry tail has held for `dryTail` consecutive batches. "all techniques + more".
function convergenceDone({ coveragePending, coverageDryStreak, dryTail } = {}) {
  const K = Math.max(1, Math.floor(Number(dryTail) || 2));
  return Number(coveragePending) === 0 && Math.floor(Number(coverageDryStreak) || 0) >= K;
}

// The dry-tail streak transition. The tail only accrues once coverage is complete
// (pending 0); ANY new confirmed finding OR a reopened cell resets it to 0 so the
// "plus more" tail keeps probing until the surface is genuinely quiet.
function nextDryStreak(prevStreak, { coveragePending, newConfirmed, reopened } = {}) {
  if (Number(coveragePending) !== 0) return 0;
  if (newConfirmed || reopened) return 0;
  return Math.max(0, Math.floor(Number(prevStreak) || 0)) + 1;
}

// Fold a batch's terminal candidate results into accumulators + a per-class
// coverage signal. Each result: { verdict, class_id? }.
function reduceCandidateVerdicts(results) {
  const out = { confirmed: [], rejected: [], dropped: [], byClass: {} };
  for (const r of (results || [])) {
    if (!r || !r.verdict) continue;
    const sub = terminalSubdir(r.verdict);
    const bucket = sub === 'validated' ? 'confirmed' : (r.verdict === 'REJECTED' ? 'rejected' : 'dropped');
    out[bucket].push(r);
    if (r.class_id) (out.byClass[r.class_id] = out.byClass[r.class_id] || []).push(r.verdict);
  }
  return out;
}

// The loop's return counts (so adaptSummary never reads a silent null).
function summarizeLoopCounts(confirmed, rejected, dropped) {
  const n = (x) => (Array.isArray(x) ? x.length : (Number(x) || 0));
  const c = n(confirmed), r = n(rejected), d = n(dropped);
  return { confirmed: c, rejected: r, dropped: d, total: c + r + d };
}

// ---------------------------------------------------------------------------
// VALIDATION LANE — the shared per-finding validation schemas, prompt builders,
// and the interim-JSON builder. Pure builders (no I/O, no closures): both
// workflow files embed byte-identical copies, parity-guarded. Prompt builders
// take P = { OUTPUT_DIR, TARGET, NVD_KEV, REPAIR, BUSINESS_TIER }; buildInterim
// takes { tier, platform, votes }. Single source of truth for BOTH the
// interleaved coordinator-loop lane AND the standalone validate-findings run.
// ---------------------------------------------------------------------------

// Authoritative CVE/KEV instruction, single-sourced. When cache/snapshot paths
// are supplied (an engagement froze its operands for determinism) read those;
// else fall back to a live fetch (standalone/regression wants fresh drift).
function nvdKevText(P = {}) {
  const nvd = P.nvd_cache_dir ? `python3 tools/nvd-lookup.py --cache-dir ${P.nvd_cache_dir} <CVE-ID>` : `python3 tools/nvd-lookup.py <CVE-ID>`;
  const kev = P.nvd_cache_dir ? `python3 tools/kev-lookup.py --cache-dir ${P.nvd_cache_dir} <CVE-ID> (reads the frozen ${P.kev_snapshot || 'kev-snapshot.json'}, create-on-miss)` : `WebFetch https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json and check whether the CVE is listed`;
  return [
    'AUTHORITATIVE CVE SOURCES (do not rely on the finding\'s own claim):',
    `1. NVD: \`${nvd}\` — parse the final \`JSON_SUMMARY: {...}\` line (cve_id, score, severity, cvss_version, cvss_vector, cwes[], status) AND the per-version "Vector:" lines. Use the PRIMARY per the v4.0-first ladder: CVSS v4.0 preferred, then v3.1 -> v3.0 -> v2.0 (nvd-lookup already marks the primary and fills cvss_version/cvss_vector).`,
    `2. CISA KEV (known-exploited): ${kev} (records {cveID, dateAdded, requiredAction, knownRansomwareCampaignUse}). Being on KEV raises real-world priority regardless of base score.`,
    '3. Vendor/official advisory: follow the authoritative reference URLs NVD returns (cve.references) and confirm affected versions + the vulnerability class match the finding. Quote the source.',
    'Reconcile: the finding\'s claimed CVE id, CVSS vector, base score, and severity must all agree with NVD and with your from-vector recomputation (|delta| <= 0.1 on the score, exact match on the vector and band). Flag KEV status. Any unreconciled divergence => CVE check FAILS.',
  ];
}

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
        nvd_score: { type: ['number', 'null'] }, computed_score: { type: ['number', 'null'], description: 'from-vector recompute via the cvss lib / nvd-lookup (the TOOL computes it; JS reconciles)' },
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
};

const VOTE_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['refuted'],
  properties: {
    refuted: { type: 'boolean' },
    reason: { type: 'string' },
    weakest_link: { type: 'string', description: 'the single most doubtful claim/step' },
  },
};

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
};

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
};

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
    `Return CHECKS_SCHEMA with each lane's booleans + the reported numbers + poc[] + report_fields. Be strict and evidence-bound: if you cannot corroborate something, mark it false with detail.`;
}

function refuterPrompt(f, i, P = {}) {
  return `ROLE: ADVERSARIAL VALIDATOR #${i} (blind). Your job is to REFUTE finding ${f.id}. You see ONLY its evidence package — NOT any validator's verdict, NOT attack-chain/session-memory, NOT other findings. Default to skepticism: if a claim is not independently supported, it is refuted.\n\n` +
    `Read ${f.dir}/description.md, ${f.dir}/poc.py, ${f.dir}/poc_output.txt, ${f.dir}/evidence/ (including evidence/validation/poc-rerun-output.txt, cve-verification.md, verification-script.py). For a CVE, independently sanity-check against the SAME frozen operands the validator used: ${(P.NVD_KEV || nvdKevText(P))[1]} Does the claimed CVSS vector actually yield the claimed score? does NVD agree? For the exploit: does the captured output actually PROVE the vulnerability, or is the "evidence" incidental/ambiguous/self-asserted? Could the output be produced on a non-vulnerable target? Are the factual claims present in raw scan output?\n\n` +
    `COMMON FALSE-HIGH CALIBRATION — apply \`skills/coordination/reference/severity-calibration.md\`. REFUTE (impact not demonstrated/reachable as claimed) and name the unmet precondition as weakest_link if the finding is any of: CORS reflected-origin scored as token-theft WITHOUT \`Access-Control-Allow-Credentials: true\` + ambient-cookie-auth'd sensitive data; Azure \`AADSTS50126\` (failed auth) read as "MFA disabled" (Entra checks credentials BEFORE MFA — a failed login never reaches the MFA prompt); an ENABLER (spray-capability / Golden-SAML or cert template / writable ACL / SSRF reachability) scored as a DEMONSTRATED compromise it never actually performed; a scanner/vulners version-only "Critical" on a backported-distro or appliance-bundled package (version banner ≠ patch level); or a verified CVE scored at base WITHOUT confirming the vulnerable feature is enabled and reachable (e.g. IKEv1 CVE on an IKEv2-only gateway, an inbound-HRS CVE on an outbound-only client).\n\n` +
    `Return VOTE_SCHEMA: refuted (true if you found a real reason to doubt the finding, the score, or the CVE), reason, and weakest_link (the single most doubtful element).`;
}

function probePrompt(f, manifest, P = {}) {
  return `ROLE: EVIDENCE PROBE (one job, no judgment). cwd is repo root. For EACH path below, run \`test -f\`/\`wc -c\` (for a \`*.png\` glob, count matching files and report the largest as one entry with its byte size; exists=true iff at least one non-empty match). Report ONLY the real on-disk facts — do not create, repair, or judge anything.\n\n` +
    `FINDING: ${f.id}\nPATHS:\n${manifest.map((m) => `  - ${m.path} (${m.type})`).join('\n')}\n\n` +
    `Return PROBE_SCHEMA: files:[{path, exists, bytes}] with one entry per path above (use the exact path string given).`;
}

function reproPrompt(f, poc, P = {}) {
  return `ROLE: BLIND PoC REPRODUCER (context-free, independent). cwd is repo root. You are handed ONLY a finding's ordered PoC STEPS and the target. You did NOT run the original test; you may NOT read the finding's description.md, poc.py, evidence/, attack-chain.md, session-memory.md, other findings, or any validator/refuter output. Reproduce the result as a competent tester with zero prior context would, by following the recipe EXACTLY.\n\n` +
    `FINDING: ${f.id}\nTARGET: ${P.TARGET || '(from the steps)'}\nSTEPS: ${JSON.stringify(Array.isArray(poc) ? poc : [])}\n\n` +
    `Rules: read-only / non-destructive only — NO brute force, NO DoS, NO destructive writes, stay on the given target.\n` +
    `1. ENTRY POINT: confirm step 1 is a genuine starting point (open a terminal / open a browser / establish the initial connection). entry_point_ok accordingly.\n` +
    `2. EXECUTE each step IN ORDER, running its \`command\` exactly as written (timeout ~60s/step). At the LAST step, compare the observed output to the finding's claimed result; put the real observed final output in observed_result; result_matches accordingly.\n` +
    `3. PERFECT IT: if a step is wrong/ambiguous but the finding IS still reproducible, return the minimal corrected_steps (same {description, command, image_url} shape) that DO reproduce it (step 1 still an entry point, LAST step still the actual result). Only set reproduced=true if you ACTUALLY observed the result — with the given OR the corrected recipe.\n` +
    `Write ${f.dir}/evidence/validation/reproduction.md (what you ran, what you observed, any corrections). Return REPRO_SCHEMA. reproduced=true ONLY when you independently observed the finding's result.`;
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
    `Reversible/authorized, non-destructive actions ONLY. Return {cured_gates:[...], notes} — the workflow re-validates on fresh blind agents and recomputes the verdict; your return is NOT trusted as proof.`;
}

// Build the interim validated JSON — the deterministic contract report_data_build.py
// consumes. Content is JS-authored; a writer agent only persists it verbatim.
function buildInterim(f, checks, verdict, repro, opts = {}) {
  const tier = opts.tier || 'unknown';
  const platform = opts.platform || 'generic';
  const votes = opts.votes != null ? opts.votes : DEFAULT_VOTES;
  const cve = (checks && checks.cve) || {};
  const cvss = cve.computed_score != null ? cve.computed_score : (cve.claimed_score != null ? cve.claimed_score : (f.claimed_score != null ? f.claimed_score : null));
  const sev = cvss != null ? severityBand(cvss) : (f.claimed_severity && SEVERITY.includes(f.claimed_severity) ? f.claimed_severity : 'Info');
  const feasibility = verdict.verdict === 'VALID' || verdict.verdict === 'REPAIRED' ? 1.0 : 0.5;
  const risk = riskScore({ cvss, tier, exposure: exposureFor({ platform }), feasibility });
  const rf = (checks && checks.report_fields) || {};
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
  };
}

// ---- schemas ---------------------------------------------------------------
const BOOTSTRAP_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['ok', 'output_dir', 'exp_count'],
  properties: {
    ok: { type: 'boolean' },
    output_dir: { type: 'string' },
    exp_count: { type: 'number' },
    services: { type: 'array', items: { type: 'string' } },
    surface: { type: 'array', items: { type: 'string' } },
    source_read: { type: 'array', items: { type: 'string' }, description: 'files/dirs of source actually read' },
    initial_goal: { type: 'string' },
    blocked_reason: { type: ['string', 'null'] },
    coverage_seeded: { type: 'boolean', description: 'coverage mode: OUTPUT_DIR/coverage.json written from the matrix' },
    applicable_class_count: { type: 'number', description: 'coverage mode: count of applicable attack classes to clear' },
  },
}

const THINK_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['batch', 'chosen', 'research_needed', 'terminate'],
  properties: {
    batch: { type: 'number' },
    hypotheses: {
      type: 'array', description: 'exactly 3, >=1 wildcard',
      items: {
        type: 'object', additionalProperties: true,
        properties: {
          id: { type: 'string' }, text: { type: 'string' }, wildcard: { type: 'boolean' },
          goal: { type: 'string' }, technique: { type: 'string' }, target: { type: 'string' }, expected_signal: { type: 'string' },
        },
      },
    },
    chosen: {
      type: 'array', description: '1-2 missions to run this batch',
      items: {
        type: 'object', additionalProperties: true,
        required: ['objective', 'goal', 'role'],
        properties: {
          objective: { type: 'string' },
          goal: { type: 'string', description: 'conceptual goal (NOT technique)' },
          technique: { type: 'string' },
          target: { type: 'string' },
          role: { type: 'string', enum: ['explore', 'exploit'] },
          skill_files: { type: 'array', items: { type: 'string' }, description: '1-2 specific reference/*.md or scenarios/*.md paths' },
          scenario: { type: ['string', 'null'] },
          patt_url: { type: ['string', 'null'] },
          expected_signal: { type: 'string' },
          invented: { type: 'boolean', description: 'true if this is a novel technique not in the skill library' },
          covers_class: { type: ['string', 'null'], description: 'coverage mode: class_id from coverage.json this mission advances, or null for a pure goal/wildcard mission' },
          covers_cells: { type: 'array', description: 'coverage mode: the deterministic (scope_key, class_id) cells this mission will cover (generalizes covers_class; from coverage_gate.py --emit-open)', items: { type: 'object', additionalProperties: true, properties: { key: { type: 'string' }, class_id: { type: 'string' } } } },
        },
      },
    },
    coverage_state: {
      type: 'object', additionalProperties: true,
      description: 'coverage mode only',
      properties: {
        applicable: { type: 'number' },
        covered: { type: 'number' },
        coverage_ratio: { type: 'number' },
        open_cells: { type: 'array', description: 'the code-computed open-cell backlog from coverage_gate.py --emit-open', items: { type: 'object', additionalProperties: true } },
        pending_ranked: {
          type: 'array', description: 'highest-value uncovered classes first',
          items: { type: 'object', additionalProperties: true, properties: { class_id: { type: 'string' }, value_rank: { type: 'number' }, rationale: { type: 'string' } } },
        },
      },
    },
    research_needed: { type: 'boolean' },
    research_reason: { type: 'string' },
    terminate: { type: 'boolean' },
    terminate_reason: { type: 'string' },
    notes: { type: 'string' },
  },
}

const RESEARCH_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['brief', 'has_wildcard'],
  properties: {
    brief: { type: 'string', description: 'RESEARCH_BRIEF, <=10 lines, tagged [model]/[web]/[skills]/[chain]/[wildcard]' },
    has_wildcard: { type: 'boolean' },
    cves: { type: 'array', items: { type: 'string' } },
  },
}

const EXEC_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['mission_objective', 'goal', 'result'],
  properties: {
    mission_objective: { type: 'string' },
    goal: { type: 'string' },
    technique: { type: 'string' },
    target: { type: 'string' },
    result: { type: 'string', enum: ['success', 'partial', 'fail'] },
    finding: {
      type: ['object', 'null'], additionalProperties: true,
      properties: { id: { type: 'string' }, title: { type: 'string' }, severity: { type: 'string' }, cvss: { type: 'number' }, dir: { type: 'string' } },
    },
    reproduced_3x: { type: 'boolean' },
    escalation_exhausted: { type: 'boolean', description: 'all 5 ladder rungs tried before declaring fail' },
    observations: { type: 'string', description: 'what happened / where it broke / what would unblock' },
    evidence_paths: { type: 'array', items: { type: 'string' } },
    unexpected: { type: ['string', 'null'], description: 'findings outside the objective' },
    experiments_logged: { type: 'number', description: 'how many E-rows this mission warrants' },
  },
}

const INTEGRATE_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['batch', 'exp_count', 'goal_reached', 'progress', 'terminate'],
  properties: {
    batch: { type: 'number' },
    exp_count: { type: 'number', description: 'authoritative count of E- rows in experiments.md after this batch' },
    goal_reached: { type: 'boolean' },
    goal_reached_evidence: { type: 'string' },
    progress: { type: 'boolean', description: 'did this batch advance the engagement (new access/info/finding)?' },
    new_findings: {
      type: 'array',
      items: { type: 'object', additionalProperties: true, properties: { id: { type: 'string' }, title: { type: 'string' }, dir: { type: 'string' } } },
    },
    active_goal: { type: 'string' },
    stuck_goal: { type: ['string', 'null'] },
    recommend_reset: { type: 'boolean', description: 'goal_attempts >= 3 on active goal -> P4b' },
    terminate: { type: 'boolean' },
    terminate_reason: { type: 'string' },
    chain_summary: { type: 'string' },
    coverage_update: {
      type: 'array', description: 'coverage mode: classes whose status changed this batch',
      items: { type: 'object', additionalProperties: true, properties: { class_id: { type: 'string' }, new_status: { type: 'string', enum: ['covered', 'pending', 'NA'] }, evidence_ref: { type: 'array', items: { type: 'string' } }, justification: { type: 'string' } } },
    },
    coverage_ratio: { type: 'number', description: 'coverage mode: coverage_gate.py coverage_ratio after this batch' },
    applicable_pending: { type: 'number', description: 'coverage mode: coverage_gate.py missing_cells count after this batch (0 => complete)' },
    coverage_complete: { type: 'boolean', description: 'coverage mode: coverage_gate.py reported "complete":true (ratio==1.0, no missing/extra/dangling/false_NA)' },
    open_cells: { type: 'array', description: 'coverage mode: the CURRENT open-cell set from coverage_gate.py --emit-open (each "class_id @ scope_key") — drives the dry-tail reopen set-diff', items: { type: 'object', additionalProperties: true, properties: { key: { type: 'string' }, class_id: { type: 'string' } } } },
  },
}

const ENGAGEMENT_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['engagement_status'],
  properties: { engagement_status: { type: 'string', enum: ['THOROUGH', 'GAPS_FOUND'] }, checks: { type: 'object', additionalProperties: true }, coverage_ratio: { type: 'number' }, remediation: { type: 'array', items: { type: 'string' } } },
}

const REPORT_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['status', 'report_path'],
  properties: { status: { type: 'string' }, report_path: { type: 'string' }, narrative: { type: 'string' }, stats: { type: 'object', additionalProperties: true } },
}

// Shared discipline preamble baked into every loop agent (keeps each fresh
// context aligned with the standing principles without re-reading SKILL.md).
// Coverage-mode discipline — appended to DISCIPLINE only when MODE==='coverage'.
// Flips the engine from a flag-hunt to a breadth-complete coverage audit and licenses
// reversible active exploitation + root-cause severity. Empty in flag mode (zero change).
const COVERAGE_DISCIPLINE = MODE === 'coverage' ? '\n' + [
  '',
  'COVERAGE MODE (web/API/cloud pentest — skills/coordination/reference/coverage-matrix.md):',
  '- BREADTH BEFORE DEPTH: this is a coverage audit, not a flag hunt. Every applicable attack class in OUTPUT_DIR/coverage.json must reach `covered` (>=1 experiment) or justified `NA` before COMPLETE.',
  '- NO-FINGERPRINT CLASSES emit no symptom until probed — proactively test: CORS (reflected/null/credentials), unauth webhook/ingress oracles, redirect scheme-downgrade + missing HSTS, security headers on the API AND each web origin, unauth existence oracles, verbose errors, public docs/swagger, TLS posture (sslscan), stored-URL/connector SSRF.',
  '- REAL TOOLS FIRST for recon: crt.sh/certspotter/subfinder (surface), sslscan (TLS), nuclei (templated exposure), httpx, Burp/Playwright — before any bespoke requests script. Record an unavailable tool-class as a limitation; never skip it silently.',
  '- ACTIVE EXPLOITATION (RoE: ' + (ROE.reversible_writes ? 'reversible writes AUTHORIZED' : 'read-only') + '): ' + (ROE.reversible_writes ? 'a create-then-delete in your OWN org/tenant is NOT destructive. If a finding can only be proven by a write (connector base_url SSRF, mass-assignment), do the minimal write + clean up and log both in experiments.md. Prohibitions: ' + JSON.stringify(ROE.prohibitions || []) : 'no state changes — read-only.'),
  '- SEVERITY (' + SEVERITY_RUBRIC + '): score C/I/A on the confirmed ROOT CAUSE per formats/transilience-report-style/pentest-report.md §7.1. A transient/reversible data-state (empty table, deleted records, IMDSv2, toggled-off feature) is NOT a mitigating factor and NOT a severity ceiling; record the demonstration boundary as confidence, not as a C/I/A reduction.',
  '- BLOCKED-ON-CREDS IS FORBIDDEN until the wall is proven a true credential gap, not a self-imposed method restriction. If a class is reachable with the creds in hand (incl. an unauthenticated probe or a reversible own-org write), it is NOT blocked — test it.',
].join('\n') : ''

const DISCIPLINE = [
  'STANDING PRINCIPLES (skills/coordination/reference/principles.md):',
  '- SOURCE CODE FIRST: read every accessible source/config/script/share before acting. Most answers are already in the data.',
  '- DEPTH OVER BREADTH: pursue one promising thread fully before scattering.',
  '- NO BRUTE FORCE: no password/credential spraying, no wordlist fuzzing as a primitive. Reason about logic flaws instead.',
  '- CLI TOOLS FIRST: impacket CLI (secretsdump.py/getST.py/getTGT.py/ticketer.py), smbclient, bloodyAD, certipy, nmap, curl before bespoke Python; read a library\'s source before scripting against it.',
  '- DIAGNOSE BEFORE RETRY: read the error, check perms/prereqs/config; never retry a cosmetic variant.',
  '- ON ANY CVE-YYYY-NNNNN: run `python3 tools/nvd-lookup.py <CVE-ID>` and fold the result into evidence.',
  '- AUTONOMOUS: never call AskUserQuestion. Missing credential -> run `python3 tools/env-reader.py <VARS>`; if NOT_SET, report blocked, do not ask.',
  '- ALL output stays under OUTPUT_DIR. Bullets, not prose, in internal files.',
].join('\n') + COVERAGE_DISCIPLINE

// ============================================================================
// PHASE: Bootstrap (P1) — init dir, deep recon in parallel, seed state files
// ============================================================================
phase('Bootstrap')

// Deterministically establish OUTPUT_DIR FIRST so the parallel recon agents all
// write to one concrete path (avoids a create-the-dir race across 4 agents).
if (!OUTPUT_DIR) {
  // The active-engagement pointer written below is best-effort for standalone runs:
  // concurrent standalone coordinator-loops may clobber the single global
  // .claude/state/active-engagement; the activity-logger's filesystem-anchor is the
  // robust primary resolver.
  const init = await agent(
    `${DISCIPLINE}\n\nROLE: engagement init. cwd is repo root. Create the engagement directory and return its absolute path. Do NOT recon yet.\n` +
    `TARGET: ${TARGET}\nPLATFORM: ${PLATFORM}\n\n` +
    `Compute a tag: lowercase kebab of the target name/host (or "target-<sanitised>" for an IP/id). date=$(date +%y%m%d). OUTPUT_DIR = ${OUTPUT_BASE}/<date>_<tag>/ (do NOT clobber an existing non-empty dir — append -2 etc. if needed).\n` +
    `Run: mkdir -p OUTPUT_DIR/{recon,findings,logs/activity,artifacts,tools,reports}; write OUTPUT_DIR/stats.json = "{}" ; write OUTPUT_DIR/start_time.txt = $(date -u +%Y-%m-%dT%H:%M:%SZ). ALSO record the active-engagement pointer: \`mkdir -p .claude/state\` (repo-root relative) then write .claude/state/active-engagement = the ABSOLUTE OUTPUT_DIR (compute via \`"$(cd OUTPUT_DIR && pwd)"\`). Then capture the primary runner's egress IP and register it: \`PRIMARY_IP=$(curl -s --max-time 5 ifconfig.me || curl -s --max-time 5 https://api.ipify.org || echo unavailable)\` then run \`python3 tools/register_source_ip.py "$PRIMARY_IP" --role primary-runner --engagement "<absolute OUTPUT_DIR>"\` (best-effort).\n` +
    `Return JSON {"output_dir":"<absolute path>"}.`,
    { schema: { type: 'object', additionalProperties: true, required: ['output_dir'], properties: { output_dir: { type: 'string' } } }, label: 'init', phase: 'Bootstrap', agentType: 'general-purpose' }
  )
  if (!init || !init.output_dir) { log('Init failed to create OUTPUT_DIR'); return { status: 'BLOCKED', phase: 'Bootstrap', reason: 'could not create OUTPUT_DIR' } }
  OUTPUT_DIR = init.output_dir
  log(`OUTPUT_DIR=${OUTPUT_DIR}`)
}
// Normalize: strip trailing slash so every `${OUTPUT_DIR}/x` join is clean (whether from args or init).
OUTPUT_DIR = OUTPUT_DIR.replace(/\/+$/, '')

const RECON_ANGLES = [
  { key: 'ports', what: 'Full TCP port scan (all 65535, not top-1k) + service/version detection; UDP top-100 if relevant. Write recon/nmap-*.txt.' },
  { key: 'web', what: 'Map every HTTP/S surface: endpoints, params, forms, admin panels, JS chunks, headers, tech fingerprint, vhost/DNS enumeration, robots/sitemap. Write recon/web-*.md.' },
  { key: 'source', what: 'Locate and READ all accessible source: app code, configs, scripts, share contents, downloadable binaries (strings/decompile), provided files. Write recon/source/ dumps + recon/source-map.md.' },
  { key: 'context', what: 'Platform/lab metadata, starter creds, tags, difficulty, OS; tech-stack identification; known-CVE surface for fingerprinted versions. Write recon/context.md.' },
]

// Coverage mode WITHOUT a pre-supplied matrix = a standalone run that owns its own
// surface expansion. When the pentest-engagement orchestrator already ran an Expand
// phase it passes coverage_matrix, so we skip this angle to avoid double work.
if (MODE === 'coverage' && !COVERAGE_MATRIX) {
  RECON_ANGLES.push({
    key: 'surface-expansion',
    what: 'MANDATORY (coverage): CT-log / passive-DNS / origin-discovery across every in-scope apex — crt.sh, certspotter, urlscan, hackertarget, subfinder/amass; CDN/WAF-fronted -> explicit origin-discovery pass (direct cloud endpoints, archive.org CDX, historical A records). Mount skills/reconnaissance/reference/scenarios/subdomain-enumeration.md + reconnaissance-principles.md. Write recon/inventory/subdomains.json. Scope = discovered surface, not the handoff; record any unavailable tool-class as a limitation, never skip silently.',
  })
}

const reconResults = await parallel(RECON_ANGLES.map(angle => () =>
  agent(
    `${DISCIPLINE}\n\nROLE: explore-executor (recon angle: ${angle.key}). You observe and record; you do NOT claim findings.\n` +
    `TARGET: ${TARGET}\nPLATFORM: ${PLATFORM}\nSCOPE: ${SCOPE}\nGOAL of the engagement: ${GOAL}\n` +
    `OUTPUT_DIR: ${OUTPUT_DIR}\n\n` +
    `Read skills/coordination/reference/executor-role.md for the recon contract, and skills/reconnaissance/SKILL.md routing if HTTP is present.\n\n` +
    `TASK: ${angle.what}\n\n` +
    `Write all output under OUTPUT_DIR/recon/ and log significant tools to OUTPUT_DIR/tools/NNN_<tool>.md. Return a terse bullet summary of what you found (services/surface/source files) as your final text — this feeds the state-file synthesis.`,
    { label: `recon:${angle.key}`, phase: 'Bootstrap', agentType: 'general-purpose' }
  )
))

const reconDigest = reconResults.filter(Boolean).map((r, i) => `### ${RECON_ANGLES[i].key}\n${r}`).join('\n\n')

const bootstrap = await agent(
  `${DISCIPLINE}\n\nROLE: coordinator bootstrap (P1 synthesis). You seed the three engagement state files from recon. Read skills/coordination/reference/bookkeeping.md (for the verbatim attack-chain.md skeleton + experiments.md header) and skills/coordination/reference/preflight-checklist.md.\n\n` +
  `TARGET: ${TARGET}\nPLATFORM: ${PLATFORM}\nSCOPE: ${SCOPE}\nGOAL: ${GOAL}\nSKILLS_HINT: ${SKILLS_HINT || '<none>'}\n` +
  `OUTPUT_DIR: ${OUTPUT_DIR}\n\n` +
  `RECON DIGEST:\n${reconDigest}\n\n` +
  `Do:\n` +
  `1. Confirm/create the OUTPUT_DIR tree {recon,findings,logs,artifacts,tools,reports} and ensure stats.json exists ("{}" is fine so the stats hook accrues).\n` +
  `2. Run the preflight-checklist Phase-1 gate. If a recon angle was skipped (e.g. ports not fully scanned, source unread), the next experiment is to fill it — note it; do NOT proceed as if complete.\n` +
  `3. Write OUTPUT_DIR/attack-chain.md using the verbatim skeleton from bookkeeping.md (Services / Surface / Theory / Tested / Next, <=50 lines).\n` +
  `4. Write OUTPUT_DIR/experiments.md using the verbatim header from bookkeeping.md (first column = E-NNN id; include the Goal and Goal_attempts columns; the stats hook only counts rows whose first cell starts "E-" and a row is a failure when a cell equals "fail").\n` +
  `5. Write OUTPUT_DIR/session-memory.md — the DURABLE session memory (append-only across the whole run). Sections, each a bullet list:\n` +
  `   ## Access & Credentials  (footholds, creds, tokens, shells we hold)\n` +
  `   ## Confirmed Facts        (verified truths about the target)\n` +
  `   ## Dead Ends              (what definitively does NOT work + WHY — so we never re-try it)\n` +
  `   ## Open Threads           (promising leads not yet pursued)\n` +
  `   ## Pivot History          (goals attempted, resets, why)\n` +
  `   ## Creative Leads         (wildcard ideas, research findings, intuitions worth trying)\n` +
  `   Seed it from recon (known facts, surface, any starter creds).\n` +
  (MODE === 'coverage'
    ? `6. COVERAGE (deterministic): (a) ENUMERATE the discovered asset surface into OUTPUT_DIR/recon/inventory/surface.json — schema surface/v2: {"schema":"surface/v2","asset_tag":<the OUTPUT_DIR basename>,"apex":<apex or "">,"units":[{"unit_id":"u-0001","type":"page|endpoint|param|form|origin|host|port|service","address":<url or host:port>,"methods":[...],"flags":[<ONLY agent-set coverage flags that the observation warrants: object_by_id,json_body,role_verb_gated,sensitive_flow,server_fetched_url,input_sink,workflow,deser_or_ci,inbound_webhook,id_keyed_unauth,stored_field,auth_surface,consumes_upstream,static_js_or_repo>],"evidence_ref":["E-NNN"],"equiv_group":<null OR a short group id shared ONLY by cells with the SAME route template / handler / param family (e.g. one id for /users/{id} across ids) — assign CONSERVATIVELY; when unsure, null>}]}. RESUME-AWARE: if OUTPUT_DIR/recon/inventory/surface.json AND OUTPUT_DIR/coverage.json BOTH already exist (a resume run), PRESERVE both verbatim — do NOT re-enumerate or overwrite — and skip straight to (c); if exactly one of the two exists, generate the missing one from the present one WITHOUT discarding the present file. (b) write OUTPUT_DIR/coverage.json = one row per class_id {class_id, applicability, status, units_tested:[]}. The catalog is skills/coordination/reference/coverage-matrix.json (machine) / .md (human); code (tools/enumerate_cells.py + tools/coverage_gate.py) computes applicability and the work-list from your surface.json — you supply the FACTS, code enforces coverage. (c) DETERMINISTIC MECHANICAL COVERAGE (E1 tools-not-agents): run \`python3 tools/passive_web_probe.py --asset-dir OUTPUT_DIR --allow <the in-scope host(s) from surface.json>\` — one non-destructive pass that clears the mechanical attack-classes (TLS posture, security headers, HTTPS downgrade/HSTS, verbose errors, CORS, vulnerable components, secret-exposure, inventory) as tool-corroborated covered_negative cells and READ-MERGES OUTPUT_DIR/coverage.json (it never clobbers). Then the reasoning loop only chases the harder classes. Matrix hint:\n${COVERAGE_MATRIX ? JSON.stringify(COVERAGE_MATRIX) : 'READ skills/coordination/reference/coverage-matrix.json and instantiate its full class list.'}\n`
    : ``) +
  `\nReturn BOOTSTRAP_SCHEMA: ok, output_dir (absolute), exp_count (0), services[], surface[], source_read[], initial_goal (the first concrete goal to pursue toward "${GOAL}"), blocked_reason (null unless an environmental wall like a privileged-port bind or pool mismatch makes the engagement impossible)${MODE === 'coverage' ? ', coverage_seeded (true once coverage.json is written), applicable_class_count (count of applicable rows)' : ''}.`,
  { schema: BOOTSTRAP_SCHEMA, label: 'bootstrap-synth', phase: 'Bootstrap', agentType: 'general-purpose' }
)

if (!bootstrap || !bootstrap.ok || bootstrap.blocked_reason) {
  const reason = bootstrap ? (bootstrap.blocked_reason || 'bootstrap not ok') : 'no bootstrap result'
  log(`Bootstrap blocked: ${reason}`)
  return { status: 'BLOCKED', phase: 'Bootstrap', reason }
}
OUTPUT_DIR = (bootstrap.output_dir || OUTPUT_DIR).replace(/\/+$/, '')
log(`Bootstrap complete. OUTPUT_DIR=${OUTPUT_DIR}. ${MODE === 'coverage' ? `Convergence loop: run to full coverage + ${DRY_TAIL}-batch dry tail, per-asset agent-slice backstopped (ceiling ${ABSOLUTE_MAX_BATCHES} batches).` : `Loop budget: ${MAX_EXPERIMENTS} experiments / ${MAX_BATCHES} batches.`}`)

// ============================================================================
// Prompt builders for the loop
// ============================================================================
function thinkPrompt(batch, resetMode, resetGoal, skepticBriefs) {
  return `${DISCIPLINE}\n\nROLE: coordinator THINK (P2${resetMode ? ' + P4b RESET' : ''}). cwd is repo root. You reason between batches; executors do not.\n` +
    `OUTPUT_DIR: ${OUTPUT_DIR}\nGOAL: ${GOAL}\nBATCH: ${batch}\nPLATFORM: ${PLATFORM}\n\n` +
    `READ FIRST (this is your state): OUTPUT_DIR/attack-chain.md, OUTPUT_DIR/experiments.md (the full ledger), OUTPUT_DIR/session-memory.md` +
    `${skepticBriefs.length ? ', and the latest skeptic brief(s): ' + skepticBriefs.join(', ') + ' — treat their counter-hypotheses as candidates for your wildcard slot' : ''}.\n` +
    `Also skim skills/INDEX.md and skills/coordination/reference/ATTACK_INDEX.md to map the surface to candidate techniques.\n\n` +
    (MODE === 'coverage'
      ? `COVERAGE (deterministic backlog): FIRST run \`python3 tools/enumerate_cells.py --asset-dir OUTPUT_DIR\` then \`python3 tools/coverage_gate.py --asset-dir OUTPUT_DIR --emit-open\`. The OPEN lines are the EXACT remaining (attack-class @ scope_key) cells the gate computed from OUTPUT_DIR/recon/inventory/surface.json — this is your completion obligation, computed by code, NOT a memory task. If surface.json does not exist yet, ENUMERATE the asset surface into it FIRST (schema surface/v2, asset_tag = the OUTPUT_DIR basename, one unit per page/endpoint/param/form/origin with only the agent-set flags each warrants), then re-run the two tools. Rank the OPEN cells by value (impact x likelihood-on-surface x low-credential reachability). AT LEAST ONE mission this batch MUST target the highest-value open cell(s): set covers_cells=[{key,class_id}] AND covers_class=that class_id, and mount the class's scenario file (per coverage-matrix.md/.json). Populate coverage_state.open_cells. EQUIV GROUPING (E2): the OPEN lines carry [equiv:<group>] — cells sharing a (class_id, equiv_group) are equivalent; target ONE representative per group (validate it for real) and the gate credits the siblings, so do NOT spend a separate mission on each sibling. NEVER mark a code-applicable cell NA — the gate treats that as a hard fabrication FAIL; instead find fresh surface or record a corroborated genuine-negative.\n\n`
      : ``) +
    (resetMode
      ? `*** P4b RESET MODE *** The goal "${resetGoal}" has 3+ failed attempts. ABANDON its current theory entirely. Re-read ALL recon + source + session-memory Dead Ends. Do NOT propose cosmetic variants of what already failed. Your 3 hypotheses must open genuinely new directions; at least one must CONTRADICT the prior dominant theory. research_needed MUST be true.\n\n`
      : ``) +
    `Do:\n` +
    `1. Verify the preflight stuck-gate is honestly satisfied before treating any goal as exhausted (every share spidered anon+guest, every readable file inspected for secrets, every username casing/LDAP attribute/history file checked). An unchecked item is the next experiment, not a dead end.\n` +
    `2. Write EXACTLY 3 hypotheses to attack-chain.md "Theory (this batch)", >=1 tagged [wildcard]. The wildcard must be an angle NO mounted skill prescribes — invent it from intuition, an analogy, or a creative recombination of observed facts. Record the 2 non-chosen hypotheses as backlog (they persist).\n` +
    `3. Choose 1-2 to run now. Each chosen mission names: objective, conceptual goal, technique, target, role (explore|exploit), 1-2 specific skill reference/scenario file paths to mount (NEVER a SKILL.md, never the full set), an optional specific PATT_URL, and the expected signal. Mark invented:true for any technique not in the skill library.\n` +
    `4. Set research_needed=true if ANY creative-research trigger applies (skills/coordination/reference/creative-research.md): reset mode, new tech not covered by skills, no clear hypothesis, novel error class, source unreadable, or last batch made zero progress.\n` +
    `5. Set terminate=true ONLY if the goal is environmentally impossible (and explain) — otherwise keep hunting; switching goals is preferred over terminating.${MODE === 'coverage' ? ' COVERAGE: terminate MUST be false while any applicable class in coverage.json is pending — "I exhausted my hypotheses" or "I hit a goal" is NOT completion; pending classes are. Request terminate only when every applicable class is covered or justified-NA.' : ''}\n\n` +
    `Update attack-chain.md (Theory + Next), keep it <=50 lines. Do NOT write experiments.md rows (INTEGRATE owns the ledger). Return THINK_SCHEMA.`
}

function researchPrompt(think) {
  return `${DISCIPLINE}\n\nROLE: coordinator CREATIVE RESEARCH (P2b). Read skills/coordination/reference/creative-research.md and obey its budget: max 3 WebSearch, max 2 WebFetch, < 2 min wall; research must NEVER block execution — if 2 queries return noise, stop and finalize from model knowledge.\n` +
    `OUTPUT_DIR: ${OUTPUT_DIR}\nGOAL: ${GOAL}\n` +
    `WHY RESEARCH FIRED: ${think.research_reason || 'see triggers'}\n` +
    `CHOSEN MISSIONS this batch: ${JSON.stringify((think.chosen || []).map(c => ({ goal: c.goal, technique: c.technique, invented: c.invented })))}\n\n` +
    `Synthesize from three sources: (a) model knowledge — 3-5 candidate hypotheses; (b) skill cross-ref via ATTACK_INDEX.md; (c) the web — technique writeups / advisories / PoCs only (distill {technique, payload, conditions, version-affected}; never pass raw HTML downstream). For any CVE found: run python3 tools/nvd-lookup.py <CVE-ID>.\n` +
    `Be inventive: if the surface is unusual, reason by analogy from adjacent classes and propose a NOVEL approach, not just catalogued ones.\n` +
    `Produce a RESEARCH_BRIEF (<=10 lines), each line tagged [model]/[web]/[skills]/[chain]/[wildcard], with >=1 [wildcard]. Append the searched topics to session-memory.md "Creative Leads" so the next reset does not repeat them. Return RESEARCH_SCHEMA.`
}

function execPrompt(mission, brief, missionId, predictedExpId) {
  return `${DISCIPLINE}\n\nROLE: ${mission.role}-executor. cwd is repo root. Read skills/coordination/reference/executor-role.md for your contract (escalation ladder, reproduce-3x, evidence package).\n` +
    `MISSION_ID: ${missionId}\nEXPERIMENT_ID hint: ${predictedExpId} (the coordinator finalizes ledger rows; you focus on the work + evidence)\n` +
    `OUTPUT_DIR: ${OUTPUT_DIR}\nTARGET: ${mission.target || TARGET}\nPLATFORM: ${PLATFORM}\n` +
    `OBJECTIVE: ${mission.objective}\nGOAL: ${mission.goal}\nTECHNIQUE: ${mission.technique || '(choose appropriately)'}${mission.invented ? ' [INVENTED — no skill prescribes this; execute it carefully and document the method as a candidate new technique]' : ''}\n` +
    `EXPECTED SIGNAL: ${mission.expected_signal || ''}\n\n` +
    `MOUNTED SKILL FILES (read these, 1-2 only): ${JSON.stringify(mission.skill_files || [])}\n` +
    (mission.scenario ? `SCENARIO: ${mission.scenario}\n` : '') +
    (mission.patt_url ? `PATT_URL (fetch only at ladder rung 5): ${mission.patt_url}\n` : '') +
    (brief ? `\nRESEARCH_BRIEF (advisory, not gospel — report contradictions):\n${brief}\n` : '') +
    `\nProcedure: read source first; run the FULL escalation ladder (quickstart payloads -> encoding variants -> filter bypass -> cheat-sheet catalog -> PATT) before reporting failure; on success confirm by REPRODUCING 3x and capture a complete evidence package.\n` +
    (MODE === 'coverage'
      ? `\nCOVERAGE-MODE EXECUTOR RULES:\n- RoE: ${ROE.reversible_writes ? 'a reversible own-org create-then-delete is AUTHORIZED to prove write-dependent findings (SSRF via a stored connector base_url, mass-assignment) — do the minimal write and ALWAYS clean up; log the create + cleanup. Prohibitions: ' + JSON.stringify(ROE.prohibitions || []) : 'read-only; no state changes'}.\n- SEVERITY: score on the confirmed ROOT CAUSE, not the demonstrated sub-impact; a transient/reversible condition (deleted data, IMDSv2, a toggled-off feature) is NOT a severity ceiling — record it as the demonstration boundary (poc_verified + a note), never as a C/I/A reduction (formats/transilience-report-style/pentest-report.md §7.1).\n- SSRF: also mount skills/server-side/reference/scenarios/ssrf/stored-connector-url-ssrf.md and test the stored-URL/connector pattern (create a resource whose stored base_url/webhook the server later fetches -> point at 169.254.170.2 / a collaborator host -> trigger sync).\n`
      : ``) +
    `WRITE (race-free — do NOT touch experiments.md, attack-chain.md, or session-memory.md; the coordinator owns those):\n` +
    `  - On a finding: OUTPUT_DIR/findings/finding-${missionId}/ with description.md, poc.py, poc_output.txt, evidence/ (must include evidence/raw-source.txt).\n` +
    `  - Always: OUTPUT_DIR/logs/mission-${missionId}.md (objective, each technique->result, observations) and significant tools to OUTPUT_DIR/tools/NNN_<tool>.md.\n` +
    `Report negatives in full (what tried / where it broke / what would unblock) and any unexpected finding outside the objective. Return EXEC_SCHEMA (set finding.dir to findings/finding-${missionId}/ when a finding exists; experiments_logged = how many distinct ladder attempts this warrants).`
}

function integratePrompt(batch, execResults, resetMode, verdictSignal = {}) {
  return `${DISCIPLINE}\n\nROLE: coordinator INTEGRATE (P4). You are the SOLE writer of the ledger and the two memory files. Read skills/coordination/reference/bookkeeping.md for the experiments.md row schema + goal_attempts rule.\n` +
    `OUTPUT_DIR: ${OUTPUT_DIR}\nGOAL: ${GOAL}\nBATCH: ${batch}${resetMode ? ' (post-reset batch)' : ''}\n\n` +
    `EXECUTOR RESULTS this batch:\n${JSON.stringify(execResults, null, 2)}\n\n` +
    `Read current OUTPUT_DIR/experiments.md + attack-chain.md + session-memory.md, then:\n` +
    `1. APPEND one experiments.md row per distinct experiment the executors performed (id E-NNN monotonic; columns per bookkeeping.md). Result is one of success/partial/fail (use the literal "fail" so the stats hook + goal_attempts rollup work). For each fail row, increment Goal_attempts for that Goal = prior fails on that Goal + 1. Never rewrite/prune existing rows.\n` +
    `2. REWRITE attack-chain.md (<=50 lines): update Tested (terse one-liners, prune resolved), set Next to the single most promising step, keep the backlog hypotheses.\n` +
    `3. UPDATE session-memory.md (append/merge, never delete): add any new Access & Credentials, Confirmed Facts; record every dead end with WHY under Dead Ends; move pursued Open Threads out, add new ones; log goal pivots/resets under Pivot History.\n` +
    `4. Catalog any new finding dirs into new_findings[].\n` +
    `5. Decide: goal_reached (the engagement GOAL is met, with reproducible proof — be strict, require evidence); progress (did we gain new access/info/finding this batch?); per-goal goal_attempts; recommend_reset (true if the active goal now has goal_attempts>=3); terminate (true only if every avenue is exhausted AND creative research is dry AND session-memory Open Threads is empty — rare).\n` +
    (MODE === 'coverage'
      ? `6. COVERAGE-BY-VALID (deterministic): update OUTPUT_DIR/coverage.json — every class row carries units_tested:[{key,status,e_id,finding_id?,negative_kind?,vantages?,corroborator?}], ONE entry per (scope_key) cell you exercised. A cell is 'covered' ONLY with a VALID/REPAIRED finding in OUTPUT_DIR/artifacts/validated/ whose class_id + unit_refs match that cell. A cell is 'covered_negative' only for a genuinely-clean probe: active_probe negatives need a non-agent corroborator (a tools/NNN_*.md whose 'Experiment: E-NNN' header cites the raw tool output, or a corroborator file path); reachability negatives need >=min_vantages distinct VERIFIED regions from logs/activity/source-ips.jsonl. A cell whose candidate was rejected/dropped STAYS uncovered — NEVER mark it covered on a raw/unvalidated finding, and NEVER mark a code-applicable cell NA. Interleaved verdicts so far: confirmed=${JSON.stringify(verdictSignal.confirmed || [])} rejected=${JSON.stringify(verdictSignal.rejected || [])} dropped=${JSON.stringify(verdictSignal.dropped || [])} (this batch's own new findings validate NEXT batch — do NOT pre-cover them). EQUIVALENCE (E2): for a (class_id x equiv_group) with several sibling unit cells, validate ONE representative (a VALID/REPAIRED finding in artifacts/validated/ with class_id + unit_refs=[the representative's key]); for each sibling in the SAME equiv_group write a units_tested entry {key:<sibling key>,status:'covered',e_id,representative:<the representative's key>} — the gate's covered_equiv branch credits it (bounded: one representative covers at most 8 siblings; a larger group needs additional representatives). Only cells sharing the SAME route template / handler / param family may share a representative. THEN run \`python3 tools/enumerate_cells.py --asset-dir OUTPUT_DIR\` and \`python3 tools/coverage_gate.py --asset-dir OUTPUT_DIR\`; report coverage_update[], coverage_ratio (the gate's), applicable_pending (the gate's missing_cells count), coverage_complete (the gate's "complete" boolean), and open_cells (the gate's missing_cells mapped to [{key:<scope_key>,class_id}] — the CURRENT open set, so the loop can detect a reopened cell). Set goal_reached=true ONLY when coverage_complete is true.\n`
      : ``) +
    `\nReturn INTEGRATE_SCHEMA. exp_count MUST be the authoritative total count of E- rows now in experiments.md.`
}

function skepticPrompt(N) {
  return `${DISCIPLINE}\n\nROLE: SKEPTIC (mandatory checkpoint at experiment ${N}). You are BLIND to the coordinator's theory — this keeps you empirical.\n` +
    `OUTPUT_DIR: ${OUTPUT_DIR}\nGOAL: ${GOAL}\nEXPERIMENT_COUNT: ${N}\n\n` +
    `READ ONLY: OUTPUT_DIR/experiments.md (the full ledger) and a listing + key files of OUTPUT_DIR/recon/. DO NOT read attack-chain.md, session-memory.md, skill files, or any research brief — reading them voids your independence.\n` +
    `Read skills/coordination/reference/skeptic-role.md for the contract. From the ledger alone: infer the dominant theory being pursued, argue against it, surface unstated assumptions and any recon evidence that CONTRADICTS the current direction, and propose EXACTLY 2 counter-hypotheses (>=1 grounded in already-collected evidence; do not propose techniques already tried with goal_attempts>=1).\n` +
    `Write OUTPUT_DIR/skeptic-brief-${N}.md using the verbatim template in skeptic-role.md. <=5 minutes; if no real objection forms, write "no skepticism — current theory looks well-grounded" and exit. Return your brief text.`
}

// ============================================================================
// PHASE: Loop (P2 -> P2b -> P3 -> P4 -> skeptic, repeat)
// ============================================================================
phase('Loop')

let batch = 0
let exp = bootstrap.exp_count || 0
let prevExp = exp
let dryStreak = 0
let resetMode = false
let resetGoal = null
let solved = false
let terminated = false
let terminateReason = ''
// Coverage-mode state (driven by agent-returned counts — the script sandbox has no
// filesystem, so we never read coverage.json from here; INTEGRATE reports the counts).
let coveragePending = MODE === 'coverage' ? Infinity : 0
let prevPending = Infinity
// Convergence-first state (coverage mode): the dry tail accrues once pending hits 0;
// prevOpenCells is the last batch's open-cell SET so a net-zero cover+reopen still
// resets the tail (set-diff, not a bare count); prevConfirmedCount detects new findings.
let coverageDryStreak = 0
let prevOpenCells = null
let prevConfirmedCount = 0
const skepticBriefs = []
const findings = []

// ---- Interleaved per-finding validation (strict) + governor state -------
// Frozen operands (P) + a per-asset agent RESERVE: assessBudget partitions the
// shared 1000-agent lifetime cap across the orchestrator's assets. agentsSpawned
// approximates the real agent cost so backstopDecision can DEFER whole candidates
// (never shrink the quorum — that would make the REJECT threshold run-dependent).
const P = { OUTPUT_DIR, TARGET, BUSINESS_TIER, REPAIR, nvd_cache_dir: NVD_CACHE_DIR, kev_snapshot: KEV_SNAPSHOT }
P.NVD_KEV = nvdKevText(P)
const assetBudget = assessBudget({ assets: Number(a.assets) || 1, reserve: AGENT_RESERVE })
const HARD_RESERVE = assetBudget.hardReserve
// The per-asset agent slice: in coverage mode the loop runs to convergence, backstopped
// by this honest slice (never a cost-style batch budget). perAsset*N + reserve <= 1000.
const perAssetSlice = MODE === 'coverage' ? assetBudget.perAsset : 0
const seenIds = new Set()
const confirmedFindings = []   // VALID/REPAIRED interim JSONs -> the report body
const rejectedFindings = []    // adversarially refuted -> false-positives/ (audit only)
const droppedFindings = []     // uncured DEMOTED -> dropped/ (audit only); drop-entirely
const deferredCandidates = []  // budget-deferred -> validated at full quorum in the end-of-loop sweep
let agentsSpawned = 0           // approx running agent cost this asset (governor input)

// E4 replay-cache: a finding directory whose content is unchanged restores its
// recorded terminal verdict via tools/validation_cache.py — skipping the ~6-agent
// lane. Content-hash keyed by the finding dir; prompt_id namespaces by asset_tag +
// CACHE_VERSION so a lane change (or a different asset) can never replay a stale one.
const RESTORE_INTERIM_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['restored'],
  properties: { restored: { type: 'boolean' }, verdict: { type: ['string', 'null'] }, interim: { type: ['object', 'null'], additionalProperties: true } },
}
const ASSET_TAG = OUTPUT_DIR.split('/').filter(Boolean).pop()
const CACHE_PROMPT_ID = `cov-${ASSET_TAG}-v${CACHE_VERSION}`

// Stamp the current cell's coverage-join fields onto an interim (C3). Idempotent —
// applied after buildInterim (parity-locked) AND after a cache restore. coverage_gate.py
// joins a 'covered' cell to this finding by class_id + (scope_key in unit_refs) + asset_tag.
function stampCoverageJoin(interim, f) {
  interim.class_id = f.covers_class || (f.covers_cells && f.covers_cells[0] && f.covers_cells[0].class_id) || null
  interim.unit_refs = (f.covers_cells || []).map(c => c && c.key).filter(Boolean)
  interim.asset_tag = OUTPUT_DIR.split('/').filter(Boolean).pop()
  return interim
}

// Validate ONE candidate to a terminal verdict, curing the named gaps up to
// MAX_CURE_ROUNDS on FRESH blind agents each round. Fixed DEFAULT_VOTES quorum.
async function validateOneCandidate(f) {
  if (REPLAY_CACHE && f.dir) {
    const cached = await agent(
      `ROLE: CACHE RESTORE (deterministic tool run; no judgment). cwd is repo root. Run EXACTLY:\n` +
      `python3 tools/validation_cache.py restore --finding-dir ${f.dir} --cache-dir ${VALIDATION_CACHE_DIR} --output-dir ${OUTPUT_DIR} --prompt-id ${CACHE_PROMPT_ID}\n` +
      `If it prints restored:true, ALSO read the restored interim JSON it wrote back to disk and return its full object verbatim as \`interim\`. Return {restored, verdict, interim}. On restored:false return {restored:false}.`,
      { schema: RESTORE_INTERIM_SCHEMA, label: `cache-restore:${f.id}`, phase: 'Loop', agentType: 'general-purpose' }
    ).catch(() => ({ restored: false }))
    agentsSpawned += 1
    if (cached && cached.restored && cached.verdict && cached.interim) {
      return { finding_id: f.id, class_id: f.covers_class || null, verdict: cached.verdict, interim: stampCoverageJoin(cached.interim, f) }
    }
  }
  let round = 0
  while (true) {
    const checks = await agent(checksPrompt(f, P), { schema: CHECKS_SCHEMA, label: `checks:${f.id}`, phase: 'Loop', agentType: 'general-purpose' }).catch(() => null)
    agentsSpawned += 1
    let votes = [], probe = { files: [] }, repro = null, cveIds = f.cve_ids || []
    if (checks) {
      cveIds = (checks.cve && checks.cve.applicable) ? [checks.cve.primary_cve || 'CVE'] : (f.cve_ids || [])
      const manifest = EVIDENCE_MANIFEST({ ...f, is_web: checks.is_web, cites_code: checks.cites_code, cve_ids: cveIds })
      const lanes = await Promise.all([
        parallel(Array.from({ length: DEFAULT_VOTES }, (_, i) => () =>
          agent(refuterPrompt(f, i + 1, P), { schema: VOTE_SCHEMA, label: `refute:${f.id}#${i + 1}`, phase: 'Loop', agentType: 'general-purpose' })
        )).then(x => x.filter(Boolean)),
        agent(probePrompt(f, manifest, P), { schema: PROBE_SCHEMA, label: `probe:${f.id}`, phase: 'Loop', agentType: 'general-purpose' }).catch(() => ({ files: [] })),
        agent(reproPrompt(f, checks.poc, P), { schema: REPRO_SCHEMA, label: `repro:${f.id}`, phase: 'Loop', agentType: 'general-purpose' }).catch(() => null),
      ])
      votes = lanes[0]; probe = lanes[1]; repro = lanes[2]
      agentsSpawned += DEFAULT_VOTES + 2
    }
    const finding = { ...f, is_web: checks && checks.is_web, cites_code: checks && checks.cites_code, cve_ids: cveIds }
    if (checks && checks.cve && checks.cve.applicable) {
      checks.cve.reconciled = cveReconcile({ claimed_score: checks.cve.claimed_score, computed_score: checks.cve.computed_score, nvd_score: checks.cve.nvd_score, claimed_vector: checks.cve.claimed_vector, computed_vector: checks.cve.vector }).reconciled
    }
    const verdict = computeVerdict(finding, checks, votes, probe, repro, { votesTotal: DEFAULT_VOTES })
    const interim = buildInterim(finding, checks, verdict, repro, { tier: BUSINESS_TIER, platform: PLATFORM, votes: DEFAULT_VOTES })
    // C3 (coverage-join): stamp onto the interim AFTER buildInterim (parity-locked).
    stampCoverageJoin(interim, f)
    const decision = cureLoopDecision(round, verdict.verdict, MAX_CURE_ROUNDS)
    if (decision === 'CURE') {
      await agent(curePrompt(f, verdict.failed_checks, verdict.missing_evidence, P), { label: `cure:${f.id}#${round + 1}`, phase: 'Loop', agentType: 'general-purpose' }).catch(() => null)
      agentsSpawned += 1
      round += 1
      continue
    }
    return { finding_id: f.id, class_id: f.covers_class || null, verdict: verdict.verdict, interim }
  }
}

// Persist a batch's terminal verdicts with ONE writer agent (sandbox has no FS).
async function persistBatch(results) {
  const writePlan = []
  for (const r of results) {
    if (!r) continue
    const sub = terminalSubdir(r.verdict)
    if (sub === 'validated') confirmedFindings.push(r.interim)
    else if (r.verdict === 'REJECTED') rejectedFindings.push(r.interim)
    else droppedFindings.push(r.interim)
    const content = JSON.stringify(r.interim, null, 2)
    writePlan.push({ path: `${OUTPUT_DIR}/artifacts/${sub}/${r.finding_id}.json`, content })
    writePlan.push({ path: `${OUTPUT_DIR}/${sub}/${r.finding_id}.json`, content })
  }
  if (!writePlan.length) return
  await agent(
    `ROLE: VALIDATION WRITER (persist verbatim, no judgment). cwd is repo root. Ensure ${OUTPUT_DIR}/{artifacts/validated,artifacts/false-positives,artifacts/dropped,validated,false-positives,dropped} exist, then write each file with EXACTLY the given bytes (do not reformat, re-key, or add fields):\n${writePlan.map((w, i) => `--- FILE ${i + 1}: ${w.path} ---\n${w.content}`).join('\n')}\nReturn {written:${writePlan.length}}.`,
    { label: 'validate-writer', phase: 'Loop', agentType: 'general-purpose' }
  ).catch(() => null)
  agentsSpawned += 1
  // E4 replay-cache STORE: record each terminal verdict content-hash-keyed so a
  // later resume run restores it instead of re-running the lane. Populated on every
  // run with a cache dir (restore is the resume-only side); prompt_id namespaces by asset.
  if (VALIDATION_CACHE_DIR) {
    const storeCmds = results.filter(Boolean).map(r =>
      `python3 tools/validation_cache.py store --cache-dir ${VALIDATION_CACHE_DIR} --interim-file ${OUTPUT_DIR}/artifacts/${terminalSubdir(r.verdict)}/${r.finding_id}.json --root ${OUTPUT_DIR} --prompt-id ${CACHE_PROMPT_ID}`)
    await agent(
      `ROLE: CACHE STORE (deterministic tool runs; no judgment). cwd is repo root. Run EACH command; a failure on one is non-fatal (continue):\n${storeCmds.join('\n')}\nReturn {stored:${storeCmds.length}}.`,
      { label: 'cache-store', phase: 'Loop', agentType: 'general-purpose' }
    ).catch(() => null)
    agentsSpawned += 1
  }
}

// Validate a batch's NEW candidates strictly per-finding, before the next batch.
// Dedup engagement-wide; cap fan-out; DEFER (full quorum) under budget pressure.
async function validateBatch(candidates) {
  const fresh = []
  for (const c of (candidates || [])) {
    if (!c || !c.id || seenIds.has(c.id)) continue
    seenIds.add(c.id)
    fresh.push(c)
  }
  const nowList = []
  for (const c of fresh) {
    if (nowList.length < MAX_VALIDATE_PER_BATCH && backstopDecision(agentsSpawned, HARD_RESERVE) === 'run_now') nowList.push(c)
    else deferredCandidates.push(c)
  }
  const deferredN = fresh.length - nowList.length
  if (deferredN > 0) log(`governor: deferring ${deferredN} candidate(s) to the end-of-loop sweep (agentsSpawned=${agentsSpawned}, reserve=${HARD_RESERVE}, cap/batch=${MAX_VALIDATE_PER_BATCH}) — full quorum, never dropped unvalidated.`)
  if (!nowList.length) return
  const results = await Promise.all(nowList.map(c => validateOneCandidate(c)))
  await persistBatch(results)
}

// COVERAGE mode: run to convergence (all cells covered + a DRY_TAIL of empty batches),
// backstopped by the honest per-asset agent slice + an absolute runaway ceiling — NOT a
// cost-style experiment budget. FLAG mode keeps the original budget-bounded loop.
while (MODE === 'coverage'
  ? (agentsSpawned < perAssetSlice && batch < ABSOLUTE_MAX_BATCHES)
  : (exp < MAX_EXPERIMENTS && batch < MAX_BATCHES)) {
  batch++

  // --- P2: Think (+ P4b reset folded in) ---
  const think = await agent(thinkPrompt(batch, resetMode, resetGoal, skepticBriefs.slice(-2)), {
    schema: THINK_SCHEMA, label: `think:b${batch}`, phase: 'Loop', agentType: 'general-purpose',
  })
  if (!think) { terminated = true; terminateReason = 'think agent returned null'; break }
  if (think.terminate) {
    // Coverage mode: a premature terminate is overridden until convergence — every cell
    // covered AND the dry tail satisfied. "I ran out of hypotheses / hit a goal" is not it.
    if (MODE === 'coverage' && !convergenceDone({ coveragePending, coverageDryStreak, dryTail: DRY_TAIL })) {
      log(`coverage: ignoring premature think.terminate — ${coveragePending === Infinity ? 'classes still' : coveragePending} pending, dry ${coverageDryStreak}/${DRY_TAIL}`)
      think.terminate = false
    } else {
      terminated = true; terminateReason = think.terminate_reason || 'think requested terminate'; break
    }
  }

  const missions = (think.chosen || []).slice(0, 2)
  if (!missions.length) {
    // Coverage tail: once every cell is covered, a batch that surfaces no fresh mission
    // is a genuine dry batch — advance the tail toward convergence instead of aborting.
    if (MODE === 'coverage' && coveragePending === 0 &&
        !convergenceDone({ coveragePending, coverageDryStreak, dryTail: DRY_TAIL })) {
      agentsSpawned += 1 // this batch's think agent (accounted against the slice)
      coverageDryStreak = nextDryStreak(coverageDryStreak, { coveragePending: 0, newConfirmed: false, reopened: false })
      log(`coverage tail: dry batch (no fresh mission) -> streak ${coverageDryStreak}/${DRY_TAIL}`)
      if (convergenceDone({ coveragePending: 0, coverageDryStreak, dryTail: DRY_TAIL })) { solved = true; break }
      continue
    }
    terminated = true; terminateReason = 'think produced no missions'; break
  }

  // --- P2b: Creative research (conditional) ---
  let brief = null
  if (think.research_needed || resetMode) {
    const research = await agent(researchPrompt(think), {
      schema: RESEARCH_SCHEMA, label: `research:b${batch}`, phase: 'Loop', agentType: 'general-purpose',
    })
    brief = research ? research.brief : null
  }

  // --- P3: Execute 1-2 executors in parallel ---
  const execResults = (await parallel(missions.map((m, i) => () =>
    agent(execPrompt(m, brief, `b${batch}m${i + 1}`, `E-${exp + i + 1}`), {
      schema: EXEC_SCHEMA, label: `exec:b${batch}m${i + 1}`, phase: 'Loop', agentType: 'general-purpose',
    })
  ))).filter(Boolean)

  // --- P4: Integrate — write ledger + memory, decide next state ---
  const verdictSignal = { confirmed: confirmedFindings.map(x => x.finding_id), rejected: rejectedFindings.map(x => x.finding_id), dropped: droppedFindings.map(x => x.finding_id) }
  const integ = await agent(integratePrompt(batch, execResults, resetMode, verdictSignal), {
    schema: INTEGRATE_SCHEMA, label: `integrate:b${batch}`, phase: 'Loop', agentType: 'general-purpose',
  })
  resetMode = false
  if (!integ) { terminated = true; terminateReason = 'integrate returned null'; break }

  prevExp = exp
  exp = integ.exp_count > exp ? integ.exp_count : exp + 1 // never stall the counter
  agentsSpawned += 6 // approx this batch's search cost (think+research+exec+integrate+skeptic)
  // STRICT PER-FINDING INTERLEAVE: validate each new candidate to a terminal
  // verdict NOW, before the next batch. Flag mode / inline_validate:false keeps
  // the raw-accumulate path (htb-solve; downstream validates).
  if (INLINE_VALIDATE) await validateBatch(integ.new_findings || [])
  else for (const f of (integ.new_findings || [])) if (f && f.id) findings.push(f)

  // Coverage bookkeeping — the deterministic coverage_gate.py (run by the INTEGRATE
  // agent over OUTPUT_DIR) is authoritative: coverage_complete:true forces pending 0,
  // else applicable_pending is the gate's missing_cells count. The sandbox has no FS,
  // so the agent relays the gate's facts (it cannot fabricate them — the gate joins to
  // real on-disk evidence and its output is deterministic).
  let coverageAdvanced = false
  if (MODE === 'coverage') {
    const pend = integ.coverage_complete === true ? 0
      : (typeof integ.applicable_pending === 'number' ? integ.applicable_pending : prevPending)
    // set-diff reopen: a cell open now that was NOT open last batch means coverage
    // regressed — reset the dry tail even if the net pending count is unchanged.
    const openSet = new Set((Array.isArray(integ.open_cells) ? integ.open_cells : [])
      .map(c => c && `${c.class_id}@${c.key}`).filter(Boolean))
    const reopened = prevOpenCells != null && [...openSet].some(k => !prevOpenCells.has(k))
    const newConfirmed = confirmedFindings.length > prevConfirmedCount
    coverageDryStreak = nextDryStreak(coverageDryStreak, { coveragePending: pend, newConfirmed, reopened })
    coverageAdvanced = pend < prevPending
    prevPending = pend
    coveragePending = pend
    prevOpenCells = openSet
    prevConfirmedCount = confirmedFindings.length
  }

  log(`batch ${batch}: experiments=${exp} progress=${integ.progress}${MODE === 'coverage' ? ` pending=${coveragePending} dry=${coverageDryStreak}/${DRY_TAIL}` : ''} ${integ.goal_reached ? 'GOAL_REACHED' : ''}${integ.recommend_reset ? ' (reset queued)' : ''}`)

  // Completion: flag mode -> goal_reached; coverage mode -> convergence (every cell
  // covered/negated AND the dry tail held). goal_reached alone does NOT satisfy it.
  const done = MODE === 'coverage'
    ? convergenceDone({ coveragePending, coverageDryStreak, dryTail: DRY_TAIL })
    : integ.goal_reached
  if (done) { solved = true; break }
  if (integ.terminate) {
    if (MODE === 'coverage' && !convergenceDone({ coveragePending, coverageDryStreak, dryTail: DRY_TAIL })) {
      log(`coverage: ignoring integrate terminate — ${coveragePending} cell(s) pending, dry ${coverageDryStreak}/${DRY_TAIL}`)
    } else {
      terminated = true; terminateReason = integ.terminate_reason || 'integrate requested terminate'; break
    }
  }

  // P4b: queue a reset for next batch if a goal is stuck
  if (integ.recommend_reset) { resetMode = true; resetGoal = integ.stuck_goal || integ.active_goal || GOAL }

  // dry-streak backstop. In coverage mode, advancing coverage (covering/NA-ing a class)
  // counts as progress, so the streak only grows when coverage genuinely stalls; a larger
  // tolerance lets it keep probing other pending classes before giving up to budget.
  dryStreak = (integ.progress || coverageAdvanced) ? 0 : dryStreak + 1
  const effDryLimit = MODE === 'coverage' ? DRY_LIMIT * 2 : DRY_LIMIT
  if (dryStreak >= effDryLimit) { terminated = true; terminateReason = `no progress for ${effDryLimit} consecutive batches`; break }

  // --- Skeptic checkpoint (blind) at 5/15/25, then every 25 ---
  const N = skepticDue(prevExp, exp)
  if (N) {
    await agent(skepticPrompt(N), { label: `skeptic:E${N}`, phase: 'Loop', agentType: 'general-purpose' })
    skepticBriefs.push(`${OUTPUT_DIR}/skeptic-brief-${N}.md`)
  }
}

// Coverage mode: the loop is bounded by the honest per-asset agent slice (not a cost
// budget). Slice-exhausted-with-cells-still-open is RESUMABLE — the remaining cells
// carry over to a resume run; a stuck-but-slice-remaining exit is genuine INCOMPLETE.
const sliceExhausted = MODE === 'coverage' && !solved && agentsSpawned >= perAssetSlice && coveragePending !== 0
if (!solved && !terminated && MODE === 'coverage' && sliceExhausted) terminateReason = `agent slice (${perAssetSlice}) exhausted — ${coveragePending} cell(s) resumable`
if (!solved && !terminated && MODE === 'coverage' && batch >= ABSOLUTE_MAX_BATCHES) terminateReason = `absolute batch ceiling (${ABSOLUTE_MAX_BATCHES}) reached`
if (!solved && !terminated && MODE !== 'coverage' && batch >= MAX_BATCHES) terminateReason = `batch cap (${MAX_BATCHES}) reached — agent-spawn backstop`
if (!solved && !terminated && MODE !== 'coverage' && exp >= MAX_EXPERIMENTS) terminateReason = `experiment budget (${MAX_EXPERIMENTS}) exhausted`
log(`Loop ended after ${batch} batches / ${exp} experiments. solved=${solved}. ${terminateReason}`)

// ============================================================================
// PHASE: Validate (P5) — blind finding-validators + engagement-validator
// ============================================================================
phase('Validate')

// de-dup raw findings (flag mode / inline_validate:false only — inline mode
// tracks candidates via seenIds and confirms via confirmedFindings).
const uniqFindings = []
const seen = new Set()
for (const f of findings) { if (f && f.id && !seen.has(f.id)) { seen.add(f.id); uniqFindings.push(f) } }

if (INLINE_VALIDATE) {
  // End-of-loop sweep: any budget-deferred candidates are validated NOW at the
  // FULL quorum (never dropped unvalidated) and persisted.
  if (deferredCandidates.length) {
    log(`Deferred sweep: validating ${deferredCandidates.length} budget-deferred candidate(s) at full quorum.`)
    const swept = await Promise.all(deferredCandidates.map(c => validateOneCandidate(c)))
    await persistBatch(swept)
  }
  log(`Interleaved validation: ${confirmedFindings.length} confirmed, ${rejectedFindings.length} rejected, ${droppedFindings.length} dropped of ${seenIds.size} candidate(s).`)
} else {
  log(`Inline validation off (flag/inline_validate:false) — ${uniqFindings.length} finding(s) pending downstream validation.`)
}

let engagement = null
if (INLINE_VALIDATE && (confirmedFindings.length || seenIds.size || MODE === 'coverage')) {
  engagement = await agent(
    `ROLE: ENGAGEMENT VALIDATOR (blind, thoroughness audit). Read ONLY skills/coordination/reference/VALIDATION.md and skills/coordination/reference/validator-role.md (Engagement Validator checks); judge from the OUTPUT_DIR directory state — NOT from attack-chain.md or finding internals.\n` +
    `OUTPUT_DIR: ${OUTPUT_DIR}\n\n` +
    (MODE === 'coverage'
      ? `Run the 8 thoroughness checks. Checks 1-7: port coverage vs experiments.md; share enumeration anon+guest (NA for pure web); source-code coverage; >=1 tested [wildcard] hypothesis; mandatory skeptic-brief-{5,15,25...} exist for the counts reached; time-to-first-finding <= 0.3*duration; zero AskUserQuestion calls. CHECK 8 attack-class coverage (DETERMINISTIC — hard 100% gate, no longer a 0.80 soft bar): run \`python3 tools/coverage_gate.py --asset-dir OUTPUT_DIR\` and read OUTPUT_DIR/reports/coverage-matrix.json; set coverage_ratio = its "coverage_ratio" and FAIL (engagement_status=GAPS_FOUND) UNLESS its "complete" is true (ratio==1.0 with NO missing/extra/dangling/false_NA/surface_undercount cells), listing the missing_cells (class_id @ scope_key) in remediation. EQUIV SAMPLING (E2 guard): sample up to K_SAMPLE=3 cells credited via mode=="covered_equiv" in reports/coverage-matrix.json (the covered_equiv list); for EACH, verify the credited sibling genuinely shares its representative's route template / handler / param family (cross-check OUTPUT_DIR/recon/inventory/surface.json). If ANY sampled sibling does not, set engagement_status=GAPS_FOUND and list the mis-grouped siblings in remediation (they re-open next run). Set coverage_ratio in the return.`
      : `Run the 7 thoroughness checks (port coverage vs experiments.md; share enumeration anon+guest; source-code coverage; >=1 tested [wildcard] hypothesis; mandatory skeptic-brief-{5,15,25...} exist for the counts reached; time-to-first-finding <= 0.3*duration; zero AskUserQuestion calls).`) +
    ` Write artifacts/engagement-validation.json + artifacts/engagement-validation-summary.md. Return ENGAGEMENT_SCHEMA.`,
    { schema: ENGAGEMENT_SCHEMA, label: 'validate:engagement', phase: 'Validate', agentType: 'general-purpose' }
  )
}

const confirmed = confirmedFindings   // interim JSONs (finding_id/verdict/report_fields/...)

// ============================================================================
// PHASE: Report
// ============================================================================
phase('Report')

// Interleaved mode confirms in-loop; flag mode gauges by the raw count (the
// orchestrator/downstream validates those).
const hasFindings = INLINE_VALIDATE ? confirmed.length : uniqFindings.length
const coverageGapFail = MODE === 'coverage' && engagement && engagement.engagement_status === 'GAPS_FOUND'
// Tri-state per-asset coverage status. RESUMABLE (slice spent, cells still open) is
// carried forward to a resume run; INCOMPLETE_COVERAGE is a genuine gap/stuck asset.
const status = MODE === 'coverage'
  ? ((solved && !coverageGapFail) ? 'COVERAGE_COMPLETE' : (sliceExhausted ? 'INCOMPLETE_RESUMABLE' : 'INCOMPLETE_COVERAGE'))
  : (solved ? 'SUCCESS' : (hasFindings ? 'FAILED_partial' : (terminateReason.includes('budget') || terminateReason.includes('cap') ? 'EXHAUSTED' : 'BLOCKED')))

// Report format: transilience (per-asset source + JSON; the orchestrator renders the
// engagement PDF) vs the default HTB completion report.
const reportFmtInstr = REPORT_FORMAT === 'transilience'
  ? `Write OUTPUT_DIR/reports/pentest-report-source.md + OUTPUT_DIR/artifacts/pentest-report.json for THIS asset per formats/transilience-report-style/pentest-report.md (Finding Quality Standard; severity per §7.1 root-cause floor — a transient/reversible state is never a severity ceiling). Summarize the coverage.json status (covered / NA / pending per class). Do NOT render a PDF — the engagement orchestrator aggregates all assets into the final Transilience PDF.`
  : `Write OUTPUT_DIR/reports/completion-report.md per formats/htb-completion-report.md (all 8 sections; Attack Chain is a 3-8 sentence narrative; every vuln carries a CVSS; Lessons Learned + Failed Approaches from session-memory.md Dead Ends).`

const report = await agent(
  `${DISCIPLINE}\n\nROLE: coordinator REPORT (P6). cwd is repo root.\n` +
  `OUTPUT_DIR: ${OUTPUT_DIR}\nGOAL: ${GOAL}\nMODE: ${MODE}\nSTATUS: ${status}\nsolved=${solved}; experiments=${exp}; batches=${batch}; end_reason="${terminateReason}"${MODE === 'coverage' ? `; applicable_pending=${coveragePending}; coverage_ratio=${engagement && typeof engagement.coverage_ratio === 'number' ? engagement.coverage_ratio : 'n/a'}` : ''}\n` +
  (INLINE_VALIDATE
    ? `Validated findings (interleaved, drop-entirely): ${JSON.stringify(confirmed.map(c => c.finding_id))}\nEngagement thoroughness: ${engagement ? engagement.engagement_status : 'n/a (no findings)'}\n\n${reportFmtInstr} Use ONLY validated (VALID/REPAIRED) findings in the body; rejected/uncured ones live ONLY in artifacts/false-positives/ and artifacts/dropped/ (never the report).`
    : `Findings (PENDING authoritative validation — the orchestrator runs validate-findings): ${JSON.stringify(uniqFindings.map(f => f.id))}\n\n${reportFmtInstr} Mark each finding "pending validation"; do NOT assert a finding is confirmed (validate-findings decides that).`) +
  ` Ensure stats.json reflects experiment/finding/agent counts + duration.\n` +
  `Return REPORT_SCHEMA: status, report_path, narrative (3-6 sentences of how it was/ would be solved), stats.`,
  { schema: REPORT_SCHEMA, label: 'report', phase: 'Report', agentType: 'general-purpose' }
)

return {
  status,
  solved,
  mode: MODE,
  output_dir: OUTPUT_DIR,
  experiments: exp,
  batches: batch,
  end_reason: terminateReason || (solved ? (MODE === 'coverage' ? 'coverage complete' : 'goal reached') : ''),
  validation_delegated: !INLINE_VALIDATE,
  verdict_counts: summarizeLoopCounts(confirmedFindings, rejectedFindings, droppedFindings),
  confirmed: confirmedFindings.length,
  dropped: droppedFindings.length,
  rejected: rejectedFindings.length,
  findings_confirmed: INLINE_VALIDATE ? confirmed.map(c => ({ id: c.finding_id, summary: (c.report_fields && c.report_fields.title) || '' })) : uniqFindings.map(f => ({ id: f.id, summary: 'pending validation' })),
  findings_total: INLINE_VALIDATE ? seenIds.size : uniqFindings.length,
  engagement_status: engagement ? engagement.engagement_status : null,
  coverage_status: MODE === 'coverage' ? status : null,
  coverage_pending: MODE === 'coverage' ? coveragePending : null,
  resumable: MODE === 'coverage' ? sliceExhausted : false,
  open_cells_remaining: MODE === 'coverage' ? coveragePending : null,
  coverage_ratio: engagement && typeof engagement.coverage_ratio === 'number' ? engagement.coverage_ratio : null,
  report_path: report ? report.report_path : `${OUTPUT_DIR}/reports/${REPORT_FORMAT === 'transilience' ? 'pentest-report-source.md' : 'completion-report.md'}`,
  narrative: report ? report.narrative : '',
}
