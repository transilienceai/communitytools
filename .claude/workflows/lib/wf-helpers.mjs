// wf-helpers.mjs — pure, deterministic helpers for the pentest-engagement redesign.
//
// WHY THIS FILE EXISTS
//   The Workflow sandbox runs plain JS with NO `import`/`require`, no filesystem,
//   and no Date.now/Math.random. So the two workflow scripts (pentest-engagement.js,
//   validate-findings.js) embed *copies* of these functions inline. This module is
//   the single tested source of truth; helpers.test.mjs exercises it, and a static
//   parity check asserts the inline copies match (see the test file).
//
//   Every function here is PURE: same inputs -> same output, no I/O, no clock, no
//   randomness. That is what makes the guarantees deterministic — all the deciding,
//   counting, math and gating lives here, not in an LLM prompt.

// ---------------------------------------------------------------------------
// Severity vocabulary (the report_data schema enum — note: no "None"; 0 => Info)
// ---------------------------------------------------------------------------
export const SEVERITY = ['Critical', 'High', 'Medium', 'Low', 'Info']; // high -> low

export function severityBand(score) {
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
export const TIER_WEIGHTS = { crown_jewel: 1.0, revenue: 0.7, support: 0.4, dev: 0.2, unknown: 0.3 };
export const RISK_THRESHOLDS = { immediate: 0.6, short_term: 0.3, medium_term: 0.1 };

export function round4(x) { return Math.round((x + Number.EPSILON) * 1e4) / 1e4; }

export function riskBucket(score) {
  if (score >= RISK_THRESHOLDS.immediate) return 'immediate';
  if (score >= RISK_THRESHOLDS.short_term) return 'short_term';
  if (score >= RISK_THRESHOLDS.medium_term) return 'medium_term';
  return 'monitor';
}

export function riskScore({ cvss, tier, exposure, feasibility } = {}) {
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
export function exposureFor(asset) {
  if (asset && (asset.exposure === 1.0 || asset.exposure === 0.5)) return asset.exposure;
  if (asset && typeof asset.external === 'boolean') return asset.external ? 1.0 : 0.5;
  return (asset && asset.platform === 'network') ? 0.5 : 1.0;
}

// ---------------------------------------------------------------------------
// CVE reconcile — the CVSS score itself comes from the verified tool-runner
// (tools/cvss_calc.py -> NVD; CVSS v4.0 is primary, falling back v3.1 -> v3.0
// -> v2.0). JS only decides whether the numbers agree.
// Rule: computed (from vector) must exist and agree with NVD and the claim
// within |Δ| <= 0.1, and vectors must match when both present.
// ---------------------------------------------------------------------------
export function normVector(v) {
  if (!v) return '';
  // Strip the version prefix of any supported version so v4.0/v3.x/v2.0 vectors
  // normalize consistently for comparison.
  return String(v).replace(/^CVSS:(?:4\.0|3\.[01]|2\.0)\//i, '').split('/').filter(Boolean).sort().join('/').toUpperCase();
}

export function cveReconcile({ claimed_score, computed_score, nvd_score, claimed_vector, computed_vector } = {}) {
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
export function EVIDENCE_MANIFEST(finding) {
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
export function evidenceComplete(finding, probe) {
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
export function computeVerdict(finding, checks, votes, probe, repro, opts = {}) {
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
export function finalPoc(checks, repro) {
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
export const DEFAULT_VOTES = 3;          // adversarial refuter quorum (was 2)
export const AGENT_CAP = 1000;           // the runtime's per-run agent lifetime cap
export const GLOBAL_RESERVE = 40;        // reserve for correlate + report + slack

// The per-candidate cure/verdict outcome. round is 0-based; a DEMOTED finding is
// cured up to maxCureRounds times before it is DROPPED (drop-entirely). VALID or
// REPAIRED -> CONFIRMED; adversarially REJECTED -> terminal. Use `<` so cap=0
// drops immediately (a caller's strict no-cure single pass).
export function cureLoopDecision(round, verdict, maxCureRounds) {
  if (verdict === 'VALID' || verdict === 'REPAIRED') return 'CONFIRMED';
  if (verdict === 'REJECTED') return 'REJECTED';
  if (Number(round) < Number(maxCureRounds)) return 'CURE';
  return 'DROPPED';
}

// Which artifacts/<subdir> a terminal verdict is persisted to. VALID/REPAIRED ->
// the report body; REJECTED -> false-positives (audit only); everything else
// (DEMOTED / unknown) -> dropped (audit only, never the report).
export function terminalSubdir(verdict) {
  if (verdict === 'VALID' || verdict === 'REPAIRED') return 'validated';
  if (verdict === 'REJECTED') return 'false-positives';
  return 'dropped';
}

// Coverage-by-VALID: a class is covered only when it has a VALID/REPAIRED finding
// OR a genuine negative (thoroughly tested clean). A class whose only candidates
// were REJECTED/DROPPED stays pending, so the loop keeps searching.
export function coverageDecision(findingVerdicts, negativeResult) {
  const vs = findingVerdicts || [];
  if (vs.some((v) => v === 'VALID' || v === 'REPAIRED')) return 'covered';
  if (negativeResult === 'genuine_negative') return 'covered';
  return 'pending';
}

// Inline validation fires when explicitly enabled; else defaults ON for coverage
// mode (preserves the old RUN_VALIDATION default-true for standalone coverage
// runs) and OFF for flag mode (htb-solve is untouched).
export function shouldInlineValidate(mode, inlineValidate) {
  if (inlineValidate === true) return true;
  if (inlineValidate === false) return false;
  return mode === 'coverage';
}

// Fixed-quorum + deferral governor: validate in-loop at the FULL quorum while the
// asset is below its hard reserve; once it reaches the reserve, DEFER whole
// candidates to the reserved end-of-loop sweep (still full quorum). Never shrink
// the quorum — that would make the REJECT threshold run-dependent.
export function backstopDecision(agentsSpawned, hardReserve) {
  return Number(agentsSpawned) >= Number(hardReserve) ? 'defer' : 'run_now';
}

// Partition the shared 1000-agent lifetime budget across N assets so the worst-
// case total stays under the runtime cap (invariant: perAsset*A + reserve <= cap).
// `reserve` overrides GLOBAL_RESERVE (e.g. the network deep-dive folds in the
// pre-deep-dive sweep spend); omitted -> GLOBAL_RESERVE.
export function assessBudget({ assets, reserve } = {}) {
  const A = Math.max(1, Math.floor(Number(assets) || 1));
  const R = Number.isFinite(Number(reserve)) ? Math.max(0, Math.floor(Number(reserve))) : GLOBAL_RESERVE;
  const perAsset = Math.floor((AGENT_CAP - R) / A);
  const hardReserve = Math.max(0, Math.floor(perAsset * 0.85));
  return { assets: A, perAsset, hardReserve, agentCap: AGENT_CAP, globalReserve: R };
}

// Convergence-first completion (coverage mode): done only when every applicable
// (surface-unit x attack-class) cell is covered/negated (coveragePending===0) AND
// the dry tail has held for `dryTail` consecutive batches. "all techniques + more".
export function convergenceDone({ coveragePending, coverageDryStreak, dryTail } = {}) {
  const K = Math.max(1, Math.floor(Number(dryTail) || 2));
  return Number(coveragePending) === 0 && Math.floor(Number(coverageDryStreak) || 0) >= K;
}

// The dry-tail streak transition. The tail only accrues once coverage is complete
// (pending 0); ANY new confirmed finding OR a reopened cell resets it to 0 so the
// "plus more" tail keeps probing until the surface is genuinely quiet.
export function nextDryStreak(prevStreak, { coveragePending, newConfirmed, reopened } = {}) {
  if (Number(coveragePending) !== 0) return 0;
  if (newConfirmed || reopened) return 0;
  return Math.max(0, Math.floor(Number(prevStreak) || 0)) + 1;
}

// How many INCOMPLETE assets to fully converge THIS run so each gets a real agent
// slice and the worst-case total stays under the runtime cap; the rest defer to a
// resume run. Always runs >=1 when any work remains (else the engagement stalls).
export function resumeSchedule({ incompleteCount, agentCap, deepSlice, overhead } = {}) {
  const cap = Math.max(0, Math.floor(Number(agentCap) || 0) - Math.max(0, Math.floor(Number(overhead) || 0)));
  const slice = Math.max(1, Math.floor(Number(deepSlice) || 1));
  const capacity = Math.floor(cap / slice);
  const inc = Math.max(0, Math.floor(Number(incompleteCount) || 0));
  const assetsThisRun = inc === 0 ? 0 : Math.max(1, Math.min(inc, capacity));
  return { assetsThisRun, deferred: inc - assetsThisRun };
}

// Tri-state engagement status from the per-asset rows + the deferred (not-run-this-
// run) tags. A genuinely-stuck asset (INCOMPLETE_COVERAGE / degraded) blocks COMPLETE
// and is surfaced for a human; resumable + deferred assets (and stuck ones, retried
// each run) populate the resume list that drives the next run.
export function classifyEngagement(assetRows, deferredTags) {
  const rows = Array.isArray(assetRows) ? assetRows : [];
  const stuck = rows.filter((r) => r && (r.coverage_status === 'INCOMPLETE_COVERAGE' || r.degraded)).map((r) => r.tag);
  const resumable = rows.filter((r) => r && r.coverage_status === 'INCOMPLETE_RESUMABLE').map((r) => r.tag);
  const remaining = [...new Set([...resumable, ...stuck, ...(Array.isArray(deferredTags) ? deferredTags : [])])];
  const engagement_status = stuck.length ? 'INCOMPLETE_coverage' : (remaining.length ? 'INCOMPLETE_resumable' : 'COMPLETE');
  const resume = remaining.length
    ? { remaining_assets: remaining, deferred_reason: stuck.length ? 'mixed: stuck + deferred' : 'agent-slice / per-run budget', rerun_hint: 'resume_dir=<engagement_dir>' }
    : { remaining_assets: [], deferred_reason: null, rerun_hint: null };
  return { engagement_status, resume };
}

// Fold a batch's terminal candidate results into accumulators + a per-class
// coverage signal. Each result: { verdict, class_id? }.
export function reduceCandidateVerdicts(results) {
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
export function summarizeLoopCounts(confirmed, rejected, dropped) {
  const n = (x) => (Array.isArray(x) ? x.length : (Number(x) || 0));
  const c = n(confirmed), r = n(rejected), d = n(dropped);
  return { confirmed: c, rejected: r, dropped: d, total: c + r + d };
}

// ---------------------------------------------------------------------------
// NETWORK / VANTAGE HELPERS (source-IP/geo-allowlist auto-probe).
// ---------------------------------------------------------------------------
// Source-IP / geo-allowlist SIGNATURE from the per-slice scan results. The
// discriminator (and the cost bound) is the workers' `filtered[]` set: hosts
// with a POSITIVE existence proof (host-up-but-all-filtered / tcp-rst / prior-
// known-live) yet NO reachable service from this vantage. Genuinely-down hosts
// stay in `dead_count` and never fire the signature, so a clean run (live +
// down) never triggers a second-geography probe / cloud spend.
export function detectAllowlist(sliceResults) {
  const slices = Array.isArray(sliceResults) ? sliceResults : [];
  const liveCount = slices.reduce((n, s) => n + ((s && Array.isArray(s.live)) ? s.live.length : 0), 0);
  const filteredHosts = [];
  const seen = new Set();
  for (const s of slices) {
    for (const f of ((s && Array.isArray(s.filtered)) ? s.filtered : [])) {
      if (f && f.ip && !seen.has(f.ip)) { seen.add(f.ip); filteredHosts.push({ ip: f.ip, signal: f.signal || 'host-up-but-all-filtered' }); }
    }
  }
  return { signature: liveCount >= 1 && filteredHosts.length >= 1, filteredHosts };
}

// Resolve the ≤2 second-vantage gcp ZONES to probe from. An explicit
// geoVantages override is honored verbatim (dedup + cap 2). Otherwise the
// default US+EU pair is used, minus the zone on the SAME continent as the
// primary vantage (avoids a redundant same-geography probe). primaryGeo is a
// best-effort ISO country code; unknown -> keep both defaults.
export function resolveGeoZones({ geoVantages, primaryGeo } = {}) {
  const DEFAULTS = ['us-central1-a', 'europe-west1-b'];
  const dedupCap = (zs) => { const o = []; for (const z of zs) { if (!o.includes(z)) o.push(z); if (o.length === 2) break; } return o; };
  const override = (Array.isArray(geoVantages) ? geoVantages : []).map((s) => (s == null ? '' : String(s).trim())).filter(Boolean);
  if (override.length) return dedupCap(override);
  const primary = String(primaryGeo || '').toUpperCase();
  const US = ['US', 'CA', 'MX'];
  const EU = ['DE', 'NL', 'ES', 'FR', 'IT', 'GB', 'UK', 'IE', 'BE', 'CH', 'AT', 'SE', 'NO', 'FI', 'DK', 'PL', 'PT', 'CZ', 'RO', 'HU', 'GR'];
  const cont = US.includes(primary) ? 'us' : (EU.includes(primary) ? 'eu' : null);
  const regionOf = (z) => (z.startsWith('us-') || z.startsWith('northamerica-')) ? 'us' : (z.startsWith('europe-') ? 'eu' : 'other');
  const kept = cont ? DEFAULTS.filter((z) => regionOf(z) !== cont) : DEFAULTS.slice();
  return dedupCap(kept.length ? kept : DEFAULTS);
}

// Deterministic replay-cache key (C3): a pure, filename-safe composite of a
// promptId + an evidence content-hash. The hash itself is computed by the
// tool-mediated tools/validation_cache.py (JS has no crypto/FS); JS only
// composes the key so the format is single-sourced + testable. The Python tool
// mirrors this exactly (sanitize non-[A-Za-z0-9_.-] to '_', join with '-').
export function cacheKey(promptId, evidenceHash) {
  const safe = (s) => String(s == null ? '' : s).replace(/[^A-Za-z0-9_.-]/g, '_');
  return `${safe(promptId)}-${safe(evidenceHash)}`;
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
export function nvdKevText(P = {}) {
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

export const CHECKS_SCHEMA = {
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
};

export const VOTE_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['refuted'],
  properties: {
    refuted: { type: 'boolean' },
    reason: { type: 'string' },
    weakest_link: { type: 'string', description: 'the single most doubtful claim/step' },
  },
};

export const PROBE_SCHEMA = {
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

export const REPRO_SCHEMA = {
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

export function checksPrompt(f, P = {}) {
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

export function refuterPrompt(f, i, P = {}) {
  return `ROLE: ADVERSARIAL VALIDATOR #${i} (blind). Your job is to REFUTE finding ${f.id}. You see ONLY its evidence package — NOT any validator's verdict, NOT attack-chain/session-memory, NOT other findings. Default to skepticism: if a claim is not independently supported, it is refuted.\n\n` +
    `Read ${f.dir}/description.md, ${f.dir}/poc.py, ${f.dir}/poc_output.txt, ${f.dir}/evidence/ (including evidence/validation/poc-rerun-output.txt, cve-verification.md, verification-script.py). For a CVE, independently sanity-check against the SAME frozen operands the validator used: ${(P.NVD_KEV || nvdKevText(P))[1]} Does the claimed CVSS vector actually yield the claimed score? does NVD agree? For the exploit: does the captured output actually PROVE the vulnerability, or is the "evidence" incidental/ambiguous/self-asserted? Could the output be produced on a non-vulnerable target? Are the factual claims present in raw scan output?\n\n` +
    `COMMON FALSE-HIGH CALIBRATION — apply \`skills/coordination/reference/severity-calibration.md\`. REFUTE (impact not demonstrated/reachable as claimed) and name the unmet precondition as weakest_link if the finding is any of: CORS reflected-origin scored as token-theft WITHOUT \`Access-Control-Allow-Credentials: true\` + ambient-cookie-auth'd sensitive data; Azure \`AADSTS50126\` (failed auth) read as "MFA disabled" (Entra checks credentials BEFORE MFA — a failed login never reaches the MFA prompt); an ENABLER (spray-capability / Golden-SAML or cert template / writable ACL / SSRF reachability) scored as a DEMONSTRATED compromise it never actually performed; a scanner/vulners version-only "Critical" on a backported-distro or appliance-bundled package (version banner ≠ patch level); or a verified CVE scored at base WITHOUT confirming the vulnerable feature is enabled and reachable (e.g. IKEv1 CVE on an IKEv2-only gateway, an inbound-HRS CVE on an outbound-only client).\n\n` +
    `Return VOTE_SCHEMA: refuted (true if you found a real reason to doubt the finding, the score, or the CVE), reason, and weakest_link (the single most doubtful element).`;
}

export function probePrompt(f, manifest, P = {}) {
  return `ROLE: EVIDENCE PROBE (one job, no judgment). cwd is repo root. For EACH path below, run \`test -f\`/\`wc -c\` (for a \`*.png\` glob, count matching files and report the largest as one entry with its byte size; exists=true iff at least one non-empty match). Report ONLY the real on-disk facts — do not create, repair, or judge anything.\n\n` +
    `FINDING: ${f.id}\nPATHS:\n${manifest.map((m) => `  - ${m.path} (${m.type})`).join('\n')}\n\n` +
    `Return PROBE_SCHEMA: files:[{path, exists, bytes}] with one entry per path above (use the exact path string given).`;
}

export function reproPrompt(f, poc, P = {}) {
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
export function curePrompt(f, failedChecks, missingEvidence, P = {}) {
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
export function buildInterim(f, checks, verdict, repro, opts = {}) {
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

// ---------------------------------------------------------------------------
// Assess reconciliation — completeness by BACKFILL, never throw. WEB keyed by
// tag, NET by ip (caller passes keyOf). normalizeAssess guards the return shape
// of one coordinator-loop/validate result (wraps the .catch object too).
// ---------------------------------------------------------------------------
export function normalizeAssess(v, asset) {
  const lo = v || {};
  const degraded = !!(lo.blocked_reason || lo.status === 'FAILED' || lo.coverage_status === 'FAILED');
  return {
    tag: asset.tag,
    key: asset.key,
    output_dir: asset.output_dir || lo.output_dir || null,
    type: asset.type || null,
    business_tier: asset.business_tier || null,
    coverage_status: lo.coverage_status || lo.status || 'UNKNOWN',
    coverage_ratio: typeof lo.coverage_ratio === 'number' ? lo.coverage_ratio : null,
    findings_total: lo.findings_total != null ? lo.findings_total : (Array.isArray(lo.findings_confirmed) ? lo.findings_confirmed.length : 0),
    validation: lo.validation || null,
    degraded,
    blocked_reason: lo.blocked_reason || (degraded ? 'assessment degraded' : null),
  };
}

export function reconcileAssessed(expected, assessed, keyOf) {
  const seen = new Set(assessed.map((a) => a.key));
  const backfilled = expected
    .filter((e) => !seen.has(keyOf(e)))
    .map((e) => ({
      tag: e.tag, key: keyOf(e), output_dir: e.output_dir || null, type: e.type || null,
      business_tier: e.business_tier || null, coverage_status: 'MISSING', coverage_ratio: null,
      findings_total: 0, validation: null, degraded: true, blocked_reason: 'no result returned',
    }));
  const all = assessed.concat(backfilled);
  const gaps = all.filter((a) => a.degraded || a.coverage_status !== 'COVERAGE_COMPLETE');
  return { all, backfilled, gaps, complete: gaps.length === 0 };
}

// finalizeGate — the deterministic COMPLETE/BLOCKED decision over the finalize
// runner's reported facts. A deliverable ships only when the report assembled, the
// branded PDF rendered, AND the code-computed attack-class coverage is 100%
// (coverage_complete). Fails closed: a missing/false coverage_complete blocks.
export function finalizeGate({ report_data_ok, report_data_lint_ok, renderGateOk, coverage_complete, coverage_untested, renderBlockedReason }) {
  const ok = !!(report_data_ok && report_data_lint_ok && renderGateOk && coverage_complete);
  const blocked_reason = ok ? null
    : !report_data_ok ? 'report_data_build failed'
    : !report_data_lint_ok ? 'report_data lint failed (schema/escaping)'
    : !renderGateOk ? (renderBlockedReason || 'render failed')
    : `attack-class coverage < 100% (${coverage_untested} cell(s) untested)`;
  return { ok, status: ok ? 'COMPLETE' : 'BLOCKED', blocked_reason };
}

// ---------------------------------------------------------------------------
// Engagement metadata + version resolution (req 10). Prompt > prior > default.
// Prior SCOPE is metadata-only: we compute a display-only diff, never a work list.
// ---------------------------------------------------------------------------
export function bumpVersion(priorVersion) {
  if (!priorVersion) return 'v1.0';
  const m = String(priorVersion).match(/v?(\d+)(?:\.(\d+))?/i);
  if (!m) return 'v1.0';
  return `v${Number(m[1]) + 1}.0`;
}

export function scopeDiff(priorScope, currentScope) {
  const P = new Set((priorScope || []).map(String));
  const C = new Set((currentScope || []).map(String));
  const added = [...C].filter((x) => !P.has(x)).sort();
  const removed = [...P].filter((x) => !C.has(x)).sort();
  const unchanged = [...C].filter((x) => P.has(x)).sort();
  return { added, removed, unchanged, changed: added.length > 0 || removed.length > 0 };
}

export function resolveEngagementMeta({ prior, prompt, currentScope, dateTag, explicitVersion } = {}) {
  const p = prior || {}, pr = prompt || {};
  const pick = (k) => (pr[k] != null && pr[k] !== '' ? pr[k] : p[k]) || null;
  const meta = {};
  for (const k of ['title', 'title_lines', 'subtitle', 'sector', 'target', 'classification', 'method', 'prepared_by', 'duration']) meta[k] = pick(k);
  meta.version = explicitVersion || bumpVersion(p.version || ((p.report_id || '').match(/v\d+(\.\d+)?/i) || [])[0]);
  meta.supersedes = p.report_id || p.version || null;
  // Fresh report_id — never reuse the prior's. Deterministic from dateTag + version.
  const base = (meta.title || meta.sector || 'ENGAGEMENT').replace(/[^A-Za-z0-9]+/g, '-').slice(0, 24).toUpperCase().replace(/-+$/,'');
  meta.report_id = pr.report_id || `${base}-${dateTag || '000000'}-${meta.version}`;
  meta.scope_changes = scopeDiff(p.scope, currentScope);
  return meta;
}

// ---------------------------------------------------------------------------
// Secret scan / redaction — run over the fields that actually RENDER into the
// PDF, before assembly. Returns redacted text + the hit types found.
// ---------------------------------------------------------------------------
export const SECRET_PATTERNS = [
  { name: 'aws_akia', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'private_key', re: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/g },
  { name: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { name: 'bearer', re: /\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*\b/gi },
  { name: 'pan_india', re: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g },
];

function luhnValid(digits) {
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum % 10 === 0;
}

export function redactSecrets(text) {
  if (text == null) return { text, hits: [] };
  let out = String(text);
  const hits = [];
  for (const { name, re } of SECRET_PATTERNS) {
    out = out.replace(re, (m) => { hits.push(name); return '[REDACTED:' + name + ']'; });
  }
  // Payment-card PAN: 13-19 digit runs that pass Luhn.
  out = out.replace(/\b(?:\d[ -]?){13,19}\b/g, (m) => {
    const digits = m.replace(/[ -]/g, '');
    if (digits.length >= 13 && digits.length <= 19 && luhnValid(digits)) { hits.push('card_pan'); return '[REDACTED:card_pan]'; }
    return m;
  });
  return { text: out, hits };
}

// ---------------------------------------------------------------------------
// assertReportData — the pre-render gate. Validates the report_data.json shape
// against the transilience report-data-schema (required keys + per-finding
// id/title/severity-enum) and secret-scans the rendered fields.
// ---------------------------------------------------------------------------
export const RENDERED_FINDING_FIELDS = ['title', 'description', 'impact', 'recommendation', 'calibration'];

export function assertReportData(obj) {
  const errors = [];
  const secretHits = [];
  if (!obj || typeof obj !== 'object') return { ok: false, errors: ['report_data is not an object'], secretHits };
  if (!obj.engagement || typeof obj.engagement !== 'object') errors.push('missing engagement');
  if (!Array.isArray(obj.findings)) {
    errors.push('findings is not an array');
  } else {
    obj.findings.forEach((f, i) => {
      if (!f || typeof f !== 'object') { errors.push(`findings[${i}] not an object`); return; }
      if (!f.id) errors.push(`findings[${i}] missing id`);
      if (!f.title) errors.push(`findings[${i}] missing title`);
      if (!SEVERITY.includes(f.severity)) errors.push(`findings[${i}] (${f.id || '?'}) invalid severity: ${JSON.stringify(f.severity)}`);
      for (const fld of RENDERED_FINDING_FIELDS) {
        if (f[fld]) { const r = redactSecrets(f[fld]); if (r.hits.length) secretHits.push({ id: f.id, field: fld, kinds: r.hits }); }
      }
      // poc[] is an ordered list of steps; scan each step's rendered text fields.
      if (Array.isArray(f.poc)) {
        f.poc.forEach((s, j) => {
          if (!s || typeof s !== 'object') return;
          for (const fld of ['description', 'command']) {
            if (s[fld]) { const r = redactSecrets(s[fld]); if (r.hits.length) secretHits.push({ id: f.id, field: `poc[${j}].${fld}`, kinds: r.hits }); }
          }
        });
      }
    });
  }
  return { ok: errors.length === 0, errors, secretHits };
}
