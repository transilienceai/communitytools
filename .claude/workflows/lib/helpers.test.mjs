// helpers.test.mjs — offline, deterministic unit suite for wf-helpers.mjs.
// Run: node .claude/workflows/lib/helpers.test.mjs
// No test framework (none exists in this repo); a tiny assert harness + process exit code.

import { createHash } from 'node:crypto';
import {
  SEVERITY, severityBand, TIER_WEIGHTS, RISK_THRESHOLDS, riskScore, exposureFor,
  cveReconcile, normVector, EVIDENCE_MANIFEST, evidenceComplete, computeVerdict, finalPoc,
  normalizeAssess, reconcileAssessed, finalizeGate, bumpVersion, scopeDiff, resolveEngagementMeta,
  redactSecrets, assertReportData,
  DEFAULT_VOTES, AGENT_CAP, GLOBAL_RESERVE, buildInterim, cacheKey,
  cureLoopDecision, terminalSubdir, coverageDecision, shouldInlineValidate,
  backstopDecision, assessBudget, reduceCandidateVerdicts, summarizeLoopCounts,
  detectAllowlist, resolveGeoZones,
  convergenceDone, nextDryStreak, resumeSchedule, classifyEngagement,
  scrubCheck, capFor, capBudget, promotionGate, writeGate, violationKey, lintDelta,
  skillUpdateGate, skillAgentBudget, buildChangeReport,
} from './wf-helpers.mjs';

let pass = 0, fail = 0;
const fails = [];
function eq(actual, expected, msg) {
  const a = JSON.stringify(actual), e = JSON.stringify(expected);
  if (a === e) { pass++; } else { fail++; fails.push(`✗ ${msg}\n    expected ${e}\n    got      ${a}`); }
}
function ok(cond, msg) { if (cond) pass++; else { fail++; fails.push(`✗ ${msg}`); } }

// --- severityBand ---------------------------------------------------------
eq(severityBand(9.8), 'Critical', 'severityBand 9.8');
eq(severityBand(9.0), 'Critical', 'severityBand boundary 9.0');
eq(severityBand(7.0), 'High', 'severityBand boundary 7.0');
eq(severityBand(6.9), 'Medium', 'severityBand 6.9');
eq(severityBand(4.0), 'Medium', 'severityBand boundary 4.0');
eq(severityBand(0.1), 'Low', 'severityBand 0.1');
eq(severityBand(0), 'Info', 'severityBand 0 -> Info (never None)');
eq(severityBand(null), 'Info', 'severityBand null -> Info');
ok(!SEVERITY.includes('None'), 'SEVERITY has no None');

// --- riskScore (parity with scoring-formula.md worked examples) -----------
eq(TIER_WEIGHTS, { crown_jewel: 1.0, revenue: 0.7, support: 0.4, dev: 0.2, unknown: 0.3 }, 'tier weights == risk-prioritise.py defaults');
eq(RISK_THRESHOLDS, { immediate: 0.6, short_term: 0.3, medium_term: 0.1 }, 'thresholds == risk-prioritise.py defaults');
{ // Example A: crown-jewel, cvss 9.8, external, confirmed
  const r = riskScore({ cvss: 9.8, tier: 'crown_jewel', exposure: 1.0, feasibility: 1.0 });
  eq(r.risk_score, 0.98, 'riskScore A score 0.98'); eq(r.risk_bucket, 'immediate', 'riskScore A bucket');
}
{ // Example C: support tier RCE, cvss 9.0
  const r = riskScore({ cvss: 9.0, tier: 'support', exposure: 1.0, feasibility: 1.0 });
  eq(r.risk_score, 0.36, 'riskScore C score 0.36'); eq(r.risk_bucket, 'short_term', 'riskScore C bucket');
}
{ // Example B numbers as a standalone finding: cvss 7.5, revenue, feas 0.5
  const r = riskScore({ cvss: 7.5, tier: 'revenue', exposure: 1.0, feasibility: 0.5 });
  eq(r.risk_score, 0.2625, 'riskScore B score 0.2625'); eq(r.risk_bucket, 'medium_term', 'riskScore B bucket');
}
{ // No CVSS -> technical 0.5; unknown tier -> 0.3
  const r = riskScore({ cvss: 0, tier: 'nope', exposure: 0.5, feasibility: 1.0 });
  eq(r.cvss_missing, true, 'riskScore cvss_missing'); eq(r.business_impact, 0.3, 'unknown tier weight 0.3');
  eq(r.risk_score, 0.075, 'riskScore no-cvss internal -> 0.075 monitor'); eq(r.risk_bucket, 'monitor', 'monitor bucket');
}
eq(exposureFor({ platform: 'web' }), 1.0, 'web asset exposure 1.0');
eq(exposureFor({ platform: 'network' }), 0.5, 'network host exposure 0.5');
eq(exposureFor({ external: false }), 0.5, 'explicit external:false -> 0.5');

// --- cveReconcile ---------------------------------------------------------
eq(normVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), normVector('AV:N/AC:L/UI:N/PR:N/S:U/A:H/C:H/I:H'), 'normVector order-insensitive');
ok(cveReconcile({ claimed_score: 9.8, computed_score: 9.8, nvd_score: 9.8, claimed_vector: 'AV:N', computed_vector: 'AV:N' }).reconciled, 'reconcile all-agree');
ok(cveReconcile({ computed_score: 9.8, nvd_score: 9.9 }).reconciled, 'reconcile boundary |Δ|=0.1 (0.9 vs 9.8... )'); // 9.9-9.8=0.1
// IEEE-754 regression: 9.8-9.7 = 0.10000000000000009 > 0.1 without the epsilon,
// which would wrongly demote a valid CVE at the exact one-step rounding gap.
ok(cveReconcile({ computed_score: 9.8, nvd_score: 9.7 }).reconciled, 'reconcile boundary |Δ|=0.1 float-safe (9.8 vs 9.7)');
ok(cveReconcile({ computed_score: 0.8, claimed_score: 0.7 }).reconciled, 'reconcile boundary |Δ|=0.1 float-safe (0.8 vs 0.7)');
ok(!cveReconcile({ computed_score: 9.8, nvd_score: 9.95 }).reconciled, 'reconcile |Δ|=0.15 fails');
ok(!cveReconcile({ computed_score: 7.0, claimed_vector: 'AV:N/AC:L', computed_vector: 'AV:L/AC:H' }).reconciled, 'reconcile vector mismatch fails');
ok(!cveReconcile({ claimed_score: 7.0, nvd_score: 7.0 }).reconciled, 'reconcile with no computed score fails');

// --- evidence manifest + probe -------------------------------------------
{
  const web = { id: 'F1', dir: 'd/finding-F1', is_web: true, cve_ids: [], cites_code: false };
  const man = EVIDENCE_MANIFEST(web).map((m) => m.path);
  ok(man.some((p) => p.endsWith('screenshots/*.png')), 'web finding requires screenshots');
  const raw = { id: 'F2', dir: 'd/finding-F2', is_web: false, cve_ids: [], cites_code: false };
  ok(!EVIDENCE_MANIFEST(raw).some((m) => m.path.includes('screenshots')), 'raw-banner finding does NOT require screenshots');
  // probe present for all mandatory of the raw finding
  const probe = { files: [
    { path: 'd/finding-F2/evidence/validation/validation-summary.md', exists: true, bytes: 20 },
    { path: 'd/finding-F2/evidence/validation/poc-rerun-output.txt', exists: true, bytes: 20 },
    { path: 'd/finding-F2/evidence/validation/verification-script.py', exists: true, bytes: 20 },
  ] };
  eq(evidenceComplete(raw, probe).all_present, true, 'raw finding evidence complete');
  eq(evidenceComplete(web, probe).all_present, false, 'web finding missing screenshots -> incomplete');
}

// --- computeVerdict truth table ------------------------------------------
const goodChecks = {
  canonical: { cvss_consistency: true, evidence_exists: true, poc_validation: true, claims_vs_raw: true, log_corroboration: true },
  cve: { applicable: false }, exploit: { ran: true, proven: true, deterministic: true, signal_token: 'uid=0', repaired: false },
};
const fullProbe = (f) => ({ files: EVIDENCE_MANIFEST(f).map((m) => ({ path: m.path.replace('/*.png', '/shot.png'), exists: true, bytes: 10 })) });
const REPRO = { reproduced: true };  // the blind reproduction agent confirmed the step-by-step
const F = { id: 'F1', dir: 'd/finding-F1', type: 'exploit', is_web: false, cve_ids: [] };
eq(computeVerdict(F, goodChecks, [{ refuted: false }, { refuted: false }], fullProbe(F), REPRO, { votesTotal: 2 }).verdict, 'VALID', 'verdict all-pass + reproduced -> VALID');
eq(computeVerdict(F, { ...goodChecks, exploit: { ...goodChecks.exploit, repaired: true } }, [], fullProbe(F), REPRO, { votesTotal: 0 }).verdict, 'REPAIRED', 'verdict repaired -> REPAIRED');
eq(computeVerdict(F, goodChecks, [{ refuted: true }, { refuted: true }], fullProbe(F), REPRO, { votesTotal: 2 }).verdict, 'REJECTED', 'verdict majority-refuted -> REJECTED');
eq(computeVerdict(F, goodChecks, [{ refuted: true }, { refuted: false }], fullProbe(F), REPRO, { votesTotal: 2 }).verdict, 'VALID', 'verdict 1-of-2 refuted (no majority) -> VALID');
{
  const bad = { ...goodChecks, canonical: { ...goodChecks.canonical, claims_vs_raw: false } };
  const v = computeVerdict(F, bad, [{ refuted: false }], fullProbe(F), REPRO, { votesTotal: 1 });
  eq(v.verdict, 'DEMOTED', 'verdict one canonical false (not refuted) -> DEMOTED');
  ok(v.failed_checks.includes('canonical:claims_vs_raw'), 'DEMOTED lists the failed check');
}
eq(computeVerdict(F, null, [], fullProbe(F), REPRO, { votesTotal: 0 }).verdict, 'DEMOTED', 'verdict checks===null -> DEMOTED (infra error, never REJECTED)');
eq(computeVerdict(F, goodChecks, [], { files: [] }, REPRO, { votesTotal: 0 }).verdict, 'DEMOTED', 'verdict missing evidence -> DEMOTED');
// PoC reproduction gate (new)
eq(computeVerdict(F, goodChecks, [], fullProbe(F), null, { votesTotal: 0 }).verdict, 'DEMOTED', 'verdict no reproduction agent -> DEMOTED');
{
  const v = computeVerdict(F, goodChecks, [], fullProbe(F), { reproduced: false }, { votesTotal: 0 });
  eq(v.verdict, 'DEMOTED', 'verdict PoC not reproduced -> DEMOTED');
  ok(v.failed_checks.includes('poc:not_reproduced'), 'DEMOTED lists poc:not_reproduced');
}
{ // CVE-applicable but unreconciled, not refuted -> DEMOTED
  const cveBad = { ...goodChecks, cve: { applicable: true, reconciled: false } };
  eq(computeVerdict(F, cveBad, [], fullProbe(F), REPRO, { votesTotal: 0 }).verdict, 'DEMOTED', 'verdict CVE-divergence -> DEMOTED');
}
{ // info-type finding needs no exploit proof but still needs a reproduced PoC
  const info = { id: 'I1', dir: 'd/finding-I1', type: 'info', is_web: false, cve_ids: [] };
  const noExploit = { canonical: goodChecks.canonical, cve: { applicable: false }, exploit: {} };
  eq(computeVerdict(info, noExploit, [], fullProbe(info), REPRO, { votesTotal: 0 }).verdict, 'VALID', 'info finding valid without exploit proof (PoC reproduced)');
}
// finalPoc: reproduction agent's corrected list wins when it adjusted steps.
// PoC shape is now an ordered list of {description, command, image_url} steps.
{
  const authored = { poc: [{ description: 'open terminal', command: 'bash' }, { description: 'the disclosed value proves it' }] };
  eq(finalPoc(authored, { reproduced: true }).length, 2, 'finalPoc keeps authored steps when repro did not adjust');
  const adj = finalPoc(authored, { reproduced: true, corrected_steps: [{ description: 'open browser', command: 'open x' }, { description: 'x' }, { description: 'result' }] });
  eq(adj.length, 3, 'finalPoc uses reproduction agent corrected_steps when present');
  eq(finalPoc({}, {}), [], 'finalPoc returns [] when no poc was authored');
}

// --- reconcileAssessed / normalizeAssess ---------------------------------
{
  const expected = [{ tag: 'a', key: 'a', output_dir: 'o/a' }, { tag: 'b', key: 'b', output_dir: 'o/b' }];
  const assessed = [normalizeAssess({ coverage_status: 'COVERAGE_COMPLETE' }, { tag: 'a', key: 'a', output_dir: 'o/a' })];
  const r = reconcileAssessed(expected, assessed, (e) => e.key);
  eq(r.backfilled.length, 1, 'reconcileAssessed backfills the missing asset');
  eq(r.backfilled[0].coverage_status, 'MISSING', 'backfilled placeholder is MISSING');
  eq(r.complete, false, 'reconcileAssessed not complete when a gap exists');
  ok(r.all.length === 2, 'reconcileAssessed keeps every expected asset');
}
eq(normalizeAssess({ status: 'FAILED' }, { tag: 'x', key: 'x' }).degraded, true, 'normalizeAssess flags FAILED as degraded');

// --- engagement meta / version -------------------------------------------
eq(bumpVersion('v1.3'), 'v2.0', 'bumpVersion v1.3 -> v2.0');
eq(bumpVersion(undefined), 'v1.0', 'bumpVersion none -> v1.0');
eq(scopeDiff(['a.com', 'b.com'], ['b.com', 'c.com']), { added: ['c.com'], removed: ['a.com'], unchanged: ['b.com'], changed: true }, 'scopeDiff');
{
  const meta = resolveEngagementMeta({
    prior: { title: 'Old T', sector: 'Bank', report_id: 'ACME-000000-v1.0', version: 'v1.0', scope: ['a.com'] },
    prompt: { title: 'New T' },
    currentScope: ['a.com', 'b.com'], dateTag: '260707',
  });
  eq(meta.title, 'New T', 'meta prompt overrides prior title');
  eq(meta.sector, 'Bank', 'meta prior fills sector gap');
  eq(meta.version, 'v2.0', 'meta version auto-increments');
  eq(meta.supersedes, 'ACME-000000-v1.0', 'meta records supersedes');
  ok(meta.report_id !== 'ACME-000000-v1.0', 'meta mints a FRESH report_id (not the prior)');
  eq(meta.scope_changes.added, ['b.com'], 'meta scope_changes.added (display-only, never a work list)');
}

// --- secret scan / assertReportData --------------------------------------
{
  const r = redactSecrets('key AKIAIOSFODNN7EXAMPLE and header Bearer abcdef0123456789abcdef');
  ok(r.hits.includes('aws_akia'), 'redact AWS AKIA'); ok(r.hits.includes('bearer'), 'redact bearer');
  ok(!r.text.includes('AKIAIOSFODNN7EXAMPLE'), 'AKIA removed from text');
  ok(redactSecrets('PAN ABCDE1234F').hits.includes('pan_india'), 'redact Indian PAN');
  ok(redactSecrets('card 4111111111111111').hits.includes('card_pan'), 'redact Luhn-valid card');
  ok(!redactSecrets('id 1234567890123456').hits.includes('card_pan'), 'non-Luhn 16-digit not flagged as card');
}
{
  const good = { engagement: { title: 'T' }, findings: [{ id: 'F1', title: 'X', severity: 'High' }] };
  eq(assertReportData(good).ok, true, 'assertReportData accepts a valid object');
  eq(assertReportData({ engagement: {}, findings: [{ id: 'F1', title: 'X', severity: 'Sev5' }] }).ok, false, 'assertReportData rejects bad severity enum');
  eq(assertReportData({ engagement: {}, findings: [{ id: 'F1', title: 'X' }] }).ok, false, 'assertReportData rejects missing severity');
  const withSecret = assertReportData({ engagement: {}, findings: [{ id: 'F1', title: 'X', severity: 'Low', poc: [{ description: 'send the request', command: 'curl -H "Authorization: Bearer abcdef0123456789abcd"' }] }] });
  ok(withSecret.secretHits.length > 0, 'assertReportData surfaces secret hits in poc step fields');
}

// --- strict per-finding interleave: decision helpers ---------------------
eq(DEFAULT_VOTES, 3, 'DEFAULT_VOTES is 3 (raised quorum)');
// cureLoopDecision: verdict -> outcome; DEMOTED cures up to cap then drops
eq(cureLoopDecision(0, 'VALID', 1), 'CONFIRMED', 'cure VALID -> CONFIRMED');
eq(cureLoopDecision(0, 'REPAIRED', 1), 'CONFIRMED', 'cure REPAIRED -> CONFIRMED');
eq(cureLoopDecision(0, 'REJECTED', 1), 'REJECTED', 'cure REJECTED -> REJECTED');
eq(cureLoopDecision(0, 'DEMOTED', 1), 'CURE', 'cure DEMOTED round0/cap1 -> CURE');
eq(cureLoopDecision(1, 'DEMOTED', 1), 'DROPPED', 'cure DEMOTED round1/cap1 -> DROPPED (out of rounds)');
eq(cureLoopDecision(0, 'DEMOTED', 0), 'DROPPED', 'cure DEMOTED cap0 -> DROPPED immediately (strict no-cure)');
eq(cureLoopDecision(0, 'DEMOTED', 2), 'CURE', 'cure DEMOTED round0/cap2 -> CURE');
{ // driver: always-DEMOTED terminates in exactly maxCureRounds cures then DROPPED
  for (const cap of [0, 1, 2, 3]) {
    let round = 0, cures = 0, outcome = null;
    while (true) {
      const d = cureLoopDecision(round, 'DEMOTED', cap);
      if (d === 'CURE') { cures++; round++; continue; }
      outcome = d; break;
    }
    eq(cures, cap, `always-DEMOTED does exactly ${cap} cure(s)`);
    eq(outcome, 'DROPPED', `always-DEMOTED terminates DROPPED (cap ${cap})`);
  }
}
// terminalSubdir
eq(terminalSubdir('VALID'), 'validated', 'terminalSubdir VALID');
eq(terminalSubdir('REPAIRED'), 'validated', 'terminalSubdir REPAIRED');
eq(terminalSubdir('REJECTED'), 'false-positives', 'terminalSubdir REJECTED');
eq(terminalSubdir('DEMOTED'), 'dropped', 'terminalSubdir DEMOTED -> dropped (drop-entirely)');
eq(terminalSubdir('WAT'), 'dropped', 'terminalSubdir unknown -> dropped');
// coverageDecision
eq(coverageDecision(['REJECTED', 'DROPPED'], null), 'pending', 'coverage rejected/dropped-only -> pending');
eq(coverageDecision(['VALID'], null), 'covered', 'coverage with VALID -> covered');
eq(coverageDecision(['REPAIRED'], null), 'covered', 'coverage with REPAIRED -> covered');
eq(coverageDecision([], 'genuine_negative'), 'covered', 'coverage genuine negative -> covered');
eq(coverageDecision([], null), 'pending', 'coverage empty -> pending');
// shouldInlineValidate: explicit wins, else default ON for coverage / OFF for flag
eq(shouldInlineValidate('coverage', undefined), true, 'inline default ON for coverage (standalone)');
eq(shouldInlineValidate('flag', undefined), false, 'inline default OFF for flag (htb-solve untouched)');
eq(shouldInlineValidate('coverage', false), false, 'inline explicit false overrides coverage');
eq(shouldInlineValidate('flag', true), true, 'inline explicit true overrides flag (network deep-dive)');
// backstopDecision: fixed-quorum + deferral governor (never shrink quorum)
eq(backstopDecision(0, 100), 'run_now', 'backstop below reserve -> run_now');
eq(backstopDecision(99, 100), 'run_now', 'backstop just below reserve -> run_now');
eq(backstopDecision(100, 100), 'defer', 'backstop at reserve -> defer');
eq(backstopDecision(150, 100), 'defer', 'backstop above reserve -> defer');
// assessBudget: worst-case agent total stays under the 1000-cap (invariant)
for (const A of [1, 2, 5, 10, 20, 50]) {
  const b = assessBudget({ assets: A });
  ok(b.perAsset * A + GLOBAL_RESERVE <= AGENT_CAP, `assessBudget invariant holds for ${A} asset(s) (perAsset*A+reserve<=cap)`);
  ok(b.hardReserve <= b.perAsset, `assessBudget hardReserve <= perAsset for ${A}`);
}
eq(AGENT_CAP, 1000, 'AGENT_CAP is the runtime 1000-agent lifetime cap');
// assessBudget reserve override: a larger reserve shrinks perAsset; invariant holds.
{
  const b = assessBudget({ assets: 4, reserve: 120 });
  eq(b.perAsset, Math.floor((1000 - 120) / 4), 'assessBudget honors an explicit reserve in perAsset');
  eq(b.globalReserve, 120, 'assessBudget returns the effective reserve');
  ok(b.perAsset * 4 + 120 <= AGENT_CAP, 'assessBudget invariant holds with an explicit reserve');
  eq(assessBudget({ assets: 5 }).perAsset, Math.floor(960 / 5), 'assessBudget default reserve = GLOBAL_RESERVE (40)');
}
// convergenceDone: coverage complete (pending 0) AND dry tail held for K batches.
eq(convergenceDone({ coveragePending: 3, coverageDryStreak: 9, dryTail: 2 }), false, 'convergenceDone false while cells pending');
eq(convergenceDone({ coveragePending: 0, coverageDryStreak: 1, dryTail: 2 }), false, 'convergenceDone false: tail not yet K');
eq(convergenceDone({ coveragePending: 0, coverageDryStreak: 2, dryTail: 2 }), true, 'convergenceDone true: pending 0 + tail>=K');
eq(convergenceDone({ coveragePending: 0, coverageDryStreak: 5 }), true, 'convergenceDone default K=2 satisfied');
// nextDryStreak: only accrues at pending 0; new finding / reopen resets it.
eq(nextDryStreak(4, { coveragePending: 2, newConfirmed: false, reopened: false }), 0, 'nextDryStreak resets while pending>0');
eq(nextDryStreak(1, { coveragePending: 0, newConfirmed: false, reopened: false }), 2, 'nextDryStreak +1 on a clean complete batch');
eq(nextDryStreak(3, { coveragePending: 0, newConfirmed: true, reopened: false }), 0, 'nextDryStreak resets on a new confirmed finding');
eq(nextDryStreak(3, { coveragePending: 0, newConfirmed: false, reopened: true }), 0, 'nextDryStreak resets on a reopened cell (set-diff)');
{ // the K=2 tail converges: two clean complete batches after pending hit 0
  let s = 0;
  s = nextDryStreak(s, { coveragePending: 0, newConfirmed: false, reopened: false });
  ok(!convergenceDone({ coveragePending: 0, coverageDryStreak: s, dryTail: 2 }), 'tail batch 1 not yet done');
  s = nextDryStreak(s, { coveragePending: 0, newConfirmed: false, reopened: false });
  ok(convergenceDone({ coveragePending: 0, coverageDryStreak: s, dryTail: 2 }), 'tail batch 2 -> done');
}
// resumeSchedule: fully-converge as many as fit the agent slice; defer the rest.
eq(resumeSchedule({ incompleteCount: 10, agentCap: 1000, deepSlice: 200, overhead: 40 }), { assetsThisRun: 4, deferred: 6 }, 'resumeSchedule 10 assets @200 slice -> 4 this run, 6 deferred');
eq(resumeSchedule({ incompleteCount: 3, agentCap: 1000, deepSlice: 200, overhead: 40 }), { assetsThisRun: 3, deferred: 0 }, 'resumeSchedule fits all when under capacity');
eq(resumeSchedule({ incompleteCount: 0, agentCap: 1000, deepSlice: 200, overhead: 40 }), { assetsThisRun: 0, deferred: 0 }, 'resumeSchedule nothing incomplete -> 0/0');
eq(resumeSchedule({ incompleteCount: 3, agentCap: 1000, deepSlice: 2000, overhead: 40 }), { assetsThisRun: 1, deferred: 2 }, 'resumeSchedule always runs >=1 even when slice exceeds capacity');
{ // partition invariant: this-run + deferred == incomplete, and this-run fits the cap
  for (const inc of [1, 4, 7, 25]) {
    const r = resumeSchedule({ incompleteCount: inc, agentCap: 1000, deepSlice: 200, overhead: 40 });
    eq(r.assetsThisRun + r.deferred, inc, `resumeSchedule partitions all ${inc}`);
    ok(r.assetsThisRun * 200 + 40 <= 1000 || r.assetsThisRun === 1, `resumeSchedule this-run fits the cap (${inc})`);
  }
}
// classifyEngagement: tri-state status + resume list.
eq(classifyEngagement([{ tag: 'a', coverage_status: 'COVERAGE_COMPLETE' }], []), { engagement_status: 'COMPLETE', resume: { remaining_assets: [], deferred_reason: null, rerun_hint: null } }, 'classifyEngagement all-complete -> COMPLETE');
{
  const c = classifyEngagement([{ tag: 'a', coverage_status: 'COVERAGE_COMPLETE' }, { tag: 'b', coverage_status: 'INCOMPLETE_RESUMABLE' }], ['c']);
  eq(c.engagement_status, 'INCOMPLETE_resumable', 'classifyEngagement resumable+deferred, none stuck -> INCOMPLETE_resumable');
  eq(c.resume.remaining_assets, ['b', 'c'], 'classifyEngagement resume list = resumable + deferred');
}
{
  const c = classifyEngagement([{ tag: 'a', coverage_status: 'INCOMPLETE_COVERAGE' }, { tag: 'b', coverage_status: 'COVERAGE_COMPLETE' }], []);
  eq(c.engagement_status, 'INCOMPLETE_coverage', 'classifyEngagement a stuck asset -> INCOMPLETE_coverage (needs human)');
  ok(c.resume.remaining_assets.includes('a'), 'classifyEngagement retries the stuck asset next run');
}
// reduceCandidateVerdicts: fold terminal verdicts; only VALID/REPAIRED confirmed
{
  const red = reduceCandidateVerdicts([
    { verdict: 'VALID', class_id: 'A01' }, { verdict: 'REPAIRED', class_id: 'A02' },
    { verdict: 'REJECTED', class_id: 'A01' }, { verdict: 'DEMOTED', class_id: 'A03' },
    { verdict: 'WAT' }, null,
  ]);
  eq(red.confirmed.length, 2, 'reduce: only VALID+REPAIRED in confirmed');
  eq(red.rejected.length, 1, 'reduce: REJECTED bucket');
  eq(red.dropped.length, 2, 'reduce: DEMOTED + unknown dropped');
  eq(coverageDecision(red.byClass['A01'], null), 'covered', 'reduce: class A01 covered (has VALID despite a REJECTED)');
  eq(coverageDecision(red.byClass['A03'], null), 'pending', 'reduce: class A03 pending (dropped only)');
}
// summarizeLoopCounts
eq(summarizeLoopCounts([1, 2], [3], []), { confirmed: 2, rejected: 1, dropped: 0, total: 3 }, 'summarizeLoopCounts from arrays');
eq(summarizeLoopCounts(2, 1, 4), { confirmed: 2, rejected: 1, dropped: 4, total: 7 }, 'summarizeLoopCounts from numbers');
// cacheKey (C3 replay-cache): pure, stable, filename-safe, deterministic
eq(cacheKey('interim', 'abc123'), 'interim-abc123', 'cacheKey composes promptId-hash');
eq(cacheKey('interim', 'abc123'), cacheKey('interim', 'abc123'), 'cacheKey deterministic (same inputs -> same key)');
ok(cacheKey('interim', 'a/b c:d') !== cacheKey('interim', 'abcd'), 'cacheKey changes when the hash changes');
ok(/^[A-Za-z0-9_.-]+$/.test(cacheKey('int/erim', 'a b:c/d')), 'cacheKey is filename-safe (sanitizes unsafe chars)');
eq(cacheKey('interim', 'a b/c'), 'interim-a_b_c', 'cacheKey golden: unsafe chars -> underscore');

// --- C4 determinism harness: computeVerdict is N×-stable AND == a golden sha256
// (the golden guards against silent drift; N×-stability proves purity). ---------
{
  const F = { id: 'F1', dir: 'd/finding-F1', type: 'exploit', is_web: false, cve_ids: [] };
  const checks = { canonical: { cvss_consistency: true, evidence_exists: true, poc_validation: true, claims_vs_raw: true, log_corroboration: true }, cve: { applicable: false }, exploit: { ran: true, proven: true, deterministic: true, signal_token: 'uid=0', repaired: false } };
  const probe = { files: EVIDENCE_MANIFEST(F).map((m) => ({ path: m.path.replace('/*.png', '/shot.png'), exists: true, bytes: 10 })) };
  const repro = { reproduced: true };
  const votes3 = [{ refuted: false }, { refuted: false }, { refuted: false }];
  const shas = new Set();
  for (let i = 0; i < 5; i++) shas.add(createHash('sha256').update(JSON.stringify(computeVerdict(F, checks, votes3, probe, repro, { votesTotal: 3 }))).digest('hex'));
  eq([...shas], ['a8d837f7ea176c182e0da26d3e5ed2bb267a6170487c72756497baefa7d4c8fc'], 'computeVerdict: 5 runs identical AND == golden sha256 (deterministic)');
}
// buildInterim behavioral golden — tier/platform/votes actually drive risk + exposure + adversarial.
{
  const F = { id: 'F1', dir: 'd/finding-F1', type: 'exploit', is_web: false, cve_ids: [] };
  const vVALID = { verdict: 'VALID', failed_checks: [], refuteCount: 0 };
  const crown = buildInterim(F, { cve: { computed_score: 9.8, vector: 'AV:N', primary_cve: 'CVE-2024-1', cwes: ['CWE-79'] }, report_fields: { title: 'X' } }, vVALID, { reproduced: true }, { tier: 'crown_jewel', platform: 'web', votes: 3 });
  const dev = buildInterim(F, { cve: { computed_score: 9.8 }, report_fields: {} }, { verdict: 'DEMOTED', failed_checks: [], refuteCount: 0 }, { reproduced: true }, { tier: 'dev', platform: 'network', votes: 1 });
  eq({ sev: crown.severity, risk: crown.risk.risk_score, exp: crown.risk.entry_exposure, biz: crown.risk.business_impact, votes: crown.adversarial.votes }, { sev: 'Critical', risk: 0.98, exp: 1, biz: 1, votes: 3 }, 'buildInterim crown_jewel/web/VALID golden');
  eq({ sev: dev.severity, risk: dev.risk.risk_score, exp: dev.risk.entry_exposure, biz: dev.risk.business_impact, votes: dev.adversarial.votes }, { sev: 'Critical', risk: 0.049, exp: 0.5, biz: 0.2, votes: 1 }, 'buildInterim dev/network/DEMOTED golden (tier+exposure+feasibility+votes all differ)');
}

// --- detectAllowlist (source-IP/geo-allowlist signature) ------------------
{ // POSITIVE: a live host + a sibling that is existence-confirmed-but-dark -> signature
  const r = detectAllowlist([
    { live: [{ ip: '192.0.2.10', open_ports: [443] }], dead_count: 3, filtered: [{ ip: '192.0.2.20', signal: 'host-up-but-all-filtered' }] },
  ]);
  eq(r.signature, true, 'detectAllowlist POSITIVE (live + filtered sibling) -> signature true');
  eq(r.filteredHosts, [{ ip: '192.0.2.20', signal: 'host-up-but-all-filtered' }], 'detectAllowlist POSITIVE surfaces the filtered host');
}
{ // NEGATIVE (the clean-run control): live + genuinely-down (no filtered[]) -> no signature, no spend
  const r = detectAllowlist([{ live: [{ ip: '192.0.2.10' }], dead_count: 253, filtered: [] }]);
  eq(r.signature, false, 'detectAllowlist NEGATIVE (live + down, no filtered) -> signature false');
  eq(r.filteredHosts, [], 'detectAllowlist NEGATIVE -> no filtered hosts (no cloud spend)');
}
{ // filtered-but-no-live and empty/garbage inputs never fire
  eq(detectAllowlist([{ live: [], filtered: [{ ip: '192.0.2.20' }] }]).signature, false, 'detectAllowlist filtered-but-no-live -> false');
  eq(detectAllowlist([]).signature, false, 'detectAllowlist empty -> false');
  eq(detectAllowlist(null).signature, false, 'detectAllowlist null-safe -> false');
  // dedup across slices + default signal fill
  const r = detectAllowlist([{ live: [{ ip: 'a' }], filtered: [{ ip: '192.0.2.20' }] }, { live: [], filtered: [{ ip: '192.0.2.20', signal: 'tcp-rst' }] }]);
  eq(r.filteredHosts.length, 1, 'detectAllowlist dedups the same filtered ip across slices');
  eq(r.filteredHosts[0].signal, 'host-up-but-all-filtered', 'detectAllowlist fills a default signal when missing (first-seen wins)');
}

// --- resolveGeoZones (<=2 second-vantage gcp zones) -----------------------
eq(resolveGeoZones({ primaryGeo: 'IT' }), ['us-central1-a'], 'resolveGeoZones EU primary -> drop europe default, keep US');
eq(resolveGeoZones({ primaryGeo: 'US' }), ['europe-west1-b'], 'resolveGeoZones US primary -> drop US default, keep EU');
eq(resolveGeoZones({ primaryGeo: 'unknown' }), ['us-central1-a', 'europe-west1-b'], 'resolveGeoZones unknown primary -> both defaults');
eq(resolveGeoZones({}), ['us-central1-a', 'europe-west1-b'], 'resolveGeoZones no primary -> both defaults');
eq(resolveGeoZones({ geoVantages: ['asia-east1-a', 'us-west1-b'] }), ['asia-east1-a', 'us-west1-b'], 'resolveGeoZones honors explicit override verbatim');
eq(resolveGeoZones({ geoVantages: ['a', 'b', 'c', 'd'] }), ['a', 'b'], 'resolveGeoZones caps override at 2');
eq(resolveGeoZones({ geoVantages: ['a', 'a', 'b'] }), ['a', 'b'], 'resolveGeoZones dedups the override');
eq(resolveGeoZones({ geoVantages: [' z1 ', '', null] }), ['z1'], 'resolveGeoZones trims + drops empty override entries');

// --- finalizeGate (COMPLETE/BLOCKED incl. the deterministic coverage gate) -----
{
  const allGood = finalizeGate({ report_data_ok: true, report_data_lint_ok: true, renderGateOk: true, coverage_complete: true, coverage_untested: 0 });
  eq(allGood, { ok: true, status: 'COMPLETE', blocked_reason: null }, 'finalizeGate all-true -> COMPLETE');
  const cov = finalizeGate({ report_data_ok: true, report_data_lint_ok: true, renderGateOk: true, coverage_complete: false, coverage_untested: 4 });
  eq(cov, { ok: false, status: 'BLOCKED', blocked_reason: 'attack-class coverage < 100% (4 cell(s) untested)' }, 'finalizeGate incomplete coverage -> BLOCKED with count');
  eq(finalizeGate({ report_data_ok: false, report_data_lint_ok: true, renderGateOk: true, coverage_complete: true }).blocked_reason, 'report_data_build failed', 'finalizeGate report_data failure wins');
  eq(finalizeGate({ report_data_ok: true, report_data_lint_ok: false, renderGateOk: true, coverage_complete: true }).blocked_reason, 'report_data lint failed (schema/escaping)', 'finalizeGate report_data lint failure blocks before render');
  eq(finalizeGate({ report_data_ok: true, report_data_lint_ok: true, renderGateOk: false, coverage_complete: true, renderBlockedReason: 'PDF is empty' }).blocked_reason, 'PDF is empty', 'finalizeGate render reason preserved');
  eq(finalizeGate({ report_data_ok: true, report_data_lint_ok: true, renderGateOk: true, coverage_complete: undefined, coverage_untested: 2 }).ok, false, 'finalizeGate fails closed on missing coverage_complete');
  eq(finalizeGate({ report_data_ok: true, report_data_lint_ok: undefined, renderGateOk: true, coverage_complete: true }).ok, false, 'finalizeGate fails closed on missing report_data_lint_ok');
}

// --- report ---------------------------------------------------------------

// --- skill-update: scrub / caps -------------------------------------------
ok(!scrubCheck('on 10.10.11.42 the exploit worked').clean, 'scrub catches a lab IP');
ok(!scrubCheck('FLAG{abc123}').clean, 'scrub catches a preserved flag');
ok(!scrubCheck('see /Users/someone/dev/x').clean, 'scrub catches an operator path');
ok(!scrubCheck('projects/pentest/20260709_zorbix/report').clean, 'scrub catches an engagement path');
ok(scrubCheck('When the response echoes the payload, try a filter bypass.').clean, 'scrub passes a reusable pattern');
eq(capFor('skills/x/SKILL.md', { 'SKILL.md': 150 }), 150, 'capFor SKILL.md');
eq(capFor('skills/x/reference/y.md', { reference: 200 }), 200, 'capFor reference');
eq(capFor('skills/x/reference/scenarios/z.md', { scenario: 400 }), 400, 'capFor scenario');
eq(capFor('skills/x/reference/a-principles.md', { principles: 150 }), 150, 'capFor principles');
eq(capBudget('skills/x/SKILL.md', 100, 20, { 'SKILL.md': 150 }).action, 'append', 'capBudget fits');
eq(capBudget('skills/x/SKILL.md', 140, 20, { 'SKILL.md': 150 }).action, 'split', 'capBudget over cap -> split not truncate');
eq(capBudget('skills/x/SKILL.md', null, 20, { 'SKILL.md': 150 }).action, 'reject', 'capBudget refuses to write blind');

// --- skill-update: promotionGate (four gates AND + quorum) -----------------
const goodJ = { generalizable: true, material: true, not_already_captured: true,
  minimal_footprint: true, duplicate_search: [{ query: 'x', hits: 0 }], footprint: 'extend' };
const cand = { id: 'c1', text: 'When X condition appears, try Y approach.' };
eq(promotionGate(cand, goodJ, []).decision, 'PROMOTE', 'promotionGate promotes when all four hold');
for (const g of ['generalizable', 'material', 'not_already_captured', 'minimal_footprint']) {
  eq(promotionGate(cand, { ...goodJ, [g]: false }, []).decision, 'SKIP', `promotionGate requires ${g}`);
}
eq(promotionGate(cand, { ...goodJ, duplicate_search: [] }, []).decision, 'SKIP', 'novelty claim without a search is unevidenced');
eq(promotionGate(cand, { ...goodJ, footprint: 'new-file' }, []).decision, 'SKIP', 'new-file needs a no_host_reason');
eq(promotionGate(cand, { ...goodJ, footprint: 'new-file', no_host_reason: 'no existing file covers it' }, []).decision, 'PROMOTE', 'new-file with a reason promotes');
eq(promotionGate(cand, { ...goodJ, restates_cross_cutting: true }, []).decision, 'SKIP', 'restating a single-owner rule is rejected');
eq(promotionGate({ id: 'c2', text: 'on 10.10.11.42 it worked' }, goodJ, []).decision, 'SKIP', 'scrub blocks lore even when the judge approves');
eq(promotionGate(cand, goodJ, [{ refuted: true }, { refuted: true }, { refuted: false }]).decision, 'REJECT', 'majority refutation rejects');
eq(promotionGate(cand, goodJ, [{ refuted: true }, { refuted: false }, { refuted: false }]).decision, 'PROMOTE', 'minority refutation does not');
eq(promotionGate(cand, null, []).decision, 'SKIP', 'a missing judgment fails closed');

// --- skill-update: writeGate ----------------------------------------------
const info = { lines: 100 };
const caps = { 'SKILL.md': 150, reference: 200 };
const base = { target_path: 'skills/x/reference/y.md', content: 'When A, try B.\n' };
eq(writeGate(base, info, caps).ok, true, 'writeGate accepts a clean block');
eq(writeGate({ ...base, content: 'You MUST NOT do this.' }, info, caps).ok, false, 'writeGate blocks a negative outside Anti-Patterns');
eq(writeGate({ ...base, content: '## Anti-Patterns\n- MUST NOT do this.' }, info, caps).ok, true, 'writeGate allows a negative inside Anti-Patterns');
eq(writeGate({ ...base, target_path: 'skills/x/CHANGELOG.md' }, info, caps).ok, false, 'writeGate blocks auxiliary files');
eq(writeGate({ ...base, content: 'try 10.10.11.42' }, info, caps).ok, false, 'writeGate scrubs lore');
eq(writeGate({ ...base, links_verified: [{ url: 'a.md', exists: false }] }, info, caps).ok, false, 'writeGate blocks an unresolved link');
eq(writeGate({ ...base, creates_file: true }, info, caps).ok, false, 'writeGate blocks an unlinked new file (orphan)');
eq(writeGate({ ...base, creates_file: true, linked_from: 'skills/x/SKILL.md' }, info, caps).action, 'create', 'writeGate allows a linked new file');
eq(writeGate(base, { lines: 199 }, caps).action, 'split', 'writeGate routes an over-cap write to a split');
eq(writeGate({ target_path: 'a.md', content: '  ' }, info, caps).ok, false, 'writeGate rejects empty content');

// --- skill-update: lintDelta + skillUpdateGate -----------------------------
const V = (code, file, line) => ({ code, file, line, detail: 'd' });
const before = { violations: [V('CAP', 'a.md', 1), V('NEGATIVE', 'b.md', 2)] };
const same = { violations: [V('CAP', 'a.md', 1), V('NEGATIVE', 'b.md', 2)] };
const worse = { violations: [...same.violations, V('LINK', 'c.md', 3)] };
const better = { violations: [V('CAP', 'a.md', 1)] };
eq(lintDelta(before, same).regressed, false, 'lintDelta: pre-existing violations do not block');
eq(lintDelta(before, worse).regressed, true, 'lintDelta: a new violation blocks');
eq(lintDelta(before, worse).introduced.length, 1, 'lintDelta counts only the new one');
eq(lintDelta(before, better).resolved.length, 1, 'lintDelta reports resolved violations');
eq(skillUpdateGate({ baselineOk: true, afterOk: true, writeOk: true, delta: lintDelta(before, same) }).status, 'COMPLETE', 'gate passes with no regression');
eq(skillUpdateGate({ baselineOk: true, afterOk: true, writeOk: true, delta: lintDelta(before, worse) }).status, 'BLOCKED', 'gate blocks on regression');
eq(skillUpdateGate({ baselineOk: false, afterOk: true, writeOk: true, delta: lintDelta(before, same) }).status, 'BLOCKED', 'gate fails closed without a baseline');
eq(skillUpdateGate({ baselineOk: true, afterOk: true, writeOk: false, delta: lintDelta(before, same) }).status, 'BLOCKED', 'gate blocks when the writer drifted');
eq(skillUpdateGate({ baselineOk: true, afterOk: true, writeOk: true, delta: null }).status, 'BLOCKED', 'gate fails closed with no delta');

// --- skill-update: budget + report ----------------------------------------
eq(skillAgentBudget(24, 3, 200).take, 24, 'budget fits 24 candidates at 200');
ok(skillAgentBudget(24, 3, 40).deferred > 0, 'budget defers overflow rather than dropping it');
eq(skillAgentBudget(24, 3, 40).take + skillAgentBudget(24, 3, 40).deferred, 24, 'budget never loses a candidate');
ok(buildChangeReport([], [], { ok: true }).startsWith('**No changes.**'), 'report: no changes');
ok(buildChangeReport([{ id: 'c1', decision: 'SKIP', reason: 'already captured' }], [], { ok: true }).includes('**Skipped.**'), 'report: skipped bucket');
ok(buildChangeReport([], [{ path: 'skills/x/SKILL.md', summary: 'added a pattern' }], { ok: true }).includes('**Updated.**'), 'report: updated bucket');
ok(buildChangeReport([], [], { ok: false, blocked_reason: 'regressed' }).includes('BLOCKED'), 'report surfaces a blocked gate');

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) { console.log('\n' + fails.join('\n')); process.exit(1); }
