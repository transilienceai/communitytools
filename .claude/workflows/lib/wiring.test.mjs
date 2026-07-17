// wiring.test.mjs — static-source assertions that the orchestrator + loop are
// wired for the strict per-finding interleaved model (things unit tests / parity
// can't see: no Stage-2 validate pass, inline_validate threaded, drop-entirely
// routing, coverage-by-VALID). Run: node .claude/workflows/lib/wiring.test.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const wfDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (f) => readFileSync(join(wfDir, f), 'utf8');
const pe = read('pentest-engagement.js');
const cl = read('coordinator-loop.js');
const vf = read('validate-findings.js');
const pv = readFileSync(join(wfDir, '..', '..', 'tools', 'provision_vantage.sh'), 'utf8');
const ciYml = readFileSync(join(wfDir, '..', '..', '.github', 'workflows', 'pentest-workflow-tests.yml'), 'utf8');

let pass = 0, fail = 0; const fails = [];
const ok = (cond, msg) => { if (cond) pass++; else { fail++; fails.push(`✗ ${msg}`); } };

// pentest-engagement: validation is INLINE — no Stage-2 validate-findings call,
// inline_validate + business_tier + frozen-operand paths threaded, snapshot created.
ok(!/workflow\('validate-findings'/.test(pe), 'pentest-engagement no longer calls the validate-findings workflow (validation is inline)');
ok((pe.match(/inline_validate: true/g) || []).length >= 2, 'inline_validate:true passed for BOTH the WEB and NETWORK deep-dive loops');
ok(/nvd_cache_dir: nvdCacheDir/.test(pe) && /kev_snapshot: kevSnapshot/.test(pe), 'frozen NVD/KEV snapshot paths threaded into the loop');
ok(/assets: N,/.test(pe) && /assets: NH,/.test(pe), 'assets:N (web) + assets:NH (network) threaded — the governor partitions the cap by the PER-RUN running count');
ok(/kev-lookup\.py --cache-dir/.test(pe), 'Setup freezes the KEV snapshot via kev-lookup.py --cache-dir');
ok(!/validate: false/.test(pe), 'the retired validate:false flag is gone');
ok((pe.match(/VALID\/REPAIRED/g) || []).length >= 2, 'Correlate reads VALID+REPAIRED (both modes), not VALID-only');

// coordinator-loop: interleave machinery present; vestigial P5 retired.
ok(/const INLINE_VALIDATE = shouldInlineValidate\(MODE, a\.inline_validate\)/.test(cl), 'coordinator-loop gates the lane on shouldInlineValidate');
ok(/async function validateBatch\(/.test(cl) && /async function validateOneCandidate\(/.test(cl), 'coordinator-loop defines the strict per-finding validateBatch/validateOneCandidate');
ok(/if \(INLINE_VALIDATE\) await validateBatch\(integ\.new_findings/.test(cl), 'the loop validates each batch of new candidates inline before continuing');
ok(/backstopDecision\(agentsSpawned, HARD_RESERVE\)/.test(cl), 'the fixed-quorum + deferral governor is wired (never shrinks the quorum)');
ok(/COVERAGE-BY-VALID/.test(cl), 'INTEGRATE uses coverage-by-VALID (a class covers only on a VALID finding)');
ok(!/function validateFindingPrompt/.test(cl) && !/VALIDATE_FINDING_SCHEMA =/.test(cl), 'the vestigial lightweight P5 validator is retired');
ok(!/const RUN_VALIDATION =/.test(cl), 'the RUN_VALIDATION arg is retired (replaced by INLINE_VALIDATE)');
ok(/verdict_counts: summarizeLoopCounts\(/.test(cl), 'the loop returns verdict_counts so adaptSummary never reads a silent null');

// validate-findings (standalone): drop-entirely routing + raised quorum.
ok(/const sub = terminalSubdir\(r\.verdict\.verdict\)/.test(vf), 'standalone validate-findings routes terminal verdicts via terminalSubdir (DEMOTED -> dropped/)');
ok(/: DEFAULT_VOTES/.test(vf), 'standalone VOTES defaults to DEFAULT_VOTES (raised quorum)');

// C3 replay-cache (Phase 2): validate-findings restores hits + stores live verdicts, tool-mediated.
ok(/const VALIDATION_CACHE_DIR = a\.validation_cache_dir/.test(vf), 'validate-findings reads a validation_cache_dir (C3 opt-in)');
ok(/validation_cache\.py restore/.test(vf) && /validation_cache\.py store/.test(vf), 'C3 restore (skip lane on hit) + store (record live verdict) are wired via the tool');
ok(/toValidate = inventory\.filter/.test(vf), 'restored (cache-hit) findings are excluded from the live validation set');
ok(/mkdir -p engagement_dir\/artifacts\/nvd-cache engagement_dir\/artifacts\/validation-cache/.test(pe), 'Setup creates the validation-cache dir alongside nvd-cache');

// deterministic activity / source-IP logging: Setup + Bootstrap capture the primary
// runner's egress vantage, thread the report counts, and keep the raw command ledger
// out of the client deliverable.
ok(/logs\/activity/.test(pe), 'pentest-engagement Setup creates logs/activity');
ok(/active-engagement/.test(pe), 'Setup writes the active-engagement pointer');
ok(/ifconfig\.me/.test(pe) && /api\.ipify\.org/.test(pe) && /unavailable/.test(pe), 'Setup captures egress IP with fallback');
ok(/register_source_ip\.py/.test(pe) && /--role primary-runner/.test(pe), 'Setup registers the primary-runner source IP');
ok(/tools_used_count/.test(pe) && /source_ips_count/.test(pe) && /reconciliation_gaps/.test(pe), 'finalize threads activity counts + reconciliation gaps');
ok(/tool-invocations\.jsonl/.test(pe), 'finalize zip excludes the raw command ledger from the client deliverable');
ok(/logs\/activity/.test(cl) && /active-engagement/.test(cl), 'coordinator-loop Bootstrap creates logs/activity + pointer');
ok(/register_source_ip\.py/.test(cl) && /--role primary-runner/.test(cl), 'coordinator-loop Bootstrap registers the primary-runner IP');

// network-scan: full-range default profiles + two-stage + odd-TLS + host-count guard.
ok(/const fullRange = fullPorts \|\| scanProfile === 'standard'/.test(pe), 'standard profile is now full-range (-p-)');
ok(/const portSpec = fullRange \? '-p-' :/.test(pe), 'portSpec branches on fullRange (not a bare literal)');
ok(/-p 1-1024,\$\{LESS_COMMON_PORTS\}/.test(pe), 'light/bounded profile = 1-1024 + curated less-common set');
ok(/const udpScan = !!input\.udp \|\| scanProfile === 'full'/.test(pe), 'full profile auto-enables UDP');
ok(/STAGE A fast SYN sweep of ALL 65535/.test(pe) && /STAGE B version\+scripts on ONLY those open ports/.test(pe), 'full-range path is two-stage (SYN sweep -> -sV on found-open ports, no host-timeout truncation)');
ok(/--script ssl-cert,ssl-enum-ciphers/.test(pe), 'odd-port TLS is fingerprinted via the ssl-cert/ssl-enum-ciphers NSE');
ok(/FULL_RANGE_HOST_CAP/.test(pe) && /DOWNGRADE to the bounded set/.test(pe), 'full-range is host-count-guarded (dense slices fall back to bounded)');
ok(!/Do NOT scan all 65535 ports/.test(pe), 'the blanket "Do NOT scan all 65535" clause is dropped on the full-range path');

// network-scan: source-IP/geo-allowlist detection + 2nd-geography auto-probe.
ok(/filtered:/.test(pe) && /existence proof from this vantage/i.test(pe), 'SCAN_SLICE_SCHEMA carries the filtered[] existence-signal set');
ok(/const \{ signature: allowlistDetected, filteredHosts \} = detectAllowlist\(sliceResults\)/.test(pe), 'allowlist signature computed via detectAllowlist');
ok(/resolveGeoZones\(\{ geoVantages, primaryGeo \}\)/.test(pe), 'the <=2 second-vantage zones come from resolveGeoZones');
ok(/const willProvision = autoProvision && !dryRun && geos\.length > 0/.test(pe), 'geo-escalation is gated on autoProvision && !dryRun (clean/dry runs never spend)');
{ // the newly_reachable -> allLive in-memory merge MUST run BEFORE ranking (else it only hits disk)
  const mergeIdx = pe.indexOf('allLive.push({ ...h');
  const rankedIdx = pe.indexOf('const ranked = allLive.filter');
  ok(mergeIdx > 0 && rankedIdx > 0 && mergeIdx < rankedIdx, 'geo-reached hosts merge into in-memory allLive BEFORE ranking (reach the deep-dive)');
}
ok(/runGeoEscalation\(\{ geos, filteredHosts \}\)/.test(pe), 'runGeoEscalation re-probes ONLY the filtered hosts');
ok(/provision_vantage\.sh --teardown/.test(pe) && /provision_vantage\.sh --reap/.test(pe) && /trap '\[ -n "\$handle" \]/.test(pe) && /--ssh-ready/.test(pe), 'geo-probe agent creates/reaps/tears-down via provision_vantage.sh with a teardown trap');
ok(/no_surface_from: geosTried\.slice\(\)/.test(pe), 'still-dark filtered hosts are recorded no_surface_from (honest negative, never bare dead)');
ok(/udp: udpScan/.test(pe) && /allowlist_detected: allowlistDetected/.test(pe) && /escalation_plan: escalationPlan/.test(pe) && /no_surface_from: noSurfaceFrom/.test(pe), 'dryRun return surfaces udp + allowlist_detected + escalation_plan + no_surface_from');
ok(/ipinfo\.io\/\$PRIMARY_IP\/country/.test(pe) && /primary_geo/.test(pe), 'Setup best-effort geolocates the primary egress (primary_geo) for a complementary 2nd vantage');

// provision_vantage.sh: ephemerality guarantees (crash-safe VM lifecycle).
ok(/--teardown\)/.test(pv) && /--reap\)/.test(pv) && /--ssh-ready\)/.test(pv), 'provision_vantage.sh implements --teardown / --reap / --ssh-ready');
ok(/--max-run-duration="\$\{TTL\}s" --instance-termination-action=DELETE/.test(pv), 'created VMs carry a provider-native max-run-duration TTL + DELETE (SIGKILL-proof backstop)');
ok(/--labels="engagement=\$\{eng_id\}/.test(pv), 'created VMs are labelled engagement=<id> so --reap can GC orphans');
ok(/--role decommissioned/.test(pv) || /decommissioned "torn down/.test(pv), 'teardown APPENDS a role:decommissioned ledger line (append-only, never a mutation)');

// ---------------------------------------------------------------------------
// Deterministic attack-class coverage gate (surface-unit × attack-class):
// finalize runs it, JS hard-gates COMPLETE on it, network is tiered + coverage-gated.
// ---------------------------------------------------------------------------
ok(/tools\/coverage_gate\.py --engagement-dir/.test(pe), 'finalize runner runs coverage_gate.py --engagement-dir (deterministic gate)');
ok(/tools\/network_coverage_map\.py --engagement-dir/.test(pe), 'finalize runner runs network_coverage_map.py before the gate (swept-host tail)');
ok(/coverage_complete: \{ type: 'boolean'/.test(pe), 'FINALIZE_SCHEMA carries coverage_complete');
ok(/finalizeGate\(\{ report_data_ok: r\.report_data_ok, renderGateOk, coverage_complete: r\.coverage_complete/.test(pe), 'the JS hard gate routes through finalizeGate incl. coverage_complete');
ok(/const coverageComplete = wantReport \? \(report\.coverage_complete === true\) : true/.test(pe), 'WEB engagement_status derives from the gate (fails closed)');
ok(/coverageComplete && convStatus === 'COMPLETE'/.test(pe), 'WEB COMPLETE requires the gate coverage_complete AND convergence (nothing resumable)');
ok(/const netCoverageComplete = wantReport \? \(reportNet\.coverage_complete === true\) : true/.test(pe), 'NETWORK engagement_status derives from the gate (fails closed)');
ok(/netCoverageComplete && netConvStatus === 'COMPLETE'/.test(pe), 'NETWORK COMPLETE requires scanComplete AND gate coverage_complete AND convergence');
ok(/const isAppBearing = /.test(pe) && /allLive\.filter\(h => h && isAppBearing\(h\)\)/.test(pe), 'NETWORK deep-dive selects app-bearing hosts (tiered), not an arbitrary top-N');
ok(/mode: 'coverage',\s+\/\/ tiered/.test(pe), 'NETWORK app-bearing deep-dive loops run in coverage mode');
ok(/deepenTop === 0 \? \[\] : \(deepenTop > 0 \? ranked\.slice\(0, deepenTop\) : ranked\)/.test(pe), 'deepen_top: 0 disables, N caps, null(default) = ALL app-bearing hosts');
ok(/recon\/inventory\/surface\.json \(schema surface\/v2/.test(pe), 'NETWORK app-bearing loop is told to emit surface/v2 so unit-scope cells are enumerated');

// coordinator-loop: coverage mode is driven by the deterministic tools, not agent narrative.
ok(/tools\/enumerate_cells\.py --asset-dir OUTPUT_DIR/.test(cl), 'THINK runs enumerate_cells.py to compute the applicable cells');
ok(/tools\/coverage_gate\.py --asset-dir OUTPUT_DIR --emit-open/.test(cl), 'THINK runs coverage_gate.py --emit-open to inject the open-cell backlog');
ok(/covers_cells: \{ type: 'array'/.test(cl), 'THINK schema carries covers_cells (deterministic (key,class_id) cells)');
ok(/coverage_complete: \{ type: 'boolean'/.test(cl), 'INTEGRATE schema carries coverage_complete (the gate\'s "complete")');
ok(/Set goal_reached=true ONLY when coverage_complete is true/.test(cl), 'INTEGRATE gates goal_reached on the deterministic coverage_complete');
ok(/interim\.class_id = f\.covers_class/.test(cl) && /interim\.unit_refs = /.test(cl) && /interim\.asset_tag = OUTPUT_DIR/.test(cl), 'C3: validated finding is stamped class_id/unit_refs/asset_tag AFTER buildInterim (parity-safe)');
ok(/integ\.coverage_complete === true \? 0/.test(cl), 'loop termination keys off the gate\'s coverage_complete, not an agent count');
ok(/CHECK 8 attack-class coverage \(DETERMINISTIC/.test(cl) && !/coverage_ratio < 0\.80/.test(cl), 'check 8 is the hard coverage_gate.py gate; the 0.80 soft bar is gone');
ok(/schema surface\/v2/.test(cl), 'coordinator-loop emits surface/v2 (bootstrap + THINK) so cells are enumerable');

// CI registers the new deterministic-coverage + report tests and watches tools/**.
ok(/python3 tools\/test_coverage_gate\.py/.test(ciYml) && /python3 tools\/test_validate_catalog\.py/.test(ciYml), 'CI runs the coverage-gate + catalog tests');
ok(/python3 tools\/test_report_data_build\.py/.test(ciYml) && /python3 tools\/test_report_schema\.py/.test(ciYml), 'CI runs the report assembler + schema tests');
ok(/'tools\/\*\*'/.test(ciYml), 'CI paths filter watches tools/** (so the new tools trigger the job)');

// ---------------------------------------------------------------------------
// Convergence-first depth (remove the cost-style budget) + honest cross-run resume
// + E1/E2/E4 efficiency levers. The depth formulas are DELETED; completion is
// coverage-convergence + a dry tail, backstopped by the per-asset agent slice.
// ---------------------------------------------------------------------------
// Negative locks: the three magic depth formulas are gone (a stray one would silently
// re-cap depth / blow the 1000-agent kill limit).
ok(!/loopBudgetBatches/.test(pe) && !/loopBudgetExperiments/.test(pe), 'WEB depth formula (loopBudget*) is deleted');
ok(!/deepBudgetBatches/.test(pe) && !/deepBudgetExp/.test(pe), 'NETWORK deep-dive depth formula (deepBudget*) is deleted');
ok(!/max_experiments: loopBudget/.test(pe) && !/max_batches: loopBudget/.test(pe) && !/max_experiments: deepBudget/.test(pe) && !/max_batches: deepBudget/.test(pe), 'derived max_experiments/max_batches are no longer passed into coordinator-loop');
ok(!/userMaxExp/.test(pe), 'the dead userMaxExp bindings are removed (no ReferenceError)');

// coordinator-loop: coverage-mode loop is convergence-bounded (agent slice + ceiling);
// flag mode keeps the original budget-bounded loop.
ok(/agentsSpawned < perAssetSlice && batch < ABSOLUTE_MAX_BATCHES/.test(cl), 'coverage loop head is the per-asset agent slice + absolute ceiling');
ok(/exp < MAX_EXPERIMENTS && batch < MAX_BATCHES/.test(cl), 'flag-mode loop head is unchanged (htb-solve untouched)');
ok(/const perAssetSlice = MODE === 'coverage' \? assetBudget\.perAsset/.test(cl), 'perAssetSlice derives from the (test-locked) assessBudget partition');
ok(/assessBudget\(\{ assets: Number\(a\.assets\) \|\| 1, reserve: AGENT_RESERVE \}\)/.test(cl), 'assessBudget is called with the agent_reserve override');
ok(/const done = MODE === 'coverage'\s*\?\s*convergenceDone\(/.test(cl), 'coverage completion is convergenceDone (not a bare pending===0 || goal_reached)');
ok(/coverageDryStreak = nextDryStreak\(/.test(cl), 'the dry tail is advanced via nextDryStreak');
ok(/const reopened = prevOpenCells != null && \[\.\.\.openSet\]\.some/.test(cl), 'reopen detection is a set-diff over the open-cell set (not a bare count)');
ok(/INCOMPLETE_RESUMABLE/.test(cl) && /agent slice \(\$\{perAssetSlice\}\) exhausted/.test(cl), 'a slice-exhausted-with-open-cells exit is INCOMPLETE_RESUMABLE (resumable, not a gap)');
ok(/DRY_TAIL = Number\(a\.dry_tail\)/.test(cl), 'dry_tail is a coordinator-loop arg');

// pentest-engagement: convergence knobs threaded + honest cross-run resume (WEB + NETWORK).
ok((pe.match(/dry_tail: dryTail/g) || []).length >= 2, 'dry_tail threaded into BOTH the web and network coverage loops');
ok(/resumeSchedule\(\{ incompleteCount:/.test(pe), 'resumeSchedule picks the per-run asset slice; the rest defer');
ok((pe.match(/classifyEngagement\(/g) || []).length >= 2, 'classifyEngagement derives the tri-state status (web + network)');
ok(/label: 'resume-scan'/.test(pe) && /label: 'resume-scan-net'/.test(pe), 'a deterministic resume-scan runs coverage_gate.py per asset/host (web + network)');
ok(/complete === true && Number\(r\.applicable\) > 0/.test(pe), 'resume-COMPLETE requires the gate boolean AND applicable>0 (no vacuous-complete skip)');
ok(/input\.resume_dir/.test(pe) && /RESUME_DIR:/.test(pe), 'Setup reuses input.resume_dir to continue a prior engagement');
ok(/max_resume_rounds/.test(pe), 'a resume-round churn guard caps endless retries of stuck assets');
ok(/deep_asset_slice/.test(pe) && /const deepAssetSlice = /.test(pe), 'DEEP_ASSET_SLICE (per-asset agent budget) is configurable, default 200');

// E1 tools-not-agents: the deterministic mechanical-class probe is wired into the loop.
ok(/tools\/passive_web_probe\.py --asset-dir OUTPUT_DIR/.test(cl), 'E1: passive_web_probe.py runs at bootstrap to clear the mechanical attack-classes');
ok(/RESUME-AWARE: if OUTPUT_DIR\/recon\/inventory\/surface\.json AND OUTPUT_DIR\/coverage\.json BOTH already exist/.test(cl), 'coverage bootstrap is resume-aware (preserves surface.json/coverage.json, re-derives the backlog)');

// E2 equivalence-class validation: gate credit + loop instruction + validator sampling.
ok(/EQUIVALENCE \(E2\)/.test(cl) && /validate ONE representative/.test(cl), 'COVERAGE-BY-VALID instructs one representative per (class x equiv_group)');
ok(/EQUIV SAMPLING \(E2 guard\)/.test(cl) && /K_SAMPLE=3/.test(cl), 'the blind engagement-validator samples equiv-credited cells (mis-group -> GAPS_FOUND)');
ok(/"equiv_group":<null OR a short group id/.test(cl), 'the surface/v2 emitter carries a conservative equiv_group directive');
ok(/AND a conservative equiv_group/.test(pe), 'the network app-bearing goal carries the equiv_group directive too');

// E4 replay-cache: restore before the lane (resume), store after (populate).
ok(/validation_cache\.py restore --finding-dir/.test(cl) && /validation_cache\.py store --cache-dir/.test(cl), 'E4: validateOneCandidate restores on a resume hit and stores every terminal verdict');
ok(/const REPLAY_CACHE = !!a\.replay_cache/.test(cl) && /prompt-id \$\{CACHE_PROMPT_ID\}/.test(cl), 'E4 is asset-namespaced + resume-gated (no cross-asset replay)');
ok((pe.match(/validation_cache_dir:/g) || []).length >= 2 && (pe.match(/replay_cache: !!setup\.resumed/g) || []).length >= 2, 'pentest-engagement threads the cache dir + resume-gated replay flag into both loops');

// CI registers the new E1 probe test.
ok(/python3 tools\/test_passive_web_probe\.py/.test(ciYml), 'CI runs the passive_web_probe test');

// Password-protected deliverable: finalize also emits an AES-256 protected copy
// (kept alongside the plaintext), with an auto-generated out-of-band password.
ok(/tools\/protect_deliverable\.py --engagement-dir/.test(pe), 'finalize runs protect_deliverable.py for an AES-256 protected copy');
ok(/const wantProtect = opts\.protect !== false/.test(pe), 'protection is default-ON with a protect:false kill-switch');
ok((pe.match(/protect: input\.protect !== false/g) || []).length >= 2, 'the protect flag is threaded from BOTH the web and network finalize calls');
ok(/deliverable_password: \{ type/.test(pe) && /protected_zip: \{ type/.test(pe), 'FINALIZE_SCHEMA carries the protected artifacts + password');
ok(/NEVER write the password VALUE into summary\.md/.test(pe), 'the runner is told to keep the password value out of the zipped summary');
ok(/DELIVERABLE-PASSWORD\.txt/.test(pe), 'the password is surfaced via a root file excluded from the deliverable');
ok(/python3 tools\/test_protect_deliverable\.py/.test(ciYml), 'CI runs the protect_deliverable test');

console.log(`\nwiring: ${pass} passed, ${fail} failed`);
if (fail) { console.log('\n' + fails.join('\n')); process.exit(1); }
