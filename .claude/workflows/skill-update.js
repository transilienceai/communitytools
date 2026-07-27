export const meta = {
  name: 'skill-update',
  description: 'Deterministically add, refine, or create skill content from engagement learnings. Stores a BASELINE violation key set via `scripts/skill_linter.py --write-baseline` (the tool computes the later delta, so no large payload crosses an agent), harvests candidate learnings from an engagement tree (or takes them directly), reframes each as a reusable "when X condition, try Y approach" pattern using <TARGET_IP>/<DC_FQDN>/<DOMAIN> placeholders, then per candidate: a judge proposes the four-gate promotion verdict with a CITED duplicate-search, N blind adversarial refuters attack every PROMOTE, and the pure-JS promotionGate applies the kill rules (all four gates AND no majority refutation AND a clean machine scrub for challenge-specific identifiers). Promoted candidates are routed to a target file, an author agent emits the exact insertion block, and pure-JS gates refuse it when it would breach a line cap (routing to a split instead), add DO NOT/MUST NOT/NEVER outside an Anti-Patterns section, restate a single-owner cross-cutting rule, create a forbidden auxiliary file, orphan a new reference file, or carry a link that does not resolve. JS then builds a byte-exact write plan, one writer persists it verbatim, an independent verifier recomputes the line counts, the confidentiality guard sweeps the result, and a post-write linter DELTA gate — not an absolute clean-tree gate, since the tree carries pre-existing violations — blocks on any newly introduced violation. The three-bucket Updated. / Skipped. / No changes. report is built in code, never authored by an agent.',
  whenToUse: 'Post-engagement skill-base maintenance. Parent-ORCHESTRATOR only — a coordinator must never invoke it. mode:"harvest" {output_dir} -> mine one engagement tree for learnings; mode:"learnings" {learnings:[{text,technique_type}]} -> judge and write an already-extracted set (also the resume path); mode:"create" {create:{name,description}} -> scaffold a new skill; mode:"audit" -> read-only conformance report over skills/, writes nothing. Options: votes(3), max_candidates(24), agent_budget(200), dryRun, invoked_by.',
  phases: [
    { title: 'Intake', detail: 'date tag + base commit, BASELINE skill_linter key set, dirty-path snapshot, mode preconditions' },
    { title: 'Harvest', detail: 'one Explore agent per engagement artifact -> reframed "when X, try Y" candidates; pure-JS dedupe, stable ids, machine scrub' },
    { title: 'Judge', detail: 'per candidate: four-gate judge with a CITED duplicate-search -> N blind adversarial refuters -> pure-JS promotionGate' },
    { title: 'Route', detail: 'author agent emits the exact block; pure-JS writeGate accepts, routes to a split, or rejects it' },
    { title: 'Write', detail: 'JS builds the byte-exact write plan; a writer persists it verbatim; an independent verifier recomputes the line counts' },
    { title: 'Sweep', detail: 'confidentiality guard over the written tree — no client/engagement data may enter the public skill base' },
    { title: 'Verify', detail: 'skill_linter --delta against the stored baseline; skillUpdateGate blocks on any NEW violation; the three-bucket report' },
  ],
}

// Sandbox: no import/require, no fs, no bash, no Date.now()/Math.random()/new Date().
// Agents run every command and touch every file; this script only decides.
//
// The determinism contract, mirroring pentest-engagement.js: a tool computes the
// facts, a tool-runner agent relays them VERBATIM, and the pure-JS gates below make
// every accept/reject call. No LLM decides whether a learning is promoted, whether a
// write is allowed, or whether the run passed.
//
// The lint gate is a DELTA gate, deliberately. `scripts/skill_linter.py` reports 78
// pre-existing violations on a clean tree, so an absolute gate would block every run
// forever. The question this workflow answers is whether THIS run made things worse.

const DEFAULT_VOTES = 3

// ---- inputs ---------------------------------------------------------------
let __raw = args
if (typeof __raw === 'string') {
  const s = __raw.trim()
  if (s.startsWith('{') || s.startsWith('[')) { try { __raw = JSON.parse(s) } catch (e) { __raw = { output_dir: __raw } } }
  else __raw = { output_dir: __raw }
}
const input = (__raw && typeof __raw === 'object' && !Array.isArray(__raw)) ? __raw : {}

const MODES = ['harvest', 'learnings', 'create', 'audit']
const mode = MODES.includes(input.mode) ? input.mode
  : (input.create ? 'create'
  : (Array.isArray(input.learnings) && input.learnings.length ? 'learnings'
  : (input.output_dir || input.engagement_dir ? 'harvest' : 'audit')))

const OUTPUT_DIR = String(input.output_dir || input.engagement_dir || '').replace(/\/+$/, '')
const ENGAGEMENT = String(input.engagement || input.target || '').trim()
const LEARNINGS = (Array.isArray(input.learnings) ? input.learnings : [])
  .map((l) => (typeof l === 'string' ? { text: l, technique_type: 'other' } : l))
  .filter((l) => l && l.text)
const CREATE = (input.create && typeof input.create === 'object') ? input.create : null
const VOTES = Number(input.votes) > 0 ? Math.floor(Number(input.votes)) : DEFAULT_VOTES
const MAX_CAND = Number(input.max_candidates) > 0 ? Math.floor(Number(input.max_candidates)) : 24
const AGENT_BUDGET = Number(input.agent_budget) > 0 ? Math.floor(Number(input.agent_budget)) : 200
const dryRun = !!input.dryRun
const INVOKED_BY = String(input.invoked_by || '').toLowerCase()

const BASELINE = '.claude/state/skill-update/baseline.json'

const EMPTY = { counts: { candidates: 0, promoted: 0, skipped: 0, written: 0, deferred: 0 }, updated_files: [], skipped: [], report_markdown: '**No changes.**' }

// ---- inline helpers ------------------------------------------------------
// Byte-identical copies of .claude/workflows/lib/wf-helpers.mjs — the sandbox
// forbids import, and lib/parity.test.mjs fails the build if these drift.
// Every promote/reject/write/gate decision in this workflow lives here, in code.

// Challenge- and target-specific identifiers a reusable skill must never carry.
// A learning that needs one of these to make sense is lore, not a pattern.
const SCRUB_PATTERNS = [
  [/\b(HackTheBox|hackthebox|HTB)\b/, 'platform name'],
  [/\bVulnlab\b/, 'lab platform'],
  [/\bXBEN-\d+-\d+\b/, 'challenge id'],
  [/\b10\.(?:10|129)\.\d+\.\d+\b/, 'lab IP'],
  [/\b(?:FLAG|flag)\{[^}]{2,}\}/, 'preserved flag'],
  [/\bprojects\/(?:pentest|compliance|offsec|webinars)\/\d{6,8}[_-]/, 'engagement path'],
  [/\/(?:Users|home)\/[A-Za-z][A-Za-z0-9._-]{2,}\//, 'operator path'],
];

// scrubCheck — machine half of the "generalizable" gate. The judge rules on
// meaning; this rules on identifiers, which needs no judgement and must not be
// left to one.
function scrubCheck(text) {
  const hits = [];
  for (const [re, label] of SCRUB_PATTERNS) if (re.test(String(text || ''))) hits.push(label);
  return { clean: hits.length === 0, hits };
}

// capFor — which cap applies to a path. Single source: the linter's published caps.
function capFor(path, caps = {}) {
  const p = String(path || '');
  if (p.endsWith('/SKILL.md') || p === 'SKILL.md') return caps['SKILL.md'] || 150;
  if (p.endsWith('/README.md') || p === 'README.md') return caps['README.md'] || 100;
  if (/\/reference\/scenarios\//.test(p)) return caps.scenario || 400;
  if (/-principles\.md$/.test(p)) return caps.principles || 150;
  if (/\/reference\//.test(p)) return caps.reference || 200;
  return caps.reference || 200;
}

// capBudget — refuse a write that would breach a cap, and say what to do instead.
// Truncating the block would silently corrupt content, so an over-cap write is
// routed to a split rather than trimmed.
function capBudget(path, linesBefore, addedLines, caps = {}) {
  const cap = capFor(path, caps);
  // null/undefined mean "unknown", not zero — Number(null) is 0, which would read
  // a missing line count as an empty file and let a blind write through.
  const before = linesBefore == null ? NaN : Number(linesBefore);
  const added = addedLines == null ? NaN : Number(addedLines);
  if (!Number.isFinite(before) || !Number.isFinite(added)) {
    return { ok: false, action: 'reject', cap, after: null,
             reason: 'line counts unavailable; refusing to write blind' };
  }
  const after = before + added;
  if (after <= cap) return { ok: true, action: 'append', cap, after, headroom: cap - after };
  return { ok: false, action: 'split', cap, after,
           reason: `${path} would reach ${after} lines (cap ${cap}); split into reference/ instead` };
}

// promotionGate — the four-gate promotion test as a pure boolean AND, plus a
// blind adversarial quorum and the machine scrub. Mirrors computeVerdict.
// Gate 3 is EVIDENCE-BOUND: "not already captured" is only believed when the
// judge actually searched, so an unevidenced novelty claim rejects.
function promotionGate(candidate, judgment, votes, opts = {}) {
  const id = (candidate && candidate.id) || (judgment && judgment.id) || 'unknown';
  const scrub = scrubCheck((candidate && candidate.text) || '');
  if (!judgment) {
    return { id, decision: 'SKIP', reason: 'judge returned no result', failed_gates: ['judge_error'] };
  }
  const failed = [];
  if (!judgment.generalizable) failed.push('generalizable');
  if (!judgment.material) failed.push('material');
  if (!judgment.not_already_captured) failed.push('not_already_captured');
  if (!judgment.minimal_footprint) failed.push('minimal_footprint');
  // An unsearched novelty claim is not evidence of novelty.
  const searched = Array.isArray(judgment.duplicate_search) && judgment.duplicate_search.length > 0;
  if (judgment.not_already_captured && !searched) failed.push('not_already_captured:unevidenced');
  // A new file must name the existing files that could not host the learning.
  if (judgment.footprint === 'new-file' && !String(judgment.no_host_reason || '').trim()) {
    failed.push('minimal_footprint:no_host_reason');
  }
  if (judgment.restates_cross_cutting) failed.push('single_canonical_home');
  if (!scrub.clean) failed.push(`generalizable:scrub(${scrub.hits.join(',')})`);

  const votesTotal = opts.votesTotal != null ? opts.votesTotal : (votes || []).length;
  const refuteCount = (votes || []).filter((v) => v && v.refuted).length;
  const majority = Math.floor(votesTotal / 2) + 1;
  const refuted = votesTotal > 0 && refuteCount >= majority;

  if (refuted) {
    const g = (votes || []).find((v) => v && v.refuted && v.gate);
    return { id, decision: 'REJECT', reason: `refuted ${refuteCount}/${votesTotal}` +
             (g && g.gate ? ` on ${g.gate}` : ''), failed_gates: failed, refuteCount };
  }
  if (failed.length) {
    return { id, decision: 'SKIP', reason: `failed: ${failed.join(', ')}`,
             failed_gates: failed, refuteCount };
  }
  return { id, decision: 'PROMOTE', reason: 'all four gates hold', failed_gates: [], refuteCount };
}

// writeGate — the composite pre-write check. Every rule the skill declares is
// enforced here BEFORE anything is written, so a rejected block costs nothing.
function writeGate(block, fileInfo, caps = {}) {
  const reasons = [];
  if (!block || !String(block.content || '').trim()) {
    return { ok: false, action: 'reject', reasons: ['author produced no content'] };
  }
  const path = String(block.target_path || '');
  const content = String(block.content);

  // Auxiliary/meta files the skill explicitly forbids.
  if (/\/(CHANGELOG|SUMMARY|VERIFICATION|NOTES|TODO)\.md$/i.test(path)) {
    reasons.push('forbidden auxiliary file (CHANGELOG/SUMMARY/VERIFICATION)');
  }
  // Negative rules belong in an Anti-Patterns section, wherever they land.
  if (/\b(DO NOT|MUST NOT|NEVER)\b/.test(content)) {
    const underAnti = /^#{2,3}\s.*anti-pattern/im.test(content) || block.anchor_is_anti_patterns === true;
    if (!underAnti) reasons.push('DO NOT/MUST NOT/NEVER outside an ## Anti-Patterns section');
  }
  // Cross-cutting rules have one canonical home; elsewhere they must be linked.
  if (block.restates_cross_cutting) reasons.push('restates a single-owner cross-cutting rule; link instead');
  // Challenge/target identifiers.
  const scrub = scrubCheck(content);
  if (!scrub.clean) reasons.push(`challenge-specific identifiers: ${scrub.hits.join(', ')}`);
  // Links must resolve — the author is required to have checked each one.
  const unresolved = (block.links_verified || []).filter((l) => l && l.exists === false);
  if (unresolved.length) reasons.push(`unresolved link(s): ${unresolved.map((l) => l.url).join(', ')}`);
  // A new reference file that nothing links to is born an orphan.
  if (block.creates_file && !block.linked_from) reasons.push('new reference file is not linked from anywhere (orphan)');

  if (reasons.length) return { ok: false, action: 'reject', reasons };

  const added = content.split('\n').length;
  const budget = capBudget(path, (fileInfo && fileInfo.lines) || 0, added, caps);
  if (!budget.ok) return { ok: false, action: budget.action, reasons: [budget.reason], budget };
  return { ok: true, action: block.creates_file ? 'create' : 'append', reasons: [], budget };
}

// skillUpdateGate — the COMPLETE/BLOCKED decision over the run's reported facts.
// Fails closed: a missing lint payload blocks, because without it the delta is
// unknowable and "unknown" must never read as "clean".
function skillUpdateGate({ baselineOk, afterOk, delta, writeOk, writeMismatch }) {
  const ok = !!(baselineOk && afterOk && writeOk && delta && !delta.regressed);
  const blocked_reason = ok ? null
    : !baselineOk ? 'baseline skill_linter --json did not parse; refusing to write without a delta baseline'
    : !writeOk ? `writer did not persist the plan faithfully (${writeMismatch || 'mismatch'})`
    : !afterOk ? 'post-write skill_linter --json did not parse; cannot prove no regression'
    : !delta ? 'no lint delta computed'
    : `introduced ${delta.introduced.length} new linter violation(s): ` +
      delta.introduced.slice(0, 5).map((v) => `${v.code} ${v.file}`).join('; ');
  return { ok, status: ok ? 'COMPLETE' : 'BLOCKED', blocked_reason };
}

// skillAgentBudget — decide how many candidates fit the agent budget BEFORE the
// judge phase. Overflow is deferred and reported, never silently dropped.
function skillAgentBudget(candidateCount, votes, budget, overhead = 9) {
  const perCandidate = 2 + Math.max(0, Number(votes) || 0); // judge + author + refuters
  const usable = Math.max(0, (Number(budget) || 0) - overhead);
  const fit = perCandidate > 0 ? Math.floor(usable / perCandidate) : 0;
  const take = Math.max(0, Math.min(Number(candidateCount) || 0, fit));
  return { take, deferred: Math.max(0, (Number(candidateCount) || 0) - take), perCandidate };
}

// buildChangeReport — the three-bucket output, built in code. An agent writing
// this could claim an update that never happened.
function buildChangeReport(decisions, written, gate) {
  const updated = (written || []).filter((w) => w && w.path);
  const skipped = (decisions || []).filter((d) => d && d.decision !== 'PROMOTE');
  const lines = [];
  if (gate && gate.ok === false) {
    lines.push(`⚠️ **BLOCKED.** ${gate.blocked_reason}`, '');
  }
  if (updated.length) {
    lines.push('**Updated.**');
    for (const w of updated) lines.push(`- \`${w.path}\` — ${w.summary || 'content added'}`);
    lines.push('');
  }
  if (skipped.length) {
    lines.push('**Skipped.**');
    for (const s of skipped) lines.push(`- ${s.id} — ${s.reason}`);
    lines.push('');
  }
  if (!updated.length && !skipped.length) lines.push('**No changes.** Nothing warranted an update.');
  else if (!updated.length) lines.push('**No changes.** No candidate passed all four promotion gates.');
  return lines.join('\n').trim();
}

// ---- schemas --------------------------------------------------------------
const INTAKE_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['lint'],
  properties: {
    date_tag: { type: 'string' },
    base_commit: { type: 'string' },
    dirty_paths: { type: 'array', items: { type: 'string' } },
    sources_present: { type: 'array', items: { type: 'string' }, description: 'harvest mode: which candidate source files exist' },
    lint: {
      type: 'object', additionalProperties: true, required: ['ok'],
      properties: {
        ok: { type: 'boolean', description: 'true only if the JSON parsed' },
        payload: { type: 'object', additionalProperties: true, description: 'the linter JSON VERBATIM — do not summarise, reorder or edit' },
      },
    },
  },
}

const HARVEST_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['candidates'],
  properties: {
    candidates: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: true, required: ['text', 'technique_type'],
        properties: {
          text: { type: 'string', description: 'a reusable "When <condition>, <approach>" pattern' },
          technique_type: { type: 'string' },
          evidence: { type: 'string', description: 'where in the source this was observed' },
        },
      },
    },
  },
}

const JUDGE_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['generalizable', 'material', 'not_already_captured', 'minimal_footprint', 'duplicate_search'],
  properties: {
    generalizable: { type: 'boolean', description: 'reusable pattern, not target-specific lore' },
    material: { type: 'boolean', description: 'adds coverage, efficiency or decision-quality for FUTURE engagements' },
    not_already_captured: { type: 'boolean' },
    minimal_footprint: { type: 'boolean' },
    duplicate_search: {
      type: 'array',
      description: 'MANDATORY. Each grep you actually ran. An empty array is treated as an unevidenced novelty claim and rejects the candidate.',
      items: {
        type: 'object', additionalProperties: true, required: ['query', 'hits'],
        properties: { query: { type: 'string' }, hits: { type: 'number' }, closest: { type: 'string', description: 'file:line + the quoted line' } },
      },
    },
    footprint: { type: 'string', enum: ['extend', 'new-section', 'new-file'] },
    no_host_reason: { type: 'string', description: 'REQUIRED when footprint is new-file: the existing files considered and why none can host it' },
    restates_cross_cutting: { type: 'boolean', description: 'true when it restates the brute-force / output-dir / env-reader / skill-update rule' },
    proposed_target: { type: 'string', description: 'repo-relative path' },
    anchor: { type: 'string', description: 'the exact existing "## "/"### " heading to insert under' },
    why: { type: 'string' },
  },
}

const REFUTE_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['refuted'],
  properties: {
    refuted: { type: 'boolean' },
    gate: { type: 'string', enum: ['generalizable', 'material', 'not_already_captured', 'minimal_footprint', ''] },
    reason: { type: 'string' },
    duplicate_at: { type: 'string', description: 'file:line + quoted line, when refuting on not_already_captured' },
  },
}

const AUTHOR_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['content', 'target_path', 'lines_before'],
  properties: {
    content: { type: 'string', description: 'the EXACT markdown to insert — no preamble, no fence around the whole block' },
    target_path: { type: 'string' },
    anchor: { type: 'string' },
    anchor_is_anti_patterns: { type: 'boolean' },
    creates_file: { type: 'boolean' },
    linked_from: { type: 'string', description: 'REQUIRED when creates_file: the file that will link to it' },
    restates_cross_cutting: { type: 'boolean' },
    lines_before: { type: 'number', description: 'from `wc -l < <target>` — run it, do not estimate' },
    links_verified: {
      type: 'array',
      items: { type: 'object', additionalProperties: true, properties: { url: { type: 'string' }, exists: { type: 'boolean' } } },
    },
  },
}

const WRITER_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['written'],
  properties: {
    written: { type: 'number' },
    files: { type: 'array', items: { type: 'object', additionalProperties: true, properties: { path: { type: 'string' }, lines_after: { type: 'number' } } } },
  },
}

const SWEEP_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['clean'],
  properties: {
    clean: { type: 'boolean', description: 'exit code 0 from scripts/check_client_data.py' },
    findings: { type: 'array', items: { type: 'string' } },
  },
}

const LINT_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['ok'],
  properties: { ok: { type: 'boolean' }, payload: { type: 'object', additionalProperties: true } },
}

// ---- validation-failure returns (fail closed; never throw) ----------------
if (INVOKED_BY === 'coordinator') {
  return { status: 'BLOCKED', mode, blocked_reason: 'skill-update is orchestrator-only; a coordinator must not run it (skills/coordination/reference/role-matrix.md).', ...EMPTY }
}
if (mode === 'harvest' && !OUTPUT_DIR) {
  return { status: 'BLOCKED', mode, blocked_reason: 'harvest mode needs {output_dir} — the engagement tree to mine. Use {mode:"learnings", learnings:[...]} to skip harvesting.', ...EMPTY }
}
if (mode === 'learnings' && !LEARNINGS.length) {
  return { status: 'BLOCKED', mode, blocked_reason: 'learnings mode needs a non-empty {learnings:[{text,technique_type}]}.', ...EMPTY }
}
if (mode === 'create' && !CREATE) {
  return { status: 'BLOCKED', mode, blocked_reason: 'create mode needs {create:{name,description}}.', ...EMPTY }
}

// ---- Intake ---------------------------------------------------------------
phase('Intake')

const SOURCES = OUTPUT_DIR ? [
  `${OUTPUT_DIR}/reports/completion-report.md`,
  `${OUTPUT_DIR}/session-memory.md`,
  `${OUTPUT_DIR}/findings/attack-chain.md`,
  `${OUTPUT_DIR}/reports/validation-report.md`,
  `${OUTPUT_DIR}/logs/experiments.md`,
] : []

const intake = await agent(
  `ROLE: SKILL-UPDATE INTAKE RUNNER (deterministic tool-runner; run commands, relay facts — do NOT author, judge or edit). cwd is repo root. You write NOTHING.\n` +
  `Run EXACTLY, in order, and relay each result verbatim:\n` +
  `1. \`date -u +%Y%m%d\` -> date_tag\n` +
  `2. \`git rev-parse HEAD\` -> base_commit\n` +
  `3. \`git status --porcelain skills/\` -> dirty_paths (the path field of every row; [] when clean)\n` +
  `4. \`python3 scripts/skill_linter.py --write-baseline ${BASELINE}\`\n` +
  `   It stores the violation key set for a later delta and prints a SMALL JSON summary. Parse that summary and return it under lint.payload VERBATIM. Set lint.ok=true only if it parsed. It always exits 0 — the JSON is the result, so do not treat any exit code as failure.\n` +
  (SOURCES.length ? `5. For each of these paths run \`test -f <p> && echo <p>\`; return the ones that exist as sources_present: ${SOURCES.join(' ')}\n` : '') +
  `Return INTAKE_SCHEMA. Do not interpret the linter output — relaying it IS the job.`,
  { schema: INTAKE_SCHEMA, label: 'intake', phase: 'Intake', agentType: 'general-purpose' },
).catch(() => null)

const baseline = (intake && intake.lint && intake.lint.ok && intake.lint.payload) || null
if (!baseline || !baseline.baseline_path) {
  return { status: 'BLOCKED', mode, blocked_reason: 'baseline skill_linter --json did not parse; refusing to write without a delta baseline', ...EMPTY }
}
const CAPS = baseline.caps || {}
// No file inventory is relayed any more — the author agent reports lines_before
// from its own `wc -l`, which is the same number without a 200 KB round trip.
const fileIndex = new Map()
const dirtyPaths = new Set((intake && intake.dirty_paths) || [])
const baseCommit = (intake && intake.base_commit) || ''
log(`Baseline: ${baseline.count} pre-existing linter violation(s) stored. Gating on the DELTA.`)

if (mode === 'audit') {
  // Audit is the one mode that wants the detail, so it asks for a SUMMARY of the
  // full payload rather than the payload itself — the agent counts, JS reports.
  const a = await agent(
    `ROLE: SKILL AUDIT RUNNER (deterministic tool-runner; run the command, relay the counts — do NOT author, judge or edit). cwd is repo root.\n` +
    `Run EXACTLY: \`python3 scripts/skill_linter.py --json\`\n` +
    `From its JSON return ONLY: counts.by_code verbatim, counts.violations, counts.files, and over_cap = every files[] entry where cap is non-null and lines > cap, as "<path> <lines>/<cap>" strings.\n` +
    `Do NOT return the full violations or files arrays.`,
    { schema: { type: 'object', additionalProperties: true, required: ['by_code'],
        properties: { by_code: { type: 'object', additionalProperties: true }, violations: { type: 'number' },
                      files: { type: 'number' }, over_cap: { type: 'array', items: { type: 'string' } } } },
      label: 'audit', phase: 'Intake', agentType: 'general-purpose' },
  ).catch(() => null)
  const byCode = (a && a.by_code) || {}
  const overCap = (a && a.over_cap) || []
  const lines = ['**Audit.** Read-only; nothing was written.', '',
    `- Files: ${(a && a.files) || 'unknown'}`,
    `- Violations: ${(a && a.violations) != null ? a.violations : baseline.count} — ${Object.entries(byCode).map(([k, v]) => `${k} ${v}`).join(', ') || 'none'}`,
    `- Over cap: ${overCap.length}${overCap.length ? ` (${overCap.slice(0, 5).join(', ')})` : ''}`]
  return { status: 'AUDIT', mode, counts_by_code: byCode, over_cap: overCap,
           report_markdown: lines.join('\n'), ...EMPTY }
}

// ---- Harvest --------------------------------------------------------------
let candidates = []
if (mode === 'learnings') {
  candidates = LEARNINGS.map((l, i) => ({ id: `arg-${i + 1}`, text: String(l.text), technique_type: l.technique_type || 'other', evidence: l.source || 'caller-supplied' }))
} else if (mode === 'harvest') {
  phase('Harvest')
  const present = (intake && intake.sources_present) || []
  if (!present.length) {
    return { status: 'BLOCKED', mode, blocked_reason: `no harvestable artifact found under ${OUTPUT_DIR} (looked for ${SOURCES.length} known paths)`, ...EMPTY }
  }
  const groups = await parallel(present.slice(0, 5).map((p) => () => agent(
    `ROLE: LEARNING HARVESTER (read-only). Read EXACTLY ONE file: ${p}. Read nothing else in the engagement tree.\n` +
    `Extract at most 6 REUSABLE patterns. Each MUST be written as "When <observable condition>, <approach to try>" — never "on <machine>, Y worked".\n` +
    `Substitute placeholders for every concrete value: <TARGET_IP>, <DC_FQDN>, <DOMAIN>, <USER>, <PORT>.\n` +
    `Drop any candidate that needs a machine name, lab id, target IP, challenge id, preserved flag or writeup attribution to make sense — it is lore, not a pattern.\n` +
    `Classify technique_type from: injection | auth | traversal | ssrf | client-side | api | attack-chain | recon | tooling | privesc | ad | cloud | crypto | binary | mobile | dfir | scenario | other.\n` +
    `Do NOT judge novelty, materiality or placement — a later stage does that. Do NOT edit any file.\n` +
    `Return HARVEST_SCHEMA.`,
    { schema: HARVEST_SCHEMA, label: `harvest:${p.split('/').pop()}`, phase: 'Harvest', agentType: 'Explore' },
  ).catch(() => null)))
  const seen = new Set()
  groups.filter(Boolean).forEach((g, gi) => ((g && g.candidates) || []).forEach((c, ci) => {
    const key = String(c.text || '').toLowerCase().replace(/[^a-z0-9 ]/g, '').slice(0, 80)
    if (!key || seen.has(key)) return
    seen.add(key)
    candidates.push({ id: `h${gi + 1}-${ci + 1}`, text: String(c.text), technique_type: c.technique_type || 'other', evidence: c.evidence || present[gi] })
  }))
} else if (mode === 'create') {
  return { status: 'BLOCKED', mode, blocked_reason: 'create mode is not implemented in this revision; scaffold by hand and re-run mode:"audit" to check conformance.', ...EMPTY }
}

// Machine scrub before any agent spends a token on lore.
const scrubbed = []
candidates = candidates.filter((c) => {
  const s = scrubCheck(c.text)
  if (s.clean) return true
  scrubbed.push({ id: c.id, decision: 'SKIP', reason: `challenge-specific identifiers: ${s.hits.join(', ')}` })
  return false
})

const budget = skillAgentBudget(candidates.length, VOTES, AGENT_BUDGET)
const deferred = candidates.slice(budget.take).map((c) => ({ id: c.id, decision: 'SKIP', reason: 'budget:deferred (raise agent_budget or max_candidates)' }))
candidates = candidates.slice(0, Math.min(budget.take, MAX_CAND))
if (deferred.length) log(`Budget: ${deferred.length} candidate(s) deferred, not dropped.`)
if (!candidates.length) {
  const report = buildChangeReport([...scrubbed, ...deferred], [], { ok: true })
  return { status: 'COMPLETE', mode, counts: { candidates: 0, promoted: 0, skipped: scrubbed.length + deferred.length, written: 0, deferred: deferred.length }, updated_files: [], skipped: [...scrubbed, ...deferred], report_markdown: report }
}
log(`${candidates.length} candidate learning(s) to judge.`)

// ---- Judge ----------------------------------------------------------------
phase('Judge')
const judged = await pipeline(
  candidates,
  (c) => agent(
    `ROLE: SKILL-PROMOTION JUDGE (read-only). Decide whether ONE candidate learning may enter the skill base.\n` +
    `CANDIDATE [${c.id}]: ${c.text}\ntechnique_type: ${c.technique_type}\nobserved at: ${c.evidence}\n\n` +
    `Apply the four gates from skills/skill-update/SKILL.md. ALL FOUR must hold to promote:\n` +
    ` 1 GENERALIZABLE — a reusable pattern, not target-specific lore. No machine names, lab ids, target IPs, preserved flags, writeup attributions.\n` +
    ` 2 MATERIAL — adds coverage, efficiency or decision-quality for FUTURE engagements. "A competent agent already does this" fails.\n` +
    ` 3 NOT ALREADY CAPTURED — you MUST actually search: grep skills/ for the technique's distinctive tokens, at least 2 different queries, and report each query, its hit count, and the closest existing file:line with the quoted line. An empty duplicate_search is treated as an UNEVIDENCED novelty claim and the candidate is rejected.\n` +
    ` 4 MINIMAL FOOTPRINT — prefer extending an existing entry over a new section, and a new section over a new file. footprint:"new-file" REQUIRES no_host_reason naming the existing files you considered and why none can host it.\n\n` +
    `Also set restates_cross_cutting when the learning restates the brute-force / output-dir / env-reader / skill-update rule — those have a single canonical home and must be LINKED, never restated.\n` +
    `Propose the target file (repo-relative) and the EXACT existing "## "/"### " heading it belongs under.\n` +
    `Caps you must respect: SKILL.md <=${CAPS['SKILL.md']}, reference/*.md <=${CAPS.reference}, reference/scenarios/*.md <=${CAPS.scenario}.\n` +
    `Do NOT edit any file. Return JUDGE_SCHEMA.`,
    { schema: JUDGE_SCHEMA, label: `judge:${c.id}`, phase: 'Judge', agentType: 'Explore' },
  ).catch(() => null),
  (j, c) => {
    // Refute only what would otherwise promote — refuting a dead candidate is waste.
    const wouldPromote = j && j.generalizable && j.material && j.not_already_captured && j.minimal_footprint
    if (!wouldPromote) return Promise.resolve({ j, votes: [] })
    return parallel(Array.from({ length: VOTES }, (_, i) => () => agent(
      `ROLE: ADVERSARIAL PROMOTION REFUTER #${i + 1} (blind). Try hard to KILL this promotion. Default to skepticism; refute when uncertain.\n` +
      `CANDIDATE: ${c.text}\nproposed target: ${j.proposed_target || '(none)'}\nclaimed footprint: ${j.footprint || 'extend'}\n\n` +
      `Break exactly ONE gate and say which:\n` +
      ` (1) it is target-specific lore dressed up as a pattern;\n` +
      ` (2) it is not material — any competent agent already does this;\n` +
      ` (3) it is ALREADY captured — find it and cite file:line with the quoted line (the strongest refutation, so search first);\n` +
      ` (4) it is not the minimal footprint — name the existing entry that should have been extended instead.\n` +
      `Return REFUTE_SCHEMA.`,
      { schema: REFUTE_SCHEMA, label: `refute:${c.id}#${i + 1}`, phase: 'Judge', agentType: 'Explore' },
    ).catch(() => null))).then((v) => ({ j, votes: v.filter(Boolean) }))
  },
  // PURE JS — no agent decides anything here.
  (carry, c) => Promise.resolve({ candidate: c, judgment: carry.j, votes: carry.votes,
                                  decision: promotionGate(c, carry.j, carry.votes) }),
)

const results = judged.filter(Boolean)
const promoted = results.filter((r) => r.decision.decision === 'PROMOTE')
const rejected = results.filter((r) => r.decision.decision !== 'PROMOTE').map((r) => r.decision)
log(`Judge: ${promoted.length} promoted, ${rejected.length} skipped/rejected.`)

if (!promoted.length) {
  const report = buildChangeReport([...scrubbed, ...deferred, ...rejected], [], { ok: true })
  return { status: 'COMPLETE', mode, counts: { candidates: results.length, promoted: 0, skipped: rejected.length + scrubbed.length + deferred.length, written: 0, deferred: deferred.length },
           updated_files: [], skipped: [...scrubbed, ...deferred, ...rejected], report_markdown: report }
}

// ---- Route ----------------------------------------------------------------
phase('Route')
const authored = await pipeline(
  promoted,
  (d) => {
    const target = (d.judgment && d.judgment.proposed_target) || ''
    const info = fileIndex.get(target) || {}
    const cap = info.cap || capFor(target, CAPS)
    return agent(
      `ROLE: SKILL BLOCK AUTHOR. Write the EXACT markdown to insert for ONE approved learning. You write NO files.\n` +
      `TARGET FILE: ${target}\nCURRENT LINES: ${info.lines != null ? info.lines : '(unknown — run wc -l)'}\nCAP: ${cap}\nHEADROOM: ${info.lines != null ? cap - info.lines : '(compute it)'} lines\n` +
      `HAS "## Anti-Patterns": ${info.has_anti_patterns === true}\n` +
      `ANCHOR (insert under this existing heading, copied byte-for-byte from the file): ${(d.judgment && d.judgment.anchor) || '(append to end)'}\n` +
      `LEARNING: ${d.candidate.text}\n\n` +
      `Rules — a block violating ANY of these is rejected by a deterministic gate and your work is discarded:\n` +
      ` - Frame it as "When <condition>, <approach>". Use <TARGET_IP>/<DC_FQDN>/<DOMAIN> placeholders; no literal targets, machine names, lab ids, preserved flags or writeup attributions.\n` +
      ` - No "DO NOT" / "MUST NOT" / "NEVER" unless the anchor heading is an Anti-Patterns heading (set anchor_is_anti_patterns).\n` +
      ` - Do NOT restate a cross-cutting rule with a canonical home (brute-force, output-dir, env-reader, skill-update) — LINK to it instead, and set restates_cross_cutting.\n` +
      ` - Every relative link you write MUST be checked: run \`test -e\` on the path RESOLVED RELATIVE TO the target file's directory, and report each in links_verified.\n` +
      ` - Brevity first — challenge every token. No preamble, no "Added:" framing, no meta-commentary, no fence around the whole block.\n` +
      `Run EXACTLY \`wc -l < ${target}\` and report it as lines_before — do not estimate.\n` +
      `Return AUTHOR_SCHEMA.`,
      { schema: AUTHOR_SCHEMA, label: `author:${d.candidate.id}`, phase: 'Route', agentType: 'general-purpose' },
    ).catch(() => null)
  },
  (a, d) => {
    if (!a) return Promise.resolve({ ...d, accepted: false, reason: 'author agent returned no block' })
    const target = a.target_path || (d.judgment && d.judgment.proposed_target) || ''
    const info = fileIndex.get(target) || { lines: a.lines_before }
    // Prefer the linter's inventory; fall back to the author's measured wc -l.
    const lines = info.lines != null ? info.lines : a.lines_before
    const gate = writeGate({ ...a, target_path: target }, { lines }, CAPS)
    if (gate.ok) return Promise.resolve({ ...d, author: { ...a, target_path: target }, accepted: true, gate })
    return Promise.resolve({ ...d, accepted: false, reason: gate.reasons.join('; '), gate })
  },
)

const accepted = authored.filter((a) => a && a.accepted)
const refusedWrites = authored.filter((a) => a && !a.accepted)
  .map((a) => ({ id: a.candidate.id, decision: 'SKIP', reason: a.reason }))
log(`Route: ${accepted.length} block(s) passed the write gate, ${refusedWrites.length} refused.`)

const allSkipped = [...scrubbed, ...deferred, ...rejected, ...refusedWrites]

if (!accepted.length) {
  return { status: 'COMPLETE', mode, counts: { candidates: results.length, promoted: promoted.length, skipped: allSkipped.length, written: 0, deferred: deferred.length },
           updated_files: [], skipped: allSkipped, report_markdown: buildChangeReport(allSkipped, [], { ok: true }) }
}

// ---- Write ----------------------------------------------------------------
const writePlan = accepted.map((a) => ({
  path: a.author.target_path,
  anchor: a.author.anchor || '',
  content: a.author.content,
  expected_after: (fileIndex.get(a.author.target_path) || {}).lines != null
    ? fileIndex.get(a.author.target_path).lines + a.author.content.split('\n').length
    : null,
}))

if (dryRun) {
  return { status: 'DRY_RUN', mode, write_plan: writePlan.map((w) => ({ path: w.path, added_lines: w.content.split('\n').length })),
           counts: { candidates: results.length, promoted: promoted.length, skipped: allSkipped.length, written: 0, deferred: deferred.length },
           updated_files: [], skipped: allSkipped, report_markdown: buildChangeReport(allSkipped, [], { ok: true }) }
}

phase('Write')
const writer = await agent(
  `ROLE: SKILL WRITER (persist verbatim — no judgment, no regeneration, no reformatting). cwd is repo root.\n` +
  `Insert EACH block below into its file, immediately after the given anchor heading and its existing content block, or appended at end of file when the anchor is empty.\n` +
  `Write the content EXACTLY as given, byte-for-byte. Do NOT reword, re-indent, re-wrap, summarise or add framing. Do NOT touch any other file or any other part of these files.\n\n` +
  writePlan.map((w, i) => `--- FILE ${i + 1}: ${w.path} ---\nANCHOR: ${w.anchor || '(append to end)'}\nCONTENT:\n${w.content}`).join('\n\n') +
  `\n\nThen run \`wc -l < <path>\` for each file you touched and report it as files[].lines_after.\n` +
  `Return WRITER_SCHEMA {written: <count>, files: [{path, lines_after}]}.`,
  { schema: WRITER_SCHEMA, label: 'write:persist', phase: 'Write', agentType: 'general-purpose' },
).catch(() => null)

// Independent check that the writer persisted what JS planned — not what it felt like.
const reported = new Map((((writer && writer.files) || [])).map((f) => [f.path, Number(f.lines_after)]))
const mismatches = writePlan.filter((w) => {
  if (w.expected_after == null) return false
  const got = reported.get(w.path)
  return got == null || Math.abs(got - w.expected_after) > 1   // ±1 for a trailing newline
})
const writeOk = !!(writer && Number(writer.written) === writePlan.length && mismatches.length === 0)
if (!writeOk) log(`Write verification: ${mismatches.length} file(s) differ from the planned line count.`)

// ---- Sweep ----------------------------------------------------------------
phase('Sweep')
const sweep = await agent(
  `ROLE: CONFIDENTIALITY SWEEP RUNNER (deterministic tool-runner; run the command, relay the facts — do NOT judge or fix). cwd is repo root.\n` +
  `Run EXACTLY: \`python3 scripts/check_client_data.py\`\n` +
  `Set clean=true only if it exited 0. If it exited non-zero, return every reported line verbatim in findings[].\n` +
  `Do NOT edit any file to make it pass. Return SWEEP_SCHEMA.`,
  { schema: SWEEP_SCHEMA, label: 'sweep:confidentiality', phase: 'Sweep', agentType: 'general-purpose' },
).catch(() => ({ clean: false, findings: ['confidentiality sweep agent error'] }))

const sweepClean = !!(sweep && sweep.clean)
if (!sweepClean) log(`Confidentiality sweep FAILED: ${((sweep && sweep.findings) || []).length} finding(s).`)

// ---- Verify ---------------------------------------------------------------
phase('Verify')
const after = await agent(
  `ROLE: SKILL-UPDATE VERIFY RUNNER (deterministic tool-runner; run the command, relay the JSON — do NOT author, judge or edit). cwd is repo root.\n` +
  `Run EXACTLY: \`python3 scripts/skill_linter.py --delta ${BASELINE}\`\n` +
  `It compares against the baseline this run stored and prints ONLY what this run INTRODUCED — normally an empty list. Parse that JSON and return it under payload VERBATIM. Set ok=true only if it parsed. It always exits 0.\n` +
  `Return LINT_SCHEMA.`,
  { schema: LINT_SCHEMA, label: 'lint:after', phase: 'Verify', agentType: 'general-purpose' },
).catch(() => null)

// The TOOL computes the delta (see --delta): relaying the full ~280 KB payload
// through an agent is slow and lossy — a model asked to echo a quarter-megabyte
// verbatim truncates, silently corrupting the baseline the gate depends on.
// JS still owns the DECISION; it just no longer carries the haystack.
const afterPayload = (after && after.ok && after.payload) || null
const delta = (afterPayload && afterPayload.baseline_ok)
  ? { introduced: afterPayload.introduced || [], resolved: [],
      regressed: !!afterPayload.regressed,
      baseline_count: afterPayload.baseline_count, after_count: afterPayload.after_count }
  : null
const gate = skillUpdateGate({
  baselineOk: true,
  afterOk: !!afterPayload,
  delta,
  writeOk,
  writeMismatch: mismatches.map((m) => m.path).join(', '),
})

// The confidentiality sweep is an independent, non-overridable veto.
const finalGate = (gate.ok && !sweepClean)
  ? { ok: false, status: 'BLOCKED', blocked_reason: `confidentiality sweep failed: ${((sweep && sweep.findings) || []).slice(0, 3).join('; ')}` }
  : gate

if (!finalGate.ok && baseCommit) {
  // Revert ONLY the paths this run planned, and never one that was already dirty
  // at Intake — that would destroy the operator's uncommitted work.
  const revertable = writePlan.map((w) => w.path).filter((p) => !dirtyPaths.has(p))
  const skippedRevert = writePlan.map((w) => w.path).filter((p) => dirtyPaths.has(p))
  if (revertable.length) {
    await agent(
      `ROLE: REVERT RUNNER (deterministic tool-runner; run the command, relay the result — do NOT author or judge). cwd is repo root.\n` +
      `This run was BLOCKED: ${finalGate.blocked_reason}\n` +
      `Restore ONLY these paths to the pre-run commit ${baseCommit}; touch nothing else:\n` +
      `\`git checkout ${baseCommit} -- ${revertable.join(' ')}\`\n` +
      `For any path that did not exist at that commit, \`rm -f\` it instead.\n` +
      `Return {reverted: <count>}.`,
      { schema: { type: 'object', additionalProperties: true, required: ['reverted'], properties: { reverted: { type: 'number' } } },
        label: 'revert', phase: 'Verify', agentType: 'general-purpose' },
    ).catch(() => null)
    log(`Reverted ${revertable.length} path(s) to ${baseCommit.slice(0, 8)}.`)
  }
  if (skippedRevert.length) log(`Left ${skippedRevert.length} path(s) alone — already dirty before this run.`)
}

const written = finalGate.ok ? writePlan.map((w) => ({
  path: w.path,
  summary: (accepted.find((a) => a.author.target_path === w.path) || {}).candidate?.text?.slice(0, 80) || 'content added',
})) : []

return {
  status: finalGate.status,
  mode,
  blocked_reason: finalGate.blocked_reason,
  counts: {
    candidates: results.length,
    promoted: promoted.length,
    skipped: allSkipped.length,
    written: written.length,
    deferred: deferred.length,
    lint_introduced: delta ? delta.introduced.length : null,
    lint_resolved: delta ? delta.resolved.length : null,
  },
  confidentiality_clean: sweepClean,
  updated_files: written.map((w) => w.path),
  skipped: allSkipped,
  report_markdown: buildChangeReport(allSkipped, written, finalGate),
}
