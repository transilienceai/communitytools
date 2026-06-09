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
// Inline P5 validation. Default true (self-contained standalone runs). An
// orchestrator that runs the authoritative validate-findings workflow itself
// (e.g. htb-solve) passes validate:false so we don't double-validate under the
// shared agent cap.
const RUN_VALIDATION = a.validate !== false
// COVERAGE MODE (web/API/cloud pentest) vs default FLAG mode (CTF/HTB). Every
// coverage block below is guarded by `MODE === 'coverage'`, so flag-mode behavior
// — and htb-solve, which passes no `mode` — is byte-identical to before.
const MODE = a.mode === 'coverage' ? 'coverage' : 'flag'
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
    coverage_ratio: { type: 'number', description: 'coverage mode: covered/applicable after this batch' },
    applicable_pending: { type: 'number', description: 'coverage mode: count of applicable classes still pending' },
  },
}

const VALIDATE_FINDING_SCHEMA = {
  type: 'object', additionalProperties: true,
  required: ['finding_id', 'valid'],
  properties: { finding_id: { type: 'string' }, valid: { type: 'boolean' }, summary: { type: 'string' }, proof_dir: { type: 'string' } },
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
  const init = await agent(
    `${DISCIPLINE}\n\nROLE: engagement init. cwd is repo root. Create the engagement directory and return its absolute path. Do NOT recon yet.\n` +
    `TARGET: ${TARGET}\nPLATFORM: ${PLATFORM}\n\n` +
    `Compute a tag: lowercase kebab of the target name/host (or "target-<sanitised>" for an IP/id). date=$(date +%y%m%d). OUTPUT_DIR = ${OUTPUT_BASE}/<date>_<tag>/ (do NOT clobber an existing non-empty dir — append -2 etc. if needed).\n` +
    `Run: mkdir -p OUTPUT_DIR/{recon,findings,logs,artifacts,tools,reports}; write OUTPUT_DIR/stats.json = "{}" ; write OUTPUT_DIR/start_time.txt = $(date -u +%Y-%m-%dT%H:%M:%SZ).\n` +
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
    ? `6. COVERAGE: write OUTPUT_DIR/coverage.json by instantiating the attack-class matrix. For each row set applicability ("applicable" iff its trigger matches the discovered surface, else "not_applicable" with the failed trigger quoted as justification), status "pending" for applicable rows / "NA" for non-applicable, evidence_ref [] (schema: skills/coordination/reference/coverage-matrix.md "Instance-file contract"). Matrix to instantiate:\n${COVERAGE_MATRIX ? JSON.stringify(COVERAGE_MATRIX) : 'READ skills/coordination/reference/coverage-matrix.md and instantiate its full class catalog.'}\n`
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
log(`Bootstrap complete. OUTPUT_DIR=${OUTPUT_DIR}. Loop budget: ${MAX_EXPERIMENTS} experiments / ${MAX_BATCHES} batches.`)

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
      ? `COVERAGE: also READ OUTPUT_DIR/coverage.json — your completion obligation. Rank the applicable pending classes by value (impact x likelihood-on-this-surface x low-credential reachability; a high-impact class reachable with no/low creds ranks first). AT LEAST ONE chosen mission this batch MUST target the highest-value pending class: set its covers_class and mount that class's scenario file (per skills/coordination/reference/coverage-matrix.md). Mark a class NA only with a justification quoting the unmet applicability trigger — never to skip testing it. Populate coverage_state.\n\n`
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

function integratePrompt(batch, execResults, resetMode) {
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
      ? `6. COVERAGE: update OUTPUT_DIR/coverage.json — for every class a mission this batch probed, set status:covered with evidence_ref = the E-NNN row(s)/finding dir(s) just created (NEVER covered without a real evidence_ref), OR status:NA with a trigger-quoting justification if the surface proves it inapplicable. Report coverage_update[], coverage_ratio, and applicable_pending (count of applicable classes still pending). In coverage mode set goal_reached=true ONLY when applicable_pending==0.\n`
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

function validateFindingPrompt(f) {
  return `ROLE: FINDING VALIDATOR (blind, independent). Read ONLY skills/coordination/reference/VALIDATION.md for the 6-check procedure. Do NOT read attack-chain.md, session-memory.md, other findings, executor logs, or skill files — you judge from the evidence package alone.\n` +
    `finding_id: ${f.id}\nFINDING_DIR: ${f.dir}\nTARGET: ${TARGET}\nOUTPUT_DIR: ${OUTPUT_DIR}/artifacts\n\n` +
    `Run all 6 checks (CVSS consistency; evidence files present; PoC parses + references target + re-runs when safe; every factual claim corroborated by a raw scan/log; executor log shows recon/experiment/test/verify with timestamps >=2s apart; AND check 6 root-cause severity floor — REJECT for UNDER-rating when the description asserts a latent higher impact from a CONFIRMED missing control but scores C/I/A only on a demonstrated sub-impact capped by a transient/reversible condition, recomputing per pentest-report.md section 7.1). ALL must PASS or the verdict is REJECTED. On any CVE: python3 tools/nvd-lookup.py <CVE-ID> and flag >1.0 divergence from NVD.\n` +
    `Write the verdict JSON to ${OUTPUT_DIR}/artifacts/validated/${f.id}.json (VALID) or ${OUTPUT_DIR}/artifacts/false-positives/${f.id}.json (REJECTED), and the proof package to ${f.dir}/evidence/validation/ (validation-summary.md always; poc-rerun-output.txt; verification-script.py — standalone, must not import the executor poc; code-references.md when code claims; screenshots for web). Return VALIDATE_FINDING_SCHEMA.`
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
const skepticBriefs = []
const findings = []

while (exp < MAX_EXPERIMENTS && batch < MAX_BATCHES) {
  batch++

  // --- P2: Think (+ P4b reset folded in) ---
  const think = await agent(thinkPrompt(batch, resetMode, resetGoal, skepticBriefs.slice(-2)), {
    schema: THINK_SCHEMA, label: `think:b${batch}`, phase: 'Loop', agentType: 'general-purpose',
  })
  if (!think) { terminated = true; terminateReason = 'think agent returned null'; break }
  if (think.terminate) {
    // Coverage mode: a premature terminate is overridden while applicable classes
    // remain pending. "I ran out of hypotheses / hit a goal" is not completion.
    if (MODE === 'coverage' && coveragePending !== 0) {
      log(`coverage: ignoring premature think.terminate — ${coveragePending === Infinity ? 'classes still' : coveragePending} pending`)
      think.terminate = false
    } else {
      terminated = true; terminateReason = think.terminate_reason || 'think requested terminate'; break
    }
  }

  const missions = (think.chosen || []).slice(0, 2)
  if (!missions.length) { terminated = true; terminateReason = 'think produced no missions'; break }

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
  const integ = await agent(integratePrompt(batch, execResults, resetMode), {
    schema: INTEGRATE_SCHEMA, label: `integrate:b${batch}`, phase: 'Loop', agentType: 'general-purpose',
  })
  resetMode = false
  if (!integ) { terminated = true; terminateReason = 'integrate returned null'; break }

  prevExp = exp
  exp = integ.exp_count > exp ? integ.exp_count : exp + 1 // never stall the counter
  for (const f of (integ.new_findings || [])) if (f && f.id) findings.push(f)

  // Coverage bookkeeping — counts come from the INTEGRATE agent (no FS in the sandbox).
  let coverageAdvanced = false
  if (MODE === 'coverage' && typeof integ.applicable_pending === 'number') {
    coverageAdvanced = integ.applicable_pending < prevPending
    prevPending = integ.applicable_pending
    coveragePending = integ.applicable_pending
  }

  log(`batch ${batch}: experiments=${exp} progress=${integ.progress}${MODE === 'coverage' ? ` pending=${coveragePending}` : ''} ${integ.goal_reached ? 'GOAL_REACHED' : ''}${integ.recommend_reset ? ' (reset queued)' : ''}`)

  // Completion: flag mode -> goal_reached; coverage mode -> every applicable class covered/NA.
  const done = MODE === 'coverage' ? (coveragePending === 0 || integ.goal_reached) : integ.goal_reached
  if (done) { solved = true; break }
  if (integ.terminate) {
    if (MODE === 'coverage' && coveragePending !== 0) {
      log(`coverage: ignoring integrate terminate — ${coveragePending} classes pending`)
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

if (!solved && !terminated && batch >= MAX_BATCHES) terminateReason = `batch cap (${MAX_BATCHES}) reached — agent-spawn backstop`
if (!solved && !terminated && exp >= MAX_EXPERIMENTS) terminateReason = `experiment budget (${MAX_EXPERIMENTS}) exhausted`
log(`Loop ended after ${batch} batches / ${exp} experiments. solved=${solved}. ${terminateReason}`)

// ============================================================================
// PHASE: Validate (P5) — blind finding-validators + engagement-validator
// ============================================================================
phase('Validate')

// de-dup finding ids
const uniqFindings = []
const seen = new Set()
for (const f of findings) { if (f && f.id && !seen.has(f.id)) { seen.add(f.id); uniqFindings.push(f) } }

if (!RUN_VALIDATION) {
  log(`Inline validation skipped (validate:false) — orchestrator runs the authoritative validate-findings workflow. ${uniqFindings.length} finding(s) pending validation.`)
}

let validated = []
if (RUN_VALIDATION && uniqFindings.length) {
  const verdicts = await parallel(uniqFindings.map(f => () =>
    agent(validateFindingPrompt(f), { schema: VALIDATE_FINDING_SCHEMA, label: `validate:${f.id}`, phase: 'Validate', agentType: 'general-purpose' })
  ))
  validated = verdicts.filter(Boolean)
}

let engagement = null
if (RUN_VALIDATION && (uniqFindings.length || MODE === 'coverage')) {
  engagement = await agent(
    `ROLE: ENGAGEMENT VALIDATOR (blind, thoroughness audit). Read ONLY skills/coordination/reference/VALIDATION.md and skills/coordination/reference/validator-role.md (Engagement Validator checks); judge from the OUTPUT_DIR directory state — NOT from attack-chain.md or finding internals.\n` +
    `OUTPUT_DIR: ${OUTPUT_DIR}\n\n` +
    (MODE === 'coverage'
      ? `Run the 8 thoroughness checks. Checks 1-7: port coverage vs experiments.md; share enumeration anon+guest (NA for pure web); source-code coverage; >=1 tested [wildcard] hypothesis; mandatory skeptic-brief-{5,15,25...} exist for the counts reached; time-to-first-finding <= 0.3*duration; zero AskUserQuestion calls. CHECK 8 attack-class coverage: read OUTPUT_DIR/coverage.json, compute coverage_ratio = covered/applicable (a covered row needs a resolvable evidence_ref — a present E-NNN row or finding dir — else treat it as pending; every not_applicable row needs a justification), and FAIL (engagement_status=GAPS_FOUND) if coverage_ratio < 0.80, listing the pending class_ids in remediation. Set coverage_ratio in the return.`
      : `Run the 7 thoroughness checks (port coverage vs experiments.md; share enumeration anon+guest; source-code coverage; >=1 tested [wildcard] hypothesis; mandatory skeptic-brief-{5,15,25...} exist for the counts reached; time-to-first-finding <= 0.3*duration; zero AskUserQuestion calls).`) +
    ` Write artifacts/engagement-validation.json + artifacts/engagement-validation-summary.md. Return ENGAGEMENT_SCHEMA.`,
    { schema: ENGAGEMENT_SCHEMA, label: 'validate:engagement', phase: 'Validate', agentType: 'general-purpose' }
  )
}

const confirmed = validated.filter(v => v && v.valid)

// ============================================================================
// PHASE: Report
// ============================================================================
phase('Report')

// When validation is delegated, gauge "has findings" by the raw count, not by
// the (empty) confirmed set — the authoritative pass runs at the orchestrator.
const hasFindings = RUN_VALIDATION ? confirmed.length : uniqFindings.length
const coverageGapFail = MODE === 'coverage' && engagement && engagement.engagement_status === 'GAPS_FOUND'
const status = MODE === 'coverage'
  ? ((solved && !coverageGapFail) ? 'COVERAGE_COMPLETE' : 'INCOMPLETE_COVERAGE')
  : (solved ? 'SUCCESS' : (hasFindings ? 'FAILED_partial' : (terminateReason.includes('budget') || terminateReason.includes('cap') ? 'EXHAUSTED' : 'BLOCKED')))

// Report format: transilience (per-asset source + JSON; the orchestrator renders the
// engagement PDF) vs the default HTB completion report.
const reportFmtInstr = REPORT_FORMAT === 'transilience'
  ? `Write OUTPUT_DIR/reports/pentest-report-source.md + OUTPUT_DIR/artifacts/pentest-report.json for THIS asset per formats/transilience-report-style/pentest-report.md (Finding Quality Standard; severity per §7.1 root-cause floor — a transient/reversible state is never a severity ceiling). Summarize the coverage.json status (covered / NA / pending per class). Do NOT render a PDF — the engagement orchestrator aggregates all assets into the final Transilience PDF.`
  : `Write OUTPUT_DIR/reports/completion-report.md per formats/htb-completion-report.md (all 8 sections; Attack Chain is a 3-8 sentence narrative; every vuln carries a CVSS; Lessons Learned + Failed Approaches from session-memory.md Dead Ends).`

const report = await agent(
  `${DISCIPLINE}\n\nROLE: coordinator REPORT (P6). cwd is repo root.\n` +
  `OUTPUT_DIR: ${OUTPUT_DIR}\nGOAL: ${GOAL}\nMODE: ${MODE}\nSTATUS: ${status}\nsolved=${solved}; experiments=${exp}; batches=${batch}; end_reason="${terminateReason}"${MODE === 'coverage' ? `; applicable_pending=${coveragePending}; coverage_ratio=${engagement && typeof engagement.coverage_ratio === 'number' ? engagement.coverage_ratio : 'n/a'}` : ''}\n` +
  (RUN_VALIDATION
    ? `Validated findings: ${JSON.stringify(confirmed.map(c => c.finding_id))}\nEngagement thoroughness: ${engagement ? engagement.engagement_status : 'n/a (no findings)'}\n\n${reportFmtInstr} Use ONLY validated findings in the body; rejected ones live only in artifacts/false-positives/.`
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
  validation_delegated: !RUN_VALIDATION,
  findings_confirmed: RUN_VALIDATION ? confirmed.map(c => ({ id: c.finding_id, summary: c.summary })) : uniqFindings.map(f => ({ id: f.id, summary: 'pending validation' })),
  findings_total: uniqFindings.length,
  engagement_status: engagement ? engagement.engagement_status : null,
  coverage_status: MODE === 'coverage' ? status : null,
  coverage_pending: MODE === 'coverage' ? coveragePending : null,
  coverage_ratio: engagement && typeof engagement.coverage_ratio === 'number' ? engagement.coverage_ratio : null,
  report_path: report ? report.report_path : `${OUTPUT_DIR}/reports/${REPORT_FORMAT === 'transilience' ? 'pentest-report-source.md' : 'completion-report.md'}`,
  narrative: report ? report.narrative : '',
}
