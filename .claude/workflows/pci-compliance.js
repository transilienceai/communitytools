export const meta = {
  name: 'pci-compliance',
  description: 'Automated PCI Secure Software Standard (SSS) v2.0 readiness gap-assessment of an application. Ingests a scope file (source/docs/BOM paths, running-instance, declared assets, module hints, RoE), fingerprints the tech stack, makes evidence-backed applicability decisions per conditional Security Objective (4,7) and Module (A/B/C/D), loads the deterministic Test-Requirement catalog and filters to the applicable work-list, then per atomic Test Requirement: an assessor proposes a verdict with cited evidence, N blind adversarial refuters attack every MET/NOT_MET, a verdict agent applies the kill rules (MET requires verified evidence else REQUIRES_MANUAL_REVIEW; dynamic-required-but-not-run is never a faked MET), the deterministic citation_verify.py greps every citation, a coverage gate requires every applicable requirement to have a verdict, and a Transilience gap report (PDF + JSON + tracker.csv) is produced. Sharded by mode so the full standard stays within the agent budget. Output is a READINESS / GAP analysis, explicitly NOT an official PCI validation.',
  whenToUse: 'Run a PCI SSS v2.0 readiness/gap-assessment. mode:"intake" {scope_file|scope} -> returns engagement_dir + applicable objectives; mode:"assess" {engagement_dir, objective} -> assesses one Security Objective; mode:"report" {engagement_dir} -> Verify + Report; mode:"full" runs everything (small/limited apps). Options: votes(3), maxConcurrent(4), dryRun, max_requirements.',
  phases: [
    { title: 'Intake', detail: 'parse scope, env-reader creds, OUTPUT_DIR, tech-stack fingerprint' },
    { title: 'Applicability', detail: 'evidence-backed AppContext (NOT_APPLICABLE needs negative evidence) -> deterministic work-list' },
    { title: 'Assess', detail: 'per Test Requirement: assessor (cited evidence) -> N blind refuters -> verdict (kill rules)' },
    { title: 'Verify', detail: 'deterministic citation_verify.py + coverage gate + rollup' },
    { title: 'Report', detail: 'Transilience gap PDF + compliance-report.json + tracker.csv' },
  ],
}

const CATALOG = 'skills/pci-secure-software/reference/catalog/pci-sss-v2.0.json'

// ---- arg normalization (mirrors pentest-engagement.js) ----
let __raw = args
if (typeof __raw === 'string') {
  const s = __raw.trim()
  if (s.startsWith('{') || s.startsWith('[')) { try { __raw = JSON.parse(s) } catch (e) { __raw = { scope_file: __raw } } }
  else __raw = { scope_file: __raw }
}
const input = (__raw && typeof __raw === 'object' && !Array.isArray(__raw)) ? __raw : {}
const mode = ['intake', 'assess', 'report', 'full'].includes(input.mode) ? input.mode : 'full'
const VOTES = Number(input.votes) > 0 ? Math.floor(Number(input.votes)) : 3
const MAX_REQ = Number(input.max_requirements) > 0 ? Math.floor(Number(input.max_requirements)) : 0
const dryRun = !!input.dryRun
const scopeArg = input.scope_file ? JSON.stringify({ scope_file: input.scope_file }) : JSON.stringify({ scope: input.scope || null })

const MAJORITY = Math.floor(VOTES / 2) + 1   // refuters needed to kill an affirmative verdict

const SCENARIO = {
  '1': 'architecture-composition', '2': 'sensitive-assets', '3': 'sensitive-assets', '6': 'sensitive-assets',
  '4': 'protection-and-modes', '5': 'protection-and-modes',
  '7': 'crypto-key-management', '8': 'crypto-key-management', '9': 'crypto-key-management',
  '10': 'threats-and-deployment', '11': 'threats-and-deployment',
  'A1': 'module-a-account-data', 'B1': 'module-b-poi', 'B2': 'module-b-poi', 'B3': 'module-b-poi',
  'C1': 'module-c-web', 'C2': 'module-c-web', 'C3': 'module-c-web', 'C4': 'module-c-web', 'D1': 'module-d-sdk',
}
const scenarioPath = (obj) => `skills/pci-secure-software/reference/scenarios/${SCENARIO[String(obj)] || 'sensitive-assets'}.md`

// ====================== SCHEMAS ======================
const SCOPE_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['ok', 'date_tag', 'engagement_dir', 'app_name'],
  properties: {
    ok: { type: 'boolean' }, date_tag: { type: 'string' }, app_name: { type: 'string' },
    engagement_dir: { type: 'string' }, blocked_global: { type: ['string', 'null'] },
    source_paths: { type: 'array', items: { type: 'string' } },
    docs_paths: { type: 'array', items: { type: 'string' } },
    bom_paths: { type: 'array', items: { type: 'string' } },
    running_instance: { type: ['object', 'null'], additionalProperties: true },
    declared_assets: { type: 'array', items: { type: 'object', additionalProperties: true } },
    module_hints: { type: 'object', additionalProperties: true },
    tech_stack: { type: 'object', additionalProperties: true },
    roe: { type: 'object', additionalProperties: true },
    creds: { type: 'object', additionalProperties: true }, notes: { type: 'array', items: { type: 'string' } },
  },
}
const APPLICABILITY_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['ok', 'app_context', 'applicable_objectives', 'applicable_count'],
  properties: {
    ok: { type: 'boolean' },
    app_context: { type: 'object', additionalProperties: true,
      properties: { account_data: {type:'boolean'}, sensitive_mode:{type:'boolean'}, random_for_sensitive_assets:{type:'boolean'},
        pts_poi_device:{type:'boolean'}, public_network_interface:{type:'boolean'}, is_sdk:{type:'boolean'}, sred_approved:{type:'boolean'} } },
    decisions: { type: 'array', items: { type: 'object', additionalProperties: true } },
    applicable_modules: { type: 'array', items: { type: 'string' } },
    applicable_objectives: { type: 'array', items: { type: 'string' } },
    applicable_count: { type: 'number' }, dynamic_blocked_count: { type: 'number' },
    running_instance_available: { type: 'boolean' }, notes: { type: 'array', items: { type: 'string' } },
  },
}
const LOADER_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['objective', 'reqs'],
  properties: { objective: { type: 'string' }, reqs: { type: 'array', items: { type: 'object', additionalProperties: true } } },
}
const ASSESS_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['req_id', 'proposed_status', 'evidence'],
  properties: {
    req_id: { type: 'string' },
    proposed_status: { type: 'string', enum: ['MET', 'NOT_MET', 'PARTIALLY_MET', 'NOT_APPLICABLE', 'REQUIRES_MANUAL_REVIEW'] },
    evidence: { type: 'array', items: { type: 'object', additionalProperties: true,
      properties: { source_file:{type:'string'}, source_lineno:{type:['number','null']}, quoted_text:{type:'string'}, sha256:{type:'string'}, evidence_type:{type:'string'} } } },
    applicability_evidence: { type: 'array', items: { type: 'object', additionalProperties: true } },
    analysis_performed: { type: 'array', items: { type: 'string' } },
    dynamic_required_not_run: { type: 'boolean' },
    why: { type: 'string' }, remediation: { type: 'string' }, confidence: { type: 'number' },
  },
}
const REFUTE_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['refuted'],
  properties: { refuted: { type: 'boolean' }, reason: { type: 'string' }, weakest_link: { type: 'string' }, citation_doubt: { type: 'boolean' } },
}
const VERDICT_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['req_id', 'status'],
  properties: {
    req_id: { type: 'string' },
    status: { type: 'string', enum: ['MET', 'NOT_MET', 'PARTIALLY_MET', 'NOT_APPLICABLE', 'REQUIRES_MANUAL_REVIEW'] },
    downgraded_from: { type: ['string', 'null'] }, refuted_count: { type: 'number' }, votes: { type: 'number' },
    why: { type: 'string' }, remediation: { type: 'string' }, proof_dir: { type: 'string' }, wrote_to: { type: 'string' },
  },
}
const VERIFY_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['coverage_ratio'],
  properties: { coverage_ratio: { type: 'number' }, applicable: { type: 'number' }, emitted: { type: 'number' },
    missing_ids: { type: 'array', items: { type: 'string' } }, quarantined: { type: 'number' }, complete: { type: 'boolean' },
    rollup: { type: 'object', additionalProperties: true } },
}
const REPORT_SCHEMA = {
  type: 'object', additionalProperties: true, required: ['ok'],
  properties: { ok: { type: 'boolean' }, report_path: { type: 'string' }, json_path: { type: 'string' }, tracker_path: { type: 'string' },
    report_verify_ok: { type: 'boolean' }, report_verify_failures: { type: 'array', items: { type: 'string' } } },
}

// ====================== PHASE FUNCTIONS ======================
async function runIntake() {
  phase('Intake')
  const setup = await agent(
    `You are the INTAKE step of the pci-compliance orchestrator (PCI Secure Software Standard v2.0 gap-assessment). cwd is the repo root. Do real work with Bash/Read/Write. Do NOT assess requirements yet. Read skills/pci-secure-software/SKILL.md and skills/coordination/reference/credential-loading.md first.

SCOPE_INPUT: ${scopeArg}
DRY_RUN: ${dryRun}

Do:
1) PARSE SCOPE. If scope_file is given, READ it; else use inline scope. Normalize to SCOPE_SCHEMA: app_name (kebab); source_paths[]; docs_paths[]; bom_paths[]; running_instance{available,base_url,creds_env[]}; declared_assets[] (each {kind:PAN|SAD|crypto-key|credential|PII|other, location, notes}); module_hints{A,B,C,D}; roe{read_only(default true), dynamic_analysis_authorized(default = running_instance.available), prohibitions[]}.
2) CREDS: if any creds_env are named, run python3 tools/env-reader.py <NAMES...>. Record creds.present (NAMES only, never values). A missing credential is NOT a global block. Set blocked_global ONLY if NO source AND NO docs are reachable on disk.
3) DATE TAG + OUTPUT_DIR (do this BEFORE writing any engagement file): date_tag=$(date +%y%m%d). engagement_dir=projects/compliance/outputs/<date_tag>_<app_name>/ (append -2 if a non-empty dir already exists). Create the tree: recon/ applicability/ findings/ artifacts/validated artifacts/false-positives reports/ logs/. Then write engagement-scope.json (the normalized scope) and engagement-meta.json ({app_name, started:$(date -u +%Y-%m-%dT%H:%M:%SZ), creds_present, roe, running_instance_available}).
4) FINGERPRINT: from source_paths + bom_paths derive tech_stack{languages[],frameworks[],datastores[],crypto_libs[],web_surface(bool),payment_surface(bool)} (mount skills/techstack-identification/SKILL.md if useful). Write <engagement_dir>/recon/tech-stack.json.

Return SCOPE_SCHEMA. Never print secret values.`,
    { schema: SCOPE_SCHEMA, agentType: 'general-purpose', label: 'intake', phase: 'Intake' }
  ).catch(() => null)
  if (!setup || !setup.ok || setup.blocked_global) {
    const reason = setup ? (setup.blocked_global || 'intake ok:false') : 'no intake result'
    log(`Intake blocked: ${reason}`)
    return { status: 'BLOCKED', reason, setup }
  }
  const engagementDir = (setup.engagement_dir || '').replace(/\/+$/, '')
  const roe = setup.roe || {}
  const dynOK = !!(roe.dynamic_analysis_authorized) && !!(setup.running_instance && setup.running_instance.available)
  log(`Intake ok. dir=${engagementDir}; running_instance=${dynOK}`)

  phase('Applicability')
  const applic = await agent(
    `ROLE: PCI SSS v2.0 APPLICABILITY analyst. cwd is repo root. Decide which conditional Security Objectives and Modules apply to THIS app, with evidence, then build the deterministic work-list. Mount skills/pci-secure-software/reference/core/applicability.md. Use skills/source-code-scanning for grep-based asset detection.

OUTPUT_DIR: ${engagementDir}
SOURCE_PATHS / DOCS_PATHS / DECLARED_ASSETS / MODULE_HINTS / TECH_STACK: read \${OUTPUT_DIR}/engagement-scope.json and recon/tech-stack.json.
RUNNING_INSTANCE_AVAILABLE: ${dynOK}

Do:
1) Determine the 7-key AppContext booleans (account_data, sensitive_mode, random_for_sensitive_assets, pts_poi_device, public_network_interface, is_sdk, sred_approved). CORE always applies. Setting a key TRUE needs positive evidence; setting a key FALSE (excluding its Module/objective) needs NEGATIVE evidence — record the exact search that returned nothing (e.g. PAN regex for account_data, RNG call sites for random_for_sensitive_assets, public listener/route for public_network_interface). When ambiguous, default TRUE (conservative). Operator module_hints are advisory only.
2) Write per-decision evidence to \${OUTPUT_DIR}/applicability/<scope_unit>.md and a machine record \${OUTPUT_DIR}/applicability/decisions.json (array of {scope_unit, decision:APPLICABLE|NOT_APPLICABLE, why, evidence:[{file,line,quote,kind:positive|negative}]}).
3) RUN the deterministic filter (this is what makes enumeration non-hallucinated):
   python3 tools/pci-sss/applicability.py --context '<the 7 booleans as JSON>' --out-dir ${engagementDir}${dynOK ? ' --running-instance' : ''}
   This writes applicability/{applicable.jsonl,not-applicable.jsonl,work-list.json}. Read work-list.json counts.
Return APPLICABILITY_SCHEMA: app_context, decisions, applicable_modules (always includes "core"), applicable_objectives (distinct objective codes present in applicable.jsonl, e.g. ["1",...,"11","A1","C2"]), applicable_count, dynamic_blocked_count, running_instance_available=${dynOK}.`,
    { schema: APPLICABILITY_SCHEMA, agentType: 'general-purpose', label: 'applicability', phase: 'Applicability' }
  ).catch(() => null)
  if (!applic || !applic.ok || !applic.applicable_count) {
    return { status: 'BLOCKED', reason: 'applicability failed or empty work-list', engagement_dir: engagementDir, applic }
  }
  log(`Applicability: modules=${(applic.applicable_modules || []).join(',')}; objectives=${(applic.applicable_objectives || []).join(',')}; ${applic.applicable_count} Test Requirements (${applic.dynamic_blocked_count || 0} dynamic-blocked).`)
  return {
    status: 'INTAKE_DONE', engagement_dir: engagementDir, date_tag: setup.date_tag, app_name: setup.app_name,
    running_instance: dynOK, applicable_objectives: applic.applicable_objectives, applicable_modules: applic.applicable_modules,
    applicable_count: applic.applicable_count,
  }
}

function assessPrompt(r, engagementDir) {
  return `ROLE: PCI SSS v2.0 REQUIREMENT ASSESSOR. cwd is repo root. Assess ONE atomic Test Requirement against the application's source/docs and propose a verdict WITH cited evidence. Mount ${scenarioPath(r.objective)} (the objective playbook) and skills/pci-secure-software/reference/core/schema.md. Use skills/source-code-scanning and the playbook's named sub-skills for evidence gathering. Do NOT read other requirements' verdicts.

TEST REQUIREMENT: ${r.id}  (objective ${r.objective}, security_requirement ${r.requirement_id}, module ${r.module})
REQUIREMENT TEXT: ${r.requirement_text || ''}
TEST REQUIREMENT TEXT: ${r.test_requirement_text || ''}
TEST METHOD: ${r.test_method}   ANALYSIS TYPE: ${r.analysis_type}   DYNAMIC_BLOCKED: ${!!r.dynamic_blocked}
OUTPUT_DIR: ${engagementDir}  (app source/docs paths, and any running-instance base_url/creds, are in engagement-scope.json)

DYNAMIC_BLOCKED is authoritative: it is true exactly when this requirement needs dynamic analysis AND no authorized running instance is in scope. Rules:
- MET or NOT_MET REQUIRE >=1 cited evidence item {source_file, source_lineno, quoted_text (EXACT verbatim line a deterministic grep will find), sha256 (shasum -a 256 of the file), evidence_type}. No verbatim quote => you may NOT return MET/NOT_MET.
- If DYNAMIC_BLOCKED is true -> set dynamic_required_not_run=true and proposed_status=REQUIRES_MANUAL_REVIEW. NEVER fake a dynamic MET from docs/static reading.
- If DYNAMIC_BLOCKED is false AND this is a dynamic/negative test, a running instance IS in scope (see engagement-scope.json): perform the test (attempt the bypass the text describes) and record a dynamic_observation as evidence.
- PARTIALLY_MET only when some lettered sub-conditions are met and others not, each with its own cited evidence.
- NOT_APPLICABLE only with negative evidence (the search you ran returning nothing) in applicability_evidence.
Write your reasoning + cited snippets to ${engagementDir}/findings/${r.id}/ (assessment.md + an evidence/ dir). Return ASSESS_SCHEMA. Set analysis_performed to the methods you actually used.`
}
function refuterPrompt(r, assess, i) {
  return `ROLE: ADVERSARIAL COMPLIANCE REFUTER #${i} (blind). REFUTE the proposed verdict for PCI SSS v2.0 Test Requirement ${r.id}. You see ONLY this requirement and its evidence package — NOT other requirements, NOT the assessor's reasoning, NOT other refuters. Default to skepticism. Mount skills/pci-secure-software/reference/agents/refutation-validator.md.

REQUIREMENT TEXT: ${r.requirement_text || ''}
TEST REQUIREMENT TEXT: ${r.test_requirement_text || ''}
PROPOSED: status=${assess.proposed_status}; evidence=${JSON.stringify(assess.evidence || [])}; why=${JSON.stringify(assess.why || '')}

Independently check: (1) Does each quoted snippet ACTUALLY appear at the cited source_file:source_lineno? You MAY grep/Read it yourself — if a quote is absent, misquoted, or fabricated, set citation_doubt=true. (2) Does the cited evidence genuinely satisfy the test requirement text, or is it incidental/over-claimed? (3) For a MET: could the same evidence exist in a NON-compliant app? If yes, it is insufficient -> refuted. Return REFUTE_SCHEMA {refuted, reason, weakest_link, citation_doubt}.`
}
// Deterministic kill-rule: decide the final status in JS (no LLM discretion) from the
// assessor's proposal + the blind refuter votes. The writer agent only RECORDS this.
function decideVerdict(assess, votes, r) {
  const proposed = assess && assess.proposed_status
  const refuted = (votes || []).filter(v => v && v.refuted).length
  const citeDoubt = (votes || []).some(v => v && v.citation_doubt)
  const hasEvidence = Array.isArray(assess && assess.evidence) && assess.evidence.length > 0
  const hasApplEv = Array.isArray(assess && assess.applicability_evidence) && assess.applicability_evidence.length > 0
  // dynamic_blocked is the AUTHORITATIVE flag (set by applicability.py), independent of the
  // assessor's self-reported dynamic_required_not_run — never trust the LLM to gate dynamic.
  const dynBlocked = !!(r && r.dynamic_blocked) || !!(assess && assess.dynamic_required_not_run)
  let status = proposed, downgraded_from = null
  const downgrade = () => { if (status !== 'REQUIRES_MANUAL_REVIEW') { downgraded_from = status; status = 'REQUIRES_MANUAL_REVIEW' } }
  if (dynBlocked) downgrade()
  else if (proposed === 'MET' || proposed === 'NOT_MET' || proposed === 'PARTIALLY_MET') {
    if (!hasEvidence || citeDoubt || refuted >= MAJORITY) downgrade()
  } else if (proposed === 'NOT_APPLICABLE') {
    if (!hasApplEv) downgrade()
  } else if (proposed !== 'REQUIRES_MANUAL_REVIEW') {
    status = 'REQUIRES_MANUAL_REVIEW'   // unknown/empty proposal -> manual review
  }
  return { status, downgraded_from, refuted }
}
function verdictWritePrompt(r, assess, finalStatus, downgradedFrom, refuted, actualVotes, engagementDir) {
  return `ROLE: COMPLIANCE VERDICT WRITER for PCI SSS v2.0 Test Requirement ${r.id}. cwd is repo root. The final status has ALREADY been decided by a deterministic kill-rule. RECORD it faithfully — do NOT change it. Mount skills/pci-secure-software/reference/core/schema.md.

FINAL STATUS (record EXACTLY this): ${finalStatus}${downgradedFrom ? `   [downgraded_from ${downgradedFrom} by the kill-rule]` : ''}
PROPOSED (from the assessor): ${JSON.stringify(assess)}
ADVERSARIAL VOTES: ${actualVotes} run, ${refuted} refuted.

Build the RequirementVerdict JSON (schema.md §3):
- test_requirement_id="${r.id}", status="${finalStatus}".
- evidence: carry the assessor's proposed evidence items VERBATIM (do NOT invent or alter quotes/line numbers — the deterministic citation verifier greps them next). A downgraded verdict may still carry the proposed evidence for traceability.
- applicability_evidence (for NOT_APPLICABLE), analysis_performed, why (explain the status; if downgraded, state why), remediation (for NOT_MET/PARTIALLY_MET).
- control_ref {framework:"PCI_SSS_v2.0", test_requirement_id:"${r.id}", requirement_id:"${r.requirement_id}", objective:"${r.objective}", version:"2.0"}.
- analysis_type:"${r.analysis_type}", dynamic_blocked:${!!(r && r.dynamic_blocked)}  (carry these verbatim — the deterministic verifier uses them to enforce the dynamic-evidence rule).
- votes:${actualVotes} (the number of adversarial refuters that ACTUALLY ran), refuted_count:${refuted}, downgraded_from:${downgradedFrom ? `"${downgradedFrom}"` : 'null'}, proof_dir:"findings/${r.id}/evidence/".
- chain_of_custody.created_at from: date -u +%Y-%m-%dT%H:%M:%SZ.
WRITE the JSON to ${engagementDir}/artifacts/validated/${r.id}.json.${downgradedFrom ? ` ALSO write the downgrade record (status + downgraded_from + the refuter reasons) to ${engagementDir}/artifacts/false-positives/${r.id}.json.` : ''}
You MUST NOT record any status other than "${finalStatus}". Return VERDICT_SCHEMA with wrote_to=the validated path.`
}

const AFFIRMATIVE = new Set(['MET', 'NOT_MET', 'PARTIALLY_MET'])

async function assessObjective(engagementDir, objective) {
  phase('Assess')
  const loaded = await agent(
    `ROLE: work-list loader (pure tool runner — NO judgement). cwd is repo root. Run exactly:
  python3 tools/pci-sss/worklist.py --output-dir ${engagementDir} --objective ${objective}
It prints a JSON array of the applicable Test Requirements for objective ${objective}. Return LOADER_SCHEMA {objective:"${objective}", reqs:<that exact array parsed verbatim — do NOT add, drop, reorder, or edit any element or field>}.`,
    { schema: LOADER_SCHEMA, agentType: 'general-purpose', label: `load:${objective}`, phase: 'Assess' }
  ).catch(() => null)
  let reqs = (loaded && Array.isArray(loaded.reqs)) ? loaded.reqs.filter(r => r && r.id) : []
  if (MAX_REQ > 0 && reqs.length > MAX_REQ) {
    log(`NOTE objective ${objective}: ${reqs.length} reqs; assessing first ${MAX_REQ} (max_requirements). Remainder NOT dropped silently — coverage gate will flag them; raise max_requirements to cover.`)
    reqs = reqs.slice(0, MAX_REQ)
  }
  if (!reqs.length) { log(`Assess objective ${objective}: no applicable requirements`); return { objective, assessed: 0, total: 0 } }
  log(`Assess objective ${objective}: ${reqs.length} Test Requirements (votes=${VOTES})`)

  // Barrier-free pipeline (harness throttles concurrency). Refuters run ONLY for affirmative
  // proposals (MET/NOT_MET/PARTIALLY_MET) — refuting a manual-review/no-claim verdict is wasted work.
  const results = await pipeline(
    reqs,
    (r) => agent(assessPrompt(r, engagementDir), { schema: ASSESS_SCHEMA, label: `assess:${r.id}`, phase: 'Assess', agentType: 'general-purpose' })
        .then(a => a || { req_id: r.id, proposed_status: 'REQUIRES_MANUAL_REVIEW', evidence: [], why: 'assessor returned no result' })
        .catch(() => ({ req_id: r.id, proposed_status: 'REQUIRES_MANUAL_REVIEW', evidence: [], why: 'assessor agent error' })),
    (assess, r) => {
      // Refute only affirmative proposals that are not dynamic-blocked (authoritative flag).
      if (AFFIRMATIVE.has(assess.proposed_status) && !assess.dynamic_required_not_run && !(r && r.dynamic_blocked)) {
        return parallel(Array.from({ length: VOTES }, (_, i) => () =>
          agent(refuterPrompt(r, assess, i + 1), { schema: REFUTE_SCHEMA, label: `refute:${r.id}#${i + 1}`, phase: 'Assess', agentType: 'general-purpose' })
        )).then(votes => ({ assess, votes: votes.filter(Boolean) }))
      }
      return Promise.resolve({ assess, votes: [] })
    },
    (carry, r) => {
      const d = decideVerdict(carry.assess, carry.votes, r)
      const actualVotes = (carry.votes || []).length   // 0 when no refuters ran (non-affirmative / dynamic-blocked)
      return agent(verdictWritePrompt(r, carry.assess, d.status, d.downgraded_from, d.refuted, actualVotes, engagementDir),
        { schema: VERDICT_SCHEMA, label: `verdict:${r.id}`, phase: 'Assess', agentType: 'general-purpose' })
        .then(v => v || { req_id: r.id, status: d.status })
        .catch(() => null)   // a failed write leaves the id missing -> coverage gate flags it (never silently MET)
    },
  )
  const done = results.filter(Boolean).length
  log(`Assess objective ${objective}: ${done}/${reqs.length} verdicts emitted`)
  return { objective, assessed: done, total: reqs.length }
}

async function runVerifyAndReport(engagementDir) {
  phase('Verify')
  const verify = await agent(
    `ROLE: deterministic CITATION VERIFICATION + COVERAGE GATE for a PCI SSS v2.0 assessment. cwd is repo root. OUTPUT_DIR: ${engagementDir}.
Run, in order, and report each tool's output:
1. python3 tools/pci-sss/citation_verify.py --output-dir ${engagementDir} --catalog ${CATALOG}
   (greps every cited quote at file:line; quarantines + downgrades any miss to REQUIRES_MANUAL_REVIEW; writes artifacts/quarantined.json). A non-zero exit is EXPECTED if anything was quarantined — that is the gate working, not an error.
2. python3 tools/pci-sss/coverage_gate.py --output-dir ${engagementDir}
   (writes artifacts/coverage.json; exit 0 iff coverage_ratio==1.0 and no missing ids).
3. python3 tools/pci-sss/aggregate.py --output-dir ${engagementDir} --catalog ${CATALOG}
   (writes artifacts/status-rollup.json).
Then cat artifacts/coverage.json and artifacts/status-rollup.json. Return VERIFY_SCHEMA taking coverage_ratio, applicable, emitted, missing_ids, and complete VERBATIM from the fields coverage_gate.py wrote into artifacts/coverage.json (do NOT compute your own — relay the file's literal values); quarantined = number of entries in artifacts/quarantined.json; rollup = the "overall" object from artifacts/status-rollup.json.`,
    { schema: VERIFY_SCHEMA, agentType: 'general-purpose', label: 'verify', phase: 'Verify' }
  ).catch(err => ({ coverage_ratio: 0, complete: false, error: String(err) }))
  const coverageComplete = !!(verify && verify.complete)
  log(`Verify: coverage=${verify && verify.coverage_ratio}; quarantined=${verify && verify.quarantined}; coverage_complete=${coverageComplete}`)

  phase('Report')
  const report = await agent(
    `ROLE: COMPLIANCE REPORT for a PCI SSS v2.0 readiness gap-assessment. cwd is repo root. Produce the Transilience-style gap report, then prove it faithfully reflects the verified verdicts. Mount formats/transilience-report-style/compliance-report.md, formats/transilience-report-style/SKILL.md, and skills/pci-secure-software/reference/reporting/gap-report.md.
OUTPUT_DIR: ${engagementDir}   COVERAGE_COMPLETE: ${coverageComplete}   COVERAGE_RATIO: ${verify && verify.coverage_ratio}
Do:
1. Aggregate artifacts/validated/*.json + artifacts/quarantined.json + artifacts/coverage.json + artifacts/status-rollup.json + applicability/decisions.json into ${engagementDir}/artifacts/compliance-report.json (schema in compliance-report.md section 8). Each requirement's status MUST equal its verified verdict's status (an affirmative verdict with citation_verified != true counts as REQUIRES_MANUAL_REVIEW). Downgraded/false-positive verdicts appear ONLY as REQUIRES_MANUAL_REVIEW in Coverage & Limitations — never as MET. The rollup counts MUST match the verdict files.
2. Write ${engagementDir}/reports/compliance-report-source.md (sections per compliance-report.md) and ${engagementDir}/reports/tracker.csv (columns: req_id,objective,requirement_text,status,evidence_file,evidence_line,quoted_evidence,why,remediation,citation_verified) — one row per applicable Test Requirement.
3. Write+run ${engagementDir}/reports/build_report.py (ReportLab per formats/transilience-report-style/SKILL.md; register Carlito/Poppins from formats/transilience-report-style/fonts/; footer "TRANSILIENCE AI · PCI SSS v2.0 Gap Assessment · CONFIDENTIAL") -> ${engagementDir}/reports/Compliance-Assessment-Report.pdf. NO emoji; text status labels. The cover and every page MUST carry the disclaimer: "Readiness gap-analysis — NOT an official PCI validation; marking occurs only in the ROV/AOV templates."
4. RUN the deterministic report-integrity gate: python3 tools/pci-sss/report_verify.py --output-dir ${engagementDir}. If it FAILS, read artifacts/report-verify.json, fix compliance-report.json / tracker.csv to match the verdict files, and re-run until it PASSES (or until only coverage-incompleteness remains, which is expected when COVERAGE_COMPLETE is false).
Return REPORT_SCHEMA {ok, report_path, json_path, tracker_path, report_verify_ok (the ok field from artifacts/report-verify.json), report_verify_failures (its failures array)}.`,
    { schema: REPORT_SCHEMA, agentType: 'general-purpose', label: 'report', phase: 'Report' }
  ).catch(err => ({ ok: false, error: String(err) }))

  const reportVerifyOk = !!(report && report.report_verify_ok)
  const complianceStatus = (coverageComplete && reportVerifyOk) ? 'COMPLETE'
    : (!coverageComplete ? 'INCOMPLETE_coverage' : 'INCOMPLETE_report_integrity')
  log(`Report: coverage_complete=${coverageComplete}; report_verify_ok=${reportVerifyOk}; status=${complianceStatus}`)

  return {
    status: 'DONE', compliance_status: complianceStatus, engagement_dir: engagementDir,
    coverage_ratio: verify && verify.coverage_ratio, coverage_complete: coverageComplete,
    report_verify_ok: reportVerifyOk, report_verify_failures: (report && report.report_verify_failures) || [],
    quarantined: verify && verify.quarantined, rollup: verify && verify.rollup,
    report_path: (report && report.report_path) || `${engagementDir}/reports/Compliance-Assessment-Report.pdf`,
    json_path: (report && report.json_path) || `${engagementDir}/artifacts/compliance-report.json`,
    tracker_path: (report && report.tracker_path) || `${engagementDir}/reports/tracker.csv`,
  }
}

// ====================== MODE DISPATCH ======================
if (mode === 'intake') {
  return await runIntake()
}

if (mode === 'assess') {
  const engagementDir = (input.engagement_dir || '').replace(/\/+$/, '')
  if (!engagementDir || !input.objective) return { status: 'BLOCKED', reason: 'assess mode needs {engagement_dir, objective}' }
  return await assessObjective(engagementDir, String(input.objective))
}

if (mode === 'report') {
  const engagementDir = (input.engagement_dir || '').replace(/\/+$/, '')
  if (!engagementDir) return { status: 'BLOCKED', reason: 'report mode needs {engagement_dir}' }
  return await runVerifyAndReport(engagementDir)
}

// mode === 'full' : intake -> assess every applicable objective -> verify+report (small/limited apps)
const intake = await runIntake()
if (intake.status !== 'INTAKE_DONE') return intake
if (dryRun) {
  log('dryRun — returning intake + applicability only, no assessment')
  return { status: 'DRY_RUN', ...intake }
}
const objectives = intake.applicable_objectives || []
// Pre-flight agent-budget guard: full mode runs all objectives in ONE workflow process, which
// shares the 1000-agent lifetime cap. Worst case ~ applicable*(2+VOTES) assessor/refuter/verdict
// agents + one loader per objective + ~4 setup/verify/report. If that exceeds a safe budget,
// refuse and tell the operator to use the sharded intake->assess(per objective)->report path.
const estAgents = (Number(intake.applicable_count) || 0) * (2 + VOTES) + objectives.length + 4
const AGENT_BUDGET = 900
if (!MAX_REQ && estAgents > AGENT_BUDGET) {
  log(`full mode refused: ~${estAgents} agents (> ${AGENT_BUDGET}) for ${intake.applicable_count} requirements.`)
  return {
    status: 'BLOCKED',
    reason: `full mode would spawn ~${estAgents} agents (cap 1000). Use the sharded path: mode:'assess' once per objective (${objectives.join(', ')}) then mode:'report', or pass max_requirements to bound a sample.`,
    engagement_dir: intake.engagement_dir, applicable_objectives: objectives, applicable_count: intake.applicable_count,
  }
}
log(`full mode: assessing ${objectives.length} objective(s) sequentially (~${estAgents} agents est.)`)
const perObjective = []
for (const obj of objectives) {
  perObjective.push(await assessObjective(intake.engagement_dir, String(obj)))
}
const final = await runVerifyAndReport(intake.engagement_dir)
return { ...final, applicable_objectives: objectives, applicable_count: intake.applicable_count, per_objective: perObjective }
