export const meta = {
  name: 'htb-solve',
  description: 'Orchestrate HackTheBox solves (challenges, machines, fortresses) end-to-end: setup -> delegate each target to the coordinator-loop workflow -> flag submission -> skill-update + Slack.',
  whenToUse: 'Solve one or more HTB targets. Pass args: a target name/id, a list, or {targets,kind,maxConcurrent,dryRun,max_experiments}. The workflow plays the parent ORCHESTRATOR; each target is driven by the coordinator-loop workflow (continuous recon/think/experiment/integrate loop), depth-budgeted by target count.',
  phases: [
    { title: 'Setup', detail: 'creds, target resolution, VPN pool pre-flight, OUTPUT_DIR tree, STARTED Slack' },
    { title: 'Solve', detail: 'delegates each target to the coordinator-loop workflow — continuous recon/think/experiment/integrate loop' },
    { title: 'Validate', detail: 'delegates to the validate-findings workflow — authoritative NVD/CVSS/exploit/risk validation of every finding' },
    { title: 'Submit', detail: 'verify ownership + resubmit any unsubmitted flag (HTB API transport gotchas)' },
    { title: 'Post-solve', detail: 'finalize stats.json, skill-update (generalized), COMPLETED Slack gated on full success' },
  ],
}

// ============================================================================
// HTB SOLVE — parent orchestrator as a deterministic workflow.
//
// Architecture (faithful to skills/coordination + skills/hackthebox):
//   ORCHESTRATOR  = this workflow. Owns creds, OUTPUT_DIR creation, the queue,
//                   flag resubmission, and Phase 3 (skill-update + Slack).
//                   The ONLY layer allowed to touch Slack / skill-update.
//   COORDINATOR   = the `coordinator-loop` workflow, run once per target via
//                   workflow() (one level of nesting). It runs the continuous
//                   recon/think/experiment/integrate loop, spawns its own
//                   executors/skeptic/validators, and submits flags to confirm
//                   ownership. It never does Slack / skill-update / AskUser.
//
// Pipeline (no barrier): each target flows solve -> validate -> submit ->
// post-solve independently, so a multi-target event pipelines while a single
// machine / fortress is just one item. Concurrency is capped (default 3) in
// chunks. Solve and Validate each delegate to a sibling workflow (coordinator-
// loop, validate-findings) — both are one level below htb-solve, which is legal;
// neither of THEM nests further.
//
// AGENT-CAP NOTE: child workflows SHARE this run's 1000-agent lifetime counter.
// So each coordinator-loop's depth is budgeted by the number of ready targets
// (loopBudgetBatches below): one target -> deep (up to 150 batches), many
// targets -> shallower. validate-findings adds ~4 agents/finding (bounded by its
// max_findings), so the shared cap is never blown.
//
// NOTE: scripts run in a restricted JS sandbox — no Date.now()/Math.random()/
// new Date() (all timestamps come from agents shelling out to `date`). All real
// tool work (Bash/Read/Write/HTB-API/Agent) happens inside agents.
// ============================================================================

// ---- helpers ---------------------------------------------------------------
function chunk(arr, n) {
  const out = []
  for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n))
  return out
}

// ---- structured-output schemas --------------------------------------------
const SETUP_SCHEMA = {
  type: 'object',
  additionalProperties: true,
  required: ['ok', 'date_tag', 'targets'],
  properties: {
    ok: { type: 'boolean' },
    date_tag: { type: 'string', description: 'YYMMDD from `date +%y%m%d`' },
    blocked_global: { type: ['string', 'null'], description: 'non-null if the whole run is blocked, e.g. HTB_TOKEN NOT_SET' },
    creds: {
      type: 'object', additionalProperties: true,
      properties: { htb_token: { type: 'boolean' }, slack: { type: 'boolean' } },
    },
    targets: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: true,
        required: ['tag', 'kind', 'name', 'target', 'output_dir', 'status'],
        properties: {
          tag: { type: 'string' },
          kind: { type: 'string', enum: ['machine', 'challenge', 'fortress'] },
          name: { type: 'string' },
          id: { type: 'string' },
          target: { type: 'string', description: 'IP for machine/fortress, challenge_id for challenge' },
          output_dir: { type: 'string' },
          scope: { type: 'string' },
          skills_hint: { type: 'string' },
          difficulty: { type: 'string' },
          difficulty_rating: { type: 'number', description: 'multiple of 10 (10..100) for flag submission' },
          os: { type: 'string' },
          status: { type: 'string', enum: ['ready', 'blocked'] },
          blocked_reason: { type: ['string', 'null'] },
        },
      },
    },
    notes: { type: 'array', items: { type: 'string' } },
  },
}

// The Solve stage delegates to the `coordinator-loop` workflow (one level of
// nesting). adaptSummary() maps its return into the lightweight "summary" shape
// the Submit/Post-solve stages consume:
//   { tag, status: SUCCESS|FAILED_partial|BLOCKED|FAILED, flags:[], narrative,
//     completion_report, stats_file, blocked_reason, loop:{experiments,batches,...} }
// flags[] is intentionally empty here — the loop already submits to confirm
// ownership, and the Submit stage re-reads flags.txt/findings from OUTPUT_DIR.

const SUBMIT_SCHEMA = {
  type: 'object',
  additionalProperties: true,
  required: ['tag', 'all_submitted', 'flags'],
  properties: {
    tag: { type: 'string' },
    all_submitted: { type: 'boolean' },
    flags: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: true,
        properties: {
          name: { type: 'string' },
          value: { type: ['string', 'null'] },
          owned: { type: 'boolean' },
          submitted: { type: 'boolean' },
        },
      },
    },
    notes: { type: 'string' },
  },
}

const POST_SCHEMA = {
  type: 'object',
  additionalProperties: true,
  required: ['tag', 'slack_sent'],
  properties: {
    tag: { type: 'string' },
    skill_update_summary: { type: 'string' },
    report_ok: { type: 'boolean' },
    slack_sent: { type: 'boolean' },
    slack_skipped_reason: { type: ['string', 'null'] },
  },
}

// ---- normalize inputs ------------------------------------------------------
const input = (args && typeof args === 'object' && !Array.isArray(args)) ? args : { targets: args }
const cap = Number(input.maxConcurrent) > 0 ? Math.floor(Number(input.maxConcurrent)) : 3
const dryRun = !!input.dryRun
const kindHint = input.kind || 'auto'
const targetSpec = JSON.stringify({ targets: input.targets ?? null, kind: kindHint })

// ============================================================================
// PHASE: Setup
// ============================================================================
phase('Setup')

const setupPrompt = `You are the SETUP step of the HTB orchestrator. cwd is the repo root. Do real work (Bash/Read/Write/WebFetch). Do NOT spawn coordinators or run any exploitation — only resolve targets and prepare the engagement. Read skills/hackthebox/reference/workflow.md and skills/hackthebox/reference/vpn-pool-routing.md before acting; follow their exact commands.

TARGET_SPEC (what the user asked to solve): ${targetSpec}
DRY_RUN: ${dryRun}

Do the following:

1) CREDENTIALS. Run: python3 tools/env-reader.py HTB_USER HTB_PASS HTB_TOKEN ANTHROPIC_API_KEY SLACK_BOT_TOKEN HTB_SLACK_CHANNEL_ID
   - Parse the ENV_VALUES: block (NOT ENV_STATUS:, which masks secret-named vars).
   - If HTB_TOKEN is NOT_SET -> set blocked_global="HTB_TOKEN NOT_SET" and return (cannot proceed).
   - Record creds.htb_token and creds.slack (slack = both SLACK_BOT_TOKEN and HTB_SLACK_CHANNEL_ID set).

2) DATE TAG. date_tag = output of: date +%y%m%d

3) RESOLVE EACH TARGET via the HTB API (labs.hackthebox.com/api/v4). HARD API rules from workflow.md: omit any -A/--user-agent (Cloudflare bans custom UA AND python urllib default UA -> shell out to curl, never urllib/requests); add --http1.1; pass the bearer with -H "Authorization: Bearer $HTB_TOKEN". For each requested target determine:
   - kind: machine | challenge | fortress (honor TARGET_SPEC.kind unless it is "auto"). If TARGET_SPEC.targets is null/empty: query active machine (/machine/active); if exactly one active, use it; otherwise return ok:true with an empty targets array and a note "no target specified".
   - For a CHALLENGE: resolve challenge_id (search the challenges list / accept a numeric id). target = the challenge_id (string). Read /challenge/info/<id> for name, category (-> skills_hint), difficulty, and authUserSolve (skip if already solved -> blocked_reason "already solved"). Challenges need NO VPN.
   - For a MACHINE: resolve machine_id + name; read /machine/profile/<name-or-id> for difficulty, os, ip (info.ip), tags (-> skills_hint), and ownership (authUserInUserOwns / authUserInRootOwns).
   - For a FORTRESS: resolve fortress id + name; scope notes it is multi-flag and SEQUENTIAL. Needs VPN (its own pool).

4) VPN POOL PRE-FLIGHT (machines + fortresses only — per vpn-pool-routing.md). AGENTS DO NOT START/STOP THE VPN.
   - Resolve target lab_server + vpn_server_id from the machine profile.
   - Inspect the running tunnel: ps aux | grep -v grep | grep openvpn ; head -5 the active .ovpn (the 'remote' line) if found.
   - If NO openvpn is running, OR the running tunnel's pool does NOT match the target's lab_server: status="blocked", blocked_reason naming the exact pool/server to connect (e.g. "Connect dedivip_lab (vpn_server_id 704) VPN — running tunnel is <X> or none"). Save the correct .ovpn to <output_dir>/artifacts/ if you can fetch GET /api/v4/access/ovpnfile/<server_id>/0, but do NOT start it.
   - Only when the tunnel matches: spawn the VM (POST /vm/spawn machine_id), poll /machine/active for the IP, then ping -c 2 <ip> and a quick nmap -Pn -sT --top-ports 50 <ip>. If ALL ports filtered + unreachable -> pool-mismatch symptom -> status="blocked" with that reason. Else status="ready", target=<ip>.

5) OUTPUT_DIR. For every target (ready or blocked), output_dir = projects/ctf/<date_tag>_<tag>/ where tag is a short kebab id (machine/fortress name lowercased; "challenge-<id>" for challenges). For READY targets create the tree and seed files (do NOT seed attack-chain.md or experiments.md — those are the coordinator's first action):
   mkdir -p <output_dir>/{recon,findings,logs,artifacts/vpn,tools,reports}
   - Write <output_dir>/stats.json = {}  (MUST exist so the stats PostToolUse hook accrues counters).
   - Write <output_dir>/challenge-meta.json = {"name":..,"type":<kind>,"target":<target>,"started":<iso utc>,"completed":null,"flag":null,"techniques":[]}
   - Write <output_dir>/start_time.txt = ISO-8601 UTC (date -u +%Y-%m-%dT%H:%M:%SZ).
   - difficulty_rating: a multiple of 10 for flag submission — Easy=20, Medium=40, Hard=60, Insane=80 (default 30 if unknown).
   - scope: one line incl. kind, difficulty, os, ip/challenge_id, and "fortress: multiple sequential flags" when applicable.

6) STARTED SLACK (only if creds.slack AND not DRY_RUN AND status=="ready"). For each ready target send the verbatim started notification from skills/hackthebox/reference/slack-notifications.md (the printf ':crossed_swords: *Starting: %s*...' piped to: python3 tools/slack-send.py --token "$SLACK_BOT_TOKEN" --channel "$HTB_SLACK_CHANNEL_ID" -). Slack failure is non-blocking — log and continue.

Return the SETUP_SCHEMA object. Never log secret values. Reference vars by name.`

const setup = await agent(setupPrompt, { schema: SETUP_SCHEMA, agentType: 'general-purpose', label: 'setup', phase: 'Setup' })

if (!setup || !setup.ok || setup.blocked_global) {
  const reason = setup ? (setup.blocked_global || 'setup returned ok:false') : 'no setup result'
  log(`Setup blocked: ${reason}`)
  return { status: 'BLOCKED', reason, setup }
}

// Normalize output_dir to NO trailing slash so every `${t.output_dir}/x` join is clean.
for (const t of (setup.targets || [])) { if (t && typeof t.output_dir === 'string') t.output_dir = t.output_dir.replace(/\/+$/, '') }

const ready = (setup.targets || []).filter(t => t && t.status === 'ready')
const blocked = (setup.targets || []).filter(t => t && t.status === 'blocked')
for (const b of blocked) log(`BLOCKED ${b.tag}: ${b.blocked_reason || 'unspecified'}`)
for (const n of (setup.notes || [])) log(`note: ${n}`)

if (dryRun) {
  log(`dryRun complete: ${ready.length} ready, ${blocked.length} blocked`)
  return { status: 'DRY_RUN', date_tag: setup.date_tag, ready, blocked, notes: setup.notes || [] }
}
if (!ready.length) {
  return { status: 'NO_READY_TARGETS', blocked, notes: setup.notes || [] }
}

// ============================================================================
// Prompt builders for the per-target pipeline
// ============================================================================

// Goal string handed to coordinator-loop — carries the HTB-specific success
// condition + submission API so the platform-agnostic loop knows what "solved"
// means and how to confirm a flag.
function goalFor(t) {
  const api = 'Submission API: read skills/hackthebox/reference/workflow.md sections 5-6 — machine POST /machine/own {id,flag,difficulty}; challenge POST /challenge/own with key challenge_id (NOT id) and difficulty a MULTIPLE OF 10 (' + (t.difficulty_rating || 30) + '); fortress via its flag endpoint. Always --http1.1, default UA (no -A), 2-2.5s between submits; "Incorrect Flag" is ambiguous so verify ownership via the profile endpoint. HTB_TOKEN via python3 tools/env-reader.py. A flag counts as proven ONLY once the API confirms ownership. NO BRUTE FORCE.'
  if (t.kind === 'challenge') return `Capture the challenge flag and SUBMIT it via the HTB API to confirm ownership, with reproducible proof. ${api}`
  if (t.kind === 'fortress') return `Capture and SUBMIT every fortress flag, IN SEQUENCE, via the HTB API. The engagement is incomplete until ALL flags are owned. ${api}`
  return `Capture and SUBMIT the user flag FIRST, then the root flag, via the HTB API. Establish a stable foothold before attempting root. SUCCESS only when BOTH flags are owned. ${api}`
}

// Map coordinator-loop's return into the summary shape Submit/Post-solve consume.
function adaptSummary(t, loopOut) {
  const lo = loopOut || {}
  const status = lo.solved ? 'SUCCESS'
    : (lo.status === 'FAILED_partial' ? 'FAILED_partial'
      : (lo.status === 'BLOCKED' ? 'BLOCKED' : 'FAILED'))
  return {
    tag: t.tag,
    status,
    flags: [], // loop already submitted to confirm; Submit stage re-reads flags.txt/findings from OUTPUT_DIR
    narrative: lo.narrative || '',
    completion_report: lo.report_path || `${t.output_dir}/reports/completion-report.md`,
    stats_file: `${t.output_dir}/stats.json`,
    blocked_reason: lo.end_reason || null,
    loop: { experiments: lo.experiments, batches: lo.batches, findings_confirmed: lo.findings_confirmed, engagement_status: lo.engagement_status },
  }
}

function submitPrompt(t, summary) {
  const status = summary ? summary.status : 'UNKNOWN'
  const required = t.kind === 'machine' ? 'user + root (2 flags)' : (t.kind === 'fortress' ? 'every fortress flag listed on its profile' : 'the single challenge flag')
  return `You are the parent orchestrator's FLAG-SUBMISSION/VERIFICATION step for one HTB target. cwd is repo root. Read skills/hackthebox/reference/workflow.md sections 5-6 first.

TARGET tag: ${t.tag}
KIND: ${t.kind}
ID/IP: ${t.target}
DIFFICULTY_RATING (multiple of 10): ${t.difficulty_rating || 30}
REQUIRED FLAGS: ${required}
COORDINATOR-LOOP status: ${status}

The coordinator-loop already submitted flags during the run to confirm ownership, so on a clean SUCCESS this is verification only. Captured flag values, if any, are in ${t.output_dir}/flags.txt and/or ${t.output_dir}/findings/*/ — read them from disk (the loop summary does not carry them).

Job: make sure every REQUIRED flag is actually OWNED on the platform.
  - First, verify ownership (machine: GET /machine/profile/<id> -> authUserInUserOwns/authUserInRootOwns; challenge: GET /challenge/info/<id> -> authUserSolve; fortress: fortress profile shows owned flag count). If all required flags already owned -> all_submitted=true, done.
  - If a required flag is NOT owned but its value exists on disk: resubmit with the documented transport — curl, --http1.1, default UA (NO -A), bearer via -H; machine POST /machine/own {id,flag,difficulty}; challenge POST /challenge/own with key challenge_id and difficulty a multiple of 10; fortress via its endpoint. Rate-limit 2-2.5s; on "Too Many Attempts" wait 2-3 min then retry once. Treat a transport failure (302->/login, 419, HTTP 000) as transport-only, not a wrong flag — retry with --http1.1/default UA.
  - If a required flag was never captured (no value on disk): do not guess and do NOT brute force; report it unmet.

Return SUBMIT_SCHEMA: tag, all_submitted (true iff EVERY required flag is owned), flags[] (name,value,owned,submitted), notes.`
}

function postPrompt(t, summary, submit, validation) {
  const status = summary ? summary.status : 'UNKNOWN'
  const allSubmitted = submit ? !!submit.all_submitted : false
  const techniques = JSON.stringify((summary && summary.techniques) || [])
  const lessons = JSON.stringify((summary && summary.lessons) || [])
  const skillsToUpdate = JSON.stringify((summary && summary.skills_to_update) || [])
  const narrative = (summary && summary.narrative) || ''
  const valCounts = validation && validation.counts ? JSON.stringify(validation.counts) : 'n/a'
  const valReport = validation && validation.report_path ? validation.report_path : `${t.output_dir}/reports/validation-report.md`
  return `You are the parent orchestrator's PHASE 3 (post-solve) step for one HTB target. cwd is repo root. This runs after EVERY coordinator completes — even on BLOCKED (lessons still have value). You are the ONLY layer allowed to do skill-update and Slack.

TARGET: ${t.name || t.tag} (tag ${t.tag}, ${t.kind}, ${t.difficulty || ''} ${t.os || ''})
OUTPUT_DIR: ${t.output_dir}
COORDINATOR status: ${status}
ALL_FLAGS_SUBMITTED: ${allSubmitted}
VALIDATION counts: ${valCounts} (authoritative validation report: ${valReport}) — use ONLY validated findings in any write-up; rejected ones are false positives.
narrative: ${JSON.stringify(narrative)}
techniques: ${techniques}
lessons: ${lessons}
skills_to_update: ${skillsToUpdate}

NOTE: the techniques/lessons/skills_to_update fields above may be empty — the coordinator-loop records the detail in ${t.output_dir}/reports/completion-report.md (Techniques Used / Lessons Learned / Failed Approaches) and ${t.output_dir}/session-memory.md (Dead Ends, Creative Leads). Derive them from those files.

Steps:
1) STATS. Ensure ${t.output_dir}/stats.json has experiment/finding/agent counts + duration. If empty, recount from logs/experiments.md (the stats fallback greps in formats/htb-completion-report.md).
2) COMPLETION REPORT. Verify ${t.output_dir}/reports/completion-report.md exists and has all 8 sections (formats/htb-completion-report.md). If missing, generate it from challenge-meta.json, start_time.txt, stats.json, findings/, and logs/.
3) SKILL-UPDATE (skill-improvement loop — skills/hackthebox/reference/skill-improvement.md). Review challenge-log/findings, then GENERALIZE every learning — strip ALL platform/challenge-specific names and CTF-only file paths. Route each: injection bypass -> skills/injection/reference/*-quickstart.md|*-cheat-sheet.md; auth -> skills/authentication/reference/*; traversal -> skills/server-side/reference/scenarios/path-traversal/; attack-chain combo -> skills/coordination/reference/spawning-recipes.md; recon -> skills/reconnaissance/*. Enforce the gates: no platform/challenge names, technique generic beyond this scenario, no duplication, quickstart/cheat-sheet < 200 lines, no CTF-specific bias. If nothing generalizes, skip and say so. (You may invoke the skill-update skill if available; otherwise make the edits directly.) Summarize which skills changed and why.
4) SLACK — COMPLETED notification, GATED. Send ONLY if BOTH: (a) Slack creds are set (python3 tools/env-reader.py SLACK_BOT_TOKEN HTB_SLACK_CHANNEL_ID — both set), AND (b) FULL SUCCESS: coordinator status==SUCCESS AND ALL_FLAGS_SUBMITTED==true. Partial/BLOCKED/FAILED -> NO post (set slack_skipped_reason). Build the message in the verbatim COMPLETED format from skills/hackthebox/reference/slack-notifications.md (header ":trophy: PWNED — <name>"; Difficulty/OS/Time line; Flags line with one :white_check_mark: per owned flag; "Experiments: N | Findings: M | Agents: K" from stats.json; a 3-6 sentence "How It Was Hacked" narrative; "Key Techniques" bullets; "Skills Updated" from step 3). Send via stdin form: printf '...' | python3 tools/slack-send.py --token "$SLACK_BOT_TOKEN" --channel "$HTB_SLACK_CHANNEL_ID" -. Slack failure is non-blocking — log and continue.

Return POST_SCHEMA: tag, skill_update_summary, report_ok, slack_sent, slack_skipped_reason.`
}

// ============================================================================
// PHASES: Solve -> Submit -> Post-solve (pipeline, concurrency-capped chunks)
// ============================================================================
// Budget each coordinator-loop's depth by the number of ready targets, because
// child-workflow agents share this run's 1000-agent lifetime cap. Reserve ~80
// agents for setup/submit/post/validate overhead; a loop spends ~4 agents/batch.
const N = ready.length
const loopBudgetBatches = Math.min(150, Math.max(12, Math.floor((920 / N - 16) / 4)))
const userMaxExp = Number(input.max_experiments) > 0 ? Math.floor(Number(input.max_experiments)) : 1000
const loopBudgetExperiments = Math.min(userMaxExp, loopBudgetBatches * 8)
log(`Per-target loop budget: ~${loopBudgetBatches} batches / ${loopBudgetExperiments} experiments (shared agent cap across ${N} target(s)).`)

const groups = chunk(ready, cap)
const results = []

for (const grp of groups) {
  const grpResults = await pipeline(
    grp,
    // Stage 1 — Solve: delegate to the coordinator-loop workflow (one level of nesting)
    (t) => workflow('coordinator-loop', {
      target: t.target,
      output_dir: t.output_dir,
      goal: goalFor(t),
      scope: t.scope || '',
      skills_hint: t.skills_hint || '',
      platform: 'htb',
      max_experiments: loopBudgetExperiments,
      max_batches: loopBudgetBatches,
      validate: false, // htb-solve runs the authoritative validate-findings stage itself
    }).then(loopOut => adaptSummary(t, loopOut))
      .catch(err => ({ tag: t.tag, status: 'FAILED', flags: [], blocked_reason: 'coordinator-loop error: ' + String(err) })),
    // Stage 2 — Validate: delegate to the validate-findings workflow (sibling, one level of nesting).
    // Returns fast (NO_FINDINGS) for flag-only challenges with no findings/ entries.
    (summary, t) =>
      workflow('validate-findings', {
        output_dir: t.output_dir,
        target: t.target,
        platform: 'htb',
        business_tier: 'unknown',
      }).then(validation => ({ summary, validation }))
        .catch(err => ({ summary, validation: { status: 'ERROR', reason: String(err) } })),
    // Stage 3 — Submit / verify flags
    (carry, t) => {
      const summary = carry ? carry.summary : null
      return agent(submitPrompt(t, summary), { schema: SUBMIT_SCHEMA, agentType: 'general-purpose', label: `submit:${t.tag}`, phase: 'Submit' })
        .then(submit => ({ ...carry, submit }))
        .catch(() => ({ ...carry, submit: null }))
    },
    // Stage 4 — Post-solve (stats, skill-update, gated Slack)
    (carry, t) => {
      const summary = carry ? carry.summary : null
      const submit = carry ? carry.submit : null
      const validation = carry ? carry.validation : null
      return agent(postPrompt(t, summary, submit, validation), { schema: POST_SCHEMA, agentType: 'general-purpose', label: `post:${t.tag}`, phase: 'Post-solve' })
        .then(post => ({ tag: t.tag, status: summary ? summary.status : 'UNKNOWN', summary, submit, validation, post }))
        .catch(() => ({ tag: t.tag, status: summary ? summary.status : 'UNKNOWN', summary, submit, validation, post: null }))
    },
  )
  results.push(...grpResults.filter(Boolean))
}

// ============================================================================
// Synthesis
// ============================================================================
const solved = results.filter(r => r && r.status === 'SUCCESS' && r.submit && r.submit.all_submitted)
log(`Done: ${solved.length}/${ready.length} fully solved, ${blocked.length} blocked at setup`)

return {
  status: 'DONE',
  date_tag: setup.date_tag,
  fully_solved: solved.map(r => r.tag),
  results,
  blocked: blocked.map(b => ({ tag: b.tag, reason: b.blocked_reason })),
  notes: setup.notes || [],
}
