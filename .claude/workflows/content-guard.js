export const meta = {
  name: 'content-guard',
  description: 'Deterministically prove that the changes currently in this repository carry no customer name, engagement identifier, target IP, credential, personal data or operator path before any of it becomes public. Scans what PUSHING THIS BRANCH would publish — every blob any commit on the branch introduced, plus the worktree, the index and untracked files — not the net diff, because a push publishes history and a secret added then deleted is absent from `BASE...HEAD` yet still fetched by anyone who clones the PR ref. Runs the changed scan AND a whole-tree backstop, plus the IP-neutrality and report-generator-fork guards, then computes the verdict in pure JS from the tools JSON. NO model is in the finding path: agents run commands and relay output verbatim, and every accept/reject is code. Matched values never leave the tool — findings are truncated at the first " -> " so a report, a transcript and a public CI log carry the rule and the location only.',
  whenToUse: 'Before publishing anything from this repo — invoked on its own to answer "is what I have right now safe to push?", or as the hard gate inside /safe-pr. args: {base?: "origin/main", scope?: "both"|"changed"|"full", require_denylist?: true, manifest?: true, dryRun?}. Exit-code semantics are the tool\'s: CLEAN, BLOCKED (findings) or CONFIG_ERROR (the scan could not be trusted). Read-only — it writes nothing except gitignored scan artefacts under .claude/state/confidentiality/.',
  phases: [
    { title: 'Scope', detail: 'resolve the base ref, HEAD, branch and the size of the change set' },
    { title: 'Scan', detail: 'run the deterministic guards; agents relay their JSON verbatim' },
    { title: 'Verdict', detail: 'pure-JS gate over the tool output — no model decides' },
  ],
}

// Sandbox: no import/require, no fs, no bash, no wall-clock, no randomness.
// Agents run every command; this script only decides.
//
// THE DETERMINISM CONTRACT
// ------------------------
// For a fixed git object graph, a fixed worktree, a fixed $CLIENT_DENYLIST and a
// fixed scripts/content-guard-allowlist.json, this workflow returns the same
// status and the same finding set on every run. That holds because:
//
//   1. Every finding is produced by scripts/check_client_data.py — a pure
//      function of git object content plus two config files. There is no LLM
//      lane. A model cannot add a finding, and cannot clear one.
//   2. The universe is enumerated by named git commands recorded in the tool's
//      own UNIVERSE_CMDS and echoed into the manifest, so the coverage proof
//      names the commands that actually ran.
//   3. The verdict is one pure function of (parsed payloads, exit codes) — see
//      verdict() below. Agents are transport: their schemas cannot express a
//      verdict, only "the command exited N and here is its JSON".
//   4. Anything unexpected BLOCKS. An unparsed payload, a git failure, an
//      unresolvable base, a dead agent or a disagreement between two agents
//      about HEAD all fail closed. A guard that reports clean when it could not
//      run is worse than no guard, because it is believed.
//
// No rule lives here. Regexes, allowlists, thresholds and exemptions are all in
// the Python tool; re-implementing one in JS would fork the rule set, which is
// the single thing this repo's confidentiality doc forbids most explicitly.

// ---- inputs ---------------------------------------------------------------
let __raw = args
if (typeof __raw === 'string') {
  const s = __raw.trim()
  if (s.startsWith('{')) { try { __raw = JSON.parse(s) } catch (e) { __raw = { base: __raw } } }
  else __raw = { base: __raw }
}
const input = (__raw && typeof __raw === 'object' && !Array.isArray(__raw)) ? __raw : {}

const SCOPES = ['both', 'changed', 'full']
const SCOPE = SCOPES.includes(input.scope) ? input.scope : 'both'
const BASE = String(input.base || '').trim()
const REQUIRE_DENYLIST = input.require_denylist !== false
const WANT_MANIFEST = input.manifest !== false
const dryRun = !!input.dryRun

const STATE = '.claude/state/confidentiality'
const CHANGED_JSON = `${STATE}/report-changed.json`
const FULL_JSON = `${STATE}/report.json`

const blocked = (reason, extra) => ({
  status: 'BLOCKED', clean: false, reason,
  findings: [], warnings: [], counts: { findings: 0, warnings: 0, universe: 0 },
  report_markdown: `⛔ **Content guard BLOCKED.** ${reason}`,
  ...(extra || {}),
})

if (dryRun) {
  return { status: 'DRY_RUN', clean: false, scope: SCOPE, base: BASE || '(auto)',
    report_markdown: '**Dry run.** Nothing scanned.' }
}

// ---- pure-JS gates --------------------------------------------------------
// Every accept/reject in this workflow is one of these functions.

/** A relayed payload is usable only if it is the shape we asked for. Anything
 *  else — truncated, paraphrased, wrong schema — is treated as "did not run". */
function usable(p, schema) {
  return !!p && typeof p === 'object' && p.schema === schema
    && p.counts && typeof p.counts.findings === 'number'
}

/** The verdict. Pure function of the relayed facts; the only place a run can be
 *  declared clean. Note the ordering: CONFIG_ERROR outranks BLOCKED, because
 *  "the scan could not be trusted" is a different remedy from "fix the leak". */
function verdict(lanes) {
  const ran = lanes.filter((l) => l.required)
  for (const l of ran) {
    if (l.exit === 2) return { status: 'CONFIG_ERROR', clean: false,
      reason: `${l.name} could not run a trustworthy scan (exit 2): ${l.detail || 'see output'}` }
    if (l.payloadRequired && !l.payload) return { status: 'CONFIG_ERROR', clean: false,
      reason: `${l.name} did not return a usable ${l.schema} payload; the scan cannot be verified` }
    if (l.exit === null || l.exit === undefined) return { status: 'CONFIG_ERROR', clean: false,
      reason: `${l.name} did not report an exit code; treating as not-run` }
    // `l.exit` is a number an AGENT typed. The tool's own JSON report — which we
    // already hold — states the same thing authoritatively. Trusting only the
    // transcribed field would put a model in the finding path after all: a
    // mistyped 0 over a report listing findings would read as CLEAN. So they must
    // agree, and a disagreement is CONFIG_ERROR rather than BLOCKED, because what
    // it proves is that nothing was reliably certified.
    if (l.payload && (l.payload.exit !== l.exit
        || (l.payload.counts.findings > 0) !== (l.exit !== 0))) {
      return { status: 'CONFIG_ERROR', clean: false,
        reason: `${l.name} relayed exit ${l.exit}, but its JSON report says exit `
          + `${l.payload.exit} with ${l.payload.counts.findings} finding(s). The `
          + `transcript and the tool disagree, so no state was certified.` }
    }
    if (l.exit !== 0) return { status: 'BLOCKED', clean: false,
      reason: `${l.name} found content that must not become public` }
  }
  return { status: 'CLEAN', clean: true, reason: 'no findings in any lane' }
}

/** The denylist lane silently no-ops when $CLIENT_DENYLIST is absent, so a green
 *  scan can mean "the client-name lane never ran". That must not read as clean. */
function denylistOk(payload) {
  return !REQUIRE_DENYLIST || !payload || payload.lanes?.denylist === 'active'
}

// ---- Scope ----------------------------------------------------------------
phase('Scope')

const SCOPE_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['ok', 'branch', 'head', 'base_ref', 'commits_ahead', 'dirty_files', 'untracked_files'],
  properties: {
    ok: { type: 'boolean', description: 'true only if EVERY command exited 0' },
    branch: { type: 'string', description: 'current branch name, or "(detached)"' },
    head: { type: 'string', description: 'full HEAD sha' },
    base_ref: { type: 'string', description: 'the base ref that resolved, or "" if none did' },
    commits_ahead: { type: 'number' },
    dirty_files: { type: 'number' },
    untracked_files: { type: 'number' },
    notes: { type: 'string', description: 'any command that failed, verbatim stderr' },
  },
}

const baseArg = BASE ? BASE : ''
const scope = await agent(`Run these commands in the repository root and report the results EXACTLY.
Do not interpret, summarise or fix anything. You are a transport, not a judge.

\`\`\`bash
git rev-parse --abbrev-ref HEAD
git rev-parse HEAD
for r in ${baseArg ? `"${baseArg}"` : 'origin/main main origin/master master'}; do
  git rev-parse --verify --quiet "$r^{commit}" >/dev/null && { echo "BASE=$r"; break; }
done
git rev-list --count "$(git merge-base ${baseArg || 'origin/main'} HEAD 2>/dev/null || echo HEAD)"..HEAD 2>/dev/null || echo 0
git diff HEAD --name-only --diff-filter=ACMR | wc -l
git ls-files --others --exclude-standard | wc -l
\`\`\`

Report: branch, head (full sha), base_ref (the ref printed after BASE=, or "" if none),
commits_ahead, dirty_files, untracked_files. Set ok=true ONLY if every command exited 0.
Do NOT edit any file. Do NOT run any git command that writes.`,
  { label: 'scope', phase: 'Scope', schema: SCOPE_SCHEMA })
  .catch(() => null)

if (!scope || scope.ok !== true || !scope.head) {
  return blocked('could not read the repository state; refusing to certify anything. '
    + (scope?.notes ? `git said: ${String(scope.notes).slice(0, 300)}` : 'the scope agent returned nothing.'))
}
if (SCOPE !== 'full' && !scope.base_ref) {
  return blocked('no base ref resolved (tried origin/main, main, origin/master, master). '
    + 'A changed-scope scan with no base cannot know what is new. Run `git fetch origin`, '
    + 'or pass {base:"<ref>"}.')
}

log(`branch ${scope.branch} @ ${scope.head.slice(0, 8)} vs ${scope.base_ref || '(full only)'} — `
  + `${scope.commits_ahead} commit(s) ahead, ${scope.dirty_files} dirty, ${scope.untracked_files} untracked`)

// ---- Scan -----------------------------------------------------------------
phase('Scan')

const REPORT_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['ok', 'exit', 'payload'],
  properties: {
    ok: { type: 'boolean', description: 'true only if the command ran AND its JSON parsed. NOT a judgement about the content.' },
    exit: { type: ['number', 'null'], description: 'the process exit code, verbatim: 0 clean, 1 findings, 2 config error' },
    payload: { type: ['object', 'null'], additionalProperties: true, description: 'the JSON report file, parsed and reproduced EXACTLY. Never edit, filter or summarise it.' },
    stderr_tail: { type: 'string', description: 'last ~15 lines of stderr, verbatim' },
  },
}

const guardCmd = (mode) => {
  const flags = ['--redact', `--json ${mode === 'changed' ? CHANGED_JSON : FULL_JSON}`]
  if (WANT_MANIFEST) flags.push('--manifest')
  if (REQUIRE_DENYLIST) flags.push('--require-denylist')
  const scopeFlag = mode === 'changed' ? `--changed${BASE ? ` ${BASE}` : ''}` : ''
  return `python3 scripts/check_client_data.py ${scopeFlag} ${flags.join(' ')}`.replace(/\s+/g, ' ').trim()
}

const runnerPrompt = (cmd, jsonPath, what) => `Run EXACTLY this command from the repository root:

\`\`\`bash
${cmd}
echo "EXIT=$?"
\`\`\`

Then read \`${jsonPath}\` and reproduce its parsed JSON EXACTLY as \`payload\`.

Rules — this is a security gate and you are transport, not a judge:
- Report the exit code VERBATIM. 0 = clean, 1 = findings, 2 = config error.
- Do NOT edit, create or delete ANY file to make this pass. Do NOT amend the
  allowlist, the denylist, the binary pin list, or any scanned file.
- Do NOT re-run with different flags, and do NOT "fix" a finding.
- Do NOT omit, summarise, redact further, or reorder anything in the payload.
- If the command fails or the file is missing, set ok=false, report the exit code
  you saw and put stderr in stderr_tail. Never invent a payload.
This is ${what}.`

const CHECKS_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['neutrality_exit', 'no_forks_exit'],
  properties: {
    neutrality_exit: { type: ['number', 'null'], description: 'exit code of check_neutrality.py, verbatim' },
    no_forks_exit: { type: ['number', 'null'], description: 'exit code of check_no_forks.py, verbatim' },
    output_tail: { type: 'string', description: 'combined output, verbatim, last ~20 lines' },
  },
}

const needChanged = SCOPE === 'both' || SCOPE === 'changed'
const needFull = SCOPE === 'both' || SCOPE === 'full'

const [changedRun, fullRun, checksRun] = await parallel([
  () => (needChanged
    ? agent(runnerPrompt(guardCmd('changed'), CHANGED_JSON,
        'the CHANGED-scope scan: every blob this branch would publish, including blobs that exist only in branch history'),
      { label: 'scan:changed', phase: 'Scan', schema: REPORT_SCHEMA }).catch(() => null)
    : Promise.resolve(null)),
  () => (needFull
    ? agent(runnerPrompt(guardCmd('full'), FULL_JSON,
        'the WHOLE-TREE backstop: it catches anything a change-scoped view cannot see'),
      { label: 'scan:full', phase: 'Scan', schema: REPORT_SCHEMA }).catch(() => null)
    : Promise.resolve(null)),
  () => agent(`Run EXACTLY these two commands from the repository root and report both exit codes verbatim.

\`\`\`bash
python3 scripts/check_neutrality.py; echo "NEUTRALITY_EXIT=$?"
python3 scripts/check_no_forks.py;   echo "NOFORKS_EXIT=$?"
\`\`\`

Do NOT edit any file to make either pass. Report what happened, nothing else.`,
    { label: 'scan:neutrality+forks', phase: 'Scan', schema: CHECKS_SCHEMA }).catch(() => null),
])

// ---- Verdict --------------------------------------------------------------
phase('Verdict')

const changedPayload = usable(changedRun?.payload, 'content-guard-report/v1') ? changedRun.payload : null
const fullPayload = usable(fullRun?.payload, 'content-guard-report/v1') ? fullRun.payload : null

// Two agents independently reported HEAD. If they disagree, the tree moved
// underneath the scan and neither result describes a single state of the repo.
const headMismatch = [changedPayload, fullPayload]
  .filter(Boolean)
  .some((p) => p.head && scope.head && p.head !== scope.head)
if (headMismatch) {
  return blocked('the repository changed while it was being scanned (HEAD differs between '
    + 'lanes); no single state was certified. Re-run with a quiet worktree.')
}

const lanes = [
  { name: 'content guard (changed scope)', required: needChanged, payloadRequired: needChanged,
    schema: 'content-guard-report/v1', exit: changedRun?.exit, payload: changedPayload,
    detail: changedRun?.stderr_tail },
  { name: 'content guard (whole tree)', required: needFull, payloadRequired: needFull,
    schema: 'content-guard-report/v1', exit: fullRun?.exit, payload: fullPayload,
    detail: fullRun?.stderr_tail },
  { name: 'IP neutrality (check_neutrality.py)', required: true, payloadRequired: false,
    exit: checksRun?.neutrality_exit, detail: checksRun?.output_tail },
  { name: 'report-generator forks (check_no_forks.py)', required: true, payloadRequired: false,
    exit: checksRun?.no_forks_exit, detail: checksRun?.output_tail },
]

let v = verdict(lanes)

// The scan may be green because a lane never ran. That is not clean.
if (v.clean && !denylistOk(changedPayload || fullPayload)) {
  v = { status: 'CONFIG_ERROR', clean: false,
    reason: 'the client-name term list is not configured, so that lane did not run — a clean '
      + 'result would be misleading. Set CLIENT_DENYLIST (see scripts/gen_denylist.py), or '
      + 'pass {require_denylist:false} to accept a scan without it.' }
}

const primary = changedPayload || fullPayload
const findings = [...new Set([...(changedPayload?.findings || []), ...(fullPayload?.findings || [])])].sort()
const warnings = [...new Set([...(changedPayload?.warnings || []), ...(fullPayload?.warnings || [])])].sort()

// Paths this run actually certified — what /safe-pr is allowed to stage. Taken
// from the tool's own universe (live worktree/index entries only), so the staged
// set can never exceed the scanned set.
const stageablePaths = [...new Set(changedPayload?.paths || [])].sort()

const counts = {
  findings: findings.length,
  warnings: warnings.length,
  universe_changed: changedPayload?.counts?.universe ?? null,
  universe_full: fullPayload?.counts?.universe ?? null,
}

const lanesMd = lanes.filter((l) => l.required).map((l) => {
  const icon = l.exit === 0 ? '✅' : l.exit === 2 ? '⚠️' : l.exit === 1 ? '⛔' : '❓'
  const n = l.payload?.counts ? ` — ${l.payload.counts.universe} item(s) scanned, ${l.payload.counts.findings} finding(s)` : ''
  return `| ${icon} | ${l.name} | exit ${l.exit ?? '—'}${n} |`
}).join('\n')

const findingsMd = findings.length
  ? '\n\n**Findings** (rule and location only — the matched value never leaves the tool):\n'
    + findings.slice(0, 40).map((f) => `- \`${f}\``).join('\n')
    + (findings.length > 40 ? `\n- …and ${findings.length - 40} more` : '')
  : ''

const warningsMd = warnings.length
  ? `\n\n**Warnings** (heuristic classes — review, they do not block):\n`
    + warnings.slice(0, 15).map((w) => `- \`${w}\``).join('\n')
    + (warnings.length > 15 ? `\n- …and ${warnings.length - 15} more` : '')
  : ''

const icon = v.status === 'CLEAN' ? '✅' : v.status === 'BLOCKED' ? '⛔' : '⚠️'
const report_markdown = `${icon} **Content guard — ${v.status}**

\`${scope.branch}\` @ \`${scope.head.slice(0, 8)}\` vs \`${scope.base_ref || 'n/a'}\` · `
  + `${scope.commits_ahead} commit(s) ahead · ${scope.dirty_files} dirty · ${scope.untracked_files} untracked

| | lane | result |
|---|---|---|
${lanesMd}

${v.reason}${findingsMd}${warningsMd}`

return {
  status: v.status,
  clean: v.clean,
  reason: v.reason,
  scope: SCOPE,
  base: scope.base_ref,
  head: scope.head,
  branch: scope.branch,
  commits_ahead: scope.commits_ahead,
  dirty_files: scope.dirty_files,
  untracked_files: scope.untracked_files,
  tree_digest: primary?.tree_digest || null,
  denylist_lane: primary?.lanes?.denylist || 'unknown',
  counts,
  findings,
  warnings,
  stageable_paths: stageablePaths,
  report_markdown,
}
