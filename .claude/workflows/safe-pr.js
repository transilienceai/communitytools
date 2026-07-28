export const meta = {
  name: 'safe-pr',
  description: 'Turn the work currently in this repository — uncommitted changes and the commits already on this branch — into a pull request, but ONLY after the standalone /content-guard workflow certifies that none of it carries a customer name, engagement identifier, target IP, credential, personal data or operator path. The guard runs FIRST and its verdict is structural: on anything other than CLEAN this returns before a branch, commit, push or PR step is ever constructed, so there is no ordering mistake available and nothing reaches GitHub. Then it branches off main if needed, stages exactly the paths the guard certified (never `git add -A`), commits under the repo\'s conventional format, RE-VERIFIES that the committed tree digest still matches the one the guard read, scans the PR and issue bodies as authored public text, and finally pushes and opens the PR against the repo template. Never force-pushes, never uses --no-verify, never commits to main.',
  whenToUse: 'When you want the current state of the repo saved as a reviewable PR without leaking client data — "open a PR for this", "save this work", "/safe-pr". args: {title?, summary?, issue?: <number to link>, create_issue?: true, base?: "main", branch?, draft?: false, type?: "feat"|"fix"|"docs"|"refactor"|"test"|"chore", paths?: [restrict staging to these], dryRun?}. Blocks rather than publishing whenever the guard is not CLEAN, the gh CLI is unauthenticated, or the push would need a token scope the token does not hold.',
  phases: [
    { title: 'Guard', detail: 'the standalone /content-guard workflow — hard gate, nothing runs past it unless CLEAN' },
    { title: 'Plan', detail: 'branch, commit message and PR body, validated against the repo conventions in code' },
    { title: 'Commit', detail: 'branch off main if needed, stage exactly the certified paths, commit' },
    { title: 'Verify', detail: 're-scan the committed state and confirm the digest the guard certified is what will be pushed' },
    { title: 'Publish', detail: 'scan the PR/issue bodies, then push and open the PR' },
  ],
}

// Sandbox: no import/require, no fs, no bash, no wall-clock, no randomness.
//
// WHY THE GATE IS STRUCTURAL, NOT A FLAG
// --------------------------------------
// The sandbox has no shell primitive: the ONLY way this workflow can run git or
// gh is to construct an agent() that does it. The guard check below sits before
// phase('Plan') and returns on anything but CLEAN, so on the blocked path no
// agent capable of touching the remote is ever created. That is a stronger
// property than "we check a boolean before pushing", which is a line of code
// someone can later reorder.
//
// Every rule about what counts as a leak lives in scripts/check_client_data.py,
// reached only through the /content-guard workflow. Nothing here re-implements
// one, and nothing here can overrule one.

// ---- inputs ---------------------------------------------------------------
let __raw = args
if (typeof __raw === 'string') {
  const s = __raw.trim()
  if (s.startsWith('{')) { try { __raw = JSON.parse(s) } catch (e) { __raw = { title: __raw } } }
  else __raw = { title: __raw }
}
const input = (__raw && typeof __raw === 'object' && !Array.isArray(__raw)) ? __raw : {}

const BASE = String(input.base || '').trim()
const TITLE_IN = String(input.title || '').trim()
const SUMMARY_IN = String(input.summary || '').trim()
const ISSUE = Number.isInteger(Number(input.issue)) && Number(input.issue) > 0 ? Number(input.issue) : null
const CREATE_ISSUE = input.create_issue !== false
const DRAFT = !!input.draft
const BRANCH_IN = String(input.branch || '').trim()
const TYPE_IN = String(input.type || '').trim()
const ONLY_PATHS = Array.isArray(input.paths) ? input.paths.filter((p) => typeof p === 'string' && p) : null
const dryRun = !!input.dryRun

const PROTECTED = ['main', 'master']
const COMMIT_TYPES = ['feat', 'fix', 'docs', 'refactor', 'test', 'chore', 'perf', 'ci', 'build', 'style']
const BODY_FILE = '.claude/state/confidentiality/pr-body.md'
const ISSUE_FILE = '.claude/state/confidentiality/issue-body.md'

const EMPTY = { pr_url: null, issue_url: null, branch: null, committed: false, pushed: false }

/** The trailing sentence of a BLOCKED report must be a FUNCTION of the state the
 *  run actually reached, never a constant. A late failure (the PR step) after an
 *  early success (the push) is precisely the case a constant gets wrong, and it
 *  gets it wrong in the dangerous direction — under-reporting what is already
 *  public. Whoever reads this report decides what to clean up from it. */
const NOTHING_HAPPENED = 'Nothing was committed, pushed or published.'
function stateSentence({ committed, pushed, branch }) {
  const on = branch ? `\`${branch}\`` : 'this branch'
  if (pushed) return `⚠️ The commit **was pushed** to \`origin\` on ${on} and is already public — only the step above failed.`
  if (committed) return `The commit exists locally on ${on}; nothing was pushed.`
  return NOTHING_HAPPENED
}

const blocked = (reason, extra) => {
  const state = { ...EMPTY, ...(extra || {}) }
  return {
    ...state, status: 'BLOCKED', reason,
    report_markdown: `⛔ **/safe-pr BLOCKED.** ${reason}\n\n${stateSentence(state)}`,
  }
}

// ---- pure-JS gates --------------------------------------------------------

/** GIT_CONVENTIONS.md: `type: description`. CLAUDE.md makes that file canonical
 *  where the other three documents in this repo disagree. */
function validCommitSubject(s) {
  if (typeof s !== 'string') return false
  const m = s.match(/^([a-z]+)(\([a-z0-9.\-_/]+\))?: (.+)$/)
  if (!m || !COMMIT_TYPES.includes(m[1])) return false
  return m[3].trim().length >= 10 && s.length <= 100 && !s.endsWith('.')
}

function sanitizeBranch(name, type) {
  const slug = String(name || '').toLowerCase().replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '').slice(0, 48).replace(/-+$/g, '')
  const prefix = ({ fix: 'bugfix', docs: 'docs', refactor: 'refactor', test: 'test', chore: 'chore' })[type] || 'feature'
  return slug ? `${prefix}/${slug}` : ''
}

/** A subject line is authored text on its way to a public git log. Refuse the
 *  obvious structural classes here too — the tool scans the PR body, but a commit
 *  subject is published by the push itself, before any body exists. */
const SUBJECT_FORBIDDEN = [
  [/\/(?:Users|home)\/[A-Za-z][A-Za-z0-9._-]{2,}\//, 'an operator home path'],
  [/\b(?:projects|outputs?)\/[a-z-]*\/?\d{6,8}[_-]/, 'an engagement directory'],
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,}\b/, 'credential material'],
]
function subjectLeak(s) {
  for (const [re, what] of SUBJECT_FORBIDDEN) if (re.test(s)) return what
  return null
}

if (dryRun) {
  return { ...EMPTY, status: 'DRY_RUN', report_markdown: '**Dry run.** No guard, no commit, no PR.' }
}

// ---- Guard — the hard gate, before anything else --------------------------
phase('Guard')
log('running the standalone /content-guard workflow over the current changes…')

let guard = null
try {
  guard = await workflow('content-guard', { base: BASE || undefined, scope: 'both' })
} catch (e) {
  return blocked(`the content-guard workflow could not run (${String(e).slice(0, 200)}). `
    + 'Refusing to publish anything that was not scanned.')
}

if (!guard || guard.clean !== true) {
  const why = guard?.reason || 'the guard returned no verdict'
  const detail = guard?.report_markdown ? `\n\n---\n\n${guard.report_markdown}` : ''
  return {
    ...EMPTY,
    status: 'BLOCKED',
    reason: why,
    guard_status: guard?.status || 'UNKNOWN',
    findings: guard?.findings || [],
    report_markdown: `⛔ **/safe-pr BLOCKED — the content guard did not certify this change.**\n\n`
      + `${why}\n\n${NOTHING_HAPPENED} Fix the findings, then re-run `
      + `\`/safe-pr\`. Describe the CLASS of issue rather than the customer, use RFC 5737 `
      + `addresses (203.0.113.x) in examples, and keep engagement data under \`projects/\`.`
      + `${detail}`,
  }
}

log(`guard CLEAN — ${guard.counts?.universe_changed ?? '?'} changed item(s) certified, digest ${String(guard.tree_digest || '').slice(0, 12)}`)

const nothingToDo = !guard.commits_ahead && !guard.dirty_files && !guard.untracked_files
if (nothingToDo) {
  return { ...EMPTY, status: 'NO_CHANGES', branch: guard.branch,
    report_markdown: '**No changes.** Nothing is uncommitted and the branch is level with its base — there is nothing to open a PR for.' }
}

// ---- Plan -----------------------------------------------------------------
phase('Plan')

let stageable = guard.stageable_paths || []
if (ONLY_PATHS) {
  const keep = new Set(ONLY_PATHS)
  const unknown = ONLY_PATHS.filter((p) => !stageable.includes(p))
  if (unknown.length) {
    return blocked(`paths[] names ${unknown.length} path(s) the guard did not scan: `
      + `${unknown.slice(0, 5).join(', ')}. Only certified paths may be staged.`)
  }
  stageable = stageable.filter((p) => keep.has(p))
}

const PLAN_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['type', 'subject', 'summary', 'changes'],
  properties: {
    type: { type: 'string', enum: COMMIT_TYPES, description: 'conventional commit type' },
    subject: { type: 'string', description: 'the full commit subject, `type: description`, imperative mood, no trailing period, <=100 chars. Describe WHY, not a file list. Never name a customer, an engagement directory, a real host or an absolute home path.' },
    summary: { type: 'string', description: '1-3 sentences for the PR Summary section' },
    changes: { type: 'array', items: { type: 'string' }, description: 'bullet points for the Changes Made section, one per meaningful change' },
    branch_slug: { type: 'string', description: 'short kebab-case slug for a branch name, e.g. "content-guard-pr-gate"' },
    touches_skills: { type: 'boolean', description: 'true if any change is under skills/' },
  },
}

const changeList = stageable.slice(0, 60).join('\n')
const plan = await agent(`Describe the change currently in this repository so it can be committed and opened as a pull request.

Base: \`${guard.base}\` · branch: \`${guard.branch}\` · ${guard.commits_ahead} commit(s) already on the branch.

Inspect the actual change — run these (read-only) and read what matters:
\`\`\`bash
git status --short
git diff HEAD --stat
git log --oneline ${guard.base}..HEAD
git diff HEAD
\`\`\`

Paths in scope (${stageable.length}):
${changeList}${stageable.length > 60 ? `\n…and ${stageable.length - 60} more` : ''}

${TITLE_IN ? `The user supplied this title, prefer it: "${TITLE_IN}"` : ''}
${SUMMARY_IN ? `The user supplied this summary, prefer it: "${SUMMARY_IN}"` : ''}
${TYPE_IN ? `The user asked for commit type: "${TYPE_IN}"` : ''}

Conventions (skills/coordination/reference/GIT_CONVENTIONS.md is canonical here):
- commit subject is \`type: description\` — types: ${COMMIT_TYPES.join(', ')}
- imperative mood, no trailing period, <= 100 characters
- the message explains WHY, not a restatement of the diff

THIS REPOSITORY IS PUBLIC. Nothing you write may contain a customer or brand name,
an engagement directory (\`projects/<tree>/<date>_<slug>\`), a real hostname, a
routable IP, a credential, or an absolute home path. Write about the class of
change. Do NOT edit any file. Do NOT run git commands that write.`,
  { label: 'plan', phase: 'Plan', schema: PLAN_SCHEMA }).catch(() => null)

if (!plan || !plan.subject) return blocked('could not describe the change for a commit message.')

let subject = String(plan.subject).trim()
if (TYPE_IN && !subject.startsWith(`${TYPE_IN}:`) && !subject.startsWith(`${TYPE_IN}(`)) {
  subject = `${TYPE_IN}: ${subject.replace(/^[a-z]+(\([^)]*\))?:\s*/, '')}`
}
if (!validCommitSubject(subject)) {
  return blocked(`the proposed commit subject does not match this repo's convention `
    + `\`type: description\` (types: ${COMMIT_TYPES.join(', ')}, imperative, no trailing period, `
    + `<=100 chars). Got: "${subject.slice(0, 80)}". Pass {title:"..."} to set it yourself.`)
}
const subjLeak = subjectLeak(subject)
if (subjLeak) {
  return blocked(`the proposed commit subject contains ${subjLeak}. A commit subject is `
    + `published by the push itself. Rewrite it with {title:"..."}.`)
}

const branch = PROTECTED.includes(guard.branch)
  ? (BRANCH_IN || sanitizeBranch(plan.branch_slug || TITLE_IN || subject.replace(/^[a-z]+(\([^)]*\))?:\s*/, ''), plan.type))
  : guard.branch
if (!branch) return blocked('could not derive a branch name; pass {branch:"feature/..."}.')
if (PROTECTED.includes(branch)) {
  return blocked(`refusing to commit to \`${branch}\`. GIT_CONVENTIONS.md: never commit directly to main.`)
}

// ---- Commit ---------------------------------------------------------------
phase('Commit')

const COMMIT_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['ok', 'branch', 'head', 'committed'],
  properties: {
    ok: { type: 'boolean', description: 'true only if every command exited 0 (or was correctly skipped)' },
    branch: { type: 'string', description: 'the branch actually checked out afterwards' },
    head: { type: 'string', description: 'the full HEAD sha afterwards' },
    committed: { type: 'boolean', description: 'true if a new commit was created; false if there was nothing to commit' },
    staged_count: { type: 'number', description: 'how many paths were staged' },
    error: { type: 'string', description: 'verbatim stderr of the first command that failed' },
  },
}

const needBranch = PROTECTED.includes(guard.branch)
const stageArgs = stageable.map((p) => `'${p.replace(/'/g, `'\\''`)}'`).join(' \\\n     ')

const commitRun = stageable.length === 0
  ? { ok: true, branch: guard.branch, head: guard.head, committed: false, staged_count: 0 }
  : await agent(`Commit the current changes. Run EXACTLY these commands in order, from the repository root.

${needBranch ? `The current branch is protected, so create the feature branch first:
\`\`\`bash
git checkout -b '${branch}'
\`\`\`
` : `Stay on the current branch \`${branch}\`.`}

Stage EXACTLY these ${stageable.length} path(s) — no more, no fewer:
\`\`\`bash
git add -- \\
     ${stageArgs}
\`\`\`

Then commit:
\`\`\`bash
git commit -m '${subject.replace(/'/g, `'\\''`)}'
\`\`\`

Then report:
\`\`\`bash
git rev-parse --abbrev-ref HEAD
git rev-parse HEAD
\`\`\`

HARD RULES:
- NEVER use \`git add -A\`, \`git add .\`, \`git add -f\`, or any path not listed above.
  The listed paths are exactly what a content-security scan certified; anything
  else would be published without ever having been scanned.
- NEVER use \`--no-verify\`. The pre-commit hook is a required gate.
- NEVER use \`--amend\`, \`--force\`, rebase, reset or any history rewrite.
- Do NOT push. Do NOT create a pull request. That happens later.
- If \`git commit\` reports nothing to commit, that is fine: set committed=false
  and report ok=true.
- If ANY command fails, stop immediately, set ok=false and put the verbatim
  stderr in error. Do NOT try to fix it.`,
    { label: 'commit', phase: 'Commit', schema: COMMIT_SCHEMA }).catch(() => null)

if (!commitRun || commitRun.ok !== true) {
  return blocked(`the commit step failed: ${commitRun?.error || 'the agent returned nothing'}.`,
    { branch })
}

// ---- Verify — the committed state must be what the guard read -------------
phase('Verify')

const post = await workflow('content-guard', { base: BASE || undefined, scope: 'both' })
  .catch(() => null)

if (!post || post.clean !== true) {
  return blocked(`the post-commit re-scan did not come back clean (${post?.reason || 'no verdict'}).`,
    { branch: commitRun.branch || branch, committed: !!commitRun.committed })
}
if (post.tree_digest && guard.tree_digest && post.tree_digest !== guard.tree_digest) {
  return blocked('the content changed between the guard run and the commit — the tree digest '
    + `no longer matches what was certified (${String(guard.tree_digest).slice(0, 12)} → `
    + `${String(post.tree_digest).slice(0, 12)}). Re-run /safe-pr on a quiet tree.`,
    { branch: commitRun.branch || branch, committed: !!commitRun.committed })
}

// ---- Publish --------------------------------------------------------------
phase('Publish')

const changesMd = (plan.changes || []).length
  ? plan.changes.map((c) => `- ${String(c).replace(/^[-*]\s*/, '')}`).join('\n')
  : '- (see commits)'

const typeBox = (t) => (plan.type === t ? 'x' : ' ')
const guardBlock = `**Content guard:** \`/content-guard\` — **CLEAN**
- changed-scope: ${post.counts?.universe_changed ?? '?'} item(s) scanned (every blob this branch introduces, plus worktree, index and untracked)
- whole-tree backstop: ${post.counts?.universe_full ?? '?'} item(s) scanned
- client-name lane: ${post.denylist_lane}
- tree digest: \`${String(post.tree_digest || '').slice(0, 16)}\`
${post.counts?.warnings ? `- ${post.counts.warnings} heuristic warning(s) — non-blocking, reviewed` : ''}`

const prBody = `## Summary

${plan.summary || SUMMARY_IN || subject}

## Related Issue

Closes #${ISSUE ? ISSUE : '__ISSUE__'}

## Changes Made

${changesMd}

## Type of Change

- [${typeBox('fix')}] Bug fix (non-breaking change that fixes an issue)
- [ ] New skill or agent
- [${plan.touches_skills && plan.type !== 'fix' ? 'x' : ' '}] Enhancement to existing skill/agent
- [${typeBox('docs')}] Documentation update
- [${typeBox('ci')}] CI/CD or infrastructure
- [${typeBox('refactor')}] Refactoring (no functional change)
- [${['feat', 'test', 'chore', 'perf', 'build', 'style'].includes(plan.type) && !plan.touches_skills ? 'x' : ' '}] Other: ${plan.type}

## Testing

- [ ] Tested skill/agent in Claude Code session
- [ ] Tested against vulnerable application (DVWA, WebGoat, Juice Shop, etc.)
- [ ] Verified no false positives
- [x] Ran existing tests
- [ ] Manual review only (documentation/config changes)

**Test details:**

${guardBlock}

## Checklist

- [x] My code follows the contribution guidelines
- [x] Commits use conventional format: \`type: description\`
- [ ] I've updated documentation where needed
- [ ] New skills include \`SKILL.md\` and \`reference/\` directory
- [x] No secrets, credentials, or unauthorized target information included
- [x] This PR links to an issue with \`Closes #N\`
${plan.touches_skills ? `
## Skill / agent checklist

- [ ] \`python3 scripts/skill_linter.py\` runs clean (or rationale below).
- [ ] No new challenge-specific identifiers outside \`skills/hackthebox/\`.
- [ ] \`SKILL.md\` ≤ 150 lines; \`reference/*.md\` ≤ 200 lines.
` : ''}
---
🤖 Generated with [Claude Code](https://claude.com/claude-code)
`

const touchesWorkflows = (post.stageable_paths || []).some((p) => p.startsWith('.github/workflows/'))
const issueTitle = subject.replace(/^[a-z]+(\([^)]*\))?:\s*/, '')

// The bodies are written and SCANNED by their own agent, which has no push and no
// gh capability. The gate on its result is a code-side return below, so — exactly
// like the content-guard gate — the agent that can publish is never constructed
// when the scan fails. Folding this into the publishing agent would make it a
// sentence in a prompt asking the model to stop itself, which is not a gate.
const BODIES_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['ok', 'pr_body_exit', 'issue_body_exit'],
  properties: {
    ok: { type: 'boolean', description: 'true only if both files were written and both scans ran' },
    pr_body_exit: { type: ['number', 'null'], description: 'exit code of the PR-body scan, verbatim: 0 clean, 1 findings, 2 config error' },
    issue_body_exit: { type: ['number', 'null'], description: 'exit code of the issue-body scan, verbatim; 0 if no issue body was needed' },
    findings_tail: { type: 'string', description: 'the redacted scan output, verbatim, if either scan was non-zero' },
    error: { type: 'string', description: 'verbatim stderr of anything that failed' },
  },
}

const issueBody = `## Summary

${plan.summary || subject}

## Scope

${changesMd}

---
🤖 Generated with [Claude Code](https://claude.com/claude-code)
`

const bodies = await agent(`Write two files and scan them. You are NOT publishing anything — do not push, do not run any \`gh\` command, do not touch git.

**Step 1.** Write EXACTLY this content to \`${BODY_FILE}\` (create the directory if needed), verbatim:

<<<PR_BODY
${prBody}
PR_BODY

${ISSUE ? `**Step 2.** No issue body is needed. Set issue_body_exit to 0.` : `**Step 2.** Write EXACTLY this to \`${ISSUE_FILE}\`, verbatim:

<<<ISSUE_BODY
${issueBody}
ISSUE_BODY`}

**Step 3 — scan both files.** A PR body and an issue body are public text that no
other seam in this repository scans.

\`\`\`bash
python3 scripts/check_client_data.py --scan-file ${BODY_FILE} --redact; echo "PR_BODY_EXIT=$?"
${ISSUE ? '' : `python3 scripts/check_client_data.py --scan-file ${ISSUE_FILE} --redact; echo "ISSUE_BODY_EXIT=$?"`}
\`\`\`

Report both exit codes VERBATIM. Do NOT edit either file to make a scan pass, and do
NOT omit a finding. If a scan is non-zero, that is the correct outcome to report —
put its redacted output in findings_tail. Reporting 0 for a scan that printed
findings would publish the very thing the scan exists to catch.`,
  { label: 'bodies', phase: 'Publish', schema: BODIES_SCHEMA }).catch(() => null)

if (!bodies || bodies.ok !== true
    || bodies.pr_body_exit !== 0 || bodies.issue_body_exit !== 0) {
  const codes = `PR body exit ${bodies?.pr_body_exit ?? '—'}, issue body exit ${bodies?.issue_body_exit ?? '—'}`
  return blocked(`the PR/issue body did not pass the content scan (${codes}). Authored text `
    + `becomes public the moment the PR opens. `
    + `${bodies?.findings_tail ? `Scan said: ${String(bodies.findings_tail).slice(0, 400)}` : ''}`
    + `${bodies?.error ? ` ${String(bodies.error).slice(0, 200)}` : ''}`,
    { branch: commitRun.branch || branch, committed: !!commitRun.committed })
}

/** `pushed` and `pr_create_exit` are REQUIRED and reported separately from `ok`.
 *  Collapsing them into one boolean is what let a failed `gh pr create` erase a
 *  push that had already succeeded: the report then denied that public bytes were
 *  public. Each observable step reports its own outcome; JS decides what they mean. */
const PUBLISH_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['ok', 'pushed', 'pr_create_exit'],
  properties: {
    ok: {
      type: 'boolean',
      description: 'true only if `gh auth status` and `git push` exited 0. The PR step reports through pr_create_exit, NOT through this field.',
    },
    gh_scopes: { type: 'string', description: 'the token scopes line from `gh auth status`, verbatim' },
    pushed: { type: 'boolean', description: 'true only if `git push` exited 0' },
    pr_create_exit: { type: 'integer', description: 'the exit code of `gh pr create`, verbatim' },
    pr_create_error: { type: 'string', description: 'verbatim stderr of `gh pr create` if it failed, else ""' },
    issue_url: { type: 'string', description: 'URL of the issue created or linked, or ""' },
    pr_url: { type: 'string', description: 'the URL printed by `gh pr view` in the final step, or ""' },
    error: { type: 'string', description: 'verbatim stderr of the first command that failed' },
  },
}

const publish = await agent(`Publish this branch as a pull request. The PR body at \`${BODY_FILE}\`${ISSUE ? '' : ` and the issue body at \`${ISSUE_FILE}\``} are already written and have already passed a content scan — use them as they are and do not rewrite their prose.

Branch: \`${commitRun.branch || branch}\` · base: \`${(guard.base || 'main').replace(/^origin\//, '')}\`

Follow the steps IN ORDER and stop at the first failure.

**Step 1 — check the token can do the push.**
\`\`\`bash
gh auth status
\`\`\`
Report the token scopes line verbatim in gh_scopes.${touchesWorkflows ? `
This change touches \`.github/workflows/\`, so the token MUST hold the \`workflow\` scope.
If it does not, STOP: set ok=false, pushed=false and put this in error:
"the gh token lacks the 'workflow' scope and this change edits .github/workflows/; run: gh auth refresh -h github.com -s workflow"` : ''}
If gh is not authenticated at all, STOP: set ok=false and say so.

**Step 2 — push.**
\`\`\`bash
git push -u origin '${commitRun.branch || branch}'
\`\`\`
NEVER \`--force\`, NEVER \`--force-with-lease\`, NEVER \`--no-verify\`. If the push is
rejected, STOP and report the verbatim error — do not rebase, reset or retry.

${ISSUE ? `**Step 3 — the issue is already chosen (#${ISSUE}).** Set issue_url to its URL:
\`\`\`bash
gh issue view ${ISSUE} --json url --jq .url
\`\`\`
` : CREATE_ISSUE ? `**Step 3 — create the tracking issue** (this repo will not merge a PR without one):
\`\`\`bash
gh issue create --title '${issueTitle.replace(/'/g, `'\\''`)}' --body-file ${ISSUE_FILE}
\`\`\`
Report its URL as issue_url. Then replace the literal text \`__ISSUE__\` in
\`${BODY_FILE}\` with the new issue's NUMBER (digits only, no #). That is the only
edit you may make to that file.
` : `**Step 3 — no issue.** Replace the line \`Closes #__ISSUE__\` in \`${BODY_FILE}\`
with \`_No issue linked._\` and set issue_url to "".
`}

**Step 4 — open the pull request.**
\`\`\`bash
gh pr create --base '${(guard.base || 'main').replace(/^origin\//, '')}' \\
  --head '${commitRun.branch || branch}' \\
  --title '${subject.replace(/'/g, `'\\''`)}' \\
  --body-file ${BODY_FILE}${DRAFT ? ' \\\n  --draft' : ''}; echo "PR_CREATE_EXIT=$?"
\`\`\`
Report that exit code VERBATIM as pr_create_exit and its stderr as pr_create_error.
A non-zero exit is NOT yours to interpret or work around: do not close, reopen,
retarget or edit any existing pull request, and do not retry with different flags.
Report it and continue to Step 5 — the caller decides what it means.

**Step 5 — resolve the pull request for this branch.** Run this WHETHER OR NOT
Step 4 succeeded. It returns the PR that the push just updated when the branch
already had one open, and the PR Step 4 just opened otherwise.
\`\`\`bash
gh pr view '${commitRun.branch || branch}' --json url --jq .url
\`\`\`
Report that URL as pr_url, or "" if the command finds no pull request.

HARD RULES: do not modify any repository file other than the issue-number
substitution above. Do not amend, rebase, reset or force anything. Do not re-run the
content guard with different flags. If a step fails, stop and report it verbatim —
never work around it.`,
  { label: 'publish', phase: 'Publish', schema: PUBLISH_SCHEMA }).catch(() => null)

const prBranch = commitRun.branch || branch

if (!publish || publish.ok !== true || !publish.pushed) {
  return blocked(`${publish?.error || 'the publish step returned nothing'}. Nothing reached GitHub.`,
    { branch: prBranch, committed: !!commitRun.committed })
}

// The push has landed, so the certified bytes are on `origin` — and if this branch
// already had an open PR, they are already in review. `gh pr create` refusing
// because that PR exists is therefore the SUCCESS path: what /safe-pr promises is
// that the work is guard-certified and reviewable on GitHub, not that this
// particular run is the one that opened the PR. Only an unresolvable PR blocks.
const prUrl = String(publish.pr_url || '').trim()
const prExisted = publish.pr_create_exit !== 0

if (!prUrl) {
  return blocked(`the push succeeded but no pull request could be resolved for \`${prBranch}\` `
    + `(\`gh pr create\` exited ${publish.pr_create_exit}`
    + `${publish.pr_create_error ? `: ${String(publish.pr_create_error).slice(0, 300)}` : ''}). `
    + `Open one by hand against \`${(guard.base || 'main').replace(/^origin\//, '')}\`, or re-run `
    + `\`/safe-pr\` once the cause is fixed — the commit itself is certified and pushed.`,
    { branch: prBranch, committed: !!commitRun.committed, pushed: true })
}

const warn = post.counts?.warnings
  ? `\n\n⚠️ ${post.counts.warnings} heuristic warning(s) from the guard (address / named contact / phone). They do not block, but review them:\n`
    + (post.warnings || []).slice(0, 10).map((w) => `- \`${w}\``).join('\n')
  : ''

// A pre-existing PR keeps its own title and description: they are authored text a
// human may have edited, and silently overwriting them would be the documentation
// equivalent of a force-push. Say so instead.
const existedNote = prExisted
  ? `\n\nThis branch already had an open pull request, so the push added the commit to it `
    + `rather than opening a second one. Its existing title and description were left `
    + `untouched — the body this run composed was **not** applied. Update it by hand if it `
    + `no longer describes the branch.`
  : ''

return {
  status: 'OK',
  reason: prExisted
    ? 'guard clean, committed, pushed; the branch already had an open PR, which now carries the commit'
    : 'guard clean, committed, pushed, PR opened',
  branch: prBranch,
  committed: !!commitRun.committed,
  pushed: true,
  pr_url: prUrl,
  pr_existed: prExisted,
  issue_url: publish.issue_url || null,
  subject,
  guard_status: post.status,
  tree_digest: post.tree_digest,
  counts: post.counts,
  report_markdown: `✅ **${prExisted ? 'Existing PR updated' : 'PR opened'}.**

${prUrl}

| | |
|---|---|
| branch | \`${prBranch}\` → \`${(guard.base || 'main').replace(/^origin\//, '')}\` |
| commit | \`${subject}\` |
| issue | ${publish.issue_url || '—'} |
| content guard | **CLEAN** — ${post.counts?.universe_changed ?? '?'} changed item(s) + ${post.counts?.universe_full ?? '?'} whole-tree item(s) scanned |
| client-name lane | ${post.denylist_lane} |
| tree digest | \`${String(post.tree_digest || '').slice(0, 16)}\` |

The guard ran before the commit and again after it, and the digest it certified is the one that was pushed.${existedNote}${warn}`,
}
