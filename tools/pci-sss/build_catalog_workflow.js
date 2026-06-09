export const meta = {
  name: 'pci-sss-catalog-build',
  description: 'Transcribe the PCI SSS v2.0 Test Requirements catalog verbatim from the source PDF, one agent per Security Objective / Module, then a completeness+fidelity review pass. Each agent writes a JSON array part to skills/pci-secure-software/reference/catalog/parts/<unit>.json. The parent then merges (build_catalog.py) and validates (validate_catalog.py).',
  whenToUse: 'Build/rebuild the deterministic PCI SSS v2.0 catalog from the pinned PDF.',
  phases: [
    { title: 'Transcribe', detail: 'one agent per Security Objective / Module reads its PDF pages and emits verbatim catalog entries' },
    { title: 'Review', detail: 'a second agent re-reads the same pages and repairs the part for completeness + verbatim fidelity + correct enums' },
  ],
}

const PDF = 'PCI-Secure-Software-Standard-v2.0.pdf'
const PARTS = 'skills/pci-secure-software/reference/catalog/parts'

// PDF page = printed page + 4 (constant offset in the document body).
const UNITS = [
  { unit: 'so-01', module: 'core', objectives: { '1': 'Software Architecture, Composition, and Versioning' }, lo: 12, hi: 16, appl: '{"always":true}' },
  { unit: 'so-02', module: 'core', objectives: { '2': 'Sensitive Asset Identification' }, lo: 17, hi: 28, appl: '{"always":true}' },
  { unit: 'so-03', module: 'core', objectives: { '3': 'Sensitive Asset Storage and Retention' }, lo: 29, hi: 34, appl: '{"always":true}' },
  { unit: 'so-04', module: 'core', objectives: { '4': 'Sensitive Modes of Operation' }, lo: 35, hi: 41, appl: '{"all":[{"ctx":"sensitive_mode","eq":true}]}' },
  { unit: 'so-05', module: 'core', objectives: { '5': 'Sensitive Asset Protection Mechanisms' }, lo: 42, hi: 53, appl: '{"always":true}' },
  { unit: 'so-06', module: 'core', objectives: { '6': 'Sensitive Asset Output' }, lo: 54, hi: 56, appl: '{"always":true}' },
  { unit: 'so-07', module: 'core', objectives: { '7': 'Random Numbers' }, lo: 57, hi: 60, appl: '{"all":[{"ctx":"random_for_sensitive_assets","eq":true}]}' },
  { unit: 'so-08', module: 'core', objectives: { '8': 'Key Management' }, lo: 61, hi: 63, appl: '{"always":true}' },
  { unit: 'so-09', module: 'core', objectives: { '9': 'Cryptography' }, lo: 64, hi: 64, appl: '{"always":true}' },
  { unit: 'so-10', module: 'core', objectives: { '10': 'Threats and Vulnerabilities' }, lo: 65, hi: 66, appl: '{"always":true}' },
  { unit: 'so-11', module: 'core', objectives: { '11': 'Secure Deployment and Management' }, lo: 67, hi: 68, appl: '{"always":true}' },
  { unit: 'module-a', module: 'A', objectives: { 'A1': 'Securing Account Data' }, lo: 69, hi: 70, appl: '{"all":[{"ctx":"account_data","eq":true}]}' },
  { unit: 'module-b', module: 'B', objectives: { 'B1': 'PTS Approval', 'B2': 'Approved POI Device Functionality', 'B3': 'Authentication' }, lo: 71, hi: 77, appl: '{"all":[{"ctx":"pts_poi_device","eq":true}]}',
    note: 'Module B applicability base is {"all":[{"ctx":"pts_poi_device","eq":true}]}. For requirement 2-1 (B2-1) — the NON-SRED branch — ADD {"ctx":"sred_approved","eq":false}. For requirement 2-2 and its sub-tree (B2-2.x) — the SRED branch — ADD {"ctx":"sred_approved","eq":true}. All other B rows use the base.' },
  { unit: 'module-c', module: 'C', objectives: { 'C1': 'HTTP Headers', 'C2': 'Input Protection Mechanisms', 'C3': 'Session Management', 'C4': 'User Authentication' }, lo: 78, hi: 87, appl: '{"all":[{"ctx":"public_network_interface","eq":true}]}' },
  { unit: 'module-d', module: 'D', objectives: { 'D1': 'SDK Integrity' }, lo: 88, hi: 89, appl: '{"all":[{"ctx":"is_sdk","eq":true}]}' },
]

const SCHEMA_BRIEF = `Each catalog entry is a JSON object with EXACTLY these fields (schema: skills/pci-secure-software/reference/core/schema.md §1):
- "id": the atomic lettered Test Requirement id, verbatim from the PDF. Format <objective>-<req>[.<sub>[.<sub>]].<letter>, e.g. "1-3.c", "2-1.8.9.a", "4-1.7.6.c", "C2-1.d", "A1-1.a", "B2-2.1.1.a". The id ALWAYS ends in a single lowercase letter (a Test Requirement). Do NOT emit rows for bare Security Requirements (e.g. "1-3" with no letter) — only the lettered Test Requirements under them.
- "module": "core" | "A" | "B" | "C" | "D"
- "objective": the Security Objective number/code as a string (e.g. "1", "11", "A1", "B2", "C2", "D1")
- "objective_title": the verbatim Security Objective title (given to you per objective below)
- "requirement_id": the parent Security Requirement id = the id WITHOUT the trailing ".<letter>" (e.g. "5-3.3.1" for "5-3.3.1.c"; "C2-1" for "C2-1.d")
- "requirement_text": VERBATIM text of the parent Security Requirement (the statement the lettered tests verify). Copy exactly from the PDF, including punctuation. If several letters share one parent, repeat the same requirement_text on each.
- "test_requirement_text": VERBATIM text of THIS lettered Test Requirement (the ".a"/".b"/".c"/".d" line). Copy exactly, including any "- Attempting to ..." bullet sub-text and any leveraged-from references. This is the citation anchor — fidelity is critical.
- "test_method": the FIRST word of test_requirement_text, one of: "Examine" | "Interview" | "Observe" | "Perform" | "Test" | "Verify".
- "analysis_type": derive from the text: "Perform static analysis" -> "static"; "Perform dynamic analysis" -> "dynamic"; "Perform static and/or dynamic analysis" (or "static and dynamic") -> "static-and-or-dynamic"; "Perform research" -> "research"; everything else (Examine / Verify / Interview / Observe) -> "documentation-only".
- "polarity": "negative" if the text describes attempting to violate, bypass, or circumvent a control (look for "Attempting to violate, bypass, or otherwise circumvent" or similar); otherwise "positive".
- "applicability": the applicability AST for this row (given to you per unit below). Copy it verbatim as a JSON object.
- "cross_refs": array of strings parsed from "Leverage information from X and Y", "as accounted for in Z", "from <id>.a/.b" — list the referenced requirement_ids or ids. Empty array if none.
- "guidance": VERBATIM text of any Implementation Note / Testing Note / Guidance attached to this requirement (may be ""). Keep it short — the note text only.
- "printed_page": the printed footer page number where this row appears (an integer).
- "pdf_page": printed_page + 4 (the PDF page; equals the page you Read it from).`

function transcribePrompt(u) {
  const objList = Object.entries(u.objectives).map(([k, v]) => `  - objective "${k}": title "${v}"`).join('\n')
  return `ROLE: VERBATIM CATALOG TRANSCRIBER for the PCI Secure Software Standard v2.0. cwd is the repo root.

Read the source PDF "${PDF}" pages ${u.lo}-${u.hi} using the Read tool with the pages parameter (e.g. Read("${PDF}", pages:"${u.lo}-${u.hi}")). These pages contain Security Objective(s):
${objList}

Transcribe EVERY lettered Test Requirement on those pages that belongs to the objective(s) above into a JSON array. Boundary discipline: only emit rows whose id belongs to your objective(s); ignore any content from adjacent objectives that bleeds onto a boundary page.

${SCHEMA_BRIEF}

applicability for this unit: use ${u.appl} for every row${u.note ? '. SPECIAL CASE: ' + u.note : ''}.

CRITICAL fidelity rules:
- requirement_text and test_requirement_text MUST be verbatim copies from the PDF — no paraphrasing, no summarizing, no fixing of wording. Preserve exact punctuation and any sub-bullets.
- Capture ALL letters for each Security Requirement (if you see .a and .c, there is a .b — find it). The validator enforces contiguous a,b,c lettering per requirement.
- Capture deeply-nested ids (e.g. 2-1.8.9.a, 4-1.7.7.a, 5-3.3.1.c, B2-2.1.1.a). Do not skip sub-levels.
- Be exhaustive. Missing a Test Requirement is the worst failure.

Write the JSON array (and NOTHING else — no markdown fences, no prose) to ${PARTS}/${u.unit}.json using the Write tool. The file content must be a single valid JSON array of entry objects.

Return a status object: {unit, count, ids_first, ids_last, objectives_covered}.`
}

function reviewPrompt(u) {
  const objList = Object.keys(u.objectives).join(', ')
  return `ROLE: CATALOG FIDELITY + COMPLETENESS REVIEWER for PCI SSS v2.0. cwd is the repo root.

Re-read "${PDF}" pages ${u.lo}-${u.hi} (Read with pages parameter) AND read the existing part file ${PARTS}/${u.unit}.json. Your job is to REPAIR that file so it is a complete, verbatim, schema-correct transcription of every lettered Test Requirement for objective(s) ${objList}.

Check and fix, editing ${PARTS}/${u.unit}.json in place (Write the corrected full JSON array):
1. COMPLETENESS: every lettered Test Requirement on those pages is present. Find any missing letters (contiguous a,b,c,... per requirement) and any missing deeply-nested ids. Add them.
2. VERBATIM: requirement_text and test_requirement_text exactly match the PDF (no paraphrase). Fix any drift.
3. ENUMS: test_method is the first word; analysis_type matches the rule ("Perform static analysis"->static, "Perform dynamic analysis"->dynamic, "static and/or dynamic"->static-and-or-dynamic, "Perform research"->research, else documentation-only); polarity is "negative" iff the text says attempt to violate/bypass/circumvent.
4. IDS: ids match ^([0-9]{1,2}|[A-D][0-9])-[0-9]+(\\.[0-9]+){0,2}\\.[a-z]$ and end in a single letter; requirement_id is the id minus the trailing letter; printed_page/pdf_page correct (pdf_page = printed_page + 4).
5. APPLICABILITY: ${u.appl}${u.note ? ' — ' + u.note : ''}.

The file must remain a single valid JSON array, no markdown fences. Return {unit, count, issues_fixed:[...], complete:true|false}.`
}

const STATUS = {
  type: 'object', additionalProperties: true, required: ['unit', 'count'],
  properties: {
    unit: { type: 'string' }, count: { type: 'number' },
    ids_first: { type: ['string', 'null'] }, ids_last: { type: ['string', 'null'] },
    objectives_covered: { type: 'array', items: { type: 'string' } },
    issues_fixed: { type: 'array', items: { type: 'string' } },
    complete: { type: 'boolean' },
  },
}

const results = await pipeline(
  UNITS,
  (u) => agent(transcribePrompt(u), { schema: STATUS, label: `transcribe:${u.unit}`, phase: 'Transcribe', agentType: 'general-purpose' })
           .then(r => ({ u, transcribe: r })),
  (carry) => agent(reviewPrompt(carry.u), { schema: STATUS, label: `review:${carry.u.unit}`, phase: 'Review', agentType: 'general-purpose' })
           .then(r => ({ unit: carry.u.unit, transcribed: carry.transcribe && carry.transcribe.count, reviewed: r && r.count, complete: r && r.complete }))
           .catch(e => ({ unit: carry.u.unit, error: String(e) })),
)

const total = results.reduce((s, r) => s + (Number(r && r.reviewed) || 0), 0)
log(`catalog transcription complete: ${results.length} units, ~${total} test requirements`)
return { units: results, total_estimate: total }
