// certin-wiring.test.mjs — static-source assertions that the CERT-In export is
// wired correctly and NON-BLOCKING (things unit tests can't see): the standalone
// workflow conventions, the guarded finalize step placed BEFORE packaging, the
// schema/return fields, and — critically — that CERT-In never becomes a gate
// operand and the frozen wf-helpers.mjs is untouched.
// Run: node .claude/workflows/lib/certin-wiring.test.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const libDir = dirname(fileURLToPath(import.meta.url));
const wfDir = join(libDir, '..');
const repo = join(wfDir, '..', '..');
const read = (f) => readFileSync(join(wfDir, f), 'utf8');
const readRepo = (f) => readFileSync(join(repo, f), 'utf8');

const ce = read('certin-export.js');
const pe = read('pentest-engagement.js');
const helpers = readFileSync(join(libDir, 'wf-helpers.mjs'), 'utf8');
const build = readRepo('tools/certin_metadata_build.py');
const scope = readRepo('skills/pentest-engagement/reference/scope-file-format.md');
const index = readRepo('formats/INDEX.md');

let pass = 0, fail = 0; const fails = [];
const ok = (cond, msg) => { if (cond) pass++; else { fail++; fails.push(`✗ ${msg}`); } };

// ---- certin-export.js conventions ----------------------------------------
ok(/export const meta = \{/.test(ce) && /name:\s*'certin-export'/.test(ce), 'certin-export has meta.name');
ok(/whenToUse:/.test(ce) && /output_dir/.test(ce) && /certin/.test(ce) && /first_final/.test(ce) && /dryRun/.test(ce), 'whenToUse documents output_dir/certin/first_final/dryRun');
ok((ce.match(/\{ title:/g) || []).length >= 4, 'certin-export declares >=4 phases (Gather/Classify/Build/Verify)');
ok(!/^\s*(import |const .*= *require\()/m.test(ce), 'certin-export uses no top-level import/require (sandbox)');
{
  // every agent( ... ) call is paired with a .catch(
  const agentCalls = (ce.match(/await agent\(/g) || []).length;
  const catches = (ce.match(/\)\s*\.catch\(/g) || []).length;
  ok(agentCalls >= 4 && catches >= agentCalls, `every agent() is .catch()-wrapped (${agentCalls} calls, ${catches} catches)`);
}
ok(/return \{[\s\S]*status:/.test(ce), 'certin-export returns a status object');
ok(/certin_metadata_build\.py --engagement-dir \$\{OUTPUT_DIR\}/.test(ce), 'Build phase runs the deterministic builder');
ok(/GATHER_SCHEMA/.test(ce) && /CLASSIFY_SCHEMA/.test(ce) && /BUILD_SCHEMA/.test(ce) && /VERIFY_SCHEMA/.test(ce), 'each phase declares its *_SCHEMA');
ok(/ROLE: CERT-IN CLASSIFIER \(single batched pass/.test(ce), 'Classify is a single batched agent (not per-finding fan-out — P1)');
ok(/ROLE: CERT-IN VERIFIER \(blind/.test(ce), 'Verify is a blind independent agent');

// ---- pentest-engagement.js auto-trigger (guarded, non-blocking) ----------
// Exact equality, not >=: the property is that EVERY finalize site threads it and
// no site is dead code. A mobile CERT-In audit would otherwise silently lose its
// deliverable.
ok((pe.match(/certinExport: input\.certin_export === true/g) || []).length === 3, 'certinExport threaded at ALL THREE finalize call sites (web + network + mobile)');
ok(/const wantCertin = opts\.certinExport === true/.test(pe), 'finalizeEngagement derives wantCertin from opts');
ok(/certin_metadata_build\.py --engagement-dir \$\{engagementDir\}/.test(pe), 'the guarded finalize step runs the builder');
{
  // the certin build step must appear BEFORE the packaging zip in the runner prompt
  const iCertin = pe.indexOf('certin_metadata_build.py');
  const iZip = pe.indexOf('Package the deliverable');
  ok(iCertin > 0 && iZip > 0 && iCertin < iZip, 'CERT-In build is injected BEFORE the Step 5 zip (both files land in the deliverable)');
}
ok(/certin_ok: \{ type: 'boolean'/.test(pe) && /certin_needs_manual: \{ type: 'array'/.test(pe), 'FINALIZE_SCHEMA carries the certin_* fields');
ok(/certin_json: wantCertin \? \(r\.certin_json \|\| null\) : null/.test(pe), 'the return surfaces certin_json gated by wantCertin');

// ---- NON-BLOCKING invariant (the load-bearing assertion) -----------------
{
  const gateCall = (pe.match(/const gate = finalizeGate\(\{[^}]*\}\)/) || [''])[0];
  ok(gateCall.length > 0 && !/certin/i.test(gateCall), 'finalizeGate(...) has NO certin operand');
  const renderGate = (pe.match(/const renderGateOk =[^\n]*/) || [''])[0];
  ok(!/certin/i.test(renderGate), 'renderGateOk has NO certin operand');
}
ok(!/certin/i.test(helpers), 'the frozen wf-helpers.mjs is UNTOUCHED by the CERT-In feature (no certin references)');

// ---- builder is stdlib-only (openpyxl/xlsxwriter are installed) -----------
ok(!/\b(import\s+openpyxl|from\s+openpyxl|import\s+xlsxwriter|from\s+xlsxwriter)\b/.test(build), 'builder imports no openpyxl/xlsxwriter');

// ---- docs + index --------------------------------------------------------
ok(/certin_export/.test(scope) && /"certin"/.test(scope), 'scope-file-format.md documents certin_export + certin');
ok(/Regulatory \/ Submission Formats/.test(index) && /certin-audit-metadata\/certin-audit-metadata\.md/.test(index), 'formats/INDEX.md links the CERT-In spec under a Regulatory section');

// ---- report --------------------------------------------------------------
if (fail) { console.error(fails.join('\n')); console.error(`\ncertin-wiring: ${pass} passed, ${fail} FAILED`); process.exit(1); }
console.log(`certin-wiring: ${pass} passed, 0 failed`);
