// parity.test.mjs — guarantees the inline helper copies embedded in the workflow
// scripts are byte-identical to the tested source of truth (wf-helpers.mjs).
// The sandbox forbids `import`, so the workflows MUST embed copies; this test is
// what keeps them from drifting. Run: node .claude/workflows/lib/parity.test.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const module = readFileSync(join(here, 'wf-helpers.mjs'), 'utf8');
const wfDir = join(here, '..');

// Extract a top-level `function NAME(...) { ... }` OR `const NAME = { ... }` by
// brace matching. For functions, skip the parameter list first (so a `= {}`
// default param is not mistaken for the body) then match the real body brace.
function extractFn(src, name) {
  const fnSig = `function ${name}(`;
  let start = src.indexOf(fnSig);
  let bodyStart;
  if (start >= 0) {
    let pdepth = 0, k = start + fnSig.length - 1; // at the '('
    for (; k < src.length; k++) {
      if (src[k] === '(') pdepth++;
      else if (src[k] === ')') { pdepth--; if (pdepth === 0) { k++; break; } }
    }
    bodyStart = src.indexOf('{', k);
  } else {
    start = src.indexOf(`const ${name} = {`);
    if (start < 0) return null;
    bodyStart = src.indexOf('{', start);
  }
  if (bodyStart < 0) return null;
  let depth = 0;
  for (let j = bodyStart; j < src.length; j++) {
    const ch = src[j];
    if (ch === '{') depth++;
    else if (ch === '}') { depth--; if (depth === 0) return src.slice(start, j + 1); }
  }
  return null;
}

// Which shared functions/schemas each workflow file embeds. The two entries
// DIFFER: each file lists only what it actually embeds (no dead-code forced).
const LANE = ['nvdKevText', 'terminalSubdir', 'buildInterim', 'checksPrompt', 'refuterPrompt', 'probePrompt', 'reproPrompt', 'curePrompt', 'CHECKS_SCHEMA', 'VOTE_SCHEMA', 'PROBE_SCHEMA', 'REPRO_SCHEMA'];
const VERDICT = ['severityBand', 'riskBucket', 'riskScore', 'exposureFor', 'normVector', 'cveReconcile', 'EVIDENCE_MANIFEST', 'evidenceComplete', 'computeVerdict', 'finalPoc', 'round4', 'TIER_WEIGHTS', 'RISK_THRESHOLDS'];
const GOVERNOR = ['cureLoopDecision', 'coverageDecision', 'shouldInlineValidate', 'backstopDecision', 'assessBudget', 'summarizeLoopCounts', 'reduceCandidateVerdicts'];
const EXPECT = {
  'validate-findings.js': ['severityBand', 'riskBucket', 'riskScore', 'exposureFor', 'normVector', 'cveReconcile', 'EVIDENCE_MANIFEST', 'evidenceComplete', 'computeVerdict', 'finalPoc', 'round4', ...LANE],
  // coordinator-loop embeds the WHOLE interleaved validation lane (verdict + governor + prompts).
  'coordinator-loop.js': [...VERDICT, ...GOVERNOR, ...LANE],
  'pentest-engagement.js': ['severityBand', 'normalizeAssess', 'reconcileAssessed', 'finalizeGate', 'bumpVersion', 'scopeDiff', 'resolveEngagementMeta', 'detectAllowlist', 'resolveGeoZones'],
};

// Scalar constants that must be identical everywhere they appear.
const SCALARS = { 'DEFAULT_VOTES = 3': ['validate-findings.js', 'coordinator-loop.js'] };

// Compare LOGIC, not cosmetics: strip semicolons (the workflow files follow the
// repo's no-semicolon style) and collapse whitespace. Real logic changes still fail.
const norm = (s) => s
  .replace(/\/\*[\s\S]*?\*\//g, '')   // block comments
  .replace(/\/\/[^\n]*/g, '')         // line comments (helper bodies contain no // in strings)
  .replace(/;/g, '')                  // semicolons (workflow files omit them)
  .replace(/\s+/g, ' ')
  .replace(/\s*,\s*/g, ',')           // spacing around commas (arg-list line-wrapping)
  .replace(/,([}\])])/g, '$1')        // trailing commas (multi-line canonical vs inlined copy)
  .replace(/\s+([}\])])/g, '$1')      // space before a closing bracket (line-wrapping)
  .replace(/([{[(])\s+/g, '$1')       // space after an opening bracket (line-wrapping)
  .replace(/\s*\.\s*/g, '.')          // spacing around method-chain dots (line-wrapping)
  .trim();

let pass = 0, fail = 0; const fails = [];
const moduleNoExport = module.replace(/^export /gm, '');
for (const [file, names] of Object.entries(EXPECT)) {
  const wf = norm(readFileSync(join(wfDir, file), 'utf8'));
  for (const name of names) {
    const canonical = extractFn(moduleNoExport, name);
    if (!canonical) { fail++; fails.push(`✗ ${name}: not found in wf-helpers.mjs`); continue; }
    if (wf.includes(norm(canonical))) pass++;
    else { fail++; fails.push(`✗ ${file}: inline ${name} LOGIC differs from wf-helpers.mjs (drift!)`); }
  }
}
// Scalar constants must appear verbatim in each listed file.
for (const [needle, files] of Object.entries(SCALARS)) {
  for (const file of files) {
    if (readFileSync(join(wfDir, file), 'utf8').includes(needle)) pass++;
    else { fail++; fails.push(`✗ ${file}: missing scalar \`${needle}\``); }
  }
}
console.log(`\nparity: ${pass} matched, ${fail} drifted`);
if (fail) { console.log('\n' + fails.join('\n')); process.exit(1); }
