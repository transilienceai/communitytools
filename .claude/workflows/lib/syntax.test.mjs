// syntax.test.mjs — parse every workflow script the way the sandbox actually runs it.
// Run: node .claude/workflows/lib/syntax.test.mjs
//
// `node --check <workflow>.js` cannot validate these files and never could: a
// workflow is a FRAGMENT, not a module. It opens with `export const meta` (illegal
// in CommonJS, which is how node treats a bare .js) and uses top-level `await` and
// top-level `return` (illegal in a module). So the check in CI has been failing on
// every workflow rather than catching anything — a broken syntax gate is worse than
// none, because it reads as coverage.
//
// The sandbox wraps the body in an async function. Do the same, then parse.

import { readdirSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = join(dirname(fileURLToPath(import.meta.url)), '..');
let pass = 0, fail = 0;
const fails = [];

const files = readdirSync(DIR).filter((f) => f.endsWith('.js')).sort();
if (!files.length) { console.error('syntax: no workflow files found'); process.exit(1); }

for (const f of files) {
  const src = readFileSync(join(DIR, f), 'utf8');

  // `meta` must be a pure literal the host can read without executing the script.
  if (!/^export const meta = \{/m.test(src)) {
    fail++; fails.push(`✗ ${f}: missing \`export const meta = {\``);
    continue;
  }
  for (const key of ['name', 'description']) {
    if (!new RegExp(`^\\s*${key}:`, 'm').test(src)) {
      fail++; fails.push(`✗ ${f}: meta.${key} is missing`);
    }
  }
  const name = (src.match(/^\s*name:\s*'([^']+)'/m) || [])[1];
  if (name && name !== f.replace(/\.js$/, '')) {
    fail++; fails.push(`✗ ${f}: meta.name "${name}" does not match the filename`);
  }

  // Parse the body exactly as the sandbox composes it.
  const body = src.replace(/^export const meta = \{[\s\S]*?\n\}\n/, 'const meta = {}\n');
  const r = spawnSync(process.execPath, ['--input-type=module', '--check'],
    { input: `(async function(){\n${body}\n})`, encoding: 'utf8' });
  if (r.status === 0) pass++;
  else {
    fail++;
    const first = (r.stderr || '').split('\n').filter(Boolean).slice(0, 4).join(' | ');
    fails.push(`✗ ${f}: syntax error — ${first}`);
  }
}

// Guard against the sandbox's hard bans, which fail at RUN time otherwise: a
// workflow that calls Date.now() dies mid-run, hours in.
const BANNED = [
  [/\bDate\.now\s*\(/, 'Date.now()'],
  [/\bMath\.random\s*\(/, 'Math.random()'],
  [/\bnew Date\s*\(\s*\)/, 'new Date()'],
  [/^\s*(?:import|const .*= *require)\b/m, 'import/require'],
];
for (const f of files) {
  const src = readFileSync(join(DIR, f), 'utf8')
    .replace(/^\s*\/\/[^\n]*$/gm, '');   // comments may legitimately name them
  for (const [re, label] of BANNED) {
    if (re.test(src)) { fail++; fails.push(`✗ ${f}: uses ${label}, which the sandbox forbids`); }
    else pass++;
  }
}

console.log(`syntax: ${pass} passed, ${fail} failed`);
if (fails.length) { console.error('\n' + fails.join('\n')); process.exit(1); }
