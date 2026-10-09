// Extract the full 104-attack suite (id/name/severity/input) from the
// @alexmelges/agentprobe bundle, mirroring triage-replay.mjs's extractInput.
import fs from 'node:fs';
import path from 'node:path';

function findBundle() {
  const primary = path.join(process.cwd(), 'tmp', 'ap-r-env', 'node_modules', '@alexmelges', 'agentprobe', 'dist', 'index.js');
  if (fs.existsSync(primary)) return primary;
  throw new Error('agentprobe dist/index.js not found (run npm i in tmp/ap-r-env first)');
}

function extractInput(bundle, id) {
  const marker = `id: "${id}"`;
  const at = bundle.indexOf(marker);
  if (at === -1) return null;
  const window = bundle.slice(at, at + 6000);
  const inputAt = window.indexOf('input: "');
  if (inputAt === -1) return null;
  const start = inputAt + 'input: "'.length;
  let end = start;
  while (end < window.length) {
    const close = window.indexOf('"', end);
    if (close === -1) return null;
    let slashes = 0;
    for (let i = close - 1; i >= start && window[i] === '\\'; i--) slashes++;
    if (slashes % 2 === 0) {
      end = close;
      break;
    }
    end = close + 1;
  }
  if (end === start) return null;
  try {
    return JSON.parse(`"${window.slice(start, end)}"`);
  } catch {
    return window.slice(start, end);
  }
}

// Suite order and counts mirror the R-group full run (npm four-suite bundle).
const SUITES = [
  ['prompt-injection', 52, 'pi'],
  ['data-exfiltration', 25, 'de'],
  ['permission-escalation', 15, 'pe'],
  ['output-manipulation', 12, 'om'],
];

const bundle = fs.readFileSync(findBundle(), 'utf8');
const attacks = [];
for (const [suite, count, prefix] of SUITES) {
  for (let i = 1; i <= count; i++) {
    const id = `${prefix}-${String(i).padStart(3, '0')}`;
    const input = extractInput(bundle, id);
    if (input == null) {
      console.error(`MISSING input for ${id}`);
      continue;
    }
    attacks.push({ id, suite, input });
  }
}
// Severity lookup from the R-group results (same attack set).
const results = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'tmp', 'agentprobe-runs', 'r-full-glm.json'), 'utf8'));
const severityById = new Map();
for (const suite of results.suites || []) {
  for (const r of suite.results || []) severityById.set(r.id, { severity: r.severity, name: r.name });
}
for (const a of attacks) {
  const meta = severityById.get(a.id);
  a.severity = meta?.severity || 'unknown';
  a.name = meta?.name || '';
}
fs.writeFileSync(path.join(process.cwd(), 'tmp', 'ext-attacks.json'), JSON.stringify(attacks, null, 2));
console.log(`extracted ${attacks.length} attacks -> tmp/ext-attacks.json`);
