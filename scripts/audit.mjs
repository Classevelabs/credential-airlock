/**
 * The dependency gate: nothing that ships may carry a known advisory, unless
 * audit-exceptions.json names it, says why it cannot reach this product, and
 * points at the test that holds that reason true.
 *
 * `npm audit` alone can only pass or fail. An advisory landed on node-forge's
 * signature verification with no fixed release to move to; Airlock signs
 * certificates with forge and never verifies with it, yet the gate could only
 * stay red until upstream shipped or be switched off. Neither says what is true.
 *
 * An exception cannot outlive its reason: the day npm offers a fixed version,
 * or stops reporting the advisory, this fails until the entry is removed.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EXCEPTIONS = 'audit-exceptions.json';

function fail(lines) {
  for (const line of [].concat(lines)) console.error(`audit: ${line}`);
  process.exit(1);
}

// On Windows npm is a .cmd, which cannot be started without a shell; under
// `npm run` the path to npm's own entry is known, so start that with this Node.
const npmCli = process.env.npm_execpath;
const args = ['audit', '--omit=dev', '--json'];
const options = { cwd: root, encoding: 'utf8', windowsHide: true };
const run = npmCli && /\.[cm]?js$/.test(npmCli)
  ? spawnSync(process.execPath, [npmCli, ...args], options)
  : spawnSync(`npm ${args.join(' ')}`, { ...options, shell: true });

// An audit that could not be read is not a clean audit.
let report;
try {
  report = JSON.parse(run.stdout);
} catch {
  fail(`npm audit gave no readable report (exit ${run.status}): ${(run.stderr || run.stdout || '').trim().slice(0, 300)}`);
}
if (report.error || !report.vulnerabilities || !report.metadata?.vulnerabilities) {
  fail(`npm audit did not complete: ${JSON.stringify(report.error ?? report).slice(0, 300)}`);
}

let exceptions;
try {
  exceptions = JSON.parse(fs.readFileSync(path.join(root, EXCEPTIONS), 'utf8'));
} catch (error) {
  fail(`${EXCEPTIONS} could not be read: ${error.message}`);
}
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

// Each package lists the advisories against it as objects; a package that is
// only affected through another names that package as a string instead.
const found = [];
for (const entry of Object.values(report.vulnerabilities)) {
  for (const via of entry.via ?? []) {
    if (typeof via === 'string') continue;
    found.push({
      id: String(via.url ?? '').split('/').pop(),
      package: via.name,
      title: via.title,
      severity: via.severity,
      url: via.url,
      fixAvailable: Boolean(entry.fixAvailable),
    });
  }
}
if (report.metadata.vulnerabilities.total > 0 && found.length === 0) {
  fail('npm audit counts vulnerabilities but names no advisory; refusing to read that as clean');
}

const errors = [];
const used = new Set();
for (const advisory of found) {
  const exception = exceptions.find((e) => e.advisory === advisory.id && e.package === advisory.package);
  if (!exception) {
    errors.push(`${advisory.package}: ${advisory.title} (${advisory.severity}) ${advisory.url}`);
    continue;
  }
  used.add(exception);
  if (advisory.fixAvailable) {
    errors.push(`${advisory.package}: a fixed version now exists for ${advisory.id}; upgrade and remove it from ${EXCEPTIONS}`);
  } else {
    console.log(`audit: excepted ${advisory.id} (${advisory.package}, ${advisory.severity}), held by ${exception.heldBy}`);
    console.log(`       ${exception.reason}`);
  }
}

for (const exception of exceptions) {
  const name = exception.advisory ?? '(unnamed)';
  if (!exception.advisory || !exception.package || !exception.reason || !exception.heldBy) {
    errors.push(`${name}: an exception needs advisory, package, reason and heldBy`);
    continue;
  }
  if (!used.has(exception)) {
    errors.push(`${name}: npm no longer reports it against ${exception.package}; remove it from ${EXCEPTIONS}`);
  }
  // A reason nothing checks is an opinion: the test must exist and run in `npm test`.
  if (!fs.existsSync(path.join(root, exception.heldBy)) || !String(pkg.scripts?.test ?? '').includes(exception.heldBy)) {
    errors.push(`${name}: ${exception.heldBy} must exist and run as part of npm test`);
  }
}

if (errors.length) fail(errors);
const excepted = used.size ? `, ${used.size} excepted with a held reason` : '';
console.log(`audit: no advisory reaches what ships (${found.length} reported${excepted})`);
