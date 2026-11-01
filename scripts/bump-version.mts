/**
 * Bump the release version everywhere it is duplicated.
 *
 * The version lives in the two manifests, the CLI constant, the core constants
 * (including the SARIF tool version), the Helm chart, the container label, the
 * installers and the documented download URLs. A missed file produces a
 * release whose `--version` or chart disagrees with its tag, so the list is
 * kept in one place.
 *
 * Usage: npm run version:bump -- 0.1.2
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const root = process.cwd();
const next = process.argv[2];

if (!next || !/^\d+\.\d+\.\d+$/.test(next)) {
  process.stderr.write('usage: npm run version:bump -- <major.minor.patch>\n');
  process.exit(2);
}

const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version: string };
const current = manifest.version;

if (current === next) {
  process.stdout.write(`already at ${next}\n`);
  process.exit(0);
}
if (!/^\d+\.\d+\.\d+$/.test(current)) {
  process.stderr.write(`refusing to bump unexpected current version: ${current}\n`);
  process.exit(2);
}

const FILES = [
  'package.json',
  'aegis.package.json',
  'packages/cli/src/main.ts',
  'packages/core/src/index.ts',
  'packages/core/src/output.ts',
  'infra/helm/aegis/Chart.yaml',
  'infra/helm/aegis/values.yaml',
  'infra/sandbox/Dockerfile',
  'install.ps1',
  'install.sh',
  'README.md',
  'PUBLISHING.md',
  'docs/START-HERE.md',
];

let changed = 0;
for (const relative of FILES) {
  const path = join(root, relative);
  const before = readFileSync(path, 'utf8');
  if (!before.includes(current)) {
    process.stderr.write(`warning: ${relative} does not mention ${current}\n`);
    continue;
  }
  const after = before.split(current).join(next);
  writeFileSync(path, after, 'utf8');
  const count = before.split(current).length - 1;
  process.stdout.write(`${relative}: ${count} occurrence${count === 1 ? '' : 's'}\n`);
  changed += 1;
}

process.stdout.write(`\n${current} -> ${next} across ${changed} files\n`);
process.stdout.write('Now add a CHANGELOG entry, then commit and tag.\n');