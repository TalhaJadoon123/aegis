/**
 * Assert every place the release version is written agrees.
 *
 * The version is duplicated by necessity: the two npm manifests, the pnpm
 * workspace manifest, the CLI and core constants (one of which is stamped into
 * every SARIF report), the Helm chart and its default image tag, the container
 * label, both installers and the documented download URLs.
 *
 * A mismatch is not cosmetic:
 *   - an installer that points at the previous tag cannot download this one;
 *   - a chart whose `image.tag` is stale pulls an image that was never pushed;
 *   - a CLI whose constant is stale reports the wrong version to an auditor.
 *
 * `npm run version:bump -- <version>` updates the whole set; this gate proves
 * it did before anything is published.
 *
 * Usage: node --experimental-strip-types scripts/check-versions.mts [expected]
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = process.cwd();

interface Check {
  file: string;
  label: string;
  /** Return the version found in the file, or undefined when absent. */
  read: (text: string) => string | undefined;
}

/** Read a top-level key from a JSON file. */
const json = (key: string) => (text: string) => {
  const value = (JSON.parse(text) as Record<string, unknown>)[key];
  return typeof value === 'string' ? value : undefined;
};

/** First capture group of a regex. */
const match = (pattern: RegExp) => (text: string) => pattern.exec(text)?.[1];

const CHECKS: Check[] = [
  { file: 'package.json', label: 'package.json', read: json('version') },
  { file: 'aegis.package.json', label: 'aegis.package.json', read: json('version') },

  {
    file: 'packages/cli/src/main.ts',
    label: 'CLI VERSION',
    read: match(/^const VERSION = '([^']+)'/m),
  },
  {
    file: 'packages/core/src/index.ts',
    label: 'core VERSION',
    read: match(/^export const VERSION = '([^']+)'/m),
  },
  {
    file: 'packages/core/src/output.ts',
    label: 'SARIF AEGIS_VERSION',
    read: match(/^export const AEGIS_VERSION = '([^']+)'/m),
  },

  {
    file: 'infra/helm/aegis/Chart.yaml',
    label: 'Chart.yaml version',
    read: match(/^version:\s*["']?([^"'\s]+)/m),
  },
  {
    file: 'infra/helm/aegis/Chart.yaml',
    label: 'Chart.yaml appVersion',
    read: match(/^appVersion:\s*["']?([^"'\s]+)/m),
  },
  {
    file: 'infra/helm/aegis/values.yaml',
    label: 'chart image.tag',
    read: match(/^\s*tag:\s*["']?([^"'\s]+)/m),
  },
  {
    file: 'infra/sandbox/Dockerfile',
    label: 'image version label',
    read: match(/org\.opencontainers\.image\.version="([^"]+)"/),
  },

  {
    file: 'install.ps1',
    label: 'install.ps1 default version',
    read: match(/\$Version = '([^']+)'/),
  },
  {
    file: 'install.sh',
    label: 'install.sh default version',
    read: match(/AEGIS_VERSION:-([0-9.]+)/),
  },
];

/**
 * Files that must mention the version somewhere rather than in one fixed spot:
 * the download URLs and the prose that explains how to install it.
 */
const MENTIONS = [
  'README.md',
  'PUBLISHING.md',
  'docs/START-HERE.md',
  'install.ps1',
  'install.sh',
];

const documented = (process.argv[2] ?? '').trim().replace(/^v/, '');
const manifestPath = join(root, 'package.json');
if (!existsSync(manifestPath)) {
  process.stderr.write(`not a package root: ${manifestPath} not found\n`);
  process.exit(2);
}
const expected = documented || json('version')(readFileSync(manifestPath, 'utf8')) || '';

if (!/^\d+\.\d+\.\d+$/.test(expected)) {
  process.stderr.write(`cannot determine a valid version (got "${expected}")\n`);
  process.exit(2);
}

const problems: string[] = [];

for (const check of CHECKS) {
  const path = join(root, check.file);
  if (!existsSync(path)) {
    problems.push(`${check.label}: ${check.file} is missing`);
    continue;
  }
  const found = check.read(readFileSync(path, 'utf8'));
  if (found === undefined) {
    problems.push(`${check.label}: no version could be read from ${check.file}`);
  } else if (found !== expected) {
    problems.push(`${check.label}: ${found} (expected ${expected})`);
  }
}

for (const file of MENTIONS) {
  const path = join(root, file);
  if (!existsSync(path)) {
    problems.push(`${file} is missing`);
    continue;
  }
  if (!readFileSync(path, 'utf8').includes(expected)) {
    problems.push(`${file} never mentions ${expected}`);
  }
}

if (problems.length > 0) {
  process.stderr.write(`\nRelease metadata disagrees with ${expected}:\n`);
  for (const problem of problems) process.stderr.write(`  - ${problem}\n`);
  process.stderr.write(
    `\nRun: npm run version:bump -- ${expected}\n` +
      'then update CHANGELOG.md and commit.\n',
  );
  process.exit(1);
}

process.stdout.write(`All ${CHECKS.length + MENTIONS.length} version locations agree on ${expected}\n`);