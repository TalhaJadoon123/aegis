/**
 * Installs the built tarball into a throwaway directory and exercises it.
 *
 * This is the only check that proves the *published* artifact works. Every
 * other test runs against source; this one runs against what a customer would
 * actually install, which is how the `node_modules` type-stripping failure was
 * found in the first place.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { tmpdir } from 'node:os';

// Credentials are assembled at runtime; see
// packages/core/test/synthetic-secrets.ts. Hardcoding them here would make
// Aegis's own repository show credential findings on every self-scan.
import { FAKE } from '../packages/core/test/synthetic-secrets.js';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..');
const DIST = join(ROOT, 'dist');

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok });
  process.stdout.write(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '   ' + detail : ''}\n`);
}

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, {
    cwd: opts.cwd ?? ROOT,
    encoding: 'utf8',
    timeout: opts.timeout ?? 600000,
    // Windows cannot spawn the npm `.cmd` shim without a shell.
    shell: /\.(cmd|bat)$/i.test(cmd),
  });
  return { code: r.status ?? -1, out: r.stdout ?? '', err: r.stderr ?? '' };
}

/** `npm` as an executable spawnSync can actually start on this platform. */
const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';
/** `npx` likewise. */
const NPX = process.platform === 'win32' ? 'npx.cmd' : 'npx';

const tarballs = existsSync(DIST) ? readdirSync(DIST).filter((f) => f.endsWith('.tgz')) : [];
if (tarballs.length === 0) {
  process.stderr.write('no tarball in dist/ — run `npm run package` first\n');
  process.exit(1);
}
const tarball = join(DIST, tarballs[0]);
process.stdout.write(`Verifying ${tarballs[0]}\n`);
process.stdout.write('='.repeat(60) + '\n\n');

/* ---- static inspection of the tarball ---- */
{
  const listing = run('tar', ['-tzf', tarball]);
  // npm prefixes every entry with `package/`, and on Windows each line carries
  // a trailing \r that would defeat a suffix match.
  const entries = listing.out
    .split('\n')
    .map((e) => e.replace(/\r$/, '').replace(/^package\//, ''))
    .filter(Boolean);
  const has = (suffix) => entries.some((e) => e.endsWith(suffix));

  check('tarball is readable', listing.code === 0, `${entries.length} entries`);
  check('tarball ships compiled JS',
    has('packages/cli/src/bin.js'),
    'bin must be .js for node_modules');
  check('tarball ships rule packs', has('rules/owasp-agentic-top10.yaml'));
  check('tarball ships the dashboard asset', has('packages/web/public/index.html'));
  check('tarball ships the type declarations', has('packages/core/src/index.d.ts'));
  check('tarball contains no TypeScript entry point',
    !entries.some((e) => /(^|\/)bin\.m?ts$/.test(e)),
    'Node cannot strip types inside node_modules');
  check('tarball contains no node_modules',
    !entries.some((e) => e.includes('node_modules/')));
  check('tarball contains no test sources',
    !entries.some((e) => /\.(test|spec)\.ts$/.test(e)));
}

/* ---- install into a clean directory ---- */
const sandbox = mkdtempSync(join(tmpdir(), 'aegis-pkg-'));
let installed = false;
try {
  process.stdout.write('\n[install] into a clean temp directory\n');
  writeFileSync(join(sandbox, 'package.json'), JSON.stringify({ name: 'probe', version: '1.0.0', private: true }));
  const install = run(NPM, ['install', tarball, '--no-audit', '--no-fund'], { cwd: sandbox });
  check('installs cleanly', install.code === 0, (install.err || install.out).slice(0, 200));
  installed = install.code === 0;

  if (installed) {
    /* ---- run it as a consumer would ---- */
    process.stdout.write('\n[run] npx aegis\n');
    const v = run(NPX, ['aegis', '--version'], { cwd: sandbox });
    check('npx aegis --version', v.code === 0 && /aegis \d+\.\d+\.\d+/.test(v.out), v.err.slice(0, 200));

    const h = run(NPX, ['aegis', '--help'], { cwd: sandbox });
    check('npx aegis --help', h.code === 0 && h.out.includes('COMMANDS'));

    // A real scan against a real fixture, from outside the repository.
    process.stdout.write('\n[run] scan a deliberately vulnerable agent\n');
    const fixture = join(sandbox, 'vulnerable');
    mkdirSync(join(fixture), { recursive: true });
    writeFileSync(
      join(fixture, 'agent.py'),
      [
        'import subprocess',
        // Template literal, not a quoted string: the literal text "FAKE.openai"
        // would be written into the fixture verbatim and the scanner would
        // correctly report no key at all.
        `OPENAI_API_KEY = "${FAKE.openai}"`,
        'def run(user_input):',
        '    subprocess.run(f"grep {user_input} /var/log", shell=True)',
        'while True:',
        '    pass',
        '',
      ].join('\n'),
    );

    const s = run(NPX, ['aegis', 'scan', fixture, '--no-connect', '--no-spawn', '--no-color'], { cwd: sandbox });
    check('scan finds the planted issues',
      s.code === 1 && /CRITICAL|Score/.test(s.out),
      s.out.slice(0, 120).replace(/\n/g, ' '));
    check('scan does not echo the raw key',
      !s.out.includes(FAKE.openai),
      'the full credential must never reach the output');
    check('scan redacts the key',
      s.out.includes(FAKE.openai.slice(0, 8)) && s.out.includes('****'),
      'the visible prefix is kept and the rest is masked');

    const sarif = run(NPX, ['aegis', 'scan', fixture, '--format', 'sarif', '--no-connect', '--no-spawn'], { cwd: sandbox });
    let sarifOk = false;
    try {
      const doc = JSON.parse(sarif.out);
      sarifOk = doc.version === '2.1.0' && doc.runs[0].results.length > 0;
    } catch {
      sarifOk = false;
    }
    check('emits valid SARIF', sarifOk);

    const md = run(NPX, ['aegis', 'report', fixture, '--compliance', '--organisation', 'Probe Ltd', '--no-connect', '--no-spawn'], { cwd: sandbox });
    check('compliance attestation renders', md.code === 0 && md.out.includes('Attestation'));

    const rt = run(NPX, ['aegis', 'redteam', '--dry-run', '--population', '4', '--generations', '1', '--budget', '8'], { cwd: sandbox });
    check('redteam --dry-run works', rt.code === 0 && rt.out.includes('Red team report'));

    const rules = readdirSync(join(sandbox, 'node_modules', 'aegis', 'packages', 'rules', 'rules'));
    check('rule packs are readable from the install', rules.length >= 6, `${rules.length} packs`);

    // The installed tree must contain nothing but Aegis. npm's own bookkeeping
    // entries (.bin, .package-lock.json) are not dependencies.
    const installedPkgs = readdirSync(join(sandbox, 'node_modules'))
      .filter((p) => !p.startsWith('.'));
    check('zero transitive dependencies',
      installedPkgs.length === 1 && installedPkgs[0] === 'aegis',
      installedPkgs.join(','));
  }
} finally {
  rmSync(sandbox, { recursive: true, force: true });
}

process.stdout.write('\n' + '='.repeat(60) + '\n');
const failed = results.filter((x) => !x.ok);
process.stdout.write(`${results.length - failed.length}/${results.length} package checks passed\n`);
if (failed.length) {
  process.stdout.write('\nFAILURES:\n');
  for (const f of failed) process.stdout.write(`  - ${f.name}\n`);
}
process.exitCode = failed.length === 0 ? 0 : 1;