/**
 * Builds the publishable tarball.
 *
 * `npm pack` reads `package.json` from the directory it runs in, and the
 * repository root's manifest describes the *monorepo*, not the published
 * package. Copying the publish manifest over it would destroy the workspace
 * setup, so the package is assembled in a staging directory instead and packed
 * from there.
 */
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..');
const STAGE = join(ROOT, 'build', 'stage');
const DIST = join(ROOT, 'dist');

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { cwd: opts.cwd ?? ROOT, encoding: 'utf8', shell: false });
  if (r.status !== 0) {
    process.stderr.write(`${cmd} ${args.join(' ')} failed:\n${r.stdout ?? ''}${r.stderr ?? ''}\n`);
    process.exit(r.status ?? 1);
  }
  return r.stdout ?? '';
}

/**
 * Run a command, tolerating a non-zero exit when combined output still proves
 * success. `npm pack` reports its notice on stderr, which Windows surfaces as a
 * native-command error even when the exit code is 0.
 *
 * On Windows `npm` is a `.cmd` shim and `spawnSync` without `shell` cannot
 * resolve it — hence `npmCmd()`.
 */
function runTolerant(cmd, args, opts = {}) {
  // `shell: true` only for the npm shim: Windows cannot spawn a `.cmd` without
  // it, and every argument here is a literal we construct ourselves.
  return spawnSync(cmd, args, {
    cwd: opts.cwd ?? ROOT,
    encoding: 'utf8',
    shell: cmd.endsWith('.cmd') || cmd === 'npm' || cmd === 'npm.cmd',
  });
}

/** Resolve `npm` to something spawnSync can actually start on this platform. */
function npmCmd() {
  return process.platform === 'win32' ? 'npm.cmd' : 'npm';
}

/** Resolve the local tsc binary without depending on `npx` resolving correctly. */
function tsc(args) {
  const local = join(ROOT, 'node_modules', 'typescript', 'bin', 'tsc');
  const entry = existsSync(local) ? [process.execPath, local] : ['npx', 'tsc'];
  return run(entry[0], [...entry.slice(1), ...args]);
}

process.stdout.write('[1/5] Compiling TypeScript for publication\n');
tsc(['-p', 'tsconfig.publish.json']);

process.stdout.write('[2/5] Preparing staging directory\n');
rmSync(STAGE, { recursive: true, force: true });
mkdirSync(STAGE, { recursive: true });

// The publish manifest is the package's real identity.
cpSync(join(ROOT, 'aegis.package.json'), join(STAGE, 'package.json'));

process.stdout.write('[3/5] Copying runtime files\n');
cpSync(join(ROOT, 'build', 'publish'), join(STAGE, 'build', 'publish'), { recursive: true });
cpSync(join(ROOT, 'packages', 'rules'), join(STAGE, 'packages', 'rules'), { recursive: true });
cpSync(join(ROOT, 'packages', 'web', 'public'), join(STAGE, 'packages', 'web', 'public'), {
  recursive: true,
});
cpSync(join(ROOT, 'packages', 'core', 'test', 'fixtures'), join(STAGE, 'packages', 'core', 'test', 'fixtures'), {
  recursive: true,
});
for (const doc of ['README.md', 'SECURITY.md', 'LICENSE', 'DELIVERY.md', 'PUBLISHING.md']) {
  const from = join(ROOT, doc);
  if (existsSync(from)) cpSync(from, join(STAGE, doc));
}

process.stdout.write('[4/5] Verifying the staged package\n');
const manifest = JSON.parse(readFileSync(join(STAGE, 'package.json'), 'utf8'));
const problems = [];

const deps = Object.keys(manifest.dependencies ?? {});
if (deps.length > 0) problems.push(`manifest declares dependencies: ${deps.join(', ')}`);

if (!manifest.bin?.aegis) problems.push('manifest has no bin.aegis');
else if (!existsSync(join(STAGE, manifest.bin.aegis))) {
  problems.push(`bin.aegis points at a missing file: ${manifest.bin.aegis}`);
}

if (!manifest.main || !existsSync(join(STAGE, manifest.main))) {
  problems.push(`main points at a missing file: ${manifest.main ?? '(unset)'}`);
}
if (!manifest.types || !existsSync(join(STAGE, manifest.types))) {
  problems.push(`types points at a missing file: ${manifest.types ?? '(unset)'}`);
}

// The bin must not be TypeScript: Node refuses to strip types inside
// node_modules, so shipping a .ts entry point produces a package that installs
// cleanly and then fails on first run.
if (/\.(ts|mts|cts)$/.test(String(manifest.bin?.aegis ?? ''))) {
  problems.push('bin.aegis is TypeScript, which Node cannot execute from node_modules');
}

for (const asset of [
  'packages/rules/rules/owasp-agentic-top10.yaml',
  'packages/web/public/index.html',
]) {
  if (!existsSync(join(STAGE, asset))) problems.push(`missing runtime asset: ${asset}`);
}

if (problems.length > 0) {
  process.stderr.write('\nPackage verification failed:\n');
  for (const p of problems) process.stderr.write(`  - ${p}\n`);
  process.exit(1);
}
process.stdout.write(`      zero dependencies, ${manifest.bin.aegis} present\n`);

process.stdout.write('[5/5] Packing\n');
rmSync(DIST, { recursive: true, force: true });
mkdirSync(DIST, { recursive: true });
const packed = runTolerant(npmCmd(), ['pack', '--pack-destination', DIST], { cwd: STAGE });
const produced = readdirSync(DIST).filter((f) => f.endsWith('.tgz'));
if (produced.length !== 1) {
  process.stderr.write(`packing failed (status=${packed.status}, signal=${packed.signal})\n`);
  process.stderr.write(`stdout:\n${packed.stdout ?? '(empty)'}\n`);
  process.stderr.write(`stderr:\n${packed.stderr ?? '(empty)'}\n`);
  if (packed.error) process.stderr.write(`error: ${packed.error.message}\n`);
  process.exit(1);
}
const tarball = produced[0];
const size = (readFileSync(join(DIST, tarball)).length / 1024).toFixed(0);

process.stdout.write(`\nBuilt ${tarball} (${size} KB)\n`);
process.stdout.write('Verify it installs and runs:\n  npm run package:verify\n');
process.stdout.write('Publish it:\n  npm publish dist/' + tarball + '\n');

// Record the exact build recipe so a release is reproducible.
writeFileSync(
  join(ROOT, 'build', 'package-info.json'),
  JSON.stringify({ tarball, builtFrom: 'aegis.package.json', sizeKb: Number(size) }, null, 2),
  'utf8',
);