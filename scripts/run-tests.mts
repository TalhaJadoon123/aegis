/**
 * Authoritative test runner.
 *
 * Exists so the file list cannot drift out of sync with the test scripts --
 * they had silently gone stale, and `npm test` was running 219 of the 250
 * tests. Discovering that via a red build is a bad way to find out.
 *
 * Suites:
 *   unit  — fast, no subprocesses; safe to parallelise
 *   e2e   — spawns the CLI as a child process; MUST run serially, because the
 *           dashboard test opens an HTTP listener and node's runner reports
 *           spurious failures when several such tests overlap
 *   all   — everything
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..');
// `--import` needs a URL: on Windows a bare `E:\...` is parsed as a URL scheme.
const HOOK = pathToFileURL(join(ROOT, 'tools', 'register-ts.mjs')).href;

function testFiles(dir) {
  const full = join(ROOT, dir);
  if (!existsSync(full)) return [];
  return readdirSync(full)
    .filter((f) => f.endsWith('.test.ts'))
    .sort()
    .map((f) => `${dir}/${f}`);
}

const ALL = [...testFiles('packages/core/test'), ...testFiles('packages/intel-feeds/test')];
// The end-to-end suite spawns the binary; it is excluded from the fast path.
const E2E = ['packages/core/test/e2e.test.ts'];
const UNIT = ALL.filter((f) => !E2E.includes(f));

const mode = process.argv[2] ?? 'unit';
const selected = mode === 'e2e' ? E2E : mode === 'all' ? ALL : UNIT;

if (selected.length === 0) {
  process.stderr.write(`no test files found for "${mode}"\n`);
  process.exit(1);
}

process.stdout.write(`Aegis tests — ${mode} (${selected.length} file(s))\n`);
process.stdout.write('='.repeat(60) + '\n');

const started = Date.now();
const result = spawnSync(
  process.execPath,
  [
    '--import', HOOK,
    '--test',
    // Serial execution: several suites spawn child processes or bind sockets,
    // and concurrency produced failures that did not reproduce in isolation.
    '--test-concurrency=1',
    ...selected,
  ],
  { cwd: ROOT, stdio: 'inherit', shell: false },
);

const seconds = ((Date.now() - started) / 1000).toFixed(1);
process.stdout.write(`\n${'='.repeat(60)}\n`);
process.stdout.write(`${mode} finished in ${seconds}s — exit ${result.status ?? -1}\n`);

process.exitCode = result.status ?? 1;