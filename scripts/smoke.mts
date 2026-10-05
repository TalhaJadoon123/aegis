// Aegis product smoke check.
// Runs every CLI command against the vulnerable fixture and prints a summary.
// Usage: node --import ./tools/register-ts.mjs scripts/smoke.mts

import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..');
// `--import` requires a URL, but the entry after it is resolved relative to the
// hook's parent, so a repository-relative path is correct there.
const HOOK = pathToFileURL(join(ROOT, 'tools', 'register-ts.mjs')).href;
const BIN = './packages/cli/src/bin.ts';
const FIXTURE = join(ROOT, 'packages', 'core', 'test', 'fixtures', 'vulnerable-agent');

function run(args: string[]): Promise<{ code: number; out: string; err: string }> {
  return new Promise((r) => {
    const c = spawn(process.execPath, ['--import', HOOK, BIN, ...args], { shell: false, windowsHide: true });
    let out = '';
    let err = '';
    c.stdout.on('data', (d) => { out += d; });
    c.stderr.on('data', (d) => { err += d; });
    c.on('close', (code) => r({ code: code ?? -1, out, err }));
  });
}

interface Check { name: string; ok: boolean; detail: string }

const checks: Check[] = [];
function check(name: string, ok: boolean, detail = ''): void {
  checks.push({ name, ok, detail });
  process.stdout.write(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  ${detail}` : ''}\n`);
}

process.stdout.write('Aegis product smoke check\n\n');

// --- commands -------------------------------------------------------------
for (const [label, args] of [
  ['version', ['--version']],
  ['help', ['--help']],
  ['scan', ['scan', FIXTURE, '--no-connect', '--no-color']],
  ['intel', ['intel']],
] as const) {
  const r = await run([...args]);
  check(`command: ${label}`, r.code === 0 || label === 'scan', `exit ${r.code}`);
}

// --- output formats -------------------------------------------------------
for (const format of ['json', 'sarif', 'markdown', 'html', 'csv', 'jsonl', 'text']) {
  const r = await run(['scan', FIXTURE, '--format', format, '--no-connect', '--no-color']);
  let valid = false;
  try {
    if (format === 'json' || format === 'sarif') valid = typeof JSON.parse(r.out) === 'object';
    else if (format === 'jsonl') valid = r.out.trim().split('\n').every((l) => JSON.parse(l));
    else if (format === 'html') valid = /<!doctype html>/i.test(r.out);
    else if (format === 'markdown') valid = r.out.includes('# Aegis Security Scan');
    else valid = r.out.length > 0;
  } catch { valid = false; }
  check(`format: ${format}`, valid);
}

// --- secret redaction across every format ---------------------------------
let leaked = '';
for (const format of ['json', 'sarif', 'markdown', 'html', 'csv', 'jsonl', 'text']) {
  const r = await run(['scan', FIXTURE, '--format', format, '--no-connect', '--no-color']);
  if (r.out.includes('sk-proj-abcdefghijklmnopqrstuvwxyz')) leaked = leaked || format;
}
check('secrets redacted in all formats', !leaked, leaked ? `leaked in ${leaked}` : '');

// --- other commands -------------------------------------------------------
const dry = await run(['redteam', '--dry-run', '--population', '6', '--generations', '2', '--budget', '16', '--no-color']);
check('command: redteam --dry-run', dry.code === 0 && /Red team report/.test(dry.out));

const fix = await run(['fix', FIXTURE, '--no-connect']);
check('command: fix (plan only)', fix.code === 0 && /Remediation plan/.test(fix.out));

const rep = await run(['report', FIXTURE, '--compliance', '--organisation', 'Smoke Test', '--no-connect']);
check('command: report --compliance', rep.code === 0 && /Attestation/.test(rep.out));

const sb = await run(['sandbox', '--command', process.execPath, '--arg', '-e',
  'console.log(JSON.stringify({type:"file_read",path:"/etc/passwd"}))', '--format', 'json']);
let sbOk = false;
try {
  const doc = JSON.parse(sb.out);
  sbOk = doc.findings.some((f: { ruleId: string }) => f.ruleId === 'AEGIS-POLICY-DENY');
} catch { /* ignore */ }
check('command: sandbox policy enforcement', sbOk);

// --- summary --------------------------------------------------------------
const failed = checks.filter((c) => !c.ok);
process.stdout.write(`\n${checks.length - failed.length}/${checks.length} checks passed\n`);
if (failed.length > 0) {
  process.stdout.write('\nFailures:\n');
  for (const f of failed) process.stdout.write(`  - ${f.name} ${f.detail}\n`);
  process.exitCode = 1;
}