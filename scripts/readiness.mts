/**
 * Production readiness check.
 *
 * Verifies the whole product the way a customer would exercise it, and prints
 * a pass/fail table that can be pasted into a go/no-go document.
 */
import { spawnSync } from 'node:child_process';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { existsSync, readFileSync, mkdirSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';

// Credentials are assembled at runtime; see
// packages/core/test/synthetic-secrets.ts. Hardcoding them here would make
// Aegis's own repository show credential findings on every self-scan.
import { FAKE, vulnerableAgentPython } from '../packages/core/test/synthetic-secrets.js';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..');
const HOOK = pathToFileURL(join(ROOT, 'tools', 'register-ts.mjs')).href;
const BIN = './packages/cli/src/bin.ts';

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok, detail });
  process.stdout.write(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '   ' + detail : ''}\n`);
}

function run(args, opts = {}) {
  const r = spawnSync(process.execPath, ['--experimental-strip-types', '--import', HOOK, BIN, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: opts.timeout ?? 120000,
    shell: false,
  });
  return { code: r.status ?? -1, out: r.stdout ?? '', err: r.stderr ?? '' };
}

process.stdout.write('AEGIS PRODUCTION READINESS\n');
process.stdout.write('='.repeat(72) + '\n\n');

/* ---- 1. packaging ---- */
process.stdout.write('[1] Packaging\n');
{
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  check('engines require Node >= 22', String(pkg.engines?.node).includes('22'), pkg.engines?.node);
  check('root has zero runtime dependencies',
    Object.keys(pkg.dependencies ?? {}).length === 0);
  check('published bin exists', existsSync(join(ROOT, 'bin', 'aegis.mts')));
  const core = JSON.parse(readFileSync(join(ROOT, 'packages/core/package.json'), 'utf8'));
  check('core has zero runtime dependencies',
    Object.keys(core.dependencies ?? {}).length === 0);
  const pub = JSON.parse(readFileSync(join(ROOT, 'aegis.package.json'), 'utf8'));
  check('publish manifest has zero dependencies',
    Object.keys(pub.dependencies ?? {}).length === 0);
  check('publish manifest lists an executable bin', Boolean(pub.bin?.aegis));
}

/* ---- 2. licence ---- */
process.stdout.write('\n[2] Licensing\n');
{
  check('LICENSE is MIT', readFileSync(join(ROOT, 'LICENSE'), 'utf8').includes('MIT License'));
  check('rule packs are CC0',
    readFileSync(join(ROOT, 'packages/rules/LICENSE'), 'utf8').includes('CC0'));
  check('SECURITY.md exists', existsSync(join(ROOT, 'SECURITY.md')));
  check('CONTRIBUTING.md exists', existsSync(join(ROOT, 'CONTRIBUTING.md')));
  check('CODE_OF_CONDUCT.md exists', existsSync(join(ROOT, 'CODE_OF_CONDUCT.md')));
}

/* ---- 3. CLI surface ---- */
process.stdout.write('\n[3] CLI surface\n');
{
  const help = run(['--help']);
  for (const c of ['scan', 'redteam', 'sandbox', 'fix', 'report', 'intel']) {
    check(`command registered: ${c}`, help.out.includes(c));
    const sub = run([c, '--help']);
    check(`command has help: ${c}`, sub.code === 0 && sub.out.includes('OPTIONS'));
  }
  check('--version works', run(['--version']).code === 0);
  check('unknown command exits 2', run(['nope']).code === 2);
  check('unknown option exits 2', run(['scan', '.', '--nope']).code === 2);
}

/* ---- 4. output formats ---- */
process.stdout.write('\n[4] Output formats\n');
const FIXTURE = join('packages', 'core', 'test', 'fixtures', 'vulnerable-agent');

/**
 * A fixture that actually contains a credential.
 *
 * The committed fixture reads its key from the environment, so scanning it proves
 * nothing about redaction -- there is no secret to leak. This materialises a
 * copy with synthetic keys spliced in, so the check below is testing the
 * redactor rather than asserting that an absent string is absent.
 */
const SECRET_FIXTURE = (() => {
  const dir = join(mkdtempSync(join(tmpdir(), 'aegis-gate-')), 'secret-fixture');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'agent.py'), vulnerableAgentPython(), 'utf8');
  return dir;
})();
{
  for (const f of ['json', 'sarif', 'markdown', 'html', 'csv', 'jsonl', 'text']) {
    const r = run(['scan', FIXTURE, '--format', f, '--no-connect', '--no-spawn', '--no-color']);
    check(`format emits output: ${f}`, r.out.length > 100, `${r.out.length} bytes`);
  }
  const sarif = JSON.parse(run(['scan', FIXTURE, '--format', 'sarif', '--no-connect', '--no-spawn']).out);
  check('SARIF is 2.1.0', sarif.version === '2.1.0');
  check('SARIF rule/results stay aligned',
    sarif.runs[0].results.every((x) => sarif.runs[0].tool.driver.rules[x.ruleIndex]?.id === x.ruleId));
}

/* ---- 5. secret safety ---- */
process.stdout.write('\n[5] Secret safety (hard requirement)\n');
{
  const secrets = [FAKE.openai, FAKE.github];

  // Prove the fixture is fit for the purpose before trusting a pass from it.
  // A redaction test against a file with no secret in it passes forever and
  // means nothing; this makes that degradation a hard failure.
  const seeded = readFileSync(join(SECRET_FIXTURE, 'agent.py'), 'utf8');
  const present = secrets.filter((s) => seeded.includes(s));
  check('redaction fixture actually contains credentials', present.length === secrets.length,
    `only ${present.length}/${secrets.length} present -- this check would be vacuous`);

  for (const f of ['json', 'sarif', 'markdown', 'html', 'csv', 'jsonl', 'text']) {
    const r = run(['scan', SECRET_FIXTURE, '--format', f, '--no-connect', '--no-spawn', '--no-color']);
    const leaked = secrets.filter((s) => r.out.includes(s));
    check(`no raw secret in ${f}`, leaked.length === 0, leaked.join(','));
    // A mask that removed the whole value would also satisfy "no raw secret".
    // Require the visible prefix so redaction is proven, not deletion.
    if (f !== 'csv' && f !== 'jsonl') {
      check(`secret is masked not deleted in ${f}`,
        r.out.includes(FAKE.openai.slice(0, 8)) && r.out.includes('****'));
    }
  }
}

/* ---- 6. CI contract ---- */
process.stdout.write('\n[6] CI contract\n');
{
  check('exits 1 when findings meet --fail-on',
    run(['scan', FIXTURE, '--fail-on', 'critical', '--no-connect', '--no-spawn', '--no-color']).code === 1);

  const clean = join(ROOT, '.aegis', 'readiness', 'clean');
  mkdirSync(clean, { recursive: true });
  writeFileSync(join(clean, 'ok.py'), 'def add(a, b):\n    return a + b\n');
  check('exits 0 on a clean tree',
    run(['scan', join('.aegis', 'readiness', 'clean'), '--no-connect', '--no-spawn', '--no-color']).code === 0);
}

/* ---- 7. safety modes ---- */
process.stdout.write('\n[7] Safety modes\n');
{
  const r = run(['redteam', '--dry-run', '--population', '6', '--generations', '2', '--budget', '12']);
  check('redteam --dry-run makes no requests', r.code === 0 && r.out.includes('Red team report'));
  check('redteam without target is a usage error', run(['redteam']).code === 2);
  const s = run(['scan', '.', '--no-connect', '--no-spawn', '--format', 'json']);
  check('--no-connect --no-spawn scans statically', s.out.includes('findings'));
}

/* ---- 8. dashboard ---- */
process.stdout.write('\n[8] Dashboard\n');
{
  for (const a of ['packages/web/public/index.html', 'packages/web/public/app.css', 'packages/web/src/server.ts']) {
    check(`asset present: ${a}`, existsSync(join(ROOT, a)));
  }
  const html = readFileSync(join(ROOT, 'packages/web/public/index.html'), 'utf8');
  check('dashboard has no external script', !/<script[^>]+src=["']https?:/i.test(html));
  check('dashboard has no external stylesheet', !/<link[^>]+href=["']https?:/i.test(html));
  check('dashboard declares all views',
    ['overview', 'findings', 'graph', 'intel', 'compliance'].every((v) => html.includes(`data-view="${v}"`)));
  const css = readFileSync(join(ROOT, 'packages/web/public/app.css'), 'utf8');
  check('dashboard has no remote font import', !/@import\s+url\(https?:/i.test(css));
}

/* ---- 9. container ---- */
process.stdout.write('\n[9] Container profile\n');
{
  const dockerfile = join(ROOT, 'infra/sandbox/Dockerfile');
  check('Dockerfile exists', existsSync(dockerfile));
  if (existsSync(dockerfile)) {
    const df = readFileSync(dockerfile, 'utf8');
    check('runs as non-root', /^USER\s+(?!root)\S+/m.test(df));
    // Strip comments before checking: the Dockerfile explains *why* there is no
    // install step, so a naive grep matches its own explanation.
    const directives = df
      .split('\n')
      .filter((l) => !l.trim().startsWith('#'))
      .join('\n');
    check('no npm install in image', !/npm\s+(install|ci)\b/.test(directives));
    check('uses an init shim', /tini|ENTRYPOINT/.test(df));
  }
  check('sandbox compose profile exists', existsSync(join(ROOT, 'infra/sandbox/docker-compose.sandbox.yml')));
  check('local compose exists', existsSync(join(ROOT, 'docker-compose.yml')));
}

/* ---- 10. CI ---- */
process.stdout.write('\n[10] CI\n');
{
  const ci = join(ROOT, '.github/workflows/ci.yml');
  check('CI workflow exists', existsSync(ci));
  if (existsSync(ci)) {
    const y = readFileSync(ci, 'utf8');
    check('CI runs tests', /npm (run )?test/.test(y));
    check('CI runs e2e', /test:e2e/.test(y));
    check('CI runs the smoke check', /smoke/.test(y));
  }
}

/* ---- 11. docs ---- */
process.stdout.write('\n[11] Documentation\n');
{
  for (const d of ['README.md', 'DELIVERY.md', 'PUBLISHING.md', 'GTM.md', 'SECURITY.md']) {
    check(`document exists: ${d}`, existsSync(join(ROOT, d)));
  }
  const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');
  check('README has an architecture diagram', readme.includes('```mermaid'));
  check('README documents the zero-dependency install',
    readme.toLowerCase().includes('zero runtime npm dependencies'));
  check('docs cover the CLI', existsSync(join(ROOT, 'packages/docs/content/docs/cli.mdx')));
}

/* ---- 12. self-scan precision ---- */
process.stdout.write('\n[12] Self-scan precision\n');
{
  const selfPath = join(ROOT, '.aegis', 'readiness', 'self.json');
  const r = run(['scan', '.', '--no-connect', '--no-spawn', '--format', 'json', '--output', selfPath]);
  if (r.code === 0 || r.code === 1) {
    const d = JSON.parse(readFileSync(selfPath, 'utf8'));
    check('self-scan result is bounded', d.findings.length < 120, `${d.findings.length} findings`);
    check('self-scan criticals are bounded', (d.score.bySeverity.critical ?? 0) < 40,
      `${d.score.bySeverity.critical} critical`);
    check('self-scan reports a score', d.score.score >= 0, `${d.score.score}/100`);
  } else {
    check('self-scan runs', false, `exit ${r.code}`);
  }
}

/* ---- summary ---- */
process.stdout.write('\n' + '='.repeat(72) + '\n');
const failed = results.filter((x) => !x.ok);
process.stdout.write(`${results.length - failed.length}/${results.length} checks passed\n`);
if (failed.length) {
  process.stdout.write('\nFAILURES:\n');
  for (const f of failed) process.stdout.write(`  - ${f.name}${f.detail ? ' (' + f.detail + ')' : ''}\n`);
}
process.exitCode = failed.length === 0 ? 0 : 1;