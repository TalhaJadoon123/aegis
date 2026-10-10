import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { FAKE } from './synthetic-secrets.js';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..', '..', '..');
const BIN = join(ROOT, 'packages', 'cli', 'src', 'bin.ts');
// `--import` requires a URL, not a path: on Windows `E:\...` is parsed as a URL
// scheme and rejected by the ESM loader.
// `--import` needs a URL (on Windows `E:\...` parses as a URL scheme), but the
// entry point after it is resolved against the hook's parent, so a bare path is
// correct there.
const HOOK = pathToFileURL(join(ROOT, 'tools', 'register-ts.mjs')).href;
const BIN_REL = './packages/cli/src/bin.ts';
const FIXTURES = join(ROOT, 'packages', 'core', 'test', 'fixtures');

/**
 * End-to-end integration tests.
 *
 * These invoke the CLI exactly as a user would — as a subprocess, with real
 * argument parsing and real exit codes. Unit tests can all pass while the
 * binary is unusable, and that is precisely the failure a customer hits first.
 */

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

function aegis(args: readonly string[], cwd = ROOT): Promise<RunResult> {
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, ['--experimental-strip-types', '--import', HOOK, BIN_REL, ...args], {
      cwd,
      shell: false,
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c.toString(); });
    child.stderr.on('data', (c) => { stderr += c.toString(); });
    child.on('error', (error) => {
      resolvePromise({ code: -1, stdout, stderr: `${stderr}\n${error.message}` });
    });
    child.on('close', (code) => resolvePromise({ code: code ?? -1, stdout, stderr }));
  });
}

describe('CLI: discovery', () => {
  test('--version prints a version', async () => {
    const r = await aegis(['--version']);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /^aegis \d+\.\d+\.\d+$/m);
  });

  test('no arguments prints help', async () => {
    const r = await aegis([]);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /the security platform for AI agents/);
    for (const command of ['scan', 'redteam', 'sandbox', 'fix', 'report', 'intel']) {
      assert.match(r.stdout, new RegExp(command));
    }
  });

  test('--help lists every command with a summary', async () => {
    const r = await aegis(['--help']);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /COMMANDS/);
    assert.match(r.stdout, /Evolutionary red team/);
  });

  test('unknown command exits 2 with a helpful message', async () => {
    const r = await aegis(['nonsense']);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /unknown command "nonsense"/);
  });

  test('unknown option exits 2 rather than being ignored', async () => {
    const r = await aegis(['scan', '.', '--not-a-real-option']);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /unknown option --not-a-real-option/);
  });

  test('option requiring a value says so', async () => {
    const r = await aegis(['scan', '.', '--format']);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /requires a value/);
  });

  test('per-command help works', async () => {
    const r = await aegis(['scan', '--help']);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /--min-severity/);
    assert.match(r.stdout, /--fail-on/);
  });
});

describe('CLI: scan', () => {
  test('finds issues in the vulnerable fixture and exits 1', async () => {
    const r = await aegis(['scan', join(FIXTURES, 'vulnerable-agent'), '--no-color', '--no-connect']);
    assert.equal(r.code, 1, 'should exit 1 when findings meet the fail-on threshold');
    assert.match(r.stdout, /Score \d+\/100 \([A-F]\)/);
    assert.match(r.stdout, /CRITICAL/);
    assert.match(r.stdout, /hardcoded in source/);
  });

  test('JSON output is valid and complete', async () => {
    const r = await aegis(['scan', join(FIXTURES, 'vulnerable-agent'), '--format', 'json', '--no-connect']);
    const doc = JSON.parse(r.stdout) as {
      tool: { name: string };
      score: { score: number; grade: string };
      findings: Array<{ severity: string; ruleId: string; compliance: unknown[] }>;
      artifacts: Record<string, unknown>;
    };
    assert.equal(doc.tool.name, 'Aegis');
    assert.ok(doc.score.score >= 0 && doc.score.score <= 100);
    assert.ok(doc.findings.length > 0);
    assert.ok(doc.artifacts['threatModel'], 'threat model should be generated');
  });

  test('SARIF output is valid 2.1.0 with aligned rules and results', async () => {
    const r = await aegis(['scan', join(FIXTURES, 'vulnerable-agent'), '--format', 'sarif', '--no-connect']);
    const sarif = JSON.parse(r.stdout) as {
      version: string;
      runs: Array<{
        tool: { driver: { rules: Array<{ id: string }> } };
        results: Array<{ ruleId: string; ruleIndex: number; level: string }>;
      }>;
    };
    assert.equal(sarif.version, '2.1.0');
    const run = sarif.runs[0]!;
    assert.ok(run.tool.driver.rules.length > 0);
    // Every result must point at a rule that exists at that index. This is the
    // exact invariant that was broken and silently mislabelled findings.
    for (const result of run.results) {
      const rule = run.tool.driver.rules[result.ruleIndex];
      assert.ok(rule, `ruleIndex ${result.ruleIndex} out of range`);
      assert.equal(rule.id, result.ruleId, 'ruleIndex does not match ruleId');
    }
  });

  test('findings are ordered most severe first', async () => {
    const r = await aegis(['scan', join(FIXTURES, 'vulnerable-agent'), '--format', 'json', '--no-connect']);
    const findings = (JSON.parse(r.stdout) as { findings: Array<{ severity: string }> }).findings;
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    const ranks = findings.map((f) => order.indexOf(f.severity));
    const sorted = [...ranks].sort((a, b) => a - b);
    assert.deepEqual(ranks, sorted, 'findings are not sorted by severity');
  });

  test('secrets are never echoed in any output format', async () => {
    for (const format of ['json', 'sarif', 'markdown', 'html', 'csv', 'text']) {
      const r = await aegis([
        'scan', join(FIXTURES, 'vulnerable-agent'),
        '--format', format, '--no-connect', '--no-color',
      ]);
      assert.ok(
        !r.stdout.includes(FAKE.openai),
        `${format} leaked the raw API key`,
      );
      assert.ok(
        !r.stdout.includes(FAKE.github),
        `${format} leaked the raw GitHub token`,
      );
    }
  });

  test('every finding carries remediation and compliance data', async () => {
    const r = await aegis(['scan', join(FIXTURES, 'vulnerable-agent'), '--format', 'json', '--no-connect']);
    const findings = (JSON.parse(r.stdout) as {
      findings: Array<{
        remediation: { title: string; description: string };
        compliance: unknown[];
        fingerprint: string;
        severity: string;
      }>;
    }).findings;
    for (const finding of findings) {
      assert.ok(finding.remediation.title.length > 5);
      assert.ok(finding.remediation.description.length > 20);
      assert.ok(finding.compliance.length > 0, 'every finding must map to a control');
      assert.ok(finding.fingerprint.length > 0);
    }
  });

  test('--min-severity filters lower severities', async () => {
    const all = await aegis(['scan', join(FIXTURES, 'vulnerable-agent'), '--format', 'json', '--no-connect']);
    const criticalOnly = await aegis([
      'scan', join(FIXTURES, 'vulnerable-agent'),
      '--format', 'json', '--no-connect', '--min-severity', 'critical',
    ]);
    const allN = (JSON.parse(all.stdout) as { findings: unknown[] }).findings.length;
    const criticalN = (JSON.parse(criticalOnly.stdout) as { findings: unknown[] }).findings.length;
    assert.ok(criticalN <= allN, 'filtering must not add findings');
    const severities = (JSON.parse(criticalOnly.stdout) as { findings: Array<{ severity: string }> })
      .findings.map((f) => f.severity);
    assert.ok(severities.every((s) => s === 'critical'));
  });

  test('--fail-on controls the exit code', async () => {
    const strict = await aegis([
      'scan', join(FIXTURES, 'vulnerable-agent'), '--no-connect', '--no-color', '--fail-on', 'critical',
    ]);
    const lenient = await aegis([
      'scan', join(FIXTURES, 'vulnerable-agent'), '--no-connect', '--no-color', '--fail-on', 'info',
    ]);
    assert.equal(strict.code, 1);
    // There are critical findings in this fixture, so `info` also fails; the
    // point is that the flag is honoured rather than ignored.
    assert.equal(lenient.code, 1);
  });

  test('--output writes to a file and reports the path', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aegis-e2e-'));
    try {
      const out = join(dir, 'report.sarif');
      const r = await aegis([
        'scan', join(FIXTURES, 'vulnerable-agent'), '--format', 'sarif',
        '--output', out, '--no-connect',
      ]);
      assert.match(r.stderr, /wrote /);
      const content = await readFile(out, 'utf8');
      assert.equal(JSON.parse(content).version, '2.1.0');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test('scanning a clean tree produces a passing exit code', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aegis-clean-'));
    try {
      await writeFile(join(dir, 'safe.py'), 'def add(a, b):\n    return a + b\n');
      const r = await aegis(['scan', dir, '--no-connect', '--no-color']);
      assert.equal(r.code, 0, `expected clean exit, got ${r.code}: ${r.stdout.slice(0, 300)}`);
      assert.match(r.stdout, /No security issues found/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('CLI: redteam', () => {
  test('--dry-run makes no requests and produces a report', async () => {
    const r = await aegis([
      'redteam', '--dry-run', '--population', '6', '--generations', '2', '--budget', '16', '--no-color',
    ]);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /Red team report/);
    assert.match(r.stdout, /Attacks run/);
    assert.match(r.stdout, /Attack success rate/);
  });

  test('dry-run reports the full catalogue, not a subset', async () => {
    const r = await aegis([
      'redteam', '--dry-run', '--population', '12', '--generations', '3', '--budget', '80',
      '--format', 'json', '--no-color',
    ]);
    const report = (JSON.parse(r.stdout) as { redTeam: { byCategory: unknown[] } }).redTeam;
    assert.equal(report.byCategory.length, 6, 'all six attack categories should be reported');
  });

  test('is deterministic for a given seed', async () => {
    const args = ['redteam', '--dry-run', '--population', '6', '--generations', '2', '--budget', '20', '--format', 'json'];
    const a = await aegis([...args, '--seed', '777']);
    const b = await aegis([...args, '--seed', '777']);
    const ra = (JSON.parse(a.stdout) as { redTeam: { reproducibility: { seed: number } } }).redTeam;
    const rb = (JSON.parse(b.stdout) as { redTeam: { reproducibility: { seed: number } } }).redTeam;
    assert.equal(ra.reproducibility.seed, rb.reproducibility.seed);
  });

  test('missing target is a usage error', async () => {
    const r = await aegis(['redteam']);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /--target is required/);
  });
});

describe('CLI: intel', () => {
  test('renders the attack graph as mermaid', async () => {
    const r = await aegis(['intel']);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /graph LR/);
    assert.match(r.stdout, /classDef/);
  });

  test('--alerts reports graph statistics', async () => {
    const r = await aegis(['intel', '--alerts']);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /techniques/);
    assert.match(r.stdout, /unmitigated/);
  });

  test('unknown technique exits 2', async () => {
    const r = await aegis(['intel', '--technique', 'does-not-exist']);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /unknown technique/);
  });
});

describe('CLI: fix', () => {
  test('produces a plan without writing files by default', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aegis-fix-'));
    try {
      const code = `OPENAI_API_KEY = "${FAKE.openai}"\nprint(OPENAI_API_KEY)\n`;
      await writeFile(join(dir, 'agent.py'), code);
      const before = await readFile(join(dir, 'agent.py'), 'utf8');

      const r = await aegis(['fix', dir, '--no-connect']);
      assert.equal(r.code, 0);
      assert.match(r.stdout, /Remediation plan/);

      const after = await readFile(join(dir, 'agent.py'), 'utf8');
      assert.equal(after, before, 'fix must not write without --apply');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test('--apply rewrites the secret and --max-severity gates it', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aegis-fix-apply-'));
    try {
      const path = join(dir, 'agent.py');
      await writeFile(path, `OPENAI_API_KEY = "${FAKE.openai}"\n`);

      await aegis(['fix', dir, '--no-connect', '--max-severity', 'low', '--apply']);
      const patched = await readFile(path, 'utf8');
      assert.ok(patched.includes('os.environ'), 'expected the key moved to the environment');
      assert.ok(!patched.includes(FAKE.openai), 'secret still present');

      // Re-scan to confirm the fix actually resolved the finding.
      const rescan = await aegis(['scan', dir, '--format', 'json', '--no-connect']);
      const doc = JSON.parse(rescan.stdout) as { findings: Array<{ ruleId: string }> };
      assert.ok(
        !doc.findings.some((f) => f.ruleId === 'AEGIS-SEC-001'),
        'the secret finding should be gone after the fix',
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('CLI: report', () => {
  test('produces a compliance attestation', async () => {
    const r = await aegis([
      'report', join(FIXTURES, 'vulnerable-agent'), '--compliance',
      '--organisation', 'Test Corp', '--system', 'Test Agent',
      '--format', 'markdown', '--no-connect',
    ]);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /Compliance Attestation/);
    // The disclaimer is the most important line in the document, so the
    // assertion normalises whitespace: it must be present however it wraps.
    // The disclaimer is the most important line in the document. Normalise
    // whitespace and strip markdown emphasis, so the assertion tests the
    // claim rather than its formatting.
    const flat = r.stdout.replace(/\s+/g, ' ').replace(/\*\*/g, '');
    assert.match(flat, /not a certification/i);
    assert.match(flat, /Test Corp/);
  });

  test('attestation never claims a control passed', async () => {
    const r = await aegis([
      'report', join(FIXTURES, 'vulnerable-agent'), '--compliance',
      '--organisation', 'Test Corp', '--format', 'markdown', '--no-connect',
    ]);
    assert.ok(!/\bPASS\b/.test(r.stdout), 'the report must never print "PASS"');
    assert.match(
      r.stdout.replace(/\s+/g, ' ').replace(/\*\*/g, ''),
      /not an attestation|No findings \(not attested\)/i,
    );
  });

  test('HTML attestation is self-contained', async () => {
    const r = await aegis([
      'report', join(FIXTURES, 'vulnerable-agent'), '--compliance',
      '--organisation', 'Test Corp', '--format', 'html', '--no-connect',
    ]);
    assert.match(r.stdout, /<!doctype html>/i);
    assert.ok(!/\b(src|href)=["']https?:/i.test(r.stdout), 'unexpected external asset');
  });
});

describe('CLI: sandbox', () => {
  test('records events and fingerprints behaviour', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aegis-sandbox-'));
    try {
      // An "agent" that emits instrumented JSON lines on stdout.
      const agent = join(dir, 'agent.mjs');
      await writeFile(
        agent,
        [
          'process.stdout.write(JSON.stringify({type:"tool_call",tool:"read_file",arguments:{path:"README.md"}}) + "\\n");',
          'process.stdout.write(JSON.stringify({type:"file_read",path:"/etc/passwd"}) + "\\n");',
          'process.stdout.write(JSON.stringify({type:"http_request",url:"http://169.254.169.254/latest/meta-data/"}) + "\\n");',
          'process.stdout.write("done\\n");',
        ].join('\n'),
      );

      const r = await aegis([
        'sandbox', '--command', process.execPath, '--arg', agent, '--format', 'json',
      ]);
      const doc = JSON.parse(r.stdout) as {
        findings: Array<{ ruleId: string; severity: string }>;
        artifacts: {
          fingerprint: { toolUsage: unknown[]; networkHosts: string[] };
          events: number;
          exitCode: number | null;
        };
      };

      // The agent emits three instrumented JSON events plus a plain-text "done".
      // Only the structured lines are recorded as behavioural events.
      assert.equal(doc.artifacts.events, 3, 'expected three recorded events');
      assert.ok(doc.artifacts.fingerprint.toolUsage.length > 0);
      assert.ok(doc.artifacts.fingerprint.networkHosts.includes('169.254.169.254'));

      // Both policy violations must be caught: reading /etc/passwd and
      // contacting the cloud metadata service.
      const denied = doc.findings.filter((f) => f.ruleId.startsWith('AEGIS-POLICY-DENY'));
      assert.ok(denied.length >= 2, `expected 2+ policy denials, got ${denied.length}`);
      assert.ok(denied.some((f) => f.severity === 'critical'));
      assert.equal(r.code, 1, 'policy violations should fail the run');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test('--command is required', async () => {
    const r = await aegis(['sandbox']);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /--command is required/);
  });
});

describe('CLI: dashboard API', () => {
  test('serves scan data produced by the CLI', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aegis-dash-'));
    const port = 8123 + Math.floor(Math.random() * 400);
    let dashboard: { start(): Promise<{ url: string }>; stop(): Promise<void> } | null = null;
    try {
      // Produce a scan export the dashboard can serve.
      const out = join(dir, 'scan.json');
      await aegis([
        'scan', join(FIXTURES, 'vulnerable-agent'),
        '--format', 'json', '--output', out, '--no-connect',
      ]);

      const { Dashboard } = (await import(
        pathToFileURL(join(ROOT, 'packages/web/src/server.ts')).href
      )) as {
        Dashboard: new (options: Record<string, unknown>) => {
          start(): Promise<{ url: string }>;
          stop(): Promise<void>;
        };
      };

      dashboard = new Dashboard({ dataDir: dir, port, host: '127.0.0.1' });
      const { url } = await dashboard.start();

      const health = (await (await fetch(`${url}/healthz`)).json()) as { ok: boolean; scans: number };
      assert.equal(health.ok, true);
      assert.equal(health.scans, 1);

      const scans = (await (await fetch(`${url}/api/scans`)).json()) as Array<{ findings: unknown[]; score: number }>;
      assert.equal(scans.length, 1);
      assert.ok(scans[0]!.findings.length > 0);
      assert.ok(scans[0]!.score > 0);

      const trends = (await (await fetch(`${url}/api/trends`)).json()) as { points: unknown[] };
      assert.equal(trends.points.length, 1);

      const missing = await fetch(`${url}/api/scans/nope`);
      assert.equal(missing.status, 404);
    } finally {
      // Must close the listener or the test process never exits.
      await dashboard?.stop();
      await rm(dir, { recursive: true, force: true });
    }
  });
});