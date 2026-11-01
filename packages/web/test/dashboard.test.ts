import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Dashboard, resolveAssetDir } from '../src/server.js';

describe('dashboard', () => {
  let dir: string;
  let dashboard: Dashboard;
  let base: string;

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), 'aegis-dashboard-'));
    writeFileSync(
      join(dir, 'scan-1.json'),
      JSON.stringify({
        target: { path: '/repo/agent' },
        startedAt: '2026-01-01T00:00:00.000Z',
        durationMs: 12,
        score: { score: 72, grade: 'C' },
        findings: [{ severity: 'critical' }, { severity: 'high' }],
      }),
      'utf8',
    );

    // Port 0 asks the OS for a free port; the server reports the chosen one.
    dashboard = new Dashboard({ dataDir: dir, port: 0 });
    const started = await dashboard.start();
    base = started.url;
  });

  after(async () => {
    await dashboard.stop();
    rmSync(dir, { recursive: true, force: true });
  });

  test('serves the dashboard UI at /', async () => {
    const res = await fetch(`${base}/`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type') ?? '', /text\/html/);
    const html = await res.text();
    assert.match(html, /<title>/i);
    // The UI is useless without its stylesheet, which used to 404 because the
    // server looked for assets inside the user's scan-data directory.
    assert.match(html, /app\.css/);
  });

  test('serves the stylesheet', async () => {
    const res = await fetch(`${base}/app.css`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type') ?? '', /text\/css/);
  });

  test('lists scans with their score', async () => {
    const res = await fetch(`${base}/api/scans`);
    assert.equal(res.status, 200);
    const scans = (await res.json()) as Array<{ score: number; grade: string }>;
    assert.equal(scans.length, 1);
    assert.equal(scans[0]?.score, 72);
    assert.equal(scans[0]?.grade, 'C');
  });

  test('exposes readiness and Prometheus metrics', async () => {
    const ready = await fetch(`${base}/readyz`);
    assert.equal(ready.status, 200);
    const readyBody = (await ready.json()) as { ready: boolean; scans: number };
    assert.equal(readyBody.ready, true);
    assert.equal(readyBody.scans, 1);

    const metrics = await fetch(`${base}/metrics`);
    assert.equal(metrics.status, 200);
    const text = await metrics.text();
    assert.match(text, /aegis_scans_total 1/);
    assert.match(text, /aegis_findings_critical_total 1/);
  });

  test('returns 404 for an unknown asset', async () => {
    const res = await fetch(`${base}/does-not-exist.js`);
    assert.equal(res.status, 404);
  });
});

describe('dashboard token auth', () => {
  let dir: string;
  let dashboard: Dashboard;
  let base: string;

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), 'aegis-auth-'));
    writeFileSync(
      join(dir, 'scan-1.json'),
      JSON.stringify({
        target: { path: '/repo/agent' },
        startedAt: '2026-01-01T00:00:00.000Z',
        durationMs: 5,
        score: { score: 90, grade: 'A' },
        findings: [],
      }),
      'utf8',
    );
    dashboard = new Dashboard({ dataDir: dir, port: 0, token: 'secret-token' });
    base = (await dashboard.start()).url;
  });

  after(async () => {
    await dashboard.stop();
    rmSync(dir, { recursive: true, force: true });
  });

  test('rejects API requests without the bearer token', async () => {
    // The API carries findings, evidence and file paths. With a token
    // configured, an unauthenticated caller must not read them.
    for (const path of ['/api/scans', '/api/audit', '/api/trends']) {
      const res = await fetch(`${base}${path}`);
      assert.equal(res.status, 401, `${path} should require a token`);
    }
  });

  test('accepts API requests with the bearer token', async () => {
    const res = await fetch(`${base}/api/scans`, {
      headers: { authorization: 'Bearer secret-token' },
    });
    assert.equal(res.status, 200);
    const scans = (await res.json()) as unknown[];
    assert.equal(scans.length, 1);
  });

  test('serves the static UI without a token', async () => {
    // The HTML and CSS are static; the findings behind /api are the secret.
    const res = await fetch(`${base}/`);
    assert.equal(res.status, 200);
  });
});

describe('resolveAssetDir', () => {
  let root: string;

  before(() => {
    root = mkdtempSync(join(tmpdir(), 'aegis-layout-'));
  });

  after(() => {
    rmSync(root, { recursive: true, force: true });
  });

  /** Create `dir` with an `index.html`, proving it is a valid asset root. */
  function assets(dir: string): string {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'index.html'), '<title>aegis</title>', 'utf8');
    return dir;
  }

  test('source layout: packages/web/src -> packages/web/public', () => {
    const moduleDir = join(root, 'source', 'packages', 'web', 'src');
    const publicDir = assets(join(root, 'source', 'packages', 'web', 'public'));

    assert.equal(resolveAssetDir(moduleDir, join(root, 'source', 'data')), resolve(publicDir));
  });

  test('published layout: build/publish/packages/web/src -> packages/web/public', () => {
    // Mirrors the tarball exactly: the compiled server is nested under
    // build/publish, while the assets stay at the package root. With the wrong
    // number of `..` this returns a path that does not exist and the published
    // dashboard serves 404 for its own index.html.
    const pkg = join(root, 'published');
    const moduleDir = join(pkg, 'build', 'publish', 'packages', 'web', 'src');
    const publicDir = assets(join(pkg, 'packages', 'web', 'public'));

    assert.equal(resolveAssetDir(moduleDir, join(pkg, 'data')), resolve(publicDir));
  });

  test('explicit assetDir wins over every other layout', () => {
    const moduleDir = join(root, 'source', 'packages', 'web', 'src');
    assets(join(root, 'source', 'packages', 'web', 'public'));
    const override = assets(join(root, 'override'));

    assert.equal(
      resolveAssetDir(moduleDir, join(root, 'source', 'data'), override),
      resolve(override),
    );
  });

  test('falls back to the legacy <data>/public location', () => {
    const moduleDir = join(root, 'legacy', 'packages', 'web', 'src');
    const dataDir = join(root, 'legacy', 'data');
    const legacyPublic = assets(join(dataDir, 'public'));

    assert.equal(resolveAssetDir(moduleDir, dataDir), resolve(legacyPublic));
  });

  test('falls back to the source path when nothing exists', () => {
    const moduleDir = join(root, 'empty', 'packages', 'web', 'src');
    const expected = resolve(join(moduleDir, '..', 'public'));

    assert.equal(resolveAssetDir(moduleDir, join(root, 'empty', 'data')), expected);
  });
});