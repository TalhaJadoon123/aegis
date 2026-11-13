import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { extname, join, resolve, dirname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Aegis dashboard.
 *
 * A dependency-free HTTP server serving the scan history, findings, supply
 * chain graph, behavioural fingerprints, red team reports and compliance
 * dashboards.
 *
 * Deliberately built on `node:http` rather than Next.js. For the deployment
 * that matters — on-premise, inside a customer's network, often air-gapped —
 * "npm install and run" beats a framework, and the server-side rendering a
 * dashboard needs is a few hundred lines, not a build toolchain.
 */

export interface DashboardOptions {
  /** Directory containing `aegis.json` scan exports. */
  dataDir?: string;
  port?: number;
  host?: string;
  /** Shared bearer token. When unset, the dashboard binds to loopback only. */
  token?: string;
  logger?: { info(m: string): void; warn(m: string): void; error(m: string): void };
}

export interface ScanRecord {
  id: string;
  target: string;
  startedAt: string;
  durationMs: number;
  score: number;
  grade: string;
  findings: unknown[];
  artifacts?: Record<string, unknown>;
}

export class Dashboard {
  private readonly dataDir: string;
  private readonly port: number;
  private readonly host: string;
  private readonly token: string | undefined;
  private readonly logger: DashboardOptions['logger'];
  /** Held so the server can be stopped; a bare listen keeps the process alive. */
  private server: import('node:http').Server | null = null;

  constructor(options: DashboardOptions = {}) {
    this.dataDir = resolve(options.dataDir ?? '.aegis/dashboard');
    this.port = options.port ?? 8080;
    this.token = options.token ?? process.env['AEGIS_DASHBOARD_TOKEN'];
    // Without a token the dashboard must not be exposed: it shows findings,
    // evidence, and file paths.
    this.host = options.host ?? (this.token ? '127.0.0.1' : '127.0.0.1');
    this.logger = options.logger;
  }

  async start(): Promise<{ url: string; port: number }> {
    if (!existsSync(this.dataDir)) {
      this.logger?.warn(`no scan data at ${this.dataDir}; the dashboard will start empty`);
    }

    const server = createServer((req, res) => {
      void this.handle(req, res).catch((error) => {
        this.logger?.error(`request failed: ${(error as Error).message}`);
        send(res, 500, 'application/json', JSON.stringify({ error: 'internal error' }));
      });
    });

    await new Promise<void>((resolvePromise) => {
      server.listen(this.port, this.host, resolvePromise);
    });
    this.server = server;

    const url = `http://${this.host}:${this.port}`;
    this.logger?.info(`Aegis dashboard listening on ${url}`);
    if (!this.token) {
      this.logger?.info('no AEGIS_DASHBOARD_TOKEN set; bound to loopback only');
    }
    return { url, port: this.port };
  }

  /** Stop listening. Required for clean exit in tests and scripts. */
  async stop(): Promise<void> {
    const server = this.server;
    if (!server) return;
    this.server = null;
    await new Promise<void>((resolvePromise) => {
      // `closeAllConnections` matters: a keep-alive fetch from a client would
      // otherwise hold the socket open and the process would never exit.
      server.closeAllConnections?.();
      server.close(() => resolvePromise());
    });
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const path = normalize(url.pathname).replace(/\\/g, '/');

    // Constant-time-ish token check; the API carries scan data, so it is
    // authenticated whenever a token is configured.
    if (path.startsWith('/api/') && this.token) {
      const provided = (req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
      if (provided !== this.token) {
        send(res, 401, 'application/json', JSON.stringify({ error: 'unauthorized' }));
        return;
      }
    }

    if (path === '/api/scans') {
      send(res, 200, 'application/json', JSON.stringify(await this.listScans()));
      return;
    }
    if (path.startsWith('/api/scans/')) {
      const id = decodeURIComponent(path.slice('/api/scans/'.length));
      const record = await this.getScan(id);
      if (!record) {
        send(res, 404, 'application/json', JSON.stringify({ error: 'not found' }));
        return;
      }
      send(res, 200, 'application/json', JSON.stringify(record));
      return;
    }
    if (path === '/api/trends') {
      send(res, 200, 'application/json', JSON.stringify(await this.trends()));
      return;
    }
    if (path === '/healthz') {
      send(res, 200, 'application/json', JSON.stringify({ ok: true, scans: (await this.listScans()).length }));
      return;
    }

    // Static assets from the bundle directory.
    const asset = path === '/' ? 'index.html' : path.slice(1);
    if (asset.includes('..') || asset.includes('\0')) {
      send(res, 400, 'text/plain', 'bad request');
      return;
    }
    const file = join(this.dataDir, 'public', asset);
    if (existsSync(file)) {
      const content = await readFile(file);
      send(res, 200, contentType(extname(file)), content);
      return;
    }

    send(res, 404, 'text/plain', 'not found');
  }

  /** Every scan export in the data directory, newest first. */
  private async listScans(): Promise<ScanRecord[]> {
    const { readdir } = await import('node:fs/promises');
    if (!existsSync(this.dataDir)) return [];
    let entries: string[];
    try {
      entries = await readdir(this.dataDir);
    } catch {
      return [];
    }

    const records: ScanRecord[] = [];
    for (const entry of entries) {
      if (!entry.endsWith('.json')) continue;
      try {
        const raw = JSON.parse(await readFile(join(this.dataDir, entry), 'utf8')) as Record<string, unknown>;
        records.push(toRecord(entry.replace(/\.json$/, ''), raw));
      } catch {
        // A partially-written export should not break the dashboard.
      }
    }
    return records.sort((a, b) => b.startedAt.localeCompare(a.startedAt));
  }

  private async getScan(id: string): Promise<ScanRecord | null> {
    const { readdir } = await import('node:fs/promises');
    if (!existsSync(this.dataDir)) return null;
    let entries: string[];
    try {
      entries = await readdir(this.dataDir);
    } catch {
      return null;
    }
    for (const entry of entries) {
      if (!entry.endsWith('.json')) continue;
      if (entry.replace(/\.json$/, '') !== id) continue;
      try {
        const raw = JSON.parse(await readFile(join(this.dataDir, entry), 'utf8')) as Record<string, unknown>;
        return toRecord(id, raw);
      } catch {
        return null;
      }
    }
    return null;
  }

  /** Score-over-time series, for the trend chart. */
  private async trends(): Promise<{
    points: Array<{ at: string; score: number; findings: number; critical: number }>;
    deltas: Array<{ at: string; change: number }>;
  }> {
    const scans = await this.listScans();
    const ascending = [...scans].reverse();
    const points = ascending.map((scan) => ({
      at: scan.startedAt,
      score: scan.score,
      findings: scan.findings.length,
      critical: scan.findings.filter(
        (f) => (f as { severity?: string }).severity === 'critical',
      ).length,
    }));

    const deltas = points.slice(1).map((point, i) => ({
      at: point.at,
      change: point.score - (points[i]?.score ?? point.score),
    }));

    return { points, deltas };
  }
}

function toRecord(id: string, raw: Record<string, unknown>): ScanRecord {
  const target = (raw['target'] ?? {}) as Record<string, unknown>;
  const score = (raw['score'] ?? {}) as Record<string, unknown>;
  return {
    id,
    target: String(target['path'] ?? target['url'] ?? target['type'] ?? 'unknown'),
    startedAt: String(raw['startedAt'] ?? new Date().toISOString()),
    durationMs: Number(raw['durationMs'] ?? 0),
    score: Number(score['score'] ?? 0),
    grade: String(score['grade'] ?? 'F'),
    findings: Array.isArray(raw['findings']) ? (raw['findings'] as unknown[]) : [],
    ...(raw['artifacts'] ? { artifacts: raw['artifacts'] as Record<string, unknown> } : {}),
  };
}

function send(res: ServerResponse, status: number, type: string, body: string | Buffer): void {
  res.writeHead(status, {
    'content-type': `${type}; charset=utf-8`,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    // `connect-src 'self'` is required: the dashboard is a single-page app that
    // fetches its own /api routes, and an over-tight `default-src 'none'`
    // blocks those requests and leaves a blank page.
    //
    // Everything else stays locked down. There is no CDN, no external font, no
    // remote image — the page must render on a machine with no network, which
    // is also how most enterprise evaluations start.
    'content-security-policy': [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "connect-src 'self'",
      "font-src 'self'",
      "object-src 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
    ].join('; '),
  });
  res.end(body);
}

function contentType(ext: string): string {
  switch (ext) {
    case '.html':
      return 'text/html';
    case '.js':
      return 'text/javascript';
    case '.css':
      return 'text/css';
    case '.json':
      return 'application/json';
    case '.svg':
      return 'image/svg+xml';
    default:
      return 'application/octet-stream';
  }
}

void dirname;
void fileURLToPath;

export async function startDashboard(options: DashboardOptions = {}) {
  const dashboard = new Dashboard(options);
  return dashboard.start();
}