import { existsSync } from 'node:fs';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { dedupeRecords, parseFeed, type FeedRecord } from './feeds.js';

/**
 * Feed clients.
 *
 * Every network call is optional and every failure is non-fatal. Threat
 * intelligence that stops working when a feed rate-limits you is worse than
 * nothing, because it silently under-reports. So: cached-first, fail-open, and
 * every record carries the source it came from.
 */

export interface FeedSource {
  id: string;
  name: string;
  /** Feed format, which determines the parser. */
  format: 'nvd' | 'ghsa' | 'osv' | 'ndjson';
  url: string;
  /** Public feeds need no credential. */
  auth?: { header?: string; token?: string };
  /** How often to refetch, in milliseconds. */
  refreshMs?: number;
  /** Records below this severity are discarded at ingest. */
  minSeverity?: FeedRecord['severity'];
  enabled?: boolean;
}

export interface FetchOptions {
  timeoutMs?: number;
  userAgent?: string;
  cacheDir?: string;
  /** Skip the network entirely and use only the cache. */
  offline?: boolean;
  /** Called for each source before it is fetched. */
  onProgress?: (source: FeedSource, status: 'fetching' | 'cached' | 'failed', detail?: string) => void;
}

export interface FetchResult {
  records: FeedRecord[];
  /** Per-source outcome, so failures are visible rather than silent. */
  sources: Array<{ source: FeedSource; ok: boolean; count: number; error?: string; fromCache: boolean }>;
}

/**
 * Public sources that carry signal about AI agents and MCP.
 *
 * Curated, not exhaustive. Ingesting all of NVD on every run would bury the
 * handful of advisories that actually concern an agent system in noise, and
 * noise is what makes teams disable a tool. Every source here is free, needs
 * no credential, and has a documented rate limit.
 */
export const DEFAULT_SOURCES: FeedSource[] = [
  {
    id: 'ghsa',
    name: 'GitHub Security Advisory (agent and MCP packages)',
    format: 'ghsa',
    url: 'https://api.github.com/advisories?per_page=100&sort=published',
    refreshMs: 60 * 60 * 1000,
    minSeverity: 'medium',
  },
  {
    id: 'osv',
    name: 'OSV — npm, PyPI and Go',
    format: 'ndjson',
    url: 'https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip',
    refreshMs: 6 * 60 * 60 * 1000,
    minSeverity: 'medium',
  },
  {
    id: 'nvd',
    name: 'NVD — known exploited vulnerabilities',
    format: 'nvd',
    url: 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=200&hasKev',
    refreshMs: 12 * 60 * 60 * 1000,
    minSeverity: 'high',
  },
];

/**
 * Free, no-credential APIs for checking the target's own dependencies.
 *
 * These are what a team needs on day one: not "what is vulnerable in the
 * world" but "is anything I depend on vulnerable".
 */
export const OSV_QUERY = 'https://api.osv.dev/v1/query';
export const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
export const NPM_REGISTRY = 'https://registry.npmjs.org';
export const PYPI_REGISTRY = 'https://pypi.org/pypi';

export interface DependencyCheck {
  name: string;
  version?: string;
  ecosystem: 'npm' | 'pypi' | 'go';
  vulns: Array<{ id: string; summary: string; severity: FeedRecord['severity']; fixedIn?: string }>;
}

/**
 * Ask OSV whether one dependency version is vulnerable.
 *
 * The highest value-per-request check Aegis makes: it turns "you have a
 * vulnerable dependency" into a specific, fixable finding.
 */
export async function checkDependency(
  name: string,
  version: string,
  ecosystem: DependencyCheck['ecosystem'],
  options: { timeoutMs?: number } = {},
): Promise<DependencyCheck> {
  const result: DependencyCheck = { name, ...(version ? { version } : {}), ecosystem, vulns: [] };
  try {
    const response = await fetch(OSV_QUERY, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ version, package: { name, ecosystem } }),
      signal: AbortSignal.timeout(options.timeoutMs ?? 15_000),
    });
    if (!response.ok) return result;
    const payload = (await response.json()) as {
      vulns?: Array<{
        id: string;
        summary?: string;
        database_specific?: { severity?: string };
        affected?: Array<{ ranges?: Array<{ events?: Array<{ fixed?: string }> }> }>;
      }>;
    };
    for (const vuln of payload.vulns ?? []) {
      const fixed = firstFixed(vuln);
      result.vulns.push({
        id: vuln.id,
        summary: vuln.summary ?? vuln.id,
        severity: mapOsvSeverity(vuln.database_specific?.severity),
        ...(fixed ? { fixedIn: fixed } : {}),
      });
    }
  } catch {
    // A failed lookup reports no known vulnerabilities. That is the safe
    // direction: it never invents a finding.
  }
  return result;
}

/** Check many dependencies concurrently, with a small concurrency cap. */
export async function checkDependencies(
  deps: ReadonlyArray<{ name: string; version?: string; ecosystem: DependencyCheck['ecosystem'] }>,
  options: { concurrency?: number; timeoutMs?: number } = {},
): Promise<DependencyCheck[]> {
  const limit = options.concurrency ?? 8;
  const out: DependencyCheck[] = [];
  const queue = [...deps];
  const workers = Array.from({ length: Math.max(1, Math.min(limit, queue.length)) }, async () => {
    for (;;) {
      const dep = queue.shift();
      if (!dep) return;
      out.push(await checkDependency(dep.name, dep.version ?? '', dep.ecosystem, options));
    }
  });
  await Promise.all(workers);
  return out;
}

function mapOsvSeverity(label?: string): FeedRecord['severity'] {
  switch ((label ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MODERATE':
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return 'medium';
  }
}

function firstFixed(vuln: {
  affected?: Array<{ ranges?: Array<{ events?: Array<{ fixed?: string }> }> }>;
}): string | undefined {
  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return undefined;
}

/** Flatten dependency results into findings that flow through every report. */
export function dependencyFindings(
  checks: readonly DependencyCheck[],
): Array<{
  name: string; version?: string; ecosystem: string; vulnId: string;
  summary: string; severity: string; fixedIn?: string;
}> {
  const out: Array<{
    name: string; version?: string; ecosystem: string; vulnId: string;
    summary: string; severity: string; fixedIn?: string;
  }> = [];
  for (const check of checks) {
    for (const vuln of check.vulns) {
      out.push({
        name: check.name,
        ...(check.version ? { version: check.version } : {}),
        ecosystem: check.ecosystem,
        vulnId: vuln.id,
        summary: vuln.summary,
        severity: vuln.severity,
        ...(vuln.fixedIn ? { fixedIn: vuln.fixedIn } : {}),
      });
    }
  }
  return out;
}

/**
 * Fetch a set of feeds, using a local cache when the network is unavailable or
 * the refresh interval has not elapsed.
 */
export async function fetchFeeds(
  sources: readonly FeedSource[],
  options: FetchOptions = {},
): Promise<FetchResult> {
  const timeoutMs = options.timeoutMs ?? 20_000;
  const cacheDir = options.cacheDir ? resolve(options.cacheDir) : undefined;
  const userAgent = options.userAgent ?? 'aegis-intel/0.1 (+https://aegis.dev)';

  const all: FeedRecord[] = [];
  const results: FetchResult['sources'] = [];

  for (const source of sources) {
    if (source.enabled === false) continue;

    // Cache first: a working cache is better than a failed request, and it
    // makes repeat runs fast and reproducible.
    if (!options.offline && cacheDir) {
      const cached = await readCache(cacheDir, source);
      if (cached && Date.now() - cached.fetchedAt < (source.refreshMs ?? 3_600_000)) {
        options.onProgress?.(source, 'cached');
        all.push(...cached.records);
        results.push({ source, ok: true, count: cached.records.length, fromCache: true });
        continue;
      }
    }

    if (options.offline) {
      const cached = cacheDir ? await readCache(cacheDir, source) : null;
      if (cached) {
        options.onProgress?.(source, 'cached');
        all.push(...cached.records);
        results.push({ source, ok: true, count: cached.records.length, fromCache: true });
      } else {
        results.push({ source, ok: false, count: 0, error: 'offline and no cache', fromCache: false });
      }
      continue;
    }

    options.onProgress?.(source, 'fetching');
    try {
      const response = await fetch(source.url, {
        headers: {
          'user-agent': userAgent,
          accept: 'application/json, application/x-ndjson, */*',
          ...(source.auth?.header ? { [source.auth.header]: source.auth.token ?? '' } : {}),
        },
        signal: AbortSignal.timeout(timeoutMs),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status} ${response.statusText}`);
      }

      const body = await response.text();
      let records = parseFeed(body, source.format);

      // Apply the source's severity floor, but keep anything agent-relevant:
      // a "low" MCP advisory is more interesting here than a "high" one in a
      // graphics library.
      const floor = source.minSeverity;
      if (floor) {
        const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        records = records.filter((r) => order[r.severity] <= order[floor] || r.agentRelevant);
      }

      if (cacheDir) await writeCache(cacheDir, source, records);

      options.onProgress?.(source, 'cached', `${records.length} record(s)`);
      all.push(...records);
      results.push({ source, ok: true, count: records.length, fromCache: false });
    } catch (error) {
      // Fail open to the cache rather than dropping the source entirely.
      const cached = cacheDir ? await readCache(cacheDir, source) : null;
      if (cached) {
        options.onProgress?.(source, 'cached', `stale cache after failure`);
        all.push(...cached.records);
        results.push({ source, ok: true, count: cached.records.length, fromCache: true });
      } else {
        const message = (error as Error).message;
        options.onProgress?.(source, 'failed', message);
        results.push({ source, ok: false, count: 0, error: message, fromCache: false });
      }
    }
  }

  return { records: dedupeRecords(all), sources: results };
}

interface CacheEntry {
  fetchedAt: number;
  sourceId: string;
  records: FeedRecord[];
}

function cachePath(dir: string, source: FeedSource): string {
  return join(dir, `${source.id}.json`);
}

async function readCache(dir: string, source: FeedSource): Promise<CacheEntry | null> {
  try {
    const path = cachePath(dir, source);
    if (!existsSync(path)) return null;
    return JSON.parse(await readFile(path, 'utf8')) as CacheEntry;
  } catch {
    return null;
  }
}

async function writeCache(dir: string, source: FeedSource, records: FeedRecord[]): Promise<void> {
  try {
    await mkdir(dir, { recursive: true });
    await writeFile(
      cachePath(dir, source),
      JSON.stringify({ fetchedAt: Date.now(), sourceId: source.id, records }),
      'utf8',
    );
  } catch {
    // A cache write failure is not worth failing the run for.
  }
}

/**
 * Parse an NVD 2.0 API response for a given CVE range.
 *
 * NVD paginates and rate-limits aggressively (5 requests per 30 seconds
 * without a key), so this is exposed as an explicit caller rather than run
 * automatically.
 */
export async function fetchNvd(
  options: {
    apiKey?: string;
    from?: string;
    to?: string;
    pageSize?: number;
    maxPages?: number;
    timeoutMs?: number;
  } = {},
): Promise<FeedRecord[]> {
  const pageSize = options.pageSize ?? 2000;
  const maxPages = options.maxPages ?? 5;
  const out: FeedRecord[] = [];

  for (let page = 0; page < maxPages; page++) {
    const startIndex = page * pageSize;
    const params = new URLSearchParams({
      resultsPerPage: String(pageSize),
      startIndex: String(startIndex),
    });
    if (options.from) params.set('pubStartDate', options.from);
    if (options.to) params.set('pubEndDate', options.to);

    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${params.toString()}`;
    const response = await fetch(url, {
      headers: { 'user-agent': 'aegis-intel/0.1 (+https://aegis.dev)' },
      ...(options.apiKey ? { headers: { 'apiKey': options.apiKey } } : {}),
      signal: AbortSignal.timeout(options.timeoutMs ?? 30_000),
    });
    if (!response.ok) throw new Error(`NVD returned HTTP ${response.status}`);

    const { parseNvd } = await import('./feeds.js');
    const batch = parseNvd((await response.json()) as never);
    out.push(...batch);

    if (batch.length === 0 || batch.length < pageSize) break;
    // NVD without an API key allows 5 requests per 30 seconds.
    if (!options.apiKey) await new Promise((r) => setTimeout(r, 6500));
  }

  return dedupeRecords(out);
}

void dirname;