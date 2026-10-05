import { relative, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { computeScore, dedupeFindings, sortFindings } from '../../severity.js';
import { evaluateFile, matchToFinding, RuleSet, type FileUnderScan } from '../../rules/evaluator.js';
import { parseJsonLoose } from '../../walk.js';
import { analyzeIntrospection, analyzeMcpConfig } from './analyzers.js';
import { createConnector, type Connector } from './connectors.js';
import {
  discoverMcpServers,
  type DiscoveredMcpServer,
  type McpConfigLocation,
} from './discovery.js';
import {
  buildSupplyChainGraph,
  graphToD3,
  graphToMermaid,
  type SupplyChainGraph,
} from './graph.js';
import { emptyIntrospection, type McpIntrospection } from './protocol.js';
import type {
  Finding,
  Scanner,
  ScanTarget,
  ScannerContext,
  SecurityScore,
  Severity,
} from '../../types.js';

export interface McpScanOptions {
  /** Scan explicit config paths only. */
  configPaths?: string[];
  /** Also enumerate running MCP server processes. */
  includeProcesses?: boolean;
  /** Connect to servers and introspect them. Default true. */
  connect?: boolean;
  /** Per-server introspection timeout. Default 15s. */
  timeoutMs?: number;
  /** Refuse to spawn server processes (config-only analysis). */
  noSpawn?: boolean;
  minSeverity?: Severity;
  /** Skip servers whose name matches. */
  exclude?: string[];
  /** Scan every config file, not just the first that parses. */
  allConfigs?: boolean;
}

export interface McpScanReport {
  target: ScanTarget;
  servers: DiscoveredMcpServer[];
  introspections: Array<{ server: DiscoveredMcpServer; introspection: McpIntrospection }>;
  locations: McpConfigLocation[];
  findings: Finding[];
  graph: SupplyChainGraph;
  score: SecurityScore;
  /** Per-server score, so the report can name the worst offender. */
  serverScores: Array<{ name: string; score: number; grade: string; findings: number }>;
  durationMs: number;
  errors: string[];
}

/**
 * MCP server scanner.
 *
 * Runs in two passes, because a config-only scan and a live scan answer
 * different questions:
 *
 *  - **Config pass** (always): what the machine will execute. Detects unpinned
 *    installs, shell wrappers, inline credentials, plaintext transports. Works
 *    with servers switched off, which is how most people run this in CI.
 *  - **Introspection pass** (when `connect`): what the server actually exposes.
 *    This is the only way to see tool poisoning, because a poisoned
 *    description is invisible in the config file — it arrives over the wire.
 *
 * The supply chain graph is built from *both* passes, so a credential in a
 * config file and a poisoned tool over the wire end up in the same picture.
 */
export class McpScanner implements Scanner<McpScanOptions> {
  readonly name = 'mcp';
  readonly targetType = 'mcp' as const;
  readonly sideEffects = 'local-exec' as const;
  readonly options: McpScanOptions;

  constructor(options: McpScanOptions = {}) {
    this.options = options;
  }

  /**
   * Evaluate the YAML rule packs against each discovered config file.
   *
   * The code analyzers handle live introspection, which rules cannot see. Rules
   * handle config-file structure, which code analyzers cannot reach — patterns
   * like `alwaysAllow: ["*"]` live only in the rule pack, so without this the
   * most important MCP misconfiguration was never reported.
   */
  private async scanConfigs(
    locations: readonly McpConfigLocation[],
    rules: RuleSet,
  ): Promise<Finding[]> {
    const out: Finding[] = [];
    for (const location of locations) {
      if (!location.exists) continue;
      try {
        const content = await readFile(location.path, 'utf8');
        let json: unknown;
        try {
          json = parseJsonLoose(content);
        } catch {
          json = undefined;
        }
        const file: FileUnderScan = {
          path: location.path,
          content,
          language: location.path.endsWith('.json') ? 'json' : 'text',
          targetType: 'mcp',
          ...(json !== undefined ? { json } : {}),
        };
        for (const match of evaluateFile(rules, file, { scanner: 'mcp' })) {
          out.push(matchToFinding(match, 'mcp'));
        }
      } catch {
        // Unreadable config: the discovery pass already reported it.
      }
    }
    return out;
  }

  async *scan(target: ScanTarget, ctx: ScannerContext): AsyncIterable<Finding> {
    const report = await this.scanToReport(target, ctx);
    for (const finding of report.findings) {
      yield finding;
    }
  }

  async scanToReport(target: ScanTarget, ctx: ScannerContext): Promise<McpScanReport> {
    const started = Date.now();
    const cwd = target.path ? resolve(target.path) : ctx.root;
    const findings: Finding[] = [];
    const errors: string[] = [];

    // --- Discover -----------------------------------------------------------
    const discovery = await discoverMcpServers({
      cwd,
      ...(this.options.configPaths ?? (target.path ? [target.path] : undefined)
        ? { explicitPaths: this.options.configPaths ?? [target.path!] }
        : {}),
      ...(this.options.includeProcesses === undefined
        ? {}
        : { includeProcesses: this.options.includeProcesses }),
      logger: ctx.logger,
    });
    errors.push(...discovery.errors);

    const excluded = new Set(this.options.exclude ?? []);
    const servers = discovery.servers.filter((s) => !excluded.has(s.name));
    if (servers.length === 0) {
      ctx.logger.info('no MCP servers found in any known configuration');
    }

    // --- Config pass --------------------------------------------------------
    for (const server of servers) {
      findings.push(...analyzeMcpConfig(server));
    }
    // The rule packs also carry config-file structure checks (jsonpath
    // patterns, regexes over the raw JSON) that the code analyzers duplicate
    // only partially.
    findings.push(...(await this.scanConfigs(discovery.locations, ctx.registry.ruleSet() as RuleSet)));

    // --- Introspection pass -------------------------------------------------
    const introspections: Array<{ server: DiscoveredMcpServer; introspection: McpIntrospection }> = [];
    if (this.options.connect !== false) {
      for (const server of servers) {
        if (ctx.signal?.aborted) break;
        const result = await this.introspectServer(server, ctx);
        introspections.push(result);
        for (const error of result.introspection.errors) {
          errors.push(`${server.name}: ${error}`);
        }
        findings.push(...analyzeIntrospection(server, result.introspection));
      }
    } else {
      for (const server of servers) {
        introspections.push({ server, introspection: emptyIntrospection(server.name) });
      }
    }

    // --- Graph & score ------------------------------------------------------
    const graph = buildSupplyChainGraph({ servers, introspections });
    const deduped = sortFindings(dedupeFindings(findings));

    const serverScores = servers.map((server) => {
      const own = deduped.filter((f) => f.metadata?.['serverId'] === server.id);
      const score = computeScore({ findings: own });
      return {
        name: server.name,
        score: score.score,
        grade: score.grade,
        findings: own.length,
      };
    });

    ctx.logger.info(
      `mcp scanner: ${servers.length} server(s), ${introspections.filter((i) => i.introspection.complete).length} introspected, ` +
        `${deduped.length} finding(s), ${graph.stats.exfiltrationPaths.length} exfiltration path(s)`,
    );

    return {
      target,
      servers,
      introspections,
      locations: discovery.locations,
      findings: deduped,
      graph,
      score: computeScore({ findings: deduped }),
      serverScores,
      durationMs: Date.now() - started,
      errors,
    };
  }

  private async introspectServer(
    server: DiscoveredMcpServer,
    ctx: ScannerContext,
  ): Promise<{ server: DiscoveredMcpServer; introspection: McpIntrospection }> {
    let connector: Connector;
    try {
      connector = createConnector(server, {
        ...(this.options.timeoutMs !== undefined ? { timeoutMs: this.options.timeoutMs } : {}),
        ...(this.options.noSpawn !== undefined ? { noSpawn: this.options.noSpawn } : {}),
        ...(server.cwd ? { cwd: server.cwd } : {}),
        ...(server.env ? { env: server.env } : {}),
        ...(server.headers ? { headers: server.headers } : {}),
        logger: ctx.logger,
      });
    } catch (error) {
      const introspection = emptyIntrospection(server.name);
      introspection.errors.push(`could not connect: ${(error as Error).message}`);
      return { server, introspection };
    }

    try {
      const introspection = await connector.introspect();
      return { server, introspection };
    } catch (error) {
      const introspection = emptyIntrospection(server.name);
      introspection.errors.push(`introspection failed: ${(error as Error).message}`);
      ctx.logger.warn(`mcp "${server.name}" introspection failed: ${(error as Error).message}`);
      return { server, introspection };
    } finally {
      await connector.close().catch(() => {});
    }
  }
}

/**
 * Render the supply chain graph as a standalone HTML page with D3.
 *
 * Accepts either a `SupplyChainGraph` or an already-serialised D3 payload, so a
 * caller that already has the graph in report form does not rebuild it.
 */
export function renderGraphHtml(
  graph: SupplyChainGraph | ReturnType<typeof graphToD3>,
  options: { title?: string } = {},
): string {
  const isD3 = Array.isArray((graph as { nodes?: unknown }).nodes);
  const data = isD3
    ? (graph as ReturnType<typeof graphToD3>)
    : graphToD3(graph as SupplyChainGraph);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>${escapeHtml(options.title ?? 'MCP Supply Chain Graph')}</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; background:#0b1020; color:#e2e8f0; font:14px ui-sans-serif,system-ui,-apple-system,sans-serif; }
  header { padding:16px 20px; border-bottom:1px solid #1e293b; }
  h1 { margin:0 0 4px; font-size:18px; }
  .sub { color:#94a3b8; font-size:13px; }
  #wrap { display:flex; height:calc(100vh - 68px); }
  #graph { flex:1; }
  #panel { width:340px; padding:16px; border-left:1px solid #1e293b; overflow:auto; }
  .stat { display:flex; justify-content:space-between; padding:4px 0; border-bottom:1px solid #1e293b; }
  .node-label { font-size:10px; fill:#cbd5e1; pointer-events:none; }
  .path { font-family:ui-monospace,monospace; font-size:11px; color:#fca5a5; margin:6px 0; word-break:break-all; }
</style>
</head>
<body>
<header>
  <h1>${escapeHtml(options.title ?? 'MCP Supply Chain Graph')}</h1>
  <div class="sub">${data.stats.serverCount} servers · ${data.stats.toolCount} tools · ${data.stats.resourceCount} resources · ${data.stats.edgeCount} edges</div>
</header>
<div id="wrap">
  <div id="graph"></div>
  <aside id="panel"></aside>
</div>
<script type="application/json" id="data">${JSON.stringify(data).replace(/</g, '\\u003c')}</script>
<script src="https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"></script>
<script>
const data = JSON.parse(document.getElementById('data').textContent);
const COLORS = {
  server: '#2563eb', tool: '#0ea5e9', resource: '#7c3aed', prompt: '#a855f7',
  dataset: '#f59e0b', credential: '#e11d48', 'external-service': '#64748b', agent: '#10b981'
};
const width = document.getElementById('graph').clientWidth;
const height = document.getElementById('graph').clientHeight;

const svg = d3.select('#graph').append('svg')
  .attr('width', width).attr('height', height);
const g = svg.append('g');

svg.call(d3.zoom().scaleExtent([0.2, 6]).on('zoom', (ev) => g.attr('transform', ev.transform)));

const sim = d3.forceSimulation(data.nodes)
  .force('link', d3.forceLink(data.links).id((d) => d.id).distance(110))
  .force('charge', d3.forceManyBody().strength(-420))
  .force('center', d3.forceCenter(width / 2, height / 2))
  .force('collide', d3.forceCollide().radius((d) => d.radius + 8));

const link = g.append('g').selectAll('line').data(data.links).join('line')
  .attr('stroke', (d) => (d.kind === 'exfiltrates-to' ? '#e11d48' : '#334155'))
  .attr('stroke-width', (d) => 1 + d.weight * 2.5)
  .attr('stroke-dasharray', (d) => (d.kind === 'exfiltrates-to' ? '4 3' : null));

const node = g.append('g').selectAll('circle').data(data.nodes).join('circle')
  .attr('r', (d) => d.radius)
  .attr('fill', (d) => COLORS[d.kind] || '#64748b')
  .attr('stroke', (d) => (d.risk >= 0.8 ? '#dc2626' : '#0b1020'))
  .attr('stroke-width', (d) => (d.risk >= 0.8 ? 3 : 1));

node.append('title').text((d) => d.label + ' [' + d.kind + '] risk=' + d.risk);

g.append('g').selectAll('text').data(data.nodes).join('text')
  .attr('class', 'node-label')
  .attr('x', (d) => d.radius + 3)
  .attr('y', 3)
  .text((d) => (d.risk >= 0.5 ? d.label : ''));

node.call(d3.drag()
  .on('start', (ev, d) => { if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
  .on('drag', (ev, d) => { d.fx = ev.x; d.fy = ev.y; })
  .on('end', (ev, d) => { if (!ev.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));

sim.on('tick', () => {
  link.attr('x1', (d) => d.source.x).attr('y1', (d) => d.source.y)
      .attr('x2', (d) => d.target.x).attr('y2', (d) => d.target.y);
  node.attr('cx', (d) => d.x).attr('cy', (d) => d.y);
});

const panel = document.getElementById('panel');
panel.innerHTML =
  '<div class="stat"><span>Servers</span><b>' + data.stats.serverCount + '</b></div>' +
  '<div class="stat"><span>Tools</span><b>' + data.stats.toolCount + '</b></div>' +
  '<div class="stat"><span>Resources</span><b>' + data.stats.resourceCount + '</b></div>' +
  '<div class="stat"><span>Prompts</span><b>' + data.stats.promptCount + '</b></div>' +
  '<div class="stat"><span>Edges</span><b>' + data.stats.edgeCount + '</b></div>' +
  '<div class="stat"><span>Max depth</span><b>' + data.stats.maxDepth + '</b></div>' +
  '<h3 style="margin-top:16px;font-size:14px">Exfiltration paths</h3>' +
  (data.stats.exfiltrationPaths.length === 0
    ? '<p class="sub">None found.</p>'
    : data.stats.exfiltrationPaths.slice(0, 12).map((p) => '<div class="path">' + p.join(' → ') + '</div>').join(''));
</script>
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!,
  );
}

export { graphToMermaid, graphToD3 };