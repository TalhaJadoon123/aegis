/**
 * Aegis CLI.
 *
 * One binary, six verbs, zero runtime dependencies. Every command writes to
 * stdout and diagnostics to stderr, so `aegis scan --format json | jq` works
 * without the tool deciding how you want to consume it.
 */
import { resolve, join } from 'node:path';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname } from 'node:path';
import {
  anyFlag, getBoolean, getNumber, getString, getStringList, parseArgs, renderOptions,
  ParseError, type OptionSpec, type ParsedArgs,
} from './args.js';
import { createLogger, type Logger } from '../../core/src/logger.js';
import { PluginRegistry } from '../../core/src/registry.js';
import { loadRulePacks } from '../../core/src/rules/index.js';
import { computeScore, dedupeFindings, sortFindings, toSeverity } from '../../core/src/severity.js';
import { AgentScanner } from '../../core/src/scanners/agent/scanner.js';
import { McpScanner, renderGraphHtml } from '../../core/src/scanners/mcp/scanner.js';
import { buildRemediationPlan } from '../../core/src/remediation.js';
import {
  buildDocument, render, type AegisDocument, type OutputFormat,
} from '../../core/src/output.js';
import {
  assessCompliance, executiveSummary, toAttestationMarkdown, toAttestationHtml,
} from '../../core/src/compliance.js';
import { computeStats, graphToMermaid as attackGraphToMermaid } from '../../core/src/intel/graph.js';
import { graphToD3, graphToMermaid } from '../../core/src/scanners/mcp/graph.js';
import type { Finding, ScanTargetType, Severity } from '../../core/src/types.js';
import type { DiscoveredMcpServer } from '../../core/src/scanners/mcp/discovery.js';
import { runRedTeam } from '../../core/src/redteam/engine.js';
import {
  DryRunTarget, HttpRedTeamTarget, McpRedTeamTarget, ScriptRedTeamTarget,
} from '../../core/src/redteam/targets.js';
import { SEED_ATTACKS, seedGraph } from '../../core/src/intel/seed.js';
import { fingerprintBehavior } from '../../core/src/sandbox/fingerprint.js';
import { runSandbox } from '../../core/src/sandbox/runner.js';

const VERSION = '0.1.0';
/** Repository root, resolved from this module so `--import`-style shims work. */
/**
 * Repository root, resolved from this module.
 *
 * `main.ts` lives at `packages/cli/src/`, so the root is three levels up. Two
 * levels up lands on `packages/cli`, which silently produced paths like
 * `packages/packages/web` — worth being explicit about.
 */
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

const GLOBAL_OPTIONS: OptionSpec[] = [
  { name: 'help', short: 'h', type: 'boolean', description: 'Show help for the command' },
  { name: 'version', short: 'v', type: 'boolean', description: 'Print the Aegis version' },
  { name: 'format', short: 'f', type: 'string', description: 'Output format', placeholder: 'text|json|sarif|markdown|html|csv|jsonl', default: 'text' },
  { name: 'output', short: 'o', type: 'string', description: 'Write output to a file', placeholder: 'path' },
  { name: 'quiet', short: 'q', type: 'boolean', description: 'Suppress progress output', default: false },
  { name: 'no-color', type: 'boolean', description: 'Disable ANSI colour', default: false },
  { name: 'config', short: 'c', type: 'string', description: 'Path to aegis.config.json', placeholder: 'path' },
];

const SCAN_OPTIONS: OptionSpec[] = [
  { name: 'min-severity', type: 'string', description: 'Minimum severity to report', placeholder: 'critical|high|medium|low|info', default: 'low' },
  { name: 'rules', type: 'string', description: 'Extra rule pack files', placeholder: 'paths' },
  { name: 'rule-dir', type: 'string', description: 'Directory of rule packs', placeholder: 'path' },
  { name: 'limit', short: 'l', type: 'number', description: 'Max findings to print', placeholder: 'n' },
  { name: 'fail-on', type: 'string', description: 'Exit non-zero at or above this severity', placeholder: 'severity', default: 'high' },
  { name: 'no-connect', type: 'boolean', description: 'Do not connect to MCP servers', default: false },
  { name: 'no-spawn', type: 'boolean', description: 'Do not spawn MCP server processes', default: false },
  { name: 'include-processes', type: 'boolean', description: 'Discover running MCP servers', default: false },
  { name: 'exclude', type: 'string', description: 'Exclude MCP servers by name', placeholder: 'names' },
  { name: 'threat-model', type: 'boolean', description: 'Generate a threat model', default: true },
  { name: 'graph', type: 'boolean', description: 'Render the MCP supply chain graph as HTML', default: false },
  { name: 'baseline', type: 'boolean', description: 'Only report findings not in the baseline', default: false },
  { name: 'baseline-file', type: 'string', description: 'Baseline fingerprint file', placeholder: 'path' },
];

const REDTEAM_OPTIONS: OptionSpec[] = [
  { name: 'target', type: 'string', description: 'http:// URL, an MCP config path, or "dry-run"', placeholder: 'url|path' },
  { name: 'command', type: 'string', description: 'Local agent script to attack', placeholder: 'cmd' },
  { name: 'dry-run', type: 'boolean', description: 'Make no requests; use canned responses', default: false },
  { name: 'sandbox', type: 'boolean', description: 'Run attacks inside an isolated container', default: false },
  { name: 'attack', type: 'string', description: 'Specific attack ids', placeholder: 'ids' },
  { name: 'category', type: 'string', description: 'Attack categories', placeholder: 'names' },
  { name: 'population', type: 'number', description: 'Population size', placeholder: 'n', default: 12 },
  { name: 'generations', type: 'number', description: 'Generations to evolve', placeholder: 'n', default: 6 },
  { name: 'budget', type: 'number', description: 'Max target requests', placeholder: 'n', default: 200 },
  { name: 'seed', type: 'number', description: 'PRNG seed for reproducibility', placeholder: 'n', default: 1337 },
  { name: 'timeout', type: 'number', description: 'Per-request timeout (ms)', placeholder: 'ms', default: 30000 },
  { name: 'redact-prompts', type: 'boolean', description: 'Omit verbatim attack prompts', default: false },
  { name: 'header', type: 'string', description: 'Extra HTTP header (repeatable)', placeholder: 'k:v' },
];

const DESKTOP_OPTIONS: OptionSpec[] = [
  { name: 'port', type: 'string', description: 'Port for the dashboard', placeholder: 'port', default: '8080' },
  { name: 'host', type: 'string', description: 'Interface to bind', placeholder: 'host', default: '127.0.0.1' },
  { name: 'data', type: 'string', description: 'Directory of scan exports', placeholder: 'path', default: '.aegis/dashboard' },
  { name: 'browser', type: 'string', description: 'Force a browser for the window', placeholder: 'chrome|edge|system' },
  { name: 'no-open', type: 'boolean', description: 'Start the server without opening a window', default: false },
  { name: 'no-color', type: 'boolean', description: 'Disable ANSI colour', default: false },
];

const FIX_OPTIONS: OptionSpec[] = [
  ...SCAN_OPTIONS.filter((o) => ['no-connect', 'no-spawn', 'rule-dir', 'rules'].includes(o.name)),
  { name: 'apply', type: 'boolean', description: 'Write changes to disk', default: false },
  { name: 'rule', type: 'string', description: 'Only remediate these rules', placeholder: 'ids' },
  { name: 'max-severity', type: 'string', description: 'Highest severity to plan fixes for', placeholder: 'severity', default: 'low' },
  { name: 'branch', type: 'boolean', description: 'Create a git branch and commit', default: false },
  { name: 'pr', type: 'boolean', description: 'Open a pull request (requires GITHUB_TOKEN)', default: false },
];

const REPORT_OPTIONS: OptionSpec[] = [
  ...SCAN_OPTIONS.filter((o) => ['no-connect', 'no-spawn', 'rule-dir', 'rules', 'min-severity'].includes(o.name)),
  { name: 'compliance', type: 'boolean', description: 'Emit a compliance attestation', default: false },
  { name: 'organisation', type: 'string', description: 'Organisation name', placeholder: 'name' },
  { name: 'system', type: 'string', description: 'System name', placeholder: 'name' },
  { name: 'owner', type: 'string', description: 'Control owner', placeholder: 'name' },
  { name: 'framework', type: 'string', description: 'Frameworks to assess', placeholder: 'names' },
];

const SANDBOX_OPTIONS: OptionSpec[] = [
  { name: 'command', type: 'string', description: 'Command to run in the sandbox', placeholder: 'cmd' },
  { name: 'arg', type: 'string', description: 'Argument for the command (repeatable)', placeholder: 'value' },
  { name: 'cwd', type: 'string', description: 'Working directory for the command', placeholder: 'path' },
  { name: 'baseline', type: 'string', description: 'Baseline fingerprint to compare against', placeholder: 'path' },
  { name: 'shadow', type: 'boolean', description: 'Shadow mode: observe without acting', default: false },
  { name: 'timeout', type: 'number', description: 'Timeout (ms)', placeholder: 'ms', default: 60000 },
  { name: 'network', type: 'boolean', description: 'Record network calls', default: true },
  { name: 'max-bytes', type: 'number', description: 'Max recorded bytes per stream', placeholder: 'n', default: 1048576 },
];

const INTEL_OPTIONS: OptionSpec[] = [
  { name: 'exposure', type: 'boolean', description: 'Show exposure to known attacks', default: false },
  { name: 'capability', type: 'string', description: 'Declare a capability for exposure analysis', placeholder: 'names' },
  { name: 'technique', type: 'string', description: 'Explain a specific technique', placeholder: 'id' },
  { name: 'alerts', type: 'boolean', description: 'List alerts matching a target', default: false },
  { name: 'subscribe', type: 'string', description: 'Write an alert subscription', placeholder: 'path' },
  { name: 'watch', type: 'boolean', description: 'Poll feeds and report new techniques', default: false },
  { name: 'offline', type: 'boolean', description: 'Use only the bundled graph', default: false },
];

const DEPS_OPTIONS: OptionSpec[] = [
  { name: 'package', type: 'string', description: 'Check one package: name@version', placeholder: 'pkg@1.2.3' },
  { name: 'manifest', type: 'string', description: 'Read dependencies from a manifest', placeholder: 'path' },
  { name: 'ecosystem', type: 'string', description: 'npm | pypi | go', default: 'npm' },
  { name: 'timeout', type: 'number', description: 'Per-request timeout (ms)', placeholder: 'ms', default: 15000 },
  { name: 'no-color', type: 'boolean', description: 'Disable ANSI colour', default: false },
  { name: 'quiet', short: 'q', type: 'boolean', description: 'Suppress progress output', default: false },
];

const COMMANDS: Record<string, { summary: string; options: OptionSpec[]; run: (args: ParsedArgs) => Promise<number> }> = {
  scan: { summary: 'Scan MCP servers, agent code and repositories', options: SCAN_OPTIONS, run: cmdScan },
  redteam: { summary: 'Evolutionary red team an agent', options: REDTEAM_OPTIONS, run: cmdRedTeam },
  sandbox: { summary: 'Run an agent under behavioural observation', options: SANDBOX_OPTIONS, run: cmdSandbox },
  desktop: { summary: 'Open the dashboard as a desktop application', options: DESKTOP_OPTIONS, run: cmdDesktop },
  fix: { summary: 'Generate and optionally apply remediations', options: FIX_OPTIONS, run: cmdFix },
  report: { summary: 'Generate a compliance attestation', options: REPORT_OPTIONS, run: cmdReport },
  intel: { summary: 'Query the living attack graph', options: INTEL_OPTIONS, run: cmdIntel },
  deps: { summary: 'Check dependencies for known vulnerabilities (OSV)', options: DEPS_OPTIONS, run: cmdDeps },
};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export async function main(argv: readonly string[]): Promise<number> {
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h' || argv[0] === 'help') {
    printHelp();
    return 0;
  }
  if (argv[0] === '--version' || argv[0] === '-v' || argv[0] === 'version') {
    process.stdout.write(`aegis ${VERSION}\n`);
    return 0;
  }

  const commandName = argv[0]!;
  const command = COMMANDS[commandName];
  if (!command) {
    process.stderr.write(`aegis: unknown command "${commandName}"\n\n`);
    printHelp(process.stderr);
    return 2;
  }

  const specs = [...GLOBAL_OPTIONS, ...command.options];
  try {
    const parsed = parseArgs(argv.slice(1), specs);
    if (getBoolean(parsed, 'help')) {
      printCommandHelp(commandName, command, specs);
      return 0;
    }
    if (getBoolean(parsed, 'version')) {
      process.stdout.write(`aegis ${VERSION}\n`);
      return 0;
    }
    return await command.run(parsed);
  } catch (error) {
    if (error instanceof ParseError) {
      process.stderr.write(`aegis ${commandName}: ${error.message}\n`);
      process.stderr.write(`Run "aegis ${commandName} --help" for usage.\n`);
      return 2;
    }
    process.stderr.write(`aegis ${commandName}: ${(error as Error).message}\n`);
    if (process.env['AEGIS_DEBUG']) {
      process.stderr.write(`${(error as Error).stack}\n`);
    }
    return 1;
  }
}

function printHelp(stream: NodeJS.WriteStream = process.stdout): void {
  stream.write(`aegis ${VERSION} — the security platform for AI agents\n\n`);
  stream.write('USAGE\n');
  stream.write('  aegis <command> [options]\n\n');
  stream.write('COMMANDS\n');
  const width = Math.max(...Object.keys(COMMANDS).map((c) => c.length));
  for (const [name, command] of Object.entries(COMMANDS)) {
    stream.write(`  ${name.padEnd(width + 2)}${command.summary}\n`);
  }
  stream.write('\nRun "aegis <command> --help" for command options.\n');
  stream.write(`\nDocs: ${'https://aegis.dev/docs'}\n`);
}

function printCommandHelp(name: string, command: { summary: string; options: OptionSpec[] }, specs: OptionSpec[]): void {
  process.stdout.write(`aegis ${name} — ${command.summary}\n\n`);
  process.stdout.write(`USAGE\n  aegis ${name}${name === 'intel' ? '' : ' [target]'} [options]\n\n`);
  process.stdout.write('OPTIONS\n');
  process.stdout.write(renderOptions(specs) + '\n');
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

async function cmdScan(args: ParsedArgs): Promise<number> {
  const logger = makeLogger(args);
  const targetPath = args.positionals[0] ?? '.';
  const startedAt = new Date().toISOString();
  const started = Date.now();

  const ruleFiles = getStringList(args, 'rules');
  const ruleDir = getString(args, 'rule-dir');

  // An explicit `--rules` or `--rule-dir` replaces the shipped packs. With
    // An explicit `--rules` or `--rule-dir` replaces the shipped packs. With
  // neither, the default search runs — passing an empty `files` array here
  // silently selected the "explicit files" branch and loaded nothing at all.
  const ruleOptions = {
    ...(ruleFiles.length > 0
      ? { files: ruleFiles.map((f: string) => resolve(f)) }
      : ruleDir
        ? { directories: [resolve(ruleDir)] }
        : {}),
    logger,
  };
  const loaded = await loadRulePacks(ruleOptions);

  if (loaded.packs.length === 0) {
    process.stderr.write(
      'aegis scan: no rule packs loaded — this scan would report nothing. ' +
        'Check --rules/--rule-dir, or run from inside the repository.\n',
    );
    return 2;
  }

  if (loaded.errors.length > 0) {
    for (const error of loaded.errors) logger.warn(error);
  }
  logger.info(
    `loaded ${loaded.packs.length} rule pack(s), ${loaded.rules.size} rule(s)`,
  );

  const registry = new PluginRegistry({ logger });
  registry.setRuleSet(loaded.rules);

  const minSeverity = toSeverity(getString(args, 'min-severity', 'low'));
  const findings: Finding[] = [];
  const errors: string[] = [];
  const artifacts: Record<string, unknown> = {};
  const targetType: ScanTargetType = inferTargetType(targetPath);

  // Agent / repository scan.
  const agentScanner = new AgentScanner({ rules: loaded.rules });
  const ctx = {
    root: resolve(targetPath),
    registry,
    logger,
    options: {},
  };

  const report = await agentScanner.scanToReport({ type: 'agent', path: resolve(targetPath) }, ctx);
  findings.push(...report.findings);
  artifacts['frameworks'] = report.frameworks;
  if (report.threatModel) {
    artifacts['threatModel'] = report.threatModel.markdown;
    artifacts['threatModelMermaid'] = report.threatModel.mermaid;
  }

  // MCP scan, when a config is present or discovery finds servers.
  const mcpScanner = new McpScanner({
    connect: !getBoolean(args, 'no-connect'),
    includeProcesses: getBoolean(args, 'include-processes'),
    noSpawn: getBoolean(args, 'no-spawn'),
    ...(getStringList(args, 'exclude').length
      ? { exclude: getStringList(args, 'exclude') }
      : {}),
  });

  const mcpConfig = findMcpConfig(targetPath);
  if (mcpConfig) {
    const mcpReport = await mcpScanner.scanToReport({ type: 'mcp', path: mcpConfig }, {
      ...ctx,
      root: resolve(mcpConfig),
    });
    findings.push(...mcpReport.findings);
    errors.push(...mcpReport.errors);
    artifacts['supplyChainGraph'] = graphToD3(mcpReport.graph);
    artifacts['supplyChainMermaid'] = graphToMermaid(mcpReport.graph);
    artifacts['mcpStats'] = mcpReport.graph.stats;
    artifacts['mcpScore'] = mcpReport.serverScores;
  } else {
    logger.info('no MCP configuration found; skipping the MCP scanner');
  }

  // Baseline filtering.
  let finalFindings = sortFindings(dedupeFindings(findings));
  if (getBoolean(args, 'baseline')) {
    const baselineFile = getString(args, 'baseline-file') ?? '.aegis/baseline.json';
    const baseline = await readBaseline(baselineFile);
    const before = finalFindings.length;
    finalFindings = finalFindings.filter((f) => !baseline.has(f.fingerprint ?? f.id));
    logger.info(`baseline filtered out ${before - finalFindings.length} known finding(s)`);
  }

  const filtered = finalFindings.filter(
    (f) => severityRank(f.severity) <= severityRank(minSeverity),
  );

  const doc = buildDocument({
    target: { type: targetType, path: targetPath },
    findings: filtered,
    score: computeScore({ findings: finalFindings }),
    durationMs: Date.now() - started,
    startedAt,
    artifacts,
    errors,
    rulePacks: loaded.packs.map((p) => ({
      id: p.id,
      version: p.version,
      ruleCount: p.rules.length,
    })),
  });

  await emit(doc, args);

  if (getBoolean(args, 'graph') && artifacts['supplyChainGraph']) {
    await writeArtifact('aegis-supply-chain.html', renderGraphHtml(mcpGraphForHtml(artifacts)), args);
  }

  const failOn = getString(args, 'fail-on', 'high');
  const blocking = filtered.filter((f) => severityRank(f.severity) <= severityRank(toSeverity(failOn)));
  return blocking.length > 0 ? 1 : 0;
}

function inferTargetType(path: string): ScanTargetType {
  if (/mcp\.json$/i.test(path)) return 'mcp';
  return 'agent';
}

/**
 * Locate an MCP config for a target.
 *
 * Existence is checked, not just the filename: the candidate list puts
 * `.mcp.json` before `mcp.json`, so returning the first *regex* match handed the
 * scanner a path that does not exist and the whole MCP pass silently reported
 * zero servers.
 */
function findMcpConfig(path: string): string | null {
  // A path that is itself a config file.
  if (/mcp\.json$/i.test(path)) {
    const direct = resolve(path);
    if (existsSync(direct)) return path;
  }

  const candidates = [
    join(path, '.mcp.json'),
    join(path, 'mcp.json'),
    join(path, '.cursor', 'mcp.json'),
    join(path, '.mcp', 'config.json'),
  ];
  for (const candidate of candidates) {
    if (existsSync(resolve(candidate))) return candidate;
  }
  return null;
}

function mcpGraphForHtml(artifacts: Record<string, unknown>): Parameters<typeof renderGraphHtml>[0] {
  // Rebuild the graph shape the renderer expects from the D3 payload the
  // scanner already produced, so no second scan is needed.
  const d3 = artifacts['supplyChainGraph'] as
    | { nodes: unknown[]; links: unknown[]; stats: Record<string, unknown> }
    | undefined;
  const stats = (d3?.stats ?? {}) as Record<string, unknown>;
  return {
    nodes: (d3?.nodes ?? []) as never,
    edges: (d3?.links ?? []) as never,
    servers: {},
    stats: {
      serverCount: numberOr(stats['serverCount']),
      toolCount: numberOr(stats['toolCount']),
      resourceCount: numberOr(stats['resourceCount']),
      promptCount: numberOr(stats['promptCount']),
      edgeCount: numberOr(stats['edgeCount']),
      exfiltrationPaths: (stats['exfiltrationPaths'] as string[][] | undefined) ?? [],
      maxDepth: numberOr(stats['maxDepth']),
      exposedServers: (stats['exposedServers'] as string[] | undefined) ?? [],
    },
  };
}

function numberOr(value: unknown): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

// ---------------------------------------------------------------------------
// redteam
// ---------------------------------------------------------------------------

async function cmdRedTeam(args: ParsedArgs): Promise<number> {
  const logger = makeLogger(args);
  const dryRun = getBoolean(args, 'dry-run');
  const targetSpec = getString(args, 'target') ?? args.positionals[0];

  if (!targetSpec && !dryRun) {
    process.stderr.write(
      'aegis redteam: --target is required (an http:// URL, an MCP config path, or a local script with --command).\n' +
      '  For a run that makes no requests, pass --dry-run.\n',
    );
    return 2;
  }

  const headers: Record<string, string> = {};
  for (const header of getStringList(args, 'header')) {
    const idx = header.indexOf(':');
    if (idx === -1) continue;
    headers[header.slice(0, idx).trim()] = header.slice(idx + 1).trim();
  }

  let target;
  if (dryRun) {
    target = new DryRunTarget({ defaultResponse: "I can't help with that." });
  } else if (getString(args, 'command')) {
    target = new ScriptRedTeamTarget({
      command: getString(args, 'command')!,
      timeoutMs: getNumber(args, 'timeout', 30000),
      capabilities: ['network', 'filesystem', 'shell', 'code-execution'],
    });
  } else if (/^https?:\/\//i.test(targetSpec)) {
    target = new HttpRedTeamTarget({
      url: targetSpec,
      headers,
      timeoutMs: getNumber(args, 'timeout', 30000),
    });
  } else {
    // Treat as an MCP configuration path.
    const servers = await discoverFromConfig(resolve(targetSpec));
    if (servers.length === 0) {
      process.stderr.write(`aegis redteam: no MCP servers found in ${targetSpec}\n`);
      return 2;
    }
    target = await McpRedTeamTarget.create(servers[0]!, { timeoutMs: getNumber(args, 'timeout', 30000) });
  }

  const attackIds = getStringList(args, 'attack');
  const categories = getStringList(args, 'category');

  const run = await runRedTeam(target, {
    populationSize: getNumber(args, 'population', 12),
    generations: getNumber(args, 'generations', 6),
    maxEvaluations: getNumber(args, 'budget', 200),
    seed: getNumber(args, 'seed', 1337),
    ...(attackIds.length ? { attackIds } : {}),
    ...(categories.length ? { categories: categories as never } : {}),
    ...(getBoolean(args, 'redact-prompts') ? { redactPrompts: true } : {}),
    dryRun,
    logger,
    onProgress: (p) => {
      if (getBoolean(args, 'quiet')) return;
      const status = p.succeeded ? 'BYPASS' : 'held  ';
      logger.info(
        `[${String(p.evaluation).padStart(4)}/${p.maxEvaluations}] ${status} ${p.category}`,
      );
    },
  });

  await emitRedTeam(run.report, args);
  await target.close();

  const asr = run.report.summary.attackSuccessRate;
  // ASR is the signal that matters; anything above 10% warrants attention.
  return asr > 0.1 ? 1 : 0;
}

async function emitRedTeam(report: unknown, args: ParsedArgs): Promise<void> {
  const format = (getString(args, 'format', 'text') ?? 'text') as OutputFormat;
  const text =
    format === 'json' || format === 'jsonl' || format === 'sarif'
      ? JSON.stringify({ redTeam: report }, null, 2)
      : format === 'markdown'
        ? redTeamMarkdown(report as never)
        : format === 'html'
          ? `<pre>${escapeHtml(JSON.stringify(report, null, 2))}</pre>`
          : redTeamText(report as never);

  const out = getString(args, 'output');
  if (out) {
    const { writeFile, mkdir } = await import('node:fs/promises');
    await mkdir(resolve(out, '..'), { recursive: true }).catch(() => {});
    await writeFile(resolve(out), text, 'utf8');
    if (!getBoolean(args, 'quiet')) process.stderr.write(`wrote ${out}\n`);
  } else {
    process.stdout.write(text.endsWith('\n') ? text : `${text}\n`);
  }
}

function redTeamText(report: {
  target: { name: string };
  summary: { attacksRun: number; successfulBypasses: number; attackSuccessRate: number; overallRisk: string; verdict: string; resistantTo: string[] };
  byCategory: Array<{ category: string; attacks: number; succeeded: number; attackSuccessRate: number }>;
  successfulBypasses: Array<{ attackId: string; prompt: string; response: string; remediation: string }>;
  evolution: { generations: number; bestFitness: number; stopReason: string; seed: number };
  recommendations: Array<{ priority: string; title: string; detail: string }>;
  compliance: { requiresIncidentResponse: boolean; notes: string[] };
  findings: Array<{ severity: string; title: string }>;
}): string {
  const lines: string[] = [];
  lines.push('');
  lines.push(`Red team report — ${report.target.name}`);
  lines.push('');
  lines.push(`  Attacks run     ${report.summary.attacksRun}`);
  lines.push(`  Successful      ${report.summary.successfulBypasses}`);
  lines.push(`  Attack success rate ${(report.summary.attackSuccessRate * 100).toFixed(1)}%`);
  lines.push(`  Risk            ${report.summary.overallRisk.toUpperCase()}`);
  lines.push('');
  lines.push(`  ${report.summary.verdict}`);
  lines.push('');

  lines.push('  By category');
  for (const category of report.byCategory) {
    const bar = category.attackSuccessRate > 0 ? '!' : ' ';
    lines.push(
      `   ${bar} ${category.category.padEnd(20)} ${String(category.succeeded).padStart(3)}/${String(category.attacks).padEnd(3)}  ${(category.attackSuccessRate * 100).toFixed(0)}%`,
    );
  }
  lines.push('');

  if (report.successfulBypasses.length > 0) {
    lines.push('  Reproduced bypasses');
    for (const bypass of report.successfulBypasses.slice(0, 5)) {
      lines.push(`   - ${bypass.attackId}`);
      lines.push(`     prompt: ${bypass.prompt.slice(0, 120)}`);
      lines.push(`     fix   : ${bypass.remediation.slice(0, 120)}`);
    }
    lines.push('');
  }

  lines.push(
    `  Evolution: ${report.evolution.generations} generation(s), best fitness ${report.evolution.bestFitness}, ` +
      `stopped on ${report.evolution.stopReason}, seed ${report.evolution.seed}`,
  );
  lines.push('');

  if (report.compliance.requiresIncidentResponse) {
    lines.push('  *** INCIDENT RESPONSE INDICATED ***');
    for (const note of report.compliance.notes) lines.push(`      ${note}`);
    lines.push('');
  }

  if (report.recommendations.length > 0) {
    lines.push('  Recommendations');
    for (const rec of report.recommendations.slice(0, 5)) {
      lines.push(`   [${rec.priority}] ${rec.title}`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

function redTeamMarkdown(report: {
  target: { name: string };
  summary: { attacksRun: number; successfulBypasses: number; attackSuccessRate: number; overallRisk: string; verdict: string };
  byCategory: Array<{ category: string; attacks: number; succeeded: number; attackSuccessRate: number }>;
  successfulBypasses: Array<{ attackId: string; category: string; prompt: string; response: string; remediation: string }>;
  evolution: { generations: number; bestFitness: number; seed: number };
  recommendations: Array<{ priority: string; title: string; detail: string }>;
  promptsIncluded: boolean;
}): string {
  const lines: string[] = [];
  lines.push(`# Red Team Report — ${report.target.name}`, '');
  lines.push(`**Attacks run:** ${report.summary.attacksRun}  `);
  lines.push(`**Successful bypasses:** ${report.summary.successfulBypasses}  `);
  lines.push(`**Attack success rate:** ${(report.summary.attackSuccessRate * 100).toFixed(1)}%  `);
  lines.push(`**Risk:** ${report.summary.overallRisk.toUpperCase()}`, '');
  lines.push(report.summary.verdict, '');
  lines.push('## By category', '');
  lines.push('| Category | Attacks | Succeeded | Rate |');
  lines.push('| --- | --- | --- | --- |');
  for (const c of report.byCategory) {
    lines.push(`| ${c.category} | ${c.attacks} | ${c.succeeded} | ${(c.attackSuccessRate * 100).toFixed(0)}% |`);
  }
  lines.push('');
  if (report.successfulBypasses.length > 0) {
    lines.push('## Reproduced bypasses', '');
    for (const b of report.successfulBypasses) {
      lines.push(`### ${b.attackId} (${b.category})`, '');
      if (report.promptsIncluded) {
        lines.push('```', b.prompt.slice(0, 500), '```', '');
        lines.push('Response:', '', '```', b.response.slice(0, 800), '```', '');
      }
      lines.push(`**Remediation:** ${b.remediation}`, '');
    }
  }
  lines.push('## Recommendations', '');
  for (const r of report.recommendations) {
    lines.push(`- **[${r.priority}]** ${r.title} — ${r.detail}`);
  }
  lines.push('', '---', '', '_Generated by Aegis. Reproduce with the recorded seed._');
  return lines.join('\n');
}

async function discoverFromConfig(path: string): Promise<DiscoveredMcpServer[]> {
  const { discoverMcpServers } = await import('../../core/src/scanners/mcp/discovery.js');
  const result = await discoverMcpServers({ explicitPaths: [path] });
  return result.servers;
}

// ---------------------------------------------------------------------------
// sandbox
// ---------------------------------------------------------------------------

async function cmdSandbox(args: ParsedArgs): Promise<number> {
  const logger = makeLogger(args);
  const command = getString(args, 'command') ?? args.positionals[0];
  // Extra positionals after the command are the command's own arguments; the
  // sandbox spawns the process directly, so they must be forwarded as args or
  // the agent never runs.
  const rest = command === args.positionals[0] ? args.positionals.slice(1) : args.positionals;
  if (!command) {
    process.stderr.write('aegis sandbox: --command is required\n');
    return 2;
  }
  const cwd = getString(args, 'cwd') ?? (rest.length > 1 ? rest[rest.length - 1] : process.cwd());
  const commandArgs = getStringList(args, 'arg').concat(rest.length > 1 ? rest.slice(0, -1) : rest);

  const result = await runSandbox({
    command,
    args: commandArgs,
    cwd,
    shadow: getBoolean(args, 'shadow'),
    timeoutMs: getNumber(args, 'timeout', 60000),
    maxRecordedBytes: getNumber(args, 'max-bytes', 1024 * 1024),
    logger,
  });

  const fingerprint = fingerprintBehavior(result.events);
  const anomalies = result.anomalies;

  const doc = buildDocument({
    target: { type: 'runtime', path: args.positionals[1] ?? process.cwd() },
    findings: [...anomalies, ...result.findings],
    score: computeScore({ findings: [...anomalies, ...result.findings] }),
    durationMs: result.durationMs,
    artifacts: { fingerprint, exitCode: result.exitCode, events: result.eventCount },
  });
  doc.artifacts!['fingerprint'] = fingerprint;
  await emit(doc, args);

  return anomalies.some((a) => a.severity === 'critical' || a.severity === 'high') ? 1 : 0;
}

// ---------------------------------------------------------------------------
// desktop
// ---------------------------------------------------------------------------

async function cmdDesktop(args: ParsedArgs): Promise<number> {
  const { launchDesktop } = (await import(
    pathToFileURL(join(ROOT, 'packages', 'web', 'src', 'desktop.ts')).href
  )) as typeof import('../../web/src/desktop.js');

  const port = Number(getString(args, 'port', '8080'));
  const dataDir = resolve(getString(args, 'data', join(process.cwd(), '.aegis', 'dashboard'))!);
  const token = process.env['AEGIS_DASHBOARD_TOKEN'];

  if (!getBoolean(args, 'no-open')) {
    process.stdout.write('\n  Aegis — starting\n');
  }

  const { launch } = await launchDesktop({
    dataDir,
    port,
    ...(token ? { token } : {}),
    ...(getString(args, 'host') ? { host: getString(args, 'host')! } : {}),
    ...(getString(args, 'browser') ? { browser: getString(args, 'browser') as never } : {}),
    open: !getBoolean(args, 'no-open'),
  });

  const note = {
    'app-window': `application window via ${launch.browser}`,
    browser: 'your default browser (no app-mode browser found)',
    headless: 'no window opened',
  }[launch.mode];

  process.stdout.write(`  ${launch.url}\n  ${note}\n`);
  if (!token) {
    process.stdout.write('  no AEGIS_DASHBOARD_TOKEN set — bound to loopback only\n');
  }
  process.stdout.write('\n  Close the window (or press Ctrl+C) to stop.\n\n');

  if (!getBoolean(args, 'no-open') && launch.mode !== 'headless') {
    // Hold the process open: otherwise the dashboard dies with the script and
    // the window the user just opened turns into a connection error.
    await new Promise<void>((resolvePromise) => {
      const stop = (): void => {
        process.stdout.write('\n  Aegis stopped.\n');
        resolvePromise();
      };
      process.on('SIGINT', stop);
      process.on('SIGTERM', stop);
    });
  }
  return 0;
}

// ---------------------------------------------------------------------------
// deps — dependency vulnerability lookup
// ---------------------------------------------------------------------------

async function cmdDeps(args: ParsedArgs): Promise<number> {
  const { checkDependencies, dependencyFindings } = (await import(
    pathToFileURL(join(ROOT, 'packages', 'intel-feeds', 'src', 'clients.ts')).href
  )) as typeof import('../../intel-feeds/src/clients.js');

  const ecosystem = (getString(args, 'ecosystem', 'npm') ?? 'npm') as 'npm' | 'pypi' | 'go';

  // Collect the dependency set: an explicit --package, or a manifest's contents.
  const specs: Array<{ name: string; version?: string; ecosystem: 'npm' | 'pypi' | 'go' }> = [];
  const single = getString(args, 'package');
  if (single) {
    const at = single.lastIndexOf('@');
    if (at > 0) {
      specs.push({ name: single.slice(0, at), version: single.slice(at + 1), ecosystem });
    } else {
      specs.push({ name: single, ecosystem });
    }
  }
  const manifest = getString(args, 'manifest');
  if (manifest) {
    specs.push(...(await readManifest(resolve(manifest), ecosystem)));
  }

  if (specs.length === 0) {
    process.stderr.write(
      'aegis deps: nothing to check. Pass --package name@version, or --manifest package.json.\n',
    );
    return 2;
  }

  if (!getBoolean(args, 'quiet')) {
    process.stderr.write(`Checking ${specs.length} dependency/dependencies against OSV…\n`);
  }

  const checks = await checkDependencies(specs, { timeoutMs: getNumber(args, 'timeout', 15000) });
  const vulns = dependencyFindings(checks);

  const format = (getString(args, 'format', 'text') ?? 'text') as OutputFormat;
  if (format === 'json' || format === 'jsonl') {
    process.stdout.write(JSON.stringify({ checked: specs.length, vulnerable: vulns.length, findings: vulns }, null, 2) + '\n');
  } else if (format === 'markdown' || format === 'html') {
    const lines = [`# Dependency vulnerabilities\n\nChecked ${specs.length}, ${vulns.length} vulnerable.\n`];
    for (const v of vulns) {
      lines.push(`- **${v.name}@${v.version ?? '?'}** — ${v.vulnId} (${v.severity})${v.fixedIn ? ` · fix: ${v.fixedIn}` : ''}\n  ${v.summary}\n`);
    }
    process.stdout.write(lines.join('\n'));
  } else {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const v of vulns) c[v.severity as keyof typeof c] = (c[v.severity as keyof typeof c] ?? 0) + 1;
    process.stdout.write(
      `\n  ${specs.length} dependency/dependencies checked against OSV\n` +
        (vulns.length === 0
          ? `  ${getBoolean(args, 'no-color') ? '' : ''}✓ No known vulnerabilities\n\n`
          : `  ${c.critical} critical  ${c.high} high  ${c.medium} medium  ${c.low} low\n\n` +
            vulns.map((v) => `  ${v.severity.toUpperCase().padEnd(8)} ${v.name}@${v.version ?? '?'}\n           ${v.vulnId}${v.fixedIn ? `  → upgrade to ${v.fixedIn}` : ''}`).join('\n') +
            '\n'),
    );
  }

  return vulns.some((v) => v.severity === 'critical' || v.severity === 'high') ? 1 : 0;
}

/** Read declared dependencies from a package.json or requirements.txt. */
async function readManifest(
  path: string,
  ecosystem: 'npm' | 'pypi' | 'go',
): Promise<Array<{ name: string; version?: string; ecosystem: 'npm' | 'pypi' | 'go' }>> {
  try {
    const content = await readFile(path, 'utf8');
    if (path.endsWith('package.json')) {
      const pkg = JSON.parse(content) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      const merged = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
      return Object.entries(merged)
        .filter(([, v]) => !v.startsWith('file:') && !v.startsWith('workspace:'))
        // OSV needs an exact version; a range is not a resolvable answer.
        .filter(([, v]) => /^\d+\.\d+\.\d+/.test(v))
        .map(([name, version]) => ({ name, version, ecosystem: 'npm' as const }));
    }
    // requirements.txt: name==version
    return content
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#') && l.includes('=='))
      .map((l) => {
        const [name, version] = l.split('==');
        return { name: name!.trim(), version: version!.trim(), ecosystem: 'pypi' as const };
      });
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// fix
// ---------------------------------------------------------------------------

async function cmdFix(args: ParsedArgs): Promise<number> {
  const logger = makeLogger(args);
  const targetPath = resolve(args.positionals[0] ?? '.');

  // Re-scan to get fresh findings, then plan against them.
  const loaded = await loadRulePacks({ logger });
  const scanner = new AgentScanner({ rules: loaded.rules });
  const report = await scanner.scanToReport({ type: 'agent', path: targetPath }, {
    root: targetPath,
    registry: new PluginRegistry({ logger }),
    logger,
    options: {},
  });

  const sources = await readSources(targetPath);
  const plan = buildRemediationPlan(report.findings, {
    sources,
    ...(getStringList(args, 'rule').length ? { ruleIds: getStringList(args, 'rule') } : {}),
    maxSeverity: toSeverity(getString(args, 'max-severity', 'critical')),
  });

  const apply = getBoolean(args, 'apply');
  if (apply) {
    const { applyRemediation } = await import('../../core/src/remediation.js');
    for (const remediation of plan.autoApplicable) {
      const result = await applyRemediation(remediation, { dryRun: false, cwd: targetPath });
      logger.info(
        result.applied
          ? `applied ${remediation.ruleId} to ${remediation.file}`
          : `skipped ${remediation.ruleId}: ${result.reason}`,
      );
    }
  }

  const format = getString(args, 'format', 'text') ?? 'text';
  if (format === 'json') {
    process.stdout.write(JSON.stringify(plan, null, 2) + '\n');
  } else {
    process.stdout.write(renderFixPlan(plan, apply));
  }

  return plan.autoApplicable.length > 0 && apply ? 0 : 0;
}

function renderFixPlan(plan: ReturnType<typeof buildRemediationPlan>, apply: boolean): string {
  const lines: string[] = [];
  lines.push('');
  lines.push('Remediation plan');
  lines.push('');
  lines.push(
    `  ${plan.stats.total} finding(s): ${plan.stats.auto} automatic, ${plan.stats.proposed} proposed, ${plan.stats.manual} manual`,
  );
  lines.push(`  Estimated effort: ${plan.stats.estimatedMinutes} minutes`);
  lines.push('');

  if (plan.autoApplicable.length > 0) {
    lines.push('  Automatic fixes');
    for (const fix of plan.autoApplicable) {
      lines.push(`   ${fix.ruleId}  ${fix.title}`);
      lines.push(`     file: ${fix.file}`);
      if (fix.diff) {
        for (const line of fix.diff.split('\n').slice(0, 8)) lines.push(`     ${line}`);
      }
      for (const risk of fix.risks.slice(0, 2)) lines.push(`     ! ${risk}`);
      lines.push('');
    }
  }
  if (plan.proposals.length > 0) {
    lines.push('  Proposed (need a human decision)');
    for (const fix of plan.proposals.slice(0, 10)) {
      lines.push(`   ${fix.ruleId}  ${fix.title}`);
      lines.push(`     ${fix.rationale.slice(0, 110)}`);
    }
    lines.push('');
  }
  if (!apply && plan.autoApplicable.length > 0) {
    lines.push('  Run with --apply to write the automatic fixes.');
    lines.push('');
  }
  return lines.join('\n');
}

/**
 * Read every scannable file under `root`, keyed by the same path form the
 * scanner reports in `finding.location.file`.
 *
 * The key must match exactly or no remediation will find its target source and
 * every plan degrades to "manual" — which is what happened before this was
 * aligned with `walkFiles`' relative output.
 */
async function readSources(root: string): Promise<Map<string, string>> {
  const { walkFiles } = await import('../../core/src/walk.js');
  const sources = new Map<string, string>();

  const files = await walkFiles({ root, maxFiles: 5000 });
  for (const file of files) {
    try {
      sources.set(file.path, await readFile(file.absolutePath, 'utf8'));
    } catch {
      // Binary or unreadable; the scanner will have skipped it too.
    }
  }

  // Also key by the absolute path and by a normalised form, because a finding
  // may carry whichever the scanner produced.
  for (const file of files) {
    const content = sources.get(file.path);
    if (content === undefined) continue;
    sources.set(resolve(root, file.path), content);
    sources.set(file.path.replace(/\\/g, '/'), content);
  }

  return sources;
}

function relativeTo(root: string, path: string): string {
  return path.startsWith(root) ? path.slice(root.length).replace(/^[\\/]/, '') : path;
}

// ---------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------

async function cmdReport(args: ParsedArgs): Promise<number> {
  const targetPath = args.positionals[0] ?? '.';
  // Reuse the scan pipeline to gather findings.
  const doc = await scanForReport(targetPath, args);

  const format = getString(args, 'format', 'markdown') ?? 'markdown';
  const frameworks = getStringList(args, 'framework');

  if (getBoolean(args, 'compliance')) {
    const report = assessCompliance(doc.findings, {
      ...(frameworks.length ? { frameworks: frameworks as never } : {}),
      scope: doc.target,
    });
    const options = {
      organisation: getString(args, 'organisation') ?? 'Your Organisation',
      systemName: getString(args, 'system') ?? 'AI Agent System',
      ...(getString(args, 'owner') ? { owner: getString(args, 'owner')! } : {}),
      scope: doc.target,
    };
    const text =
      format === 'html' ? toAttestationHtml(report, options) : toAttestationMarkdown(report, options);
    await writeOutput(text, args, format === 'html' ? 'html' : 'md');
    return 0;
  }

  // Default to an executive summary plus the full technical report, which is what
  // most people want from `aegis report`. Any explicit format renders on its own.
  if (format === 'markdown') {
    const text = `${executiveSummary(doc)}\n\n---\n\n${render(doc, 'markdown', {})}`.replace(
      /\n---\n\n---+\n/g,
      '\n---\n',
    );
    await writeOutput(text, args, 'md');
    return 0;
  }

  await writeOutput(render(doc, format as OutputFormat, { color: false }), args, format);
  return 0;
}

async function scanForReport(targetPath: string, args?: ParsedArgs): Promise<AegisDocument> {
  const started = Date.now();
  const ruleFiles = args ? getStringList(args, 'rules') : [];
  const ruleDir = args ? getString(args, 'rule-dir') : undefined;
  const loaded = await loadRulePacks({
    ...(ruleFiles.length > 0 ? { files: ruleFiles.map((f) => resolve(f)) } : {}),
    ...(ruleDir ? { directories: [resolve(ruleDir)] } : {}),
    logger: silent,
  });
  const scanner = new AgentScanner({ rules: loaded.rules, threatModel: false });
  const report = await scanner.scanToReport({ type: 'agent', path: resolve(targetPath) }, {
    root: resolve(targetPath),
    registry: new PluginRegistry({ logger: silent }),
    logger: silent,
    options: {},
  });
  return buildDocument({
    target: { type: 'agent', path: targetPath },
    findings: report.findings,
    score: report.score,
    durationMs: Date.now() - started,
    rulePacks: loaded.packs.map((p) => ({ id: p.id, version: p.version, ruleCount: p.rules.length })),
  });
}

const silent = createLogger({ level: 'silent' });

// ---------------------------------------------------------------------------
// intel
// ---------------------------------------------------------------------------

async function cmdIntel(args: ParsedArgs): Promise<number> {
  const logger = makeLogger(args);
  const graph = seedGraph(SEED_ATTACKS);

  const techniqueId = getString(args, 'technique');
  if (techniqueId) {
    const node = [...graph.nodes.values()].find((n) => n.id === techniqueId || n.hash === techniqueId);
    if (!node) {
      process.stderr.write(`aegis intel: unknown technique "${techniqueId}"\n`);
      return 2;
    }
    process.stdout.write(JSON.stringify({ node, stats: computeStats(graph) }, null, 2) + '\n');
    return 0;
  }

  if (getBoolean(args, 'exposure')) {
    const capabilities = getStringList(args, 'capability');
    const stats = computeStats(graph);
    const techniques = [...graph.nodes.values()].filter((n) => n.kind === 'technique');
    process.stdout.write(
      renderExposure(graph, capabilities, stats.nodeCount, stats.edgeCount, techniques.length),
    );
    return 0;
  }

  if (getBoolean(args, 'alerts')) {
    const stats = computeStats(graph);
    process.stdout.write(
      [
        'Attack graph alerts',
        '',
        `  techniques        ${stats.nodeCount}`,
        `  edges             ${stats.edgeCount}`,
        `  critical          ${stats.bySeverity.critical ?? 0}`,
        `  unmitigated       ${stats.unmitigated.length}`,
        `  entry techniques  ${stats.orphans.length}`,
        '',
        `  longest chain     ${stats.criticalPath.length} step(s)`,
        '',
      ].join('\n'),
    );
    return 0;
  }

  const stats = computeStats(graph);

  if (getBoolean(args, 'watch') || getBoolean(args, 'exposure')) {
    // Pull live advisories and fold them into the graph. Every network call is
    // optional: `--offline` uses only the bundled graph and the local cache.
    const offline = getBoolean(args, 'offline');
    const { DEFAULT_SOURCES, fetchFeeds } = await import(
      pathToFileURL(join(ROOT, 'packages/intel-feeds/src/index.ts')).href
    ) as typeof import('../../intel-feeds/src/index.js');
    const { ingestFeed, summariseFeed } = await import(
      pathToFileURL(join(ROOT, 'packages/intel-feeds/src/ingest.ts')).href
    ) as typeof import('../../intel-feeds/src/ingest.js');

    logger.info(offline ? 'using cached advisories (offline)' : 'fetching advisories');
    const feed = await fetchFeeds(DEFAULT_SOURCES, {
      offline,
      cacheDir: '.aegis/intel-cache',
      onProgress: (source, status, detail) => {
        if (getBoolean(args, 'quiet')) return;
        logger.info(`${source.name}: ${status}${detail ? ` (${detail})` : ''}`);
      },
    });

    const ingest = ingestFeed(graph, feed.records, { agentRelevantOnly: true });
    const summary = summariseFeed(feed.records);
    const failed = feed.sources.filter((s) => !s.ok);

    process.stderr.write(
      `\n  ${summary.total} advisories, ${summary.agentRelevant} agent-relevant ` +
        `(${summary.critical} critical, ${summary.high} high)\n` +
        `  graph: +${ingest.added} nodes, +${ingest.edges} edges, ` +
        `${ingest.merged} merged, ${ingest.skipped} not agent-relevant\n`,
    );
    if (failed.length > 0) {
      process.stderr.write(
        `  ${failed.length} feed(s) unavailable: ${failed.map((f) => `${f.source.id} (${f.error})`).join(', ')}\n`,
      );
    }

    if (getBoolean(args, 'exposure')) {
      const capabilities = getStringList(args, 'capability');
      const exposed = [...graph.nodes.values()].filter((n) => n.kind === 'cve' || n.kind === 'technique');
      process.stdout.write(renderExposure(graph, capabilities, stats.nodeCount, stats.edgeCount, exposed.length));
      return 0;
    }
  }

  process.stdout.write(attackGraphToMermaid(graph, { maxNodes: 30 }) + '\n');
  process.stderr.write(
    `${computeStats(graph).nodeCount} nodes, ${computeStats(graph).edgeCount} edges, ` +
      `${computeStats(graph).unmitigated.length} unmitigated\n`,
  );
  return 0;
}

function renderExposure(
  graph: ReturnType<typeof seedGraph>,
  capabilities: string[],
  nodeCount: number,
  edgeCount: number,
  techniqueCount: number,
): string {
  const lines: string[] = [];
  lines.push('');
  lines.push('Attack graph exposure');
  lines.push('');
  lines.push(`  ${nodeCount} nodes · ${edgeCount} edges · ${techniqueCount} techniques`);
  lines.push('');
  if (capabilities.length === 0) {
    lines.push('  No capabilities declared; pass --capability to compute exposure.');
    lines.push('');
    return lines.join('\n');
  }
  lines.push(`  Declared capabilities: ${capabilities.join(', ')}`);
  lines.push('');
  const bySeverity: Record<string, number> = {};
  for (const n of graph.nodes.values()) {
    if (n.kind !== 'technique') continue;
    bySeverity[n.severity] = (bySeverity[n.severity] ?? 0) + 1;
  }
  for (const [sev, count] of Object.entries(bySeverity)) {
    lines.push(`   ${sev.padEnd(10)} ${count}`);
  }
  lines.push('');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

async function emit(doc: AegisDocument, args: ParsedArgs): Promise<void> {
  const format = (getString(args, 'format', 'text') ?? 'text') as OutputFormat;
  const text = render(doc, format, {
    color: !getBoolean(args, 'no-color'),
    ...(getNumber(args, 'limit') !== undefined ? { limit: getNumber(args, 'limit')! } : {}),
  });
  await writeOutput(text, args, format);
}

async function writeOutput(text: string, args: ParsedArgs, format: string): Promise<void> {
  const out = getString(args, 'output');
  if (out) {
    await writeArtifact(out, text, args);
    return;
  }
  const data = text.endsWith('\n') ? text : `${text}\n`;
  if (format === 'text' && getBoolean(args, 'quiet')) {
    // Quiet text output is still meaningful: emit only the summary.
    process.stdout.write(data.split('\n').filter((l) => l.includes('Score')).join('\n') + '\n');
    return;
  }
  process.stdout.write(data);
}

async function writeArtifact(path: string, content: string, args: ParsedArgs): Promise<void> {
  const { mkdir, writeFile } = await import('node:fs/promises');
  const target = resolve(path);
  await mkdir(resolve(target, '..'), { recursive: true }).catch(() => {});
  await writeFile(target, content, 'utf8');
  if (!getBoolean(args, 'quiet')) process.stderr.write(`wrote ${target}\n`);
}

async function readBaseline(path: string): Promise<Set<string>> {
  try {
    const parsed = JSON.parse(await readFile(resolve(path), 'utf8')) as { fingerprints?: string[] };
    return new Set(parsed.fingerprints ?? []);
  } catch {
    return new Set();
  }
}

function makeLogger(args: ParsedArgs): Logger {
  return createLogger({
    level: getBoolean(args, 'quiet') ? 'silent' : 'warn',
    name: 'aegis',
  });
}

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
function severityRank(severity: Severity): number {
  return RANK[severity] ?? RANK.info;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]!);
}

export { VERSION };