import { existsSync, readFileSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { McpConfigHint } from '../../types.js';
import { parseJsonLoose } from '../../walk.js';

const execFileAsync = promisify(execFile);

export type McpConfigSourceKind =
  | 'claude-desktop'
  | 'claude-project'
  | 'cursor'
  | 'windsurf'
  | 'vscode'
  | 'vscode-insiders'
  | 'zed'
  | 'generic'
  | 'process'
  | 'explicit';

export interface McpConfigLocation {
  /** Absolute path, or a synthetic id for process-discovered servers. */
  path: string;
  kind: McpConfigSourceKind;
  /** Human readable: "Claude Desktop (user)". */
  label: string;
  exists: boolean;
  /** Raw parsed document; undefined when the file was absent or unparsable. */
  document?: unknown;
  error?: string;
}

export interface DiscoveredMcpServer extends McpConfigHint {
  /** Stable id: `<config>:<serverName>`. */
  id: string;
  name: string;
  transport: 'stdio' | 'http' | 'sse' | 'unknown';
  source: string;
  sourceKind: McpConfigSourceKind;
  /** True when Aegis added this entry itself (e.g. from a running process). */
  discovered?: boolean;
  /** True when the same command appears in more than one config. */
  duplicatedAcross?: string[];
}

/** Known MCP config file locations, per platform. */
export function knownConfigLocations(
  home = homedir(),
  cwd = process.cwd(),
  platformName: NodeJS.Platform = platform(),
): McpConfigLocation[] {
  const home_ = home;
  const out: McpConfigLocation[] = [];

  const push = (path: string, kind: McpConfigSourceKind, label: string) => {
    const exists = existsSync(path);
    out.push({ path, kind, label, exists, ...(exists ? { document: safeReadJson(path) } : {}) });
  };

  if (platformName === 'win32') {
    const appData = process.env['APPDATA'] ?? join(home_, 'AppData', 'Roaming');
    const localAppData = process.env['LOCALAPPDATA'] ?? join(home_, 'AppData', 'Local');
    push(join(appData, 'Claude', 'claude_desktop_config.json'), 'claude-desktop', 'Claude Desktop (user)');
    push(join(appData, 'Claude', 'claude_desktop_config.json.bak'), 'claude-desktop', 'Claude Desktop (backup)');
    push(join(localAppData, 'Claude', 'claude_desktop_config.json'), 'claude-desktop', 'Claude Desktop (local)');
    push(join(appData, 'Code', 'User', 'mcp.json'), 'vscode', 'VS Code (user)');
    push(join(appData, 'Code - Insiders', 'User', 'mcp.json'), 'vscode-insiders', 'VS Code Insiders (user)');
    push(join(appData, 'Cursor', 'User', 'mcp.json'), 'cursor', 'Cursor (user)');
    push(join(appData, 'Cursor', 'User', 'globalStorage', 'mcp.json'), 'cursor', 'Cursor (global storage)');
    push(join(appData, 'Windsurf', 'User', 'mcp.json'), 'windsurf', 'Windsurf (user)');
    push(join(appData, 'Zed', 'settings.json'), 'zed', 'Zed (settings)');
  } else {
    const configHome = process.env['XDG_CONFIG_HOME'] ?? join(home_, '.config');
    push(join(home_, '.config', 'Claude', 'claude_desktop_config.json'), 'claude-desktop', 'Claude Desktop (Linux)');
    push(join(home_, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'), 'claude-desktop', 'Claude Desktop (macOS)');
    push(join(configHome, 'Code', 'User', 'mcp.json'), 'vscode', 'VS Code (user)');
    push(join(configHome, 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings.json'), 'vscode', 'Claude Dev extension');
    push(join(configHome, 'Cursor', 'User', 'mcp.json'), 'cursor', 'Cursor (user)');
    push(join(configHome, 'Windsurf', 'User', 'mcp.json'), 'windsurf', 'Windsurf (user)');
    push(join(configHome, 'zed', 'settings.json'), 'zed', 'Zed (settings)');
  }

  // Project-local configs are always searched from the working directory.
  push(join(cwd, '.cursor', 'mcp.json'), 'cursor', 'Cursor (project)');
  push(join(cwd, '.mcp.json'), 'generic', 'MCP (project)');
  push(join(cwd, 'mcp.json'), 'generic', 'MCP (project root)');
  push(join(cwd, '.vscode', 'mcp.json'), 'vscode', 'VS Code (workspace)');
  push(join(cwd, '.mcp', 'config.json'), 'generic', 'MCP (.mcp)');
  push(join(cwd, 'claude_desktop_config.json'), 'claude-desktop', 'Claude Desktop (project)');
  push(join(cwd, '.claude', 'mcp.json'), 'claude-project', 'Claude Code (project)');

  // De-duplicate by path, keeping the first (most specific) label.
  const seen = new Set<string>();
  return out.filter((loc) => {
    if (seen.has(loc.path)) return false;
    seen.add(loc.path);
    return true;
  });
}

function safeReadJson(path: string): unknown | undefined {
  try {
    return parseJsonLoose(readFileSync(path, 'utf8'));
  } catch (error) {
    return undefined;
  }
}

/**
 * Normalise every supported config shape into `mcpServers` records.
 *
 * Supported layouts:
 *   { mcpServers: {...} }                     — Claude Desktop, Cursor, Windsurf
 *   { servers: { name: [ {command,args}, … ] } } — VS Code / Zed arrays
 *   { mcp: { servers: {...} } }               — VS Code settings.json
 *   { mcpServers: [ {...} ] }                — array form
 *   { tools: [...] }                         — raw tool list, no server wrapper
 */
export function extractServers(
  document: unknown,
  sourceKind: McpConfigSourceKind,
  sourceLabel: string,
): DiscoveredMcpServer[] {
  if (!document || typeof document !== 'object') return [];
  const root = document as Record<string, unknown>;
  const out: DiscoveredMcpServer[] = [];

  const add = (name: string, raw: unknown) => {
    const normalized = normalizeServerEntry(name, raw, sourceKind, sourceLabel);
    if (normalized) out.push(normalized);
  };

  // Collect every location servers can be declared. `mcp.servers` and the
  // explicit `mcp` node resolve to the same object, so a Set de-duplicates by
  // identity and a server is never reported twice.
  const containers: unknown[] = [];
  const seenContainers = new Set<unknown>();
  const addContainer = (value: unknown) => {
    if (value === undefined || value === null) return;
    if (typeof value !== 'object') return;
    if (seenContainers.has(value)) return;
    seenContainers.add(value);
    containers.push(value);
  };

  addContainer(root['mcpServers']);
  addContainer(dotGet(root, 'mcp.servers'));
  addContainer(root['servers']);
  addContainer(root['mcpServersList']);

  const mcpNode = root['mcp'];
  if (mcpNode && typeof mcpNode === 'object') {
    addContainer((mcpNode as Record<string, unknown>)['servers']);
  }
  if (containers.length === 0 && root['command'] !== undefined) {
    // A bare single-server config file.
    add(pathBasename(sourceLabel), root);
  }

  for (const container of containers) {
    if (Array.isArray(container)) {
      for (const [i, entry] of container.entries()) {
        const name = getString(entry, 'name') ?? `${sourceKind}-${i}`;
        add(name, entry);
      }
    } else if (container && typeof container === 'object') {
      for (const [name, entry] of Object.entries(container as Record<string, unknown>)) {
        add(name, entry);
      }
    }
  }

  return out;
}

function normalizeServerEntry(
  name: string,
  raw: unknown,
  sourceKind: McpConfigSourceKind,
  sourceLabel: string,
): DiscoveredMcpServer | null {
  if (typeof raw === 'string') {
    // `{ "server": "npx -y foo" }` shorthand
    return {
      id: `${sourceLabel}#${name}`,
      name,
      command: raw,
      args: [],
      env: {},
      transport: 'stdio',
      source: sourceLabel,
      sourceKind,
    };
  }
  // VS Code and Zed declare a server as an array of entries so the same server
  // can be configured per-platform. Unwrap to the first usable entry rather
  // than treating the array itself as a config object.
  if (Array.isArray(raw)) {
    for (const entry of raw) {
      const normalized = normalizeServerEntry(name, entry, sourceKind, sourceLabel);
      if (normalized) return normalized;
    }
    return null;
  }
  if (!raw || typeof raw !== 'object') return null;
  const e = raw as Record<string, unknown>;

  const command = getString(e, 'command');
  const url = getString(e, 'url') ?? getString(e, 'endpoint') ?? getString(e, 'baseUrl');
  const args = Array.isArray(e['args']) ? e['args'].map(String) : undefined;
  const env = sanitizeEnv(e['env']);

  // Transport resolution, most explicit source first. A declared `type` beats an
  // inferred one, because a config that says `sse` and a URL containing "sse"
  // disagreeing is far more likely to be a URL coincidence than a config bug.
  let transport: DiscoveredMcpServer['transport'] = 'unknown';
  const declared = (getString(e, 'type') ?? getString(e, 'transport'))?.toLowerCase();
  if (declared === 'stdio') transport = 'stdio';
  else if (declared === 'sse') transport = 'sse';
  else if (declared === 'http' || declared === 'streamable-http' || declared === 'streamablehttp') {
    transport = 'http';
  } else if (command) {
    transport = 'stdio';
  } else if (url) {
    transport = /\bsse\b/i.test(url) ? 'sse' : 'http';
  }

  if (!command && !url) return null;

  return {
    id: `${sourceLabel}#${name}`,
    name,
    ...(command ? { command } : {}),
    ...(args ? { args } : {}),
    ...(env ? { env } : {}),
    ...(getString(e, 'cwd') ? { cwd: getString(e, 'cwd')! } : {}),
    ...(url ? { url } : {}),
    ...(headersOf(e) ? { headers: headersOf(e)! } : {}),
    ...(declared ? { type: declared as McpConfigHint['type'] } : {}),
    transport,
    source: sourceLabel,
    sourceKind,
  };
}

function headersOf(entry: Record<string, unknown>): Record<string, string> | undefined {
  const raw = entry['headers'] ?? entry['env'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (/^x-.*(key|token|auth)|^authorization$/i.test(k)) out[k] = String(v);
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/** Redact secret-looking env values so findings never echo a live credential. */
function sanitizeEnv(raw: unknown): Record<string, string> | undefined {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof v !== 'string') continue;
    out[k] = looksLikeSecret(k, v) ? redact(v) : v;
  }
  return out;
}

export function looksLikeSecret(key: string, value: string): boolean {
  if (!/key|token|secret|password|passwd|credential|auth/i.test(key)) return false;
  // Environment references are not secrets.
  return !/^[$]?\{?[A-Z_][A-Z0-9_]*\}?$/.test(value) && value.length > 0;
}

export function redact(value: string): string {
  if (value.length <= 8) return '***';
  return `${value.slice(0, 3)}***${value.slice(-2)}`;
}

/** Full discovery sweep across known config files plus an explicit path. */
export async function discoverMcpServers(options: {
  cwd?: string;
  home?: string;
  explicitPaths?: string[];
  includeProcesses?: boolean;
  platform?: NodeJS.Platform;
  logger?: { debug(m: string): void; warn(m: string): void };
}): Promise<{
  locations: McpConfigLocation[];
  servers: DiscoveredMcpServer[];
  errors: string[];
}> {
  const locations = knownConfigLocations(options.home, options.cwd, options.platform);
  // Explicit paths are typed as `McpConfigLocation` so the union below stays
  // narrow enough for TypeScript to know `document` is always present-or-error.
  const explicit: McpConfigLocation[] = (options.explicitPaths ?? []).map((p) => {
    const exists = existsSync(p);
    const loc: McpConfigLocation = {
      path: p,
      kind: 'explicit',
      label: `Explicit (${pathBasename(p)})`,
      exists,
    };
    if (!exists) {
      loc.error = 'file not found';
      return loc;
    }
    const document = safeReadJson(p);
    if (document === undefined) loc.error = 'unparsable';
    else loc.document = document;
    return loc;
  });

  const all = [...explicit, ...locations];
  const servers: DiscoveredMcpServer[] = [];
  const errors: string[] = [];

  for (const loc of all) {
    if (!loc.exists) continue;
    if (loc.document === undefined) {
      errors.push(`could not parse ${loc.path}`);
      continue;
    }
    try {
      servers.push(...extractServers(loc.document, loc.kind, loc.label));
    } catch (error) {
      errors.push(`failed reading ${loc.path}: ${(error as Error).message}`);
    }
  }

  if (options.includeProcesses) {
    try {
      servers.push(...(await discoverRunningServers()));
    } catch (error) {
      errors.push(`process discovery failed: ${(error as Error).message}`);
      options.logger?.debug(`process discovery failed: ${(error as Error).message}`);
    }
  }

  // Flag servers that appear in more than one config: same command, two
  // places, means two places to keep in sync and two places to leak from.
  const byCommand = new Map<string, DiscoveredMcpServer[]>();
  for (const s of servers) {
    if (!s.command) continue;
    const key = `${s.command} ${(s.args ?? []).join(' ')}`.trim();
    byCommand.set(key, [...(byCommand.get(key) ?? []), s]);
  }
  for (const group of byCommand.values()) {
    if (group.length < 2) continue;
    const sources = [...new Set(group.map((g) => g.source))];
    for (const s of group) s.duplicatedAcross = sources;
  }

  return { locations: all, servers, errors };
}

const PROCESS_PATTERNS: Array<{ re: RegExp; name: string }> = [
  { re: /(mcp[-_]?server|mcpserver)/i, name: 'mcp-server' },
  { re: /modelcontextprotocol/i, name: 'modelcontextprotocol' },
  { re: /--transport[\s=]+(stdio|sse|http)/i, name: 'mcp-transport' },
  { re: /\bmcp\b/i, name: 'mcp' },
];

/**
 * Discover MCP servers that are currently running.
 *
 * Aegis reads the process table rather than connecting blindly, because a
 * running process tells the operator which servers are actually live in their
 * environment right now — including ones configured by tools Aegis does not
 * know about.
 */
export async function discoverRunningServers(
  options: { platform?: NodeJS.Platform; logger?: { debug(m: string): void } } = {},
): Promise<DiscoveredMcpServer[]> {
  const platformName = options.platform ?? platform();
  const lines = await listProcesses(platformName);
  const found = new Map<string, DiscoveredMcpServer>();

  for (const line of lines) {
    if (line.includes('aegis') && !line.includes('mcp')) continue;
    const match = PROCESS_PATTERNS.find((p) => p.re.test(line));
    if (!match) continue;
    const parsed = parseProcessCommand(line);
    if (!parsed) continue;
    const key = `${parsed.command} ${parsed.args.join(' ')}`;
    if (found.has(key)) continue;
    found.set(key, {
      id: `process#${match.name}`,
      name: parsed.packageName ?? match.name,
      command: parsed.command,
      args: parsed.args,
      env: {},
      transport: parsed.transport,
      source: 'Running process',
      sourceKind: 'process',
      discovered: true,
    });
  }

  return [...found.values()];
}

async function listProcesses(platformName: NodeJS.Platform): Promise<string[]> {
  try {
    if (platformName === 'win32') {
      const { stdout } = await execFileAsync('wmic', [
        'process',
        'get',
        'ProcessId,CommandLine',
        '/format:csv',
      ]);
      return stdout.split(/\r?\n/).filter(Boolean);
    }
    const { stdout } = await execFileAsync('ps', ['-eo', 'args']);
    return stdout.split(/\r?\n/).filter(Boolean);
  } catch {
    // `ps`/`wmic` may be unavailable in a minimal container; discovery is
    // best-effort by design, never fatal.
    return [];
  }
}

export function parseProcessCommand(line: string): {
  command: string;
  args: string[];
  transport: 'stdio' | 'http' | 'sse' | 'unknown';
  packageName?: string;
} | null {
  const cleaned = line.replace(/^"|",?$/g, '').trim();
  if (!cleaned) return null;
  const parts = cleaned.match(/"[^"]*"|'[^']*'|\S+/g);
  if (!parts || parts.length === 0) return null;
  const [command, ...args] = parts.map((p) => p.replace(/^["']|["']$/g, ''));
  if (!command) return null;

  let transport: 'stdio' | 'http' | 'sse' | 'unknown' = 'unknown';
  const transportFlag = args.find((a) => a === '--transport' || a === '-t');
  const next = transportFlag ? args[args.indexOf(transportFlag) + 1] : undefined;
  if (next === 'stdio') transport = 'stdio';
  else if (next === 'sse') transport = 'sse';
  else if (next === 'http' || next === 'streamable-http') transport = 'http';
  else if (/^https?:\/\//.test(command)) transport = 'http';

  const packageName = /(?:npx|uvx|pipx|node|python|uv)\s+(-y\s+|--yes\s+)?([@\w./\-]+)/.exec(cleaned)?.[2];

  return { command, args, transport, ...(packageName ? { packageName } : {}) };
}

// --- helpers ---------------------------------------------------------------

function dotGet(obj: Record<string, unknown>, path: string): unknown {
  let cur: unknown = obj;
  for (const seg of path.split('.')) {
    if (!cur || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

function getString(obj: unknown, key: string): string | undefined {
  if (!obj || typeof obj !== 'object') return undefined;
  const v = (obj as Record<string, unknown>)[key];
  return typeof v === 'string' ? v : undefined;
}

function pathBasename(p: string): string {
  const parts = p.split(/[\\/]/);
  return parts[parts.length - 1] ?? p;
}
