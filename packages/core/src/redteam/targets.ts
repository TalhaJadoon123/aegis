import { MCP_METHODS, McpMessageDecoder, McpProtocolError, MCP_PROTOCOL_VERSION, JSONRPC_VERSION } from '../scanners/mcp/protocol.js';
import type { DiscoveredMcpServer } from '../scanners/mcp/discovery.js';
import { createConnector, type Connector } from '../scanners/mcp/connectors.js';

/**
 * Red-team targets.
 *
 * Three shapes cover essentially every agent that can be attacked:
 * an HTTP endpoint, an MCP server, or a local script. Each exposes the same
 * `send()` so the genetic engine is agnostic to what it is attacking.
 */

export interface RedTeamTarget {
  readonly kind: 'http' | 'mcp' | 'script';
  readonly name: string;
  /** Capabilities the target exposes, used to select applicable attacks. */
  readonly capabilities: Array<'network' | 'filesystem' | 'shell' | 'database' | 'email' | 'code-execution'>;
  /** Send a prompt and return the agent's response text. */
  send(prompt: string, options?: { turn?: number; signal?: AbortSignal }): Promise<TargetResponse>;
  close(): Promise<void>;
  /** Multi-turn support: true when the target maintains conversation state. */
  readonly supportsMultiTurn: boolean;
  /** Reset conversation state, if the target has any. */
  reset?(): Promise<void>;
}

export interface TargetResponse {
  text: string;
  latencyMs: number;
  /** Tool calls the agent attempted, if observable. */
  toolCalls?: Array<{ name: string; arguments?: Record<string, unknown> }>;
  /** An error from the target, rather than a refusal by the agent. */
  error?: string;
  /** HTTP status or transport-level code. */
  status?: number;
}

// ---------------------------------------------------------------------------
// HTTP endpoint
// ---------------------------------------------------------------------------

export interface HttpTargetOptions {
  url: string;
  headers?: Record<string, string>;
  /** Field the prompt is sent in. Default `message`. */
  messageField?: string;
  /** Additional body fields, e.g. `{ session_id }`. */
  extraBody?: Record<string, unknown>;
  timeoutMs?: number;
  /** Extract the assistant text from the response. */
  responsePath?: string;
  /** Send history so multi-turn attacks work. */
  maintainHistory?: boolean;
  capabilities?: RedTeamTarget['capabilities'];
  name?: string;
  logger?: { warn(m: string): void; debug?(m: string): void };
}

export class HttpRedTeamTarget implements RedTeamTarget {
  readonly kind = 'http' as const;
  readonly name: string;
  readonly capabilities: RedTeamTarget['capabilities'];
  readonly supportsMultiTurn: boolean;
  private history: Array<{ role: string; content: string }> = [];
  private readonly options: HttpTargetOptions;

  constructor(options: HttpTargetOptions) {
    this.options = options;
    this.name = options.name ?? safeHost(options.url);
    this.capabilities = options.capabilities ?? ['network'];
    this.supportsMultiTurn = options.maintainHistory ?? true;
  }

  async send(prompt: string, options: { turn?: number; signal?: AbortSignal } = {}): Promise<TargetResponse> {
    const started = Date.now();
    const field = this.options.messageField ?? 'message';
    const body: Record<string, unknown> = {
      ...(this.options.extraBody ?? {}),
      [field]: prompt,
    };
    if (this.supportsMultiTurn) {
      body['messages'] = [
        ...this.history,
        { role: 'user', content: prompt },
      ];
    }

    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      this.options.timeoutMs ?? 30_000,
    );
    options.signal?.addEventListener('abort', () => controller.abort(), { once: true });

    try {
      const response = await fetch(this.options.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(this.options.headers ?? {}) },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      const text = await response.text();

      if (!response.ok) {
        return {
          text,
          latencyMs: Date.now() - started,
          status: response.status,
          error: `HTTP ${response.status} ${response.statusText}`,
        };
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        // A plain-text agent endpoint is legitimate.
        if (this.supportsMultiTurn) {
          this.history.push({ role: 'user', content: prompt });
          this.history.push({ role: 'assistant', content: text });
        }
        return { text, latencyMs: Date.now() - started, status: response.status };
      }

      if (this.supportsMultiTurn) {
        const assistantText = extractText(parsed, this.options.responsePath);
        this.history.push({ role: 'user', content: prompt });
        this.history.push({ role: 'assistant', content: assistantText });
      }

      return {
        text: extractText(parsed, this.options.responsePath),
        latencyMs: Date.now() - started,
        status: response.status,
        toolCalls: extractToolCalls(parsed),
      };
    } catch (error) {
      const message = (error as Error).name === 'AbortError'
        ? `timed out after ${this.options.timeoutMs ?? 30_000}ms`
        : (error as Error).message;
      this.options.logger?.warn(`http target "${this.name}" request failed: ${message}`);
      return { text: '', latencyMs: Date.now() - started, error: message };
    } finally {
      clearTimeout(timeout);
    }
  }

  async reset(): Promise<void> {
    this.history = [];
  }

  async close(): Promise<void> {
    this.history = [];
  }
}

/** Pull the assistant text out of the many shapes an agent endpoint returns. */
export function extractText(payload: unknown, path?: string): string {
  if (path) {
    const value = getPath(payload, path);
    if (typeof value === 'string') return value;
  }
  const seen = new Set<object>();
  const parts: string[] = [];
  collect(payload, seen, parts, 0);
  return parts.join('\n');
}

function collect(value: unknown, seen: Set<object>, out: string[], depth: number): void {
  if (depth > 8 || out.join('').length > 20_000) return;
  if (typeof value === 'string') {
    out.push(value);
    return;
  }
  if (!value || typeof value !== 'object') return;
  if (seen.has(value)) return;
  seen.add(value);

  // Prefer well-known assistant fields before falling back to a full walk.
  const record = value as Record<string, unknown>;
  for (const key of ['output_text', 'text', 'content', 'message', 'response', 'reply', 'answer', 'output']) {
    if (key in record) {
      collect(record[key], seen, out, depth + 1);
      return;
    }
  }
  for (const nested of Object.values(record)) {
    collect(nested, seen, out, depth + 1);
  }
}

function getPath(payload: unknown, path: string): unknown {
  let current: unknown = payload;
  for (const segment of path.replace(/^\$\.?/, '').split('.').filter(Boolean)) {
    if (!current || typeof current !== 'object') return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function extractToolCalls(payload: unknown): TargetResponse['toolCalls'] {
  const calls: NonNullable<TargetResponse['toolCalls']> = [];
  const seen = new Set<object>();
  const walk = (value: unknown, depth: number): void => {
    if (depth > 8 || !value || typeof value !== 'object') return;
    if (seen.has(value)) return;
    seen.add(value);
    if (Array.isArray(value)) {
      for (const item of value) walk(item, depth + 1);
      return;
    }
    const record = value as Record<string, unknown>;
    if (typeof record['name'] === 'string' && ('arguments' in record || 'input' in record || 'parameters' in record)) {
      calls.push({
        name: record['name'],
        ...(typeof record['arguments'] === 'object' && record['arguments'] !== null
          ? { arguments: record['arguments'] as Record<string, unknown> }
          : {}),
      });
    }
    for (const nested of Object.values(record)) walk(nested, depth + 1);
  };
  walk(payload, 0);
  return calls.length > 0 ? calls : undefined;
}

function safeHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url.slice(0, 40);
  }
}

// ---------------------------------------------------------------------------
// MCP server
// ---------------------------------------------------------------------------

export class McpRedTeamTarget implements RedTeamTarget {
  readonly kind = 'mcp' as const;
  readonly name: string;
  readonly capabilities: RedTeamTarget['capabilities'];
  readonly supportsMultiTurn = true;

  private readonly connector: Connector;

  private constructor(
    connector: Connector,
    name: string,
    capabilities: RedTeamTarget['capabilities'],
  ) {
    this.connector = connector;
    this.name = name;
    this.capabilities = capabilities;
  }

  static async create(
    server: DiscoveredMcpServer,
    options: { timeoutMs?: number; capabilities?: RedTeamTarget['capabilities'] } = {},
  ): Promise<McpRedTeamTarget> {
    const connector = createConnector(server, {
      timeoutMs: options.timeoutMs ?? 15_000,
    });
    const introspection = await connector.introspect();
    return new McpRedTeamTarget(
      connector,
      server.name,
      options.capabilities ?? inferCapabilities(introspection.tools),
    );
  }

  async send(prompt: string): Promise<TargetResponse> {
    const started = Date.now();
    try {
      const result = (await this.connector.callTool('__aegis_redteam__', { prompt })) as unknown;
      return {
        text: extractText(result),
        latencyMs: Date.now() - started,
        toolCalls: extractToolCalls(result),
      };
    } catch (error) {
      // A server without the probe tool still answers usefully: send the
      // prompt to its first conversational tool, if it has one.
      const fallback = await this.sendViaFirstTool(prompt, started);
      if (fallback) return fallback;
      return {
        text: '',
        latencyMs: Date.now() - started,
        error: (error as Error).message,
      };
    }
  }

  private async sendViaFirstTool(prompt: string, started: number): Promise<TargetResponse | null> {
    try {
      const tools = await this.connector.request?.(MCP_METHODS.toolsList);
      const list = (tools as { tools?: Array<{ name: string }> } | undefined)?.tools ?? [];
      const conversational = list.find((t) => /chat|ask|prompt|complete|run|agent/i.test(t.name));
      if (!conversational) return null;
      const result = (await this.connector.callTool(conversational.name, {
        prompt,
        message: prompt,
        input: prompt,
      })) as unknown;
      return { text: extractText(result), latencyMs: Date.now() - started };
    } catch {
      return null;
    }
  }

  async close(): Promise<void> {
    await this.connector.close().catch(() => {});
  }
}

/** Guess a server's capabilities from its advertised tools. */
export function inferCapabilities(
  tools: ReadonlyArray<{ name: string; description?: string }>,
): RedTeamTarget['capabilities'] {
  const caps = new Set<RedTeamTarget['capabilities'][number]>();
  for (const tool of tools) {
    const text = `${tool.name} ${tool.description ?? ''}`.toLowerCase();
    if (/file|read|write|directory|fs_/.test(text)) caps.add('filesystem');
    if (/shell|exec|command|terminal|bash|python/.test(text)) caps.add('shell');
    if (/http|fetch|request|web|browse|curl|search/.test(text)) caps.add('network');
    if (/sql|query|database|postgres|mongo/.test(text)) caps.add('database');
    if (/email|mail|smtp|message|send/.test(text)) caps.add('email');
    if (/code|eval|interpret|execute|snippet/.test(text)) caps.add('code-execution');
  }
  return [...caps];
}

// ---------------------------------------------------------------------------
// Local agent script
// ---------------------------------------------------------------------------

export interface ScriptTargetOptions {
  command: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
  capabilities?: RedTeamTarget['capabilities'];
  name?: string;
  /**
   * Receives the agent's stdout. Return the string the runner should treat as
   * the agent's response. Defaults to all of stdout.
   */
  extract?: (stdout: string, stderr: string) => string;
}

export class ScriptRedTeamTarget implements RedTeamTarget {
  readonly kind = 'script' as const;
  readonly name: string;
  readonly capabilities: RedTeamTarget['capabilities'];
  readonly supportsMultiTurn = false;
  private readonly options: ScriptTargetOptions;

  constructor(options: ScriptTargetOptions) {
    this.options = options;
    this.name = options.name ?? options.command;
    this.capabilities = options.capabilities ?? ['filesystem', 'shell', 'network'];
  }

  async send(prompt: string, options: { signal?: AbortSignal } = {}): Promise<TargetResponse> {
    const started = Date.now();
    const { spawn } = await import('node:child_process');
    return new Promise((resolve) => {
      const child = spawn(this.options.command, this.options.args ?? [], {
        cwd: this.options.cwd,
        env: { ...process.env, ...(this.options.env ?? {}) } as NodeJS.ProcessEnv,
        stdio: ['pipe', 'pipe', 'pipe'],
        shell: false,
        windowsHide: true,
      });

      let stdout = '';
      let stderr = '';
      let settled = false;
      const finish = (result: TargetResponse) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        options.signal?.removeEventListener('abort', onAbort);
        try {
          child.kill('SIGKILL');
        } catch {
          /* already gone */
        }
        resolve(result);
      };

      const timer = setTimeout(
        () => finish({ text: '', latencyMs: Date.now() - started, error: 'agent script timed out' }),
        this.options.timeoutMs ?? 30_000,
      );
      const onAbort = () =>
        finish({ text: '', latencyMs: Date.now() - started, error: 'aborted' });
      options.signal?.addEventListener('abort', onAbort, { once: true });

      child.stdout.on('data', (c: Buffer) => {
        stdout += c.toString('utf8');
      });
      child.stderr.on('data', (c: Buffer) => {
        stderr += c.toString('utf8');
      });
      child.on('error', (error) =>
        finish({ text: '', latencyMs: Date.now() - started, error: error.message }),
      );
      child.on('close', (code) => {
        const text = this.options.extract ? this.options.extract(stdout, stderr) : stdout;
        finish({
          text,
          latencyMs: Date.now() - started,
          ...(code !== 0 ? { error: `exit ${code}: ${stderr.slice(-400)}` } : {}),
        });
      });

      child.stdin.write(prompt);
      child.stdin.end();
    });
  }

  async close(): Promise<void> {
    /* nothing to release; each send is its own process */
  }
}

// ---------------------------------------------------------------------------
// Dry-run target
// ---------------------------------------------------------------------------

export interface DryRunOptions {
  /** Canned responses keyed by attack id, or a single default. */
  responses?: Record<string, string>;
  defaultResponse?: string;
  name?: string;
  /** Latency to simulate, so budgets behave realistically in tests. */
  latencyMs?: number;
}

/**
 * A target that talks to nobody.
 *
 * `--dry-run` exists so a team can validate their red-team configuration, see
 * the report shape, and run the whole suite in CI without spending model
 * budget or sending attack traffic at a production system.
 */
export class DryRunTarget implements RedTeamTarget {
  readonly kind = 'http' as const;
  readonly name: string;
  readonly capabilities: RedTeamTarget['capabilities'] = ['network', 'filesystem', 'shell'];
  readonly supportsMultiTurn = true;
  readonly prompts: string[] = [];

  private readonly options: DryRunOptions;

  constructor(options: DryRunOptions = {}) {
    this.options = options;
    this.name = options.name ?? 'dry-run';
  }

  async send(prompt: string): Promise<TargetResponse> {
    this.prompts.push(prompt);
    if (this.options.latencyMs) {
      await new Promise((r) => setTimeout(r, this.options.latencyMs));
    }
    const canned = this.options.responses?.[prompt] ?? this.options.defaultResponse;
    return {
      text: canned ?? '[dry-run] no response configured',
      latencyMs: this.options.latencyMs ?? 0,
    };
  }

  async close(): Promise<void> {
    this.prompts.length = 0;
  }
}

export { McpMessageDecoder, McpProtocolError, MCP_PROTOCOL_VERSION, JSONRPC_VERSION };