import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import type { DiscoveredMcpServer } from './discovery.js';
import {
  JSONRPC_ERRORS,
  JSONRPC_VERSION,
  MCP_METHODS,
  MCP_PROTOCOL_VERSION,
  McpMessageDecoder,
  McpProtocolError,
  emptyIntrospection,
  type JsonRpcId,
  type JsonRpcResponse,
  type McpIntrospection,
  type McpPrompt,
  type McpResource,
  type McpResourceTemplate,
  type McpServerCapabilities,
  type McpServerInfo,
  type McpTool,
} from './protocol.js';

export interface ConnectorOptions {
  /** Total time budget for the whole introspection. Default 20s. */
  timeoutMs?: number;
  /** Per-request timeout. Default 8s. */
  requestTimeoutMs?: number;
  /** Send `initialize` before listing. Default true. */
  initialize?: boolean;
  /** Extra headers for HTTP transport. */
  headers?: Record<string, string>;
  /** Working directory for stdio servers. */
  cwd?: string;
  env?: Record<string, string>;
  /** Refuse to spawn processes (used in `--no-exec` mode). */
  noSpawn?: boolean;
  logger?: { debug(m: string, meta?: unknown): void; warn(m: string, meta?: unknown): void };
}

export interface Connector {
  readonly transport: 'stdio' | 'http' | 'sse' | 'mock';
  introspect(): Promise<McpIntrospection>;
  /**
   * Invoke a tool. Exposed on the interface because the red-team engine and the
   * sandbox both need to exercise a server rather than merely observe it.
   */
  callTool(name: string, args: Record<string, unknown>, timeoutMs?: number): Promise<unknown>;
  /** Issue an arbitrary JSON-RPC request against the server. */
  request?(method: string, params?: unknown, timeoutMs?: number): Promise<unknown>;
  close(): Promise<void>;
}

const DEFAULT_TIMEOUT = 20_000;
const DEFAULT_REQUEST_TIMEOUT = 8_000;

/**
 * Base class holding the JSON-RPC conversation that is identical for every
 * transport. Subclasses only implement `request`.
 */
abstract class BaseConnector implements Connector {
  abstract readonly transport: 'stdio' | 'http' | 'sse' | 'mock';
  protected nextId = 1;
  protected readonly decoder = new McpMessageDecoder();
  protected readonly pending = new Map<JsonRpcId, { resolve(v: unknown): void; reject(e: Error): void }>();
  protected readonly options: Required<Pick<ConnectorOptions, 'timeoutMs' | 'requestTimeoutMs' | 'initialize'>> &
    ConnectorOptions;
  protected closed = false;

  constructor(options: ConnectorOptions = {}) {
    this.options = {
      timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT,
      requestTimeoutMs: options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT,
      initialize: options.initialize ?? true,
      ...options,
    };
  }

  abstract request(method: string, params?: unknown, timeoutMs?: number): Promise<unknown>;

  protected abstract sendNotification(method: string, params?: unknown): void | Promise<void>;

  /** Route a decoded JSON-RPC response to whoever is waiting for it. */
  protected dispatch(message: JsonRpcResponse): void {
    if (message.id === null || message.id === undefined) return;
    const waiter = this.pending.get(message.id);
    if (!waiter) return;
    this.pending.delete(message.id);
    if (message.error) {
      waiter.reject(
        new McpProtocolError(message.error.message ?? 'unknown error', message.error.code, message.error.data),
      );
    } else {
      waiter.resolve(message.result ?? {});
    }
  }

  protected makeRequest(id: JsonRpcId, method: string, params?: unknown): Promise<unknown> {
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
  }

  async introspect(): Promise<McpIntrospection> {
    const result = emptyIntrospection('unknown');
    const deadline = Date.now() + this.options.timeoutMs;

    const remaining = () => Math.max(500, deadline - Date.now());

    if (this.options.initialize) {
      const started = Date.now();
      try {
        const init = (await this.request(
          MCP_METHODS.initialize,
          {
            protocolVersion: MCP_PROTOCOL_VERSION,
            capabilities: { roots: { listChanged: false }, sampling: {} },
            clientInfo: { name: 'aegis-mcp-scanner', version: '0.1.0' },
          },
          remaining(),
        )) as {
          protocolVersion?: string;
          capabilities?: McpServerCapabilities;
          serverInfo?: McpServerInfo;
          instructions?: string;
        };
        result.protocolVersion = init.protocolVersion ?? 'unknown';
        result.capabilities = init.capabilities ?? {};
        result.server = init.serverInfo ?? { name: 'unknown', version: 'unknown' };
        if (init.instructions) result.server.instructions = init.instructions;
        result.latencyMs = Date.now() - started;
        try {
          await this.sendNotification(MCP_METHODS.initialized);
        } catch {
          /* notification failures are not fatal */
        }
      } catch (error) {
        result.errors.push(`initialize failed: ${(error as Error).message}`);
        // Continue anyway: a server that refuses `initialize` may still list.
      }
    }

    // `tools/list` is the single most important call, so it is attempted even
    // when the server never declared the `tools` capability — that mismatch is
    // itself a spec violation worth reporting.
    result.tools = await this.safeList(
      () => this.request(MCP_METHODS.toolsList, {}, remaining()),
      'tools',
      result,
    );
    result.resources = await this.safeList(
      () => this.request(MCP_METHODS.resourcesList, {}, remaining()),
      'resources',
      result,
    );
    result.resourceTemplates = await this.safeList(
      () => this.request(MCP_METHODS.resourcesTemplatesList, {}, remaining()),
      'resourceTemplates',
      result,
    );
    result.prompts = await this.safeList(
      () => this.request(MCP_METHODS.promptsList, {}, remaining()),
      'prompts',
      result,
    );

    result.complete = result.errors.length === 0;
    return result;
  }

  private async safeList<T>(
    call: () => Promise<unknown>,
    label: string,
    result: McpIntrospection,
  ): Promise<T[]> {
    try {
      const raw = (await call()) as Record<string, unknown> | undefined;
      const key = label === 'resourceTemplates' ? 'resourceTemplates' : label;
      const value = raw?.[key] ?? raw?.[label];
      if (value === undefined) return [];
      if (!Array.isArray(value)) {
        result.errors.push(`${label}/list returned a non-array ${key ?? label}`);
        return [];
      }
      return value as T[];
    } catch (error) {
      const message = (error as Error).message;
      // "Method not found" is a legitimate answer for servers without a
      // capability, so it is recorded but not treated as a failure.
      if (/method not found|-32601/i.test(message)) return [];
      if (/timed out|timeout/i.test(message)) {
        result.errors.push(`${label}/list timed out after ${this.options.requestTimeoutMs}ms`);
        return [];
      }
      result.errors.push(`${label}/list failed: ${message}`);
      return [];
    }
  }

  /** Call a tool. Used by the red-team and sandbox modules. */
  async callTool(name: string, args: Record<string, unknown>, timeoutMs?: number): Promise<unknown> {
    return this.request(MCP_METHODS.toolsCall, { name, arguments: args }, timeoutMs);
  }

  async close(): Promise<void> {
    this.closed = true;
    for (const waiter of this.pending.values()) {
      waiter.reject(new McpProtocolError('connector closed', JSONRPC_ERRORS.internalError));
    }
    this.pending.clear();
  }
}

/** Talks to a stdio MCP server: spawn the process, speak newline-delimited JSON. */
export class StdioConnector extends BaseConnector {
  readonly transport = 'stdio' as const;
  private child: ChildProcessWithoutNullStreams | null = null;
  private stderr = '';
  private readonly server: DiscoveredMcpServer;

  constructor(server: DiscoveredMcpServer, options: ConnectorOptions = {}) {
    super(options);
    this.server = server;
  }

  private ensureChild(): ChildProcessWithoutNullStreams {
    if (this.child) return this.child;
    if (!this.server.command) throw new Error('stdio server has no command');
    if (this.options.noSpawn) {
      throw new Error(`refusing to spawn "${this.server.command}" (spawn disabled)`);
    }
    const child = spawn(this.server.command, this.server.args ?? [], {
      cwd: this.server.cwd ?? this.options.cwd,
      env: {
        ...process.env,
        ...(this.server.env ?? {}),
        ...(this.options.env ?? {}),
      } as NodeJS.ProcessEnv,
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false, // never shell-interpolate an untrusted command
      windowsHide: true,
    });
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      for (const message of this.decoder.push(chunk)) this.dispatch(message);
    });
    child.stderr.on('data', (chunk: string) => {
      this.stderr = (this.stderr + chunk).slice(-4000);
    });
    child.on('error', (error) => {
      this.options.logger?.warn(`stdio server "${this.server.name}" error: ${error.message}`);
    });
    child.on('exit', (code, signal) => {
      this.options.logger?.debug(
        `stdio server "${this.server.name}" exited code=${code} signal=${signal} stderr=${this.stderr.slice(-400)}`,
      );
    });
    this.child = child;
    return child;
  }

  async request(method: string, params?: unknown, timeoutMs?: number): Promise<unknown> {
    const child = this.ensureChild();
    const id = this.nextId++;
    const promise = this.makeRequest(id, method, params);
    const payload = `${JSON.stringify({ jsonrpc: JSONRPC_VERSION, id, method, ...(params ? { params } : {}) })}\n`;
    child.stdin.write(payload, (error) => {
      if (error) {
        this.pending.get(id)?.reject(new McpProtocolError(`write failed: ${error.message}`, JSONRPC_ERRORS.internalError));
      }
    });
    return withTimeout(promise, timeoutMs ?? this.options.requestTimeoutMs, method, this.stderr);
  }

  protected sendNotification(method: string, params?: unknown): void {
    const child = this.ensureChild();
    child.stdin.write(`${JSON.stringify({ jsonrpc: JSONRPC_VERSION, method, ...(params ? { params } : {}) })}\n`);
  }

  override async close(): Promise<void> {
    await super.close();
    if (!this.child) return;
    const child = this.child;
    child.stdin.end();
    // Give the process a moment to exit cleanly, then force it.
    await Promise.race([
      new Promise<void>((resolve) => child.once('exit', () => resolve())),
      delay(1500),
    ]);
    if (!child.killed) child.kill('SIGKILL');
    this.child = null;
  }
}

/** Talks to an HTTP/SSE MCP server. */
export class HttpConnector extends BaseConnector {
  readonly transport: 'http' | 'sse';
  private readonly url: string;
  private readonly httpOptions: ConnectorOptions;

  constructor(url: string, httpOptions: ConnectorOptions = {}, transport: 'http' | 'sse' = 'http') {
    super(httpOptions);
    this.url = url;
    this.httpOptions = httpOptions;
    this.transport = transport;
  }

  async request(method: string, params?: unknown, timeoutMs?: number): Promise<unknown> {
    const id = this.nextId++;
    const controller = new AbortController();
    const budget = timeoutMs ?? this.options.requestTimeoutMs;
    const timer = setTimeout(() => controller.abort(), budget);
    try {
      const response = await fetch(this.url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          'mcp-protocol-version': MCP_PROTOCOL_VERSION,
          ...(this.httpOptions.headers ?? {}),
        },
        body: JSON.stringify({
          jsonrpc: JSONRPC_VERSION,
          id,
          method,
          ...(params ? { params } : {}),
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new McpProtocolError(
          `HTTP ${response.status} ${response.statusText}`,
          JSONRPC_ERRORS.serverError,
        );
      }

      const body = await response.text();
      const messages = [
        ...this.decoder.push(body),
        ...this.decoder.end(),
      ];
      const match = messages.find((m) => m.id === id);
      if (match) {
        if (match.error) {
          throw new McpProtocolError(match.error.message, match.error.code, match.error.data);
        }
        return match.result ?? {};
      }
      // Some servers answer 202 Accepted for a request they handle out of band;
      // that is a spec deviation, not a transport failure.
      throw new McpProtocolError(
        `no JSON-RPC response for id=${id} (${messages.length} message(s) received)`,
        JSONRPC_ERRORS.requestTimeout,
      );
    } catch (error) {
      if (error instanceof McpProtocolError) throw error;
      if ((error as Error).name === 'AbortError') {
        throw new McpProtocolError(`request to ${this.url} timed out after ${budget}ms`, JSONRPC_ERRORS.requestTimeout);
      }
      throw new McpProtocolError(`request to ${this.url} failed: ${(error as Error).message}`, JSONRPC_ERRORS.serverError);
    } finally {
      clearTimeout(timer);
    }
  }

  protected async sendNotification(method: string, params?: unknown): Promise<void> {
    try {
      await fetch(this.url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          ...(this.httpOptions.headers ?? {}),
        },
        body: JSON.stringify({ jsonrpc: JSONRPC_VERSION, method, ...(params ? { params } : {}) }),
        signal: AbortSignal.timeout(this.options.requestTimeoutMs),
      });
    } catch {
      // Notifications are fire-and-forget.
    }
  }
}

/**
 * In-memory connector used by tests and by `--dry-run`, and as the fallback so
 * that a config-only scan still produces a full finding set when a server
 * cannot be started.
 */
export class MockConnector extends BaseConnector {
  readonly transport = 'mock' as const;
  private readonly responses: Map<string, unknown>;

  private readonly serverInfo: McpServerInfo;

  constructor(
    responses: Map<string, unknown> | Record<string, unknown> = {},
    serverInfo: McpServerInfo = { name: 'mock-server', version: '1.0.0' },
  ) {
    super({ timeoutMs: 1000, requestTimeoutMs: 1000 });
    this.responses = responses instanceof Map ? responses : new Map(Object.entries(responses));
    this.serverInfo = serverInfo;
  }

  async request(method: string, params?: unknown): Promise<unknown> {
    const id = this.nextId++;
    if (method === MCP_METHODS.initialize) {
      return {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: { tools: {}, resources: {}, prompts: {} },
        serverInfo: this.serverInfo,
      };
    }
    if (MCP_METHODS.toolsList in this.responses || this.responses.has(MCP_METHODS.toolsList)) {
      return { tools: (this.responses.get(MCP_METHODS.toolsList) as McpTool[]) ?? [] };
    }
    const value = this.responses.get(method);
    if (value === undefined) {
      throw new McpProtocolError(`Method not found: ${method}`, JSONRPC_ERRORS.methodNotFound);
    }
    if (Array.isArray(value)) {
      const key = method.split('/')[0] + 's';
      return { [key]: value };
    }
    void id;
    void params;
    return value;
  }

  protected sendNotification(): void {
    /* no-op */
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number, method: string, stderr: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      const suffix = stderr ? ` (server stderr: ${stderr.slice(-200)})` : '';
      reject(new McpProtocolError(`${method} timed out after ${ms}ms${suffix}`, JSONRPC_ERRORS.requestTimeout));
    }, ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error as Error);
      },
    );
  });
}

/** Pick the right connector for a discovered server. */
export function createConnector(
  server: DiscoveredMcpServer,
  options: ConnectorOptions = {},
): Connector {
  if (server.transport === 'stdio' && server.command) {
    return new StdioConnector(server, options);
  }
  if (server.url) {
    return new HttpConnector(server.url, options, server.transport === 'sse' ? 'sse' : 'http');
  }
  throw new McpProtocolError(
    `server "${server.name}" has neither a command nor a url`,
    JSONRPC_ERRORS.invalidParams,
  );
}
