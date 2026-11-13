/**
 * Minimal, dependency-free implementation of the MCP wire protocol.
 *
 * Aegis talks to servers directly rather than through the official SDK so that
 * a scan never inherits the SDK's own runtime behaviour, and so that a
 * malicious server cannot influence the scanner through SDK-side coercion. The
 * implementations below cover JSON-RPC 2.0 over stdio (newline-delimited JSON,
 * per the MCP stdio transport) and over HTTP (streamable + SSE responses).
 */

export const JSONRPC_VERSION = '2.0';
export const MCP_PROTOCOL_VERSION = '2025-06-18';
export const SUPPORTED_PROTOCOL_VERSIONS = [
  '2025-06-18',
  '2025-03-26',
  '2024-11-05',
] as const;

export const MCP_METHODS = {
  initialize: 'initialize',
  initialized: 'notifications/initialized',
  ping: 'ping',
  toolsList: 'tools/list',
  toolsCall: 'tools/call',
  resourcesList: 'resources/list',
  resourcesRead: 'resources/read',
  resourcesTemplatesList: 'resources/templates/list',
  promptsList: 'prompts/list',
  promptsGet: 'prompts/get',
  loggingSetLevel: 'logging/setLevel',
  completionComplete: 'completion/complete',
} as const;

// ---------------------------------------------------------------------------
// JSON-RPC framing
// ---------------------------------------------------------------------------

export type JsonRpcId = string | number;

export interface JsonRpcRequest {
  jsonrpc: typeof JSONRPC_VERSION;
  id: JsonRpcId;
  method: string;
  params?: unknown;
}

export interface JsonRpcNotification {
  jsonrpc: typeof JSONRPC_VERSION;
  method: string;
  params?: unknown;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc: typeof JSONRPC_VERSION;
  id: JsonRpcId | null;
  result?: unknown;
  error?: JsonRpcError;
}

export const JSONRPC_ERRORS = {
  parseError: -32700,
  invalidRequest: -32600,
  methodNotFound: -32601,
  invalidParams: -32602,
  internalError: -32603,
  serverError: -32000,
  requestTimeout: -32001,
} as const;

export class McpProtocolError extends Error {
  readonly code: number;
  readonly data?: unknown;

  constructor(message: string, code: number, data?: unknown) {
    super(message);
    this.name = 'McpProtocolError';
    this.code = code;
    this.data = data;
  }
}

/**
 * Extract JSON-RPC messages from a stream of bytes.
 *
 * Handles both newline-delimited JSON (stdio) and SSE framing (`data: ...`
 * lines), because an HTTP server may legitimately answer with either.
 */
export class McpMessageDecoder {
  private buffer = '';

  push(chunk: string | Buffer): JsonRpcResponse[] {
    this.buffer += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
    const out: JsonRpcResponse[] = [];

    // SSE frames first: `event: message\ndata: {...}\n\n`
    if (this.buffer.includes('data:')) {
      const frames = this.buffer.split(/\r?\n\r?\n/);
      this.buffer = frames.pop() ?? '';
      for (const frame of frames) {
        const dataLines = frame
          .split(/\r?\n/)
          .filter((l) => l.startsWith('data:'))
          .map((l) => l.slice(5).trim());
        if (dataLines.length === 0) continue;
        const parsed = safeParse(dataLines.join('\n'));
        if (parsed) out.push(parsed);
      }
      return out;
    }

    const lines = this.buffer.split(/\r?\n/);
    this.buffer = lines.pop() ?? '';
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const parsed = safeParse(trimmed);
      if (parsed) out.push(parsed);
      else if (/^[{[]/.test(trimmed)) {
        // Looks like JSON but did not parse — surface it rather than dropping.
        throw new McpProtocolError('malformed JSON-RPC message', JSONRPC_ERRORS.parseError, trimmed.slice(0, 200));
      }
    }
    return out;
  }

  /** Flush any trailing partial message. */
  end(): JsonRpcResponse[] {
    const trimmed = this.buffer.trim();
    this.buffer = '';
    if (!trimmed) return [];
    const parsed = safeParse(trimmed);
    return parsed ? [parsed] : [];
  }
}

function safeParse(text: string): JsonRpcResponse | null {
  if (!text.startsWith('{')) return null;
  try {
    const value = JSON.parse(text) as JsonRpcResponse;
    return value && typeof value === 'object' ? value : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Introspection model
// ---------------------------------------------------------------------------

export interface McpToolAnnotation {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

export interface McpTool {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  annotations?: McpToolAnnotation;
  /** Non-standard fields some servers add; kept for poisoning analysis. */
  [key: string]: unknown;
}

export interface McpResource {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
  [key: string]: unknown;
}

export interface McpResourceTemplate {
  uriTemplate?: string;
  name?: string;
  description?: string;
  mimeType?: string;
  [key: string]: unknown;
}

export interface McpPromptArgument {
  name: string;
  description?: string;
  required?: boolean;
  [key: string]: unknown;
}

export interface McpPrompt {
  name: string;
  title?: string;
  description?: string;
  arguments?: McpPromptArgument[];
  [key: string]: unknown;
}

export interface McpServerCapabilities {
  tools?: { listChanged?: boolean };
  resources?: { subscribe?: boolean; listChanged?: boolean };
  prompts?: { listChanged?: boolean };
  logging?: Record<string, unknown>;
  completions?: Record<string, unknown>;
  experimental?: Record<string, unknown>;
}

export interface McpServerInfo {
  name: string;
  version: string;
  title?: string;
  instructions?: string;
}

export interface McpIntrospection {
  server: McpServerInfo;
  protocolVersion: string;
  capabilities: McpServerCapabilities;
  tools: McpTool[];
  resources: McpResource[];
  resourceTemplates: McpResourceTemplate[];
  prompts: McpPrompt[];
  /** Non-protocol errors observed while listing (spec violations). */
  errors: string[];
  /** True when the server answered `tools/list` etc. successfully. */
  complete: boolean;
  /** Round-trip latency of `initialize`, ms. */
  latencyMs?: number;
}

export function emptyIntrospection(name: string): McpIntrospection {
  return {
    server: { name, version: 'unknown' },
    protocolVersion: 'unknown',
    capabilities: {},
    tools: [],
    resources: [],
    resourceTemplates: [],
    prompts: [],
    errors: [],
    complete: false,
  };
}
