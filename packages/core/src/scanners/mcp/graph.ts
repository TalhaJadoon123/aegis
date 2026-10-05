import type { McpIntrospection, McpTool } from './protocol.js';
import type { DiscoveredMcpServer } from './discovery.js';

/**
 * The MCP Supply Chain Graph.
 *
 * Nodes are servers, tools, resources, prompts, and the data/credential assets
 * they can reach. Edges are data flows and privilege escalations. What makes
 * this useful rather than decorative is that it is *composable*: a tool
 * finding, a code finding, and a runtime observation all contribute edges to
 * the same graph, so "this MCP server can read .env, and this agent has a
 * prompt injection, and this agent talks to that server" becomes a single
 * reachable path from untrusted input to secret material.
 */

export type GraphNodeKind =
  | 'server'
  | 'tool'
  | 'resource'
  | 'prompt'
  | 'agent'
  | 'dataset'
  | 'credential'
  | 'external-service';

export type GraphEdgeKind =
  | 'exposes'
  | 'reads'
  | 'writes'
  | 'executes'
  | 'fetches'
  | 'exfiltrates-to'
  | 'authenticates-with'
  | 'calls'
  | 'instructs'
  | 'depends-on';

export interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  label: string;
  /** Lower-case searchable text. */
  searchable: string;
  serverId?: string;
  /** 0–1; how much this node should draw the eye. */
  risk?: number;
  tags?: string[];
  meta?: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: GraphEdgeKind;
  /** 0–1. 1 = the canonical exfiltration path. */
  weight: number;
  label?: string;
  meta?: Record<string, unknown>;
}

export interface SupplyChainGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** Server ids keyed by graph node id. */
  servers: Record<string, string>;
  stats: GraphStats;
}

export interface GraphStats {
  serverCount: number;
  toolCount: number;
  resourceCount: number;
  promptCount: number;
  edgeCount: number;
  /** Paths from an untrusted/attacker-reachable node to a credential. */
  exfiltrationPaths: string[][];
  /** Longest chain of privilege-increasing edges from any data source. */
  maxDepth: number;
  /** Servers participating in at least one exfiltration path. */
  exposedServers: string[];
}

/** Capability classification — the vocabulary the graph edges are built from. */
export interface CapabilityModel {
  readsFiles: boolean;
  writesFiles: boolean;
  executesCommands: boolean;
  readsEnvironment: boolean;
  readsDatabase: boolean;
  makesNetworkRequests: boolean;
  readsClipboard: boolean;
  takesScreenshots: boolean;
  sendsEmail: boolean;
  modifiesGit: boolean;
  destructive: boolean;
  readOnly: boolean;
  openWorld: boolean;
}

const READ_FILE_HINTS = [
  'read_file', 'readfile', 'cat_file', 'get_file', 'fs_read', 'open_file', 'read_text',
  'list_dir', 'list_files', 'ls', 'glob', 'find_files', 'search_files', 'get_file_contents',
  'file_reader', 'readtextfile', 'directory_tree', 'grep', 'ripgrep',
];
const WRITE_FILE_HINTS = [
  'write_file', 'writefile', 'save_file', 'create_file', 'fs_write', 'edit_file',
  'patch_file', 'append_file', 'move_file', 'delete_file', 'rm_file', 'mkdir',
];
const EXEC_HINTS = [
  'exec', 'shell', 'bash', 'run_command', 'execute_command', 'run_shell', 'terminal',
  'python_exec', 'code_interpreter', 'sandbox_run', 'process', 'spawn', 'eval',
];
const ENV_HINTS = ['env', 'environment', 'get_env', 'read_env', 'os_environ', 'getenv', 'config_get'];
const DB_HINTS = ['sql', 'query', 'database', 'db_', 'postgres', 'mysql', 'mongo', 'redis', 'supabase'];
const NET_HINTS = ['fetch', 'http', 'request', 'webhook', 'api_call', 'browse', 'curl', 'download', 'upload', 'post_message'];
const CLIPBOARD_HINTS = ['clipboard', 'copy_to_clipboard', 'paste'];
const SCREEN_HINTS = ['screenshot', 'screen_capture', 'capture_screen'];
const EMAIL_HINTS = ['send_email', 'send_mail', 'email', 'smtp'];
const GIT_HINTS = ['git_commit', 'git_push', 'git', 'commit', 'push', 'merge', 'pr_create'];
const DESTRUCTIVE_HINTS = ['delete', 'remove', 'drop', 'destroy', 'purge', 'wipe', 'rm', 'truncate', 'revoke', 'uninstall', 'format'];
const SENSITIVE_PATH_HINTS = [
  '.env', '.ssh', 'id_rsa', '.aws', '.npmrc', 'credentials', '.git/config', '/etc/passwd',
  '/etc/shadow', 'secrets', '.pem', 'keychain', '.netrc', '.kube/config',
];

function hasAny(haystack: string, needles: string[]): boolean {
  return needles.some((n) => haystack.includes(n));
}

/**
 * Derive a capability model from a tool's name, description, and schema.
 *
 * Deliberately conservative in one direction only: a tool with no annotations
 * is treated as *not* read-only, because the safe default for an agent tool is
 * that it can do more than it says.
 */
export function deriveCapabilities(tool: McpTool): CapabilityModel {
  // The schema JSON is hoisted into a local: an elvis operator immediately
  // before the closing `}` of a template literal is parsed ambiguously, and
  // building the string in two steps is clearer regardless.
  const schema = JSON.stringify(tool.inputSchema ?? {});
  const text = `${tool.name} ${tool.title ?? ''} ${tool.description ?? ''} ${schema}`.toLowerCase();
  const annotations = tool.annotations ?? {};

  const readsFiles =
    hasAny(text, READ_FILE_HINTS) || /(read|get|fetch|open|list|cat|load)/.test(tool.name.toLowerCase());
  const executesCommands = hasAny(text, EXEC_HINTS);
  const readsEnvironment = hasAny(text, ENV_HINTS);
  const readsDatabase = hasAny(text, DB_HINTS);
  const makesNetworkRequests = hasAny(text, NET_HINTS);
  const destructive =
    annotations.destructiveHint === true ||
    hasAny(tool.name.toLowerCase(), DESTRUCTIVE_HINTS);
  const readOnly = annotations.readOnlyHint === true;

  return {
    readsFiles: readsFiles && !executesCommands,
    writesFiles: hasAny(text, WRITE_FILE_HINTS),
    executesCommands,
    readsEnvironment,
    readsDatabase,
    makesNetworkRequests,
    readsClipboard: hasAny(text, CLIPBOARD_HINTS),
    takesScreenshots: hasAny(text, SCREEN_HINTS),
    sendsEmail: hasAny(text, EMAIL_HINTS),
    modifiesGit: hasAny(text, GIT_HINTS),
    destructive,
    readOnly,
    openWorld: annotations.openWorldHint === true || makesNetworkRequests,
  };
}

/** Does this tool's schema touch credential material? */
export function touchesSensitiveFiles(capabilities: CapabilityModel, tool: McpTool): boolean {
  const schema = JSON.stringify(tool.inputSchema ?? {});
  const text = `${tool.name} ${tool.description ?? ''} ${schema}`.toLowerCase();
  return capabilities.readsFiles && hasAny(text, SENSITIVE_PATH_HINTS);
}

/** The read→egress chain: the primitive behind agent data exfiltration. */
export function hasExfiltrationPath(capabilities: CapabilityModel): boolean {
  const source =
    capabilities.readsFiles ||
    capabilities.readsEnvironment ||
    capabilities.readsDatabase ||
    capabilities.readsClipboard ||
    capabilities.takesScreenshots;
  return source && capabilities.makesNetworkRequests;
}

export interface GraphBuildInput {
  servers: DiscoveredMcpServer[];
  introspections: Array<{ server: DiscoveredMcpServer; introspection: McpIntrospection }>;
  /** Optional agents to include as nodes. */
  agents?: Array<{ id: string; name: string; callsServers: string[] }>;
}

const nodeId = (...parts: string[]) => parts.map(sanitizeId).join('::');

function sanitizeId(value: string): string {
  return value.replace(/[^A-Za-z0-9_.-]/g, '_');
}

export function buildSupplyChainGraph(input: GraphBuildInput): SupplyChainGraph {
  const nodes = new Map<string, GraphNode>();
  const edges = new Map<string, GraphEdge>();
  const servers: Record<string, string> = {};

  const addNode = (node: GraphNode): GraphNode => {
    const existing = nodes.get(node.id);
    if (existing) {
      existing.risk = Math.max(existing.risk ?? 0, node.risk ?? 0);
      existing.tags = [...new Set([...(existing.tags ?? []), ...(node.tags ?? [])])];
      return existing;
    }
    nodes.set(node.id, node);
    return node;
  };

  const addEdge = (edge: GraphEdge): GraphEdge => {
    const existing = edges.get(edge.id);
    if (existing) {
      existing.weight = Math.max(existing.weight, edge.weight);
      return existing;
    }
    edges.set(edge.id, edge);
    return edge;
  };

  // Aggregate capability flags, reset for each server so one server's reading
  // capability never creates an edge for another's egress tool.
  let serverHasFileReader = false;
  let serverHasEnvReader = false;
  let serverHasDbReader = false;

  for (const { server, introspection } of input.introspections) {
  // Reset the aggregate flags for this server.
  serverHasFileReader = false;
  serverHasEnvReader = false;
  serverHasDbReader = false;
  for (const tool of introspection.tools) {
    const caps = deriveCapabilities(tool);
    if (caps.readsFiles) serverHasFileReader = true;
    if (caps.readsEnvironment) serverHasEnvReader = true;
    if (caps.readsDatabase) serverHasDbReader = true;
  }
    const serverNodeId = nodeId('server', server.name);
    servers[serverNodeId] = server.id;
    const toolCount = introspection.tools.length;
    addNode({
      id: serverNodeId,
      kind: 'server',
      label: server.name,
      searchable: `${server.name} ${server.command ?? server.url ?? ''}`.toLowerCase(),
      serverId: server.id,
      risk: riskFromTransport(server),
      tags: [server.transport, ...(server.duplicatedAcross ? ['duplicated'] : [])],
      meta: {
        command: server.command,
        url: server.url,
        transport: server.transport,
        version: introspection.server.version,
        protocolVersion: introspection.protocolVersion,
        source: server.source,
        toolCount,
      },
    });

    for (const tool of introspection.tools) {
      const caps = deriveCapabilities(tool);
      const toolNodeId = nodeId('tool', server.name, tool.name);
      addNode({
        id: toolNodeId,
        kind: 'tool',
        label: tool.name,
        searchable: `${tool.name} ${tool.title ?? ''} ${tool.description ?? ''}`.toLowerCase(),
        serverId: server.id,
        risk: toolRisk(caps),
        tags: activeCapabilities(caps),
        meta: {
          capabilities: caps,
          readOnlyHint: tool.annotations?.readOnlyHint ?? null,
          destructiveHint: tool.annotations?.destructiveHint ?? null,
          hasInputSchema: Boolean(tool.inputSchema),
        },
      });
      addEdge({
        id: `${serverNodeId}->${toolNodeId}:exposes`,
        source: serverNodeId,
        target: toolNodeId,
        kind: 'exposes',
        weight: 0.4,
        label: 'exposes',
      });

      if (caps.readsFiles) {
        const fileNode = addNode({
          id: nodeId('dataset', 'filesystem'),
          kind: 'dataset',
          label: 'Local filesystem',
          searchable: 'filesystem files secrets',
          risk: touchesSensitiveFiles(caps, tool) ? 0.9 : 0.4,
          tags: touchesSensitiveFiles(caps, tool) ? ['sensitive-paths'] : [],
        });
        addEdge({
          id: `${toolNodeId}->${fileNode.id}:reads`,
          source: toolNodeId,
          target: fileNode.id,
          kind: 'reads',
          weight: touchesSensitiveFiles(caps, tool) ? 0.9 : 0.5,
          label: 'reads',
        });
      }
      if (caps.readsEnvironment) {
        const envNode = addNode({
          id: nodeId('credential', 'process-env'),
          kind: 'credential',
          label: 'Process environment',
          searchable: 'api keys tokens environment credentials',
          risk: 0.95,
          tags: ['secret'],
        });
        addEdge({
          id: `${toolNodeId}->${envNode.id}:reads`,
          source: toolNodeId,
          target: envNode.id,
          kind: 'reads',
          weight: 1,
          label: 'reads secrets',
        });
      }
      if (caps.readsDatabase) {
        const dbNode = addNode({
          id: nodeId('dataset', 'database'),
          kind: 'dataset',
          label: 'Database',
          searchable: 'database records rows sql',
          risk: 0.8,
          tags: ['pii'],
        });
        addEdge({
          id: `${toolNodeId}->${dbNode.id}:reads`,
          source: toolNodeId,
          target: dbNode.id,
          kind: 'reads',
          weight: 0.8,
          label: 'queries',
        });
      }
      if (caps.executesCommands) {
        const execNode = addNode({
          id: nodeId('external-service', 'shell'),
          kind: 'external-service',
          label: 'Host shell',
          searchable: 'shell command process exec',
          risk: 1,
          tags: ['rce'],
        });
        addEdge({
          id: `${toolNodeId}->${execNode.id}:executes`,
          source: toolNodeId,
          target: execNode.id,
          kind: 'executes',
          weight: 1,
          label: 'executes',
        });
      }
      if (caps.makesNetworkRequests) {
        const egressNode = addNode({
          id: nodeId('external-service', 'network'),
          kind: 'external-service',
          label: 'Outbound network',
          searchable: 'http fetch egress internet',
          risk: 0.7,
          tags: ['egress'],
        });
        addEdge({
          id: `${toolNodeId}->${egressNode.id}:fetches`,
          source: toolNodeId,
          target: egressNode.id,
          kind: 'fetches',
          weight: 0.7,
          label: 'network egress',
        });
        // The exfiltration edge: a data source reachable by this server can reach
        // the network through this tool. The two capabilities may live in
        // *different* tools — a malicious server splits them precisely so no
        // single tool looks dangerous — so the edge is drawn at server scope.
        const sources = [
          caps.readsFiles || serverHasFileReader ? 'filesystem' : null,
          caps.readsEnvironment || serverHasEnvReader ? 'process-env' : null,
          caps.readsDatabase || serverHasDbReader ? 'database' : null,
        ].filter((v): v is string => v !== null);
        for (const src of sources) {
          addEdge({
            id: `${src}->egress-via:${server.name}:${tool.name}`,
            source: nodeId(src === 'process-env' ? 'credential' : 'dataset', src),
            target: egressNode.id,
            kind: 'exfiltrates-to',
            weight: 1,
            label: `exfiltrates via ${tool.name}`,
            meta: { server: server.name, tool: tool.name },
          });
        }
      }
    }

    for (const resource of introspection.resources) {
      const resourceNodeId = nodeId('resource', server.name, resource.uri);
      addNode({
        id: resourceNodeId,
        kind: 'resource',
        label: resource.name ?? resource.uri,
        searchable: `${resource.uri} ${resource.name ?? ''} ${resource.description ?? ''}`.toLowerCase(),
        serverId: server.id,
        risk: 0.5,
        meta: { uri: resource.uri, mimeType: resource.mimeType ?? null },
      });
      addEdge({
        id: `${serverNodeId}->${resourceNodeId}:exposes`,
        source: serverNodeId,
        target: resourceNodeId,
        kind: 'exposes',
        weight: 0.5,
        label: 'exposes',
      });
      if (isSensitiveUri(resource.uri)) {
        const secretNode = addNode({
          id: nodeId('credential', 'resource', sanitizeId(resource.uri)),
          kind: 'credential',
          label: resource.uri,
          searchable: resource.uri.toLowerCase(),
          risk: 0.95,
          tags: ['secret'],
        });
        addEdge({
          id: `${resourceNodeId}->${secretNode.id}:reads`,
          source: resourceNodeId,
          target: secretNode.id,
          kind: 'reads',
          weight: 1,
          label: 'serves secrets',
        });
      }
    }

    for (const prompt of introspection.prompts) {
      const promptNodeId = nodeId('prompt', server.name, prompt.name);
      addNode({
        id: promptNodeId,
        kind: 'prompt',
        label: prompt.name,
        searchable: `${prompt.name} ${prompt.description ?? ''} ${JSON.stringify(prompt.arguments ?? [])}`.toLowerCase(),
        serverId: server.id,
        risk: 0.4,
        meta: { arguments: prompt.arguments ?? [] },
      });
      addEdge({
        id: `${serverNodeId}->${promptNodeId}:instructs`,
        source: serverNodeId,
        target: promptNodeId,
        kind: 'instructs',
        weight: 0.5,
        label: 'provides prompt',
      });
    }
  }

  for (const agent of input.agents ?? []) {
    const agentNodeId = nodeId('agent', agent.id);
    addNode({
      id: agentNodeId,
      kind: 'agent',
      label: agent.name,
      searchable: agent.name.toLowerCase(),
      risk: 0.5,
      tags: ['agent'],
    });
    for (const serverName of agent.callsServers) {
      const target = nodeId('server', serverName);
      if (!nodes.has(target)) continue;
      addEdge({
        id: `${agentNodeId}->${target}:calls`,
        source: agentNodeId,
        target,
        kind: 'calls',
        weight: 0.7,
        label: 'connects to',
      });
    }
  }

  const nodeList = [...nodes.values()];
  const edgeList = [...edges.values()];
  const stats = computeStats(nodeList, edgeList, servers);
  return { nodes: nodeList, edges: edgeList, servers, stats };
}

function isSensitiveUri(uri: string): boolean {
  const lower = uri.toLowerCase();
  return SENSITIVE_PATH_HINTS.some((h) => lower.includes(h)) || /\b(token|secret|credential|key)\b/.test(lower);
}

function activeCapabilities(caps: CapabilityModel): string[] {
  return (Object.keys(caps) as Array<keyof CapabilityModel>).filter((k) => caps[k]);
}

function toolRisk(caps: CapabilityModel): number {
  let risk = 0.2;
  if (caps.executesCommands) risk += 0.5;
  if (caps.readsEnvironment) risk += 0.4;
  if (caps.readsFiles) risk += 0.2;
  if (caps.readsDatabase) risk += 0.2;
  if (caps.makesNetworkRequests) risk += 0.15;
  if (caps.destructive) risk += 0.2;
  if (caps.writesFiles) risk += 0.15;
  if (caps.readOnly) risk -= 0.2;
  return Math.round(Math.max(0, Math.min(1, risk)) * 100) / 100;
}

function riskFromTransport(server: DiscoveredMcpServer): number {
  if (server.transport === 'http' || server.transport === 'sse') return 0.7;
  if (/npx|uvx|pipx/.test(server.command ?? '')) return 0.6;
  return 0.3;
}

/** Find every untrusted-input → credential path, and rank by reachability. */
function computeStats(nodes: GraphNode[], edges: GraphEdge[], servers: Record<string, string>): GraphStats {
  const adjacency = new Map<string, GraphEdge[]>();
  for (const edge of edges) {
    adjacency.set(edge.source, [...(adjacency.get(edge.source) ?? []), edge]);
  }

  // An exfiltration path is a concrete chain from something sensitive to
  // somewhere it can leave the host. The edges the builder draws are exactly
  // those chains, so start the search at the sensitive sources rather than at
  // tools: a tool that only reads is not a finding, a credential that reaches
  // the network is.
  const sensitiveSources = nodes.filter(
    (n) =>
      n.kind === 'credential' ||
      n.kind === 'dataset' ||
      n.kind === 'agent' ||
      n.kind === 'server',
  );
  const egressNodes = new Set(
    nodes.filter((n) => n.id.includes('network') || n.id.includes('shell')).map((n) => n.id),
  );

  const paths: string[][] = [];
  for (const source of sensitiveSources) {
    const queue: Array<{ id: string; path: string[] }> = [{ id: source.id, path: [source.id] }];
    const seen = new Set<string>([source.id]);
    while (queue.length > 0) {
      const current = queue.shift()!;
      if (current.path.length > 8) continue;
      for (const edge of adjacency.get(current.id) ?? []) {
        if (seen.has(edge.target)) continue;
        const nextPath = [...current.path, edge.target];
        if (egressNodes.has(edge.target)) {
          paths.push(nextPath);
          continue;
        }
        seen.add(edge.target);
        queue.push({ id: edge.target, path: nextPath });
      }
    }
  }

  const exfiltrationPaths = paths
    // A server that merely exposes a credential resource is not exfiltration
    // on its own; the path has to actually leave the host.
    .filter((p) => p.some((id) => id.includes('network') || id.includes('shell')))
    .sort((a, b) => b.length - a.length || a[0]!.localeCompare(b[0]!))
    .slice(0, 25);

  const exposedServers = [
    ...new Set(
      exfiltrationPaths
        .flatMap((p) => p)
        .map((id) => servers[id])
        .filter((v): v is string => Boolean(v)),
    ),
  ];

  return {
    serverCount: Object.keys(servers).length,
    toolCount: nodes.filter((n) => n.kind === 'tool').length,
    resourceCount: nodes.filter((n) => n.kind === 'resource').length,
    promptCount: nodes.filter((n) => n.kind === 'prompt').length,
    edgeCount: edges.length,
    exfiltrationPaths,
    maxDepth: paths.reduce((max, p) => Math.max(max, p.length), 0),
    exposedServers,
  };
}

/** Serialise for the D3 force-directed view in the dashboard. */
export function graphToD3(graph: SupplyChainGraph, options: { riskThreshold?: number } = {}) {
  const threshold = options.riskThreshold ?? 0;
  const nodes = graph.nodes.filter((n) => (n.risk ?? 0) >= threshold || n.kind === 'server');
  const ids = new Set(nodes.map((n) => n.id));
  return {
    nodes: nodes.map((n) => ({
      id: n.id,
      label: n.label,
      kind: n.kind,
      risk: n.risk ?? 0,
      tags: n.tags ?? [],
      serverId: n.serverId ?? null,
      radius: 4 + (n.risk ?? 0) * 14,
    })),
    links: graph.edges
      .filter((e) => ids.has(e.source) && ids.has(e.target))
      .map((e) => ({
        source: e.source,
        target: e.target,
        kind: e.kind,
        weight: e.weight,
        label: e.label ?? null,
      })),
    stats: graph.stats,
  };
}

/** A text rendering, useful in CLI output and in reports. */
export function graphToMermaid(graph: SupplyChainGraph): string {
  const lines = ['```mermaid', 'graph LR'];
  const shape = (kind: GraphNodeKind): string => {
    switch (kind) {
      case 'server':
        return '[[]]';
      case 'credential':
        return '[(%)]';
      case 'dataset':
        return '[(%)]';
      case 'tool':
        return '[]';
      case 'external-service':
        return '([/])';
      default:
        return '[]';
    }
  };
  const safe = (label: string) => label.replace(/["[\]{}]/g, '').replace(/:/g, ' ');
  for (const node of graph.nodes) {
    const color =
      (node.risk ?? 0) >= 0.8 ? '#dc2626' : (node.risk ?? 0) >= 0.5 ? '#f59e0b' : '#64748b';
    lines.push(`  ${mermaidId(node.id)}${shape(node.kind)}["${safe(node.label)}"]`);
    lines.push(`  class ${mermaidId(node.id)} risk-${(node.risk ?? 0) >= 0.8 ? 'high' : (node.risk ?? 0) >= 0.5 ? 'med' : 'low'}`);
    void color;
  }
  for (const edge of graph.edges) {
    if (edge.kind === 'exposes' && (graph.nodes.find((n) => n.id === edge.target)?.risk ?? 0) < 0.5) continue;
    lines.push(`  ${mermaidId(edge.source)} -->|${edge.kind}| ${mermaidId(edge.target)}`);
  }
  lines.push('  classDef risk-high fill:#fee2e2,stroke:#dc2626,stroke-width:2px');
  lines.push('  classDef risk-med fill:#fef3c7,stroke:#f59e0b');
  lines.push('  classDef risk-low fill:#f1f5f9,stroke:#94a3b8');
  lines.push('```');
  return lines.join('\n');
}

function mermaidId(id: string): string {
  return `n_${id.replace(/[^A-Za-z0-9_]/g, '_')}`;
}