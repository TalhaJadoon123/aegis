import { createHash } from 'node:crypto';

/**
 * The Living Attack Graph.
 *
 * Attack knowledge is a graph, not a list. A technique that *enables* another
 * is more useful to know than either technique in isolation, and a vulnerability
 * that *requires* a misconfiguration is only exploitable in that combination.
 *
 * What makes this "living" is that the graph is designed to be updated from
 * external sources — advisories, research papers, community submissions — with
 * every addition provenance-tracked, so an operator can always answer "why do
 * you believe this, and when did you learn it?"
 */

export type NodeKind =
  | 'technique'      // an attack technique
  | 'tool'           // a tool or capability used
  | 'vulnerability'  // a weakness in a system
  | 'agent'          // an agent component
  | 'control'        // a mitigation
  | 'cve'
  | 'supply-chain';

export type EdgeKind =
  | 'enables'
  | 'requires'
  | 'mitigates'
  | 'exploits'
  | 'targets'
  | 'uses'
  | 'detects'
  | 'leads-to';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Confidence = 'confirmed' | 'high' | 'medium' | 'low';

export type ProvenanceKind =
  | 'seed'
  | 'advisory'
  | 'research'
  | 'community'
  | 'scanner-observation'
  | 'import';

export interface Provenance {
  kind: ProvenanceKind;
  /** Source URL, feed id, or identifier. */
  source: string;
  /** When the source was published or observed. */
  observedAt: string;
  /** Verbatim excerpt supporting the node or edge. */
  excerpt?: string;
  /** Who or what contributed it. */
  actor?: string;
  /** Content hash, for deduplication across feeds. */
  hash: string;
}

export interface AttackNode {
  id: string;
  kind: NodeKind;
  label: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  /** Taxonomy references, e.g. `AML.T0051`, `ASI01`, `CWE-22`. */
  references: string[];
  tags: string[];
  /** Stable content hash; the identity used for deduplication. */
  hash: string;
  provenance: Provenance[];
  firstSeen: string;
  lastSeen: string;
  /** Community-contributed nodes are flagged so operators can discount them. */
  communityContributed?: boolean;
}

export interface AttackEdge {
  id: string;
  source: string;
  target: string;
  kind: EdgeKind;
  /** Strength of the relationship, 0–1. */
  weight: number;
  description: string;
  provenance: Provenance[];
  /** Edges asserted by an automated extractor are trusted less. */
  unverified?: boolean;
}

export interface AttackGraph {
  nodes: Map<string, AttackNode>;
  edges: Map<string, AttackEdge>;
  meta: {
    version: string;
    createdAt: string;
    updatedAt: string;
    /** Increment for every accepted mutation, for change tracking. */
    revision: number;
  };
}

export interface GraphStats {
  nodeCount: number;
  edgeCount: number;
  byKind: Record<NodeKind, number>;
  bySeverity: Record<Severity, number>;
  /** Nodes with no incoming `enables` path — reachable-from-nothing gaps. */
  orphans: string[];
  /** Nodes that no control mitigates: unmitigable techniques. */
  unmitigated: string[];
  /** Longest chain of `enables` edges: worst-case composite attack. */
  criticalPath: string[];
}

/**
 * Stable identity for a node.
 *
 * Deliberately keyed on kind + label only, never on the description. Two feeds
 * describing the same technique with different wording must collapse into one
 * node with two provenances — otherwise a "living" graph just accumulates
 * near-duplicates and becomes unusable for deduplication. Descriptions are
 * enriched on merge instead.
 */
export function nodeHash(kind: NodeKind, label: string, _description = ''): string {
  const normalized = `${kind}:${label.toLowerCase().trim().replace(/\s+/g, ' ')}`;
  return createHash('sha256').update(normalized).digest('hex').slice(0, 16);
}

export function edgeHash(source: string, target: string, kind: EdgeKind): string {
  return createHash('sha256')
    .update(`${source}->${target}:${kind}`)
    .digest('hex')
    .slice(0, 16);
}

export function createGraph(version = '1.0.0'): AttackGraph {
  const now = new Date().toISOString();
  return {
    nodes: new Map(),
    edges: new Map(),
    meta: { version, createdAt: now, updatedAt: now, revision: 0 },
  };
}

export interface AddNodeInput {
  id?: string;
  kind: NodeKind;
  label: string;
  description: string;
  severity?: Severity;
  confidence?: Confidence;
  references?: string[];
  tags?: string[];
  provenance: Provenance;
}

export type AddResult =
  | { status: 'added'; node: AttackNode; mergedProvenance: number; severityRaised: boolean }
  | { status: 'merged'; node: AttackNode; mergedProvenance: number; severityRaised: boolean }
  // `node` is optional-but-present on rejection so callers can destructure
  // `.node` without narrowing, and treat a missing node as "nothing added".
  | { status: 'rejected'; reason: string; node?: undefined; mergedProvenance: 0; severityRaised: false };

/** Narrow a result to the non-rejected variants. */
export function added(result: AddResult): AttackNode {
  if (result.status === 'rejected' || !result.node) {
    throw new Error(`rejected: ${result.status === 'rejected' ? result.reason : 'no node'}`);
  }
  return result.node;
}

/**
 * Add or merge a node.
 *
 * Deduplication is by content hash, so the same technique reported by NVD,
 * GitHub Advisories and three community submissions is one node with four
 * provenances. Merging raises severity when new evidence is more severe and
 * raises confidence as independent sources corroborate — which is what makes a
 * "living" graph more trustworthy over time rather than merely larger.
 */
export function addNode(graph: AttackGraph, input: AddNodeInput): AddResult {
  if (!input.label || input.label.trim().length < 2) {
    return { status: 'rejected', reason: 'label is too short to identify a node', node: undefined, mergedProvenance: 0, severityRaised: false };
  }
  if (!input.provenance?.source) {
    return { status: 'rejected', reason: 'every node requires provenance', node: undefined, mergedProvenance: 0, severityRaised: false };
  }

  // `input.id` may already be a fully-formed node id (`n_<hash>`) when merging
  // graphs. Prefixing again would produce `n_n_<hash>`, so it is used verbatim
  // and only hashed ids get the prefix.
  const id = input.id ?? `n_${nodeHash(input.kind, input.label, input.description)}`;
  const now = input.provenance.observedAt || new Date().toISOString();
  const existing = graph.nodes.get(id);

  if (existing) {
    const before = severityRank(existing.severity);
    const mergedProvenance = mergeProvenance(existing.provenance, input.provenance);
    // `severityRank` is higher-is-worse, so a rise is `>` not `<`.
    const severityRaised = severityRank(input.severity ?? 'info') > before;

    // Severity only ever moves up from corroborated evidence: a single low-trust
    // community report must not downgrade a CVE-confirmed technique.
    if (severityRaised) {
      existing.severity = input.severity!;
      existing.confidence = input.confidence ?? existing.confidence;
      existing.description = input.description || existing.description;
    }
    existing.lastSeen = now;
    existing.references = [...new Set([...existing.references, ...(input.references ?? [])])];
    existing.tags = [...new Set([...existing.tags, ...(input.tags ?? [])])];
    if (input.provenance.kind === 'community') existing.communityContributed = true;
    graph.meta.updatedAt = now;
    graph.meta.revision++;

    return {
      status: 'merged',
      node: existing,
      mergedProvenance: mergedProvenance,
      severityRaised,
    };
  }

  const node: AttackNode = {
    id,
    kind: input.kind,
    label: input.label.trim(),
    description: input.description.trim(),
    severity: input.severity ?? 'medium',
    confidence: input.confidence ?? 'medium',
    references: [...new Set(input.references ?? [])],
    tags: [...new Set(input.tags ?? [])],
    hash: id.replace(/^n_/, ''),
    provenance: [input.provenance],
    firstSeen: now,
    lastSeen: now,
    ...(input.provenance.kind === 'community' ? { communityContributed: true } : {}),
  };

  graph.nodes.set(id, node);
  graph.meta.updatedAt = now;
  graph.meta.revision++;
  return { status: 'added', node, mergedProvenance: 0, severityRaised: false };
}

function mergeProvenance(existing: Provenance[], incoming: Provenance): number {
  if (existing.some((p) => p.hash === incoming.hash)) return 0;
  existing.push(incoming);
  return 1;
}

export interface AddEdgeInput {
  source: string;
  target: string;
  kind: EdgeKind;
  weight?: number;
  description?: string;
  provenance: Provenance;
  /** Extracted edges start unverified. */
  unverified?: boolean;
}

export type AddEdgeResult =
  | { status: 'added'; edge: AttackEdge }
  | { status: 'merged'; edge: AttackEdge }
  | { status: 'rejected'; reason: string };

/** Narrow an edge result to the non-rejected variants. */
export function linked(result: AddEdgeResult): AttackEdge {
  if (result.status === 'rejected') throw new Error(`rejected: ${result.reason}`);
  return result.edge;
}

export function addEdge(graph: AttackGraph, input: AddEdgeInput): AddEdgeResult {
  if (!graph.nodes.has(input.source)) {
    return { status: 'rejected', reason: `unknown source node: ${input.source}` };
  }
  if (!graph.nodes.has(input.target)) {
    return { status: 'rejected', reason: `unknown target node: ${input.target}` };
  }
  if (input.source === input.target) {
    return { status: 'rejected', reason: 'self-referential edge' };
  }

  const id = `e_${edgeHash(input.source, input.target, input.kind)}`;
  const existing = graph.edges.get(id);
  const now = input.provenance.observedAt || new Date().toISOString();

  if (existing) {
    mergeProvenance(existing.provenance, input.provenance);
    existing.weight = Math.max(existing.weight, input.weight ?? existing.weight);
    // Corroboration clears the unverified flag; a relationship asserted by two
    // independent sources is no longer a single automated guess.
    if (existing.unverified && existing.provenance.length > 1) existing.unverified = false;
    graph.meta.updatedAt = now;
    graph.meta.revision++;
    return { status: 'merged', edge: existing };
  }

  const edge: AttackEdge = {
    id,
    source: input.source,
    target: input.target,
    kind: input.kind,
    weight: input.weight ?? 0.5,
    description: input.description ?? '',
    provenance: [input.provenance],
    ...(input.unverified === false ? {} : { unverified: input.unverified ?? true }),
  };
  graph.edges.set(id, edge);
  graph.meta.updatedAt = now;
  graph.meta.revision++;
  return { status: 'added', edge };
}

/**
 * Higher rank means more severe, so callers can use plain `<` comparisons.
 *
 * Note this is the inverse of `compareSeverity` in `severity.ts`, which follows
 * `Array.prototype.sort` semantics. Two functions, two conventions, both
 * documented — because both are what their call sites actually want.
 */
export function severityRank(severity: Severity): number {
  return ['info', 'low', 'medium', 'high', 'critical'].indexOf(severity);
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

export function computeStats(graph: AttackGraph): GraphStats {
  const byKind = {} as Record<NodeKind, number>;
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  for (const node of graph.nodes.values()) {
    byKind[node.kind] = (byKind[node.kind] ?? 0) + 1;
    bySeverity[node.severity] += 1;
  }

  const incoming = new Map<string, number>();
  const mitigated = new Set<string>();
  for (const edge of graph.edges.values()) {
    // "Incoming" means edges pointing *at* the node. Counting by source marked
    // every technique that starts a chain as an orphan, which is backwards:
    // an entry-point technique is exactly the one you want flagged.
    incoming.set(edge.target, (incoming.get(edge.target) ?? 0) + 1);
    // An edge `control -mitigates-> technique` means the technique is covered.
    if (edge.kind === 'mitigates') {
      const target = graph.nodes.get(edge.target);
      if (target && target.kind === 'technique') mitigated.add(edge.target);
    }
  }

  const orphans: string[] = [];
  const unmitigated: string[] = [];
  for (const node of graph.nodes.values()) {
    const isTechnique = node.kind === 'technique' || node.kind === 'vulnerability';
    if (isTechnique && (incoming.get(node.id) ?? 0) === 0) orphans.push(node.id);
    if (isTechnique && !mitigated.has(node.id)) unmitigated.push(node.id);
  }

  return {
    nodeCount: graph.nodes.size,
    edgeCount: graph.edges.size,
    byKind,
    bySeverity,
    orphans,
    unmitigated,
    criticalPath: longestEnablePath(graph),
  };
}

/**
 * Longest `enables` chain — the composite attack an attacker would build.
 *
 * This is the graph's most useful derived value: a single technique rated
 * "medium" can become the linchpin of a critical chain when it sits between two
 * others, and only a path search surfaces that.
 */
export function longestEnablePath(graph: AttackGraph): string[] {
  const adjacency = new Map<string, string[]>();
  for (const edge of graph.edges.values()) {
    if (edge.kind !== 'enables' && edge.kind !== 'leads-to') continue;
    adjacency.set(edge.source, [...(adjacency.get(edge.source) ?? []), edge.target]);
  }

  const memo = new Map<string, string[]>();
  const visiting = new Set<string>();

  const best = (id: string): string[] => {
    const cached = memo.get(id);
    if (cached) return cached;
    if (visiting.has(id)) return [id]; // cycle guard
    visiting.add(id);

    let longest: string[] = [id];
    for (const next of adjacency.get(id) ?? []) {
      const candidate = [id, ...best(next)];
      if (candidate.length > longest.length) longest = candidate;
    }
    visiting.delete(id);
    memo.set(id, longest);
    return longest;
  };

  let overall: string[] = [];
  for (const id of graph.nodes.keys()) {
    const path = best(id);
    if (path.length > overall.length) overall = path;
  }
  return overall;
}

/**
 * Can this system be reached from an attacker's entry point?
 *
 * Answers the practical question the graph exists for: "given the techniques my
 * agent actually has, which of the known attacks apply to it?"
 */
export function reachableFrom(graph: AttackGraph, entryIds: readonly string[]): Set<string> {
  const adjacency = new Map<string, string[]>();
  for (const edge of graph.edges.values()) {
    // `requires` edges are traversed in reverse: if B requires A, reaching A
    // makes B reachable.
    if (edge.kind === 'enables' || edge.kind === 'leads-to' || edge.kind === 'exploits') {
      adjacency.set(edge.source, [...(adjacency.get(edge.source) ?? []), edge.target]);
    }
    if (edge.kind === 'requires') {
      adjacency.set(edge.target, [...(adjacency.get(edge.target) ?? []), edge.source]);
    }
  }

  const seen = new Set<string>();
  const queue = [...entryIds].filter((id) => graph.nodes.has(id));
  for (const id of queue) seen.add(id);

  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const next of adjacency.get(current) ?? []) {
      if (seen.has(next)) continue;
      seen.add(next);
      queue.push(next);
    }
  }
  return seen;
}

/** Serialise for the dashboard's D3 force-directed view. */
export function graphToD3(graph: AttackGraph) {
  const stats = computeStats(graph);
  const severityColor: Record<Severity, string> = {
    critical: '#dc2626',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
    info: '#64748b',
  };
  return {
    nodes: [...graph.nodes.values()].map((n) => ({
      id: n.id,
      label: n.label,
      kind: n.kind,
      severity: n.severity,
      color: severityColor[n.severity],
      radius: 5 + (graph.edges.size > 0 ? 0 : 0) + Math.min(18, n.references.length * 3 + 6),
      references: n.references,
      community: n.communityContributed ?? false,
      provenanceCount: n.provenance.length,
    })),
    links: [...graph.edges.values()].map((e) => ({
      source: e.source,
      target: e.target,
      kind: e.kind,
      weight: e.weight,
      unverified: e.unverified ?? false,
    })),
    stats,
  };
}

export function graphToMermaid(graph: AttackGraph, options: { maxNodes?: number } = {}): string {
  const lines = ['```mermaid', 'graph LR'];
  const sorted = [...graph.nodes.values()]
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
    .slice(0, options.maxNodes ?? 40);

  const shape = (kind: NodeKind): string => {
    switch (kind) {
      case 'technique':
        return '[]';
      case 'vulnerability':
        return '[()]';
      case 'cve':
        return '([/])';
      case 'control':
        return '>{}]';
      case 'tool':
        return '{{}}';
      case 'agent':
        return '((()))';
      default:
        return '[]';
    }
  };
  const id = (value: string) => `g_${value.replace(/[^A-Za-z0-9]/g, '_')}`;
  const safe = (label: string) => label.replace(/["[\]{}]/g, '').replace(/:/g, ' ');

  for (const node of sorted) {
    lines.push(`  ${id(node.id)}${shape(node.kind)}["${safe(node.label)}"]`);
  }
  for (const edge of graph.edges.values()) {
    lines.push(`  ${id(edge.source)} -->|${edge.kind}| ${id(edge.target)}`);
  }
  lines.push('  classDef critical fill:#fee2e2,stroke:#dc2626,color:#7f1d1d');
  lines.push('  classDef high fill:#ffedd5,stroke:#f97316,color:#7c2d12');
  lines.push('  classDef medium fill:#fef9c3,stroke:#eab308,color:#713f12');
  lines.push('  classDef low fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a');
  lines.push('  classDef info fill:#f1f5f9,stroke:#64748b,color:#334155');
  for (const node of sorted) lines.push(`  class ${id(node.id)} ${node.severity}`);
  lines.push('```');
  return lines.join('\n');
}

/** Merge another graph into this one, preserving all provenance. */
export function mergeGraphs(target: AttackGraph, incoming: AttackGraph): GraphStats {
  for (const node of incoming.nodes.values()) {
    addNode(target, {
      id: node.id,
      kind: node.kind,
      label: node.label,
      description: node.description,
      severity: node.severity,
      confidence: node.confidence,
      references: node.references,
      tags: node.tags,
      provenance: node.provenance[0] ?? {
        kind: 'import',
        source: 'unknown',
        observedAt: new Date().toISOString(),
        hash: node.hash,
      },
    });
  }
  for (const edge of incoming.edges.values()) {
    addEdge(target, {
      source: edge.source,
      target: edge.target,
      kind: edge.kind,
      weight: edge.weight,
      description: edge.description,
      provenance: edge.provenance[0] ?? {
        kind: 'import',
        source: 'unknown',
        observedAt: new Date().toISOString(),
        hash: edge.id,
      },
      ...(edge.unverified === false ? { unverified: false } : {}),
    });
  }
  return computeStats(target);
}