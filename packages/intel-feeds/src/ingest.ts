import {
  addEdge,
  addNode,
  createGraph,
  type AttackGraph,
  type EdgeKind,
  type NodeKind,
  type Provenance,
  type Severity,
} from '../../core/src/intel/graph.js';
import type { FeedRecord } from './feeds.js';

/**
 * Feed → attack graph.
 *
 * The transformation is where threat intelligence becomes useful: a CVE list is
 * a list, but "this CVE is reachable from prompt injection" is actionable. Each
 * feed record becomes a `cve` node, and agent-relevant tags become the edges
 * that connect it to techniques already in the graph.
 */

export interface FeedOptions {
  /** Only include records that look agent-relevant. Default true. */
  agentRelevantOnly?: boolean;
  /** Minimum severity to include. */
  minSeverity?: Severity;
  now?: string;
}

/**
 * Add feed records to an existing attack graph.
 *
 * Edges are inferred from the record's own tags rather than asserted by the
 * feed, and are marked unverified — a machine reading a CVE description is a
 * hypothesis, not a finding.
 */
export function ingestFeed(
  graph: AttackGraph,
  records: readonly FeedRecord[],
  options: FeedOptions = {},
): { added: number; merged: number; edges: number; skipped: number } {
  const now = options.now ?? new Date().toISOString();
  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const floor = options.minSeverity ? order[options.minSeverity] : order.info;
  const agentOnly = options.agentRelevantOnly ?? true;

  let added = 0;
  let merged = 0;
  let skipped = 0;
  let edges = 0;

  for (const record of records) {
    if (agentOnly && !record.agentRelevant) {
      skipped++;
      continue;
    }
    if (order[record.severity] > floor) {
      skipped++;
      continue;
    }

    const provenance: Provenance = {
      kind: 'advisory',
      source: record.source,
      observedAt: record.published || now,
      excerpt: record.description.slice(0, 300),
      hash: hashOf(`${record.id}:${record.source}`),
    };

    const result = addNode(graph, {
      kind: 'cve',
      label: record.id,
      description: `${record.title}\n\n${record.description}`.trim(),
      severity: record.severity,
      confidence: 'high',
      references: record.cwes,
      tags: record.tags,
      provenance,
    });

    if (result.status === 'added') added++;
    else if (result.status === 'merged') merged++;

    // Connect to techniques the record's tags imply.
    for (const { technique, kind } of inferEdges(record)) {
      const target = findByLabel(graph, technique);
      if (!target || !result.node) continue;
      const edge = addEdge(graph, {
        source: result.node.id,
        target: target.id,
        kind,
        weight: 0.6,
        description: `${record.id} ${kind} ${technique}`,
        provenance,
        unverified: true,
      });
      if (edge.status === 'added') edges++;
    }
  }

  return { added, merged, edges, skipped };
}

/** Map feed tags onto graph techniques. */
function inferEdges(record: FeedRecord): Array<{ technique: string; kind: EdgeKind }> {
  const out: Array<{ technique: string; kind: EdgeKind }> = [];
  const has = (...needles: string[]) => needles.some((n) => record.tags.includes(n));

  if (has('prompt-injection')) out.push({ technique: 'prompt-injection', kind: 'exploits' });
  if (has('mcp')) out.push({ technique: 'tool-poisoning', kind: 'exploits' });
  if (has('agentic-ai', 'agent-framework')) out.push({ technique: 'excessive-agency', kind: 'exploits' });
  if (has('llm')) out.push({ technique: 'indirect-injection', kind: 'exploits' });
  if (has('model-provider')) out.push({ technique: 'untrusted-dependency', kind: 'exploits' });
  if (has('tooling')) out.push({ technique: 'untrusted-dependency', kind: 'exploits' });

  // A CVE that discloses code execution bears directly on agent code execution.
  if (/\b(?:rce|remote code execution|command injection|arbitrary code)\b/i.test(record.description)) {
    out.push({ technique: 'excessive-agency', kind: 'enables' });
  }
  if (/\bpath traversal\b|\.\.\/\.\./i.test(record.description)) {
    out.push({ technique: 'path-traversal', kind: 'exploits' });
  }
  if (/\bssrf\b|metadata service/i.test(record.description)) {
    out.push({ technique: 'ssrf', kind: 'exploits' });
  }

  return dedupePairs(out);
}

function dedupePairs(pairs: Array<{ technique: string; kind: EdgeKind }>) {
  const seen = new Set<string>();
  const out: Array<{ technique: string; kind: EdgeKind }> = [];
  for (const pair of pairs) {
    const key = `${pair.technique}:${pair.kind}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(pair);
  }
  return out;
}

function findByLabel(graph: AttackGraph, label: string) {
  for (const node of graph.nodes.values()) {
    if (node.label === label) return node;
  }
  return undefined;
}

function hashOf(value: string): string {
  let h = 0;
  for (let i = 0; i < value.length; i++) h = (Math.imul(31, h) + value.charCodeAt(i)) | 0;
  return (h >>> 0).toString(16).padStart(8, '0');
}

/** A summary suitable for a CLI banner or an email. */
export function summariseFeed(records: readonly FeedRecord[]): {
  total: number;
  agentRelevant: number;
  critical: number;
  high: number;
  byEcosystem: Record<string, number>;
} {
  const byEcosystem: Record<string, number> = {};
  let agentRelevant = 0;
  let critical = 0;
  let high = 0;

  for (const record of records) {
    if (record.agentRelevant) agentRelevant++;
    if (record.severity === 'critical') critical++;
    if (record.severity === 'high') high++;
    const eco = record.package?.ecosystem ?? 'unknown';
    byEcosystem[eco] = (byEcosystem[eco] ?? 0) + 1;
  }

  return { total: records.length, agentRelevant, critical, high, byEcosystem };
}

export { createGraph };
export type { NodeKind };