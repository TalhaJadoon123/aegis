import { shannonEntropy } from '../fingerprint.js';

/**
 * Behavioural fingerprinting.
 *
 * An agent's behaviour is more stable than its prompts. The distribution of
 * which tools it calls, where it reaches on the network, and which files it
 * touches is a signature — and a deviation from that signature is a strong
 * signal of compromise, misconfiguration, or a new capability the operator
 * never approved.
 *
 * This is the runtime complement to static scanning: static analysis tells you
 * what an agent *could* do, this tells you what it *did*.
 */

export type EventKind =
  | 'tool-call'
  | 'tool-result'
  | 'network'
  | 'file-read'
  | 'file-write'
  | 'process-spawn'
  | 'prompt'
  | 'completion'
  | 'error';

export interface BehaviorEvent {
  kind: EventKind;
  /** Tool name, hostname, path, or process name depending on kind. */
  target: string;
  timestamp: number;
  /** Truncated argument or result summary. */
  detail?: string;
  /** Bytes involved, where meaningful. */
  bytes?: number;
  /** Tool call arguments, redacted. */
  args?: Record<string, unknown>;
  /** Whether the operation was blocked by a policy. */
  blocked?: boolean;
}

export interface BehavioralFingerprint {
  /** Stable hash of the behavioural profile. */
  id: string;
  /** Distinct tools used, with relative frequency. */
  toolUsage: Array<{ name: string; count: number; share: number }>;
  /** Distinct network destinations, by registrable host. */
  networkHosts: string[];
  /** Filesystem paths touched, grouped by directory. */
  fileAccess: Array<{ directory: string; reads: number; writes: number }>;
  /** Processes spawned. */
  processes: string[];
  /** Event counts by kind. */
  eventCounts: Record<EventKind, number>;
  /** Shannon entropy of the tool-usage distribution; low means repetitive. */
  toolEntropy: number;
  /** Distinct (tool, target) pairs seen — the agent's reach. */
  distinctTargets: number;
  /** Mean seconds between events. */
  meanIntervalMs: number;
  /** Binned timeline, for shape comparison. */
  timeline: number[];
  /** Duration of the observed window. */
  windowMs: number;
  eventCount: number;
}

const TOOL_ENTROPY_FLOOR = 1.0;

/**
 * Compute a fingerprint from an event stream.
 *
 * Everything here is a *distribution*, not a sequence. A conversation with the
 * same prompts in a different order produces the same fingerprint, which is the
 * point: we want to detect behavioural change, not transcript churn.
 */
export function fingerprintBehavior(events: readonly BehaviorEvent[]): BehavioralFingerprint {
  const eventCounts = {} as Record<EventKind, number>;
  const toolCounts = new Map<string, number>();
  const hosts = new Set<string>();
  const processes = new Set<string>();
  const dirs = new Map<string, { reads: number; writes: number }>();
  const targets = new Set<string>();
  const timeline: number[] = [];

  let previous: number | undefined;
  let intervalTotal = 0;

  for (const event of events) {
    eventCounts[event.kind] = (eventCounts[event.kind] ?? 0) + 1;

    switch (event.kind) {
      case 'tool-call':
        toolCounts.set(event.target, (toolCounts.get(event.target) ?? 0) + 1);
        targets.add(`${event.target}`);
        break;
      case 'network':
        hosts.add(hostOf(event.target));
        targets.add(`net:${hostOf(event.target)}`);
        break;
      case 'file-read':
      case 'file-write': {
        const dir = directoryOf(event.target);
        const entry = dirs.get(dir) ?? { reads: 0, writes: 0 };
        if (event.kind === 'file-read') entry.reads++;
        else entry.writes++;
        dirs.set(dir, entry);
        targets.add(`file:${dir}`);
        break;
      }
      case 'process-spawn':
        processes.add(event.target);
        targets.add(`proc:${event.target}`);
        break;
      default:
        break;
    }

    if (previous !== undefined) intervalTotal += event.timestamp - previous;
    previous = event.timestamp;
    timeline.push(event.timestamp);
  }

  const totalTools = [...toolCounts.values()].reduce((a, b) => a + b, 0);
  const toolUsage = [...toolCounts.entries()]
    .map(([name, count]) => ({ name, count, share: totalTools === 0 ? 0 : round4(count / totalTools) }))
    .sort((a, b) => b.count - a.count);

  const toolEntropy = totalTools === 0 ? 0 : shannonEntropy(toolUsage.map((t) => t.name.repeat(t.count)).join(''));

  return {
    id: fingerprintId(eventCounts, toolUsage, [...hosts], [...dirs.keys()]),
    toolUsage,
    networkHosts: [...hosts].sort(),
    fileAccess: [...dirs.entries()]
      .map(([directory, v]) => ({ directory, ...v }))
      .sort((a, b) => b.reads + b.writes - (a.reads + a.writes)),
    processes: [...processes].sort(),
    eventCounts,
    toolEntropy: round4(toolEntropy),
    distinctTargets: targets.size,
    meanIntervalMs: events.length > 1 ? Math.round(intervalTotal / (events.length - 1)) : 0,
    timeline: binTimeline(timeline),
    windowMs: events.length > 0 ? (events[events.length - 1]!.timestamp - events[0]!.timestamp) : 0,
    eventCount: events.length,
  };
}

function fingerprintId(
  counts: Record<EventKind, number>,
  tools: Array<{ name: string; share: number }>,
  hosts: string[],
  dirs: string[],
): string {
  // Quantised shares keep the id stable against small sampling noise while
  // still changing when the distribution genuinely shifts.
  const shape = [
    ...Object.entries(counts).sort().map(([k, v]) => `${k}:${v}`),
    ...tools.map((t) => `${t.name}@${Math.round(t.share * 10)}`),
    ...[...hosts].sort().map((h) => `host:${h}`),
    ...[...dirs].sort().map((d) => `dir:${d}`),
  ].join('|');
  return `bfp_${hash(shape)}`;
}

function binTimeline(timestamps: number[]): number[] {
  // 10 buckets across the observed window, so fingerprint comparison is
  // insensitive to absolute time.
  const buckets = new Array(10).fill(0);
  if (timestamps.length === 0) return buckets;
  const start = timestamps[0]!;
  const end = timestamps[timestamps.length - 1]!;
  const span = Math.max(1, end - start);
  for (const t of timestamps) {
    const index = Math.min(9, Math.floor(((t - start) / span) * 10));
    buckets[index] = (buckets[index] ?? 0) + 1;
  }
  return buckets;
}

function hostOf(target: string): string {
  try {
    return new URL(target).hostname.toLowerCase();
  } catch {
    // Not a URL: fall back to the first path segment.
    return target.split('/')[0]!.toLowerCase();
  }
}

function directoryOf(path: string): string {
  const normalised = path.replace(/\\/g, '/');
  const index = normalised.lastIndexOf('/');
  return index <= 0 ? '/' : normalised.slice(0, index);
}

function hash(value: string): string {
  let h = 0;
  for (let i = 0; i < value.length; i++) h = (Math.imul(31, h) + value.charCodeAt(i)) | 0;
  return (h >>> 0).toString(16).padStart(8, '0');
}

function round4(value: number): number {
  return Math.round(value * 10_000) / 10_000;
}

/**
 * Compare two fingerprints.
 *
 * Returns a divergence score in [0, 1] plus human-readable reasons. The
 * reasons matter: "this agent started reaching a new host" is actionable, and
 * "similarity 0.83" is not.
 */
export function compareFingerprints(
  baseline: BehavioralFingerprint,
  observed: BehavioralFingerprint,
): { divergence: number; reasons: string[]; novel: string[] } {
  const reasons: string[] = [];
  const novel: string[] = [];
  let divergence = 0;

  const baseTools = new Map(baseline.toolUsage.map((t) => [t.name, t.share]));
  for (const tool of observed.toolUsage) {
    if (!baseTools.has(tool.name)) {
      novel.push(tool.name);
      divergence += 0.2;
    }
  }

  const observedHosts = new Set(observed.networkHosts);
  const newHosts = [...observedHosts].filter((h) => !baseline.networkHosts.includes(h));
  if (newHosts.length > 0) {
    novel.push(...newHosts);
    reasons.push(`Reached ${newHosts.length} previously unseen host(s): ${newHosts.join(', ')}`);
    divergence += Math.min(0.35, newHosts.length * 0.15);
  }

  const baseDirs = new Set(baseline.fileAccess.map((f) => f.directory));
  const newDirs = observed.fileAccess.map((f) => f.directory).filter((d) => !baseDirs.has(d));
  if (newDirs.length > 0) {
    novel.push(...newDirs);
    reasons.push(`Read or wrote ${newDirs.length} new director(ies): ${newDirs.join(', ')}`);
    divergence += Math.min(0.3, newDirs.length * 0.1);
  }

  const newProcs = observed.processes.filter((p) => !baseline.processes.includes(p));
  if (newProcs.length > 0) {
    novel.push(...newProcs);
    reasons.push(`Spawned ${newProcs.length} new process(es): ${newProcs.join(', ')}`);
    divergence += Math.min(0.3, newProcs.length * 0.15);
  }

  // Repetition is itself a signal: a low-entropy tool distribution is what a
  // runaway loop looks like.
  if (observed.toolEntropy > 0 && observed.toolEntropy < TOOL_ENTROPY_FLOOR) {
    reasons.push(
      `Tool usage is highly repetitive (entropy ${observed.toolEntropy.toFixed(2)}), consistent with a loop`,
    );
    divergence += 0.15;
  }

  if (observed.distinctTargets > baseline.distinctTargets * 2 && baseline.distinctTargets > 0) {
    reasons.push(
      `Reach grew from ${baseline.distinctTargets} to ${observed.distinctTargets} distinct targets`,
    );
    divergence += 0.2;
  }

  return { divergence: Math.min(1, round4(divergence)), reasons, novel: [...new Set(novel)] };
}

export { TOOL_ENTROPY_FLOOR };