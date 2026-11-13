import { spawn } from 'node:child_process';
import type { BehaviorEvent, EventKind } from './fingerprint.js';
import { fingerprintBehavior, compareFingerprints, type BehavioralFingerprint } from './fingerprint.js';
import type { Finding, Severity } from '../types.js';

/**
 * Runtime sandbox and anomaly detection.
 *
 * Two execution modes, because teams need both:
 *
 *  - **Observed**: run the agent for real and record what it does. Highest
 *    fidelity; only appropriate in a disposable environment.
 *  - **Shadow**: run alongside production and *predict* what the agent would do
 *    without letting it act. Instrumented tool calls are evaluated against
 *    policy and reported, but the underlying operation is never executed.
 *
 * Shadow mode is the one that can run in production: it answers "what would
 * this agent do with this input?" without creating the risk of asking.
 *
 * Note on isolation: full syscall-level isolation needs a container runtime
 * (see infra/sandbox/Dockerfile). What this runner provides is *observation and
 * enforcement at the tool boundary* — the layer where an agent's actions are
 * actually expressed — which is the layer that matters for agent security even
 * when the process itself is not namespaced.
 */

export interface SandboxOptions {
  command: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
  maxRecordedBytes?: number;
  /** Predict actions without executing them. */
  shadow?: boolean;
  /** Baseline fingerprint to compare against. */
  baseline?: BehavioralFingerprint;
  /** Policies to enforce. In shadow mode these are simulated. */
  policies?: AgentPolicy[];
  logger?: { info(m: string, meta?: unknown): void; warn(m: string, meta?: unknown): void; debug(m: string): void };
}

export interface SandboxResult {
  events: BehaviorEvent[];
  fingerprint: BehavioralFingerprint;
  anomalies: Finding[];
  findings: Finding[];
  durationMs: number;
  exitCode: number | null;
  eventCount: number;
  timedOut: boolean;
  stdout: string;
  stderr: string;
}

/**
 * An agent policy: a runtime rule about what the agent may do.
 *
 * These are the deployable form of Aegis's findings — a finding says "this
 * agent can read /etc/passwd"; a policy makes it stop.
 */
export interface AgentPolicy {
  id: string;
  name: string;
  /** Block an action entirely. */
  deny?: {
    kind: EventKind;
    /** Substring or glob matched against the target. */
    target: string;
    reason: string;
  }[];
  /** Require approval before an action. In shadow mode this is always flagged. */
  requireApproval?: Array<{ kind: EventKind; target: string; reason: string }>;
  severity?: Severity;
}

export const DEFAULT_POLICIES: AgentPolicy[] = [
  {
    id: 'aegis-policy-default',
    name: 'Aegis baseline runtime policy',
    deny: [
      { kind: 'file-read', target: '/etc/passwd', reason: 'Reading /etc/passwd has no legitimate agent use and precedes privilege escalation.' },
      { kind: 'file-read', target: '/etc/shadow', reason: 'Reading /etc/shadow exposes password hashes.' },
      { kind: 'file-read', target: '.ssh', reason: 'Reading SSH keys is credential theft, not agent work.' },
      { kind: 'file-read', target: '.env', reason: 'Reading dotenv files places secrets in the model context.' },
      { kind: 'file-read', target: '.aws', reason: 'Reading cloud credentials enables account takeover.' },
      { kind: 'network', target: '169.254.169.254', reason: 'Cloud metadata endpoints hand out IAM credentials to anything that can reach them.' },
      { kind: 'network', target: 'metadata.google.internal', reason: 'Cloud metadata endpoints hand out credentials to anything that can reach them.' },
    ],
    requireApproval: [
      { kind: 'network', target: 'attacker', reason: 'Outbound request to a host matching "attacker" — confirm this is expected.' },
    ],
  },
];

export async function runSandbox(options: SandboxOptions): Promise<SandboxResult> {
  const started = Date.now();
  const maxBytes = options.maxRecordedBytes ?? 1024 * 1024;
  const policies = options.policies ?? DEFAULT_POLICIES;
  const events: BehaviorEvent[] = [];

  return new Promise<SandboxResult>((resolvePromise) => {
    const child = spawn(options.command, options.args ?? [], {
      cwd: options.cwd,
      env: { ...process.env, ...(options.env ?? {}) } as NodeJS.ProcessEnv,
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
      windowsHide: true,
    });

    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let settled = false;

    const record = (kind: EventKind, target: string, extra: Partial<BehaviorEvent> = {}) => {
      const violation = evaluate(policies, kind, target);
      events.push({
        kind,
        target,
        timestamp: Date.now(),
        ...(violation ? { blocked: violation.action === 'deny' } : {}),
        ...extra,
      });
      if (violation) {
        options.logger?.warn(
          options.shadow
            ? `shadow: would ${violation.action} ${kind} ${target} (${violation.reason})`
            : `${violation.action}ed ${kind} ${target} (${violation.reason})`,
        );
      }
    };

    // Instrument the streams: tool activity in an agent's output is most
    // reliably surfaced as JSON lines, which is what agent frameworks emit.
    let buffer = '';
    const consume = (chunk: string) => {
      buffer += chunk;
      const lines = buffer.split('\n');
      buffer = lines.pop() ?? '';
      for (const line of lines) {
        const parsed = parseAgentLine(line);
        if (!parsed) continue;
        record(parsed.kind, parsed.target, {
          ...(parsed.detail !== undefined ? { detail: parsed.detail } : {}),
          ...(parsed.args !== undefined ? { args: parsed.args } : {}),
          ...(parsed.bytes !== undefined ? { bytes: parsed.bytes } : {}),
        });
      }
    };

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      stdout += chunk;
      if (stdout.length > maxBytes) stdout = stdout.slice(0, maxBytes);
      consume(chunk);
    });
    child.stderr.on('data', (chunk: string) => {
      stderr += chunk;
      if (stderr.length > maxBytes) stderr = stderr.slice(0, maxBytes);
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, options.timeoutMs ?? 60_000);

    child.on('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolvePromise(finish(error.message, null, true));
    });

    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      // Flush any trailing partial line. An agent that exits without a final
      // newline is common, and discarding that line silently loses the last
      // (often the most important) event in the recording.
      if (buffer.trim()) {
        const parsed = parseAgentLine(buffer);
        if (parsed) record(parsed.kind, parsed.target, {
          ...(parsed.detail !== undefined ? { detail: parsed.detail } : {}),
          ...(parsed.args !== undefined ? { args: parsed.args } : {}),
          ...(parsed.bytes !== undefined ? { bytes: parsed.bytes } : {}),
        });
        buffer = '';
      }
      resolvePromise(finish(undefined, code, timedOut));
    });

    function finish(errorMessage: string | undefined, exitCode: number | null, didTimeout: boolean): SandboxResult {
      const fingerprint = fingerprintBehavior(events);
      const anomalies = [
        ...detectAnomalies(events, fingerprint, options.baseline, options.shadow ?? false),
        ...policyFindings(events, policies, options.shadow ?? false),
      ];
      if (errorMessage) {
        anomalies.push(makeFinding(
          'AEGIS-SANDBOX-001',
          'Sandbox target failed to run',
          'critical',
          errorMessage,
          'agent',
          errorMessage,
          'Confirm the command exists and is executable in this environment.',
          'sandbox',
        ));
      }
      if (didTimeout) {
        anomalies.push(makeFinding(
          'AEGIS-SANDBOX-002',
          'Sandbox target exceeded its time budget',
          'high',
          `The agent did not terminate within ${options.timeoutMs ?? 60_000}ms.`,
          'agent',
          'Timed out.',
          'An agent that never terminates is a Model DoS condition; enforce a deadline in the orchestrator.',
          'dos',
        ));
      }

      return {
        events,
        fingerprint,
        anomalies,
        findings: anomalies,
        durationMs: Date.now() - started,
        exitCode,
        eventCount: events.length,
        timedOut: didTimeout,
        stdout,
        stderr,
      };
    }

    // Close stdin so an agent waiting for input proceeds.
    child.stdin.end();
  });
}

export interface PolicyViolation {
  policyId: string;
  action: 'deny' | 'require-approval';
  kind: EventKind;
  /** The action's target, included so callers can report it without re-deriving. */
  target: string;
  reason: string;
}

/** Evaluate the policies against one action. */
export function evaluate(
  policies: readonly AgentPolicy[],
  kind: EventKind,
  target: string,
): PolicyViolation | null {
  const lower = target.toLowerCase();
  for (const policy of policies) {
    for (const rule of policy.deny ?? []) {
      if (rule.kind !== kind) continue;
      if (matches(lower, rule.target.toLowerCase())) {
        return { policyId: policy.id, action: 'deny', kind, target, reason: rule.reason };
      }
    }
    for (const rule of policy.requireApproval ?? []) {
      if (rule.kind !== kind) continue;
      if (matches(lower, rule.target.toLowerCase())) {
        return { policyId: policy.id, action: 'require-approval', kind, target, reason: rule.reason };
      }
    }
  }
  return null;
}

function matches(target: string, pattern: string): boolean {
  if (pattern.startsWith('*')) return target.includes(pattern.slice(1));
  if (pattern.endsWith('*')) return target.startsWith(pattern.slice(0, -1));
  if (pattern.includes('*')) {
    const [a, b] = pattern.split('*');
    return target.includes(a ?? '') && target.includes(b ?? '');
  }
  return target.includes(pattern);
}

function parseAgentLine(
  line: string,
): { kind: EventKind; target: string; detail?: string; args?: Record<string, unknown>; bytes?: number } | null {
  const trimmed = line.trim();
  if (!trimmed) return null;
  if (!trimmed.startsWith('{')) return null;
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(trimmed) as Record<string, unknown>;
  } catch {
    return null;
  }

  // Accept the common shapes agent frameworks emit.
  const kind = String(parsed['type'] ?? parsed['event'] ?? parsed['kind'] ?? '').toLowerCase();
  const name = String(parsed['tool'] ?? parsed['name'] ?? parsed['tool_name'] ?? parsed['method'] ?? '');

  if (kind === 'tool_call' || kind === 'tool-call' || (name && kind !== 'llm')) {
    return { kind: 'tool-call', target: name || 'unknown-tool', ...(parsed['arguments'] ? { args: parsed['arguments'] as Record<string, unknown> } : {}) };
  }
  if (kind === 'tool_result' || kind === 'tool-result') {
    return { kind: 'tool-result', target: name || 'unknown-tool' };
  }
  if (kind === 'http_request' || kind === 'request' || kind === 'fetch') {
    return { kind: 'network', target: String(parsed['url'] ?? parsed['endpoint'] ?? '') };
  }
  if (kind === 'file_read' || kind === 'read_file') {
    return { kind: 'file-read', target: String(parsed['path'] ?? '') };
  }
  if (kind === 'file_write' || kind === 'write_file') {
    return { kind: 'file-write', target: String(parsed['path'] ?? ''), bytes: numberOr(parsed['bytes']) };
  }
  if (kind === 'process_spawn' || kind === 'spawn' || kind === 'exec') {
    return { kind: 'process-spawn', target: String(parsed['command'] ?? name) };
  }
  if (kind === 'prompt' || kind === 'user_message') {
    return { kind: 'prompt', target: 'user' };
  }
  if (kind === 'completion' || kind === 'assistant_message') {
    return { kind: 'completion', target: 'assistant' };
  }
  if (kind === 'error') {
    return { kind: 'error', target: String(parsed['message'] ?? 'error') };
  }
  return null;
}

function numberOr(value: unknown): number | undefined {
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

/** Turn policy violations into findings, which is what the CLI reports. */
function policyFindings(
  events: readonly BehaviorEvent[],
  policies: readonly AgentPolicy[],
  shadow: boolean,
): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();

  for (const event of events) {
    const violation = evaluate(policies, event.kind, event.target);
    if (!violation) continue;
    const key = `${violation.policyId}:${violation.kind}:${violation.target}`;
    if (seen.has(key)) continue;
    seen.add(key);

    out.push(
      makeFinding(
        `AEGIS-POLICY-${violation.action === 'deny' ? 'DENY' : 'APPROVAL'}`,
        violation.action === 'deny'
          ? `Policy blocked ${event.kind} to ${event.target}`
          : `Policy requires approval for ${event.kind} to ${event.target}`,
        violation.action === 'deny' ? 'critical' : 'high',
        violation.reason,
        'runtime',
        `policy ${violation.policyId} — ${violation.action}; observed ${event.kind} of "${event.target}" at ${new Date(event.timestamp).toISOString()}`,
        violation.reason,
        'agent-policy',
      ),
    );
  }
  void shadow;
  return out;
}

/** Deviations from the baseline fingerprint. */
function detectAnomalies(
  events: readonly BehaviorEvent[],
  observed: BehavioralFingerprint,
  baseline: BehavioralFingerprint | undefined,
  shadow: boolean,
): Finding[] {
  if (!baseline) return [];

  const { divergence, reasons, novel } = compareFingerprints(baseline, observed);
  if (divergence < 0.15) return [];

  const severity: Severity =
    divergence >= 0.6 ? 'critical' : divergence >= 0.35 ? 'high' : 'medium';

  return [
    makeFinding(
      'AEGIS-SANDBOX-003',
      'Behavioural fingerprint diverged from baseline',
      severity,
      `Runtime behaviour diverged from the recorded baseline by ${(divergence * 100).toFixed(0)}%.`,
      'runtime',
      reasons.join(' · ') || 'Behaviour changed without a matching explanation.',
      `${shadow ? 'Shadow mode: ' : ''}The agent ${novel.length ? `newly reached ${novel.slice(0, 5).join(', ')}` : 'changed its tool distribution'}. Either the agent was reconfigured, an operator approved a new capability, or it is compromised.`,
      'behavioural-drift',
    ),
  ];
}

function makeFinding(
  ruleId: string,
  title: string,
  severity: Severity,
  description: string,
  source: string,
  evidence: string,
  remediation: string,
  tag: string,
): Finding {
  return {
    id: `${ruleId}:${evidence.slice(0, 40)}`,
    ruleId,
    title,
    description,
    severity,
    confidence: 'high',
    location: { component: source, line: 1 },
    evidence,
    remediation: { title: remediation, description, automated: false, effort: 'medium' },
    compliance: [
      { framework: 'owasp-agentic', control: 'ASI10', title: 'Rogue Agents', relevant: true },
      { framework: 'soc2', control: 'CC7.2', title: 'Monitoring for anomalies', relevant: true },
    ],
    source,
    tags: ['sandbox', tag],
    fingerprint: `${ruleId}:${evidence.slice(0, 60)}`,
    createdAt: new Date().toISOString(),
  };
}

export { parseAgentLine };