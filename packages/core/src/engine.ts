import { resolve } from 'node:path';
import { createLogger, type Logger } from './logger.js';
import { PluginRegistry } from './registry.js';
import { dedupeFindings, filterBySeverity, computeScore, sortFindings, toSeverity } from './severity.js';
import type {
  Finding,
  ScanResult,
  ScanTarget,
  ScanTargetType,
  Scanner,
  ScannerContext,
  SecurityScore,
  Severity,
} from './types.js';

export interface RunOptions {
  /** Minimum severity to include. Default: `low`. */
  minSeverity?: Severity;
  /** Only run scanners matching these target types. */
  targetTypes?: ScanTargetType[];
  /** Only run these scanner names. */
  scannerNames?: string[];
  /** Extra options forwarded into `ScannerContext.options`. */
  options?: Record<string, unknown>;
  logger?: Logger;
  signal?: AbortSignal;
  /** Abort after this many milliseconds. */
  timeoutMs?: number;
  /** Deduplicate identical findings. Default: true. */
  dedupe?: boolean;
  registry?: PluginRegistry;
}

export interface RunSummary {
  target: ScanTarget;
  findings: Finding[];
  results: ScanResult[];
  score: SecurityScore;
  durationMs: number;
  errors: string[];
}

/**
 * The scan orchestrator.
 *
 * Scanners are executed in order and their findings are *streamed* through an
 * async generator, so a caller can render results live without ever holding
 * more than one finding in memory beyond what it chooses to keep. Errors in one
 * scanner never abort the run — a broken plugin must not hide findings from
 * the scanner that ran before it.
 */
export async function* runScanners(
  scanners: readonly Scanner[],
  target: ScanTarget,
  options: RunOptions = {},
): AsyncGenerator<Finding, void, unknown> {
  const logger = options.logger ?? createLogger({ level: 'info' });
  const registry = options.registry ?? new PluginRegistry({ logger });
  const root = resolve(target.path ?? process.cwd());

  const selected = scanners.filter((s) => {
    if (options.targetTypes && !options.targetTypes.includes(s.targetType)) return false;
    if (options.scannerNames && !options.scannerNames.includes(s.name)) return false;
    return true;
  });

  const controller = new AbortController();
  const onAbort = () => controller.abort();
  options.signal?.addEventListener('abort', onAbort, { once: true });
  const timer = options.timeoutMs
    ? setTimeout(() => controller.abort(), options.timeoutMs)
    : undefined;

  const ctx: ScannerContext = {
    root,
    registry,
    logger,
    signal: controller.signal,
    options: options.options ?? {},
  };

  const minSeverity = options.minSeverity ? toSeverity(options.minSeverity) : 'low';

  try {
    for (const scanner of selected) {
      if (ctx.signal?.aborted) break;
      logger.debug(`running scanner ${scanner.name} (${scanner.targetType})`);
      try {
        for await (const finding of scanner.scan(target, ctx)) {
          if (ctx.signal?.aborted) break;
          if (minSeverity !== 'info' && !passes(finding.severity, minSeverity)) continue;
          yield finding;
        }
      } catch (error) {
        if ((error as Error).name === 'AbortError') break;
        logger.warn(`scanner ${scanner.name} failed: ${(error as Error).message}`);
      }
    }
  } finally {
    if (timer) clearTimeout(timer);
    options.signal?.removeEventListener('abort', onAbort);
  }
}

function passes(severity: Severity, min: Severity): boolean {
  const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  return order.indexOf(severity) <= order.indexOf(min);
}

/**
 * Run scanners and collect everything into memory. Use this when you need the
 * full set — scoring, reports, dashboard upload.
 */
export async function runScan(
  scanners: readonly Scanner[],
  target: ScanTarget,
  options: RunOptions = {},
): Promise<RunSummary> {
  const started = Date.now();
  const findings: Finding[] = [];
  for await (const finding of runScanners(scanners, target, options)) {
    findings.push(finding);
  }
  const processed = options.dedupe === false ? findings : dedupeFindings(findings);
  return {
    target,
    findings: sortFindings(processed),
    results: [],
    score: computeScore({ findings: processed }),
    durationMs: Date.now() - started,
    errors: [],
  };
}

/** Convenience: scan and immediately filter to a severity threshold. */
export async function runScanAtSeverity(
  scanners: readonly Scanner[],
  target: ScanTarget,
  min: Severity,
  options: RunOptions = {},
): Promise<Finding[]> {
  const summary = await runScan(scanners, target, { ...options, minSeverity: min });
  return filterBySeverity(summary.findings, min);
}

/** Re-export so consumers can build their own pipelines. */
export { computeScore, dedupeFindings, filterBySeverity, sortFindings, toSeverity };
export type { SecurityScore };
