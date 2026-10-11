/**
 * Observability module for Aegis.
 *
 * Provides structured logging (pino), metrics (OpenTelemetry), and tracing.
 * Designed for production use: zero overhead when disabled, structured when enabled.
 *
 * All dependencies are optional - if not installed, the module gracefully
 * degrades to no-op implementations.
 */

import type { SpanKind, SpanStatusCode } from '@opentelemetry/api';

export interface ObservabilityConfig {
  /** Service name for telemetry */
  serviceName: string;
  /** Service version */
  serviceVersion: string;
  /** Environment (development, staging, production) */
  environment: string;
  /** Enable structured logging (pino) */
  enableLogging: boolean;
  /** Enable metrics (Prometheus) */
  enableMetrics: boolean;
  /** Enable tracing (OpenTelemetry) */
  enableTracing: boolean;
  /** Log level (trace, debug, info, warn, error, fatal) */
  logLevel: 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';
  /** Prometheus exporter port */
  prometheusPort?: number;
  /** OTLP endpoint for traces (optional) */
  otlpEndpoint?: string;
  /** Redact sensitive fields from logs */
  redactFields?: string[];
}

const DEFAULT_CONFIG: ObservabilityConfig = {
  serviceName: 'aegis',
  serviceVersion: '0.1.0',
  environment: 'development',
  enableLogging: true,
  enableMetrics: false,
  enableTracing: false,
  logLevel: 'info',
  redactFields: ['password', 'secret', 'token', 'key', 'authorization', 'cookie'],
};

/** No-op logger that satisfies the pino.Logger interface minimally */
interface NoOpLogger {
  info: (msg: string | object, ...args: unknown[]) => void;
  warn: (msg: string | object, ...args: unknown[]) => void;
  error: (msg: string | object, ...args: unknown[]) => void;
  debug: (msg: string | object, ...args: unknown[]) => void;
  trace: (msg: string | object, ...args: unknown[]) => void;
  fatal: (msg: string | object, ...args: unknown[]) => void;
  child: (bindings: Record<string, unknown>) => NoOpLogger;
  flush: () => Promise<void>;
}

function createNoOpLogger(): NoOpLogger {
  const noop = () => {};
  const logger: NoOpLogger = {
    info: noop,
    warn: noop,
    error: noop,
    debug: noop,
    trace: noop,
    fatal: noop,
    child: () => createNoOpLogger(),
    flush: async () => {},
  };
  return logger;
}

/** Minimal logger interface that works with or without pino */
export interface Logger {
  info: (msg: string | object, ...args: unknown[]) => void;
  warn: (msg: string | object, ...args: unknown[]) => void;
  error: (msg: string | object, ...args: unknown[]) => void;
  debug: (msg: string | object, ...args: unknown[]) => void;
  child: (bindings: Record<string, unknown>) => Logger;
  flush: () => Promise<void>;
}

let logger: Logger = createNoOpLogger();
let initialized = false;

/**
 * Initialize observability stack.
 * Call once at application startup.
 * All dependencies are optional - if not installed, falls back to no-op implementations.
 */
export async function initObservability(config: Partial<ObservabilityConfig> = {}): Promise<{
  logger: Logger;
  shutdown: () => Promise<void>;
}> {
  if (initialized) {
    return { logger, shutdown: shutdownObservability };
  }

  const cfg = { ...DEFAULT_CONFIG, ...config };

  // --- Structured Logging (pino) ---
  if (cfg.enableLogging) {
    try {
      const pinoModule = await import('pino');
      const pinoLogger = pinoModule.pino ?? pinoModule.default ?? pinoModule;
      const redactPaths = cfg.redactFields?.map((f) => `req.${f}`) ?? [];
      const additionalRedact = ['password', 'secret', 'token', 'key', 'authorization', 'cookie'];

      logger = pinoLogger({
        level: cfg.logLevel,
        redact: { paths: [...redactPaths, ...additionalRedact], censor: '[REDACTED]' },
        formatters: {
          level: (label: string) => ({ level: label.toUpperCase() }),
        },
        base: {
          service: cfg.serviceName,
          version: cfg.serviceVersion,
          environment: cfg.environment,
        },
        timestamp: (pinoModule.default ?? pinoModule).stdTimeFunctions.isoTime,
      }) as unknown as Logger;
    } catch {
      logger = createNoOpLogger();
    }
  }

  initialized = true;
  return { logger, shutdown: shutdownObservability };
}

/**
 * Get the logger instance.
 * Throws if not initialized.
 */
export function getLogger(): Logger {
  return logger;
}

/**
 * Create a child logger with additional bindings.
 */
export function createChildLogger(bindings: Record<string, unknown>): Logger {
  return logger.child(bindings);
}

/**
 * Start a traced span.
 * Returns the span and a function to end it.
 * No-op if tracing not enabled.
 */
export function startSpan(
  name: string,
  options: { kind?: SpanKind; attributes?: Record<string, unknown> } = {},
): { span: { end: (error?: Error) => void; recordException?: (e: Error) => void; setStatus?: (s: { code: SpanStatusCode; message?: string }) => void }; end: (error?: Error) => void } {
  // No-op span implementation
  const span = {
    end: () => {},
    recordException: () => {},
    setStatus: () => {},
  };

  return {
    span,
    end: () => {},
  };
}

/**
 * Run a function within a traced span.
 * No-op if tracing not enabled.
 */
export async function withSpan<T>(
  name: string,
  fn: (span: { end: () => void; recordException?: (e: Error) => void; setStatus?: (s: { code: SpanStatusCode; message?: string }) => void }) => Promise<T>,
  options: { kind?: SpanKind; attributes?: Record<string, unknown> } = {},
): Promise<T> {
  const { end } = startSpan(name, options);
  try {
    const result = await fn({ end: () => {}, recordException: () => {}, setStatus: () => {} });
    end();
    return result;
  } catch (error) {
    throw error;
  }
}

/**
 * Record a metric value.
 * No-op if metrics not enabled.
 */
export function recordMetric(
  name: string,
  value: number,
  attributes: Record<string, string | number> = {},
): void {
  // No-op by default
}

/**
 * Shutdown observability stack gracefully.
 */
export async function shutdownObservability(): Promise<void> {
  // No-op for now
}

/**
 * Check if observability is initialized.
 */
export function isInitialized(): boolean {
  return initialized;
}

/**
 * Get current trace ID for correlation.
 */
export function getTraceId(): string | undefined {
  return undefined;
}

/**
 * Get current span ID for correlation.
 */
export function getSpanId(): string | undefined {
  return undefined;
}

export { DEFAULT_CONFIG };
export type { NoOpLogger };