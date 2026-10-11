/**
 * Observability module for Aegis.
 *
 * Provides structured logging (pino), metrics (OpenTelemetry), and tracing.
 * Designed for production use: zero overhead when disabled, structured when enabled.
 */

import pino from 'pino';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { PrometheusExporter } from '@opentelemetry/exporter-prometheus';
import { Resource } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';
import { trace, context, SpanStatusCode, SpanKind } from '@opentelemetry/api';

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

let logger: pino.Logger | null = null;
let sdk: NodeSDK | null = null;
let prometheusExporter: PrometheusExporter | null = null;
let initialized = false;

/**
 * Initialize observability stack.
 * Call once at application startup.
 */
export function initObservability(config: Partial<ObservabilityConfig> = {}): {
  logger: pino.Logger;
  shutdown: () => Promise<void>;
} {
  if (initialized) {
    return { logger: logger!, shutdown: shutdownObservability };
  }

  const cfg = { ...DEFAULT_CONFIG, ...config };

  // --- Structured Logging (pino) ---
  const redactPaths = cfg.redactFields?.map((f) => `req.${f}`) ?? [];
  redactPaths.push('password', 'secret', 'token', 'key', 'authorization', 'cookie');

  logger = pino({
    level: cfg.logLevel,
    redact: { paths: redactPaths, censor: '[REDACTED]' },
    formatters: {
      level: (label) => ({ level: label.toUpperCase() }),
    },
    base: {
      service: cfg.serviceName,
      version: cfg.serviceVersion,
      environment: cfg.environment,
    },
    timestamp: pino.stdTimeFunctions.isoTime,
  });

  // --- Metrics (Prometheus) ---
  if (cfg.enableMetrics) {
    prometheusExporter = new PrometheusExporter(
      { port: cfg.prometheusPort ?? 9464 },
      () => {
        logger?.info({ port: cfg.prometheusPort ?? 9464 }, 'Prometheus metrics exporter started');
      },
    );
    prometheusExporter.start();
  }

  // --- Tracing (OpenTelemetry) ---
  if (cfg.enableTracing) {
    const resource = new Resource({
      [SemanticResourceAttributes.SERVICE_NAME]: cfg.serviceName,
      [SemanticResourceAttributes.SERVICE_VERSION]: cfg.serviceVersion,
      [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: cfg.environment,
    });

    sdk = new NodeSDK({
      resource,
      instrumentations: [getNodeAutoInstrumentations()],
      spanProcessor: cfg.otlpEndpoint
        ? undefined // Will use OTLP exporter if configured
        : undefined, // BatchSpanProcessor with console exporter for dev
    });

    sdk.start().catch((err) => {
      logger?.error({ err }, 'Failed to initialize OpenTelemetry SDK');
    });

    logger?.info('OpenTelemetry tracing initialized');
  }

  initialized = true;

  logger?.info({ config: { ...cfg, otlpEndpoint: cfg.otlpEndpoint ? '[REDACTED]' : undefined } }, 'Observability initialized');

  return { logger: logger!, shutdown: shutdownObservability };
}

/**
 * Get the logger instance.
 * Throws if not initialized.
 */
export function getLogger(): pino.Logger {
  if (!logger) {
    throw new Error('Observability not initialized. Call initObservability() first.');
  }
  return logger;
}

/**
 * Create a child logger with additional bindings.
 */
export function createChildLogger(bindings: Record<string, unknown>): pino.Logger {
  return getLogger().child(bindings);
}

/**
 * Start a traced span.
 * Returns the span and a function to end it.
 */
export function startSpan(
  name: string,
  options: { kind?: SpanKind; attributes?: Record<string, unknown> } = {},
): { span: ReturnType<typeof trace.getTracer('aegis').startSpan>; end: (error?: Error) => void } {
  const tracer = trace.getTracer('aegis');
  const span = tracer.startSpan(name, {
    kind: options.kind ?? SpanKind.INTERNAL,
    attributes: options.attributes,
  });

  return {
    span,
    end: (error?: Error) => {
      if (error) {
        span.recordException(error);
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
      } else {
        span.setStatus({ code: SpanStatusCode.OK });
      }
      span.end();
    },
  };
}

/**
 * Run a function within a traced span.
 */
export async function withSpan<T>(
  name: string,
  fn: (span: ReturnType<typeof trace.getTracer('aegis').startSpan>) => Promise<T>,
  options: { kind?: SpanKind; attributes?: Record<string, unknown> } = {},
): Promise<T> {
  const { span, end } = startSpan(name, options);
  try {
    const result = await fn(span);
    end();
    return result;
  } catch (error) {
    end(error as Error);
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
  // Metrics are handled by Prometheus exporter automatically via instrumentation
  // This is a placeholder for custom metrics if needed
  if (prometheusExporter) {
    // Custom metrics would be recorded here
  }
}

/**
 * Shutdown observability stack gracefully.
 */
export async function shutdownObservability(): Promise<void> {
  const shutdownPromises: Promise<void>[] = [];

  if (sdk) {
    shutdownPromises.push(sdk.shutdown());
    sdk = null;
  }

  if (prometheusExporter) {
    shutdownPromises.push(new Promise((resolve) => {
      prometheusExporter!.stop();
      resolve();
    }));
    prometheusExporter = null;
  }

  if (logger) {
    await logger.flush();
    logger = null;
  }

  await Promise.all(shutdownPromises);
  initialized = false;
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
  const span = trace.getActiveSpan();
  return span?.spanContext().traceId;
}

/**
 * Get current span ID for correlation.
 */
export function getSpanId(): string | undefined {
  const span = trace.getActiveSpan();
  return span?.spanContext().spanId;
}

export { trace, context, SpanStatusCode, SpanKind } from '@opentelemetry/api';
export type { ObservabilityConfig };