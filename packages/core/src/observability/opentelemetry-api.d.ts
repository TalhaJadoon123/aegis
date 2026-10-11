// Minimal type declarations for OpenTelemetry API
// This allows TypeScript to compile without @types/opentelemetry__api

declare module '@opentelemetry/api' {
  export type SpanKind = number;
  export type SpanStatusCode = number;

  export interface Span {
    end(endTime?: number): void;
    recordException(exception: Error, attributes?: Record<string, unknown>): void;
    setStatus(status: { code: number; message?: string }): void;
    setAttribute(key: string, value: string | number | boolean): void;
    setAttributes(attributes: Record<string, string | number | boolean>): void;
    addEvent(name: string, attributes?: Record<string, unknown>): void;
    spanContext(): { traceId: string; spanId: string; traceFlags: number };
  }

  export interface Tracer {
    startSpan(name: string, options?: { kind?: number; attributes?: Record<string, unknown> }): Span;
  }

  export interface TracerProvider {
    getTracer(name: string, version?: string): Tracer;
  }

  export const trace: {
    getTracer(name: string, version?: string): Tracer;
    getActiveSpan(): Span | undefined;
  };

  export const context: {
    active(): unknown;
    with(context: unknown, fn: () => void): void;
  };

  export const SpanStatusCode: {
    UNSET: 0;
    OK: 1;
    ERROR: 2;
  };

  export const SpanKind: {
    INTERNAL: 0;
    SERVER: 1;
    CLIENT: 2;
    PRODUCER: 3;
    CONSUMER: 4;
  };
}