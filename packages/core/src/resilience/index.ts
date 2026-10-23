/**
 * Circuit Breaker for External Integrations
 *
 * Provides fault tolerance for external API calls (GitHub, OSV, NVD, etc.)
 * with three states: Closed (normal), Open (failing), Half-Open (testing).
 *
 * Zero runtime dependencies - implemented in pure TypeScript.
 */

export type CircuitState = 'closed' | 'open' | 'half-open';

export interface CircuitBreakerConfig {
  /** Name of the circuit breaker for logging */
  name: string;
  /** Number of failures before opening circuit (default: 5) */
  failureThreshold?: number;
  /** Time in ms to wait before trying again when open (default: 60000) */
  resetTimeoutMs?: number;
  /** Number of successful calls in half-open before closing (default: 3) */
  successThreshold?: number;
  /** Timeout for individual calls in ms (default: 30000) */
  callTimeoutMs?: number;
  /** Error codes that should count as failures (default: all errors) */
  failureCodes?: number[];
  /** Whether to log state changes */
  verbose?: boolean;
}

export interface CircuitBreakerStats {
  state: CircuitState;
  failures: number;
  successes: number;
  lastFailure: Date | null;
  lastSuccess: Date | null;
  totalCalls: number;
  totalFailures: number;
  totalSuccesses: number;
  nextRetry: Date | null;
}

export class CircuitBreaker {
  private state: CircuitState = 'closed';
  private failures = 0;
  private successes = 0;
  private lastFailure: Date | null = null;
  private lastSuccess: Date | null = null;
  private totalCalls = 0;
  private totalFailures = 0;
  private totalSuccesses = 0;
  private nextRetry: Date | null = null;
  private readonly config: Required<CircuitBreakerConfig>;

  constructor(config: CircuitBreakerConfig) {
    this.config = {
      name: config.name,
      failureThreshold: config.failureThreshold ?? 5,
      resetTimeoutMs: config.resetTimeoutMs ?? 60000,
      successThreshold: config.successThreshold ?? 3,
      callTimeoutMs: config.callTimeoutMs ?? 30000,
      failureCodes: config.failureCodes ?? [],
      verbose: config.verbose ?? false,
    };
  }

  /**
   * Execute a function with circuit breaker protection.
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === 'open') {
      if (this.nextRetry && Date.now() < this.nextRetry.getTime()) {
        const error = new Error(`Circuit breaker '${this.config.name}' is open. Retry after ${this.nextRetry.toISOString()}`);
        error.name = 'CircuitBreakerOpenError';
        throw error;
      }
      // Try again - transition to half-open
      this.state = 'half-open';
      this.successes = 0;
      if (this.config.verbose) {
        console.log(`[CircuitBreaker:${this.config.name}] Transitioning from open to half-open`);
      }
    }

    this.totalCalls++;
    const timeout = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(new Error(`Circuit breaker '${this.config.name}' call timed out after ${this.config.callTimeoutMs}ms`));
      }, this.config.callTimeoutMs);
    });

    try {
      const result = await Promise.race([fn(), timeout]);
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure(error as Error);
      throw error;
    }
  }

  /**
   * Wrap a function with circuit breaker protection.
   */
  wrap<TArgs extends unknown[], TReturn>(
    fn: (...args: TArgs) => Promise<TReturn>
  ): (...args: TArgs) => Promise<TReturn> {
    return (...args: TArgs) => this.execute(() => fn(...args));
  }

  private onSuccess(): void {
    this.successes++;
    this.lastSuccess = new Date();
    this.totalSuccesses++;

    if (this.state === 'half-open' && this.successes >= this.config.successThreshold) {
      this.state = 'closed';
      this.failures = 0;
      if (this.config.verbose) {
        console.log(`[CircuitBreaker:${this.config.name}] Transitioning from half-open to closed`);
      }
    }

    if (this.state === 'closed') {
      this.failures = 0;
    }
  }

  private onFailure(error: Error): void {
    this.failures++;
    this.lastFailure = new Date();
    this.totalFailures++;

    if (this.state === 'half-open') {
      // Failed in half-open, go back to open
      this.state = 'open';
      this.nextRetry = new Date(Date.now() + this.config.resetTimeoutMs);
      if (this.config.verbose) {
        console.log(`[CircuitBreaker:${this.config.name}] Transitioning from half-open to open (failed)`);
      }
    } else if (this.state === 'closed' && this.failures >= this.config.failureThreshold) {
      this.state = 'open';
      this.nextRetry = new Date(Date.now() + this.config.resetTimeoutMs);
      if (this.config.verbose) {
        console.log(`[CircuitBreaker:${this.config.name}] Transitioning from closed to open (threshold reached)`);
      }
    }
  }

  /**
   * Get current state.
   */
  getState(): CircuitState {
    return this.state;
  }

  /**
   * Get current stats.
   */
  getStats(): CircuitBreakerStats {
    return {
      state: this.state,
      failures: this.failures,
      successes: this.successes,
      lastFailure: this.lastFailure,
      lastSuccess: this.lastSuccess,
      totalCalls: this.totalCalls,
      totalFailures: this.totalFailures,
      totalSuccesses: this.totalSuccesses,
      nextRetry: this.nextRetry,
    };
  }

  /**
   * Reset the circuit breaker to closed state.
   */
  reset(): void {
    this.state = 'closed';
    this.failures = 0;
    this.successes = 0;
    this.lastFailure = null;
    this.lastSuccess = null;
    this.nextRetry = null;
    if (this.config.verbose) {
      console.log(`[CircuitBreaker:${this.config.name}] Reset to closed`);
    }
  }

  /**
   * Force open the circuit breaker.
   */
  open(): void {
    this.state = 'open';
    this.nextRetry = new Date(Date.now() + this.config.resetTimeoutMs);
    if (this.config.verbose) {
      console.log(`[CircuitBreaker:${this.config.name}] Forced open`);
    }
  }

  /**
   * Check if the circuit is open.
   */
  isOpen(): boolean {
    return this.state === 'open' && (!this.nextRetry || Date.now() < this.nextRetry.getTime());
  }

  /**
   * Check if the circuit is closed.
   */
  isClosed(): boolean {
    return this.state === 'closed';
  }

  /**
   * Check if the circuit is half-open.
   */
  isHalfOpen(): boolean {
    return this.state === 'half-open';
  }
}

/**
 * Create a circuit breaker for an external service.
 */
export function createCircuitBreaker(
  name: string,
  config?: Omit<CircuitBreakerConfig, 'name'>
): CircuitBreaker {
  return new CircuitBreaker({ name, ...config });
}

/**
 * Common circuit breaker configurations for Aegis services.
 */
export const CIRCUIT_BREAKERS = {
  github: (verbose = false) =>
    createCircuitBreaker('github-api', {
      failureThreshold: 5,
      resetTimeoutMs: 60000,
      callTimeoutMs: 15000,
      verbose,
    }),
  osv: (verbose = false) =>
    createCircuitBreaker('osv-api', {
      failureThreshold: 3,
      resetTimeoutMs: 30000,
      callTimeoutMs: 10000,
      verbose,
    }),
  nvd: (verbose = false) =>
    createCircuitBreaker('nvd-api', {
      failureThreshold: 3,
      resetTimeoutMs: 60000,
      callTimeoutMs: 20000,
      verbose,
    }),
  mcp: (verbose = false) =>
    createCircuitBreaker('mcp-server', {
      failureThreshold: 3,
      resetTimeoutMs: 30000,
      callTimeoutMs: 15000,
      verbose,
    }),
  llm: (verbose = false) =>
    createCircuitBreaker('llm-api', {
      failureThreshold: 5,
      resetTimeoutMs: 60000,
      callTimeoutMs: 30000,
      verbose,
    }),
};

// All exports are already declared with 'export' keyword above.