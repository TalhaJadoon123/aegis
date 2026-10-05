/** Minimal leveled logger used across the engine. */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'silent';

import type { Logger } from './types.js';

export type { Logger };

const ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: 100,
};

export interface LoggerOptions {
  level?: LogLevel;
  /** Where human output goes. Defaults to stdout for <=info, stderr for >=warn. */
  write?: (line: string) => void;
  writeError?: (line: string) => void;
  json?: boolean;
  name?: string;
}

export function createLogger(options: LoggerOptions = {}): Logger {
  const level = options.level ?? 'info';
  const write = options.write ?? ((line: string) => process.stdout.write(`${line}\n`));
  const writeError = options.writeError ?? ((line: string) => process.stderr.write(`${line}\n`));
  const prefix = options.name ? `[${options.name}] ` : '';

  const emit = (lvl: Exclude<LogLevel, 'silent'>, message: string, meta?: unknown) => {
    if (ORDER[lvl] < ORDER[level]) return;
    const sink = lvl === 'warn' || lvl === 'error' ? writeError : write;
    if (options.json) {
      sink(JSON.stringify({ level: lvl, name: options.name, message, meta }));
      return;
    }
    const suffix = meta === undefined ? '' : ` ${safeStringify(meta)}`;
    sink(`${prefix}${message}${suffix}`);
  };

  return {
    debug: (m, meta) => emit('debug', m, meta),
    info: (m, meta) => emit('info', m, meta),
    warn: (m, meta) => emit('warn', m, meta),
    error: (m, meta) => emit('error', m, meta),
  };
}

export function safeStringify(value: unknown): string {
  try {
    if (typeof value === 'string') return value;
    return JSON.stringify(value, replacer) ?? String(value);
  } catch {
    return String(value);
  }
}

function replacer(_key: string, value: unknown): unknown {
  if (value instanceof Error) return { name: value.name, message: value.message };
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'function') return '[Function]';
  return value;
}

/** A logger that discards everything — handy in tests. */
export const silentLogger: Logger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
};

/** Captures log output so tests can assert on it. */
export function createCapturingLogger(level: LogLevel = 'debug') {
  const lines: string[] = [];
  const logger = createLogger({ level, write: (l) => lines.push(l), writeError: (l) => lines.push(l) });
  return { logger, lines };
}
