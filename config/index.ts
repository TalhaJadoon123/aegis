/**
 * Configuration validation for Aegis.
 *
 * Uses Zod for runtime validation of all configuration sources:
 * - Environment variables
 * - CLI arguments
 * - Configuration files
 *
 * Provides clear error messages and type-safe config objects.
 */

import { z } from 'zod';

/**
 * Core Aegis configuration
 */
export const CoreConfigSchema = z.object({
  // Scanning behavior
  minSeverity: z.enum(['critical', 'high', 'medium', 'low', 'info']).default('low'),
  failOn: z.enum(['critical', 'high', 'medium', 'low', 'info']).default('high'),
  noConnect: z.boolean().default(false),
  noSpawn: z.boolean().default(false),
  includeProcesses: z.boolean().default(false),
  threatModel: z.boolean().default(true),
  graph: z.boolean().default(false),
  baseline: z.boolean().default(false),
  baselineFile: z.string().optional(),
  exclude: z.string().optional(), // comma-separated list

  // Rule configuration
  ruleDir: z.string().optional(),
  rules: z.string().optional(), // comma-separated rule pack files

  // Output
  format: z.enum(['json', 'sarif', 'markdown', 'html', 'csv', 'jsonl', 'text']).default('text'),
  output: z.string().optional(),
  limit: z.number().int().positive().optional(),
  quiet: z.boolean().default(false),
  noColor: z.boolean().default(false),

  // Red team
  target: z.string().optional(),
  command: z.string().optional(),
  dryRun: z.boolean().default(false),
  sandbox: z.boolean().default(false),
  attack: z.string().optional(),
  category: z.string().optional(),
  population: z.number().int().positive().default(12),
  generations: z.number().int().positive().default(6),
  budget: z.number().int().positive().default(200),
  seed: z.number().int().default(1337),
  timeout: z.number().int().positive().default(30000),
  redactPrompts: z.boolean().default(false),
  header: z.array(z.string()).default([]),

  // Dashboard
  port: z.number().int().positive().default(8080),
  host: z.string().default('127.0.0.1'),
  dataDir: z.string().default('.aegis/dashboard'),
  browser: z.enum(['chrome', 'edge', 'system']).optional(),
  noOpen: z.boolean().default(false),

  // Fix
  apply: z.boolean().default(false),
  rule: z.string().optional(),
  maxSeverity: z.enum(['critical', 'high', 'medium', 'low', 'info']).default('low'),
  branch: z.boolean().default(false),
  pr: z.boolean().default(false),

  // Report
  compliance: z.boolean().default(false),
  organisation: z.string().optional(),
  system: z.string().optional(),
  owner: z.string().optional(),
  framework: z.string().optional(),

  // Sandbox
  sandboxCommand: z.string().optional(),
  sandboxArg: z.array(z.string()).default([]),
  sandboxCwd: z.string().optional(),
  sandboxBaseline: z.string().optional(),
  sandboxShadow: z.boolean().default(false),
  sandboxTimeout: z.number().int().positive().default(60000),
  sandboxNetwork: z.boolean().default(true),
  sandboxMaxBytes: z.number().int().positive().default(1048576),

  // Intel
  exposure: z.boolean().default(false),
  capability: z.string().optional(),
  technique: z.string().optional(),
  alerts: z.boolean().default(false),
  subscribe: z.string().optional(),
  watch: z.boolean().default(false),
  offline: z.boolean().default(false),

  // Deps
  package: z.string().optional(),
  manifest: z.string().optional(),
  ecosystem: z.enum(['npm', 'pypi', 'go']).default('npm'),
  depsTimeout: z.number().int().positive().default(15000),

  // Global
  help: z.boolean().default(false),
  version: z.boolean().default(false),
});

export type CoreConfig = z.infer<typeof CoreConfigSchema>;

/**
 * Dashboard-specific configuration
 */
export const DashboardConfigSchema = z.object({
  port: z.number().int().positive().default(8080),
  host: z.string().default('127.0.0.1'),
  dataDir: z.string().default('.aegis/dashboard'),
  token: z.string().optional(),
  enableMetrics: z.boolean().default(false),
  enableTracing: z.boolean().default(false),
  logLevel: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('info'),
});

export type DashboardConfig = z.infer<typeof DashboardConfigSchema>;

/**
 * Red team configuration
 */
export const RedTeamConfigSchema = z.object({
  target: z.string().optional(),
  command: z.string().optional(),
  dryRun: z.boolean().default(false),
  sandbox: z.boolean().default(false),
  attack: z.string().optional(),
  category: z.string().optional(),
  population: z.number().int().positive().default(12),
  generations: z.number().int().positive().default(6),
  budget: z.number().int().positive().default(200),
  seed: z.number().int().default(1337),
  timeout: z.number().int().positive().default(30000),
  redactPrompts: z.boolean().default(false),
  header: z.array(z.string()).default([]),
  capabilities: z.array(z.enum(['network', 'filesystem', 'shell', 'database', 'email', 'code-execution'])).default([]),
});

export type RedTeamConfig = z.infer<typeof RedTeamConfigSchema>;

/**
 * Sandbox configuration
 */
export const SandboxConfigSchema = z.object({
  command: z.string(),
  args: z.array(z.string()).default([]),
  cwd: z.string().optional(),
  env: z.record(z.string()).default({}),
  timeoutMs: z.number().int().positive().default(60000),
  maxRecordedBytes: z.number().int().positive().default(1048576),
  shadow: z.boolean().default(false),
  network: z.boolean().default(true),
  policies: z.array(z.object({
    id: z.string(),
    name: z.string(),
    deny: z.array(z.object({
      kind: z.string(),
      target: z.string(),
      reason: z.string(),
    })).default([]),
    requireApproval: z.array(z.object({
      kind: z.string(),
      target: z.string(),
      reason: z.string(),
    })).default([]),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
  })).default([]),
});

export type SandboxConfig = z.infer<typeof SandboxConfigSchema>;

/**
 * Red team target configuration
 */
export const HttpTargetConfigSchema = z.object({
  url: z.string().url(),
  headers: z.record(z.string()).default({}),
  messageField: z.string().default('message'),
  extraBody: z.record(z.unknown()).default({}),
  timeoutMs: z.number().int().positive().default(30000),
  responsePath: z.string().optional(),
  maintainHistory: z.boolean().default(true),
  capabilities: z.array(z.enum(['network', 'filesystem', 'shell', 'database', 'email', 'code-execution'])).default(['network']),
  name: z.string().optional(),
});

export type HttpTargetConfig = z.infer<typeof HttpTargetConfigSchema>;

/**
 * Environment configuration (from .env)
 */
export const EnvConfigSchema = z.object({
  // Core
  NODE_ENV: z.enum(['development', 'staging', 'production', 'test']).default('development'),
  LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('info'),

  // Database
  DATABASE_URL: z.string().url().optional(),
  REDIS_URL: z.string().url().optional(),

  // Dashboard (packages/web)
  NEXT_PUBLIC_APP_URL: z.string().url().optional(),
  NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY: z.string().optional(),
  CLERK_SECRET_KEY: z.string().optional(),

  // Payments
  STRIPE_SECRET_KEY: z.string().optional(),
  STRIPE_WEBHOOK_SECRET: z.string().optional(),
  STRIPE_PRO_PRICE_ID: z.string().optional(),
  STRIPE_TEAM_PRICE_ID: z.string().optional(),
  NEXT_PUBLIC_LEMON_SQUEEZY_CHECKOUT_URL: z.string().url().optional(),
  LEMON_SQUEEZY_API_KEY: z.string().optional(),
  PADDLE_CLIENT_TOKEN: z.string().optional(),
  PADDLE_VENDOR_ID: z.string().optional(),
  PADDLE_API_KEY: z.string().optional(),

  // Observability
  NEXT_PUBLIC_POSTHOG_KEY: z.string().optional(),
  NEXT_PUBLIC_POSTHOG_HOST: z.string().url().optional(),
  SENTRY_DSN: z.string().optional(),

  // BYOK LLM keys
  OPENAI_API_KEY: z.string().optional(),
  ANTHROPIC_API_KEY: z.string().optional(),
  GOOGLE_API_KEY: z.string().optional(),
  OLLAMA_HOST: z.string().url().optional(),

  // Red teaming
  AEGIS_API_KEY: z.string().optional(),
  AEGIS_API_URL: z.string().url().optional(),
  AEGIS_TELEMETRY: z.enum(['0', '1']).default('0'),

  // Dashboard auth
  AEGIS_DASHBOARD_TOKEN: z.string().optional(),
});

export type EnvConfig = z.infer<typeof EnvConfigSchema>;

/**
 * Validate and parse configuration with detailed error messages
 */
export function validateConfig<T>(
  schema: z.ZodSchema<T>,
  input: unknown,
  context: string = 'configuration',
): { success: true; data: T } | { success: false; errors: string[] } {
  const result = schema.safeParse(input);

  if (result.success) {
    return { success: true, data: result.data };
  }

  const errors = result.error.issues.map((issue) => {
    const path = issue.path.length > 0 ? issue.path.join('.') : 'root';
    return `${context}.${path}: ${issue.message}`;
  });

  return { success: false, errors };
}

/**
 * Parse and validate environment variables
 */
export function parseEnv(env: Record<string, string | undefined> = process.env): { success: true; data: EnvConfig } | { success: false; errors: string[] } {
  // Convert empty strings to undefined for optional fields
  const sanitized: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(env)) {
    sanitized[key] = value === '' ? undefined : value;
  }
  return validateConfig(EnvConfigSchema, sanitized, 'env');
}

/**
 * Merge configs with precedence: CLI > env > defaults
 */
export function mergeConfigs<T extends Record<string, unknown>>(
  cli: Partial<T>,
  env: Partial<T>,
  defaults: T,
): T {
  const merged = { ...defaults };

  // Apply env (lower priority)
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined && value !== '' && merged[key] === defaults[key]) {
      (merged as Record<string, unknown>)[key] = value;
    }
  }

  // Apply CLI (highest priority)
  for (const [key, value] of Object.entries(cli)) {
    if (value !== undefined && value !== '') {
      (merged as Record<string, unknown>)[key] = value;
    }
  }

  return merged;
}

/**
 * Configuration file schema (aegis.config.json)
 */
export const ConfigFileSchema = z.object({
  // Scanning
  minSeverity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
  failOn: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
  noConnect: z.boolean().optional(),
  noSpawn: z.boolean().optional(),
  includeProcesses: z.boolean().optional(),
  threatModel: z.boolean().optional(),
  exclude: z.string().optional(),

  // Rules
  ruleDir: z.string().optional(),
  rules: z.array(z.string()).optional(),

  // Output
  format: z.enum(['json', 'sarif', 'markdown', 'html', 'csv', 'jsonl', 'text']).optional(),
  output: z.string().optional(),
  limit: z.number().int().positive().optional(),
  noColor: z.boolean().optional(),

  // Red team
  target: z.string().optional(),
  dryRun: z.boolean().optional(),
  population: z.number().int().positive().optional(),
  generations: z.number().int().positive().optional(),
  budget: z.number().int().positive().optional(),
  seed: z.number().int().optional(),
  timeout: z.number().int().positive().optional(),
  redactPrompts: z.boolean().optional(),

  // Dashboard
  port: z.number().int().positive().optional(),
  host: z.string().optional(),
  dataDir: z.string().optional(),
  noOpen: z.boolean().optional(),

  // Dashboard server
  dashboard: z.object({
    port: z.number().int().positive().optional(),
    host: z.string().optional(),
    dataDir: z.string().optional(),
    token: z.string().optional(),
    enableMetrics: z.boolean().optional(),
    enableTracing: z.boolean().optional(),
    logLevel: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).optional(),
  }).optional(),

  // Observability
  observability: z.object({
    serviceName: z.string().optional(),
    serviceVersion: z.string().optional(),
    environment: z.enum(['development', 'staging', 'production']).optional(),
    enableLogging: z.boolean().optional(),
    enableMetrics: z.boolean().optional(),
    enableTracing: z.boolean().optional(),
    logLevel: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).optional(),
    prometheusPort: z.number().int().positive().optional(),
    otlpEndpoint: z.string().url().optional(),
  }).optional(),

  // Red team
  redteam: z.object({
    population: z.number().int().positive().optional(),
    generations: z.number().int().positive().optional(),
    budget: z.number().int().positive().optional(),
    seed: z.number().int().optional(),
  }).optional(),
});

export type ConfigFile = z.infer<typeof ConfigFileSchema>;

/**
 * Load and validate config file
 */
export async function loadConfigFile(path: string): Promise<{ success: true; data: ConfigFile } | { success: false; errors: string[] }> {
  try {
    const { readFile } = await import('node:fs/promises');
    const content = await readFile(path, 'utf8');
    const parsed = JSON.parse(content);
    return validateConfig(ConfigFileSchema, parsed, 'config file');
  } catch (error) {
    return { success: false, errors: [`Failed to load config file: ${(error as Error).message}`] };
  }
}

/**
 * Get default configuration
 */
export function getDefaultConfig<T extends Record<string, unknown>>(schema: z.ZodObject<Record<string, z.ZodTypeAny>>): T {
  const defaults: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(schema.shape)) {
    if ('_def' in value && 'defaultValue' in value._def) {
      defaults[key] = value._def.defaultValue;
    }
  }
  return defaults as T;
}

/**
 * Configuration validation error class
 */
export class ConfigValidationError extends Error {
  public readonly errors: string[];
  public readonly context: string;

  constructor(errors: string[], context: string = 'configuration') {
    super(`Configuration validation failed (${errors.length} error${errors.length > 1 ? 's' : ''})`);
    this.name = 'ConfigValidationError';
    this.errors = errors;
    this.context = context;
  }
}

/**
 * Validate and throw on error
 */
export function validateOrThrow<T>(
  schema: z.ZodSchema<T>,
  input: unknown,
  context: string = 'configuration',
): T {
  const result = validateConfig(schema, input, context);
  if (!result.success) {
    throw new ConfigValidationError(result.errors, context);
  }
  return result.data;
}

export { z };