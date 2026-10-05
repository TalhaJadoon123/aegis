/**
 * Aegis core type system.
 *
 * Every scanner in the platform emits `Finding` objects through the same
 * `Scanner` interface so that MCP servers, agent codebases, runtime behaviour
 * and repositories can be analysed with one engine and one report format.
 */

// ---------------------------------------------------------------------------
// Severity & confidence
// ---------------------------------------------------------------------------

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Ordered from most to least severe. `info` is last. */
export const SEVERITY_ORDER: readonly Severity[] = SEVERITIES;

/** Numeric weight used for scoring and aggregation. */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 10,
  high: 7,
  medium: 4,
  low: 2,
  info: 0,
};

export const CONFIDENCE_LEVELS = ['confirmed', 'high', 'medium', 'low'] as const;
export type Confidence = (typeof CONFIDENCE_LEVELS)[number];

/** Multiplier applied to impact when computing the overall score. */
export const CONFIDENCE_MULTIPLIER: Record<Confidence, number> = {
  confirmed: 1.0,
  high: 0.85,
  medium: 0.65,
  low: 0.4,
};

// ---------------------------------------------------------------------------
// Scan targets
// ---------------------------------------------------------------------------

export type ScanTargetType = 'mcp' | 'agent' | 'runtime' | 'repo';

export interface McpConfigHint {
  /** stdio server definition */
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  /** HTTP/SSE server definition */
  url?: string;
  headers?: Record<string, string>;
  type?: 'stdio' | 'http' | 'sse';
  /** Where in the ecosystem this config was found */
  source?: string;
}

export interface ScanTarget {
  type: ScanTargetType;
  /** Filesystem path — repo root, agent directory, or MCP config file. */
  path?: string;
  /** Remote endpoint — MCP HTTP server or red-teamable agent URL. */
  url?: string;
  /** Extra configuration, scanner specific. */
  config?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Locations
// ---------------------------------------------------------------------------

export interface SourceLocation {
  /** File path relative to the scan root, or an absolute path. */
  file?: string;
  line?: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  /** For remote findings, the logical component (e.g. `tools/read_file`). */
  component?: string;
  /** Byte offset for SARIF fidelity. */
  offset?: number;
}

// ---------------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------------

export type ComplianceFramework =
  | 'owasp-agentic'
  | 'owasp-llm'
  | 'soc2'
  | 'iso27001'
  | 'gdpr'
  | 'eu-ai-act'
  | 'nist-ai-rmf'
  | 'mitre-atlas';

export interface ComplianceMapping {
  framework: ComplianceFramework;
  /** Control identifier, e.g. `CC6.1`, `A.8.28`, `ASI01`, `AML.T0051`. */
  control: string;
  title?: string;
  /** Short quote of the control text when available. */
  description?: string;
  /** Whether satisfying the control mitigates this finding. */
  relevant: boolean;
  url?: string;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export interface Remediation {
  /** Short imperative title: "Restrict read_file to an allowlisted root". */
  title: string;
  /** Long form guidance shown in reports and the dashboard. */
  description: string;
  /** Concrete fix, usually a code/config snippet. */
  patch?: string;
  /** Docs deep link. */
  docs?: string;
  /** Rough effort estimate. */
  effort?: 'trivial' | 'low' | 'medium' | 'high';
  /** Can Aegis apply this automatically? */
  automated: boolean;
}

export interface Finding {
  /** Stable id: `<RULE_ID>.<location-hash>`. */
  id: string;
  /** Rule identifier, e.g. `AEGIS-MCP-001`. */
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  location: SourceLocation;
  /** The code / config / transcript excerpt that triggered the rule. */
  evidence: string;
  remediation: Remediation;
  compliance: ComplianceMapping[];
  /** Human readable description of the issue. */
  description: string;
  /** Which scanner produced this. */
  source: ScanTargetType | 'redteam' | 'sandbox' | 'intel' | string;
  /** Content fingerprint for de-duplication across runs and branches. */
  fingerprint?: string;
  /** CWE / CWE-like identifier when applicable. */
  cwe?: string;
  /** Extra structured data (rule metadata, attack transcripts, graph edges). */
  metadata?: Record<string, unknown>;
  /** Framework-specific classification (e.g. OWASP Agentic category). */
  taxonomy?: string;
  tags?: string[];
  createdAt?: string;
}

// ---------------------------------------------------------------------------
// Scanner interface
// ---------------------------------------------------------------------------

export interface ScannerContext {
  /** Absolute or relative root the scan was started from. */
  root: string;
  /** Registered third-party plugins contribute rules here. */
  registry: PluginRegistryLike;
  logger: Logger;
  /** Abort signal — allows cancelling long scans. */
  signal?: AbortSignal;
  /** Free-form options forwarded from the CLI/API. */
  options: Record<string, unknown>;
}

export interface PluginRegistryLike {
  getRule(id: string): RuleDefinition | undefined;
  allRules(): RuleDefinition[];
  plugins(): PluginDescriptor[];
  /**
   * The full rule set, for scanners that need to iterate rules rather than
   * look one up. Kept structurally typed so `types.ts` does not depend on the
   * evaluator implementation.
   */
  ruleSet(): {
    size: number;
    all(): RuleDefinition[];
    has(id: string): boolean;
    select(file: { path: string; language: string }, scanner?: string): RuleDefinition[];
  };
}

export interface Logger {
  debug(message: string, meta?: unknown): void;
  info(message: string, meta?: unknown): void;
  warn(message: string, meta?: unknown): void;
  error(message: string, meta?: unknown): void;
}

/**
 * Every scanner streams findings. Streaming (rather than buffering an array)
 * keeps memory flat on large repositories and lets the CLI print results as
 * they are discovered.
 */
export interface Scanner<TOptions = unknown> {
  readonly name: string;
  readonly targetType: ScanTargetType;
  /** Does this scanner need to talk to the network or spawn processes? */
  readonly sideEffects: 'none' | 'local-exec' | 'network';
  scan(target: ScanTarget, ctx: ScannerContext): AsyncIterable<Finding>;
  /** Optional per-scanner knobs, declared read-only so implementations may keep a private copy. */
  readonly options?: TOptions;
}

// ---------------------------------------------------------------------------
// Rule definitions (YAML rule packs)
// ---------------------------------------------------------------------------

export interface RuleDefinition {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  confidence?: Confidence;
  /** Languages this rule applies to; `*` for all. */
  languages?: string[];
  /** Scanner ids that own the rule, e.g. `agent`, `mcp`, `repo`. */
  scanners?: string[];
  taxonomy?: string;
  cwe?: string;
  tags?: string[];
  patterns?: RulePattern[];
  /** Conditions that must all hold for the rule to match. */
  requires?: string[];
  /** Conditions that suppress the rule when present. */
  unless?: string[];
  remediation?: Partial<Remediation>;
  compliance?: ComplianceMapping[];
  references?: string[];
  metadata?: Record<string, unknown>;
}

/**
 * A pattern is an intentionally small, well-defined matcher. Supporting
 * regex, literal, AST-call, and configuration-key patterns keeps rule files
 * declarative while still being expressive enough to catch real issues.
 */
export type RulePattern =
  | { type: 'regex'; pattern: string; flags?: string }
  | { type: 'literal'; value: string }
  | { type: 'contains-all'; values: string[] }
  | { type: 'contains-any'; values: string[] }
  | { type: 'call'; callee: string; argsContain?: string[]; argsNotContain?: string[] }
  | { type: 'assignment'; variable: string; valueMatches: string }
  | { type: 'jsonpath'; path: string; operator: 'equals' | 'not-equals' | 'exists' | 'contains'; value?: unknown }
  | { type: 'entropy'; min: number; pattern?: string };

export interface RulePack {
  id: string;
  version: string;
  name: string;
  description?: string;
  rules: RuleDefinition[];
}

// ---------------------------------------------------------------------------
// Plugin system
// ---------------------------------------------------------------------------

export interface PluginDescriptor {
  name: string;
  version: string;
  description?: string;
  author?: string;
  /** Rule packs contributed by the plugin. */
  rulePacks?: RulePack[];
  /** Scanners contributed by the plugin. */
  scanners?: Scanner[];
  /** Capabilities requested (shown to the user before enabling). */
  capabilities?: {
    network?: boolean;
    spawn?: boolean;
    filesystem?: boolean;
  };
}

export interface AegisPlugin extends PluginDescriptor {
  activate?(): void | Promise<void>;
  deactivate?(): void | Promise<void>;
}

// ---------------------------------------------------------------------------
// Scan results & reports
// ---------------------------------------------------------------------------

export interface ScanResult {
  target: ScanTarget;
  scanner: string;
  findings: Finding[];
  durationMs: number;
  /** Free-form scanner output (graphs, fingerprints, scores…). */
  artifacts?: Record<string, unknown>;
  errors?: string[];
}

export interface ScoreBreakdown {
  /** 0–100, higher is better. */
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  penalty: number;
  bySeverity: Record<Severity, number>;
  /** Weighted by confidence. */
  confidenceAdjusted: number;
}

export interface SecurityScore extends ScoreBreakdown {
  /** Per-category sub-scores, e.g. `tool_permissions`. */
  dimensions?: Record<string, number>;
}

export interface AgentScanReport {
  target: ScanTarget;
  frameworks: DetectedFramework[];
  findings: Finding[];
  score: SecurityScore;
  secretCount: number;
  durationMs: number;
  threatModel?: ThreatModelDocument;
}

export interface DetectedFramework {
  id: string;
  name: string;
  version?: string;
  evidence: string[];
  confidence: Confidence;
  fileCount: number;
}

export interface ThreatModelDocument {
  title: string;
  generatedAt: string;
  summary: string;
  mermaid: string;
  markdown: string;
  trustBoundaries: TrustBoundary[];
  assets: ThreatAsset[];
  attackSurface: string[];
}

export interface TrustBoundary {
  name: string;
  description: string;
  mermaidId: string;
}

export interface ThreatAsset {
  name: string;
  type: 'data' | 'credential' | 'service' | 'model' | 'tool';
  description: string;
  sensitivity: 'public' | 'internal' | 'confidential' | 'secret';
}
