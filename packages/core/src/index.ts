/**
 * @aegis/core — the Aegis scanning engine.
 *
 * Everything a consumer needs is re-exported here. Scanners implement the
 * `Scanner` interface and stream `Finding` objects; every renderer in
 * `output.ts` and every compliance assessment in `compliance.ts` consumes
 * those same objects, which is what lets `aegis scan | aegis report` work.
 */

// --- Core contracts --------------------------------------------------------
export type {
  AegisPlugin,
  AgentScanReport,
  ComplianceFramework,
  ComplianceMapping,
  Confidence,
  DetectedFramework,
  Finding,
  PluginDescriptor,
  PluginRegistryLike,
  RuleDefinition,
  RulePack,
  RulePattern,
  ScanResult,
  ScanTarget,
  ScanTargetType,
  Scanner,
  ScannerContext,
  SecurityScore,
  Severity,
  ThreatAsset,
  ThreatModelDocument,
  TrustBoundary,
} from './types.js';

// --- Severity, scoring, dedup ---------------------------------------------
export {
  aggregateCompliance,
  compareSeverity,
  computeScore,
  dedupeFindings,
  filterBySeverity,
  formatLocation,
  isBlocking,
  maxSeverity,
  sortFindings,
  toSeverity,
} from './severity.js';

// --- Fingerprints ---------------------------------------------------------
export { canonicalize, fingerprintFinding, normalizeEvidence, normalizePath, shannonEntropy, stableHash } from './fingerprint.js';

// --- Logging ---------------------------------------------------------------
export { createLogger, silentLogger, type LogLevel } from './logger.js';

// --- Plugins ---------------------------------------------------------------
export { PluginRegistry, findScanner, streamFindings } from './registry.js';

// --- Engine ----------------------------------------------------------------
export { runScan, runScanAtSeverity, runScanners, type RunOptions, type RunSummary } from './engine.js';

// --- YAML (dependency-free subset parser) ---------------------------------
export { YamlParseError, parseYaml, parseYamlDocuments, stringifyYaml } from './yaml.js';

// --- Rule engine -----------------------------------------------------------
export {
  RuleSet,
  evaluateFile,
  extractRegion,
  matchToFinding,
  offsetToLineCol,
  redactCredentials,
  type EvaluatorOptions,
  type FileUnderScan,
  type RuleMatch,
} from './rules/evaluator.js';
export {
  RuleValidationError,
  loadRulePackFile,
  normalizeRegexFlags,
  parseRulePack,
  rulePackHash,
  serializeRulePack,
} from './rules/loader.js';
export { defaultRuleDirectories, loadRulePacks, loadDefaultRules } from './rules/index.js';

// --- File walking ----------------------------------------------------------
export {
  DEFAULT_IGNORE,
  detectLanguage,
  isProbablyBinary,
  loadFile,
  loadFiles,
  parseJsonLoose,
  walkFiles,
  type WalkedFile,
} from './walk.js';

// --- MCP scanner -----------------------------------------------------------
export {
  discoverMcpServers,
  extractServers,
  knownConfigLocations,
  looksLikeSecret,
  parseProcessCommand,
  redact,
  type DiscoveredMcpServer,
  type McpConfigLocation,
} from './scanners/mcp/discovery.js';
export {
  JSONRPC_ERRORS,
  MCP_METHODS,
  MCP_PROTOCOL_VERSION,
  SUPPORTED_PROTOCOL_VERSIONS,
  McpMessageDecoder,
  McpProtocolError,
  emptyIntrospection,
  type McpIntrospection,
  type McpPrompt,
  type McpResource,
  type McpTool,
} from './scanners/mcp/protocol.js';
export {
  HttpConnector,
  MockConnector,
  StdioConnector,
  createConnector,
  type Connector,
} from './scanners/mcp/connectors.js';
export {
  buildSupplyChainGraph,
  deriveCapabilities,
  graphToD3,
  graphToMermaid,
  hasExfiltrationPath,
  type CapabilityModel,
  type SupplyChainGraph,
} from './scanners/mcp/graph.js';
export { analyzeIntrospection, analyzeMcpConfig } from './scanners/mcp/analyzers.js';
export { McpScanner, renderGraphHtml, type McpScanOptions, type McpScanReport } from './scanners/mcp/scanner.js';

// --- Agent scanner --------------------------------------------------------
export { FRAMEWORK_SIGNATURES, FRAMEWORK_TRUST_MODEL, detectFrameworks } from './scanners/agent/frameworks.js';
export { redact as redactSecret, scanSecrets, secretsToFindings, type SecretMatch } from './scanners/agent/secrets.js';
export {
  analyzePromptInjection,
  analyzeToolPoisoning,
  analyzeUntrustedText,
  signalsToFindings,
  type InjectionSignal,
  type PromptAnalysisInput,
} from './scanners/agent/prompt-injection.js';
export { generateThreatModel, type ThreatModelInput } from './scanners/agent/threat-model.js';
export { AgentScanner, type AgentScannerOptions } from './scanners/agent/scanner.js';

// --- Red team --------------------------------------------------------------
export {
  ATTACK_TEMPLATES,
  SLOTS,
  attacksByCategory,
  fillTemplate,
  getAttack,
  selectAttacks,
  templateSlots,
  type AttackCategory,
  type AttackTemplate,
  type ToolCapability,
} from './redteam/attacks.js';
export {
  EvolutionEngine,
  Rng,
  crossover,
  diversityBonus,
  mutate,
  randomGenome,
  tournamentSelect,
  type EvolutionConfig,
  type EvolutionResult,
  type FitnessFn,
  type Genome,
} from './redteam/genetic.js';
export {
  createFitness,
  detectRefusal,
  evaluateIndicator,
  summariseEvaluations,
  type EvaluationDetail,
  type EvaluatorOptions as FitnessOptions,
} from './redteam/fitness.js';
export {
  DryRunTarget,
  HttpRedTeamTarget,
  McpRedTeamTarget,
  ScriptRedTeamTarget,
  extractText,
  inferCapabilities,
  type RedTeamTarget,
  type TargetResponse,
} from './redteam/targets.js';
export { buildRedTeamReport, type RedTeamReport } from './redteam/report.js';
export { runRedTeam, type RedTeamOptions, type RedTeamProgress, type RedTeamRun } from './redteam/engine.js';

// --- Sandbox ---------------------------------------------------------------
export {
  fingerprintBehavior,
  compareFingerprints,
  type BehaviorEvent,
  type BehavioralFingerprint,
  type EventKind,
} from './sandbox/fingerprint.js';
export {
  DEFAULT_POLICIES,
  evaluate,
  parseAgentLine,
  runSandbox,
  type AgentPolicy,
  type PolicyViolation,
  type SandboxOptions,
  type SandboxResult,
} from './sandbox/runner.js';

// --- Remediation -----------------------------------------------------------
export {
  MECHANICAL_FIXES,
  applyRemediation,
  buildRemediationPlan,
  unifiedDiff,
  validatePatch,
  type Remediation,
  type RemediationPlan,
  type RemediationStrategy,
} from './remediation.js';
export { applyEdits, countOccurrences, parseUnifiedDiff, type FileEdit } from './patch.js';

// --- Threat intelligence ---------------------------------------------------
export {
  addEdge,
  addNode,
  computeStats,
  createGraph,
  edgeHash,
  graphToD3 as attackGraphToD3,
  graphToMermaid as attackGraphToMermaid,
  longestEnablePath,
  mergeGraphs,
  nodeHash,
  reachableFrom as attackReachableFrom,
  severityRank,
  type AttackEdge,
  type AttackGraph,
  type AttackNode,
  type EdgeKind,
  type NodeKind,
  type Provenance,
} from './intel/graph.js';
export { SEED_ATTACKS, seedGraph, type SeedTechnique } from './intel/seed.js';

// --- Output ----------------------------------------------------------------
export {
  AEGIS_URI,
  AEGIS_VERSION,
  OUTPUT_FORMATS,
  buildDocument,
  fileExtension,
  mediaType,
  render,
  rollUpCompliance,
  toCsv,
  toHtml,
  toJson,
  toJsonl,
  toMarkdown,
  toSarif,
  toText,
  type AegisDocument,
  type OutputFormat,
} from './output.js';

// --- Compliance ------------------------------------------------------------
export {
  CONTROLS,
  FRAMEWORKS,
  assessCompliance,
  buildComplianceDocuments,
  executiveSummary,
  getControl,
  toAttestationHtml,
  toAttestationMarkdown,
  type ComplianceReport,
  type ComplianceSummary,
  type ControlAssessment,
  type ControlDefinition,
  type ControlStatus,
} from './compliance.js';

export const VERSION = '0.1.0';