import { readFile } from 'node:fs/promises';
import { computeScore } from '../../severity.js';
import { RuleSet, evaluateFile, matchToFinding, type FileUnderScan } from '../../rules/evaluator.js';
import { loadFile, parseJsonLoose, walkFiles, DEFAULT_IGNORE, type WalkedFile } from '../../walk.js';
import type {
  AgentScanReport,
  Finding,
  Scanner,
  ScanTarget,
  ScannerContext,
  Severity,
} from '../../types.js';
import { detectFrameworks } from './frameworks.js';
import { scanSecrets, secretsToFindings } from './secrets.js';
import { analyzePromptInjection, signalsToFindings } from './prompt-injection.js';
import { generateThreatModel } from './threat-model.js';

export interface AgentScannerOptions {
  rules?: RuleSet;
  /** Minimum entropy for the secret sweep. Default 3.5. */
  secretMinEntropy?: number;
  /** Emit a threat model document. Default true. */
  threatModel?: boolean;
  /** Skip prompt-injection analysis (it is regex-bound and can be noisy). */
  skipPromptAnalysis?: boolean;
  maxFiles?: number;
  minSeverity?: Severity;
}

/**
 * Agent codebase scanner.
 *
 * Combines three detection strategies, because each catches a different class
 * of defect:
 *
 *  1. The declarative rule packs (OWASP Agentic Top 10, MCP, secrets, …) —
 *     broad, auditable, reviewable by people who do not read TypeScript.
 *  2. Vendor-specific secret detection — precision-critical, so it lives in
 *     code where it can be tuned against real-world false positives.
 *  3. Structural prompt analysis — the class of issue that only exists in agent
 *     systems and is invisible to general SAST.
 */
export class AgentScanner implements Scanner<AgentScannerOptions> {
  readonly name = 'agent';
  readonly targetType = 'agent' as const;
  readonly sideEffects = 'none' as const;
  readonly options: AgentScannerOptions;

  constructor(options: AgentScannerOptions = {}) {
    this.options = options;
  }

  async *scan(target: ScanTarget, ctx: ScannerContext): AsyncIterable<Finding> {
    const root = target.path ?? ctx.root;
    // An explicitly supplied RuleSet wins; otherwise fall back to whatever the
    // registry has loaded (shipped packs plus any plugin contributions).
    const rules = (this.options.rules ?? ctx.registry.ruleSet()) as RuleSet;

    const files = await walkFiles({
      root,
      ignore: target.config?.['ignore'] as string[] | undefined,
      maxFiles: this.options.maxFiles ?? 20_000,
      signal: ctx.signal,
    });

    // Read each file exactly once and reuse the contents for framework
    // detection, rule evaluation, secret scanning and prompt analysis. On a
    // large repository the naive version of this tripled the I/O.
    const usable = (await Promise.all(files.map((f) => loadFileQuietly(f)))).filter(
      (f): f is LoadedFile => f !== null,
    );

    const frameworks = detectFrameworks(
      usable.map((f) => ({ path: f.path, content: f.content, language: f.language })),
    );

    ctx.logger.info(
      `agent scanner: ${usable.length} file(s), frameworks: ${
        frameworks.map((f) => f.name).join(', ') || 'none detected'
      }`,
    );

    for (const file of usable) {
      if (ctx.signal?.aborted) return;

      const asFileUnderScan: FileUnderScan = {
        path: file.path,
        content: file.content,
        language: file.language,
        targetType: 'agent',
        ...(file.json !== undefined ? { json: file.json } : {}),
      };

      // 1. Rule packs.
      if (rules.size > 0) {
        for (const match of evaluateFile(rules, asFileUnderScan, { scanner: 'agent' })) {
          yield matchToFinding(match, 'agent');
        }
      }

      // 2. Secrets.
      const secrets = scanSecrets(file.path, file.content, {
        ...(this.options.secretMinEntropy !== undefined
          ? { minEntropy: this.options.secretMinEntropy }
          : {}),
      });
      for (const finding of secretsToFindings(file.path, secrets)) {
        yield finding;
      }

      // 3. Prompt injection structure.
      if (!this.options.skipPromptAnalysis) {
        const signals = analyzePromptInjection({ path: file.path, content: file.content });
        for (const finding of signalsToFindings(file.path, signals, 'agent')) {
          yield finding;
        }
      }
    }

    // The threat model needs the complete finding set, so it is produced by
    // `scanToReport`. Streaming it from here would mean buffering every
    // finding first, which defeats the point of a streaming scanner.
    void generateThreatModel;
  }

  /**
   * The report-producing path. Streaming exists for the CLI; the dashboard and
   * the reports need the whole picture at once, so this collects and computes.
   */
  async scanToReport(target: ScanTarget, ctx: ScannerContext): Promise<AgentScanReport> {
    const started = Date.now();
    const root = target.path ?? ctx.root;
    const findings: Finding[] = [];

    for await (const finding of this.scan(target, ctx)) {
      findings.push(finding);
    }

    const files = await walkFiles({ root, signal: ctx.signal, maxFiles: this.options.maxFiles ?? 20_000 });
    const loaded = (await Promise.all(files.map((f) => loadFileQuietly(f)))).filter(
      (f): f is LoadedFile => f !== null,
    );
    const frameworks = detectFrameworks(
      loaded.map((f) => ({ path: f.path, content: f.content, language: f.language })),
    );
    ctx.logger.info(
      `agent scanner: ${loaded.length} file(s), frameworks: ${
        frameworks.map((f) => f.name).join(', ') || 'none detected'
      }`,
    );

    const report: AgentScanReport = {
      target,
      frameworks,
      findings,
      score: computeScore({ findings }),
      secretCount: findings.filter((f) => f.ruleId === 'AEGIS-SEC-001').length,
      durationMs: Date.now() - started,
    };

    if (this.options.threatModel !== false) {
      report.threatModel = generateThreatModel({
        root,
        frameworks,
        findings,
        files: loaded.map((f) => ({ path: f.path, language: f.language })),
      });
    }

    return report;
  }
}

type LoadedFile = WalkedFile & { content: string; json?: unknown };

async function loadFileQuietly(file: WalkedFile): Promise<LoadedFile | null> {
  try {
    const content = await readFile(file.absolutePath, 'utf8');
    const loaded: LoadedFile = { ...file, content };
    if (file.language === 'json') {
      try {
        loaded.json = parseJsonLoose(content);
      } catch {
        /* leave json undefined; jsonpath rules simply will not apply */
      }
    }
    return loaded;
  } catch {
    return null;
  }
}

export { DEFAULT_IGNORE };