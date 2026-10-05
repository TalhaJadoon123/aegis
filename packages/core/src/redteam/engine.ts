import {
  ATTACK_TEMPLATES,
  selectAttacks,
  type AttackTemplate,
  type ToolCapability,
} from './attacks.js';
import { createFitness, type EvaluationDetail, type EvaluatorOptions } from './fitness.js';
import { EvolutionEngine, type EvolutionConfig } from './genetic.js';
import { buildRedTeamReport, type RedTeamReport } from './report.js';
import type { RedTeamTarget } from './targets.js';

/**
 * Red team orchestrator.
 *
 * Ties the pieces together and, importantly, records *every* evaluation —
 * including the failures. A GA that only reports successes gives no way to tell
 * "this agent is secure" from "the search never got there", and the difference
 * matters when someone is relying on the result.
 */

export interface RedTeamOptions extends EvolutionConfig, EvaluatorOptions {
  /** Limit to specific attack ids. */
  attackIds?: string[];
  /** Limit to categories. */
  categories?: AttackTemplate['category'][];
  /** Include verbatim prompts in the report. Default true. */
  includePrompts?: boolean;
  /** Redact prompts for shareable exports. */
  redactPrompts?: boolean;
  /** Report that no real requests were sent. */
  dryRun?: boolean;
  /** Progress callback, invoked after each evaluation. */
  onProgress?: (progress: RedTeamProgress) => void;
  logger?: { info(m: string, meta?: unknown): void; warn(m: string, meta?: unknown): void };
}

export interface RedTeamProgress {
  evaluation: number;
  maxEvaluations: number;
  generation: number;
  bestScore: number;
  lastPrompt: string;
  succeeded: boolean;
  category: string;
}

export interface RedTeamRun {
  report: RedTeamReport;
  details: EvaluationDetail[];
  attacks: AttackTemplate[];
  /** Every prompt attempted, for the record. */
  transcripts: Array<{ prompt: string; response: string; succeeded: boolean }>;
}

export async function runRedTeam(
  target: RedTeamTarget,
  options: RedTeamOptions = {},
): Promise<RedTeamRun> {
  // Prefer the target's own declared capabilities; fall back to the configured
  // list, then to the full taxonomy when neither is known.
  const capabilities = (target.capabilities.length > 0
    ? target.capabilities
    : (options.capabilities ?? [])) as ToolCapability[];
  const attacks = selectAttacks(capabilities);
  const filtered = filterAttacks(attacks, options);

  if (filtered.length === 0) {
    throw new Error('no applicable attacks: check --attack and --category filters');
  }

  const fitness = createFitness(target, options);
  const engine = new EvolutionEngine(filtered, options);

  const details: EvaluationDetail[] = [];
  let evaluationIndex = 0;

  const wrapped = async (genome: Parameters<typeof fitness>[0]) => {
    const result = await fitness(genome);
    evaluationIndex++;
    details.push({
      attackId: genome.attackId,
      category: genome.category,
      severity: genome.attack.severity,
      succeeded: result.succeeded,
      score: result.score,
      prompt: genome.prompt,
      response: result.response,
      reasoning: result.reasoning,
      latencyMs: result.latencyMs,
      refused: isRefusal(result),
      indicator: result.reasoning,
      generation: 0,
    });
    options.onProgress?.({
      evaluation: evaluationIndex,
      maxEvaluations: options.maxEvaluations ?? 240,
      generation: Math.floor(evaluationIndex / Math.max(1, options.populationSize ?? 12)),
      bestScore: result.score,
      lastPrompt: genome.prompt,
      succeeded: result.succeeded,
      category: genome.category,
    });
    return result;
  };

  options.logger?.info(
    `red team: ${filtered.length} attack template(s), ${options.generations ?? 6} generation(s) ` +
      `of population ${options.populationSize ?? 12}, budget ${options.maxEvaluations ?? 240}`,
  );

  const evolution = await engine.run(wrapped);

  const report = buildRedTeamReport({
    target,
    details,
    evolution,
    attacks: filtered,
    dryRun: options.dryRun ?? false,
    includePrompts: options.includePrompts ?? true,
    ...(options.redactPrompts !== undefined ? { redactPrompts: options.redactPrompts } : {}),
  });

  options.logger?.info(
    `red team complete: ${report.summary.successfulBypasses}/${report.summary.attacksRun} bypasses ` +
      `(ASR ${(report.summary.attackSuccessRate * 100).toFixed(1)}%), risk ${report.summary.overallRisk}`,
  );

  return {
    report,
    details,
    attacks: filtered,
    transcripts: details.map((d) => ({
      prompt: d.prompt,
      response: d.response,
      succeeded: d.succeeded,
    })),
  };
}

function filterAttacks(attacks: AttackTemplate[], options: RedTeamOptions): AttackTemplate[] {
  let out = attacks;
  if (options.attackIds?.length) {
    const wanted = new Set(options.attackIds);
    out = out.filter((a) => wanted.has(a.id));
  }
  if (options.categories?.length) {
    const wanted = new Set(options.categories);
    out = out.filter((a) => wanted.has(a.category));
  }
  return out;
}

/** Re-use the fitness module's refusal detector without exporting the regexes. */
function isRefusal(result: { reasoning: string; succeeded: boolean }): boolean {
  return result.reasoning === 'refused';
}

export { ATTACK_TEMPLATES, selectAttacks };
export type { AttackTemplate, ToolCapability, RedTeamTarget };