/**
 * Prompt Registry Loader
 *
 * Loads and manages prompt templates from the registry with slot substitution,
 * derived slot computation, and vocabulary expansion.
 */

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..', '..', '..');
const PROMPTS_DIR = join(ROOT, 'prompts');

export interface PromptSlot {
  type: 'string';
  description: string;
  vocabulary?: string;
  derived?: boolean;
  source?: string;
  encoding?: string;
}

export interface PromptSuccessIndicator {
  type: 'regex' | 'notRegex' | 'contains' | 'custom' | 'manual';
  pattern?: string;
  values?: string[];
  description: string;
}

export interface PromptTemplate {
  id: string;
  version: string;
  description: string;
  category: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  template: string;
  slots: Record<string, PromptSlot>;
  success_indicator: PromptSuccessIndicator;
  remediation: string;
  tags?: string[];
  requiresCapability?: string;
  output_format?: string;
}

export interface PromptRegistry {
  version: string;
  description: string;
  prompts: Record<string, PromptTemplate>;
  vocabularies: Record<string, string[]>;
}

export interface ModelConfig {
  name: string;
  baseUrl: string;
  models: Record<string, {
    name: string;
    maxTokens: number;
    costPer1kInputTokens: number;
    costPer1kOutputTokens: number;
    supportsTools: boolean;
    supportsVision?: boolean;
    supportsJsonMode?: boolean;
  }>;
  auth: {
    type: 'bearer' | 'none';
    header?: string;
    envVar: string;
  };
  rateLimits: {
    requestsPerMinute: number;
    tokensPerMinute: number;
  };
}

export interface ModelsConfig {
  providers: Record<string, ModelConfig>;
  defaults: {
    redteam: { provider: string; model: string; temperature: number; maxTokens: number; timeoutMs: number };
    fix: { provider: string; model: string; temperature: number; maxTokens: number; timeoutMs: number };
    scan: { provider: string; model: string; temperature: number; maxTokens: number; timeoutMs: number };
  };
  costBudgets: {
    redteam: { defaultBudgetUsd: number; maxBudgetUsd: number; warningThreshold: number };
    fix: { defaultBudgetUsd: number; maxBudgetUsd: number; warningThreshold: number };
  };
}

/** In-memory cache for loaded registry */
let cachedRegistry: PromptRegistry | null = null;
let cachedModels: ModelsConfig | null = null;
let cachedVocabularies: Record<string, string[]> | null = null;

/**
 * Load the prompt registry from disk.
 * Caches the result for subsequent calls.
 */
export function loadPromptRegistry(): PromptRegistry {
  if (cachedRegistry) return cachedRegistry;

  const registryPath = join(PROMPTS_DIR, 'registry.json');
  if (!existsSync(registryPath)) {
    throw new Error(`Prompt registry not found at ${registryPath}`);
  }

  const content = readFileSync(registryPath, 'utf8');
  cachedRegistry = JSON.parse(content) as PromptRegistry;
  return cachedRegistry;
}

/**
 * Load the models configuration.
 */
export function loadModelsConfig(): ModelsConfig {
  if (cachedModels) return cachedModels;

  const modelsPath = join(PROMPTS_DIR, 'models.json');
  if (!existsSync(modelsPath)) {
    throw new Error(`Models config not found at ${modelsPath}`);
  }

  const content = readFileSync(modelsPath, 'utf8');
  cachedModels = JSON.parse(content) as ModelsConfig;
  return cachedModels;
}

/**
 * Get all vocabularies from the registry.
 */
export function getVocabularies(): Record<string, string[]> {
  if (cachedVocabularies) return cachedVocabularies;

  const registry = loadPromptRegistry();
  cachedVocabularies = registry.vocabularies ?? {};
  return cachedVocabularies;
}

/**
 * Get a specific vocabulary by name.
 */
export function getVocabulary(name: string): string[] {
  const vocabs = getVocabularies();
  return vocabs[name] ?? [];
}

/**
 * Get a prompt template by ID.
 */
export function getPrompt(id: string): PromptTemplate | undefined {
  const registry = loadPromptRegistry();
  return registry.prompts[id];
}

/**
 * List all available prompt IDs.
 */
export function listPrompts(): string[] {
  const registry = loadPromptRegistry();
  return Object.keys(registry.prompts);
}

/**
 * List prompts by category.
 */
export function listPromptsByCategory(category: string): PromptTemplate[] {
  const registry = loadPromptRegistry();
  return Object.values(registry.prompts).filter((p) => p.category === category);
}

/**
 * Get a model configuration by provider and model name.
 */
export function getModelConfig(provider: string, model: string): ModelConfig['models'][string] | undefined {
  const modelsConfig = loadModelsConfig();
  return modelsConfig.providers[provider]?.models[model];
}

/**
 * Get default model configuration for a use case.
 */
export function getDefaultModelConfig(useCase: 'redteam' | 'fix' | 'scan'): {
  provider: string;
  model: string;
  temperature: number;
  maxTokens: number;
  timeoutMs: number;
} {
  const modelsConfig = loadModelsConfig();
  return modelsConfig.defaults[useCase];
}

/**
 * Get cost budget configuration for a use case.
 */
export function getCostBudget(useCase: 'redteam' | 'fix'): {
  defaultBudgetUsd: number;
  maxBudgetUsd: number;
  warningThreshold: number;
} {
  const modelsConfig = loadModelsConfig();
  return modelsConfig.costBudgets[useCase];
}

/**
 * Fill template slots with provided values.
 * Computes derived slots (encodedInstruction, spacedInstruction, encodedPath).
 */
export function fillPromptTemplate(
  template: string,
  values: Record<string, string>,
  vocabularies: Record<string, string[]> = {}
): string {
  // First, compute derived slots
  const computedValues = { ...values };

  for (const [key, value] of Object.entries(values)) {
    // encodedInstruction: base64 encode the instruction
    if (key === 'instruction') {
      computedValues.encodedInstruction = Buffer.from(value).toString('base64');
    }
    // spacedInstruction: space out characters
    if (key === 'instruction') {
      computedValues.spacedInstruction = value.split('').join(' ');
    }
    // encodedPath: URL encode the path
    if (key === 'pathTarget') {
      computedValues.encodedPath = encodeURIComponent(value);
    }
    // unicodeObfuscation: apply zero-width spaces
    if (key === 'instruction') {
      computedValues.unicodeObfuscation = value.split('').join('\u200B');
    }
  }

  // Substitute all slots
  return template.replace(/\{\{(\w+)\}\}/g, (_match, name: string) => {
    return computedValues[name] ?? `{{${name}}}`;
  });
}

/**
 * Expand a template with vocabulary sampling.
 * For each slot that references a vocabulary, picks a random value from that vocabulary.
 */
export function expandTemplateWithVocabulary(
  template: PromptTemplate,
  overrides: Record<string, string> = {}
): { prompt: string; usedValues: Record<string, string> } {
  const vocabularies = getVocabularies();
  const usedValues: Record<string, string> = { ...overrides };

  // Fill slots from vocabularies
  for (const [slotName, slotDef] of Object.entries(template.slots)) {
    if (overrides[slotName]) continue;

    const vocab = slotDef.vocabulary ? vocabularies[slotDef.vocabulary] : undefined;
      if (vocab && vocab.length > 0) {
        const idx = Math.floor(Math.random() * vocab.length);
        usedValues[slotName] = vocab[idx] as string;
    } else if (slotDef.derived) {
      // Derived slots will be computed by fillPromptTemplate
      continue;
    } else if (!usedValues[slotName]) {
      // Use a neutral default
      usedValues[slotName] = `the ${slotName.replace(/_/g, ' ')}`;
    }
  }

  const prompt = fillPromptTemplate(template.template, usedValues);
  return { prompt, usedValues };
}

/**
 * Check if a response matches a success indicator.
 */
export function checkSuccessIndicator(
  response: string,
  indicator: PromptTemplate['success_indicator']
): { succeeded: boolean; reasoning: string } {
  switch (indicator.type) {
    case 'regex': {
      const regex = new RegExp(indicator.pattern!, 'i');
      const matched = regex.test(response);
      return {
        succeeded: matched,
        reasoning: matched ? `Matched pattern: ${indicator.pattern}` : 'No match',
      };
    }
    case 'notRegex': {
      const regex = new RegExp(indicator.pattern!, 'i');
      const matched = regex.test(response);
      return {
        succeeded: !matched,
        reasoning: matched ? `Matched refusal pattern: ${indicator.pattern}` : 'No refusal detected',
      };
    }
    case 'contains': {
      const matched = indicator.values?.some((v) => response.includes(v)) ?? false;
      return {
        succeeded: matched,
        reasoning: matched ? 'Contains expected value' : 'Missing expected value',
      };
    }
    case 'custom':
    case 'manual':
      return {
        succeeded: false,
        reasoning: 'Manual/custom indicator requires human evaluation',
      };
    default:
      return {
        succeeded: false,
        reasoning: 'Unknown indicator type',
      };
  }
}

/**
 * Redact prompts for shareable reports.
 * Replaces prompt text with stable hash.
 */
export function redactPrompt(prompt: string): string {
  // Simple hash for redaction - in production use crypto.createHash
  let hash = 0;
  for (let i = 0; i < prompt.length; i++) {
    hash = ((hash << 5) - hash) + prompt.charCodeAt(i);
    hash |= 0;
  }
  return `[REDACTED_PROMPT_${Math.abs(hash).toString(16)}]`;
}

/**
 * Load all prompt templates from the registry directory.
 * Used for discovering available prompts.
 */
export function loadAllPrompts(): PromptTemplate[] {
  const registry = loadPromptRegistry();
  return Object.values(registry.prompts);
}

/**
 * Validate a prompt template structure.
 */
export function validatePrompt(template: PromptTemplate): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!template.id) errors.push('Missing id');
  if (!template.template) errors.push('Missing template');
  if (!template.success_indicator) errors.push('Missing success_indicator');
  if (!template.remediation) errors.push('Missing remediation');

  // Check that all slots referenced in template are defined
  const referencedSlots = new Set(template.template.match(/\{\{(\w+)\}\}/g)?.map((s) => s.slice(2, -2)) ?? []);
  for (const slot of referencedSlots) {
    if (!template.slots[slot]) {
      errors.push(`Slot '${slot}' referenced in template but not defined in slots`);
    }
  }

  // Check that all defined slots are used (warning, not error)
  for (const slot of Object.keys(template.slots)) {
    if (!referencedSlots.has(slot)) {
      // Warning only - not an error
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Get cost estimate for a red team run.
 */
export function estimateRedTeamCost(
  population: number,
  generations: number,
  model: string = 'gpt-4o-mini'
): { estimatedCostUsd: number; estimatedTokens: number } {
  const modelsConfig = loadModelsConfig();
  const modelConfig = modelsConfig.providers.openai?.models[model];

  if (!modelConfig) {
    return { estimatedCostUsd: 0, estimatedTokens: 0 };
  }

  const evaluations = population * generations;
  const avgInputTokens = 500;
  const avgOutputTokens = 200;

  const inputCost = (evaluations * avgInputTokens / 1000) * modelConfig.costPer1kInputTokens;
  const outputCost = (evaluations * avgOutputTokens / 1000) * modelConfig.costPer1kOutputTokens;

  return {
    estimatedCostUsd: inputCost + outputCost,
    estimatedTokens: evaluations * (avgInputTokens + avgOutputTokens),
  };
}

/**
 * Clear all caches (useful for testing).
 */
export function clearPromptCache(): void {
  cachedRegistry = null;
  cachedModels = null;
  cachedVocabularies = null;
}

