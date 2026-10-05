import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { parseYaml, stringifyYaml, type YamlValue } from '../yaml.js';
import { toSeverity } from '../severity.js';
import type {
  ComplianceMapping,
  ComplianceFramework,
  Confidence,
  RuleDefinition,
  RulePack,
  RulePattern,
  Severity,
} from '../types.js';

export class RuleValidationError extends Error {
  readonly file?: string;
  readonly ruleId?: string;

  constructor(message: string, file?: string, ruleId?: string) {
    super(message);
    this.name = 'RuleValidationError';
    this.file = file;
    this.ruleId = ruleId;
  }
}

const VALID_FRAMEWORKS: ReadonlySet<string> = new Set<ComplianceFramework>([
  'owasp-agentic',
  'owasp-llm',
  'soc2',
  'iso27001',
  'gdpr',
  'eu-ai-act',
  'nist-ai-rmf',
  'mitre-atlas',
]);

const VALID_PATTERN_TYPES = new Set([
  'regex',
  'literal',
  'contains-all',
  'contains-any',
  'call',
  'assignment',
  'jsonpath',
  'entropy',
]);

/** Parse a YAML rule pack from a string, validating every rule. */
export function parseRulePack(source: string, file?: string): RulePack {
  let doc: unknown;
  try {
    doc = parseYaml(source);
  } catch (error) {
    throw new RuleValidationError(
      `invalid YAML: ${(error as Error).message}`,
      file,
    );
  }
  return normalizeRulePack(doc, file);
}

export async function loadRulePackFile(path: string): Promise<RulePack> {
  const source = await readFile(path, 'utf8');
  return parseRulePack(source, path);
}

export function serializeRulePack(pack: RulePack): string {
  return stringifyYaml(packToPlain(pack));
}

/**
 * Flatten a pack into the plain structure the YAML emitter understands.
 *
 * The cast is deliberate: `RuleDefinition` is an interface, so it has no
 * implicit index signature and cannot be assigned to `{ [k: string]: YamlValue }`
 * even though every field it carries *is* a valid YAML value.
 */
function packToPlain(pack: RulePack): YamlValue {
  return {
    id: pack.id,
    version: pack.version,
    name: pack.name,
    ...(pack.description ? { description: pack.description } : {}),
    rules: pack.rules,
  } as unknown as YamlValue;
}

export function normalizeRulePack(doc: unknown, file?: string): RulePack {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new RuleValidationError('rule pack must be a YAML mapping', file);
  }
  const raw = doc as Record<string, unknown>;
  const rulesRaw = raw['rules'];
  if (!Array.isArray(rulesRaw)) {
    throw new RuleValidationError('rule pack must contain a `rules` array', file);
  }
  const rules = rulesRaw.map((r, i) => normalizeRule(r, i, file));
  return {
    id: requireString(raw['id'], 'id', file),
    version: String(raw['version'] ?? '0.0.0'),
    name: requireString(raw['name'], 'name', file),
    ...(raw['description'] ? { description: String(raw['description']) } : {}),
    rules,
  };
}

function normalizeRule(raw: unknown, index: number, file?: string): RuleDefinition {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new RuleValidationError(`rules[${index}] must be a mapping`, file);
  }
  const r = raw as Record<string, unknown>;
  const id = requireString(r['id'], `rules[${index}].id`, file);
  const title = requireString(r['title'], `${id}.title`, file);
  const description = requireString(r['description'], `${id}.description`, file);

  const patternsRaw = r['patterns'];
  if (!Array.isArray(patternsRaw) || patternsRaw.length === 0) {
    throw new RuleValidationError(`${id} must define at least one pattern`, file, id);
  }
  const patterns = patternsRaw.map((p, i) => normalizePattern(p, `${id}.patterns[${i}]`, file, id));
  // Pre-compile regexes so a bad pattern fails at load time, not scan time.
  for (const p of patterns) {
    if (p.type === 'regex') {
      try {
        new RegExp(p.pattern, p.flags ?? 'gm');
      } catch (error) {
        throw new RuleValidationError(
          `${id} has an invalid regex: ${(error as Error).message}`,
          file,
          id,
        );
      }
    }
    const guards: string[] = [
      ...toStringArray(r['requires']),
      ...toStringArray(r['unless']),
    ];
    for (const p of guards) {
      const { pattern: body, flags } = normalizeRegexFlags(String(p), 'gm');
      try {
        new RegExp(body, flags);
      } catch (error) {
        throw new RuleValidationError(
          `${id} has an invalid ${'requires/unless'} regex: ${(error as Error).message}`,
          file,
          id,
        );
      }
    }
  }

  const compliance = normalizeCompliance(r['compliance'], id, file);

  return {
    id,
    title,
    description,
    severity: toSeverity(r['severity']),
    confidence: normalizeConfidence(r['confidence']),
    ...(Array.isArray(r['languages']) ? { languages: r['languages'].map(String) } : {}),
    ...(Array.isArray(r['scanners']) ? { scanners: r['scanners'].map(String) } : {}),
    ...(r['taxonomy'] ? { taxonomy: String(r['taxonomy']) } : {}),
    ...(r['cwe'] ? { cwe: String(r['cwe']) } : {}),
    ...(Array.isArray(r['tags']) ? { tags: r['tags'].map(String) } : {}),
    patterns,
    ...(Array.isArray(r['requires'])
      ? { requires: r['requires'].map((x) => String(x)) }
      : {}),
    ...(Array.isArray(r['unless'])
      ? { unless: r['unless'].map((x) => String(x)) }
      : {}),
    ...(r['remediation'] ? { remediation: r['remediation'] as RuleDefinition['remediation'] } : {}),
    ...(compliance.length ? { compliance } : {}),
    ...(Array.isArray(r['references']) ? { references: r['references'].map(String) } : {}),
    ...(r['metadata'] ? { metadata: r['metadata'] as Record<string, unknown> } : {}),
  };
}

function normalizePattern(raw: unknown, path: string, file?: string, ruleId?: string): RulePattern {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new RuleValidationError(`${path} must be a mapping`, file, ruleId);
  }
  const p = raw as Record<string, unknown>;
  const type = String(p['type'] ?? '');
  if (!VALID_PATTERN_TYPES.has(type)) {
    throw new RuleValidationError(
      `${path} has unknown pattern type "${type}" (expected one of ${[...VALID_PATTERN_TYPES].join(', ')})`,
      file,
      ruleId,
    );
  }
  switch (type) {
    case 'regex': {
      const { pattern, flags } = normalizeRegexFlags(
        requireString(p['pattern'], `${path}.pattern`, file),
        p['flags'] ? String(p['flags']) : undefined,
      );
      return { type: 'regex', pattern, flags };
    }
    case 'literal':
      return { type: 'literal', value: requireString(p['value'], `${path}.value`, file) };
    case 'contains-all':
      return { type: 'contains-all', values: requireStringArray(p['values'], `${path}.values`, file) };
    case 'contains-any':
      return { type: 'contains-any', values: requireStringArray(p['values'], `${path}.values`, file) };
    case 'call': {
      const callee = requireString(p['callee'], `${path}.callee`, file);
      return {
        type: 'call',
        callee,
        ...(p['argsContain'] ? { argsContain: requireStringArray(p['argsContain'], `${path}.argsContain`, file) } : {}),
        ...(p['argsNotContain'] ? { argsNotContain: requireStringArray(p['argsNotContain'], `${path}.argsNotContain`, file) } : {}),
      };
    }
    case 'assignment':
      return {
        type: 'assignment',
        variable: requireString(p['variable'], `${path}.variable`, file),
        valueMatches: requireString(p['valueMatches'], `${path}.valueMatches`, file),
      };
    case 'jsonpath': {
      const operators = ['equals', 'not-equals', 'exists', 'contains'] as const;
      type JsonPathOperator = (typeof operators)[number];
      const raw = String(p['operator'] ?? 'exists');
      const operator = operators.find((o) => o === raw);
      if (!operator) {
        throw new RuleValidationError(`${path}.operator is invalid`, file, ruleId);
      }
      return {
        type: 'jsonpath',
        path: requireString(p['path'], `${path}.path`, file),
        operator: operator as JsonPathOperator,
        ...(p['value'] !== undefined ? { value: p['value'] } : {}),
      };
    }
    case 'entropy':
      return {
        type: 'entropy',
        min: Number(p['min'] ?? 4.2),
        ...(p['pattern'] ? { pattern: String(p['pattern']) } : {}),
      };
    default:
      throw new RuleValidationError(`${path} is unreachable`, file, ruleId);
  }
}

/** Coerce an unknown YAML value into a string array, tolerating a bare scalar. */
function toStringArray(raw: unknown): string[] {
  if (raw === undefined || raw === null) return [];
  if (Array.isArray(raw)) return raw.map((v) => String(v));
  return [String(raw)];
}

function normalizeCompliance(raw: unknown, ruleId: string, file?: string): ComplianceMapping[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) {
    throw new RuleValidationError(`${ruleId}.compliance must be an array`, file, ruleId);
  }
  return raw.map((entry, i) => {
    if (!entry || typeof entry !== 'object') {
      throw new RuleValidationError(`${ruleId}.compliance[${i}] must be a mapping`, file, ruleId);
    }
    const c = entry as Record<string, unknown>;
    const framework = String(c['framework'] ?? '');
    if (!VALID_FRAMEWORKS.has(framework)) {
      throw new RuleValidationError(
        `${ruleId}.compliance[${i}].framework "${framework}" is not a known framework`,
        file,
        ruleId,
      );
    }
    return {
      framework: framework as ComplianceFramework,
      control: requireString(c['control'], `${ruleId}.compliance[${i}].control`, file),
      ...(c['title'] ? { title: String(c['title']) } : {}),
      ...(c['description'] ? { description: String(c['description']) } : {}),
      relevant: c['relevant'] === undefined ? true : Boolean(c['relevant']),
      ...(c['url'] ? { url: String(c['url']) } : {}),
    };
  });
}

/**
 * Normalise a rule regex into JavaScript form.
 *
 * Rule packs are written with PCRE-style inline flags (`(?i)`, `(?is)`, …)
 * because that is what security engineers reach for out of habit. JavaScript
 * has no inline flags, so they are hoisted into the flags string here. This
 * keeps rule files portable between the two ecosystems.
 */
export function normalizeRegexFlags(
  pattern: string,
  declaredFlags?: string,
): { pattern: string; flags: string } {
  let body = pattern;
  let flags = new Set((declaredFlags ?? 'gm').split(''));

  // Hoist leading inline flag groups, e.g. `(?i)` `(?im)` `(?is)` `(?-i)`.
  for (;;) {
    const match = /^\(\?([imsux]*)\)/.exec(body);
    if (!match) break;
    body = body.slice(match[0].length);
    for (const flag of match[1]!) {
      if (flag === '-') {
        flags.delete('i');
        flags.delete('m');
        flags.delete('s');
        continue;
      }
      flags.add(flag);
    }
  }

  // JS has no `\A`/`\z`; anchor to the string boundaries instead.
  body = body.replace(/\\A/g, '^').replace(/\\z/g, '$').replace(/\\Z/g, '$');

  // Only keep flags that are meaningful for a global line-oriented match.
  const order = 'gimsuy';
  const normalized = [...flags].filter((f) => order.includes(f)).sort().join('');
  return { pattern: body, flags: normalized || 'gm' };
}

function normalizeConfidence(raw: unknown): Confidence | undefined {
  if (raw === undefined || raw === null) return undefined;
  const value = String(raw);
  if (['confirmed', 'high', 'medium', 'low'].includes(value)) return value as Confidence;
  // Tolerate synonyms used by upstream rule packs.
  if (value === 'certain' || value === 'definite') return 'confirmed';
  if (value === 'strong') return 'high';
  if (value === 'tentative' || value === 'possible') return 'medium';
  return undefined;
}

function requireString(value: unknown, path: string, file?: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new RuleValidationError(`${path} must be a non-empty string`, file);
  }
  return value;
}

function requireStringArray(value: unknown, path: string, file?: string): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new RuleValidationError(`${path} must be a non-empty array`, file);
  }
  return value.map((v) => {
    if (typeof v !== 'string') {
      throw new RuleValidationError(`${path} must contain only strings`, file);
    }
    return v;
  });
}

/** Stable content hash for a rule pack — used to detect stale caches. */
export function rulePackHash(pack: RulePack): string {
  return createHash('sha256').update(serializeRulePack(pack)).digest('hex').slice(0, 16);
}

export function severityOf(rule: RuleDefinition): Severity {
  return toSeverity(rule.severity);
}
