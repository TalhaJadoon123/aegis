import { fingerprintFinding, normalizeEvidence, shannonEntropy } from '../fingerprint.js';
import { normalizeRegexFlags } from './loader.js';
import { toSeverity } from '../severity.js';
import type { Finding, RuleDefinition, RulePack, RulePattern, ScanTargetType } from '../types.js';

export interface FileUnderScan {
  /** Path as it should appear in reports. */
  path: string;
  content: string;
  /** `typescript` | `python` | `go` | `json` | `yaml` | `markdown` | `text` | … */
  language: string;
  /** Which scanners should evaluate rules against this file. */
  targetType?: ScanTargetType;
  /** Parsed JSON when the file is JSON — enables `jsonpath` patterns. */
  json?: unknown;
}

export interface RuleMatch {
  rule: RuleDefinition;
  file: FileUnderScan;
  evidence: string;
  line: number;
  column: number;
  /** Optional narrowing detail, e.g. the matched JSON path. */
  detail?: string;
}

export interface EvaluatorOptions {
  /** Cap the number of findings emitted per rule per file. Default 25. */
  maxMatchesPerRule?: number;
  /** Only evaluate rules whose `scanners` list includes this value. */
  scanner?: string;
  /** Skip rules that only apply to these extensions. */
  includeLanguages?: string[];
}

/** A compiled, indexed set of rules. */
export class RuleSet {
  readonly packs: RulePack[];
  private readonly byId = new Map<string, RuleDefinition>();

  constructor(packs: readonly RulePack[] = []) {
    this.packs = [...packs];
    for (const pack of packs) for (const rule of pack.rules) this.add(rule);
  }

  add(rule: RuleDefinition): void {
    if (this.byId.has(rule.id)) {
      throw new Error(`duplicate rule id: ${rule.id}`);
    }
    this.byId.set(rule.id, rule);
  }

  merge(other: RuleSet): RuleSet {
    const merged = new RuleSet(this.packs);
    for (const pack of other.packs) merged.packs.push(pack);
    for (const rule of other.all()) merged.add(rule);
    return merged;
  }

  get(id: string): RuleDefinition | undefined {
    return this.byId.get(id);
  }

  has(id: string): boolean {
    return this.byId.has(id);
  }

  all(): RuleDefinition[] {
    return [...this.byId.values()];
  }

  get size(): number {
    return this.byId.size;
  }

  /** Rules applicable to a given file language and scanner. */
  select(file: FileUnderScan, scanner?: string): RuleDefinition[] {
    return this.all().filter((rule) => {
      if (scanner && rule.scanners && rule.scanners.length > 0 && !rule.scanners.includes(scanner)) {
        return false;
      }
      if (rule.languages && rule.languages.length > 0 && !rule.languages.includes('*')) {
        if (!rule.languages.includes(file.language)) return false;
      }
      return true;
    });
  }

  toJSON(): RulePack[] {
    return this.packs;
  }
}

/**
 * Evaluate a single file against a rule set.
 *
 * The evaluator is intentionally line-oriented rather than AST-based for
 * portability: agent code in the wild is a mix of TypeScript, Python, Go and
 * config, often without a resolvable dependency graph. Structural patterns
 * (`call`, `assignment`) give us AST-level precision for the constructs that
 * actually matter (shell=True, eval(), fetch() with a user-controlled URL)
 * without needing a compiler toolchain present.
 */
export function evaluateFile(
  rules: RuleSet,
  file: FileUnderScan,
  options: EvaluatorOptions = {},
): RuleMatch[] {
  const max = options.maxMatchesPerRule ?? 25;
  const matches: RuleMatch[] = [];
  const scanner = options.scanner ?? file.targetType;

  for (const rule of rules.select(file, scanner)) {
    if (rule.unless && rule.unless.length > 0 && rule.unless.some((p) => testRegex(p, file.content))) {
      continue;
    }
    if (rule.requires && rule.requires.length > 0) {
      const satisfied = rule.requires.every((p) => testRegex(p, file.content));
      if (!satisfied) continue;
    }

    const perRule: RuleMatch[] = [];
    for (const pattern of rule.patterns ?? []) {
      const found = matchPattern(pattern, file, rule);
      perRule.push(...found);
    }
    if (perRule.length === 0) continue;

    // One finding per rule per file, anchored at the first occurrence. Additional
    // occurrences are recorded in metadata so reports can list every location
    // without spamming a reviewer with duplicates of the same issue.
    perRule.sort((a, b) => a.line - b.line || a.column - b.column);
    const primary = perRule[0];
    if (!primary) continue;

    // When one rule legitimately covers several *distinct* behaviours (for
    // example `shell=True` and `os.popen`), report each separately: they are
    // different bugs with different fixes, and collapsing them hides one.
    const distinctKinds = new Map<string, RuleMatch[]>();
    for (const match of perRule) {
      const kind = classifyMatch(match);
      distinctKinds.set(kind, [...(distinctKinds.get(kind) ?? []), match]);
    }
    const groups = distinctKinds.size > 1 ? [...distinctKinds.values()] : [perRule];

    for (const group of groups) {
      const head = group[0]!;
      matches.push({
        rule,
        file,
        evidence: head.evidence,
        line: head.line,
        column: head.column,
        ...(head.detail ? { detail: head.detail } : {}),
        ...(group.length > 1
          ? {
              rule: {
                ...rule,
                metadata: {
                  ...rule.metadata,
                  occurrenceCount: group.length,
                  occurrences: group.slice(1, 10).map((m) => `${m.line}:${m.column}`),
                },
              },
            }
          : {}),
      });
    }
    if (matches.length >= max) break;
  }

  return matches;
}

/**
 * Group matches of one rule by *which pattern* fired, so distinct behaviours
 * are not merged. Two matches of the same pattern in the same file are the same
 * issue repeated; two different patterns are two issues.
 */
function classifyMatch(match: RuleMatch): string {
  const detail = match.detail ?? '';
  if (detail.includes('os.system') || detail.includes('os.popen')) return 'shell-exec';
  if (detail.includes('shell=True')) return 'shell-true';
  if (detail.includes('commands.getoutput')) return 'getoutput';
  if (detail.includes('fetch')) return 'fetch';
  if (detail.includes('while')) return 'loop';
  return match.rule.id;
}

function matchPattern(
  pattern: RulePattern,
  file: FileUnderScan,
  rule: RuleDefinition,
): RuleMatch[] {
  switch (pattern.type) {
    case 'regex': {
      const { pattern: body, flags } = normalizeRegexFlags(pattern.pattern, pattern.flags);
      const re = new RegExp(body, flags);
      const out: RuleMatch[] = [];
      let match: RegExpExecArray | null;
      let guard = 0;
      while ((match = re.exec(file.content)) !== null) {
        if (match[0] === '') {
          re.lastIndex += 1;
          continue;
        }
        // A guard pattern such as `1234` or `xxxx` can appear *inside* the very
        // secret it is meant to exclude (`...xyz1234`). Testing the matched text
        // keeps placeholders out without letting them mask real credentials.
        if (isPlaceholderText(match[0])) continue;
        const { line, column } = offsetToLineCol(file.content, match.index);
        const end = offsetToLineCol(file.content, match.index + match[0].length);
        out.push({
          rule,
          file,
          evidence: extractRegion(file.content, line, end.line),
          line,
          column,
          detail: match[0].slice(0, 200),
        });
        if (++guard > 500) break;
      }
      return out;
    }
    case 'literal': {
      const idx = file.content.indexOf(pattern.value);
      if (idx === -1) return [];
      const { line, column } = offsetToLineCol(file.content, idx);
      return [
        { rule, file, evidence: extractLines(file.content, line), line, column, detail: pattern.value },
      ];
    }
    case 'contains-all': {
      const missing = pattern.values.filter((v) => !file.content.includes(v));
      if (missing.length > 0) return [];
      const idx = file.content.indexOf(pattern.values[0] ?? '');
      const { line, column } = offsetToLineCol(file.content, Math.max(0, idx));
      return [
        {
          rule,
          file,
          evidence: extractLines(file.content, line),
          line,
          column,
          detail: `all of: ${pattern.values.join(', ')}`,
        },
      ];
    }
    case 'contains-any': {
      for (const value of pattern.values) {
        const idx = file.content.indexOf(value);
        if (idx === -1) continue;
        const { line, column } = offsetToLineCol(file.content, idx);
        return [
          { rule, file, evidence: extractLines(file.content, line), line, column, detail: value },
        ];
      }
      return [];
    }
    case 'call': {
      return matchCall(pattern, file, rule);
    }
    case 'assignment': {
      return matchAssignment(pattern, file, rule);
    }
    case 'jsonpath': {
      return matchJsonPath(pattern, file, rule);
    }
    case 'entropy': {
      return matchEntropy(pattern, file, rule);
    }
    default:
      return [];
  }
}

/**
 * `call` matches `callee(...)` and inspects the argument list. It understands
 * nested parentheses and both quote styles so that
 * `subprocess.run(cmd, shell=True)` and `exec(userInput)` both resolve.
 */
function matchCall(
  pattern: Extract<RulePattern, { type: 'call' }>,
  file: FileUnderScan,
  rule: RuleDefinition,
): RuleMatch[] {
  const out: RuleMatch[] = [];
  const callee = escapeRegExp(pattern.callee);
  // `(?:^|[^\w$.])callee\s*\(` — allow member access such as `os.system(`.
  const re = new RegExp(`(?:^|[^\\w$.])${callee}\\s*\\(`, 'g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(file.content)) !== null) {
    const openIdx = file.content.indexOf('(', m.index);
    if (openIdx === -1) continue;
    const args = readBalanced(file.content, openIdx);
    if (args === null) continue;
    if (pattern.argsContain && !pattern.argsContain.every((a) => args.text.includes(a))) continue;
    if (pattern.argsNotContain && pattern.argsNotContain.some((a) => args.text.includes(a))) continue;
    const { line, column } = offsetToLineCol(file.content, m.index);
    out.push({
      rule,
      file,
      evidence: extractLines(file.content, line),
      line,
      column,
      detail: `${pattern.callee}(${args.text.slice(0, 160)})`,
    });
  }
  return out;
}

function matchAssignment(
  pattern: Extract<RulePattern, { type: 'assignment' }>,
  file: FileUnderScan,
  rule: RuleDefinition,
): RuleMatch[] {
  const out: RuleMatch[] = [];
  // Python `x = ...`, JS/TS `x = ...` / `x: ...`, Go `x := ...`.
  // `variable` is itself a regex (rules use alternations like `shell|command`),
  // so it goes through flag normalisation rather than being escaped.
  const varPattern = normalizeRegexFlags(pattern.variable, 'g').pattern;
  const re = new RegExp(
    `(?:^|[\\n;])\\s*(?:const\\s+|let\\s+|var\\s+|final\\s+)?(?:${varPattern})\\s*(?::=|[:=])\\s*([^\\n;]{0,400})`,
    'g',
  );
  const valueRe = new RegExp(normalizeRegexFlags(pattern.valueMatches, 'm').pattern);
  let m: RegExpExecArray | null;
  while ((m = re.exec(file.content)) !== null) {
    const value = (m[1] ?? '').trim();
    if (!valueRe.test(value)) continue;
    const { line, column } = offsetToLineCol(file.content, m.index);
    out.push({
      rule,
      file,
      evidence: extractLines(file.content, line),
      line,
      column,
      detail: `${pattern.variable} = ${value.slice(0, 160)}`,
    });
  }
  return out;
}

function matchJsonPath(
  pattern: Extract<RulePattern, { type: 'jsonpath' }>,
  file: FileUnderScan,
  rule: RuleDefinition,
): RuleMatch[] {
  if (file.json === undefined) return [];
  const segments = pattern.path.replace(/^\$\.?/, '').split('.').filter(Boolean);
  let current: unknown = file.json;
  const trail: string[] = [];
  for (const segment of segments) {
    if (Array.isArray(current)) {
      const idx = Number(segment);
      if (Number.isNaN(idx)) {
        // Allow wildcard traversal across arrays.
        const items = current;
        const hits: RuleMatch[] = [];
        for (const [i, item] of items.entries()) {
          const child = (item as Record<string, unknown> | null)?.[segment];
          if (testJsonOperator(child, pattern)) {
            const line = findJsonLine(file.content, [...trail, String(i), segment]);
            hits.push({
              rule,
              file,
              evidence: extractLines(file.content, line),
              line,
              column: 1,
              detail: `${pattern.path} -> ${JSON.stringify(child)?.slice(0, 160)}`,
            });
          }
        }
        return hits;
      }
      current = current[idx];
    } else if (current && typeof current === 'object') {
      current = (current as Record<string, unknown>)[segment];
    } else {
      return [];
    }
    trail.push(segment);
    if (current === undefined && pattern.operator !== 'exists') return [];
  }

  const passed = testJsonOperator(current, pattern);
  if (!passed) return [];
  const line = findJsonLine(file.content, trail);
  return [
    {
      rule,
      file,
      evidence: extractLines(file.content, line),
      line,
      column: 1,
      detail: `${pattern.path} = ${JSON.stringify(current)?.slice(0, 160) ?? 'undefined'}`,
    },
  ];
}

function testJsonOperator(value: unknown, pattern: Extract<RulePattern, { type: 'jsonpath' }>): boolean {
  switch (pattern.operator) {
    case 'exists':
      return value !== undefined && value !== null;
    case 'equals':
      return deepEqual(value, pattern.value);
    case 'not-equals':
      return !deepEqual(value, pattern.value);
    case 'contains':
      if (Array.isArray(value)) return value.some((v) => deepEqual(v, pattern.value));
      if (typeof value === 'string') return value.includes(String(pattern.value));
      if (value && typeof value === 'object') {
        return Object.keys(value).includes(String(pattern.value));
      }
      return false;
    default:
      return false;
  }
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a && b && typeof a === 'object') {
    return JSON.stringify(a) === JSON.stringify(b);
  }
  return false;
}

function matchEntropy(
  pattern: Extract<RulePattern, { type: 'entropy' }>,
  file: FileUnderScan,
  rule: RuleDefinition,
): RuleMatch[] {
  const out: RuleMatch[] = [];
  const re = pattern.pattern
    ? new RegExp(normalizeRegexFlags(pattern.pattern, 'gm').pattern, 'gm')
    : /[A-Za-z0-9+/=_\-]{20,}/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(file.content)) !== null) {
    const candidate = m[0];
    const entropy = shannonEntropy(candidate);
    if (entropy < pattern.min) continue;
    const { line, column } = offsetToLineCol(file.content, m.index);
    out.push({
      rule,
      file,
      evidence: extractLines(file.content, line),
      line,
      column,
      detail: `entropy=${entropy.toFixed(2)}`,
    });
    if (out.length > 5) break;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

/**
 * Whole-value placeholders that should never be reported as findings.
 *
 * Applied to the matched text, not the file, so that a filler sequence inside a
 * genuine secret does not suppress it.
 */
const PLACEHOLDER_TEXT =
  /^(?:x{4,}|\*{4,}|\.{3,}|_{4,}|-{4,}|0+|1+|a+|z+)$|^(?:example|placeholder|redacted|changeme|change[_-]?me|replace[_-]?me|replaceme|dummy|fake|sample|your|my|test|testing|none|null|undefined|true|false)$|^(?:abc123|123456|qwerty|password|letmein|admin|root|todo|none|null)$/i;

function isPlaceholderText(text: string): boolean {
  const trimmed = text.trim().replace(/^["'`]+|["'`,;\s]+$/g, '');
  if (!trimmed || trimmed.length > 120) return false;
  return PLACEHOLDER_TEXT.test(trimmed);
}

/**
 * Test a `requires` / `unless` guard pattern against a file.
 *
 * Guards are whole-file matches, so they run without the `g` flag: a `g` regex
 * carries `lastIndex` state between calls and would make the same guard
 * alternate between true and false across files.
 */
function testRegex(pattern: string, content: string): boolean {
  const { pattern: body, flags } = normalizeRegexFlags(pattern, 'm');
  return new RegExp(body, flags.replace(/g/g, '')).test(content);
}

export function offsetToLineCol(content: string, offset: number): { line: number; column: number } {
  const clamped = Math.max(0, Math.min(offset, content.length));
  let line = 1;
  let lastBreak = -1;
  for (let i = 0; i < clamped; i++) {
    if (content[i] === '\n') {
      line += 1;
      lastBreak = i;
    }
  }
  return { line, column: clamped - lastBreak };
}

export function extractLines(content: string, line: number, context = 0): string {
  const lines = content.split('\n');
  const start = Math.max(0, line - 1 - context);
  const end = Math.min(lines.length, line + context);
  return lines
    .slice(start, end)
    .map((l, i) => `${start + i + 1}: ${l}`)
    .join('\n');
}

/**
 * Evidence for a match, spanning the matched region.
 *
 * A single line is not enough for rules whose patterns are inherently
 * multi-line — an unbounded `while True:` loop only makes sense together with
 * the body that makes it unbounded. Showing only the `while` line hides exactly
 * the thing the reviewer needs to judge.
 */
export function extractRegion(content: string, startLine: number, endLine: number): string {
  const lines = content.split('\n');
  const from = Math.max(1, startLine);
  const to = Math.min(lines.length, Math.max(endLine, from));
  // Guard against a pathological pattern producing a megabyte of evidence.
  const limit = Math.min(to, from + 12);
  return lines
    .slice(from - 1, limit)
    .map((l, i) => `${from + i}: ${l}`)
    .join('\n');
}

function readBalanced(content: string, openIdx: number): { text: string; end: number } | null {
  let depth = 0;
  let quote: string | null = null;
  for (let i = openIdx; i < content.length; i++) {
    const ch = content[i]!;
    if (quote) {
      if (ch === '\\') {
        i++;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      continue;
    }
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return { text: content.slice(openIdx + 1, i), end: i };
    } else if (ch === '\n' && depth === 0) {
      return null;
    }
  }
  return null;
}

/** Best-effort: find the 1-based line where a JSON pointer-ish path appears. */
function findJsonLine(content: string, trail: readonly string[][] | readonly string[]): number {
  const segments = trail as string[];
  if (segments.length === 0) return 1;
  const quoted = segments
    .map((s) => (/^\d+$/.test(s) ? s : `"${escapeRegExp(s).replace(/^"|"$/g, '')}"`))
    .join('"\\s*:\\s*"');
  const re = new RegExp(`"${escapeRegExp(segments[0]!)}"\\s*:`, 'm');
  const m = re.exec(content);
  if (!m) return 1;
  void quoted;
  return offsetToLineCol(content, m.index).line;
}

function escapeRegExp(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Redact credential-shaped values out of evidence.
 *
 * The code-based secret detector masks values at detection time, but a *rule*
 * match can still surface the raw line as evidence — and evidence flows into
 * every output format, including ones written to disk. A scanner that copies
 * the secret it found into its own report has widened the exposure it exists
 * to find, so this runs on every finding regardless of which path produced it.
 */
const CREDENTIAL_PATTERNS: RegExp[] = [
  // Vendor-prefixed keys, keeping a short recognisable fragment. The specific
  // `sk-proj-`/`sk-ant-` forms are listed first because the generic `sk-`
  // pattern would otherwise consume the already-redacted output and mask the
  // vendor segment, breaking idempotence.
  /\b(sk-(?:proj|ant|live|test|svcacct)-?)([A-Za-z0-9_\-]{8,})\b/g,
  /\b(sk-)([A-Za-z0-9]{20,})\b/g,
  /\b(gh[pousr]_|github_pat_)([A-Za-z0-9_]{16,})\b/g,
  /\b(AKIA|ASIA|ABIA)([0-9A-Z]{12,})\b/g,
  /\b(AIza)([A-Za-z0-9_\-]{20,})\b/g,
  /\b(xox[baprs]-)([A-Za-z0-9-]{10,})\b/g,
  /\b(glpat-)([A-Za-z0-9_\-]{16,})\b/g,
  /\b([rs]k_live_)([A-Za-z0-9]{12,})\b/g,
  /\b(npm_)([A-Za-z0-9]{24,})\b/g,
  // Private key blocks.
  /-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY[\s\S]*?-----END[^-]*-----/g,
];

export function redactCredentials(text: string): string {
  let out = text;
  for (const pattern of CREDENTIAL_PATTERNS) {
    out = out.replace(pattern, (match, prefix: string, body: string) => {
      if (!body) return match;
      // Already redacted: leave it alone so the function is idempotent.
      if (body.includes('****')) return match;
      // Keep 4 leading and 4 trailing characters so the value stays
      // identifiable for triage without being usable.
      const visible = body.length <= 10 ? '' : `${body.slice(0, 4)}****${body.slice(-4)}`;
      return `${prefix}${visible}`;
    });
  }
  return out;
}

/** Turn a `RuleMatch` into a `Finding`. */
export function matchToFinding(match: RuleMatch, source: string): Finding {
  const severity = toSeverity(match.rule.severity);
  const location = {
    file: match.file.path,
    line: match.line,
    column: match.column,
  };
  const finding: Finding = {
    id: `${match.rule.id}:${match.file.path}:${match.line}`,
    ruleId: match.rule.id,
    title: match.rule.title,
    description: match.rule.description,
    severity,
    confidence: match.rule.confidence ?? 'medium',
    location,
    evidence: redactCredentials(match.evidence),
    remediation: {
      title: match.rule.remediation?.title ?? `Fix: ${match.rule.title}`,
      description:
        match.rule.remediation?.description ??
        'Review the flagged code and apply the guidance for this rule.',
      automated: match.rule.remediation?.automated ?? false,
      ...(match.rule.remediation?.patch ? { patch: match.rule.remediation.patch } : {}),
      ...(match.rule.remediation?.docs ? { docs: match.rule.remediation.docs } : {}),
      ...(match.rule.remediation?.effort ? { effort: match.rule.remediation.effort } : {}),
    },
    compliance: match.rule.compliance ?? [],
    source,
    ...(match.rule.cwe ? { cwe: match.rule.cwe } : {}),
    ...(match.rule.taxonomy ? { taxonomy: match.rule.taxonomy } : {}),
    ...(match.rule.tags ? { tags: match.rule.tags } : {}),
    fingerprint: fingerprintFinding({ ruleId: match.rule.id, location, evidence: match.evidence, severity }),
    createdAt: new Date().toISOString(),
    metadata: {
      ...match.rule.metadata,
      // `detail` is the raw matched text, so it needs the same redaction as
      // the evidence: it lands in the JSON output like any other field.
      ...(match.detail ? { match: redactCredentials(match.detail) } : {}),
      ...(match.rule.references ? { references: match.rule.references } : {}),
    },
  };
  void normalizeEvidence;
  return finding;
}
