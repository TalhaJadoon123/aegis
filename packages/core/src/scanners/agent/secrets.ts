import { shannonEntropy } from '../../fingerprint.js';
import type { Confidence, Finding, Severity } from '../../types.js';

/**
 * Secret detection for agent codebases.
 *
 * Two complementary strategies, because each misses what the other catches:
 *
 *  1. Vendor-prefix patterns. High precision, near-zero recall for anything
 *     custom. A `sk-...` is a live credential.
 *  2. Entropy + context. Catches first-party tokens, internal API keys, and
 *     anything without a recognisable prefix — which is most of what actually
 *     ends up in a breach.
 *
 * Every candidate passes a placeholder denylist. Without it the signal-to-noise
 * ratio collapses and teams switch the scanner off, which is worse than not
 * shipping it.
 */

export interface SecretMatch {
  kind: string;
  /**
   * Redacted representation only. The raw secret is deliberately not retained:
   * this object flows into findings, JSON reports, SARIF uploads and the hosted
   * dashboard, and a scanner that copies credentials into its own output has
   * widened the very exposure it was built to find.
   */
  redacted: string;
  /** Length of the original value, useful for triage. */
  length: number;
  line: number;
  column: number;
  entropy: number;
  severity: Severity;
  confidence: Confidence;
  evidence: string;
}

interface SecretPattern {
  kind: string;
  regex: RegExp;
  severity: Severity;
  confidence: Confidence;
  /** Extract the secret itself; defaults to group 1 then 0. */
  capture?: (m: RegExpExecArray) => string;
}

/** Values that look like secrets but are not. Tuned by hand from real repos. */
const PLACEHOLDER_PATTERNS: RegExp[] = [
  /^(?:x{4,}|\*{4,}|\.{3,}|_{4,}|-{4,})$/i,
  /^(?:example|placeholder|redacted|changeme|change_me|replace_me|replaceme|dummy|fake|test|testing|sample|your|my)/i,
  /(?:^|[._-])(?:example|sample|dummy|fake|mock|test|stub)(?:[._-]|$)/i,
  /^(?:abc123|123456|qwerty|password|letmein|admin|root)$/i,
  /^\$\{[^}]+\}$/,           // ${ENV_VAR}
  /^\$[A-Z_][A-Z0-9_]*$/,    // $ENV_VAR
  /^\{\{[^}]+\}\}$/,          // {{ env_var }}
  /^<[^>]*>$/,               // <your-key-here>
  /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|example\.org|example\.net)/i,
  /^(?:utf-?8|ascii|base64|sha-?256|application\/json)$/i,
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // UUID
  /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/, // date
  /^(?:https?|file|postgres|mysql|redis):\/\/$/i,
];

const SECRET_PATTERNS: SecretPattern[] = [
  // --- AI / model providers ---------------------------------------------
  {
    kind: 'openai-api-key',
    regex: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/g,
    severity: 'critical',
    confidence: 'confirmed',
  },
  {
    kind: 'anthropic-api-key',
    regex: /\bsk-ant-[A-Za-z0-9_-]{24,}\b/g,
    severity: 'critical',
    confidence: 'confirmed',
  },
  {
    kind: 'google-api-key',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    severity: 'critical',
    confidence: 'confirmed',
  },
  {
    kind: 'huggingface-token',
    regex: /\bhf_[A-Za-z0-9]{30,}\b/g,
    severity: 'high',
    confidence: 'confirmed',
  },
  {
    kind: 'aws-access-key-id',
    regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    severity: 'critical',
    confidence: 'confirmed',
  },
  {
    kind: 'azure-openai-key',
    regex: /\b[a-f0-9]{32}\b/g,
    severity: 'medium',
    confidence: 'low',
  },

  // --- Source control / CI ---------------------------------------------
  {
    kind: 'github-token',
    regex: /\bgh[pousr]_[A-Za-z0-9]{30,255}\b/g,
    severity: 'critical',
    confidence: 'confirmed',
  },
  {
    kind: 'github-pat',
    regex: /\bgithub_pat_[A-Za-z0-9_]{50,}\b/g,
    severity: 'critical',
    confidence: 'confirmed',
  },
  {
    kind: 'gitlab-token',
    regex: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    severity: 'critical',
    confidence: 'confirmed',
  },
  {
    kind: 'npm-token',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    severity: 'high',
    confidence: 'confirmed',
  },
  {
    kind: 'pypi-token',
    regex: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g,
    severity: 'high',
    confidence: 'confirmed',
  },

  // --- Messaging / comms -------------------------------------------------
  {
    kind: 'slack-token',
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
    severity: 'high',
    confidence: 'confirmed',
  },
  {
    kind: 'slack-webhook',
    regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9]{20,}\b/g,
    severity: 'medium',
    confidence: 'confirmed',
  },
  {
    kind: 'discord-webhook',
    regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{30,}/g,
    severity: 'medium',
    confidence: 'confirmed',
  },
  {
    kind: 'stripe-key',
    regex: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}\b/g,
    severity: 'critical',
    confidence: 'confirmed',
  },

  // --- Crypto / infra ----------------------------------------------------
  {
    kind: 'private-key',
    regex: /-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY(?: BLOCK)?-----/g,
    severity: 'critical',
    confidence: 'confirmed',
  },
  {
    kind: 'jwt',
    // Three base64url segments; the signature is what makes it usable.
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\b/g,
    severity: 'medium',
    confidence: 'medium',
  },
  {
    kind: 'connection-string-password',
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|clickhouse|mssql|ftp|sftp):\/\/[^\s:@/"']+:[^\s:@/"']+@/g,
    severity: 'high',
    confidence: 'confirmed',
  },
  {
    kind: 'basic-auth-url',
    regex: /\bhttps?:\/\/[^\s:/@"']+:[^\s:/@"']+@[^\s/]+/g,
    severity: 'high',
    confidence: 'high',
  },
];

/** `KEY = "value"` style assignments, used by the entropy sweep. */
const ASSIGNMENT = [
  /\b(?:api[_-]?key|apikey|secret[_-]?key|secret|access[_-]?token|auth[_-]?token|token|password|passwd|pwd|client[_-]?secret|private[_-]?key|credential|auth)\b\s*[:=]\s*["']([^"'\n]{8,200})["']/gi,
  /\b(?:api[_-]?key|apikey|secret|token|password|credential)\b\s*[:=]\s*(?!["']|None|null|undefined|True|False|\d)\S{16,200}/gi,
];

/** Contexts that mean a "secret" is actually safe to have in source. */
const SAFE_CONTEXTS: RegExp[] = [
  /\b(?:process\.env|os\.environ|os\.getenv|getenv|Deno\.env|ENV\[|import\.meta\.env|secrets\.|vault\.|AWS_SECRET|gcp_secret|config\.get|System\.getenv)\b/,
  /\b(?:describe|it|test|example|fixture|mock|stub|benchmark|demo|docs?)\b/i,
];

const ASSIGNMENT_NAMES = new Set([
  'api_key', 'apikey', 'secret_key', 'secret', 'access_token', 'auth_token', 'token',
  'password', 'passwd', 'pwd', 'client_secret', 'private_key', 'credential', 'auth',
]);

export interface ScanSecretsOptions {
  /** Minimum shannon entropy for a candidate to count. Default 3.5. */
  minEntropy?: number;
  /** Skip test fixtures and vendored directories. Default true. */
  skipTestPaths?: boolean;
}

export function scanSecrets(
  path: string,
  content: string,
  options: ScanSecretsOptions = {},
): SecretMatch[] {
  const minEntropy = options.minEntropy ?? 3.5;
  const skipTests = options.skipTestPaths ?? true;
  const matches: SecretMatch[] = [];

  if (skipTests && /(?:^|\/)(?:tests?|__tests__|fixtures?|testdata|\.test\.|\.spec\.|e2e)(?:\/|\.|$)/i.test(path)) {
    return matches;
  }

  // Template and example files document configuration; they are *supposed* to
  // contain a credential-shaped value, and every real project has one.
  // Flagging `.env.example` guarantees a false positive in the first scan a
  // customer runs, which is the fastest way to teach them to ignore the output.
  //
  // Every other rule still applies to these files; only credential detection is
  // skipped, because a placeholder in a template is not a leak.
  if (
    /(?:\.example|\.sample|\.template|\.dist|\.defaults)\.\w+$/i.test(path) ||
    /(?:^|\/)example\.(?:env|ya?ml|json|toml|ini|conf)$/i.test(path) ||
    /^\.env\.(?:example|sample|template|dist|defaults)$/i.test(path)
  ) {
    return matches;
  }

  const safeContext = SAFE_CONTEXTS.some((re) => re.test(content));

  // Pass 1: vendor-specific patterns.
  for (const pattern of SECRET_PATTERNS) {
    const re = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : `${pattern.regex.flags}g`);
    let m: RegExpExecArray | null;
    while ((m = re.exec(content)) !== null) {
      const value = pattern.capture ? pattern.capture(m) : (m[1] ?? m[0]);
      if (isPlaceholder(value)) continue;
      const { line, column } = lineOf(content, m.index);
      matches.push({
        kind: pattern.kind,
        redacted: redact(value),
        length: value.length,
        line,
        column,
        entropy: Math.round(shannonEntropy(value) * 100) / 100,
        severity: pattern.severity,
        confidence: pattern.confidence,
        evidence: redactLine(lineText(content, line), [value]),
      });
    }
  }

  // Pass 2: entropy sweep over credential-shaped assignments.
  if (!safeContext) {
    for (const assignment of ASSIGNMENT) {
      const re = new RegExp(assignment.source, assignment.flags.includes('g') ? assignment.flags : `${assignment.flags}g`);
      let m: RegExpExecArray | null;
      while ((m = re.exec(content)) !== null) {
        const value = (m[1] ?? m[2] ?? m[0]).trim();
        if (value.length < 12) continue;
        if (isPlaceholder(value)) continue;
        if (!isStrongAssignment(content, m.index, m[0])) continue;
        const entropy = shannonEntropy(value);
        if (entropy < minEntropy) continue;
        if (looksLikeIdentifier(value)) continue;
        const { line, column } = lineOf(content, m.index);
        matches.push({
          kind: 'high-entropy-credential',
          redacted: redact(value),
          length: value.length,
          line,
          column,
          entropy: Math.round(entropy * 100) / 100,
          severity: 'high',
          confidence: entropy >= 4.2 ? 'medium' : 'low',
          evidence: lineText(content, line),
        });
      }
    }
  }

  return dedupeMatches(matches);
}

function isStrongAssignment(content: string, index: number, matchedText = ''): boolean {
  // The key name may sit inside the match (`client_secret = "…"`) or just
  // before it (`KEY: value` captured as group 1), so check both positions.
  const leading = /([A-Za-z_][\w-]*)\s*[:=]\s*$/.exec(
    content.slice(Math.max(0, index - 80), index),
  );
  if (leading && ASSIGNMENT_NAMES.has(leading[1]!.toLowerCase())) return true;

  const inline = /([A-Za-z_][\w-]*)\s*[:=]/.exec(matchedText);
  return Boolean(inline && ASSIGNMENT_NAMES.has(inline[1]!.toLowerCase()));
}

function looksLikeIdentifier(value: string): boolean {
  // Snake/camel-case identifiers and dotted paths are not secrets.
  if (/^[A-Za-z_][\w.]*$/.test(value) && value.length < 40) return true;
  if (/^[A-Za-z]+(?:[A-Z][a-z]+)+$/.test(value)) return true;
  if (/^[a-z]+(?:_[a-z]+)+$/.test(value)) return true;
  if (/^[a-zA-Z]+(?:\.[a-zA-Z]+){2,}$/.test(value)) return true;
  if (/^[\w-]+\/[\w-]+\/[\w-]+$/.test(value)) return true;
  return false;
}

function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_PATTERNS.some((re) => re.test(value.trim()));
}

function dedupeMatches(matches: SecretMatch[]): SecretMatch[] {
  const seen = new Map<string, SecretMatch>();
  for (const match of matches) {
    const key = `${match.kind}:${match.line}:${match.column}`;
    const existing = seen.get(key);
    if (!existing || match.confidence === 'confirmed') seen.set(key, match);
  }
  return [...seen.values()].sort((a, b) => a.line - b.line);
}

/**
 * Scrub the detected secret out of an evidence line.
 *
 * Evidence is shown to humans in terminals, pull request comments and PDFs.
 * Echoing the credential there would turn every report into a new leak.
 */
function redactLine(line: string, values: readonly string[]): string {
  let out = line;
  for (const value of values) {
    if (!value) continue;
    out = out.split(value).join(redact(value));
  }
  return out;
}

/** Never show more than a recognisable prefix/suffix. */
export function redact(value: string): string {
  if (value.length <= 8) return '*'.repeat(value.length);
  return `${value.slice(0, 4)}${'*'.repeat(Math.min(12, value.length - 8))}${value.slice(-4)}`;
}

function lineOf(content: string, offset: number): { line: number; column: number } {
  const clamped = Math.max(0, Math.min(offset, content.length));
  const before = content.slice(0, clamped);
  const line = before.split('\n').length;
  const lastBreak = before.lastIndexOf('\n');
  return { line, column: clamped - lastBreak };
}

function lineText(content: string, line: number): string {
  return content.split('\n')[line - 1]?.trim() ?? '';
}

/** Turn matches into findings, one per secret per file. */
export function secretsToFindings(path: string, matches: readonly SecretMatch[]): Finding[] {
  return matches.map((match) => ({
    id: `AEGIS-SECRET.${match.kind}.${path}:${match.line}`,
    // Same id as the `secrets` rule pack so the code-driven detector and the
    // YAML pack never disagree about what "this is a hardcoded credential"
    // means, and so suppression / allowlisting works uniformly.
    ruleId: 'AEGIS-SEC-001',
    title: `${match.kind} hardcoded in source`,
    description:
      `A credential of type "${match.kind}" is hardcoded in source. In an agent codebase this is reachable ` +
      'by every tool the agent can call and is included in every prompt context that touches this module.',
    severity: match.severity,
    confidence: match.confidence,
    location: { file: path, line: match.line, column: match.column },
    evidence: `${match.evidence}\n    // detected value: ${match.redacted} (entropy ${match.entropy})`,
    remediation: {
      title: `Rotate and remove this ${match.kind}`,
      description:
        'Revoke the credential at its provider, then load the replacement from the environment or a secret ' +
        'manager. Assume any committed secret has already been indexed by secret-scanning crawlers — ' +
        'rotation, not deletion, is the fix.',
      automated: false,
      effort: 'trivial',
    },
    compliance: [
      { framework: 'owasp-agentic', control: 'ASI03', title: 'Identity and Privilege Abuse', relevant: true },
      { framework: 'soc2', control: 'CC6.1', title: 'Logical access security measures', relevant: true },
      { framework: 'iso27001', control: 'A.5.17', title: 'Authentication information', relevant: true },
      { framework: 'gdpr', control: 'Art. 32', title: 'Security of processing', relevant: true },
    ],
    source: 'agent',
    cwe: 'CWE-798',
    tags: ['secret', match.kind],
    // Fingerprint on kind + file + line, never on the secret's redacted form:
    // two credentials of the same vendor on adjacent lines can redact to the
    // same visible prefix/suffix, which collided into a single finding.
    fingerprint: `secret:${match.kind}:${path}:${match.line}`,
    createdAt: new Date().toISOString(),
  }));
}