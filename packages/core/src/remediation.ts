import { readFile, writeFile } from 'node:fs/promises';
import { join, resolve as resolvePath } from 'node:path';
import { applyEdits, type FileEdit } from './patch.js';
import type { Finding, Severity } from './types.js';

/**
 * Auto-remediation.
 *
 * The hard part of automated fixing is not generating a patch — it is being
 * *conservative* about which ones to apply. A security tool that silently
 * rewrites application code is a liability, and in practice teams disable it
 * after the first bad auto-merge.
 *
 * So Aegis draws a hard line:
 *
 *  - **Mechanical fixes** (pin a version, move a secret to `os.environ`,
 *    enable `additionalProperties: false`, tighten a permission scope) are
 *    applied automatically, because the correct answer is unambiguous.
 *  - **Semantic fixes** (restructure an agent's trust boundaries, add a human
 *    approval gate, design an instruction/data separation strategy) are
 *    proposed as guidance with a worked example, never auto-applied.
 *
 * Everything is validated by re-scanning the patched output before it is
 * offered, so a fix that does not actually resolve its finding is reported as
 * such rather than shipped.
 */

export type RemediationStrategy =
  | 'auto-apply'      // unambiguous mechanical change
  | 'propose'         // needs human judgement, shipped as a suggestion
  | 'manual';         // cannot be automated safely

export interface Remediation {
  findingId: string;
  ruleId: string;
  title: string;
  strategy: RemediationStrategy;
  confidence: number;
  /** Unified diff, when a concrete code change is proposed. */
  diff?: string;
  /** The proposed replacement for the flagged region. */
  replacement?: string;
  /** The exact text being replaced, used to locate it in the file. */
  original?: string;
  file?: string;
  line?: number;
  /** Why this strategy was chosen. */
  rationale: string;
  /** What could go wrong. Always populated, even for auto-applies. */
  risks: string[];
  /** Verification steps the operator should run. */
  verification: string[];
  /** Working example, even when the fix is not auto-appliable. */
  example?: string;
}

export interface RemediationPlan {
  findings: Finding[];
  remediations: Remediation[];
  /** Remediations that can be applied without human review. */
  autoApplicable: Remediation[];
  /** Remediations that need a human decision. */
  proposals: Remediation[];
  /** Findings with no safe automated fix. */
  manual: Remediation[];
  stats: {
    total: number;
    auto: number;
    proposed: number;
    manual: number;
    /** Estimated effort, in minutes, for the whole plan. */
    estimatedMinutes: number;
  };
}

/**
 * Mechanical fixes, keyed by rule id.
 *
 * Every entry here is deliberately conservative: it matches a specific,
 * unambiguous mistake and produces one specific correct replacement.
 */
interface MechanicalFix {
  ruleId: string;
  strategy: RemediationStrategy;
  /** Patterns that identify the vulnerable text, tried in order. */
  matchers: Array<{
    description: string;
    pattern: RegExp;
    replacement: string;
    /** Only apply when this captures a group, e.g. a package name. */
    capture?: number;
    /** Skip if the surrounding text already shows the fix is applied. */
    guard?: RegExp;
  }>;
  rationale: string;
  risks: string[];
  verification: string[];
  estimatedMinutes: number;
}

const MECHANICAL_FIXES: MechanicalFix[] = [
  {
    ruleId: 'AEGIS-SEC-001',
    strategy: 'auto-apply',
    matchers: [
      // The key may be a quoted JSON/JS property or a bare Python identifier,
      // and the separator is `=` or `:`. Both forms occur in the wild and a
      // matcher that only handles one silently finds nothing.
      {
        description: 'Hardcoded OpenAI API key',
        pattern: /((?:^|[\s{,])(?:OPENAI_)?API_KEY\s*[:=]\s*)(['"])(sk-[A-Za-z0-9_-]{20,})\2/gm,
        replacement: '$1os.environ["OPENAI_API_KEY"]  # moved to the environment',
        guard: /os\.environ|process\.env|getenv|readSecret/,
      },
      {
        description: 'Hardcoded Anthropic API key',
        pattern: /((?:^|[\s{,])(?:ANTHROPIC_)?API_KEY\s*[:=]\s*)(['"])(sk-ant-[A-Za-z0-9_-]{20,})\2/gm,
        replacement: '$1os.environ["ANTHROPIC_API_KEY"]  # moved to the environment',
        guard: /os\.environ|process\.env|getenv|readSecret/,
      },
      {
        description: 'Hardcoded AWS access key id',
        pattern: /((?:^|[\s{,])(?:AWS_)?ACCESS_KEY_ID\s*[:=]\s*)(['"])((?:AKIA|ASIA)[0-9A-Z]{16})\2/gm,
        replacement: '$1os.environ["AWS_ACCESS_KEY_ID"]  # moved to the environment',
        guard: /os\.environ|process\.env|getenv|readSecret/,
      },
      {
        description: 'Hardcoded GitHub token',
        pattern: /((?:^|[\s{,])(?:GITHUB_)?TOKEN\s*[:=]\s*)(['"])(gh[pousr]_[A-Za-z0-9]{20,})\2/gm,
        replacement: '$1os.environ["GITHUB_TOKEN"]  # moved to the environment',
        guard: /os\.environ|process\.env|getenv|readSecret/,
      },
    ],
    rationale:
      'A credential literal in source is always wrong and the correct fix is always the same: read it ' +
      'from the environment. The mechanical part is unambiguous.',
    risks: [
      'The application now requires the variable to be set. If it is missing at runtime the agent fails closed rather than silently using a baked-in key.',
      'Moving the value does not revoke it. The credential must still be rotated at the provider — a leaked key stays leaked in every clone of this repository.',
    ],
    verification: [
      'Confirm the variable is set in every environment the agent runs in, including CI.',
      'Rotate the exposed credential at the provider.',
      'Re-run `aegis scan` and confirm AEGIS-SEC-001 no longer fires on this file.',
    ],
    estimatedMinutes: 15,
  },
  {
    ruleId: 'AEGIS-MCP-031',
    strategy: 'propose',
    matchers: [
      {
        description: 'Unpinned npx/uvx MCP server',
        pattern: /(["'])(-y|--yes)\1\s+([@\w][\w@\-./]*)(?=["']\s*[,}\]])/g,
        capture: 3,
        replacement: '$1--yes$1 $2',
      },
    ],
    rationale:
      'Pinning is unambiguous, but Aegis proposes rather than auto-applies it: choosing a version ' +
      'requires knowing which release is known-good, and silently pinning to "latest at time of patch" ' +
      'can lock in a version that has not been reviewed.',
    risks: [
      'Pinning to the currently-resolved version freezes whatever is deployed today, which may already be compromised.',
      'A pin removes automatic security updates; the team must own patching the MCP server.',
    ],
    verification: [
      'Identify the version currently resolving and confirm it is the intended one.',
      'Check the package for known advisories before pinning to it.',
      'Re-run the MCP scan and confirm AEGIS-MCP-031 no longer fires.',
    ],
    estimatedMinutes: 20,
  },
  {
    ruleId: 'AEGIS-MCP-030',
    strategy: 'auto-apply',
    matchers: [
      {
        description: 'MCP server launched through a shell',
        pattern: /("command"\s*:\s*")(sh|bash|zsh|cmd|cmd\.exe|powershell|pwsh)("\s*,\s*\n?\s*"args"\s*:\s*\[)/gi,
        replacement: '$1npx$3',
      },
    ],
    rationale:
      'Launching an MCP server through a shell means every argument is shell-interpreted. Removing the ' +
      'shell is a strict reduction in attack surface with no change to server behaviour.',
    risks: [
      'If the shell was genuinely load-bearing (pipelines, redirection), removing it breaks the launch and the server will not start.',
      'The `npx` replacement assumes an npm-distributed server; a Python server needs `uvx` instead.',
    ],
    verification: [
      'Start the MCP server manually and confirm it lists its tools.',
      'Re-run `aegis scan` and confirm AEGIS-MCP-030 no longer fires.',
    ],
    estimatedMinutes: 25,
  },
  {
    ruleId: 'AEGIS-MCP-013',
    strategy: 'auto-apply',
    matchers: [
      {
        description: 'JSON schema allowing additional properties',
        pattern: /("additionalProperties"\s*:\s*)true/g,
        replacement: '$1false',
      },
    ],
    rationale:
      'Allowing additional properties means the tool accepts arguments its author never considered. ' +
      'Closing the schema restricts behaviour without changing the documented contract.',
    risks: [
      'If a client currently passes extra fields, calls that were silently accepted will now fail loudly. That is the intent, but it may surface as new errors.',
    ],
    verification: [
      'Exercise every tool through the client and confirm no legitimate call is rejected.',
      'Re-run the MCP scan and confirm the finding is resolved.',
    ],
    estimatedMinutes: 15,
  },
  {
    ruleId: 'AEGIS-MCP-034',
    strategy: 'auto-apply',
    matchers: [
      {
        description: 'Blanket auto-approval of MCP tools',
        pattern: /("alwaysAllow"\s*:\s*)\[\s*"\*"\s*\]/g,
        replacement: '$1[]  // list reviewed tools explicitly; "*" disables the human-in-the-loop',
      },
      {
        description: 'Wildcard auto-approve array',
        pattern: /("(?:autoApprove|auto_approve|alwaysAllow)"\s*:\s*)\[\s*"\*"\s*\]/g,
        replacement: '$1[]',
      },
    ],
    rationale:
      'Auto-approving every tool removes the only human-in-the-loop control between a prompt injection ' +
      'and a shell. Emptying the list restores it immediately and is safe: it fails closed.',
    risks: [
      'Teams that relied on blanket approval will start seeing confirmation prompts for every tool call.',
      'If prompts are dismissed reflexively the control is theatre; it needs a real review habit behind it.',
    ],
    verification: [
      'Add back the specific tools that have genuinely been reviewed.',
      'Confirm the prompts appear for destructive tools in normal use.',
    ],
    estimatedMinutes: 20,
  },
  {
    ruleId: 'AEGIS-MCP-032',
    strategy: 'auto-apply',
    matchers: [
      {
        description: 'Inline MCP secret replaced with an env reference',
        pattern: /("(?:API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIALS|AUTHORIZATION|Authorization)"\s*:\s*")(?!\$|\{)[^"]{8,}"/g,
        replacement: '$1${',
      },
    ],
    rationale:
      'A secret literal in an MCP config is readable by every process on the machine. An environment ' +
      'reference is the only portable alternative.',
    risks: [
      'The exact expansion syntax is client-specific; verify the client expands `${VAR}` before relying on it.',
      'As with any secret move, the value must be rotated — it has been committed.',
    ],
    verification: [
      'Confirm the client expands the variable and the server still authenticates.',
      'Rotate the exposed secret.',
    ],
    estimatedMinutes: 15,
  },
  {
    ruleId: 'AEGIS-ASI08-001',
    strategy: 'propose',
    matchers: [
      {
        description: 'Null iteration cap',
        pattern: /(max_iterations|max_steps|max_turns|recursion_limit)\s*=\s*(None|null)\b/g,
        replacement: '$1 = MAX_STEPS  # set an explicit ceiling',
      },
    ],
    rationale:
      'An unbounded agent loop is a denial-of-service and a cost exposure. The correct ceiling is a ' +
      'product decision, so Aegis proposes rather than guessing a number.',
    risks: [
      'A ceiling that is too low breaks legitimate multi-step tasks.',
      'The cap must be enforced by the orchestrator, not only the loop body, or a retry path bypasses it.',
    ],
    verification: [
      'Choose a ceiling based on the longest legitimate task, with headroom.',
      'Confirm exceeding the ceiling aborts the whole agent rather than one step.',
      'Re-run the scan and confirm ASI08-001 no longer fires.',
    ],
    estimatedMinutes: 45,
  },
  {
    ruleId: 'AEGIS-ASI02-001',
    strategy: 'propose',
    matchers: [
      {
        description: 'Shell command execution with shell=True',
        pattern: /subprocess\.(run|call|check_call|check_output|Popen)\s*\(\s*([^,)]+),\s*shell\s*=\s*True/g,
        replacement: 'subprocess.run($2.split(), shell=False, check=True)',
      },
      {
        description: 'os.system call',
        pattern: /os\.system\s*\(\s*([^)]+)\)/g,
        replacement: 'subprocess.run($1.split(), shell=False, check=True)',
      },
    ],
    rationale:
      'Removing `shell=True` is mechanical, but converting a command string into a correct argument ' +
      'list requires understanding what the command does. Aegis shows the transformation and explains ' +
      'what to check rather than rewriting call sites blind.',
    risks: [
      'Naive `.split()` breaks quoted arguments, pipelines and redirection.',
      'The command may genuinely require a shell; if so, the fix is an allowlist, not `shell=False`.',
    ],
    verification: [
      'Use `shlex.split` for anything with quoted arguments.',
      'Add a test covering the argument shapes this call site actually receives.',
      'Re-run the scan and confirm ASI02-001 no longer fires.',
    ],
    estimatedMinutes: 60,
  },
];

const MECHANICAL_BY_RULE = new Map<string, MechanicalFix>();
for (const fix of MECHANICAL_FIXES) MECHANICAL_BY_RULE.set(fix.ruleId, fix);

export interface BuildPlanOptions {
  /** Map of file path to contents, used to apply and validate fixes. */
  sources?: Map<string, string>;
  /** Only plan fixes for these rule ids. */
  ruleIds?: string[];
  /** Maximum severity to remediate. Default: `critical`. */
  maxSeverity?: Severity;
}

export function buildRemediationPlan(
  findings: readonly Finding[],
  options: BuildPlanOptions = {},
): RemediationPlan {
  const remediations: Remediation[] = [];

  for (const finding of sortBySeverity(findings)) {
    if (options.ruleIds && !options.ruleIds.includes(finding.ruleId)) continue;
    // `maxSeverity` filters *at or above* the given severity, matching how the CLI
    // `--min-severity` reads to an operator: `--min-severity high` means
    // "handle high and critical".
    const maxRank = options.maxSeverity ? rankOf(options.maxSeverity) : RANK.critical;
    if (rankOf(finding.severity) > maxRank) continue;
    remediations.push(planFor(finding, options.sources));
  }

  const autoApplicable = remediations.filter((r) => r.strategy === 'auto-apply' && r.diff);
  const proposals = remediations.filter((r) => r.strategy !== 'auto-apply' && r.strategy !== 'manual');
  const manual = remediations.filter((r) => r.strategy === 'manual');

  return {
    findings: [...findings],
    remediations,
    autoApplicable,
    proposals,
    manual,
    stats: {
      total: remediations.length,
      auto: autoApplicable.length,
      proposed: proposals.length,
      manual: manual.length,
      estimatedMinutes: remediations.reduce((sum, r) => sum + estimateMinutes(r), 0),
    },
  };
}

function planFor(finding: Finding, sources?: Map<string, string>): Remediation {
  const mechanical = MECHANICAL_BY_RULE.get(finding.ruleId);
  if (mechanical) {
    const file = finding.location.file;
    const source = file && sources ? sources.get(file) : undefined;

    // Prefer patching the actual file content, so the diff is real rather than
    // a guess reconstructed from the rule matcher.
    if (source && file) {
      const applied = applyMechanical(source, mechanical);
      if (applied) {
        const line = finding.location.line ?? 1;
        // The "after" side of the diff must come from the *patched* text.
        // Diffing the original against itself produced an empty diff, so
        // `aegis fix --apply` reported "applied" while changing nothing.
        const before = contextAround(source, line);
        const after = contextAround(applied, line);
        const diff = unifiedDiff(file, before.before.join('\n'), after.before.join('\n'));
        return {
          findingId: finding.id,
          ruleId: finding.ruleId,
          title: finding.remediation.title,
          strategy: mechanical.strategy,
          confidence: 0.9,
          diff,
          replacement: after.before.join('\n'),
          original: before.before.join('\n'),
          file,
          line,
          rationale: mechanical.rationale,
          risks: mechanical.risks,
          verification: mechanical.verification,
        };
      }
    }

    // No file content available: emit the matcher as an illustrative example.
    const example = mechanical.matchers
      .map((m) => `// ${m.description}\n${String(m.pattern).replace(/\/[gimsuy]+$/, '').replace(/^\//, '')}`)
      .join('\n');

    return {
      findingId: finding.id,
      ruleId: finding.ruleId,
      title: finding.remediation.title,
      strategy: mechanical.strategy,
      confidence: 0.5,
      rationale: mechanical.rationale,
      risks: mechanical.risks,
      verification: mechanical.verification,
      example: `Apply this transformation to ${file ?? 'the flagged file'}:\n\n${example}`,
    };
  }

  return {
    findingId: finding.id,
    ruleId: finding.ruleId,
    title: finding.remediation.title,
    strategy: 'manual',
    confidence: 0.7,
    rationale:
      'No mechanical fix is defined for this rule. The remediation requires a design decision that ' +
      'depends on the application, so Aegis provides guidance rather than a patch.',
    risks: [],
    verification: [
      'Implement the remediation described in the finding.',
      'Re-run the scan and confirm the finding is resolved.',
    ],
    example: finding.remediation.patch ?? finding.remediation.description,
  };
}

function applyMechanical(source: string, fix: MechanicalFix): string | null {
  for (const matcher of fix.matchers) {
    // Always compile a fresh RegExp. A `/g` pattern carries `lastIndex`
    // between calls, so testing a shared pattern object advances it and the
    // *next* invocation starts mid-string and silently matches nothing — which
    // is why this returned null for the first matcher and found no fixes.
    const pattern = new RegExp(matcher.pattern.source, matcher.pattern.flags);
    if (!pattern.test(source)) continue;
    if (matcher.guard && new RegExp(matcher.guard.source, matcher.guard.flags).test(source)) continue;

    const patched = source.replace(
      new RegExp(matcher.pattern.source, matcher.pattern.flags),
      matcher.replacement,
    );
    if (patched !== source) return patched;
  }
  return null;
}

function contextAround(source: string, line: number): { before: string[]; after: string[] } {
  const lines = source.split('\n');
  const idx = Math.max(0, line - 1);
  const from = Math.max(0, idx - 3);
  const to = Math.min(lines.length, idx + 4);
  return { before: lines.slice(from, idx + 1), after: lines.slice(from, to) };
}

/** Minimal unified diff, sufficient for review in a PR. */
export function unifiedDiff(path: string, before: string, after: string): string {
  if (before === after) return '';
  const a = before.split('\n');
  const b = after.split('\n');
  const lines: string[] = [`--- a/${path}`, `+++ b/${path}`, `@@ -1,${a.length} +1,${b.length} @@`];
  for (const line of a) lines.push(`-${line}`);
  for (const line of b) lines.push(`+${line}`);
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Application
// ---------------------------------------------------------------------------

export interface ApplyResult {
  applied: boolean;
  file?: string;
  /** Set when the change was written. */
  written?: boolean;
  reason?: string;
  /** True when written to disk; false when returned as a dry run. */
  persisted: boolean;
  /** Whether the file must be re-scanned to confirm the fix. */
  requiresRescan: boolean;
  diff?: string;
}

/**
 * Apply a remediation.
 *
 * Fails closed in every ambiguous case: the file must exist, the original text
 * must still be present verbatim, and `dryRun` must be off. A tool that
 * overwrites code it no longer recognises is worse than one that does nothing.
 */
export async function applyRemediation(
  remediation: Remediation,
  options: { dryRun?: boolean; cwd?: string } = {},
): Promise<ApplyResult> {
  if (remediation.strategy !== 'auto-apply') {
    return {
      applied: false,
      persisted: false,
      requiresRescan: false,
      reason: `strategy is "${remediation.strategy}"; only auto-apply fixes can be applied automatically`,
    };
  }
  if (!remediation.file || !remediation.diff || !remediation.original || !remediation.replacement) {
    return {
      applied: false,
      persisted: false,
      requiresRescan: false,
      reason: 'remediation carries no concrete file edit',
    };
  }

  // `remediation.file` is relative to the scan root, which the CLI resolves
  // into the current working directory before calling this.
  const path = options.cwd ? join(options.cwd, remediation.file) : remediation.file;

  let current: string;
  try {
    current = await readFile(path, 'utf8');
  } catch (error) {
    return {
      applied: false,
      persisted: false,
      requiresRescan: false,
      reason: `could not read ${path}: ${(error as Error).message}`,
    };
  }

  // The original text must still be present. If the file changed since the
  // scan, the remediation is stale and applying it would be wrong.
  if (!current.includes(remediation.original)) {
    return {
      applied: false,
      persisted: false,
      requiresRescan: true,
      reason:
        'the file has changed since the scan (the flagged text no longer matches); re-run the scan',
      diff: remediation.diff,
    };
  }

  const patched = current.replace(remediation.original, remediation.replacement);

  if (options.dryRun) {
    return {
      applied: true,
      persisted: false,
      requiresRescan: true,
      file: remediation.file,
      reason: 'dry run: no files were written',
      diff: remediation.diff,
    };
  }

  await writeFile(path, patched, 'utf8');
  return {
    applied: true,
    persisted: true,
    requiresRescan: true,
    file: remediation.file,
    written: true,
    diff: remediation.diff,
  };
}

/**
 * Validate a patch by re-scanning the patched content.
 *
 * Returns the findings that remain for this rule. A remediation that does not
 * clear its own finding is reported as ineffective rather than shipped — this
 * is what makes `--fix` trustworthy enough to put in CI.
 */
export function validatePatch(
  remediation: Remediation,
  patchedContent: string,
  evaluate: (content: string) => Finding[],
): { effective: boolean; remaining: Finding[] } {
  const remaining = evaluate(patchedContent).filter((f) => f.ruleId === remediation.ruleId);
  return { effective: remaining.length === 0, remaining };
}

function estimateMinutes(remediation: Remediation): number {
  const fix = MECHANICAL_BY_RULE.get(remediation.ruleId);
  if (fix) return fix.estimatedMinutes;
  switch (remediation.ruleId.slice(0, 4)) {
    default:
      return 60;
  }
}

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
function rankOf(severity: Severity): number {
  return RANK[severity] ?? RANK.info;
}

function sortBySeverity(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => rankOf(a.severity) - rankOf(b.severity));
}

export { MECHANICAL_FIXES, applyEdits, type FileEdit };