import { formatLocation, sortFindings } from './severity.js';
import type { ComplianceMapping, Finding, ScanResult, SecurityScore, Severity } from './types.js';

/**
 * Output formats.
 *
 * Every Aegis scanner emits the same `Finding`, so every consumer — a terminal,
 * a CI job, GitHub code scanning, a PDF, a database row — is a rendering of the
 * same data. Keeping the renderers separate from the findings model means a
 * new consumer never requires a scanner change.
 */

export type OutputFormat = 'json' | 'sarif' | 'markdown' | 'html' | 'text' | 'csv' | 'jsonl';

export const OUTPUT_FORMATS: OutputFormat[] = [
  'json',
  'sarif',
  'markdown',
  'html',
  'text',
  'csv',
  'jsonl',
];

export interface AegisDocument {
  tool: { name: string; version: string; informationUri: string };
  /** Where the scan ran. */
  target: { type: string; path?: string; url?: string };
  startedAt: string;
  durationMs: number;
  score: SecurityScore;
  findings: Finding[];
  /** Scanner-specific artifacts (graphs, fingerprints, red-team reports). */
  artifacts?: Record<string, unknown>;
  errors?: string[];
  /** Which rule packs were loaded, for reproducibility. */
  rulePacks?: Array<{ id: string; version: string; ruleCount: number }>;
}

export const AEGIS_VERSION = '0.1.0';
export const AEGIS_URI = 'https://aegis.dev';

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

export function toJson(doc: AegisDocument, pretty = true): string {
  return JSON.stringify(doc, null, pretty ? 2 : 0);
}

/** Newline-delimited JSON, for streaming into log pipelines. */
export function toJsonl(findings: readonly Finding[]): string {
  return findings.map((f) => JSON.stringify(f)).join('\n');
}

// ---------------------------------------------------------------------------
// SARIF 2.1.0
// ---------------------------------------------------------------------------

const SARIF_LEVEL: Record<Severity, 'error' | 'warning' | 'note' | 'none'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'warning',
  info: 'note',
};

const SARIF_SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
  info: '1.0',
};

/**
 * SARIF 2.1.0.
 *
 * This is what makes Aegis usable inside the tools security teams already live
 * in — GitHub code scanning, Azure DevOps, GitLab, and anything else that
 * ingests SARIF. `security-severity` is set from Aegis's own score so the
 * findings sort correctly in those UIs, and partial fingerprints are supplied
 * so a finding stays the *same* finding across commits.
 */
export function toSarif(doc: AegisDocument): string {
  const findings = sortFindings(doc.findings);

  // Rule order must follow the *sorted* findings, not input order: SARIF
  // consumers match `results[].ruleId` against `tool.driver.rules[ruleIndex]`,
  // and a mismatch silently mislabels every finding in the host UI.
  const rules = new Map<string, Finding>();
  for (const finding of findings) {
    if (!rules.has(finding.ruleId)) rules.set(finding.ruleId, finding);
  }

  const ruleIndex = new Map<string, number>();
  let index = 0;
  for (const id of rules.keys()) ruleIndex.set(id, index++);

  const sarif = {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Aegis',
            version: AEGIS_VERSION,
            informationUri: AEGIS_URI,
            semanticVersion: AEGIS_VERSION,
            rules: [...rules.entries()].map(([id, finding]) => ({
              id,
              name: id,
              shortDescription: { text: finding.title },
              fullDescription: { text: finding.description },
              help: {
                text: `${finding.remediation.title}\n\n${finding.remediation.description}`,
                ...(finding.remediation.docs
                  ? { markdown: `[Documentation](${finding.remediation.docs})` }
                  : {}),
              },
              defaultConfiguration: {
                level: SARIF_LEVEL[finding.severity],
              },
              properties: {
                tags: [finding.source, ...(finding.tags ?? [])],
                ...(finding.taxonomy ? { taxonomy: finding.taxonomy } : {}),
                ...(finding.cwe ? { cwe: finding.cwe } : {}),
                "security-severity": SARIF_SECURITY_SEVERITY[finding.severity],
                "problem.severity": finding.severity,
                ...(finding.compliance.length
                  ? {
                      compliance: finding.compliance.map((c) => `${c.framework}:${c.control}`),
                    }
                  : {}),
              },
              ...(finding.compliance.length
                ? {
                    relationships: finding.compliance
                      .filter((c) => c.relevant)
                      .map((c) => ({
                        target: {
                          id: `${c.framework}-${c.control}`,
                          toolComponent: { name: 'AegisCompliance', guid: `${c.framework}-${c.control}` },
                        },
                        kinds: ['relevant'],
                      })),
                  }
                : {}),
            })),
          },
        },
        automationDetails: {
          id: `aegis/${doc.target.type}/${Date.now()}`,
        },
        invocations: [
          {
            executionSuccessful: (doc.errors?.length ?? 0) === 0,
            startTimeUtc: doc.startedAt,
            endTimeUtc: new Date(Date.parse(doc.startedAt) + doc.durationMs).toISOString(),
            ...(doc.errors?.length ? { toolExecutionNotifications: doc.errors.map((message) => ({ level: 'warning', message })) } : {}),
          },
        ],
        properties: {
          securityScore: doc.score.score,
          grade: doc.score.grade,
          findingCounts: doc.score.bySeverity,
        },
        results: findings.map((finding) => ({
          ruleId: finding.ruleId,
          ruleIndex: ruleIndex.get(finding.ruleId) ?? 0,
          level: SARIF_LEVEL[finding.severity],
          message: { text: `${finding.title}\n\n${finding.description}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: finding.location.file ?? 'agent://runtime',
                  ...(finding.location.file && !finding.location.file.includes('://')
                    ? {}
                    : { uriBaseId: 'AEGIS_ROOT' }),
                },
                region: {
                  startLine: Math.max(1, finding.location.line ?? 1),
                  ...(finding.location.column ? { startColumn: finding.location.column } : {}),
                  ...(finding.location.endLine ? { endLine: finding.location.endLine } : {}),
                  snippet: { text: truncate(finding.evidence, 500) },
                },
              },
              ...(finding.location.component
                ? {
                    logicalLocations: [
                      { name: finding.location.component, kind: 'module', fullyQualifiedName: finding.location.component },
                    ],
                  }
                : {}),
            },
          ],
          // A stable partial fingerprint keeps a finding the *same* finding
          // across commits, which is what drives the "new since last scan"
          // signal in code scanning UIs.
          partialFingerprints: {
            aegisFingerprint: finding.fingerprint ?? `${finding.ruleId}:${finding.location.line ?? 0}`,
          },
          properties: {
            severity: finding.severity,
            confidence: finding.confidence,
            ...(finding.taxonomy ? { taxonomy: finding.taxonomy } : {}),
            ...(finding.cwe ? { cwe: finding.cwe } : {}),
            ...(finding.tags ? { tags: finding.tags } : {}),
            compliance: finding.compliance.map((c) => ({
              framework: c.framework,
              control: c.control,
              title: c.title,
              relevant: c.relevant,
            })),
            remediation: {
              title: finding.remediation.title,
              automated: finding.remediation.automated,
              effort: finding.remediation.effort,
            },
          },
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

// ---------------------------------------------------------------------------
// Terminal
// ---------------------------------------------------------------------------

const COLOR = {
  reset: '[0m',
  bold: '[1m',
  dim: '[2m',
  red: '[31m',
  brightRed: '[91m',
  yellow: '[33m',
  green: '[32m',
  cyan: '[36m',
  magenta: '[35m',
  gray: '[90m',
  blue: '[34m',
} as const;

type ColorSet = { [K in keyof typeof COLOR]: string };

export interface TextOptions {
  color?: boolean;
  /** Include the evidence snippet. */
  evidence?: boolean;
  /** Max findings to print. */
  limit?: number;
  /** Group by rule rather than by file. */
  groupBy?: 'file' | 'rule' | 'severity';
}

export function toText(doc: AegisDocument, options: TextOptions = {}): string {
  const useColor = options.color ?? process.stdout.isTTY === true;
  const c = useColor ? COLOR : emptyColor;
  const findings = sortFindings(doc.findings);
  const limit = options.limit ?? findings.length;
  const lines: string[] = [];

  lines.push('');
  lines.push(`${c.bold}Aegis security scan${c.reset} ${c.dim}${doc.target.path ?? doc.target.url ?? doc.target.type}${c.reset}`);
  lines.push('');

  const counts = doc.score.bySeverity;
  const chips: string[] = [];
  if (counts.critical) chips.push(`${c.brightRed}${counts.critical} critical${c.reset}`);
  if (counts.high) chips.push(`${c.red}${counts.high} high${c.reset}`);
  if (counts.medium) chips.push(`${c.yellow}${counts.medium} medium${c.reset}`);
  if (counts.low) chips.push(`${counts.low} low${c.reset}`);
  if (counts.info) chips.push(`${c.dim}${counts.info} info${c.reset}`);

  lines.push(
    `  Score ${gradeColor(doc.score.grade, c)}${doc.score.score}/100 (${doc.score.grade})${c.reset}` +
      (chips.length ? `   ${chips.join('  ')}` : `   ${c.green}no findings${c.reset}`),
  );
  lines.push('');

  if (findings.length === 0) {
    lines.push(`  ${c.green}✓ No security issues found.${c.reset}`);
    lines.push('');
    return lines.join('\n');
  }

  const groups = groupFindings(findings, options.groupBy ?? 'severity');
  let shown = 0;

  for (const [groupLabel, groupFindings_] of groups) {
    if (shown >= limit) break;
    lines.push(`${c.bold}${groupLabel}${c.reset}`);
    lines.push('');
    for (const finding of groupFindings_) {
      if (shown >= limit) break;
      shown++;
      const sev = severityColor(finding.severity, c);
      lines.push(`  ${sev}${pad(finding.severity.toUpperCase(), 8)}${c.reset} ${c.bold}${finding.title}${c.reset}`);
      lines.push(`  ${c.dim}${formatLocation(finding)}${c.reset}`);
      if (finding.taxonomy || finding.cwe) {
        const refs = [finding.taxonomy, finding.cwe].filter(Boolean).join('  ');
        lines.push(`  ${c.dim}${refs}${c.reset}`);
      }
      if (options.evidence !== false && finding.evidence) {
        const snippet = finding.evidence.split('\n').slice(0, 4).join('\n');
        for (const line of snippet.split('\n')) lines.push(`    ${c.gray}${line}${c.reset}`);
      }
      lines.push(`  ${c.cyan}→ ${finding.remediation.title}${c.reset}`);
      const compliance = finding.compliance
        .filter((m) => m.relevant)
        .slice(0, 4)
        .map((m) => `${m.framework}/${m.control}`);
      if (compliance.length) {
        lines.push(`  ${c.dim}${compliance.join('  ')}${c.reset}`);
      }
      lines.push('');
    }
  }

  if (shown < findings.length) {
    lines.push(`  ${c.dim}… and ${findings.length - shown} more (use --limit to show all)${c.reset}`);
    lines.push('');
  }

  lines.push(`  ${c.dim}${findings.length} finding(s) in ${doc.durationMs}ms · score ${doc.score.score}/100${c.reset}`);
  lines.push('');

  if (doc.errors?.length) {
    lines.push(`${c.dim}Errors:${c.reset}`);
    for (const error of doc.errors.slice(0, 5)) lines.push(`  ${c.dim}${error}${c.reset}`);
    lines.push('');
  }

  return lines.join('\n');
}

const emptyColor: ColorSet = {
  reset: '', bold: '', dim: '', red: '', brightRed: '', yellow: '',
  green: '', cyan: '', magenta: '', gray: '', blue: '',
};

function severityColor(severity: Severity, c: ColorSet): string {
  switch (severity) {
    case 'critical':
      return c.brightRed;
    case 'high':
      return c.red;
    case 'medium':
      return c.yellow;
    case 'low':
      return c.blue;
    default:
      return c.gray;
  }
}

function gradeColor(grade: string, c: ColorSet): string {
  switch (grade) {
    case 'A':
      return c.green;
    case 'B':
      return c.green;
    case 'C':
      return c.yellow;
    case 'D':
      return c.yellow;
    default:
      return c.red;
  }
}

function pad(value: string, width: number): string {
  return value.padEnd(width);
}

function groupFindings(
  findings: readonly Finding[],
  by: 'file' | 'rule' | 'severity',
): Array<[string, Finding[]]> {
  const map = new Map<string, Finding[]>();
  for (const finding of findings) {
    const key =
      by === 'file'
        ? finding.location.file ?? finding.location.component ?? 'unknown'
        : by === 'rule'
          ? finding.ruleId
          : finding.severity;
    map.set(key, [...(map.get(key) ?? []), finding]);
  }
  const entries = [...map.entries()];
  if (by === 'severity') {
    entries.sort((a, b) => severityOrder(a[0]) - severityOrder(b[0]));
  }
  return entries;
}

function severityOrder(severity: string): number {
  return ['critical', 'high', 'medium', 'low', 'info'].indexOf(severity);
}

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

export function toMarkdown(doc: AegisDocument): string {
  const findings = sortFindings(doc.findings);
  const lines: string[] = [];

  lines.push(`# Aegis Security Scan`);
  lines.push('');
  lines.push(`**Target:** \`${doc.target.path ?? doc.target.url ?? doc.target.type}\`  `);
  lines.push(`**Scanned:** ${doc.startedAt}  `);
  lines.push(`**Duration:** ${doc.durationMs}ms  `);
  lines.push(
    `**Security score:** ${doc.score.score}/100 (${doc.score.grade})`,
  );
  lines.push('');

  lines.push('## Summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('| --- | --- |');
  for (const severity of ['critical', 'high', 'medium', 'low', 'info'] as const) {
    const count = doc.score.bySeverity[severity];
    if (count > 0) lines.push(`| ${cap(severity)} | ${count} |`);
  }
  if (doc.score.bySeverity.critical + doc.score.bySeverity.high === 0) {
    lines.push('| — | 0 |');
  }
  lines.push('');

  if (findings.length > 0) {
    lines.push('## Findings');
    lines.push('');
    for (const finding of findings) {
      lines.push(`### ${cap(finding.severity)}: ${finding.title}`);
      lines.push('');
      lines.push(`- **Rule:** \`${finding.ruleId}\``);
      lines.push(`- **Location:** \`${formatLocation(finding)}\``);
      if (finding.taxonomy) lines.push(`- **OWASP Agentic:** ${finding.taxonomy}`);
      if (finding.cwe) lines.push(`- **CWE:** ${finding.cwe}`);
      const compliance = finding.compliance.filter((c) => c.relevant);
      if (compliance.length) {
        lines.push(`- **Compliance:** ${compliance.map((c) => `${c.framework}/${c.control}`).join(', ')}`);
      }
      lines.push('');
      lines.push(finding.description);
      lines.push('');
      if (finding.evidence) {
        lines.push('```');
        lines.push(truncate(finding.evidence, 1500));
        lines.push('```');
        lines.push('');
      }
      lines.push(`**Remediation:** ${finding.remediation.description}`);
      lines.push('');
    }
  }

  // Compliance roll-up: the artefact most people actually need from a scan.
  const controls = rollUpCompliance(findings);
  if (controls.length > 0) {
    lines.push('## Compliance impact');
    lines.push('');
    lines.push('| Framework | Control | Findings | Worst severity |');
    lines.push('| --- | --- | --- | --- |');
    for (const control of controls) {
      lines.push(
        `| ${control.framework} | ${control.control} | ${control.count} | ${control.worst} |`,
      );
    }
    lines.push('');
  }

  return lines.join('\n');
}

export function rollUpCompliance(findings: readonly Finding[]): Array<{
  framework: string;
  control: string;
  title?: string;
  count: number;
  worst: string;
}> {
  const map = new Map<string, { framework: string; control: string; title?: string; count: number; worst: string }>();
  for (const finding of findings) {
    for (const mapping of finding.compliance) {
      const key = `${mapping.framework}:${mapping.control}`;
      const entry = map.get(key) ?? {
        framework: mapping.framework,
        control: mapping.control,
        title: mapping.title,
        count: 0,
        worst: 'info',
      };
      entry.count++;
      if (severityOrder(finding.severity) < severityOrder(entry.worst)) entry.worst = finding.severity;
      map.set(key, entry);
    }
  }
  return [...map.values()].sort(
    (a, b) => severityOrder(a.worst) - severityOrder(b.worst) || b.count - a.count,
  );
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

/**
 * Self-contained HTML report.
 *
 * No CDN, no external CSS: a security report gets emailed to auditors and
 * attached to tickets, so it has to render on a machine with no internet and
 * survive being opened from a file:// path.
 */
export function toHtml(doc: AegisDocument): string {
  const findings = sortFindings(doc.findings);
  const esc = escapeHtml;

  const rows = findings
    .map(
      (f) => `
    <details class="finding sev-${f.severity}" id="${esc(f.fingerprint ?? f.id)}">
      <summary>
        <span class="badge ${f.severity}">${esc(f.severity)}</span>
        <span class="title">${esc(f.title)}</span>
        <span class="loc">${esc(formatLocation(f))}</span>
      </summary>
      <div class="body">
        <p>${esc(f.description)}</p>
        <dl>
          <dt>Rule</dt><dd><code>${esc(f.ruleId)}</code></dd>
          ${f.taxonomy ? `<dt>OWASP Agentic</dt><dd>${esc(f.taxonomy)}</dd>` : ''}
          ${f.cwe ? `<dt>CWE</dt><dd>${esc(f.cwe)}</dd>` : ''}
          <dt>Confidence</dt><dd>${esc(f.confidence)}</dd>
          ${
            f.compliance.length
              ? `<dt>Compliance</dt><dd>${f.compliance
                  .filter((c) => c.relevant)
                  .map((c) => `<span class="pill">${esc(c.framework)}/${esc(c.control)}</span>`)
                  .join(' ')}</dd>`
              : ''
          }
        </dl>
        ${
          f.evidence
            ? `<pre>${esc(truncate(f.evidence, 3000))}</pre>`
            : ''
        }
        <div class="fix">
          <strong>${esc(f.remediation.title)}</strong>
          <p>${esc(f.remediation.description)}</p>
          ${f.remediation.patch ? `<pre class="patch">${esc(f.remediation.patch)}</pre>` : ''}
        </div>
      </div>
    </details>`,
    )
    .join('');

  const controls = rollUpCompliance(findings);

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Aegis Security Scan — ${esc(doc.target.path ?? doc.target.type)}</title>
<style>
  :root {
    --bg: #0b1020; --panel: #131a2e; --border: #1e293b; --text: #e2e8f0;
    --muted: #94a3b8; --critical: #ef4444; --high: #f97316; --medium: #eab308;
    --low: #3b82f6; --info: #64748b; --accent: #38bdf8;
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text);
    font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 32px 24px 80px; }
  header { display:flex; align-items:flex-start; gap:24px; margin-bottom:28px; }
  .score { font-size:44px; font-weight:700; line-height:1; }
  .grade { font-size:14px; color:var(--muted); margin-top:6px; }
  h1 { font-size:22px; margin:0 0 4px; }
  .meta { color:var(--muted); font-size:13px; }
  .chips { display:flex; gap:8px; flex-wrap:wrap; margin:18px 0 28px; }
  .chip { background:var(--panel); border:1px solid var(--border); border-radius:999px;
    padding:5px 14px; font-size:13px; }
  .finding { background:var(--panel); border:1px solid var(--border); border-radius:10px;
    margin-bottom:10px; overflow:hidden; }
  .finding summary { cursor:pointer; padding:13px 16px; display:flex; gap:12px;
    align-items:center; list-style:none; }
  .finding summary::-webkit-details-marker { display:none; }
  .finding[open] summary { border-bottom:1px solid var(--border); }
  .badge { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.4px;
    padding:3px 9px; border-radius:5px; flex-shrink:0; min-width:72px; text-align:center; }
  .badge.critical{background:var(--critical);color:#fff} .badge.high{background:var(--high);color:#fff}
  .badge.medium{background:var(--medium);color:#1a1400} .badge.low{background:var(--low);color:#fff}
  .badge.info{background:var(--info);color:#fff}
  .finding.sev-critical{ border-left:3px solid var(--critical) }
  .finding.sev-high{ border-left:3px solid var(--high) }
  .finding.sev-medium{ border-left:3px solid var(--medium) }
  .finding.sev-low{ border-left:3px solid var(--low) }
  .finding.sev-info{ border-left:3px solid var(--info) }
  .title { flex:1; font-weight:500; }
  .loc { color:var(--muted); font-size:12px; font-family:ui-monospace,monospace; }
  .body { padding:16px 18px 20px; }
  .body p { margin:0 0 12px; }
  dl { display:grid; grid-template-columns:150px 1fr; gap:6px 14px; font-size:13px; margin:0 0 14px; }
  dt { color:var(--muted); } dd { margin:0; }
  code { font-family:ui-monospace,monospace; background:#0b1020; padding:1px 5px; border-radius:4px; font-size:12px; }
  pre { background:#0b1020; border:1px solid var(--border); border-radius:8px; padding:12px 14px;
    overflow-x:auto; font-family:ui-monospace,monospace; font-size:12px; line-height:1.5; }
  .patch { border-color:#1f6f4a; background:#08150f; color:#a7f3d0; }
  .pill { background:#0b1020; border:1px solid var(--border); border-radius:5px;
    padding:1px 7px; font-size:11px; margin-right:4px; display:inline-block; }
  .fix { border-top:1px solid var(--border); margin-top:14px; padding-top:14px; }
  .fix strong { color:var(--accent); }
  .clean { background:var(--panel); border:1px solid var(--border); border-radius:10px;
    padding:36px; text-align:center; color:var(--muted); }
  table { width:100%; border-collapse:collapse; font-size:13px; margin-top:8px; }
  th,td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); }
  th { color:var(--muted); font-weight:500; }
  h2 { font-size:16px; margin:36px 0 12px; }
  footer { margin-top:44px; color:var(--muted); font-size:12px; border-top:1px solid var(--border); padding-top:16px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <div class="score" style="color:${gradeHex(doc.score.grade)}">${doc.score.score}</div>
      <div class="grade">grade ${esc(doc.score.grade)}</div>
    </div>
    <div style="flex:1">
      <h1>Aegis Security Scan</h1>
      <div class="meta">
        <code>${esc(doc.target.path ?? doc.target.url ?? doc.target.type)}</code><br/>
        ${esc(doc.startedAt)} · ${doc.durationMs}ms · ${doc.target.type} scanner
      </div>
    </div>
  </header>

  <div class="chips">
    ${Object.entries(doc.score.bySeverity)
      .filter(([, n]) => n > 0)
      .map(([sev, n]) => `<span class="chip"><strong>${n}</strong> ${sev}</span>`)
      .join('')}
    <span class="chip">${findings.length} total</span>
  </div>

  ${
    findings.length === 0
      ? '<div class="clean">✓ No security issues found.</div>'
      : `<h2>Findings</h2>${rows}`
  }

  ${
    controls.length
      ? `<h2>Compliance impact</h2>
  <table>
    <thead><tr><th>Framework</th><th>Control</th><th>Findings</th><th>Worst</th></tr></thead>
    <tbody>${controls
      .map(
        (c) =>
          `<tr><td>${esc(c.framework)}</td><td><code>${esc(c.control)}</code></td><td>${c.count}</td><td>${esc(c.worst)}</td></tr>`,
      )
      .join('')}</tbody>
  </table>`
      : ''
  }

  <footer>
    Generated by Aegis ${AEGIS_VERSION} — the security platform for AI agents.
    ${doc.rulePacks?.length ? `Rule packs: ${doc.rulePacks.map((p) => esc(p.id)).join(', ')}.` : ''}
  </footer>
</div>
</body>
</html>`;
}

function gradeHex(grade: string): string {
  return { A: '#22c55e', B: '#22c55e', C: '#eab308', D: '#f97316', F: '#ef4444' }[grade] ?? '#e2e8f0';
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

export function toCsv(doc: AegisDocument): string {
  const esc = (v: unknown): string => {
    const s = v === undefined || v === null ? '' : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const header = [
    'severity', 'confidence', 'rule_id', 'title', 'file', 'line', 'column',
    'taxonomy', 'cwe', 'compliance', 'remediation', 'automated', 'fingerprint',
  ];
  const rows = sortFindings(doc.findings).map((f) =>
    [
      f.severity, f.confidence, f.ruleId, f.title,
      f.location.file ?? '', f.location.line ?? '', f.location.column ?? '',
      f.taxonomy ?? '', f.cwe ?? '',
      f.compliance.map((c) => `${c.framework}/${c.control}`).join(' '),
      f.remediation.title, f.remediation.automated, f.fingerprint ?? '',
    ].map(esc).join(','),
  );
  return [header.join(','), ...rows].join('\n');
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

export function render(doc: AegisDocument, format: OutputFormat, options: TextOptions = {}): string {
  switch (format) {
    case 'json':
      return toJson(doc);
    case 'jsonl':
      return toJsonl(doc.findings);
    case 'sarif':
      return toSarif(doc);
    case 'markdown':
      return toMarkdown(doc);
    case 'html':
      return toHtml(doc);
    case 'csv':
      return toCsv(doc);
    case 'text':
      return toText(doc, options);
    default:
      return toText(doc, options);
  }
}

export function mediaType(format: OutputFormat): string {
  switch (format) {
    case 'json':
    case 'jsonl':
      return 'application/json';
    case 'sarif':
      return 'application/sarif+json';
    case 'html':
      return 'text/html';
    case 'csv':
      return 'text/csv';
    case 'markdown':
      return 'text/markdown';
    default:
      return 'text/plain';
  }
}

export function fileExtension(format: OutputFormat): string {
  switch (format) {
    case 'json':
      return 'json';
    case 'jsonl':
      return 'jsonl';
    case 'sarif':
      return '.sarif';
    case 'html':
      return '.html';
    case 'csv':
      return '.csv';
    case 'markdown':
      return '.md';
    default:
      return '.txt';
  }
}

function cap(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function escapeHtml(value: string): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function truncate(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max)}\n… (truncated)`;
}

/** Build the standard document from raw scanner output. */
export function buildDocument(input: {
  target: { type: string; path?: string; url?: string };
  findings: Finding[];
  score: SecurityScore;
  durationMs: number;
  startedAt?: string;
  artifacts?: Record<string, unknown>;
  errors?: string[];
  rulePacks?: Array<{ id: string; version: string; ruleCount: number }>;
  results?: ScanResult[];
}): AegisDocument {
  return {
    tool: { name: 'Aegis', version: AEGIS_VERSION, informationUri: AEGIS_URI },
    target: input.target,
    startedAt: input.startedAt ?? new Date().toISOString(),
    durationMs: input.durationMs,
    score: input.score,
    findings: sortFindings(input.findings),
    ...(input.artifacts ? { artifacts: input.artifacts } : {}),
    ...(input.errors?.length ? { errors: input.errors } : {}),
    ...(input.rulePacks ? { rulePacks: input.rulePacks } : {}),
  };
}