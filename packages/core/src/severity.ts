import { createHash } from 'node:crypto';
import {
  CONFIDENCE_MULTIPLIER,
  SEVERITIES,
  SEVERITY_ORDER,
  SEVERITY_WEIGHT,
  type ComplianceMapping,
  type Finding,
  type ScanResult,
  type ScoreBreakdown,
  type SecurityScore,
  type Severity,
} from './types.js';

export { SEVERITIES, SEVERITY_ORDER, SEVERITY_WEIGHT };

/** Parse a severity from untrusted input; defaults to `medium`. */
export function toSeverity(input: unknown): Severity {
  if (typeof input !== 'string') return 'medium';
  const normalized = input.trim().toLowerCase();
  return (SEVERITIES as readonly string[]).includes(normalized)
    ? (normalized as Severity)
    : 'medium';
}

/**
 * Comparator with the semantics of `Array.prototype.sort`: negative means `a`
 * sorts before `b`. `SEVERITY_ORDER` is ordered most-severe-first, so a lower
 * index is a higher severity.
 */
export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b);
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return compareSeverity(a, b) < 0 ? a : b;
}

export function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const out = emptySeverityCounts();
  for (const f of findings) out[f.severity] += 1;
  return out;
}

export function emptySeverityCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

/**
 * A CVSS-inspired base score in the 0–10 range.
 *
 * Aegis does not claim CVSS certification: agentic findings have no agreed
 * temporal/environmental model yet. What we do take from CVSS v3.1 is the
 * separation of *impact* (how bad) from *confidence* (how sure we are), so
 * numbers stay comparable across scanners and stay monotonic under filtering.
 */
export function baseScore(severity: Severity, confidence: Finding['confidence']): number {
  const impact = { critical: 10, high: 7, medium: 4.5, low: 2, info: 0.5 }[severity];
  const raw = impact * CONFIDENCE_MULTIPLIER[confidence];
  // Round to one decimal, CVSS style.
  return Math.round(Math.min(10, Math.max(0, raw)) * 10) / 10;
}

const GRADE_BANDS: Array<[number, SecurityScore['grade']]> = [
  [97, 'A'],
  [90, 'B'],
  [75, 'C'],
  [60, 'D'],
  [0, 'F'],
];

export function gradeFor(score: number): ScoreBreakdown['grade'] {
  const clamped = Math.max(0, Math.min(100, score));
  for (const [min, grade] of GRADE_BANDS) if (clamped >= min) return grade;
  return 'F';
}

export interface ScoreInput {
  findings: readonly Finding[];
  /** Optional per-dimension penalties, e.g. graph risk or behavioural anomaly. */
  dimensions?: Record<string, number>;
  /** Scale the total penalty. 1 = default. */
  weight?: number;
}

/**
 * Turn a bag of findings into a single 0–100 health score.
 *
 * Penalty per finding is `severityWeight * confidenceMultiplier`. The total
 * penalty is compressed with a soft curve so that one critical finding hurts
 * badly but 20 of them do not push the score into negative territory.
 */
export function computeScore(input: ScoreInput): SecurityScore {
  const weight = input.weight ?? 1;
  const bySeverity = countBySeverity(input.findings);
  const raw = input.findings.reduce((sum, f) => {
    const impact = { critical: 10, high: 7, medium: 4, low: 2, info: 0 }[f.severity];
    return sum + impact * CONFIDENCE_MULTIPLIER[f.confidence];
  }, 0);
  const penalty = raw * weight;
  // Soft compression: 100 * exp(-penalty/60) — 0 penalty = 100, 60 = 36.8, 180 = 5.
  const score = Math.round(100 * Math.exp(-penalty / 60));
  const clamped = Math.max(0, Math.min(100, score));

  return {
    score: clamped,
    grade: gradeFor(clamped),
    penalty: Math.round(penalty * 10) / 10,
    bySeverity,
    confidenceAdjusted: Math.round(penalty * 10) / 10,
    ...(input.dimensions ? { dimensions: input.dimensions } : {}),
  };
}

/**
 * Deduplicate findings by fingerprint, keeping the highest severity/confidence
 * instance. Runs of repeated findings (same rule across files) collapse to one
 * entry but remember where else they appeared.
 */
export function dedupeFindings(findings: readonly Finding[]): Finding[] {
  const byKey = new Map<string, Finding>();
  for (const finding of findings) {
    const key = finding.fingerprint ?? finding.id;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { ...finding, fingerprint: finding.fingerprint ?? key });
      continue;
    }
    const keep = rank(existing) >= rank(finding) ? existing : finding;
    const other = keep === existing ? finding : existing;
    const occurrences = [
      ...((keep.metadata?.['occurrences'] as string[] | undefined) ?? []),
      ...((other.metadata?.['occurrences'] as string[] | undefined) ?? []),
      formatLocation(other),
    ];
    byKey.set(key, {
      ...keep,
      fingerprint: key,
      metadata: { ...keep.metadata, occurrences: [...new Set(occurrences)] },
    });
  }
  return [...byKey.values()];
}

function rank(f: Finding): number {
  return SEVERITY_WEIGHT[f.severity] * 10 + CONFIDENCE_MULTIPLIER[f.confidence] * 5;
}

export function formatLocation(f: Finding): string {
  const { file, line, column, component } = f.location;
  if (component) return component;
  if (!file) return '<unknown>';
  return line ? `${file}:${line}${column ? `:${column}` : ''}` : file;
}

/**
 * Sort findings for report output: most severe first, then by file and line.
 *
 * `compareSeverity(a, b)` is negative when `a` is *more* severe, so `a` is
 * passed first. Passing them the other way silently produced ascending order,
 * putting critical findings at the bottom of every report.
 */
export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const s = compareSeverity(a.severity, b.severity);
    if (s !== 0) return s;
    const rankDiff = SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity];
    if (rankDiff !== 0) return rankDiff;
    const file = (a.location.file ?? '').localeCompare(b.location.file ?? '');
    if (file !== 0) return file;
    return (a.location.line ?? 0) - (b.location.line ?? 0);
  });
}

/** Keep only findings at or above `min`. */
export function filterBySeverity(findings: readonly Finding[], min: Severity): Finding[] {
  return findings.filter((f) => compareSeverity(f.severity, min) <= 0);
}

/** A finding qualifies as an error for CI purposes. */
export function isBlocking(finding: Finding, min: Severity): boolean {
  return compareSeverity(finding.severity, min) <= 0;
}

export function aggregateCompliance(
  findings: readonly Finding[],
): Array<{ control: ComplianceMapping; findings: number; worst: Severity }> {
  const map = new Map<string, { control: ComplianceMapping; findings: number; worst: Severity }>();
  for (const f of findings) {
    for (const c of f.compliance) {
      const key = `${c.framework}:${c.control}`;
      const existing = map.get(key);
      if (!existing) {
        map.set(key, { control: c, findings: 1, worst: f.severity });
      } else {
        existing.findings += 1;
        if (compareSeverity(f.severity, existing.worst) < 0) existing.worst = f.severity;
      }
    }
  }
  return [...map.values()].sort(
    (a, b) => compareSeverity(a.worst, b.worst) || b.findings - a.findings,
  );
}

/** Merge multiple `ScanResult`s into one aggregate score. */
export function scoreScanResults(results: readonly ScanResult[]): SecurityScore {
  const all = results.flatMap((r) => r.findings);
  return computeScore({ findings: all });
}
