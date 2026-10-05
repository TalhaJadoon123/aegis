import { createHash } from 'node:crypto';
import type { Finding } from './types.js';

/**
 * Content fingerprints make findings stable across runs, branches and CI jobs.
 *
 * The fingerprint deliberately excludes volatile fields (timestamps, run ids)
 * and hashes normalised source text so that re-indenting a file does not
 * produce a "new" finding. It is what powers dedup, trend lines and
 * "is this issue new since last week?".
 */
export function fingerprintFinding(
  finding: Pick<Finding, 'ruleId' | 'location' | 'evidence' | 'severity'>,
): string {
  // The file is part of the identity: the same rule firing on the same line
  // number in two different files is two distinct issues. Merging them would
  // hide one while the other was reported as resolved.
  //
  // A separator is required — without it `['a', 'bc']` and `['ab', 'c']`
  // collide, which silently merges unrelated findings.
  const parts = [
    finding.ruleId,
    normalizePath(finding.location.file ?? finding.location.component ?? ''),
    String(finding.location.line ?? ''),
    normalizeEvidence(finding.evidence),
    finding.severity,
  ];
  return stableHash(parts.join(' '));
}

export function normalizeEvidence(evidence: string): string {
  return evidence
    .replace(/\r\n/g, '\n')
    .replace(/[ \t]+/g, ' ')
    .trim()
    .toLowerCase();
}

export function normalizePath(path: string): string {
  return path.replace(/\\/g, '/').replace(/^\.\//, '');
}

/** xxhash-style 128-bit hex via sha256 truncation, stable across platforms. */
export function stableHash(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex').slice(0, 32);
}

/** Shannon entropy of a string, in bits per character. */
export function shannonEntropy(input: string): number {
  if (!input.length) return 0;
  const freq = new Map<string, number>();
  for (const ch of input) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Collapse a run of whitespace and quotes so that generated identifiers in
 * different runs hash to the same value.
 */
export function canonicalize(value: string): string {
  return value.trim().replace(/\s+/g, ' ').replace(/["']/g, '');
}
