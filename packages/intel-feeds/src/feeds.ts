/**
 * Threat feed parsers.
 *
 * Feed formats are inconsistent, versioned independently of each other, and
 * frequently contain vendor-specific quirks. Everything here is written to
 * *degrade*: an unexpected field is skipped rather than throwing, because a
 * scanner that stops working when an upstream feed adds a field is a scanner
 * that silently misses vulnerabilities.
 */

export interface FeedRecord {
  /** Canonical id: CVE id, GHSA id, or a synthetic hash. */
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** CVSS vector, when the feed provides one. */
  cvss?: string;
  /** Numeric CVSS score, 0–10. */
  score?: number;
  /** CWE identifiers. */
  cwes: string[];
  /** Package coordinates, when the record is about a dependency. */
  package?: { ecosystem: string; name: string; vulnerableRange?: string; fixedIn?: string };
  published: string;
  updated: string;
  references: string[];
  source: string;
  /** True when the record concerns AI agents, MCP, or an LLM system. */
  agentRelevant: boolean;
  tags: string[];
}

/** Signals that mark a vulnerability as relevant to agent security. */
const AGENT_SIGNALS = [
  /\bmcp\b/i,
  /\bmodel context protocol\b/i,
  /\bagentic\b/i,
  /\bllm\b/i,
  /\blarge language model\b/i,
  /\bprompt injection\b/i,
  /\bagent\b/i,
  /\blangchain\b/i,
  /\bllama.?index\b/i,
  /\bautogen\b/i,
  /\bcrewai\b/i,
  /\bopenai\b/i,
  /\banthropic\b/i,
];

const AGENT_TAGS = [
  'mcp', 'agentic-ai', 'llm', 'prompt-injection', 'agent-framework',
  'model-provider', 'tooling',
];

export function isAgentRelevant(text: string): boolean {
  return AGENT_SIGNALS.some((re) => re.test(text));
}

export function agentTags(text: string): string[] {
  const lower = text.toLowerCase();
  const out: string[] = [];
  if (/\bmcp\b|model context protocol/.test(lower)) out.push('mcp');
  if (/agent/.test(lower)) out.push('agentic-ai');
  if (/\bllm|large language model/.test(lower)) out.push('llm');
  if (/prompt injection/.test(lower)) out.push('prompt-injection');
  if (/langchain|llama.?index|autogen|crewai/.test(lower)) out.push('agent-framework');
  if (/openai|anthropic|google|mistral|cohere/.test(lower)) out.push('model-provider');
  return [...new Set(out)];
}

// ---------------------------------------------------------------------------
// NVD / CVE (CVE JSON 5.x)
// ---------------------------------------------------------------------------

export interface NvdResponse {
  vulnerabilities?: Array<{
    cve?: {
      id?: string;
      published?: string;
      lastModified?: string;
      vulnStatus?: string;
      descriptions?: Array<{ lang: string; value: string }>;
      metrics?: {
        cvssMetricV31?: Array<{ cvssData?: { baseScore?: number; vectorString?: string; baseSeverity?: string } }>;
        cvssMetricV30?: Array<{ cvssData?: { baseScore?: number; vectorString?: string; baseSeverity?: string } }>;
        cvssMetricV2?: Array<{ cvssData?: { baseScore?: number; vectorString?: string } }>;
      };
      weaknesses?: Array<{ description?: Array<{ value?: string }> }>;
      references?: Array<{ url?: string }>;
      configurations?: Array<{ nodes?: Array<{ cpeMatch?: Array<{ criteria?: string; versionStartIncluding?: string; versionEndExcluding?: string }> }> }>;
    };
  }>;
}

/** Parse an NVD API response. */
export function parseNvd(payload: NvdResponse): FeedRecord[] {
  const out: FeedRecord[] = [];
  for (const entry of payload.vulnerabilities ?? []) {
    const cve = entry.cve;
    if (!cve?.id) continue;

    const description =
      cve.descriptions?.find((d) => d.lang === 'en')?.value ??
      cve.descriptions?.[0]?.value ??
      '';

    const metric =
      cve.metrics?.cvssMetricV31?.[0]?.cvssData ??
      cve.metrics?.cvssMetricV30?.[0]?.cvssData ??
      cve.metrics?.cvssMetricV2?.[0]?.cvssData;

    const cwes = (cve.weaknesses ?? [])
      .flatMap((w) => w.description ?? [])
      .map((d) => d.value ?? '')
      .filter((v) => /^CWE-\d+$/i.test(v));

    const pkg = firstPackage(cve.configurations);
    const haystack = `${cve.id} ${description}`;

    out.push({
      id: cve.id,
      title: firstLine(description) || cve.id,
      description,
      severity: severityFromScore(metric?.baseScore),
      ...(metric?.vectorString ? { cvss: metric.vectorString } : {}),
      ...(typeof metric?.baseScore === 'number' ? { score: metric.baseScore } : {}),
      cwes,
      ...(pkg ? { package: pkg } : {}),
      published: cve.published ?? '',
      updated: cve.lastModified ?? cve.published ?? '',
      references: (cve.references ?? []).map((r) => r.url ?? '').filter(Boolean),
      source: 'nvd',
      agentRelevant: isAgentRelevant(haystack),
      tags: agentTags(haystack),
    });
  }
  return out;
}

function firstPackage(configs: NvdResponse['vulnerabilities'] extends undefined ? never : NonNullable<NonNullable<NvdResponse['vulnerabilities']>[number]['cve']>['configurations']): FeedRecord['package'] {
  for (const config of configs ?? []) {
    for (const node of config.nodes ?? []) {
      for (const match of node.cpeMatch ?? []) {
        const criteria = match.criteria ?? '';
        // cpe:2.3:a:vendor:product:version:...
        const parts = criteria.split(':');
        if (parts.length < 5) continue;
        const vendor = parts[3]!;
        const product = parts[4]!;
        // CPE product names are lowercased with underscores; restore a usable name.
        const name = `${vendor}/${product}`.replace(/_/g, '-');
        if (/^(unknown|n\/*a)$/.test(product)) continue;
        return {
          ecosystem: 'nvd-cpe',
          name,
          ...(match.versionStartIncluding || match.versionEndExcluding
            ? {
                vulnerableRange: [
                  match.versionStartIncluding ? `>=${match.versionStartIncluding}` : '',
                  match.versionEndExcluding ? `<${match.versionEndExcluding}` : '',
                ].filter(Boolean).join(' '),
              }
            : {}),
        };
      }
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// GitHub Advisory (OSV / GraphQL)
// ---------------------------------------------------------------------------

export interface GhsaAdvisory {
  ghsaId?: string;
  summary?: string;
  description?: string;
  severity?: string;
  cvss?: { score?: number; vectorString?: string };
  cwes?: Array<{ cweId?: string }>;
  publishedAt?: string;
  updatedAt?: string;
  references?: Array<{ url?: string }>;
  vulnerabilities?: Array<{
    package?: { ecosystem?: string; name?: string };
    firstPatchedVersion?: { identifier?: string };
    vulnerableVersionRange?: string;
  }>;
  identifiers?: Array<{ type?: string; value?: string }>;
}

export function parseGhsa(advisories: readonly GhsaAdvisory[]): FeedRecord[] {
  return advisories
    .filter((a) => a.ghsaId)
    .map((a) => {
      const pkg = a.vulnerabilities?.[0];
      const haystack = `${a.ghsaId} ${a.summary ?? ''} ${a.description ?? ''}`;
      return {
        id: a.ghsaId!,
        title: a.summary ?? a.ghsaId!,
        description: a.description ?? '',
        severity: severityFromLabel(a.severity) ?? 'medium',
        ...(a.cvss?.vectorString ? { cvss: a.cvss.vectorString } : {}),
        ...(typeof a.cvss?.score === 'number' ? { score: a.cvss.score } : {}),
        cwes: (a.cwes ?? []).map((c) => c.cweId ?? '').filter(Boolean),
        ...(pkg?.package?.name
          ? {
              package: {
                ecosystem: pkg.package.ecosystem ?? 'npm',
                name: pkg.package.name,
                ...(pkg.vulnerableVersionRange ? { vulnerableRange: pkg.vulnerableVersionRange } : {}),
                ...(pkg.firstPatchedVersion?.identifier
                  ? { fixedIn: pkg.firstPatchedVersion.identifier }
                  : {}),
              },
            }
          : {}),
        published: a.publishedAt ?? '',
        updated: a.updatedAt ?? a.publishedAt ?? '',
        references: (a.references ?? []).map((r) => r.url ?? '').filter(Boolean),
        source: 'github-advisory',
        agentRelevant: isAgentRelevant(haystack),
        tags: agentTags(haystack),
      } satisfies FeedRecord;
    });
}

// ---------------------------------------------------------------------------
// OSV
// ---------------------------------------------------------------------------

export interface OsvEntry {
  id?: string;
  summary?: string;
  details?: string;
  published?: string;
  modified?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { ecosystem?: string; name?: string };
    ranges?: Array<{ type: string; events: Array<{ introduced?: string; fixed?: string }> }>;
    database_specific?: { severity?: string };
  }>;
  references?: Array<{ type: string; url: string }>;
  database_specific?: { cwe_ids?: string[] };
}

export function parseOsv(entries: readonly OsvEntry[]): FeedRecord[] {
  return entries
    .filter((e) => e.id)
    .map((e) => {
      const affected = e.affected?.[0];
      const cvss = e.severity?.find((s) => s.type.startsWith('CVSS'));
      const score = cvss ? numericFromCvss(cvss.score) : undefined;
      // Prefer an explicit numeric score; otherwise use the advisory's own
      // severity label. Computing a CVSS base score from a vector string is a
      // full CVSS v3.1 implementation, and a rough approximation that silently
      // disagrees with the publisher's rating is worse than deferring to them.
      const labelSeverity = severityFromLabel(affected?.database_specific?.severity);
      const haystack = `${e.id} ${e.summary ?? ''} ${e.details ?? ''}`;
      const range = affected?.ranges?.[0];
      return {
        id: e.id!,
        title: e.summary ?? e.id!,
        description: e.details ?? '',
        severity: typeof score === 'number' ? severityFromScore(score) : labelSeverity,
        ...(cvss ? { cvss: cvss.score } : {}),
        ...(typeof score === 'number' ? { score } : {}),
        cwes: e.database_specific?.cwe_ids ?? [],
        ...(affected?.package?.name
          ? {
              package: {
                ecosystem: affected.package.ecosystem ?? 'unknown',
                name: affected.package.name,
                ...(range
                  ? {
                      vulnerableRange: range.events
                        .map((ev) =>
                          ev.introduced ? `>=${ev.introduced}` : ev.fixed ? `<${ev.fixed}` : '',
                        )
                        .filter(Boolean)
                        .join(' '),
                    }
                  : {}),
                ...(range?.events.find((ev) => ev.fixed)?.fixed
                  ? { fixedIn: range.events.find((ev) => ev.fixed)!.fixed! }
                  : {}),
              },
            }
          : {}),
        published: e.published ?? '',
        updated: e.modified ?? e.published ?? '',
        references: (e.references ?? []).map((r) => r.url).filter(Boolean),
        source: 'osv',
        agentRelevant: isAgentRelevant(haystack),
        tags: agentTags(haystack),
      } satisfies FeedRecord;
    });
}

// ---------------------------------------------------------------------------
// Generic JSON and NDJSON feeds (community submissions, internal feeds)
// ---------------------------------------------------------------------------

export function parseNdjson(text: string, source = 'community'): FeedRecord[] {
  const out: FeedRecord[] = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    try {
      out.push(...parseOsv([JSON.parse(trimmed) as OsvEntry]).map((r) => ({ ...r, source })));
    } catch {
      // Skip malformed lines rather than failing the whole feed.
    }
  }
  return out;
}

export function parseFeed(text: string, format: 'nvd' | 'ghsa' | 'osv' | 'ndjson'): FeedRecord[] {
  try {
    const parsed = JSON.parse(text) as unknown;
    switch (format) {
      case 'nvd':
        return parseNvd(parsed as NvdResponse);
      case 'ghsa':
        return parseGhsa(Array.isArray(parsed) ? (parsed as GhsaAdvisory[]) : [parsed as GhsaAdvisory]);
      case 'osv':
        return parseOsv(Array.isArray(parsed) ? (parsed as OsvEntry[]) : [parsed as OsvEntry]);
      case 'ndjson':
        return parseNdjson(text);
      default:
        return [];
    }
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function severityFromScore(score?: number): FeedRecord['severity'] {
  if (typeof score !== 'number') return 'medium';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

export function severityFromLabel(label?: string): FeedRecord['severity'] {
  switch ((label ?? '').toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'moderate':
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'medium';
  }
}

/**
 * Extract a numeric CVSS base score.
 *
 * Only a bare numeric score is returned. A CVSS vector string contains metrics
 * but no score, and computing the base score correctly requires the full
 * CVSS v3.1 specification. Rather than ship an approximation that silently
 * disagrees with the publisher, Aegis returns undefined and defers to the
 * advisory's own severity label.
 */
function numericFromCvss(vector: string): number | undefined {
  if (/^\d+(\.\d+)?$/.test(vector)) return Number(vector);
  return undefined;
}

function firstLine(text: string): string {
  return text.split('\n')[0]?.slice(0, 200) ?? '';
}

/** Deduplicate records, keeping the highest severity for a given id. */
export function dedupeRecords(records: readonly FeedRecord[]): FeedRecord[] {
  const byId = new Map<string, FeedRecord>();
  const order: Record<FeedRecord['severity'], number> = {
    critical: 0, high: 1, medium: 2, low: 3, info: 4,
  };
  for (const record of records) {
    const existing = byId.get(record.id);
    if (!existing) {
      byId.set(record.id, { ...record });
      continue;
    }
    // Merge both ways: whichever record wins on severity, the evidence from the
    // other must survive, or a later, lower-severity feed silently discards
    // references the first one supplied.
    const winner = order[record.severity] < order[existing.severity] ? record : existing;
    const loser = winner === record ? existing : record;
    byId.set(record.id, {
      ...winner,
      references: [...new Set([...winner.references, ...loser.references])],
      tags: [...new Set([...winner.tags, ...loser.tags])],
      cwes: [...new Set([...winner.cwes, ...loser.cwes])],
      agentRelevant: winner.agentRelevant || loser.agentRelevant,
      updated: winner.updated || loser.updated,
      ...(winner.package ?? loser.package ? { package: winner.package ?? loser.package } : {}),
    });
  }
  return [...byId.values()];
}