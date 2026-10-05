import type {
  DetectedFramework,
  Finding,
  ThreatAsset,
  ThreatModelDocument,
  ThreatModelDocument as ThreatModel,
  TrustBoundary,
} from '../../types.js';
import { FRAMEWORK_TRUST_MODEL } from './frameworks.js';

/**
 * Automated threat model generation.
 *
 * Threat modelling is where agent security is usually weakest: the codebase is
 * moving fast, the trust boundaries are implicit in the framework, and the
 * documentation rots immediately. Aegis derives the model from what is actually
 * in the code — frameworks, tools, data sources, sinks, and the findings it
 * produced — so the document stays true because it is regenerated, not because
 * someone maintains it.
 */

export interface ThreatModelInput {
  root: string;
  frameworks: readonly DetectedFramework[];
  findings: readonly Finding[];
  /** Files inspected, for asset enumeration. */
  files?: readonly { path: string; language: string }[];
  /** Tools discovered on the MCP side, if scanned. */
  mcpTools?: readonly string[];
  /** Date for the document header. */
  now?: Date;
}

const SENSITIVE_FILE_PATTERNS: Array<{ re: RegExp; type: ThreatAsset['type']; sensitivity: ThreatAsset['sensitivity']; desc: string }> = [
  { re: /\.(?:env|pem|key|p12|pfx|crt)$/i, type: 'credential', sensitivity: 'secret', desc: 'Credential or key material' },
  { re: /id_rsa|id_ed25519|authorized_keys/i, type: 'credential', sensitivity: 'secret', desc: 'SSH key material' },
  { re: /(?:^|\/)(?:secrets?|credentials?)(?:\.|\/|$)/i, type: 'credential', sensitivity: 'secret', desc: 'Credential store' },
  { re: /settings\.json$|claude_desktop_config\.json$|mcp\.json$/i, type: 'credential', sensitivity: 'confidential', desc: 'Agent/editor configuration, may carry tokens' },
  { re: /(?:^|\/)(?:users?|customers?|clients?|employees?|patients?|accounts?)(?:\.|\/|$)/i, type: 'data', sensitivity: 'confidential', desc: 'Personal or customer data' },
  { re: /\.(?:db|sqlite3?|sql)$/i, type: 'data', sensitivity: 'confidential', desc: 'Database artefact' },
  { re: /(?:^|\/)agents?\.(?:ts|js|py)$|(?:^|\/)agent[\w/]*\.py$/i, type: 'model', sensitivity: 'internal', desc: 'Agent definition' },
  { re: /prompts?[\w/]*\.(?:ts|js|py|md|txt)$/i, type: 'model', sensitivity: 'internal', desc: 'Prompt / instruction definition' },
];

const TRUST_BOUNDARY_TEMPLATES: Array<{ name: string; description: string }> = [
  {
    name: 'User → Agent',
    description:
      'The end user supplies input that reaches the agent. This is the primary untrusted input surface and the ' +
      'entry point for direct prompt injection.',
  },
  {
    name: 'Agent → Model Provider',
    description:
      'Prompts, tool definitions, and context leave the system boundary to an external inference provider. ' +
      'Data minimisation and provider terms become security controls here.',
  },
  {
    name: 'Agent → Tools',
    description:
      'The agent invokes tools with model-generated arguments. This is where a language-level vulnerability ' +
      'becomes a system-level one.',
  },
  {
    name: 'External Content → Agent Context',
    description:
      'Retrieved documents, web pages, API responses, and MCP resources enter the context window. Any party who ' +
      'can influence that content can influence the agent.',
  },
  {
    name: 'Agent → Filesystem / Network',
    description:
      'The agent reads and writes files and makes outbound requests. Egress here is exfiltration, and ' +
      'file reads are credential theft.',
  },
  {
    name: 'Agent → Agent',
    description:
      'Sub-agents, handoffs, and shared memory form a second trust boundary: output from one agent becomes ' +
      'input to the next.',
  },
];

export function generateThreatModel(input: ThreatModelInput): ThreatModelDocument {
  const now = input.now ?? new Date();
  const dateStamp = now.toISOString().slice(0, 10);

  const assets = collectAssets(input);
  const boundaries = collectBoundaries(input);
  const attackSurface = collectAttackSurface(input);

  const mermaid = renderMermaid(input.root, boundaries, assets, input.frameworks);
  const markdown = renderMarkdown({
    root: input.root,
    dateStamp,
    frameworks: input.frameworks,
    findings: input.findings,
    assets,
    boundaries,
    attackSurface,
    now,
  });

  return {
    title: `Threat Model — ${input.root}`,
    generatedAt: now.toISOString(),
    summary: buildSummary(input, boundaries, assets),
    mermaid,
    markdown,
    trustBoundaries: boundaries,
    assets,
    attackSurface,
  };
}

function collectAssets(input: ThreatModelInput): ThreatAsset[] {
  const assets = new Map<string, ThreatAsset>();

  for (const file of input.files ?? []) {
    for (const pattern of SENSITIVE_FILE_PATTERNS) {
      if (!pattern.re.test(file.path)) continue;
      const key = `${pattern.type}:${file.path}`;
      if (assets.has(key)) continue;
      assets.set(key, {
        name: file.path,
        type: pattern.type,
        description: pattern.desc,
        sensitivity: pattern.sensitivity,
      });
      break;
    }
  }

  // MCP tools are assets: each one is a capability the agent holds.
  for (const tool of input.mcpTools ?? []) {
    assets.set(`tool:${tool}`, {
      name: tool,
      type: 'tool',
      description: 'MCP tool capability exposed to the agent',
      sensitivity: 'internal',
    });
  }

  if (assets.size === 0) {
    assets.set('agent:model', {
      name: 'LLM inference',
      type: 'model',
      description: 'The language model backing the agent',
      sensitivity: 'internal',
    });
  }

  return [...assets.values()]
    .sort((a, b) => SENSITIVITY_RANK[b.sensitivity] - SENSITIVITY_RANK[a.sensitivity])
    .slice(0, 25);
}

const SENSITIVITY_RANK: Record<ThreatAsset['sensitivity'], number> = {
  secret: 4,
  confidential: 3,
  internal: 2,
  public: 1,
};

function collectBoundaries(input: ThreatModelInput): TrustBoundary[] {
  const wanted = new Set<string>(TRUST_BOUNDARY_TEMPLATES.map((t) => t.name));
  const extras: TrustBoundary[] = [];

  // Add framework-specific boundaries that actually apply.
  for (const framework of input.frameworks) {
    const model = FRAMEWORK_TRUST_MODEL[framework.id];
    if (!model) continue;
    for (const boundary of model.trustBoundaries) {
      const name = `Framework: ${boundary}`;
      if (wanted.has(name)) continue;
      wanted.add(name);
      extras.push({
        name,
        description:
          `${framework.name} introduces this boundary: ${boundary}. ` +
          `Primary risks: ${model.risks.join('; ')}.`,
        mermaidId: mermaidId(name),
      });
    }
  }

  const findingsTouch = (fragment: string): boolean =>
    input.findings.some((f) =>
      `${f.title} ${f.description} ${JSON.stringify(f.metadata ?? {})}`.toLowerCase().includes(fragment.toLowerCase()),
    );

  return [
    ...TRUST_BOUNDARY_TEMPLATES.filter((t) => {
      // Only include boundaries that the code or the findings actually touch.
      switch (t.name) {
        case 'External Content → Agent Context':
          return (
            findingsTouch('retriev') ||
            findingsTouch('indirect') ||
            findingsTouch('browse') ||
            input.frameworks.some((f) => ['langchain', 'llama-index', 'langgraph', 'mastra'].includes(f.id))
          );
        case 'Agent → Agent':
          return (
            findingsTouch('sub-agent') ||
            findingsTouch('handoff') ||
            input.frameworks.some((f) => ['crewai', 'autogen', 'openai-agents', 'langgraph'].includes(f.id))
          );
        case 'Agent → Filesystem / Network':
          return findingsTouch('filesystem') || findingsTouch('file') || findingsTouch('network') || findingsTouch('egress');
        default:
          return true;
      }
    }).map((t) => ({ ...t, mermaidId: mermaidId(t.name) })),
    ...extras,
  ];
}

function collectAttackSurface(input: ThreatModelInput): string[] {
  const surface = new Set<string>();
  const push = (v: string) => surface.add(v);

  for (const framework of input.frameworks) {
    push(`${framework.name} orchestration`);
    for (const risk of FRAMEWORK_TRUST_MODEL[framework.id]?.risks ?? []) {
      push(risk);
    }
  }

  for (const tool of input.mcpTools ?? []) push(`MCP tool: ${tool}`);

  for (const finding of input.findings) {
    for (const tag of finding.tags ?? []) {
      if (tag.length > 2) push(tag);
    }
  }

  return [...surface].slice(0, 30);
}

function buildSummary(input: ThreatModelInput, boundaries: TrustBoundary[], assets: ThreatAsset[]): string {
  const critical = input.findings.filter((f) => f.severity === 'critical').length;
  const high = input.findings.filter((f) => f.severity === 'high').length;
  const secrets = input.findings.filter((f) => f.ruleId === 'AEGIS-SECRET-001').length;
  const frameworkNames = input.frameworks.map((f) => f.name).join(', ') || 'no recognised agent framework';

  const topRisk = input.findings
    .slice()
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
    .slice(0, 3)
    .map((f) => f.title);

  return [
    `Scanned \`${input.root}\` and identified ${input.frameworks.length} agent framework(s): ${frameworkNames}.`,
    `${boundaries.length} trust boundaries and ${assets.length} sensitive assets were mapped.`,
    `Aegis raised ${input.findings.length} findings (${critical} critical, ${high} high)` +
      (secrets > 0 ? `, including ${secrets} hardcoded credential(s)` : '') + '.',
    topRisk.length > 0
      ? `The dominant risks are: ${topRisk.join('; ')}.`
      : 'No critical or high findings were raised.',
  ].join(' ');
}

function severityRank(severity: Finding['severity']): number {
  return ['critical', 'high', 'medium', 'low', 'info'].indexOf(severity);
}

function mermaidId(name: string): string {
  return `b_${name.replace(/[^A-Za-z0-9]+/g, '_')}`;
}

function renderMermaid(
  root: string,
  boundaries: TrustBoundary[],
  assets: ThreatAsset[],
  frameworks: readonly DetectedFramework[],
): string {
  const lines: string[] = ['```mermaid', 'flowchart TB'];

  lines.push('  subgraph T1["Untrusted"]');
  lines.push('    U["End user"]');
  lines.push('    X["External content<br/>docs, web, APIs"]');
  lines.push('    A2["Other agents"]');
  lines.push('  end');

  lines.push('  subgraph T2["Agent boundary"]');
  lines.push('    AG["Agent orchestrator"]');
  for (const framework of frameworks.slice(0, 3)) {
    lines.push(`    F_${mermaidId(framework.id)}["${framework.name}"]`);
    lines.push(`    AG --> F_${mermaidId(framework.id)}`);
  }
  lines.push('    SP["System prompt / policy"]');
  lines.push('    MEM[("Memory / vector store")]');
  lines.push('  end');

  lines.push('  subgraph T3["Execution"]');
  lines.push('    TL["Tools"]');
  lines.push('    SH["Shell / code exec"]');
  lines.push('    FS[("Filesystem")]');
  lines.push('    NET["Network egress"]');
  lines.push('  end');

  lines.push('  subgraph T4["Third party"]');
  lines.push('    MP["Model provider"]');
  lines.push('    MCP["MCP servers"]');
  lines.push('  end');

  lines.push('  U -->|"TB1: prompt injection"| AG');
  lines.push('  X -->|"TB2: indirect injection"| AG');
  lines.push('  A2 -->|"TB3: output laundering"| AG');
  lines.push('  AG <-->|"TB4: prompts + data"| MP');
  lines.push('  AG -->|"TB5: model-generated args"| TL');
  lines.push('  TL --> SH');
  lines.push('  TL --> FS');
  lines.push('  TL --> NET');
  lines.push('  MCP -->|"tools, resources"| AG');

  for (const asset of assets.filter((a) => a.sensitivity === 'secret').slice(0, 6)) {
    lines.push(`  SEC_${mermaidId(asset.name)}[("🔑 ${truncate(asset.name, 34)}")]`);
    lines.push(`  FS -.->|reachable| SEC_${mermaidId(asset.name)}`);
    lines.push(`  MEM -.->|reachable| SEC_${mermaidId(asset.name)}`);
  }

  lines.push('  classDef untrusted fill:#fee2e2,stroke:#dc2626,color:#7f1d1d;');
  lines.push('  classDef boundary fill:#dbeafe,stroke:#2563eb,color:#1e3a8a;');
  lines.push('  classDef exec fill:#fef3c7,stroke:#d97706,color:#78350f;');
  lines.push('  classDef third fill:#f1f5f9,stroke:#64748b,color:#334155;');
  lines.push('  classDef secret fill:#fce7f3,stroke:#db2777,color:#831843;');
  lines.push('  class U,X,A2 untrusted;');
  lines.push('  class AG,SP,MEM boundary;');
  lines.push('  class TL,SH,FS,NET exec;');
  lines.push('  class MP,MCP third;');
  lines.push('```');

  void root;
  void boundaries;
  return lines.join('\n');
}

function renderMarkdown(ctx: {
  root: string;
  dateStamp: string;
  frameworks: readonly DetectedFramework[];
  findings: readonly Finding[];
  assets: ThreatAsset[];
  boundaries: TrustBoundary[];
  attackSurface: string[];
  now: Date;
}): string {
  const { root, dateStamp, frameworks, findings, assets, boundaries, attackSurface } = ctx;
  const parts: string[] = [];

  parts.push(`# Threat Model: ${root}`);
  parts.push('');
  parts.push(`_Generated by Aegis on ${dateStamp}. This document is derived from the code as scanned; regenerate it after material changes._`);
  parts.push('');

  parts.push('## 1. System overview');
  parts.push('');
  if (frameworks.length > 0) {
    parts.push('| Framework | Version | Confidence | Files | Evidence |');
    parts.push('| --- | --- | --- | --- | --- |');
    for (const f of frameworks) {
      parts.push(
        `| ${f.name} | ${f.version ?? 'unknown'} | ${f.confidence} | ${f.fileCount} | ${f.evidence[0] ?? '—'} |`,
      );
    }
  } else {
    parts.push(
      'No recognised agent framework was detected. Aegis analysed the code as a general-purpose application ' +
        'that makes model calls; confirm the agent entry point so the threat model covers the real trust boundaries.',
    );
  }
  parts.push('');

  parts.push('## 2. Trust boundaries');
  parts.push('');
  for (const boundary of boundaries) {
    parts.push(`### ${boundary.name}`);
    parts.push('');
    parts.push(boundary.description);
    parts.push('');
  }

  parts.push('## 3. Assets');
  parts.push('');
  parts.push('| Asset | Type | Sensitivity | Notes |');
  parts.push('| --- | --- | --- | --- |');
  for (const asset of assets) {
    parts.push(`| \`${asset.name}\` | ${asset.type} | ${asset.sensitivity} | ${asset.description} |`);
  }
  parts.push('');

  parts.push('## 4. Attack surface');
  parts.push('');
  for (const item of attackSurface) parts.push(`- ${item}`);
  parts.push('');

  parts.push('## 5. Diagram');
  parts.push('');
  parts.push(renderMermaid(root, boundaries, assets, frameworks));
  parts.push('');

  parts.push('## 6. Findings mapped to the model');
  parts.push('');
  parts.push('| Severity | Finding | Taxonomy | Location |');
  parts.push('| --- | --- | --- | --- |');
  for (const finding of findings.slice(0, 50)) {
    const loc = finding.location.file
      ? `${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ''}`
      : (finding.location.component ?? '—');
    parts.push(
      `| ${finding.severity} | ${escapePipes(finding.title)} | ${finding.taxonomy ?? '—'} | \`${loc}\` |`,
    );
  }
  if (findings.length > 50) parts.push('');
  if (findings.length > 50) parts.push(`_…and ${findings.length - 50} more._`);
  parts.push('');

  parts.push('## 7. Recommended next steps');
  parts.push('');
  const criticals = findings.filter((f) => f.severity === 'critical');
  const step = (n: number, text: string) => parts.push(`${n}. ${text}`);
  let n = 1;
  if (criticals.length > 0) {
    step(n++, `Resolve the ${criticals.length} critical finding(s) first: ${escapePipes(criticals.slice(0, 3).map((f) => f.title).join('; '))}.`);
  }
  step(
    n++,
    'Adopt instruction/data separation in every prompt that touches untrusted content, and re-assert the ' +
      'system prompt after each untrusted block.',
  );
  step(
    n++,
    'Give the agent an explicit tool allowlist and require human approval for irreversible actions (payments, ' +
      'deletions, outbound messages, deploys).',
  );
  step(
    n++,
    'Constrain egress through a logging proxy that rejects private, link-local, and cloud-metadata ranges.',
  );
  step(
    n++,
    'Rotate any credential identified by this scan and load secrets from a secret manager.',
  );
  step(n++, 'Run `aegis redteam` against the deployed agent to validate that the fixes hold under attack.');

  return parts.join('\n');
}

function truncate(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}

function escapePipes(value: string): string {
  return value.replace(/\|/g, '\\|');
}