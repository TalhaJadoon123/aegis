import { addEdge, addNode, createGraph, type AttackGraph, type Provenance } from './graph.js';

/**
 * The seed attack graph.
 *
 * This is the knowledge Aegis ships with: the attack techniques that actually
 * apply to AI agents, expressed as a graph so the relationships are queryable
 * rather than prose. It is designed to be extended, not replaced — every node
 * carries provenance so a community addition is visibly distinct from a
 * vendor-confirmed one.
 */

export interface SeedTechnique {
  id: string;
  label: string;
  description: string;
  kind: 'technique' | 'vulnerability' | 'tool' | 'control' | 'cve' | 'agent' | 'supply-chain';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  references?: string[];
  tags?: string[];
  /** Node ids this enables. */
  enables?: string[];
  /** Control node ids that mitigate this. */
  mitigatedBy?: string[];
  requires?: string[];
}

export const SEED_ATTACKS: SeedTechnique[] = [
  // --- Entry points -------------------------------------------------------
  {
    id: 'prompt-injection',
    label: 'Prompt injection',
    description:
      'Untrusted content is concatenated into the model context so that it is read as an instruction rather than as data.',
    kind: 'technique', severity: 'high', references: ['AML.T0051', 'ASI01'], tags: ['owasp'],
    enables: ['instruction-override', 'tool-poisoning-execution'],
    mitigatedBy: ['instruction-data-separation'],
  },
  {
    id: 'indirect-injection',
    label: 'Indirect prompt injection',
    description:
      'Injection delivered through content the agent retrieves — a web page, a document, a code comment, a tool result — rather than from the user.',
    kind: 'technique', severity: 'high', references: ['AML.T0051', 'ASI01'], tags: ['rag'],
    requires: ['retrieval-access'],
    enables: ['instruction-override'],
    mitigatedBy: ['instruction-data-separation'],
  },
  {
    id: 'retrieval-access',
    label: 'Agent retrieval or browsing capability',
    description: 'The agent can fetch arbitrary documents or URLs into its context.',
    kind: 'tool', severity: 'medium', references: ['ASI02'],
  },
  {
    id: 'tool-poisoning',
    label: 'Tool poisoning',
    description:
      'A malicious MCP server hides model-directed instructions in a tool description, which is inserted into context verbatim.',
    kind: 'technique', severity: 'critical', references: ['ASI01', 'AML.T0051'], tags: ['mcp'],
    enables: ['instruction-override', 'credential-exfiltration'],
    mitigatedBy: ['mcp-server-vetting'],
  },
  {
    id: 'mcp-server-vetting',
    label: 'MCP server vetting',
    description: 'Reviewing an MCP server before granting an agent access to it.',
    kind: 'control', severity: 'high', references: ['ASI04'],
  },

  // --- Instruction manipulation -------------------------------------------
  {
    id: 'instruction-override',
    label: 'Instruction override',
    description:
      'The attacker displaces the agent’s original objective with a new one. The agent now serves the attacker.',
    kind: 'technique', severity: 'critical', references: ['ASI01'],
    enables: ['excessive-agency', 'credential-exfiltration', 'data-exfiltration'],
    mitigatedBy: ['instruction-data-separation', 'human-approval-gate'],
  },
  {
    id: 'instruction-data-separation',
    label: 'Instruction/data separation',
    description:
      'Untrusted content is fenced and explicitly labelled as data; the instruction tier is unreachable from user content.',
    kind: 'control', severity: 'high', references: ['ASI01', 'EU-AI-ACT-15'],
  },
  {
    id: 'jailbreak',
    label: 'Jailbreak',
    description: 'Safety behaviour is bypassed through framing, persona assignment, or filter evasion.',
    kind: 'technique', severity: 'high', references: ['AML.T0054', 'ASI09'],
    mitigatedBy: ['capability-restriction'],
  },
  {
    id: 'excessive-agency',
    label: 'Excessive agency',
    description:
      'The agent holds more capability, autonomy, or blast radius than its task requires.',
    kind: 'vulnerability', severity: 'high', references: ['ASI02', 'ASI06'],
    enables: ['credential-exfiltration', 'lateral-movement', 'cascading-failure'],
    mitigatedBy: ['least-privilege-tools', 'human-approval-gate'],
  },
  {
    id: 'least-privilege-tools',
    label: 'Least-privilege tool set',
    description: 'The agent is granted only the tools and scopes its task requires.',
    kind: 'control', severity: 'high', references: ['ASI02'],
  },
  {
    id: 'human-approval-gate',
    label: 'Human approval gate',
    description: 'Irreversible or high-impact actions require explicit human confirmation.',
    kind: 'control', severity: 'high', references: ['ASI09', 'EU-AI-ACT-14'],
  },

  // --- Execution and exfiltration ----------------------------------------
  {
    id: 'credential-exfiltration',
    label: 'Credential exfiltration',
    description:
      'Secrets reachable from the agent context or its host are read and sent to an attacker-controlled destination.',
    kind: 'technique', severity: 'critical', references: ['ASI02', 'ASI03'],
    enables: ['account-takeover'],
    mitigatedBy: ['secret-isolation'],
  },
  {
    id: 'secret-isolation',
    label: 'Secret isolation',
    description: 'Secrets never enter the prompt context; the agent acts via an opaque handle.',
    kind: 'control', severity: 'critical', references: ['ASI02'],
  },
  {
    id: 'account-takeover',
    label: 'Account takeover',
    description: 'Stolen credentials are used to act as the user or the service outside the agent.',
    kind: 'technique', severity: 'critical', references: ['ASI03'],
  },
  {
    id: 'data-exfiltration',
    label: 'Data exfiltration',
    description: 'Personal, customer, or business data leaves the trust boundary via the agent.',
    kind: 'technique', severity: 'critical', references: ['ASI02', 'GDPR-32'],
    enables: ['breach-notification'],
    mitigatedBy: ['egress-allowlist', 'data-minimisation'],
  },
  {
    id: 'egress-allowlist',
    label: 'Egress allowlist',
    description: 'Outbound requests are constrained to named destinations through a logging proxy.',
    kind: 'control', severity: 'high', references: ['ASI02'],
  },
  {
    id: 'data-minimisation',
    label: 'Data minimisation',
    description: 'Only the fields the task requires are placed in the prompt context.',
    kind: 'control', severity: 'high', references: ['GDPR-5', 'GDPR-25'],
  },
  {
    id: 'breach-notification',
    label: 'Regulatory breach notification',
    description: 'A personal-data breach triggers the notification obligations of GDPR Art. 33/34.',
    kind: 'technique', severity: 'critical', references: ['GDPR-34'],
  },
  {
    id: 'tool-poisoning-execution',
    label: 'Poisoned tool invocation',
    description: 'The agent invokes a poisoned tool believing it is a normal part of its task.',
    kind: 'technique', severity: 'critical', references: ['ASI01'],
    enables: ['credential-exfiltration'],
  },
  {
    id: 'ssrf',
    label: 'Server-side request forgery',
    description:
      'The agent is induced to make a request to an internal service or cloud metadata endpoint.',
    kind: 'vulnerability', severity: 'critical', references: ['ASI02'],
    enables: ['credential-exfiltration'],
    mitigatedBy: ['egress-allowlist'],
  },
  {
    id: 'path-traversal',
    label: 'Path traversal to credential files',
    description: 'A file tool is directed at `../../.ssh/id_rsa` or equivalent.',
    kind: 'vulnerability', severity: 'critical', references: ['ASI02'],
    enables: ['credential-exfiltration'],
    mitigatedBy: ['path-confinement'],
  },
  {
    id: 'path-confinement',
    label: 'Path confinement',
    description: 'File access is resolved and asserted to be inside an allowlisted root.',
    kind: 'control', severity: 'critical', references: ['ASI02'],
  },
  {
    id: 'untrusted-dependency',
    label: 'Untrusted dependency or plugin',
    description:
      'A model, plugin, or package reachable by the agent executes code without integrity verification.',
    kind: 'supply-chain', severity: 'high', references: ['ASI04'],
    enables: ['tool-poisoning', 'lateral-movement'],
    mitigatedBy: ['mcp-server-vetting'],
  },

  // --- Impact -------------------------------------------------------------
  {
    id: 'lateral-movement',
    label: 'Lateral movement',
    description: 'The compromised agent reaches systems beyond its intended scope.',
    kind: 'technique', severity: 'high', references: ['ASI02', 'ASI10'],
  },
  {
    id: 'cascading-failure',
    label: 'Cascading failure',
    description: 'An unbounded loop or resource exhaustion takes the service down.',
    kind: 'technique', severity: 'medium', references: ['ASI08'],
    mitigatedBy: ['resource-bounding'],
  },
  {
    id: 'resource-bounding',
    label: 'Resource bounding',
    description: 'Iteration ceilings, token budgets, and wall-clock deadlines on every agent run.',
    kind: 'control', severity: 'medium', references: ['ASI08'],
  },
  {
    id: 'capability-restriction',
    label: 'Capability restriction',
    description:
      'Security enforced by what the agent can do, rather than by what it is asked not to do.',
    kind: 'control', severity: 'high', references: ['ASI02'],
  },
  {
    id: 'memory-poisoning',
    label: 'Memory poisoning',
    description:
      'Persistent manipulation of the agent’s memory or retrieval store, re-injected on every later turn.',
    kind: 'technique', severity: 'high', references: ['ASI06'],
    enables: ['instruction-override'],
  },
];

/** Build the seed graph. */
export function seedGraph(techniques: readonly SeedTechnique[] = SEED_ATTACKS): AttackGraph {
  const graph = createGraph('seed-1.0.0');
  const prov: Provenance = {
    kind: 'seed',
    source: 'aegis/seed-graph',
    observedAt: '2026-01-01T00:00:00.000Z',
    hash: 'aegis-seed',
  };

  const byLabel = new Map<string, string>();
  for (const technique of techniques) byLabel.set(technique.id, technique.id);

  for (const technique of techniques) {
    addNode(graph, {
      kind: technique.kind,
      label: technique.id,
      description: technique.description,
      severity: technique.severity,
      confidence: technique.kind === 'cve' ? 'confirmed' : 'high',
      references: technique.references ?? [],
      tags: technique.tags ?? [],
      provenance: prov,
    });
  }

  for (const technique of techniques) {
    for (const target of technique.enables ?? []) link(graph, technique.id, target, 'enables', prov);
    for (const target of technique.mitigatedBy ?? []) link(graph, target, technique.id, 'mitigates', prov);
    for (const target of technique.requires ?? []) link(graph, technique.id, target, 'requires', prov);
  }

  return graph;
}

function link(graph: AttackGraph, source: string, target: string, kind: 'enables' | 'mitigates' | 'requires', prov: Provenance): void {
  const sourceId = [...graph.nodes.values()].find((n) => n.label === source)?.id;
  const targetId = [...graph.nodes.values()].find((n) => n.label === target)?.id;
  if (!sourceId || !targetId) return;
  addEdge(graph, {
    source: sourceId,
    target: targetId,
    kind,
    weight: 0.8,
    provenance: prov,
    unverified: false,
  });
}