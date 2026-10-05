import { aggregateCompliance, compareSeverity, sortFindings } from './severity.js';
import { toMarkdown, toHtml, rollUpCompliance, type AegisDocument } from './output.js';
import type {
  ComplianceFramework,
  ComplianceMapping,
  Finding,
  Severity,
} from './types.js';

/**
 * Compliance mapping and attestation.
 *
 * This is the artefact an enterprise actually buys. A security finding is
 * interesting; a finding that proves a specific control failed, with the
 * control text attached, is what gets signed off by an auditor.
 *
 * The design rule throughout: Aegis never asserts that a control *passes*. It
 * only reports that findings intersect a control, and that an auditor can read
 * the control text and the evidence side by side. A scanner that claims
 * compliance is worse than no scanner, because people act on the claim.
 */

export interface ControlDefinition {
  id: string;
  framework: ComplianceFramework;
  title: string;
  /** Verbatim control text, trimmed to what is useful in a report. */
  text: string;
  /** Which OWASP Agentic category this control is usually reached through. */
  relatedTaxonomy?: string;
  /** Severity of a finding that indicates this control is not satisfied. */
  failureSeverity?: Severity;
  /** What an auditor will want to see to close this out. */
  evidenceExpected: string;
}

export const FRAMEWORKS: Record<ComplianceFramework, { name: string; version: string; url: string }> = {
  'owasp-agentic': {
    name: 'OWASP Agentic Security Initiative Top 10',
    version: '2025',
    url: 'https://genai.owasp.org/',
  },
  'owasp-llm': {
    name: 'OWASP Top 10 for LLM Applications',
    version: '2025',
    url: 'https://genai.owasp.org/llm-top-10/',
  },
  soc2: {
    name: 'AICPA SOC 2 Trust Services Criteria',
    version: '2017 (rev. 2022)',
    url: 'https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services',
  },
  iso27001: {
    name: 'ISO/IEC 27001 Annex A',
    version: '2022',
    url: 'https://www.iso.org/standard/27001',
  },
  gdpr: {
    name: 'EU General Data Protection Regulation',
    version: '2016/679',
    url: 'https://eur-lex.europa.eu/eli/reg/2016/679/oj',
  },
  'eu-ai-act': {
    name: 'EU Artificial Intelligence Act',
    version: 'Regulation (EU) 2024/1689',
    url: 'https://eur-lex.europa.eu/eli/reg/2024/1689/oj',
  },
  'nist-ai-rmf': {
    name: 'NIST AI Risk Management Framework',
    version: '1.0',
    url: 'https://www.nist.gov/itl/ai-risk-management-framework',
  },
  'mitre-atlas': {
    name: 'MITRE ATLAS',
    version: '4.9',
    url: 'https://atlas.mitre.org/',
  },
};

/**
 * The control catalogue.
 *
 * Deliberately conservative: a control is listed only where Aegis can produce
 * concrete evidence about it. Mapping a finding to a control it does not
 * actually evidence is how a scanner loses an audit.
 */
export const CONTROLS: ControlDefinition[] = [
  // --- SOC 2 ---------------------------------------------------------------
  {
    id: 'CC6.1', framework: 'soc2', title: 'Logical access security measures',
    text: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets.',
    evidenceExpected: 'Access control configuration, role definitions, and evidence that privileges are least-privilege.',
  },
  {
    id: 'CC6.6', framework: 'soc2', title: 'Boundary protection',
    text: 'The entity implements logical access security measures to protect against threats from outside its system boundaries.',
    evidenceExpected: 'Network controls, egress policy, and boundary protection configuration.',
  },
  {
    id: 'CC6.7', framework: 'soc2', title: 'Restriction of information transmission',
    text: 'The entity restricts the transmission, movement, and removal of information to authorised internal and external users.',
    evidenceExpected: 'Encryption in transit, data-loss-prevention configuration, and transmission logs.',
  },
  {
    id: 'CC7.1', framework: 'soc2', title: 'Detection of new vulnerabilities',
    text: 'The entity selects and develops ongoing activities to obtain evidence of new and emerging vulnerabilities.',
    evidenceExpected: 'Continuous scanning, vulnerability management records, and patch cadence.',
  },
  {
    id: 'CC7.2', framework: 'soc2', title: 'Monitoring for anomalies',
    text: 'The entity monitors system components and the operation of those components for anomalies indicative of malicious acts, natural disasters, and errors affecting its ability to meet its objectives.',
    evidenceExpected: 'Runtime monitoring, anomaly detection output, and alerting configuration.',
  },
  {
    id: 'CC7.3', framework: 'soc2', title: 'Evaluation of security events',
    text: 'The entity evaluates security events to determine whether they could or have resulted in a failure and, if so, takes action.',
    evidenceExpected: 'Incident runbooks, triage records, and post-incident reviews.',
  },

  // --- ISO 27001:2022 Annex A --------------------------------------------
  {
    id: 'A.5.15', framework: 'iso27001', title: 'Access control',
    text: 'Rules to control physical and logical access to information shall be established and implemented based on business and information security requirements.',
    evidenceExpected: 'Access control policy, permissioning rules, and review evidence.',
  },
  {
    id: 'A.5.17', framework: 'iso27001', title: 'Authentication information',
    text: 'Allocation and management of authentication information shall be controlled by a management process, including advising personnel on appropriate handling.',
    evidenceExpected: 'Secret management configuration and evidence that credentials are not in source.',
  },
  {
    id: 'A.8.3', framework: 'iso27001', title: 'Information access restriction',
    text: 'Access to information and other associated assets shall be restricted in accordance with the established topic-specific policy on access control.',
    evidenceExpected: 'Per-tool and per-agent permission configuration.',
  },
  {
    id: 'A.8.6', framework: 'iso27001', title: 'Capacity management',
    text: 'The use of resources shall be managed and adjusted to ensure the capacity of systems is adequate.',
    evidenceExpected: 'Resource limits, rate limits, and budget ceilings.',
  },
  {
    id: 'A.8.8', framework: 'iso27001', title: 'Management of technical vulnerabilities',
    text: 'Information about technical vulnerabilities of information systems in use shall be obtained, the system’s exposure to such vulnerabilities shall be evaluated and appropriate measures shall be taken.',
    evidenceExpected: 'Dependency inventories, pinning, and vulnerability scanning records.',
  },
  {
    id: 'A.8.15', framework: 'iso27001', title: 'Logging',
    text: 'Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.',
    evidenceExpected: 'Audit log configuration and retention policy.',
  },
  {
    id: 'A.8.19', framework: 'iso27001', title: 'Installation of software on operational systems',
    text: 'Procedures and measures shall be implemented to securely manage software installation on operational systems.',
    evidenceExpected: 'Install-time script policy and approved-software inventory.',
  },
  {
    id: 'A.8.20', framework: 'iso27001', title: 'Networks security',
    text: 'Networks and network devices shall be secured, managed and controlled to protect information in systems and applications.',
    evidenceExpected: 'Network segmentation, egress policy, and transport security.',
  },
  {
    id: 'A.8.26', framework: 'iso27001', title: 'Application security requirements',
    text: 'Information security requirements shall be identified, specified and approved when developing or acquiring applications.',
    evidenceExpected: 'Security requirements in the SDLC and secure-by-default agent configuration.',
  },
  {
    id: 'A.8.28', framework: 'iso27001', title: 'Secure coding',
    text: 'Secure coding principles shall be applied to software development.',
    evidenceExpected: 'Static analysis results and secure coding standards.',
  },

  // --- GDPR ---------------------------------------------------------------
  {
    id: 'Art. 5', framework: 'gdpr', title: 'Principles relating to processing of personal data',
    text: 'Personal data must be processed lawfully, fairly and transparently; adequate, relevant and limited to what is necessary; and accurate.',
    evidenceExpected: 'Data-minimisation controls and evidence that personal data is not over-collected into prompts.',
  },
  {
    id: 'Art. 25', framework: 'gdpr', title: 'Data protection by design and by default',
    text: 'Data protection measures shall be designed and implemented taking into account data protection principles.',
    evidenceExpected: 'Design documentation showing privacy was considered, not retrofitted.',
  },
  {
    id: 'Art. 30', framework: 'gdpr', title: 'Records of processing activities',
    text: 'Controllers shall maintain a record of processing activities under their responsibility.',
    evidenceExpected: 'Record of processing activities, updated as agents change.',
  },
  {
    id: 'Art. 32', framework: 'gdpr', title: 'Security of processing',
    text: 'Appropriate technical and organisational measures must be implemented to ensure a level of security appropriate to the risk.',
    evidenceExpected: 'Technical controls protecting personal data in transit and at rest.',
  },
  {
    id: 'Art. 35', framework: 'gdpr', title: 'Data protection impact assessment',
    text: 'A data protection impact assessment shall be carried out where processing is likely to result in a high risk to rights and freedoms.',
    evidenceExpected: 'A completed DPIA covering automated decision-making and profiling.',
  },

  // --- EU AI Act ----------------------------------------------------------
  {
    id: 'Art. 9', framework: 'eu-ai-act', title: 'Risk management system',
    text: 'A continuous, iterative risk management system shall be maintained for high-risk AI systems throughout their lifetime.',
    evidenceExpected: 'Documented risk management covering cybersecurity of the AI system.',
  },
  {
    id: 'Art. 10', framework: 'eu-ai-act', title: 'Data and data governance',
    text: 'Training, validation and testing data sets shall be relevant, sufficiently representative, and to the best extent possible free of errors.',
    evidenceExpected: 'Data provenance and quality documentation for the agent’s inputs.',
  },
  {
    id: 'Art. 12', framework: 'eu-ai-act', title: 'Record-keeping',
    text: 'High-risk AI systems shall automatically record events over their lifetime to a degree that enables traceability.',
    evidenceExpected: 'Logging configuration and retention.',
  },
  {
    id: 'Art. 13', framework: 'eu-ai-act', title: 'Transparency and provision of information to deployers',
    text: 'Providers shall ensure high-risk AI systems are accompanied by information enabling deployers to interpret output and use it appropriately.',
    evidenceExpected: 'Documentation of model limitations and output interpretation.',
  },
  {
    id: 'Art. 14', framework: 'eu-ai-act', title: 'Human oversight',
    text: 'High-risk AI systems shall be designed so they can effectively be overseen by natural persons during the period of use.',
    evidenceExpected: 'Evidence a human can meaningfully intervene, override, or stop the system.',
  },
  {
    id: 'Art. 15', framework: 'eu-ai-act', title: 'Accuracy, robustness and cybersecurity',
    text: 'High-risk AI systems shall achieve an appropriate level of accuracy, robustness, and cybersecurity.',
    evidenceExpected: 'Prompt-injection and jailbreak resistance results, including red-team outcomes.',
    relatedTaxonomy: 'ASI01',
    failureSeverity: 'critical',
  },

  // --- NIST AI RMF -------------------------------------------------------
  {
    id: 'GOVERN 1.2', framework: 'nist-ai-rmf', title: 'Legal and regulatory requirements are understood and managed',
    text: 'Legal and regulatory requirements related to AI are understood, managed and documented.',
    evidenceExpected: 'Documented legal review of the agent’s deployment context.',
  },
  {
    id: 'GOVERN 4.1', framework: 'nist-ai-rmf', title: 'Accountability structures are in place',
    text: 'Policies and procedures exist to define roles and responsibilities for human-AI configurations and oversight.',
    evidenceExpected: 'Named owners for each agent, and documented escalation paths.',
  },
  {
    id: 'MAP 5.1', framework: 'nist-ai-rmf', title: 'Impacts are identified',
    text: 'The organization identifies and documents AI system impacts, including supply-chain and third-party risks.',
    evidenceExpected: 'Inventory of agents, frameworks, model providers and MCP servers in use.',
  },
  {
    id: 'MEASURE 2.7', framework: 'nist-ai-rmf', title: 'AI system security and resilience are evaluated',
    text: 'The organization evaluates the security and resilience of AI systems, including against adversarial attack.',
    evidenceExpected: 'Red-team results and prompt-injection resistance testing.',
  },
  {
    id: 'MANAGE 2.2', framework: 'nist-ai-rmf', title: 'Mechanism to sustain the value of deployed AI systems',
    text: 'The organization manages the risk of AI system changes over time, including mechanisms for deprecation and rollback.',
    evidenceExpected: 'Change management, rollback paths, and pinning of models and tools.',
  },

  // --- MITRE ATLAS -------------------------------------------------------
  {
    id: 'AML.T0051', framework: 'mitre-atlas', title: 'LLM Prompt Injection',
    text: 'An adversary causes the LLM to produce unintended output by manipulating the prompt.',
    evidenceExpected: 'Red-team transcripts showing injection attempts and whether they succeeded.',
  },
  {
    id: 'AML.T0054', framework: 'mitre-atlas', title: 'LLM Jailbreak',
    text: 'An adversary manipulates the input to bypass the LLM’s safety and content restrictions.',
    evidenceExpected: 'Jailbreak resistance testing results.',
  },
  {
    id: 'AML.T0050', framework: 'mitre-atlas', title: 'Exploitation for AI System Compromise',
    text: 'An adversary exploits the AI system’s underlying software or hardware to compromise its integrity or availability.',
    evidenceExpected: 'Tool and code-execution findings with reachability analysis.',
  },
];

const CONTROL_BY_KEY = new Map<string, ControlDefinition>(
  CONTROLS.map((c) => [`${c.framework}:${c.id}`, c]),
);

export function getControl(framework: ComplianceFramework, id: string): ControlDefinition | undefined {
  return CONTROL_BY_KEY.get(`${framework}:${id}`);
}

// ---------------------------------------------------------------------------
// Assessment
// ---------------------------------------------------------------------------

export type ControlStatus = 'fail' | 'risk' | 'no-findings' | 'not-assessed';

export interface ControlAssessment {
  control: ControlDefinition;
  status: ControlStatus;
  /** Findings that intersect this control. */
  findings: Finding[];
  worstSeverity: Severity;
  /** What Aegis did and did not observe. */
  assessment: string;
  evidenceExpected: string;
  /** True when the findings are strong enough to assert non-compliance. */
  actionable: boolean;
}

export interface ComplianceReport {
  generatedAt: string;
  scope: { type: string; path?: string; url?: string };
  frameworks: Array<{ framework: ComplianceFramework; name: string; version: string; url: string }>;
  assessments: ControlAssessment[];
  summary: ComplianceSummary;
  /** Explicitly stated limitations, so the report is not over-read. */
  limitations: string[];
}

export interface ComplianceSummary {
  controlsAssessed: number;
  controlsFailed: number;
  controlsAtRisk: number;
  controlsClear: number;
  /** Findings by framework. */
  byFramework: Record<string, number>;
  /** The single most urgent thing an auditor will ask about. */
  headline: string;
  /** Overall posture for the dashboard. */
  posture: 'critical' | 'poor' | 'fair' | 'good';
}

/**
 * Assess controls against a finding set.
 *
 * Two deliberate choices:
 *
 *  - `no-findings` is **not** `pass`. Aegis did not look, or looked and found
 *    nothing; only an auditor can attest a control operates effectively.
 *  - `not-assessed` is emitted for controls Aegis cannot evaluate, so an
 *    incomplete assessment is visible rather than implied by absence.
 */
export function assessCompliance(
  findings: readonly Finding[],
  options: { frameworks?: ComplianceFramework[]; scope?: ComplianceReport['scope'] } = {},
): ComplianceReport {
  const frameworks = options.frameworks ?? [
    'soc2', 'iso27001', 'gdpr', 'eu-ai-act', 'nist-ai-rmf', 'owasp-agentic',
  ];
  const relevant = frameworks.includes('owasp-agentic')
    ? [...CONTROLS, ...owaspControls()]
    : CONTROLS;

  const byControl = new Map<string, Finding[]>();
  for (const finding of findings) {
    for (const mapping of finding.compliance) {
      const key = `${mapping.framework}:${mapping.control}`;
      byControl.set(key, [...(byControl.get(key) ?? []), finding]);
    }
  }

  const assessments: ControlAssessment[] = relevant
    .filter((control) => frameworks.includes(control.framework))
    .map((control) => {
      const controlFindings = sortFindings(byControl.get(`${control.framework}:${control.id}`) ?? []);
      const worst = controlFindings.reduce<Severity>(
        (acc, f) => (compareSeverity(f.severity, acc) < 0 ? f.severity : acc),
        'info',
      );
      const critical = controlFindings.some((f) => f.severity === 'critical');
      const relevantCount = controlFindings.filter((f) => f.compliance.some(
        (m) => m.framework === control.framework && m.control === control.id && m.relevant,
      )).length;

      let status: ControlStatus;
      if (controlFindings.length === 0) status = 'no-findings';
      else if (critical) status = 'fail';
      else if (relevantCount > 0) status = 'risk';
      else status = 'risk';

      const assessment =
        controlFindings.length === 0
          ? `No findings intersected this control. Aegis did not evaluate the operational or organisational aspects of the control, so this is not an attestation that it operates effectively.`
          : `${controlFindings.length} finding(s) intersected this control, worst severity ${worst}. ` +
            `${relevantCount} of them map to it as directly relevant rather than tangentially. ` +
            (status === 'fail'
              ? 'At least one critical finding indicates this control is not operating effectively.'
              : 'Remediate the listed findings and re-run to reassess.');

      return {
        control,
        status,
        findings: controlFindings,
        worstSeverity: worst,
        assessment,
        evidenceExpected: control.evidenceExpected,
        actionable: relevantCount > 0,
      };
    });

  const failed = assessments.filter((a) => a.status === 'fail');
  const atRisk = assessments.filter((a) => a.status === 'risk');
  const clear = assessments.filter((a) => a.status === 'no-findings');

  const byFramework: Record<string, number> = {};
  for (const mapping of aggregateCompliance(findings)) {
    byFramework[mapping.control.framework] =
      (byFramework[mapping.control.framework] ?? 0) + mapping.findings;
  }

  const posture = failed.length > 0 ? 'critical' : atRisk.length > 2 ? 'poor' : atRisk.length > 0 ? 'fair' : 'good';

  return {
    generatedAt: new Date().toISOString(),
    scope: options.scope ?? { type: 'unknown' },
    frameworks: frameworks.map((f) => ({ framework: f, ...FRAMEWORKS[f] })),
    assessments,
    summary: {
      controlsAssessed: assessments.length,
      controlsFailed: failed.length,
      controlsAtRisk: atRisk.length,
      controlsClear: clear.length,
      byFramework,
      headline: failed.length
        ? `${failed.length} control(s) are indicated as not operating effectively, beginning with ${failed[0]!.control.framework.toUpperCase()} ${failed[0]!.control.id} (${failed[0]!.control.title}).`
        : atRisk.length
          ? `No control indicated a critical failure; ${atRisk.length} control(s) carry findings that need review.`
          : 'No findings intersected the assessed controls. This is not an attestation of compliance.',
      posture,
    },
    limitations: [
      'Aegis assesses technical control evidence only. It does not evaluate the organisational, procedural, or physical safeguards that most frameworks also require.',
      'A "no findings" status means Aegis found nothing. It does not mean the control operates effectively; only an auditor can attest that.',
      'Findings are correlated to controls by taxonomy mapping, not by reading the control text. A mapping may over- or under-state relevance.',
      'This output is decision support, not certification. It must not be presented as an attestation of compliance.',
    ],
  };
}

/** OWASP Agentic categories, surfaced as controls for the dashboard. */
function owaspControls(): ControlDefinition[] {
  return [
    {
      id: 'ASI01', framework: 'owasp-agentic', title: 'Agent Goal Hijacking',
      text: 'An attacker manipulates the agent’s objectives or instructions so it performs unintended actions.',
      evidenceExpected: 'Prompt-injection resistance testing and instruction/data separation in prompts.',
      failureSeverity: 'high',
    },
    {
      id: 'ASI02', framework: 'owasp-agentic', title: 'Tool Misuse and Exploitation',
      text: 'Agents misuse tools or are manipulated into invoking them outside their intended scope.',
      evidenceExpected: 'Tool allowlists, argument validation, and per-tool permissioning.',
      failureSeverity: 'critical',
    },
    {
      id: 'ASI03', framework: 'owasp-agentic', title: 'Identity and Privilege Abuse',
      text: 'An adversary abuses the agent’s identity or privileges to access resources beyond its intended authority.',
      evidenceExpected: 'Scoped credentials and per-user delegation.',
      failureSeverity: 'critical',
    },
    {
      id: 'ASI04', framework: 'owasp-agentic', title: 'Agentic Supply Chain Vulnerabilities',
      text: 'Compromise of models, tools, plugins or dependencies reachable by the agent.',
      evidenceExpected: 'Pinned versions, integrity checks, and a current inventory of reachable components.',
      failureSeverity: 'high',
    },
    {
      id: 'ASI05', framework: 'owasp-agentic', title: 'Unexpected Code Execution',
      text: 'The agent executes code it did not author, including model-generated code.',
      evidenceExpected: 'Sandboxing, approval gates, and code-generation controls.',
      failureSeverity: 'critical',
    },
    {
      id: 'ASI06', framework: 'owasp-agentic', title: 'Memory and Context Poisoning',
      text: 'Persistent manipulation of an agent’s context, memory, or retrieval store.',
      evidenceExpected: 'Provenance on memory writes and sanitisation of retrieved content.',
      failureSeverity: 'high',
    },
    {
      id: 'ASI07', framework: 'owasp-agentic', title: 'Insecure Inter-Agent Communication',
      text: 'Agent-to-agent or agent-to-tool communication that can be intercepted, spoofed or injected.',
      evidenceExpected: 'Authenticated, integrity-protected channels between agents.',
      failureSeverity: 'high',
    },
    {
      id: 'ASI08', framework: 'owasp-agentic', title: 'Cascading Failures',
      text: 'A failure in one step propagates through the agent’s loop into unbounded or unrecoverable behaviour.',
      evidenceExpected: 'Iteration ceilings, token budgets, and deadlines.',
      failureSeverity: 'medium',
    },
    {
      id: 'ASI09', framework: 'owasp-agentic', title: 'Human-Agent Trust Exploitation',
      text: 'An adversary exploits over-reliance on the agent, or deceives the human operator.',
      evidenceExpected: 'Human approval for irreversible actions and honest uncertainty signalling.',
      failureSeverity: 'high',
    },
    {
      id: 'ASI10', framework: 'owasp-agentic', title: 'Rogue Agents',
      text: 'An agent acts beyond its intended remit, retains state outside its turn lifecycle, or resists shutdown.',
      evidenceExpected: 'Bounded autonomy, immutable audit logs, and turn-scoped state.',
      failureSeverity: 'critical',
    },
  ];
}

// ---------------------------------------------------------------------------
// Attestation document
// ---------------------------------------------------------------------------

export interface AttestationOptions {
  organisation: string;
  systemName: string;
  /** Human who owns the attestation. */
  owner?: string;
  scope?: ComplianceReport['scope'];
  /** Include the full findings list as evidence. */
  includeEvidence?: boolean;
  now?: Date;
}

/**
 * Compliance attestation, as Markdown.
 *
 * Written to survive being read by an auditor who is sceptical of vendor
 * tooling: it states its own limitations up front, distinguishes "no findings"
 * from "compliant", and never self-certifies.
 */
export function toAttestationMarkdown(
  report: ComplianceReport,
  options: AttestationOptions,
): string {
  const date = (options.now ?? new Date()).toISOString().slice(0, 10);
  const lines: string[] = [];

  lines.push('# AI Agent Security Compliance Attestation');
  lines.push('');
  lines.push('**Organisation:** ' + options.organisation);
  lines.push('**System:** ' + options.systemName);
  lines.push('**Generated:** ' + date);
  if (options.owner) lines.push('**Control owner:** ' + options.owner);
  if (options.scope?.path) lines.push('**Scope:** `' + options.scope.path + '`');
  else if (options.scope?.url) lines.push('**Scope:** `' + options.scope.url + '`');
  lines.push('');

  lines.push('## Status of this document');
  lines.push('');
  lines.push(
    '> This is an automated assessment of **technical** control evidence produced by Aegis. ' +
      'It is decision support for a qualified assessor. It is **not** a certification, and it ' +
      'does not attest that the organisation complies with any framework listed.',
  );
  lines.push('');

  lines.push('## Summary');
  lines.push('');
  lines.push(report.summary.headline);
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('| --- | --- |');
  lines.push(`| Controls assessed | ${report.summary.controlsAssessed} |`);
  lines.push(`| Indicated as not operating effectively | ${report.summary.controlsFailed} |`);
  lines.push(`| Carrying findings requiring review | ${report.summary.controlsAtRisk} |`);
  lines.push(`| No findings intersected (not attested) | ${report.summary.controlsClear} |`);
  lines.push('');

  lines.push('## Frameworks assessed');
  lines.push('');
  lines.push('| Framework | Version | Reference |');
  lines.push('| --- | --- | --- |');
  for (const f of report.frameworks) {
    lines.push(`| ${f.name} | ${f.version} | ${f.url} |`);
  }
  lines.push('');

  lines.push('## Control assessment');
  lines.push('');
  for (const assessment of report.assessments.filter((a) => a.findings.length > 0)) {
    lines.push(`### ${assessment.control.framework.toUpperCase()} ${assessment.control.id} — ${assessment.control.title}`);
    lines.push('');
    lines.push(`**Status:** ${statusLabel(assessment.status)}`);
    lines.push('');
    lines.push(`> ${escapeBlock(assessment.control.text)}`);
    lines.push('');
    lines.push(assessment.assessment);
    lines.push('');
    if (options.includeEvidence) {
      lines.push('| Severity | Finding | Location | Remediation |');
      lines.push('| --- | --- | --- | --- |');
      for (const finding of assessment.findings.slice(0, 25)) {
        lines.push(
          `| ${finding.severity} | ${escapeCell(finding.title)} | \`${finding.location.file ?? finding.location.component ?? '—'}${finding.location.line ? ':' + finding.location.line : ''}\` | ${escapeCell(finding.remediation.title)} |`,
        );
      }
      if (assessment.findings.length > 25) {
        lines.push('');
        lines.push(`_…and ${assessment.findings.length - 25} more._`);
      }
      lines.push('');
    }
    lines.push(`**Evidence an assessor will expect:** ${assessment.evidenceExpected}`);
    lines.push('');
  }

  lines.push('## Controls with no intersecting findings');
  lines.push('');
  const clear = report.assessments.filter((a) => a.findings.length === 0);
  if (clear.length === 0) {
    lines.push('_None._');
  } else {
    lines.push(
      'Aegis found no findings intersecting the following controls. **This is not an attestation ' +
        'that these controls operate effectively** — Aegis evaluates technical evidence only.',
    );
    lines.push('');
    lines.push('| Framework | Control | Title |');
    lines.push('| --- | --- | --- |');
    for (const assessment of clear) {
      lines.push(
        `| ${assessment.control.framework.toUpperCase()} | ${assessment.control.id} | ${escapeCell(assessment.control.title)} |`,
      );
    }
  }
  lines.push('');

  lines.push('## Limitations');
  lines.push('');
  for (const limitation of report.limitations) lines.push(`- ${limitation}`);
  lines.push('');

  lines.push('---');
  lines.push('');
  lines.push(
    `Generated by Aegis ${'— the security platform for AI agents'}. Reproduce with ` +
      '`aegis report --format markdown`.',
  );
  return lines.join('\n');
}

/** HTML attestation, using the same self-contained styling as the scan report. */
export function toAttestationHtml(
  report: ComplianceReport,
  options: AttestationOptions,
): string {
  const date = (options.now ?? new Date()).toISOString().slice(0, 10);
  const esc = escapeHtml;

  const rows = report.assessments
    .filter((a) => a.findings.length > 0)
    .map(
      (a) => `
    <section class="ctl ${a.status}">
      <h3><span class="pill">${esc(a.control.framework.toUpperCase())} ${esc(a.control.id)}</span>
        <span class="st ${a.status}">${statusLabel(a.status)}</span></h3>
      <h4>${esc(a.control.title)}</h4>
      <blockquote>${esc(a.control.text)}</blockquote>
      <p>${esc(a.assessment)}</p>
      ${
        options.includeEvidence
          ? `<table><thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Remediation</th></tr></thead>
        <tbody>${a.findings
          .slice(0, 25)
          .map(
            (f) =>
              `<tr><td><span class="sev ${f.severity}">${esc(f.severity)}</span></td><td>${esc(f.title)}</td><td><code>${esc(
                `${f.location.file ?? f.location.component ?? '—'}${f.location.line ? ':' + f.location.line : ''}`,
              )}</code></td><td>${esc(f.remediation.title)}</td></tr>`,
          )
          .join('')}</tbody></table>`
          : ''
      }
      <p class="evidence"><strong>Evidence an assessor will expect:</strong> ${esc(a.evidenceExpected)}</p>
    </section>`,
    )
    .join('');

  const clear = report.assessments.filter((a) => a.findings.length === 0);

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Compliance Attestation — ${esc(options.systemName)}</title>
<style>
  :root{--bg:#0b1020;--panel:#131a2e;--border:#1e293b;--text:#e2e8f0;--muted:#94a3b8;
        --fail:#ef4444;--risk:#f59e0b;--ok:#22c55e;--accent:#38bdf8}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font:15px/1.65 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
  .wrap{max-width:1000px;margin:0 auto;padding:36px 24px 80px}
  h1{font-size:24px;margin:0 0 6px} h2{font-size:17px;margin:36px 0 12px}
  h3{font-size:15px;margin:0 0 8px;display:flex;gap:10px;align-items:center}
  h4{margin:0 0 10px;font-weight:600}
  .meta{color:var(--muted);font-size:13px;margin-bottom:20px}
  .banner{background:#1a1400;border:1px solid #78500a;border-left:3px solid var(--risk);
    border-radius:8px;padding:14px 18px;margin:18px 0;font-size:14px}
  table{width:100%;border-collapse:collapse;font-size:13px;margin:10px 0}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border)}
  th{color:var(--muted);font-weight:500}
  code{font-family:ui-monospace,monospace;font-size:12px;background:#0b1020;padding:1px 5px;border-radius:4px}
  blockquote{margin:0 0 12px;padding:10px 14px;background:#0b1020;border-left:2px solid var(--accent);
    border-radius:0 6px 6px 0;font-size:13px;color:#cbd5e1}
  .ctl{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:18px 20px;margin-bottom:12px}
  .ctl.fail{border-left:3px solid var(--fail)} .ctl.risk{border-left:3px solid var(--risk)}
  .pill{background:#0b1020;border:1px solid var(--border);border-radius:5px;padding:2px 8px;font-size:11px;
    font-family:ui-monospace,monospace;color:var(--muted)}
  .st{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;padding:2px 8px;border-radius:5px}
  .st.fail{background:var(--fail);color:#fff} .st.risk{background:var(--risk);color:#1a1400}
  .st.no-findings{background:#334155;color:#e2e8f0}
  .sev{font-size:11px;padding:2px 7px;border-radius:4px;font-weight:600}
  .sev.critical{background:var(--fail);color:#fff} .sev.high{background:#f97316;color:#fff}
  .sev.medium{background:#eab308;color:#1a1400} .sev.low{background:#3b82f6;color:#fff} .sev.info{background:#64748b;color:#fff}
  .evidence{color:var(--muted);font-size:13px;margin-bottom:0}
  .lim{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px 20px}
  .lim li{margin-bottom:8px;font-size:14px}
  .kpi{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}
  .kpi div{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:12px 18px}
  .kpi b{display:block;font-size:22px;line-height:1.2}
  .kpi span{color:var(--muted);font-size:12px}
  footer{margin-top:44px;color:var(--muted);font-size:12px;border-top:1px solid var(--border);padding-top:16px}
</style></head>
<body><div class="wrap">
  <h1>AI Agent Security Compliance Attestation</h1>
  <div class="meta">
    <strong>${esc(options.organisation)}</strong> — ${esc(options.systemName)}<br/>
    Generated ${esc(date)}${options.owner ? ` · Control owner: ${esc(options.owner)}` : ''}
  </div>

  <div class="banner">
    This is an automated assessment of <strong>technical</strong> control evidence produced by Aegis.
    It is decision support for a qualified assessor. It is <strong>not</strong> a certification, and it
    does not attest that the organisation complies with any framework listed.
  </div>

  <div class="kpi">
    <div><b>${report.summary.controlsAssessed}</b><span>Controls assessed</span></div>
    <div><b style="color:var(--fail)">${report.summary.controlsFailed}</b><span>Not operating effectively</span></div>
    <div><b style="color:var(--risk)">${report.summary.controlsAtRisk}</b><span>Requiring review</span></div>
    <div><b style="color:var(--ok)">${report.summary.controlsClear}</b><span>No findings (not attested)</span></div>
  </div>

  <p>${esc(report.summary.headline)}</p>

  <h2>Controls with findings</h2>
  ${rows || '<p class="meta">No findings intersected any assessed control.</p>'}

  <h2>Controls with no intersecting findings</h2>
  ${
    clear.length === 0
      ? '<p class="meta">None.</p>'
      : `<p class="meta">Aegis found no findings intersecting the following controls.
         <strong>This is not an attestation that these controls operate effectively.</strong></p>
         <table><thead><tr><th>Framework</th><th>Control</th><th>Title</th></tr></thead><tbody>
         ${clear.map((a) => `<tr><td>${esc(a.control.framework.toUpperCase())}</td><td><code>${esc(a.control.id)}</code></td><td>${esc(a.control.title)}</td></tr>`).join('')}
         </tbody></table>`
  }

  <h2>Limitations</h2>
  <div class="lim"><ul>${report.limitations.map((l) => `<li>${esc(l)}</li>`).join('')}</ul></div>

  <footer>Generated by Aegis — the security platform for AI agents.</footer>
</div></body></html>`;
}

/** Compose the standard finding-set report bundle. */
export function buildComplianceDocuments(input: {
  doc: AegisDocument;
  options: AttestationOptions;
  frameworks?: ComplianceFramework[];
}): { report: ComplianceReport; markdown: string; html: string } {
  const report = assessCompliance(input.doc.findings, {
    ...(input.frameworks ? { frameworks: input.frameworks } : {}),
    scope: input.options.scope ?? input.doc.target,
  });
  return {
    report,
    markdown: toAttestationMarkdown(report, input.options),
    html: toAttestationHtml(report, input.options),
  };
}

/** A concise executive summary suitable for a slide or an email. */
export function executiveSummary(doc: AegisDocument): string {
  const controls = rollUpCompliance(doc.findings);
  const lines: string[] = [];
  lines.push(`# Executive summary — ${doc.target.path ?? doc.target.url ?? doc.target.type}`);
  lines.push('');
  lines.push(
    `Aegis identified **${doc.findings.length} security finding(s)** across MCP servers, agent code and ` +
      `runtime behaviour. The system security score is **${doc.score.score}/100 (grade ${doc.score.grade})**.`,
  );
  lines.push('');
  lines.push('## What matters most');
  lines.push('');
  const criticals = sortFindings(doc.findings.filter((f) => f.severity === 'critical')).slice(0, 3);
  const highs = sortFindings(doc.findings.filter((f) => f.severity === 'high')).slice(0, 3);
  if (criticals.length === 0 && highs.length === 0) {
    lines.push('No critical or high-severity findings were identified.');
  } else {
    for (const finding of [...criticals, ...highs]) {
      lines.push(`- **${finding.title}** — ${finding.remediation.title}`);
    }
  }
  lines.push('');
  if (controls.length > 0) {
    lines.push('## Regulatory surface');
    lines.push('');
    lines.push('These findings intersect the following controls and are likely to be raised in an audit:');
    lines.push('');
    for (const control of controls.slice(0, 6)) {
      lines.push(`- **${control.framework.toUpperCase()} ${control.control}** — ${control.title ?? ''} (${control.count} finding(s))`);
    }
    lines.push('');
  }
  lines.push('## Recommended next steps');
  lines.push('');
  lines.push('1. Remediate critical findings first; they indicate exploitable weaknesses, not hardening opportunities.');
  lines.push('2. Rotate any credential identified by this scan and load secrets from a secret manager.');
  lines.push('3. Re-run the scan and confirm the score improves and the findings are gone.');
  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push('_Full report: `aegis report --format markdown`. Attestation: `aegis report --format markdown --compliance`._');
  return lines.join('\n');
}

export { toMarkdown as findingsMarkdown, toHtml as findingsHtml };

function statusLabel(status: ControlStatus): string {
  switch (status) {
    case 'fail':
      return 'Not operating effectively';
    case 'risk':
      return 'Findings require review';
    case 'no-findings':
      return 'No findings (not attested)';
    default:
      return 'Not assessed';
  }
}

function escapeCell(value: string): string {
  return String(value).replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function escapeBlock(value: string): string {
  return String(value).replace(/\n/g, ' ');
}

function escapeHtml(value: string): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export type { ComplianceMapping };