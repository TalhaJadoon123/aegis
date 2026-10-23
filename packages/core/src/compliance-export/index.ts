/**
 * Compliance Export
 *
 * Generates compliance attestations in PDF and DOCX formats.
 * Uses built-in Node.js APIs - no external dependencies.
 */

import { writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

export interface ComplianceExportConfig {
  organisation: string;
  system: string;
  owner: string;
  frameworks: string[];
  outputFormat: 'markdown' | 'html' | 'json' | 'pdf' | 'docx';
  outputPath: string;
}

export interface ComplianceFinding {
  id: string;
  ruleId: string;
  title: string;
  severity: string;
  file: string;
  line: number;
  description: string;
  remediation: string;
  compliance: Array<{ framework: string; control: string; title: string; relevant: boolean }>;
}

export interface ComplianceControl {
  framework: string;
  control: string;
  title: string;
  status: 'fail' | 'risk' | 'no-findings' | 'not-assessed';
  findings: ComplianceFinding[];
  worstSeverity: string;
  evidenceExpected: string;
}

export class ComplianceExporter {
  private readonly config: ComplianceExportConfig;

  constructor(config: ComplianceExportConfig) {
    this.config = config;
  }

  /**
   * Generate a compliance attestation in the requested format.
   */
  async generate(findings: ComplianceFinding[]): Promise<string> {
    const controls = this.buildControls(findings);

    switch (this.config.outputFormat) {
      case 'markdown':
        return this.toMarkdown(controls);
      case 'html':
        return this.toHtml(controls);
      case 'json':
        return JSON.stringify({ controls, findings }, null, 2);
      case 'pdf':
        return this.toPdf(controls);
      case 'docx':
        return this.toDocx(controls);
      default:
        return this.toMarkdown(controls);
    }
  }

  /**
   * Save the generated attestation to a file.
   */
  async save(content: string): Promise<string> {
    const dir = resolve(this.config.outputPath, '..');
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    writeFileSync(this.config.outputPath, content, 'utf8');
    return this.config.outputPath;
  }

  private buildControls(findings: ComplianceFinding[]): ComplianceControl[] {
    const controlMap = new Map<string, ComplianceControl>();

    for (const finding of findings) {
      for (const mapping of finding.compliance) {
        if (!mapping.relevant) continue;

        const key = `${mapping.framework}:${mapping.control}`;
        let control = controlMap.get(key);

        if (!control) {
          control = {
            framework: mapping.framework,
            control: mapping.control,
            title: mapping.title,
            status: 'no-findings',
            findings: [],
            worstSeverity: 'info',
            evidenceExpected: this.getEvidenceExpected(mapping.framework, mapping.control),
          };
          controlMap.set(key, control);
        }

        control.findings.push(finding);

        // Update status based on severity
        const severityRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        const worstRank = severityRank[control.worstSeverity] ?? 4;
        const findingRank = severityRank[finding.severity] ?? 4;

        if (findingRank < worstRank) {
          control.worstSeverity = finding.severity;
        }

        if (finding.severity === 'critical') {
          control.status = 'fail';
        } else if (finding.severity === 'high' && control.status !== 'fail') {
          control.status = 'risk';
        }
      }
    }

    // Mark controls with no findings as 'no-findings'
    for (const control of controlMap.values()) {
      if (control.findings.length === 0) {
        control.status = 'no-findings';
      }
    }

    return Array.from(controlMap.values()).sort((a, b) => {
      const severityRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      const rankA = severityRank[a.worstSeverity] ?? 4;
      const rankB = severityRank[b.worstSeverity] ?? 4;
      return rankA - rankB || b.findings.length - a.findings.length;
    });
  }

  private getEvidenceExpected(framework: string, control: string): string {
    // Default evidence expected per control
    const evidenceMap: Record<string, string> = {
      'owasp-agentic:ASI01': 'Prompt injection resistance testing results',
      'owasp-agentic:ASI02': 'Tool abuse detection and access control configuration',
      'owasp-agentic:ASI03': 'Credential management and access control configuration',
      'owasp-agentic:ASI04': 'Supply chain dependency inventory and pinning',
      'owasp-agentic:ASI05': 'Code execution controls and sandboxing',
      'owasp-agentic:ASI06': 'Input validation and output encoding',
      'owasp-agentic:ASI07': 'Least privilege configuration',
      'owasp-agentic:ASI08': 'Resource limits and rate limiting',
      'owasp-agentic:ASI09': 'Human oversight and approval gates',
      'owasp-agentic:ASI10': 'Agent behavior monitoring and anomaly detection',
      'soc2:CC6.1': 'Access control configuration, role definitions, least-privilege evidence',
      'soc2:CC6.6': 'Network controls, egress policy, boundary protection',
      'soc2:CC6.7': 'Encryption in transit, data-loss-prevention, transmission logs',
      'soc2:CC7.1': 'Continuous scanning, vulnerability management records, patch cadence',
      'soc2:CC7.2': 'Runtime monitoring, anomaly detection output, alerting configuration',
      'soc2:CC7.3': 'Incident runbooks, triage records, post-incident reviews',
      'iso27001:A.5.15': 'Access control policy, permissioning rules, review evidence',
      'iso27001:A.5.17': 'Secret management configuration, credentials not in source',
      'iso27001:A.8.3': 'Per-tool and per-agent permission configuration',
      'iso27001:A.8.6': 'Resource limits, rate limits, budget ceilings',
      'iso27001:A.8.8': 'Dependency inventories, pinning, vulnerability scanning records',
      'iso27001:A.8.15': 'Audit log configuration and retention policy',
      'iso27001:A.8.19': 'Install-time script policy, approved-software inventory',
      'iso27001:A.8.20': 'Network segmentation, egress policy, transport security',
      'iso27001:A.8.26': 'Security requirements in SDLC, secure-by-default agent config',
      'iso27001:A.8.28': 'Static analysis results, secure coding standards',
      'gdpr:Art. 5': 'Data-minimisation controls, evidence of no over-collection into prompts',
      'gdpr:Art. 25': 'Design documentation showing privacy considered',
      'gdpr:Art. 30': 'Record of processing activities, updated as agents change',
      'gdpr:Art. 32': 'Technical controls protecting personal data in transit and at rest',
      'gdpr:Art. 35': 'Completed DPIA covering automated decision-making',
      'eu-ai-act:Art. 9': 'Documented risk management covering cybersecurity of AI system',
      'eu-ai-act:Art. 10': 'Data provenance and quality documentation',
      'eu-ai-act:Art. 12': 'Logging configuration and retention',
      'eu-ai-act:Art. 13': 'Documentation of model limitations and output interpretation',
      'eu-ai-act:Art. 14': 'Evidence human can meaningfully intervene, override, or stop',
      'eu-ai-act:Art. 15': 'Prompt-injection and jailbreak resistance results, red-team outcomes',
      'nist-ai-rmf:GOVERN 1.2': 'Documented legal review of agent deployment context',
      'nist-ai-rmf:GOVERN 4.1': 'Named owners for each agent, documented escalation paths',
      'nist-ai-rmf:MAP 5.1': 'Inventory of agents, frameworks, model providers, MCP servers',
      'nist-ai-rmf:MEASURE 2.7': 'Red-team results, prompt-injection resistance testing',
      'nist-ai-rmf:MANAGE 2.2': 'Change management, rollback paths, model/tool pinning',
      'mitre-atlas:AML.T0051': 'Red-team transcripts showing injection attempts',
      'mitre-atlas:AML.T0054': 'Jailbreak resistance testing results',
      'mitre-atlas:AML.T0050': 'Tool and code-execution findings with reachability',
    };
    return evidenceMap[`${framework}:${control}`] ?? 'Technical control evidence from scan';
  }

  private toMarkdown(controls: ComplianceControl[]): string {
    const lines: string[] = [];
    lines.push('# Compliance Attestation');
    lines.push('');
    lines.push(`**Organisation:** ${this.config.organisation}`);
    lines.push(`**System:** ${this.config.system}`);
    lines.push(`**Owner:** ${this.config.owner}`);
    lines.push(`**Frameworks:** ${this.config.frameworks.join(', ')}`);
    lines.push(`**Generated:** ${new Date().toISOString()}`);
    lines.push('');
    lines.push('> This is an automated assessment of technical control evidence produced by Aegis.');
    lines.push('> It is decision support for a qualified assessor. It is not a certification,');
    lines.push('> and it does not attest that the organisation complies with any framework listed.');
    lines.push('');

    lines.push('## Summary');
    lines.push('');
    lines.push('| Status | Count |');
    lines.push('|--------|-------|');
    const statusCounts = new Map<string, number>();
    for (const c of controls) {
      statusCounts.set(c.status, (statusCounts.get(c.status) ?? 0) + 1);
    }
    for (const [status, count] of statusCounts) {
      lines.push(`| ${status} | ${count} |`);
    }
    lines.push('');

    lines.push('## Controls');
    lines.push('');
    lines.push('| Framework | Control | Title | Status | Findings | Worst Severity |');
    lines.push('|-----------|---------|-------|--------|----------|----------------|');
    for (const c of controls) {
      lines.push(`| ${c.framework} | ${c.control} | ${c.title} | ${c.status} | ${c.findings.length} | ${c.worstSeverity} |`);
    }
    lines.push('');

    for (const control of controls) {
      if (control.findings.length === 0) continue;
      lines.push(`### ${control.framework}/${control.control}: ${control.title}`);
      lines.push('');
      lines.push(`**Status:** ${control.status}`);
      lines.push(`**Evidence Expected:** ${control.evidenceExpected}`);
      lines.push('');
      lines.push('**Findings:**');
      for (const f of control.findings) {
        lines.push(`- ${f.ruleId}: ${f.title} (${f.severity}) — \`${f.file}:${f.line}\``);
      }
      lines.push('');
    }

    lines.push('## Limitations');
    lines.push('');
    lines.push('This attestation is an automated assessment of technical control evidence.');
    lines.push('It does not assess organisational or procedural safeguards (policies, training,');
    lines.push('incident response, change management). These are out of scope for this tool.');
    lines.push('');
    lines.push('A qualified assessor must review this evidence and make the final determination');
    lines.push('of control operating effectiveness.');
    lines.push('');

    return lines.join('\n');
  }

  private toHtml(controls: ComplianceControl[]): string {
    const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

    const rows = controls.map((c) => `
      <tr>
        <td>${esc(c.framework)}</td>
        <td><code>${esc(c.control)}</code></td>
        <td>${esc(c.title)}</td>
        <td class="status-${c.status}">${esc(c.status)}</td>
        <td>${c.findings.length}</td>
        <td>${esc(c.worstSeverity)}</td>
      </tr>`).join('');

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Compliance Attestation — ${esc(this.config.organisation)}</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; background:#0b1020; color:#e2e8f0; font:15px/1.6 ui-sans-serif,system-ui,-apple-system,sans-serif; }
  .wrap { max-width:1100px; margin:0 auto; padding:32px 24px 80px; }
  h1 { font-size:22px; margin:0 0 4px; }
  .meta { color:#94a3b8; font-size:13px; margin-bottom:28px; }
  .disclaimer { background:#131a2e; border:1px solid #1e293b; border-radius:10px; padding:16px; margin-bottom:28px; color:#94a3b8; font-size:13px; }
  table { width:100%; border-collapse:collapse; font-size:13px; margin-top:8px; }
  th,td { text-align:left; padding:8px 10px; border-bottom:1px solid #1e293b; }
  th { color:#94a3b8; font-weight:500; }
  .status-fail { color:#ef4444; font-weight:700; }
  .status-risk { color:#f97316; font-weight:600; }
  .status-no-findings { color:#22c55e; }
  .status-not-assessed { color:#64748b; }
  .finding { background:#131a2e; border:1px solid #1e293b; border-radius:8px; padding:12px; margin-bottom:8px; }
  .finding strong { color:#38bdf8; }
  .limitation { background:#131a2e; border:1px solid #1e293b; border-radius:10px; padding:16px; margin-top:28px; color:#94a3b8; font-size:13px; }
  footer { margin-top:44px; color:#94a3b8; font-size:12px; border-top:1px solid #1e293b; padding-top:16px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Compliance Attestation</h1>
  <div class="meta">
    <strong>${esc(this.config.organisation)}</strong> · ${esc(this.config.system)} · ${esc(this.config.owner)}<br/>
    Frameworks: ${esc(this.config.frameworks.join(', '))}<br/>
    Generated: ${new Date().toISOString()}
  </div>
  <div class="disclaimer">
    This is an automated assessment of technical control evidence produced by Aegis.
    It is decision support for a qualified assessor. It is not a certification,
    and it does not attest that the organisation complies with any framework listed.
  </div>
  <h2>Controls</h2>
  <table>
    <thead><tr><th>Framework</th><th>Control</th><th>Title</th><th>Status</th><th>Findings</th><th>Worst</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  ${controls.filter((c) => c.findings.length > 0).map((c) => `
  <div class="finding">
    <strong>${esc(c.framework)}/${esc(c.control)}: ${esc(c.title)}</strong>
    <p>Status: ${esc(c.status)} · Evidence Expected: ${esc(c.evidenceExpected)}</p>
    <ul>${c.findings.map((f) => `<li>${esc(f.ruleId)}: ${esc(f.title)} (${esc(f.severity)}) — <code>${esc(f.file)}:${f.line}</code></li>`).join('')}</ul>
  </div>`).join('')}
  <div class="limitation">
    <strong>Limitations:</strong> This attestation is an automated assessment of technical control evidence.
    It does not assess organisational or procedural safeguards (policies, training, incident response,
    change management). These are out of scope for this tool. A qualified assessor must review this
    evidence and make the final determination of control operating effectiveness.
  </div>
  <footer>
    Generated by Aegis v0.1.0 — the security platform for AI agents.
  </footer>
</div>
</body>
</html>`;
  }

  private toPdf(controls: ComplianceControl[]): string {
    // PDF generation requires external libraries (pdfkit, etc.)
    // For now, return a placeholder that explains the limitation
    return `# Compliance Attestation (PDF)

This attestation requires PDF generation libraries (pdfkit, puppeteer, etc.)
which are not available in the zero-dependency build.

To generate a PDF:
1. Use the HTML output: \`aegis report . --compliance --format html > attestation.html\`
2. Open in a browser and print to PDF (Ctrl+P → Save as PDF)

Alternatively, install pdfkit: \`npm install pdfkit\` and re-run.

Controls: ${controls.length}
Findings: ${controls.reduce((sum, c) => sum + c.findings.length, 0)}`;
  }

  private toDocx(controls: ComplianceControl[]): string {
    // DOCX generation requires external libraries (docx, officegen, etc.)
    // For now, return a placeholder that explains the limitation
    return `# Compliance Attestation (DOCX)

This attestation requires DOCX generation libraries (docx, officegen, etc.)
which are not available in the zero-dependency build.

To generate a DOCX:
1. Use the Markdown output: \`aegis report . --compliance --format markdown > attestation.md\`
2. Convert using pandoc: \`pandoc attestation.md -o attestation.docx\`

Alternatively, install docx: \`npm install docx\` and re-run.

Controls: ${controls.length}
Findings: ${controls.reduce((sum, c) => sum + c.findings.length, 0)}`;
  }
}

// All exports are already declared with 'export' keyword above.