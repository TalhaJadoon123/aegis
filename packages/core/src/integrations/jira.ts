/**
 * Jira Integration for Aegis
 *
 * Creates Jira tickets from findings for tracking and remediation.
 * Supports Jira Cloud and Server.
 */

export interface JiraConfig {
  /** Jira base URL (e.g., https://company.atlassian.net) */
  baseUrl: string;
  /** Authentication (email + API token for Cloud, username + password for Server) */
  email: string;
  apiToken: string;
  /** Default project key */
  projectKey: string;
  /** Issue type (default: Bug) */
  issueType?: string;
  /** Priority mapping */
  priorityMap?: Record<string, string>;
}

export interface JiraIssue {
  id: string;
  key: string;
  self: string;
  fields: {
    summary: string;
    description: string;
    issuetype: { name: string };
    priority: { name: string };
    project: { key: string };
    labels: string[];
  };
}

export interface JiraFinding {
  ruleId: string;
  title: string;
  severity: string;
  file: string;
  line: number;
  description: string;
  remediation: string;
  cwe?: string;
  taxonomy?: string;
}

export class JiraClient {
  private readonly config: JiraConfig;
  private readonly auth: string;

  constructor(config: JiraConfig) {
    this.config = config;
    this.auth = Buffer.from(`${config.email}:${config.apiToken}`).toString('base64');
  }

  /**
   * Create a Jira issue from a finding.
   */
  async createIssue(finding: JiraFinding): Promise<JiraIssue | null> {
    try {
      const response = await fetch(`${this.config.baseUrl}/rest/api/3/issue`, {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${this.auth}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({
          fields: {
            project: { key: this.config.projectKey },
            summary: `[Aegis] ${finding.title} in ${finding.file}`,
            description: this.buildDescription(finding),
            issuetype: { name: this.config.issueType ?? 'Bug' },
            priority: { name: this.mapSeverityToPriority(finding.severity) },
            labels: ['aegis', 'security', finding.severity, ...this.extractLabels(finding)],
          },
        }),
      });

      if (!response.ok) {
        const error = await response.text();
        console.error(`[Jira] Failed to create issue: ${response.status} ${error}`);
        return null;
      }

      return await response.json() as JiraIssue;
    } catch (error) {
      console.error(`[Jira] Error creating issue: ${(error as Error).message}`);
      return null;
    }
  }

  /**
   * Create issues for multiple findings.
   */
  async createIssues(findings: JiraFinding[]): Promise<JiraIssue[]> {
    const issues: JiraIssue[] = [];
    for (const finding of findings) {
      const issue = await this.createIssue(finding);
      if (issue) {
        issues.push(issue);
      }
    }
    return issues;
  }

  /**
   * Add a comment to an existing issue.
   */
  async addComment(issueKey: string, comment: string): Promise<boolean> {
    try {
      const response = await fetch(`${this.config.baseUrl}/rest/api/3/issue/${issueKey}/comment`, {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${this.auth}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          body: comment,
        }),
      });

      return response.ok;
    } catch (error) {
      console.error(`[Jira] Error adding comment: ${(error as Error).message}`);
      return false;
    }
  }

  /**
   * Transition an issue to a new status.
   */
  async transitionIssue(issueKey: string, transitionId: string): Promise<boolean> {
    try {
      const response = await fetch(`${this.config.baseUrl}/rest/api/3/issue/${issueKey}/transitions`, {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${this.auth}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          transition: { id: transitionId },
        }),
      });

      return response.ok;
    } catch (error) {
      console.error(`[Jira] Error transitioning issue: ${(error as Error).message}`);
      return false;
    }
  }

  /**
   * Search for existing issues by JQL.
   */
  async searchIssues(jql: string): Promise<JiraIssue[]> {
    try {
      const response = await fetch(`${this.config.baseUrl}/rest/api/3/search?jql=${encodeURIComponent(jql)}`, {
        headers: {
          'Authorization': `Basic ${this.auth}`,
          'Accept': 'application/json',
        },
      });

      if (!response.ok) return [];

      const data = await response.json() as { issues: JiraIssue[] };
      return data.issues ?? [];
    } catch (error) {
      console.error(`[Jira] Error searching issues: ${(error as Error).message}`);
      return [];
    }
  }

  private buildDescription(finding: JiraFinding): string {
    const lines = [
      `*Severity:* ${finding.severity}`,
      `*Rule:* ${finding.ruleId}`,
      `*File:* \`${finding.file}:${finding.line}\``,
      `*CWE:* ${finding.cwe ?? 'N/A'}`,
      `*OWASP Agentic:* ${finding.taxonomy ?? 'N/A'}`,
      '',
      `*Description:*`,
      finding.description,
      '',
      `*Remediation:*`,
      finding.remediation,
      '',
      `---`,
      `_Created by Aegis Security Scanner_`,
    ];
    return lines.join('\n');
  }

  private mapSeverityToPriority(severity: string): string {
    const map: Record<string, string> = {
      critical: 'Highest',
      high: 'High',
      medium: 'Medium',
      low: 'Low',
      info: 'Lowest',
    };
    return this.config.priorityMap?.[severity] ?? map[severity] ?? 'Medium';
  }

  private extractLabels(finding: JiraFinding): string[] {
    const labels: string[] = [];
    if (finding.cwe) labels.push(finding.cwe.toLowerCase().replace('cwe-', 'cwe'));
    if (finding.taxonomy) labels.push(finding.taxonomy.toLowerCase());
    return labels;
  }
}

// All exports are already declared with 'export' keyword above.