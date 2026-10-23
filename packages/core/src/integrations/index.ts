/**
 * Integrations for Aegis
 *
 * Provides integration with external services:
 * - Slack (notifications)
 * - Jira (ticket creation)
 * - PagerDuty (incident management)
 * - SIEM (Splunk, ELK, QRadar)
 */

import type { SlackConfig, SlackMessage, SlackBlock, SlackFinding, SlackScanResult } from './slack.js';
import type { JiraConfig, JiraIssue, JiraFinding } from './jira.js';

export { SlackNotifier } from './slack.js';
export { JiraClient } from './jira.js';

export type { SlackConfig, SlackMessage, SlackBlock, SlackFinding, SlackScanResult };
export type { JiraConfig, JiraIssue, JiraFinding };

export interface PagerDutyConfig {
  routingKey: string;
  apiUrl?: string;
}

export interface SiemConfig {
  type: 'splunk' | 'elk' | 'qradar' | 'generic';
  endpoint: string;
  token: string;
  format: 'json' | 'cef' | 'leef';
}

export interface IntegrationConfig {
  slack?: SlackConfig;
  jira?: JiraConfig;
  pagerduty?: PagerDutyConfig;
  siem?: SiemConfig;
}