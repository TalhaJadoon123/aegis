/**
 * Usage Metering for Billing
 *
 * Tracks API usage, scan counts, red team runs, and other billable actions
 * for metered billing in SaaS deployments.
 *
 * Zero runtime dependencies - implemented in pure TypeScript.
 */

export type PlanType = 'free' | 'pro' | 'team' | 'enterprise';
export type UsageAction =
  | 'scan.run'
  | 'scan.create'
  | 'redteam.run'
  | 'fix.apply'
  | 'report.generate'
  | 'dashboard.access'
  | 'api.request'
  | 'webhook.trigger';

export interface UsageQuota {
  plan: PlanType;
  scansPerMonth: number;
  redteamsPerMonth: number;
  fixesPerMonth: number;
  reportsPerMonth: number;
  apiRequestsPerMinute: number;
  maxConcurrentScans: number;
  retentionDays: number;
  prioritySupport: boolean;
}

export interface UsageRecord {
  id: string;
  userId: string;
  orgId?: string;
  action: UsageAction;
  resourceId?: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface UsageSummary {
  userId: string;
  orgId?: string;
  period: string; // YYYY-MM
  scans: number;
  redteams: number;
  fixes: number;
  reports: number;
  apiRequests: number;
  webhooks: number;
  overQuota: boolean;
  quotaPercent: {
    scans: number;
    redteams: number;
    fixes: number;
    reports: number;
  };
}

export const PLAN_QUOTAS: Record<PlanType, UsageQuota> = {
  free: {
    plan: 'free',
    scansPerMonth: 10,
    redteamsPerMonth: 2,
    fixesPerMonth: 5,
    reportsPerMonth: 5,
    apiRequestsPerMinute: 10,
    maxConcurrentScans: 1,
    retentionDays: 30,
    prioritySupport: false,
  },
  pro: {
    plan: 'pro',
    scansPerMonth: 100,
    redteamsPerMonth: 20,
    fixesPerMonth: 50,
    reportsPerMonth: 50,
    apiRequestsPerMinute: 60,
    maxConcurrentScans: 3,
    retentionDays: 90,
    prioritySupport: false,
  },
  team: {
    plan: 'team',
    scansPerMonth: 500,
    redteamsPerMonth: 100,
    fixesPerMonth: 200,
    reportsPerMonth: 200,
    apiRequestsPerMinute: 300,
    maxConcurrentScans: 10,
    retentionDays: 365,
    prioritySupport: true,
  },
  enterprise: {
    plan: 'enterprise',
    scansPerMonth: -1, // unlimited
    redteamsPerMonth: -1,
    fixesPerMonth: -1,
    reportsPerMonth: -1,
    apiRequestsPerMinute: 1000,
    maxConcurrentScans: 50,
    retentionDays: 365 * 3, // 3 years
    prioritySupport: true,
  },
};

export class UsageMeter {
  private readonly records: UsageRecord[] = [];
  private readonly orgId?: string;

  constructor(orgId?: string) {
    this.orgId = orgId;
  }

  /**
   * Record a usage event.
   */
  record(userId: string, action: UsageAction, resourceId?: string, metadata?: Record<string, unknown>): UsageRecord {
    const record: UsageRecord = {
      id: `usage_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      userId,
      ...(this.orgId ? { orgId: this.orgId } : {}),
      action,
      ...(resourceId ? { resourceId } : {}),
      timestamp: new Date().toISOString(),
      ...(metadata ? { metadata } : {}),
    };
    this.records.push(record);
    return record;
  }

  /**
   * Get usage summary for a user in a given period.
   */
  getUsageSummary(userId: string, period: string = getCurrentPeriod()): UsageSummary {
    const userRecords = this.records.filter(
      (r) => r.userId === userId && r.timestamp.startsWith(period)
    );

    const scans = userRecords.filter((r) => r.action === 'scan.run' || r.action === 'scan.create').length;
    const redteams = userRecords.filter((r) => r.action === 'redteam.run').length;
    const fixes = userRecords.filter((r) => r.action === 'fix.apply').length;
    const reports = userRecords.filter((r) => r.action === 'report.generate').length;
    const apiRequests = userRecords.filter((r) => r.action === 'api.request').length;
    const webhooks = userRecords.filter((r) => r.action === 'webhook.trigger').length;

    // Determine plan from user records or default to free
    const plan: PlanType = 'free';
    const quota = PLAN_QUOTAS[plan];

    const isUnlimited = (quota: number) => quota === -1;
    const percent = (used: number, quota: number) => isUnlimited(quota) ? 0 : Math.round((used / quota) * 100);

    const overQuota =
      (!isUnlimited(quota.scansPerMonth) && scans >= quota.scansPerMonth) ||
      (!isUnlimited(quota.redteamsPerMonth) && redteams >= quota.redteamsPerMonth) ||
      (!isUnlimited(quota.fixesPerMonth) && fixes >= quota.fixesPerMonth) ||
      (!isUnlimited(quota.reportsPerMonth) && reports >= quota.reportsPerMonth);

    return {
      userId,
      ...(this.orgId ? { orgId: this.orgId } : {}),
      period,
      scans,
      redteams,
      fixes,
      reports,
      apiRequests,
      webhooks,
      overQuota,
      quotaPercent: {
        scans: percent(scans, quota.scansPerMonth),
        redteams: percent(redteams, quota.redteamsPerMonth),
        fixes: percent(fixes, quota.fixesPerMonth),
        reports: percent(reports, quota.reportsPerMonth),
      },
    };
  }

  /**
   * Check if a user has exceeded their quota for an action.
   */
  checkQuota(userId: string, action: UsageAction, plan: PlanType = 'free'): { allowed: boolean; reason?: string } {
    const quota = PLAN_QUOTAS[plan];
    const period = getCurrentPeriod();
    const summary = this.getUsageSummary(userId, period);

    switch (action) {
      case 'scan.run':
      case 'scan.create':
        if (!isUnlimited(quota.scansPerMonth) && summary.scans >= quota.scansPerMonth) {
          return { allowed: false, reason: `Monthly scan quota exceeded (${quota.scansPerMonth})` };
        }
        break;
      case 'redteam.run':
        if (!isUnlimited(quota.redteamsPerMonth) && summary.redteams >= quota.redteamsPerMonth) {
          return { allowed: false, reason: `Monthly red team quota exceeded (${quota.redteamsPerMonth})` };
        }
        break;
      case 'fix.apply':
        if (!isUnlimited(quota.fixesPerMonth) && summary.fixes >= quota.fixesPerMonth) {
          return { allowed: false, reason: `Monthly fix quota exceeded (${quota.fixesPerMonth})` };
        }
        break;
      case 'report.generate':
        if (!isUnlimited(quota.reportsPerMonth) && summary.reports >= quota.reportsPerMonth) {
          return { allowed: false, reason: `Monthly report quota exceeded (${quota.reportsPerMonth})` };
        }
        break;
    }

    return { allowed: true };
  }

  /**
   * Get all usage records.
   */
  getRecords(): UsageRecord[] {
    return [...this.records];
  }

  /**
   * Get usage records for a specific period.
   */
  getRecordsForPeriod(period: string): UsageRecord[] {
    return this.records.filter((r) => r.timestamp.startsWith(period));
  }

  /**
   * Get total records count.
   */
  getTotalRecords(): number {
    return this.records.length;
  }

  /**
   * Clear all records.
   */
  clear(): void {
    this.records.length = 0;
  }
}

function getCurrentPeriod(): string {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

function isUnlimited(quota: number): boolean {
  return quota === -1;
}

// All exports are already declared with 'export' keyword above.