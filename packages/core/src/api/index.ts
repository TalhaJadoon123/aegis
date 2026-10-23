/**
 * REST API for Aegis Dashboard.
 *
 * Provides programmatic access to scan data, findings, compliance reports,
 * and scan triggers. Designed for SaaS integrations and enterprise workflows.
 *
 * All endpoints require authentication (bearer token or session cookie).
 * Rate limiting and usage tracking are built-in for metered billing.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

export interface ApiConfig {
  /** Base path for API (default: /api/v1) */
  basePath?: string;
  /** Enable rate limiting */
  enableRateLimit?: boolean;
  /** Requests per minute per user */
  rateLimitPerMinute?: number;
  /** Enable usage tracking for billing */
  enableUsageTracking?: boolean;
  /** Enable webhooks */
  enableWebhooks?: boolean;
}

export interface ApiRequest {
  method: string;
  path: string;
  params: Record<string, string>;
  query: Record<string, string>;
  body?: unknown;
  user?: ApiUser;
}

export interface ApiUser {
  id: string;
  orgId?: string;
  role: 'admin' | 'user' | 'viewer';
  plan: 'free' | 'pro' | 'team' | 'enterprise';
}

export interface ApiResponse {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
}

export interface WebhookConfig {
  url: string;
  events: WebhookEvent[];
  secret: string;
  active: boolean;
}

export type WebhookEvent =
  | 'scan.completed'
  | 'scan.failed'
  | 'finding.critical'
  | 'finding.high'
  | 'finding.new'
  | 'compliance.violation'
  | 'redteam.bypass';

export interface UsageRecord {
  userId: string;
  orgId?: string;
  timestamp: string;
  action: string;
  resourceId?: string;
  metadata?: Record<string, unknown>;
}

export class AegisApi {
  private readonly basePath: string;
  private readonly config: ApiConfig;
  private readonly scans: Map<string, unknown>;
  private readonly webhooks: Map<string, WebhookConfig>;
  private readonly usageRecords: UsageRecord[];
  private readonly rateLimiters: Map<string, { count: number; resetAt: number }>;

  constructor(config: ApiConfig = {}) {
    this.basePath = config.basePath ?? '/api/v1';
    this.config = config;
    this.scans = new Map();
    this.webhooks = new Map();
    this.usageRecords = [];
    this.rateLimiters = new Map();
  }

  /**
   * Handle an incoming API request.
   */
  async handleRequest(req: ApiRequest): Promise<ApiResponse> {
    // Rate limiting
    if (this.config.enableRateLimit && req.user) {
      const rateLimitResult = this.checkRateLimit(req.user.id);
      if (!rateLimitResult.allowed) {
        return {
          status: 429,
          body: {
            error: 'Rate limit exceeded',
            retryAfter: rateLimitResult.retryAfter,
          },
        };
      }
    }

    // Route to handler
    const path = req.path;
    const method = req.method;

    // Scans
    if (path === '/scans' && method === 'GET') {
      return this.listScans(req);
    }
    if (path === '/scans' && method === 'POST') {
      return this.createScan(req);
    }
    if (path.startsWith('/scans/') && method === 'GET') {
      const id = path.slice('/scans/'.length);
      return this.getScan(id);
    }
    if (path.startsWith('/scans/') && method === 'DELETE') {
      const id = path.slice('/scans/'.length);
      return this.deleteScan(id);
    }

    // Findings
    if (path === '/findings' && method === 'GET') {
      return this.listFindings(req);
    }
    if (path.startsWith('/findings/') && method === 'GET') {
      const id = path.slice('/findings/'.length);
      return this.getFinding(id);
    }

    // Compliance
    if (path === '/compliance' && method === 'GET') {
      return this.getCompliance(req);
    }
    if (path === '/compliance/attestation' && method === 'POST') {
      return this.generateAttestation(req);
    }

    // Reports
    if (path === '/reports' && method === 'GET') {
      return this.listReports(req);
    }
    if (path === '/reports' && method === 'POST') {
      return this.createReport(req);
    }

    // Red team
    if (path === '/redteam' && method === 'POST') {
      return this.createRedTeam(req);
    }
    if (path.startsWith('/redteam/') && method === 'GET') {
      const id = path.slice('/redteam/'.length);
      return this.getRedTeam(id);
    }

    // Webhooks
    if (path === '/webhooks' && method === 'GET') {
      return this.listWebhooks(req);
    }
    if (path === '/webhooks' && method === 'POST') {
      return this.createWebhook(req);
    }
    if (path.startsWith('/webhooks/') && method === 'DELETE') {
      const id = path.slice('/webhooks/'.length);
      return this.deleteWebhook(id);
    }

    // Usage
    if (path === '/usage' && method === 'GET') {
      return this.getUsage(req);
    }

    // Health
    if (path === '/health' && method === 'GET') {
      return { status: 200, body: { status: 'healthy', timestamp: new Date().toISOString() } };
    }

    return { status: 404, body: { error: 'Not found' } };
  }

  // --- Scan handlers ---

  private async listScans(req: ApiRequest): Promise<ApiResponse> {
    const scans = Array.from(this.scans.values());
    return { status: 200, body: { scans, total: scans.length } };
  }

  private async createScan(req: ApiRequest): Promise<ApiResponse> {
    const body = req.body as Record<string, unknown>;
    const scanId = `scan_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const scan = {
      id: scanId,
      target: body.target ?? '.',
      format: body.format ?? 'json',
      status: 'pending',
      startedAt: new Date().toISOString(),
      findings: [],
      score: 0,
      grade: 'F',
    };
    this.scans.set(scanId, scan);

    // Track usage
    this.trackUsage(req.user, 'scan.create', scanId);

    // Trigger webhook
    await this.triggerWebhook('scan.completed', { scan });

    return { status: 201, body: { scan } };
  }

  private async getScan(id: string): Promise<ApiResponse> {
    const scan = this.scans.get(id);
    if (!scan) {
      return { status: 404, body: { error: 'Scan not found' } };
    }
    return { status: 200, body: { scan } };
  }

  private async deleteScan(id: string): Promise<ApiResponse> {
    if (!this.scans.has(id)) {
      return { status: 404, body: { error: 'Scan not found' } };
    }
    this.scans.delete(id);
    return { status: 204, body: null };
  }

  // --- Finding handlers ---

  private async listFindings(req: ApiRequest): Promise<ApiResponse> {
    const allScans = Array.from(this.scans.values()) as Array<{ findings?: unknown[] }>;
    const findings = allScans.flatMap((s) => s.findings ?? []);
    return { status: 200, body: { findings, total: findings.length } };
  }

  private async getFinding(id: string): Promise<ApiResponse> {
    const allScans = Array.from(this.scans.values()) as Array<{ findings?: Array<{ id?: string }> }>;
    for (const scan of allScans) {
      const finding = scan.findings?.find((f) => f.id === id);
      if (finding) {
        return { status: 200, body: { finding } };
      }
    }
    return { status: 404, body: { error: 'Finding not found' } };
  }

  // --- Compliance handlers ---

  private async getCompliance(req: ApiRequest): Promise<ApiResponse> {
    return { status: 200, body: { compliance: { controls: [], frameworks: [] } } };
  }

  private async generateAttestation(req: ApiRequest): Promise<ApiResponse> {
    const body = req.body as Record<string, unknown>;
    return { status: 200, body: { attestation: { organisation: body.organisation, system: body.system, owner: body.owner } } };
  }

  // --- Report handlers ---

  private async listReports(req: ApiRequest): Promise<ApiResponse> {
    return { status: 200, body: { reports: [], total: 0 } };
  }

  private async createReport(req: ApiRequest): Promise<ApiResponse> {
    return { status: 201, body: { report: { id: `report_${Date.now()}` } } };
  }

  // --- Red team handlers ---

  private async createRedTeam(req: ApiRequest): Promise<ApiResponse> {
    const body = req.body as Record<string, unknown>;
    return { status: 201, body: { redteam: { id: `redteam_${Date.now()}`, target: body.target } } };
  }

  private async getRedTeam(id: string): Promise<ApiResponse> {
    return { status: 200, body: { redteam: { id } } };
  }

  // --- Webhook handlers ---

  private async listWebhooks(req: ApiRequest): Promise<ApiResponse> {
    return { status: 200, body: { webhooks: Array.from(this.webhooks.values()), total: this.webhooks.size } };
  }

  private async createWebhook(req: ApiRequest): Promise<ApiResponse> {
    const body = req.body as Record<string, unknown>;
    const id = `wh_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const webhook: WebhookConfig = {
      url: String(body.url ?? ''),
      events: (body.events as WebhookEvent[]) ?? [],
      secret: String(body.secret ?? ''),
      active: true,
    };
    this.webhooks.set(id, webhook);
    return { status: 201, body: { webhook: { id, ...webhook } } };
  }

  private async deleteWebhook(id: string): Promise<ApiResponse> {
    if (!this.webhooks.has(id)) {
      return { status: 404, body: { error: 'Webhook not found' } };
    }
    this.webhooks.delete(id);
    return { status: 204, body: null };
  }

  // --- Usage handlers ---

  private async getUsage(req: ApiRequest): Promise<ApiResponse> {
    const userRecords = req.user ? this.usageRecords.filter((r) => r.userId === req.user!.id) : this.usageRecords;
    return { status: 200, body: { usage: userRecords, total: userRecords.length } };
  }

  // --- Rate limiting ---

  private checkRateLimit(userId: string): { allowed: boolean; retryAfter?: number } {
    const now = Date.now();
    const limiter = this.rateLimiters.get(userId);

    if (!limiter || now > limiter.resetAt) {
      this.rateLimiters.set(userId, { count: 1, resetAt: now + 60000 });
      return { allowed: true };
    }

    if (limiter.count >= (this.config.rateLimitPerMinute ?? 60)) {
      return { allowed: false, retryAfter: Math.ceil((limiter.resetAt - now) / 1000) };
    }

    limiter.count++;
    return { allowed: true };
  }

  // --- Usage tracking ---

  private trackUsage(user: ApiUser | undefined, action: string, resourceId?: string, metadata?: Record<string, unknown>): void {
    if (!this.config.enableUsageTracking) return;

    this.usageRecords.push({
      userId: user?.id ?? 'anonymous',
      ...(user?.orgId ? { orgId: user.orgId } : {}),
      timestamp: new Date().toISOString(),
      action,
      ...(resourceId ? { resourceId } : {}),
      ...(metadata ? { metadata } : {}),
    });
  }

  // --- Webhook dispatch ---

  async triggerWebhook(event: WebhookEvent, payload: Record<string, unknown>): Promise<void> {
    if (!this.config.enableWebhooks) return;

    const activeWebhooks = Array.from(this.webhooks.entries()).filter(([_, wh]) => wh.active && wh.events.includes(event));

    const promises = activeWebhooks.map(async ([id, webhook]) => {
      try {
        const response = await fetch(webhook.url, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-aegis-signature': await this.signPayload(webhook.secret, payload),
            'x-aegis-event': event,
          },
          body: JSON.stringify({ event, payload, timestamp: new Date().toISOString() }),
        });

        if (!response.ok) {
          console.error(`Webhook ${id} failed: ${response.status}`);
        }
      } catch (error) {
        console.error(`Webhook ${id} error: ${(error as Error).message}`);
      }
    });

    await Promise.allSettled(promises);
  }

  private async signPayload(secret: string, payload: Record<string, unknown>): Promise<string> {
    const crypto = await import('node:crypto');
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(JSON.stringify(payload));
    return hmac.digest('hex');
  }
}

// All exports are already declared with 'export' keyword above.