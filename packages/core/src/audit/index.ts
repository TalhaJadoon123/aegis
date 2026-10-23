/**
 * Audit Logging for Aegis
 *
 * Provides immutable audit trail for all user actions, scan operations,
 * and configuration changes. Required for SOC 2, ISO 27001, GDPR compliance.
 *
 * Zero runtime dependencies - implemented in pure TypeScript.
 */

import { writeFileSync, appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

export type AuditAction =
  | 'scan.started'
  | 'scan.completed'
  | 'scan.failed'
  | 'scan.deleted'
  | 'redteam.started'
  | 'redteam.completed'
  | 'redteam.failed'
  | 'fix.applied'
  | 'fix.proposed'
  | 'report.generated'
  | 'config.updated'
  | 'user.login'
  | 'user.logout'
  | 'user.created'
  | 'user.updated'
  | 'user.deleted'
  | 'org.created'
  | 'org.updated'
  | 'org.deleted'
  | 'webhook.created'
  | 'webhook.deleted'
  | 'webhook.triggered'
  | 'api.key.created'
  | 'api.key.revoked'
  | 'dashboard.accessed'
  | 'finding.suppressed'
  | 'finding.accepted';

export interface AuditRecord {
  id: string;
  timestamp: string;
  action: AuditAction;
  actor: {
    id: string;
    type: 'user' | 'system' | 'api-key' | 'service-account';
    name?: string;
    orgId?: string;
  };
  resource: {
    type: string;
    id: string;
    name?: string;
  };
  details?: Record<string, unknown>;
  ip?: string;
  userAgent?: string;
  requestId?: string;
  result: 'success' | 'failure' | 'partial';
  metadata?: Record<string, unknown>;
}

export interface AuditQuery {
  actorId?: string;
  action?: AuditAction | AuditAction[];
  resourceType?: string;
  resourceId?: string;
  startDate?: string;
  endDate?: string;
  result?: 'success' | 'failure' | 'partial';
  limit?: number;
  offset?: number;
}

export class AuditLogger {
  private readonly logDir: string;
  private readonly logFile: string;
  private readonly records: AuditRecord[] = [];
  private readonly maxMemoryRecords: number;

  constructor(logDir: string = '.aegis/audit', maxMemoryRecords: number = 10000) {
    this.logDir = resolve(logDir);
    this.logFile = join(this.logDir, 'audit.jsonl');
    this.maxMemoryRecords = maxMemoryRecords;

    // Ensure log directory exists
    if (!existsSync(this.logDir)) {
      mkdirSync(this.logDir, { recursive: true });
    }
  }

  /**
   * Log an audit record.
   */
  log(record: Omit<AuditRecord, 'id' | 'timestamp'>): AuditRecord {
    const fullRecord: AuditRecord = {
      id: `audit_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      timestamp: new Date().toISOString(),
      ...record,
    };

    // Write to file (append-only, immutable)
    appendFileSync(this.logFile, JSON.stringify(fullRecord) + '\n', 'utf8');

    // Keep in memory (bounded)
    this.records.push(fullRecord);
    if (this.records.length > this.maxMemoryRecords) {
      this.records.shift();
    }

    return fullRecord;
  }

  /**
   * Query audit records.
   */
  query(q: AuditQuery = {}): AuditRecord[] {
    let results = [...this.records];

    if (q.actorId) {
      results = results.filter((r) => r.actor.id === q.actorId);
    }
    if (q.action) {
      const actions = Array.isArray(q.action) ? q.action : [q.action];
      results = results.filter((r) => actions.includes(r.action));
    }
    if (q.resourceType) {
      results = results.filter((r) => r.resource.type === q.resourceType);
    }
    if (q.resourceId) {
      results = results.filter((r) => r.resource.id === q.resourceId);
    }
    if (q.startDate) {
      results = results.filter((r) => r.timestamp >= q.startDate!);
    }
    if (q.endDate) {
      results = results.filter((r) => r.timestamp <= q.endDate!);
    }
    if (q.result) {
      results = results.filter((r) => r.result === q.result);
    }

    const offset = q.offset ?? 0;
    const limit = q.limit ?? 100;
    return results.slice(offset, offset + limit);
  }

  /**
   * Get audit records from file (for cold storage queries).
   */
  queryFromFile(q: AuditQuery = {}): AuditRecord[] {
    if (!existsSync(this.logFile)) return [];

    const content = readFileSync(this.logFile, 'utf8');
    const lines = content.trim().split('\n').filter(Boolean);
    let records: AuditRecord[] = lines.map((line) => JSON.parse(line));

    if (q.actorId) {
      records = records.filter((r) => r.actor.id === q.actorId);
    }
    if (q.action) {
      const actions = Array.isArray(q.action) ? q.action : [q.action];
      records = records.filter((r) => actions.includes(r.action));
    }
    if (q.resourceType) {
      records = records.filter((r) => r.resource.type === q.resourceType);
    }
    if (q.resourceId) {
      records = records.filter((r) => r.resource.id === q.resourceId);
    }
    if (q.startDate) {
      records = records.filter((r) => r.timestamp >= q.startDate!);
    }
    if (q.endDate) {
      records = records.filter((r) => r.timestamp <= q.endDate!);
    }
    if (q.result) {
      records = records.filter((r) => r.result === q.result);
    }

    const offset = q.offset ?? 0;
    const limit = q.limit ?? 100;
    return records.slice(offset, offset + limit);
  }

  /**
   * Get audit statistics.
   */
  getStats(): {
    totalRecords: number;
    memoryRecords: number;
    fileExists: boolean;
    fileSize: number;
    actions: Record<string, number>;
    actors: Record<string, number>;
    results: Record<string, number>;
  } {
    const actions: Record<string, number> = {};
    const actors: Record<string, number> = {};
    const results: Record<string, number> = {};

    for (const record of this.records) {
      actions[record.action] = (actions[record.action] ?? 0) + 1;
      actors[record.actor.id] = (actors[record.actor.id] ?? 0) + 1;
      results[record.result] = (results[record.result] ?? 0) + 1;
    }

    let fileSize = 0;
    if (existsSync(this.logFile)) {
      const stats = require('node:fs').statSync(this.logFile);
      fileSize = stats.size;
    }

    return {
      totalRecords: this.records.length,
      memoryRecords: this.records.length,
      fileExists: existsSync(this.logFile),
      fileSize,
      actions,
      actors,
      results,
    };
  }

  /**
   * Export audit records to a file (for compliance/auditors).
   */
  exportToFile(outputPath: string, q: AuditQuery = {}): string {
    const records = this.queryFromFile(q);
    const content = JSON.stringify(records, null, 2);
    writeFileSync(outputPath, content, 'utf8');
    return outputPath;
  }

  /**
   * Create an audit middleware for HTTP servers.
   */
  createMiddleware() {
    return (req: { method: string; url: string; headers: Record<string, string> }, res: { on: (event: string, cb: () => void) => void }, next: () => void) => {
      const start = Date.now();
      const requestId = `req_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

      req.headers['x-request-id'] = requestId;

      res.on('finish', () => {
        const duration = Date.now() - start;
        this.log({
          action: 'dashboard.accessed',
          actor: {
            id: req.headers['x-user-id'] ?? 'anonymous',
            type: 'user',
          },
          resource: {
            type: 'http',
            id: req.url,
          },
          details: {
            method: req.method,
            path: req.url,
            durationMs: duration,
          },
          result: 'success',
          requestId,
          ...(req.headers['x-forwarded-for'] ? { ip: req.headers['x-forwarded-for'] } : {}),
          ...(req.headers['user-agent'] ? { userAgent: req.headers['user-agent'] } : {}),
        });
      });

      next();
    };
  }
}

// All exports are already declared with 'export' keyword above.