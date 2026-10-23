/**
 * Scheduled Scans (Cron-based)
 *
 * Provides recurring scan scheduling for SaaS deployments.
 * Uses pure TypeScript cron parsing - no external dependencies.
 */

export interface ScheduleConfig {
  /** Cron expression (minute hour day month dayOfWeek) */
  cron: string;
  /** Target path or URL to scan */
  target: string;
  /** Scan options */
  options?: {
    minSeverity?: string;
    format?: string;
    noConnect?: boolean;
    noSpawn?: boolean;
  };
  /** Notification channels */
  notify?: {
    slack?: string;
    email?: string;
    webhook?: string;
  };
  /** Enabled/disabled */
  enabled?: boolean;
}

export interface ScheduleResult {
  scheduleId: string;
  nextRun: Date;
  lastRun?: Date;
  lastResult?: {
    findings: number;
    critical: number;
    score: number;
    grade: string;
  };
  status: 'active' | 'paused' | 'failed';
  runCount: number;
  failureCount: number;
}

export class ScanScheduler {
  private readonly schedules: Map<string, ScheduleConfig> = new Map();
  private readonly results: Map<string, ScheduleResult> = new Map();
  private readonly timers: Map<string, NodeJS.Timeout> = new Map();
  private running = false;

  /**
   * Add a new scheduled scan.
   */
  addSchedule(id: string, config: ScheduleConfig): void {
    if (this.schedules.has(id)) {
      throw new Error(`Schedule ${id} already exists`);
    }
    this.schedules.set(id, config);
    this.results.set(id, {
      scheduleId: id,
      nextRun: this.calculateNextRun(config.cron),
      status: config.enabled !== false ? 'active' : 'paused',
      runCount: 0,
      failureCount: 0,
    });

    if (config.enabled !== false) {
      this.scheduleNextRun(id);
    }
  }

  /**
   * Remove a scheduled scan.
   */
  removeSchedule(id: string): void {
    const timer = this.timers.get(id);
    if (timer) {
      clearTimeout(timer);
      this.timers.delete(id);
    }
    this.schedules.delete(id);
    this.results.delete(id);
  }

  /**
   * Pause a scheduled scan.
   */
  pause(id: string): void {
    const timer = this.timers.get(id);
    if (timer) {
      clearTimeout(timer);
      this.timers.delete(id);
    }
    const result = this.results.get(id);
    if (result) {
      result.status = 'paused';
    }
  }

  /**
   * Resume a paused scheduled scan.
   */
  resume(id: string): void {
    const config = this.schedules.get(id);
    if (!config) throw new Error(`Schedule ${id} not found`);

    const result = this.results.get(id);
    if (result) {
      result.status = 'active';
      result.nextRun = this.calculateNextRun(config.cron);
    }
    this.scheduleNextRun(id);
  }

  /**
   * Get all schedules.
   */
  getSchedules(): Map<string, ScheduleConfig> {
    return new Map(this.schedules);
  }

  /**
   * Get results for a schedule.
   */
  getResult(id: string): ScheduleResult | undefined {
    return this.results.get(id);
  }

  /**
   * Get all results.
   */
  getAllResults(): ScheduleResult[] {
    return Array.from(this.results.values());
  }

  /**
   * Start the scheduler.
   */
  start(): void {
    if (this.running) return;
    this.running = true;

    for (const id of this.schedules.keys()) {
      const config = this.schedules.get(id)!;
      if (config.enabled !== false) {
        this.scheduleNextRun(id);
      }
    }
  }

  /**
   * Stop the scheduler.
   */
  stop(): void {
    this.running = false;
    for (const timer of this.timers.values()) {
      clearTimeout(timer);
    }
    this.timers.clear();
  }

  /**
   * Calculate the next run time from a cron expression.
   */
  private calculateNextRun(cron: string): Date {
    const now = new Date();
    const parts = cron.split(' ');
    const [minute, hour, dayOfMonth, month, dayOfWeek] = parts;

    // Simple implementation - runs at the specified minute/hour
    // For full cron support, use a proper cron library
    const next = new Date(now);
    next.setSeconds(0);
    next.setMilliseconds(0);

    // Parse minute
    const minuteVal = minute === '*' ? now.getMinutes() : parseInt(minute ?? '0', 10);
    next.setMinutes(minuteVal);

    // Parse hour
    const hourVal = hour === '*' ? now.getHours() : parseInt(hour ?? '0', 10);
    next.setHours(hourVal);

    // If the time has already passed today, schedule for tomorrow
    if (next <= now) {
      next.setDate(next.getDate() + 1);
    }

    return next;
  }

  /**
   * Schedule the next run for a given schedule ID.
   */
  private scheduleNextRun(id: string): void {
    const config = this.schedules.get(id);
    const result = this.results.get(id);
    if (!config || !result) return;

    const delay = result.nextRun.getTime() - Date.now();
    if (delay < 0) {
      // Schedule has expired, recalculate
      result.nextRun = this.calculateNextRun(config.cron);
      this.scheduleNextRun(id);
      return;
    }

    const timer = setTimeout(() => {
      this.executeSchedule(id);
    }, delay);

    this.timers.set(id, timer);
  }

  /**
   * Execute a scheduled scan.
   */
  private async executeSchedule(id: string): Promise<void> {
    const config = this.schedules.get(id);
    const result = this.results.get(id);
    if (!config || !result) return;

    result.runCount++;
    result.lastRun = new Date();

    try {
      // This would call the actual scan function
      // For now, we just log the execution
      console.log(`[Scheduler] Executing scan: ${id} -> ${config.target}`);

      // Simulate scan result
      result.lastResult = {
        findings: 0,
        critical: 0,
        score: 100,
        grade: 'A',
      };

      // Update next run
      result.nextRun = this.calculateNextRun(config.cron);
      result.status = 'active';

      // Schedule next run
      this.scheduleNextRun(id);

      // Send notifications if configured
      if (config.notify) {
        await this.sendNotifications(config, result);
      }
    } catch (error) {
      result.failureCount++;
      result.status = 'failed';
      console.error(`[Scheduler] Scan failed: ${id}`, error);
    }
  }

  /**
   * Send notifications after a scan.
   */
  private async sendNotifications(config: ScheduleConfig, result: ScheduleResult): Promise<void> {
    if (config.notify?.slack) {
      // Send Slack notification
      console.log(`[Scheduler] Sending Slack notification to ${config.notify.slack}`);
    }
    if (config.notify?.email) {
      // Send email notification
      console.log(`[Scheduler] Sending email notification to ${config.notify.email}`);
    }
    if (config.notify?.webhook) {
      // Send webhook notification
      console.log(`[Scheduler] Sending webhook notification to ${config.notify.webhook}`);
    }
  }
}

/**
 * Parse a cron expression and validate it.
 */
export function validateCron(cron: string): { valid: boolean; error?: string } {
  const parts = cron.split(' ');
  if (parts.length !== 5) {
    return { valid: false, error: 'Cron expression must have 5 fields: minute hour day month dayOfWeek' };
  }

  const [minute, hour, dayOfMonth, month, dayOfWeek] = parts;

  // Validate minute (0-59 or *)
  if (minute !== '*' && (isNaN(Number(minute)) || Number(minute) < 0 || Number(minute) > 59)) {
    return { valid: false, error: 'Minute must be 0-59 or *' };
  }

  // Validate hour (0-23 or *)
  if (hour !== '*' && (isNaN(Number(hour)) || Number(hour) < 0 || Number(hour) > 23)) {
    return { valid: false, error: 'Hour must be 0-23 or *' };
  }

  // Validate day of month (1-31 or *)
  if (dayOfMonth !== '*' && (isNaN(Number(dayOfMonth)) || Number(dayOfMonth) < 1 || Number(dayOfMonth) > 31)) {
    return { valid: false, error: 'Day of month must be 1-31 or *' };
  }

  // Validate month (1-12 or *)
  if (month !== '*' && (isNaN(Number(month)) || Number(month) < 1 || Number(month) > 12)) {
    return { valid: false, error: 'Month must be 1-12 or *' };
  }

  // Validate day of week (0-6 or *)
  if (dayOfWeek !== '*' && (isNaN(Number(dayOfWeek)) || Number(dayOfWeek) < 0 || Number(dayOfWeek) > 6)) {
    return { valid: false, error: 'Day of week must be 0-6 or *' };
  }

  return { valid: true };
}

// All exports are already declared with 'export' keyword above.