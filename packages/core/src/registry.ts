import { RuleSet } from './rules/evaluator.js';
import type {
  AegisPlugin,
  Finding,
  PluginDescriptor,
  PluginRegistryLike,
  RuleDefinition,
  Scanner,
  ScanTarget,
  ScannerContext,
} from './types.js';
import { createLogger, type Logger } from './logger.js';

export interface RegistryOptions {
  logger?: Logger;
  /** Fail the whole run if a plugin throws during registration. */
  strict?: boolean;
}

/**
 * Plugin registry.
 *
 * Third-party scanners register here. Everything a plugin contributes —
 * rule packs, scanners, extra capabilities — is inspected before it is used,
 * so a malicious or broken plugin cannot silently widen Aegis' blast radius
 * without the user seeing a capability warning.
 */
export class PluginRegistry implements PluginRegistryLike {
  /**
   * Registered plugins, keyed by name. Named `registry` rather than `plugins`
   * because `PluginRegistryLike` exposes a `plugins()` method, and a field and
   * a method of the same name cannot coexist on one class.
   */
  private readonly registry = new Map<string, AegisPlugin>();
  private readonly scanners: Scanner[] = [];
  private rules = new RuleSet();
  private readonly logger: Logger;
  private readonly strict: boolean;

  constructor(options: RegistryOptions = {}) {
    this.logger = options.logger ?? createLogger({ level: 'silent' });
    this.strict = options.strict ?? false;
  }

  register(plugin: AegisPlugin): this {
    if (this.registry.has(plugin.name)) {
      throw new Error(`plugin already registered: ${plugin.name}`);
    }
    if (!plugin.version) throw new Error(`plugin ${plugin.name} is missing a version`);

    const caps = plugin.capabilities ?? {};
    const risky = [
      caps.network ? 'network' : null,
      caps.spawn ? 'process spawning' : null,
      caps.filesystem ? 'filesystem writes' : null,
    ].filter(Boolean);
    if (risky.length > 0) {
      this.logger.debug(
        `plugin ${plugin.name} requests sensitive capabilities: ${risky.join(', ')}`,
      );
    }

    try {
      plugin.activate?.();
    } catch (error) {
      if (this.strict) throw error;
      this.logger.warn(`plugin ${plugin.name} failed to activate: ${(error as Error).message}`);
      return this;
    }

    for (const pack of plugin.rulePacks ?? []) {
      try {
        this.rules = this.rules.merge(new RuleSet([pack]));
      } catch (error) {
        if (this.strict) throw error;
        this.logger.warn(`plugin ${plugin.name} contributed an invalid rule pack: ${String(error)}`);
      }
    }
    for (const scanner of plugin.scanners ?? []) {
      this.registerScanner(scanner);
    }

    this.registry.set(plugin.name, plugin);
    return this;
  }

  registerAll(plugins: readonly AegisPlugin[]): this {
    for (const p of plugins) this.register(p);
    return this;
  }

  registerScanner(scanner: Scanner): this {
    if (!scanner.name) throw new Error('scanner must have a name');
    if (typeof scanner.scan !== 'function') {
      throw new Error(`scanner ${scanner.name} does not implement scan()`);
    }
    this.scanners.push(scanner);
    return this;
  }

  unregister(name: string): boolean {
    const plugin = this.registry.get(name);
    if (!plugin) return false;
    try {
      plugin.deactivate?.();
    } catch (error) {
      this.logger.warn(`plugin ${name} failed to deactivate cleanly: ${(error as Error).message}`);
    }
    this.registry.delete(name);
    for (let i = this.scanners.length - 1; i >= 0; i--) {
      if (this.scanners[i]!.name === name) this.scanners.splice(i, 1);
    }
    return true;
  }

  getRule(id: string): RuleDefinition | undefined {
    return this.rules.get(id);
  }

  allRules(): RuleDefinition[] {
    return this.rules.all();
  }

  ruleSet(): RuleSet {
    return this.rules;
  }

  setRuleSet(rules: RuleSet): void {
    this.rules = rules;
  }

  plugins(): PluginDescriptor[] {
    return [...this.registry.values()].map((p) => ({
      name: p.name,
      version: p.version,
      description: p.description,
      author: p.author,
      capabilities: p.capabilities,
    }));
  }

  pluginScanners(): Scanner[] {
    return [...this.scanners];
  }

  /** Every scanner a run should execute: built-ins plus plugin scanners. */
  allScanners(builtins: readonly Scanner[]): Scanner[] {
    return [...builtins, ...this.scanners];
  }
}

/** Registry that resolves a scanner by name — handy in tests and plugins. */
export interface RegistryLike extends PluginRegistryLike {
  findScanner(name: string): Scanner | undefined;
}

export function findScanner(registry: PluginRegistry, name: string): Scanner | undefined {
  return registry.pluginScanners().find((s) => s.name === name);
}

/** Shared helper so plugins can stream findings without boilerplate. */
export async function* streamFindings(
  findings: readonly Finding[],
  signal?: AbortSignal,
): AsyncIterable<Finding> {
  for (const finding of findings) {
    if (signal?.aborted) return;
    yield finding;
  }
}

export type { ScanTarget, ScannerContext };
