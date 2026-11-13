import { readdir, readFile } from 'node:fs/promises';
import { existsSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseRulePack, RuleValidationError } from './loader.js';
import { RuleSet } from './evaluator.js';
import { findRuleDirectories } from '../rule-paths.js';
import type { RulePack } from '../types.js';

export interface LoadRulePacksOptions {
  /** Explicit rule pack file paths. Takes precedence over directories. */
  files?: string[];
  /** Directories to scan for `*.yaml` rule packs. */
  directories?: string[];
  /** Pack ids to exclude. */
  exclude?: string[];
  /** Fail the whole load if any pack is invalid. Default true. */
  strict?: boolean;
  logger?: { warn(m: string, meta?: unknown): void; debug?(m: string, meta?: unknown): void };
}

export interface LoadedRules {
  rules: RuleSet;
  packs: RulePack[];
  errors: string[];
  /** Source paths, in load order. */
  sources: string[];
}

/** Default search locations, covering the shipped packs and user overrides. */
export function defaultRuleDirectories(startFrom = process.cwd()): string[] {
  // The bundled packs are found relative to *this module*, which is always
  // inside the install tree. Searching only relative to the working directory
  // broke the published package: running `aegis scan /some/project` from
  // anywhere but the repo root found zero rules and reported a clean tree.
  const bundled = findRuleDirectories();
  const dirs: string[] = [...bundled];

  // Also search upward from the scan target, so a fork keeps working when its
  // packs live beside the code rather than inside the install tree.
  let dir = resolve(startFrom);
  for (let i = 0; i < 8; i++) {
    dirs.push(join(dir, 'rules'));
    dirs.push(join(dir, 'rules', 'rules'));
    dirs.push(join(dir, 'packages', 'rules', 'rules'));
    dirs.push(join(dir, '.aegis', 'rules'));
    const parent = resolve(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }

  const seen = new Set<string>();
  return dirs.filter((d) => {
    if (!existsSync(d) || seen.has(d)) return false;
    seen.add(d);
    return containsRules(d);
  });
}

/** A directory only counts if it actually contains rule packs. */
function containsRules(dir: string): boolean {
  try {
    return readdirSync(dir).some((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
  } catch {
    return false;
  }
}

export async function loadRulePacks(options: LoadRulePacksOptions = {}): Promise<LoadedRules> {
  const packs: RulePack[] = [];
  const errors: string[] = [];
  const sources: string[] = [];
  const seenIds = new Set<string>();

  const loadFile = async (path: string): Promise<void> => {
    let source: string;
    try {
      source = await readFile(path, 'utf8');
    } catch (error) {
      errors.push(`could not read ${path}: ${(error as Error).message}`);
      return;
    }
    let pack: RulePack;
    try {
      pack = parseRulePack(source, path);
    } catch (error) {
      const message = error instanceof RuleValidationError ? error.message : String(error);
      errors.push(`invalid rule pack ${path}: ${message}`);
      if (options.strict) throw error;
      return;
    }
    if (options.exclude?.includes(pack.id)) return;

    // Duplicate ids across packs would make rule suppression ambiguous.
    const collisions = pack.rules.filter((r) => seenIds.has(r.id)).map((r) => r.id);
    if (collisions.length > 0) {
      errors.push(
        `${path} redefines rule id(s) already loaded: ${collisions.slice(0, 5).join(', ')}` +
          (collisions.length > 5 ? ` (+${collisions.length - 5} more)` : ''),
      );
      if (options.strict) throw new Error('duplicate rule ids across packs');
      pack = { ...pack, rules: pack.rules.filter((r) => !seenIds.has(r.id)) };
    }

    for (const rule of pack.rules) seenIds.add(rule.id);
    packs.push(pack);
    sources.push(path);
  };

  if (options.files && options.files.length > 0) {
    for (const file of options.files) await loadFile(resolve(file));
  } else {
    const dirs = options.directories ?? defaultRuleDirectories();
    const seen = new Set<string>();
    for (const dir of dirs) {
      let entries: string[];
      try {
        entries = (await readdir(dir)).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml')).sort();
      } catch {
        continue;
      }
      for (const entry of entries) {
        const full = join(dir, entry);
        if (seen.has(full)) continue;
        seen.add(full);
        await loadFile(full);
      }
      // Stop at the first directory that actually contained packs, so a user
      // fork in the repo takes precedence over any installed copy.
      if (packs.length > 0) break;
    }
  }

  options.logger?.debug?.(
    `loaded ${packs.length} rule pack(s), ${packs.reduce((n, p) => n + p.rules.length, 0)} rules`,
  );

  return { rules: new RuleSet(packs), packs, errors, sources };
}

/** Convenience for the CLI: load the shipped packs plus any user overrides. */
export async function loadDefaultRules(
  startFrom = process.cwd(),
  extraFiles: string[] = [],
): Promise<LoadedRules> {
  return loadRulePacks({
    ...(extraFiles.length > 0 ? { files: extraFiles } : {}),
    logger: { warn: () => {}, debug: () => {} },
    startFrom,
  } as LoadRulePacksOptions & { startFrom: string });
}