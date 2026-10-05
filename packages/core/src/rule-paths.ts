import { existsSync, readdirSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Locating the bundled rule packs.
 *
 * This has to work from three very different places:
 *
 *  1. A git clone — `<repo>/packages/rules/rules/*.yaml`
 *  2. The npm tarball — `<install>/packages/rules/rules/*.yaml`
 *  3. An arbitrary working directory, because that is where a customer runs it
 *
 * (1) and (2) have the same shape, but only (1) can walk up from the cwd. The
 * reliable approach for every case is to walk up from *this module*, since it is
 * always inside the install tree no matter what the cwd is.
 */

const HERE = dirname(fileURLToPath(import.meta.url));

/** Candidate directories that might hold the shipped packs, most specific first. */
function candidates(): string[] {
  const out: string[] = [];
  const push = (p: string) => { if (existsSync(p)) out.push(p); };

  // Walk up from this module: works in a clone and in a tarball alike.
  let dir = HERE;
  for (let i = 0; i < 10; i++) {
    push(join(dir, 'rules'));                      // <repo>/packages/rules/rules
    push(join(dir, 'packages', 'rules', 'rules')); // <repo>/packages/rules/rules
    push(join(dir, 'node_modules', '@aegis', 'rules', 'rules'));
    push(join(dir, 'node_modules', 'aegis', 'packages', 'rules', 'rules'));
    const parent = resolve(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }

  return [...new Set(out)];
}

/** Directories that actually contain rule files. */
export function findRuleDirectories(from = HERE): string[] {
  const out: string[] = [];
  for (const candidate of candidates()) {
    try {
      const entries = readdirSync(candidate) as unknown as string[];
      if (entries.some((f) => f.endsWith('.yaml') || f.endsWith('.yml'))) out.push(candidate);
    } catch {
      // Not readable, or it disappeared mid-walk; try the next candidate.
    }
  }
  void from;
  return out;
}

/** Absolute path to the directory holding the shipped rule packs, if found. */
export function bundledRulesDirectory(): string | null {
  const dirs = findRuleDirectories();
  return dirs.length > 0 ? dirs[0]! : null;
}

/**
 * Resolve rule-pack directories for a scan.
 *
 * Order: explicit caller options, then the bundled packs, then the search
 * relative to the scan target. Returning `null` rather than an empty list is
 * deliberate — the caller must be able to tell "nothing configured" from
 * "nothing found", because those are different failures.
 */
export async function resolveRuleDirectories(options: {
  cwd?: string;
  explicitDirs?: string[];
} = {}): Promise<string[]> {
  if (options.explicitDirs && options.explicitDirs.length > 0) {
    return options.explicitDirs.map((d) => resolve(options.cwd ?? process.cwd(), d));
  }
  return findRuleDirectories();
}

/** Load the shipped packs directly, bypassing the directory search. */
export async function loadBundledPacks(): Promise<string[]> {
  const dir = bundledRulesDirectory();
  if (!dir) return [];
  try {
    const entries = await readdir(dir);
    return entries.filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
      .map((f) => join(dir, f));
  } catch {
    return [];
  }
}

/** Read a bundled rule file, for the `aegis rules` style commands. */
export async function readBundledRule(name: string): Promise<string | null> {
  const dir = bundledRulesDirectory();
  if (!dir) return null;
  const path = join(dir, name.endsWith('.yaml') ? name : `${name}.yaml`);
  try {
    return await readFile(path, 'utf8');
  } catch {
    return null;
  }
}