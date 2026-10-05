import { existsSync, readFileSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';

/**
 * Ignore files.
 *
 * A scanner that flags its own intentionally-vulnerable demo fixtures is
 * useless in a demo, and a scanner that cannot be told to look away from a
 * directory will eventually be switched off entirely. So ignore files are a
 * first-class feature, not a workaround.
 *
 * Two sources, both respected everywhere:
 *   - `.aegisignore` (gitignore-style)
 *   - inline `aegis:ignore` / `aegis:ignore[rule-id]` comments
 *
 * Ignored paths are excluded from scanning entirely. Inline suppressions
 * silence one rule on one line and are reported separately, so a reviewer can
 * see what was silenced rather than discovering it by absence.
 */

export interface IgnoreRule {
  pattern: string;
  negated: boolean;
  regex: RegExp;
  /** Only applies to directories, for a trailing-slash pattern. */
  dirOnly: boolean;
  source: string;
  line: number;
}

export interface Suppression {
  ruleId?: string;
  reason?: string;
  file: string;
  line: number;
}

/** Parse a gitignore-style file. */
export function parseIgnoreFile(content: string, source: string): IgnoreRule[] {
  const out: IgnoreRule[] = [];
  content.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith('#')) return;
    const negated = line.startsWith('!');
    const pattern = negated ? line.slice(1).trim() : line;
    if (!pattern) return;
    out.push({
      pattern,
      negated,
      regex: globToRegExp(pattern),
      dirOnly: pattern.endsWith('/'),
      source,
      line: i + 1,
    });
  });
  return out;
}

/**
 * Translate a glob to a regular expression.
 *
 * Supports `*`, `**`, `?`, character classes and a leading `/` anchor, which is
 * the subset of gitignore syntax people actually use.
 */
export function globToRegExp(glob: string): RegExp {
  // A trailing slash means "this directory and everything under it". Stripping
  // it here is what makes `demos/` actually exclude
  // `demos/vulnerable-server.mjs` -- the naive form anchored at `demos/` and
  // matched the directory but none of its contents.
  const isDirPattern = glob.endsWith('/');
  const cleaned = isDirPattern ? glob.slice(0, -1) : glob;

  let re = '';
  let i = 0;
  while (i < cleaned.length) {
    const c = cleaned[i]!;
    if (c === '*') {
      if (cleaned[i + 1] === '*') {
        // `**/` matches any number of directories, including none.
        if (cleaned[i + 2] === '/') { re += '(?:.*/)?'; i += 3; continue; }
        re += '.*';
        i += 2;
        continue;
      }
      re += '[^/]*';
      i++;
      continue;
    }
    if (c === '?') { re += '[^/]'; i++; continue; }
    if (c === '/') { re += '/'; i++; continue; }
    if (c === '[') {
      const end = cleaned.indexOf(']', i + 1);
      if (end === -1) { re += '\\['; i++; continue; }
      re += cleaned.slice(i, end + 1);
      i = end + 1;
      continue;
    }
    re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    i++;
  }

  // A leading `/` anchors to the scan root. Otherwise the pattern matches at
  // any depth, which is gitignore's behaviour for a bare `*.log`.
  const anchored = cleaned.startsWith('/');
  // `**/` already carries its own `(?:.*/)?` prefix, so the implicit one would
  // be duplicated.
  const needsPrefix = !anchored && !re.startsWith('(?:.*/)?');
  const body = anchored ? re.slice(1) : needsPrefix ? `(?:.*/)?${re}` : re;
  return new RegExp(`^${body}(?:/.*)?$`, 'i');
}

/** Escape a literal path segment for embedding in a glob. */
function escapeSegment(segment: string): string {
  return segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Loader that resolves paths against a scan root and caches the ignore files.
 */
export class IgnoreMatcher {
  private readonly rules: IgnoreRule[] = [];
  /** Rules from a nested `.aegisignore`, keyed by the directory it scopes. */
  private readonly scopedDirs = new Map<string, IgnoreRule[]>();
  private readonly scannedDirs = new Set<string>();
  readonly files: string[] = [];

  private readonly root: string;

  constructor(root: string) {
    this.root = root;
    this.load(join(root, '.aegisignore'));
    this.load(join(root, '.gitignore'));
    // Never scan Aegis's own generated output or install artefacts.
    this.addBuiltins();
  }

  private addBuiltins(): void {
    for (const dir of ['.aegis', 'node_modules', 'dist', 'build', '.next', 'coverage', '.turbo', '__pycache__', '.git']) {
      this.add(`${dir}/`);
    }
  }

  private add(pattern: string): void {
    this.rules.push({
      pattern,
      negated: false,
      regex: globToRegExp(pattern),
      dirOnly: pattern.endsWith('/'),
      source: 'built-in',
      line: 0,
    });
  }

  private load(path: string): void {
    if (!existsSync(path)) return;
    if (this.scannedDirs.has(path)) return;
    this.scannedDirs.add(path);
    this.files.push(path);
    try {
      this.rules.push(...parseIgnoreFile(readFileSync(path, 'utf8'), path));
    } catch {
      // An unreadable ignore file should not fail the scan.
    }
  }

  /**
   * Called by the walker when it enters a directory. Loads any `.aegisignore`
   * scoped to that directory and reports whether the directory is itself
   * excluded, so a vendored subtree can opt out without the root file listing it.
   */
  enterDirectory(absolutePath: string, isDirectory: boolean): boolean {
    const ignoreFile = join(absolutePath, '.aegisignore');
    if (existsSync(ignoreFile)) {
      try {
        const parsed = parseIgnoreFile(readFileSync(ignoreFile, 'utf8'), ignoreFile);
        this.scopedDirs.set(absolutePath, parsed);
        this.files.push(ignoreFile);
      } catch {
        // Unreadable nested ignore file: carry on rather than fail the scan.
      }
    }
    if (!isDirectory) return false;
    if (this.ignores(absolutePath)) {
      this.scopedDirs.delete(absolutePath);
      return true;
    }
    return false;
  }

  /** Should this absolute path be scanned? */
  ignores(absolutePath: string): boolean {
    const rel = this.relative(absolutePath);
    if (!rel) return false;

    // Rules scoped to this directory, or an ancestor of it, take precedence.
    const scoped = this.scopedFor(rel);

    let ignored = false;
    // Later rules win, matching gitignore semantics.
    for (const rule of [...this.rules, ...scoped]) {
      if (!rule.regex.test(rel)) continue;
      ignored = !rule.negated;
    }
    return ignored;
  }

  /**
   * Nested rules that apply to a path, with each rule re-based onto the full
   * relative path so a scoped `*` means "everything under my directory".
   */
  private scopedFor(rel: string): IgnoreRule[] {
    const out: IgnoreRule[] = [];
    const segments = rel.split('/');
    for (let depth = segments.length - 1; depth >= 0; depth--) {
      const prefix = segments.slice(0, depth);
      const dir = this.root + sep + prefix.join(sep);
      const rules = this.scopedDirs.get(dir);
      if (!rules) continue;

      const prefixRe = prefix.length > 0 ? prefix.map(escapeSegment).join('/') + '/' : '';
      for (const rule of rules) {
        out.unshift({
          ...rule,
          // A rule anchored with `/` is relative to its own directory.
          regex: globToRegExp(
            rule.pattern.startsWith('/') ? `${prefixRe}${rule.pattern.slice(1)}` : rule.pattern,
          ),
        });
      }
    }
    return out;
  }

  private relative(absolutePath: string): string | null {
    const rel = relative(this.root, resolve(absolutePath));
    if (!rel || rel.startsWith('..')) return null;
    return rel.split(sep).join('/');
  }
}

/**
 * Inline suppressions, read from source lines.
 *
 * `// aegis:ignore` silences every rule on that line;
 * `// aegis:ignore[ASI02-001, ASI02-004]` silences named rules.
 */
export function parseSuppressions(file: string, content: string): Suppression[] {
  const out: Suppression[] = [];
  content.split(/\r?\n/).forEach((line, i) => {
    const m = /\baegis:ignore(\[[^\]]*\])?\s*(?:--\s*(.*))?$/.exec(line.trim());
    if (!m) return;
    const ruleIds = m[1]
      ? m[1].replace(/[[\]]/g, '').split(',').map((s) => s.trim()).filter(Boolean)
      : undefined;
    out.push({
      ...(ruleIds ? { ruleId: ruleIds.join(',') } : {}),
      ...(m[2] ? { reason: m[2].trim() } : {}),
      file,
      line: i + 1,
    });
  });
  return out;
}

export interface ApplySuppressionsInput {
  findings: Array<{ ruleId: string; location: { file?: string; line?: number } }>;
  /** Map of file path to file contents, for files that were scanned. */
  contents: Map<string, string>;
  fileOf: (finding: { location: { file?: string } }) => string | undefined;
}

/**
 * Remove suppressed findings and return them so the report can show what was
 * silenced. Hiding a suppression entirely is how teams lose trust in a tool.
 */
export function applySuppressions<T extends { ruleId: string; location: { file?: string; line?: number } }>(
  findings: readonly T[],
  contents: Map<string, string>,
): { kept: T[]; suppressed: Array<{ finding: T; reason?: string; rules?: string }> } {
  const byFile = new Map<string, Suppression[]>();
  for (const [file, content] of contents) {
    for (const s of parseSuppressions(file, content)) {
      byFile.set(file, [...(byFile.get(file) ?? []), s]);
    }
  }

  const kept: T[] = [];
  const suppressed: Array<{ finding: T; reason?: string; rules?: string }> = [];

  for (const finding of findings) {
    const file = finding.location.file;
    if (!file) { kept.push(finding); continue; }
    const line = finding.location.line;
    const matches = (byFile.get(file) ?? []).filter((s) => {
      if (line !== undefined && s.line !== line) return false;
      if (line === undefined) return false;
      if (!s.ruleId) return true;
      const ids = s.ruleId.split(',');
      return ids.includes(finding.ruleId);
    });
    if (matches.length > 0) {
      suppressed.push({
        finding,
        ...(matches[0]!.reason ? { reason: matches[0]!.reason } : {}),
        ...(matches[0]!.ruleId ? { rules: matches[0]!.ruleId } : {}),
      });
    } else {
      kept.push(finding);
    }
  }

  return { kept, suppressed };
}