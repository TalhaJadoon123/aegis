import { readdir, readFile, stat } from 'node:fs/promises';
import { extname, join, relative, resolve, sep } from 'node:path';
import { IgnoreMatcher } from './ignore.js';

/** Directories never worth walking. */
export const DEFAULT_IGNORE = [
  'node_modules',
  '.git',
  '.hg',
  '.svn',
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  '.turbo',
  '.cache',
  'coverage',
  'vendor',
  '__pycache__',
  '.venv',
  'venv',
  'env',
  '.env',
  'site-packages',
  '.idea',
  '.vscode-test',
  'target',
  '.gradle',
  'Pods',
  'DerivedData',
  '.aegis',
  '.terraform',
  'bower_components',
  '*.egg-info',
  '.mypy_cache',
  '.pytest_cache',
  'storybook-static',
  '.vercel',
  '.netlify',
];

const TEXT_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts',
  '.py', '.pyi', '.go', '.rb', '.rs', '.java', '.kt', '.php', '.cs', '.c', '.h', '.cc', '.cpp', '.hpp',
  '.json', '.jsonc', '.yaml', '.yml', '.toml', '.ini', '.env', '.md', '.mdx', '.txt', '.sh', '.bash',
  '.zsh', '.ps1', '.sql', '.graphql', '.proto', '.tf', '.hcl', '.dockerfile', '.tfvars',
  '.prompt', '.txt', '.xml', '.html', '.css', '.svelte', '.vue', '.ex', '.exs', '.clj', '.lua',
]);

/** Extensions worth parsing for secrets and injections. */
export const SECRET_SCAN_EXTENSIONS = new Set([...TEXT_EXTENSIONS, '.pem', '.key', '.p12', '.pfx', '.crt']);

export interface WalkOptions {
  root: string;
  /** Absolute paths to skip. */
  ignore?: string[];
  /** Extra ignore glob-ish names. */
  ignoreNames?: string[];
  maxFileSizeBytes?: number;
  maxFiles?: number;
  includeExtensions?: Set<string>;
  followSymlinks?: boolean;
  signal?: AbortSignal;
  /**
   * Respect `.aegisignore` / `.gitignore`. Default true — a scanner that
   * cannot be told to look away from a directory will eventually be switched
   * off entirely.
   */
  useIgnoreFiles?: boolean;
  /** Pre-built matcher, to avoid re-reading ignore files per scan. */
  ignoreMatcher?: {
    ignores(absolutePath: string): boolean;
    enterDirectory?(absolutePath: string, isDirectory: boolean): boolean;
  };
}

export interface WalkedFile {
  /** Absolute path. */
  absolutePath: string;
  /** Path relative to `root`, using forward slashes. */
  path: string;
  extension: string;
  size: number;
  language: string;
}

export async function walkFiles(options: WalkOptions): Promise<WalkedFile[]> {
  const root = resolve(options.root);
  const maxSize = options.maxFileSizeBytes ?? 2_000_000;
  const maxFiles = options.maxFiles ?? 50_000;
  const ignoreNames = new Set([...(options.ignore ?? DEFAULT_IGNORE), ...(options.ignoreNames ?? [])]);
  const out: WalkedFile[] = [];

  const queue: string[] = [root];
  // `.aegisignore` and `.gitignore` are honoured unless explicitly disabled.
  const matcher =
    options.ignoreMatcher ??
    (options.useIgnoreFiles === false ? null : new IgnoreMatcher(root));
  while (queue.length > 0 && out.length < maxFiles) {
    if (options.signal?.aborted) break;
    const dir = queue.shift()!;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue; // unreadable directory (permissions, race) — skip
    }
    for (const entry of entries) {
      if (ignoreNames.has(entry.name)) continue;
      const abs = join(dir, entry.name);
      // Nested `.aegisignore` files apply from their own directory down, so a
      // vendored rules directory can opt out without the root file listing it.
      if (matcher && matcher.enterDirectory?.(abs, entry.isDirectory())) continue;
      if (matcher?.ignores(abs)) continue;
      let isDir = entry.isDirectory();
      let isFile = entry.isFile();
      if (entry.isSymbolicLink()) {
        if (!options.followSymlinks) continue;
        try {
          const st = await stat(abs);
          isDir = st.isDirectory();
          isFile = st.isFile();
        } catch {
          continue;
        }
      }
      if (isDir) {
        queue.push(abs);
        continue;
      }
      if (!isFile) continue;
      const ext = extname(entry.name).toLowerCase();
      if (options.includeExtensions && !options.includeExtensions.has(ext)) continue;
      if (!options.includeExtensions && !isTextFile(entry.name, ext)) continue;
      let size = 0;
      try {
        size = (await stat(abs)).size;
      } catch {
        continue;
      }
      if (size > maxSize) continue;
      out.push({
        absolutePath: abs,
        path: relative(root, abs).split(sep).join('/'),
        extension: ext,
        size,
        language: detectLanguage(entry.name, ext),
      });
      if (out.length >= maxFiles) break;
    }
  }
  return out;
}

function isTextFile(name: string, ext: string): boolean {
  if (TEXT_EXTENSIONS.has(ext)) return true;
  const base = name.toLowerCase();
  if (base === 'dockerfile' || base === 'makefile' || base === '.env' || base.startsWith('.env.')) {
    return true;
  }
  if (base.endsWith('dockerfile')) return true;
  if (base.startsWith('.env')) return true;
  if (ext === '' && !base.includes('.')) return true; // extensionless scripts
  return false;
}

/** Map a filename to the language label used for rule selection. */
export function detectLanguage(name: string, ext?: string): string {
  const e = ext ?? extname(name).toLowerCase();
  switch (e) {
    case '.ts':
    case '.mts':
    case '.cts':
      return 'typescript';
    case '.tsx':
      return 'tsx';
    case '.js':
    case '.mjs':
    case '.cjs':
      return 'javascript';
    case '.jsx':
      return 'jsx';
    case '.py':
    case '.pyi':
      return 'python';
    case '.go':
      return 'go';
    case '.json':
    case '.jsonc':
      return 'json';
    case '.yaml':
    case '.yml':
      return 'yaml';
    case '.toml':
      return 'toml';
    case '.md':
    case '.mdx':
      return 'markdown';
    case '.tf':
    case '.hcl':
    case '.tfvars':
      return 'terraform';
    case '.sh':
    case '.bash':
    case '.zsh':
      return 'shell';
    case '.ps1':
      return 'powershell';
    case '.sql':
      return 'sql';
    case '.html':
      return 'html';
    case '.prompt':
      return 'prompt';
    case '':
      return name.toLowerCase() === 'dockerfile' ? 'dockerfile' : 'text';
    default:
      return e.slice(1) || 'text';
  }
}

export interface LoadedFile extends WalkedFile {
  content: string;
  json?: unknown;
  /** Set when the file could not be parsed as JSON. */
  jsonError?: string;
}

export async function loadFile(file: WalkedFile): Promise<LoadedFile> {
  const content = await readFile(file.absolutePath, 'utf8');
  const loaded: LoadedFile = { ...file, content };
  if (file.language === 'json') {
    try {
      // Tolerate JSONC (comments, trailing commas) in tsconfig-style files.
      loaded.json = parseJsonLoose(content);
    } catch (error) {
      loaded.jsonError = (error as Error).message;
    }
  }
  return loaded;
}

export function parseJsonLoose(source: string): unknown {
  try {
    return JSON.parse(source);
  } catch {
    const stripped = source
      .replace(/\\"|"(?:\\"|[^"])*"|(\/\/.*|\/\*[\s\S]*?\*\/)/g, (m, comment) => (comment ? '' : m))
      .replace(/,(\s*[}\]])/g, '$1');
    return JSON.parse(stripped);
  }
}

export async function loadFiles(files: readonly WalkedFile[]): Promise<LoadedFile[]> {
  const out: LoadedFile[] = [];
  for (const file of files) {
    try {
      out.push(await loadFile(file));
    } catch {
      // Skip unreadable/binary files rather than failing the scan.
    }
  }
  return out;
}

export function isProbablyBinary(content: string): boolean {
  const probe = content.slice(0, 4096);
  let suspicious = 0;
  for (let i = 0; i < probe.length; i++) {
    const code = probe.charCodeAt(i);
    if (code === 0) return true;
    if (code < 9 || (code > 13 && code < 32)) suspicious++;
  }
  return probe.length > 0 && suspicious / probe.length > 0.3;
}
