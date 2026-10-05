/**
 * Argument parsing.
 *
 * Aegis deliberately has no runtime dependencies, including for CLI parsing.
 * A security tool that pulls in 30 transitive packages to read its own
 * command line has a supply-chain problem, and enterprises buying a security
 * product notice that immediately.
 *
 * This supports the shapes operators actually use: `--flag`, `--key value`,
 * `--key=value`, `-abc` bundles, `--` terminators, and `--no-flag` negation.
 */

export type OptionValue = string | number | boolean;

export interface ParsedArgs {
  positionals: string[];
  /** Values are stored loosely (a `number` option keeps its numeric type). */
  options: Map<string, OptionValue[]>;
  /** Everything after a bare `--`. */
  passthrough: string[];
}

export interface OptionSpec {
  /** Long name without dashes, e.g. `min-severity`. */
  name: string;
  /** Single-character alias, e.g. `o`. */
  short?: string;
  type: 'string' | 'boolean' | 'number';
  description: string;
  /** Default applied when the option is absent. */
  default?: string | boolean | number;
  /** Placeholder shown in help for string options. */
  placeholder?: string;
}

export class ParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ParseError';
  }
}

const ALIASES: Record<string, string> = {};

export function parseArgs(argv: readonly string[], specs: readonly OptionSpec[]): ParsedArgs {
  const specByName = new Map<string, OptionSpec>();
  for (const spec of specs) {
    specByName.set(spec.name, spec);
    if (spec.short) ALIASES[spec.short] = spec.name;
  }

  const positionals: string[] = [];
  const options = new Map<string, OptionValue[]>();
  const passthrough: string[] = [];

  const push = (name: string, value: OptionValue) => {
    options.set(name, [...(options.get(name) ?? []), value]);
  };

  let i = 0;
  for (; i < argv.length; i++) {
    const arg = argv[i]!;

    if (arg === '--') {
      passthrough.push(...argv.slice(i + 1));
      break;
    }

    if (arg.startsWith('--')) {
      const body = arg.slice(2);
      const eq = body.indexOf('=');
      const rawName = eq === -1 ? body : body.slice(0, eq);
      const inlineValue = eq === -1 ? undefined : body.slice(eq + 1);

      // `--no-x` negates a boolean option.
      if (rawName.startsWith('no-')) {
        const target = rawName.slice(3);
        const spec = specByName.get(target);
        if (spec && spec.type === 'boolean') {
          push(target, false);
          continue;
        }
      }

      const spec = specByName.get(rawName);
      if (!spec) {
        throw new ParseError(`unknown option --${rawName}`);
      }

      if (spec.type === 'boolean') {
        push(spec.name, inlineValue === undefined ? true : inlineValue !== 'false');
        continue;
      }

      const value = inlineValue ?? argv[++i];
      if (value === undefined) {
        throw new ParseError(`option --${spec.name} requires a value`);
      }
      if (spec.type === 'number' && !Number.isFinite(Number(value))) {
        throw new ParseError(`option --${spec.name} requires a number, got "${value}"`);
      }
      push(spec.name, value);
      continue;
    }

    if (arg.startsWith('-') && arg.length > 1) {
      const cluster = arg.slice(1);
      for (let c = 0; c < cluster.length; c++) {
        const short = cluster[c]!;
        const name = ALIASES[short];
        if (!name) throw new ParseError(`unknown option -${short}`);
        const spec = specByName.get(name)!;

        if (spec.type === 'boolean') {
          push(spec.name, true);
          continue;
        }
        // A value-taking short option consumes the rest of the cluster, or the
        // next argument: `-o out.json`, `-oout.json`, `-o out.json`.
        const rest = cluster.slice(c + 1);
        const value = rest.length > 0 ? rest : argv[++i];
        if (value === undefined) {
          throw new ParseError(`option -${short} requires a value`);
        }
        push(spec.name, value);
        break;
      }
      continue;
    }

    positionals.push(arg);
  }

  // Apply defaults for absent options.
  for (const spec of specs) {
    if (spec.default === undefined) continue;
    if (options.has(spec.name)) continue;
    push(spec.name, spec.default);
  }

  return { positionals, options, passthrough };
}

/** Read a string option, falling back to `fallback`. */
export function getString(parsed: ParsedArgs, name: string, fallback?: string): string | undefined {
  const values = parsed.options.get(name);
  if (!values || values.length === 0) return fallback;
  const last = values[values.length - 1];
  // A number option read as a string still round-trips correctly.
  if (typeof last === 'string') return last;
  if (typeof last === 'number') return String(last);
  return fallback;
}

export function getStringList(parsed: ParsedArgs, name: string): string[] {
  const values = parsed.options.get(name);
  if (!values) return [];
  return values.flatMap((v) =>
    typeof v === 'string'
      ? v.split(',').map((s) => s.trim()).filter(Boolean)
      : typeof v === 'number'
        ? [String(v)]
        : [],
  );
}

export function getNumber(parsed: ParsedArgs, name: string, fallback?: number): number | undefined {
  const raw = getString(parsed, name);
  if (raw === undefined) return fallback;
  const value = Number(raw);
  return Number.isFinite(value) ? value : fallback;
}

export function getBoolean(parsed: ParsedArgs, name: string, fallback = false): boolean {
  const values = parsed.options.get(name);
  if (!values || values.length === 0) return fallback;
  const last = values[values.length - 1];
  if (typeof last === 'boolean') return last;
  if (typeof last === 'number') return last !== 0;
  return last !== 'false';
}

/** True when any of the given flags was passed. */
export function anyFlag(parsed: ParsedArgs, ...names: string[]): boolean {
  return names.some((n) => parsed.options.has(n));
}

/** Render an option table for `--help`. */
export function renderOptions(specs: readonly OptionSpec[]): string {
  const rows = specs.map((spec) => {
    const short = spec.short ? `-${spec.short}, ` : '    ';
    const placeholder =
      spec.type === 'string' ? ` <${spec.placeholder ?? 'value'}>` : spec.type === 'number' ? ' <n>' : '';
    return { left: `  ${short}--${spec.name}${placeholder}`, description: spec.description, spec };
  });

  const width = Math.min(38, Math.max(...rows.map((r) => r.left.length)));
  const lines: string[] = [];
  let currentSection = '';
  for (const row of rows) {
    const section = row.spec.type === 'boolean' ? '' : '';
    if (section !== currentSection) {
      currentSection = section;
    }
    const pad = ' '.repeat(Math.max(1, width - row.left.length + 2));
    const def =
      row.spec.default !== undefined && row.spec.default !== false && row.spec.default !== ''
        ? ` (default: ${String(row.spec.default)})`
        : '';
    lines.push(`${row.left}${pad}${row.description}${def}`);
  }
  return lines.join('\n');
}