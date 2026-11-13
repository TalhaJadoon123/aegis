/**
 * A small, dependency-free YAML subset parser.
 *
 * Aegis ships rule packs as YAML so security engineers can edit them without
 * touching code, but the engine itself must run in environments where we do not
 * want to take a dependency on a full YAML implementation (air-gapped CI,
 * minimal containers, and the MCP stdio child processes we spawn).
 *
 * This parser supports the subset rule packs actually use: nested block
 * mappings, block sequences, flow sequences and mappings, single/double quoted
 * and plain scalars, folded/literal block scalars (`>`, `|`), comments,
 * multi-document streams, anchors are *not* supported (rejected loudly).
 *
 * Anything outside the subset throws with a line number rather than silently
 * mis-parsing, so a malformed rule pack fails loudly instead of producing wrong
 * findings.
 */

export class YamlParseError extends Error {
  readonly line: number;
  readonly file?: string;

  constructor(message: string, line: number, file?: string) {
    super(`${file ? `${file}:` : ''}${line}: ${message}`);
    this.name = 'YamlParseError';
    this.line = line;
    this.file = file;
  }
}

export type YamlValue = string | number | boolean | null | YamlValue[] | { [key: string]: YamlValue };

interface Line {
  number: number;
  indent: number;
  content: string;
}

export function parseYaml(source: string, file?: string): YamlValue {
  const docs = parseYamlDocuments(source, file);
  return docs[0] ?? null;
}

export function parseYamlDocuments(source: string, file?: string): YamlValue[] {
  const documents: string[] = [];
  let current: string[] = [];
  for (const raw of source.split(/\r?\n/)) {
    if (/^---\s*$/.test(raw)) {
      documents.push(current.join('\n'));
      current = [];
      continue;
    }
    if (/^\.\.\.\s*$/.test(raw)) continue;
    current.push(raw);
  }
  documents.push(current.join('\n'));
  const results: YamlValue[] = [];
  for (const doc of documents) {
    const parsed = parseSingle(doc, file);
    if (parsed !== undefined) results.push(parsed);
  }
  return results;
}

function parseSingle(source: string, file?: string): YamlValue | undefined {
  const lines = preprocess(source, file);
  if (lines.length === 0) return undefined;
  const parser = new Parser(lines, file);
  const value = parser.parseBlock(lines[0]!.indent);
  parser.expectEnd();
  return value;
}

function preprocess(source: string, file?: string): Line[] {
  const out: Line[] = [];
  const rawLines = source.split(/\r?\n/);
  for (let i = 0; i < rawLines.length; i++) {
    const raw = rawLines[i]!;
    if (raw.includes('\t')) {
      const beforeIndent = raw.length - raw.trimStart().length;
      if (raw.slice(0, beforeIndent).includes('\t')) {
        throw new YamlParseError('tabs are not allowed for indentation', i + 1, file);
      }
    }
    const trimmedForComment = stripComment(raw);
    const indent = trimmedForComment.length - trimmedForComment.trimStart().length;
    const content = trimmedForComment.trimEnd();
    if (content.trim() === '') continue;
    if (/^\s*#/.test(content)) continue;
    out.push({ number: i + 1, indent, content: content.slice(indent) });
  }
  return out;
}

/**
 * Remove trailing comments while respecting quoting. A `#` inside a quoted
 * scalar, or a `#` not preceded by whitespace, is literal content.
 */
function stripComment(line: string): string {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (quote) {
      if (ch === '\\' && quote === '"') {
        i++;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === '#' && (i === 0 || /\s/.test(line[i - 1]!))) return line.slice(0, i);
  }
  return line;
}

class Parser {
  private index = 0;
  private readonly lines: Line[];
  private readonly file?: string;

  constructor(lines: Line[], file?: string) {
    this.lines = lines;
    this.file = file;
  }

  expectEnd(): void {
    if (this.index < this.lines.length) {
      const line = this.lines[this.index]!;
      throw new YamlParseError(`unexpected content "${line.content}"`, line.number, this.file);
    }
  }

  private peek(): Line | undefined {
    return this.lines[this.index];
  }

  parseBlock(indent: number): YamlValue {
    const first = this.peek();
    if (!first) return null;
    if (first.content.startsWith('- ') || first.content === '-') return this.parseSequence(indent);
    return this.parseMapping(indent);
  }

  private parseSequence(indent: number): YamlValue[] {
    const out: YamlValue[] = [];
    while (this.index < this.lines.length) {
      const line = this.lines[this.index]!;
      if (line.indent < indent) break;
      if (line.indent > indent) {
        throw new YamlParseError('unexpected indentation in sequence', line.number, this.file);
      }
      if (!(line.content === '-' || line.content.startsWith('- '))) break;

      const rest = line.content === '-' ? '' : line.content.slice(2).trim();
      const itemIndent = indent + 2;
      this.index++;

      if (rest === '') {
        const next = this.peek();
        if (next && next.indent > indent) {
          out.push(this.parseBlock(next.indent));
        } else {
          out.push(null);
        }
        continue;
      }

      // `- key: value` opens an inline mapping whose remaining keys are
      // indented to the column where `key` started.
      const inlineKey = this.splitKey(rest, line);
      if (inlineKey) {
        const map: Record<string, YamlValue> = {};
        const keyColumn = indent + 2;
        this.assignKey(map, inlineKey.key, inlineKey.value, line, keyColumn);
        const next = this.peek();
        if (next && next.indent >= keyColumn) {
          const rest2 = this.parseMapping(keyColumn);
          if (rest2 && typeof rest2 === 'object' && !Array.isArray(rest2)) {
            Object.assign(map, rest2);
          }
        }
        out.push(map);
        continue;
      }

      out.push(this.parseScalarOrBlock(rest, line, indent + 2));
    }
    return out;
  }

  private parseMapping(indent: number): YamlValue {
    const map: Record<string, YamlValue> = {};
    while (this.index < this.lines.length) {
      const line = this.lines[this.index]!;
      if (line.indent < indent) break;
      if (line.indent > indent) {
        throw new YamlParseError(
          `unexpected indentation (expected ${indent}, got ${line.indent})`,
          line.number,
          this.file,
        );
      }
      if (line.content.startsWith('- ')) break;
      const split = this.splitKey(line.content, line);
      if (!split) {
        throw new YamlParseError(`expected "key: value", got "${line.content}"`, line.number, this.file);
      }
      this.index++;
      this.assignKey(map, split.key, split.value, line, indent);
    }
    return map;
  }

  private assignKey(
    map: Record<string, YamlValue>,
    key: string,
    value: string,
    line: Line,
    indent: number,
  ): void {
    if (key === '<<') {
      throw new YamlParseError('merge keys are not supported', line.number, this.file);
    }
    if (key.startsWith('&') || key.startsWith('*')) {
      throw new YamlParseError('anchors and aliases are not supported', line.number, this.file);
    }
    // An explicit block scalar indicator: `|`, `>`, `|-`, `>-`.
    if (/^[|>][-+]?$/.test(value)) {
      map[key] = this.parseBlockScalar(value, line, indent);
      return;
    }

    // An empty value means "the value is the following, more-indented block".
    // This is a nested mapping or sequence, NOT a literal block scalar —
    // distinguishing the two is the whole game in YAML.
    if (value === '') {
      const next = this.peek();
      if (next && next.indent > indent) {
        map[key] = this.parseBlock(next.indent);
      } else if (next && next.indent === indent && (next.content === '-' || next.content.startsWith('- '))) {
        // A sequence may be written at the same indentation as its key.
        map[key] = this.parseSequence(indent);
      } else {
        map[key] = null;
      }
      return;
    }

    if (value.startsWith('&') || value.startsWith('*')) {
      throw new YamlParseError('anchors and aliases are not supported', line.number, this.file);
    }

    map[key] = parseScalar(value, line, this.file);
  }

  private parseBlockScalar(header: string, line: Line, indent: number): YamlValue {
    const indicator = header.trim();
    const collected: string[] = [];
    let blockIndent = -1;

    if (indicator !== '' && indicator !== '|' && indicator !== '>') {
      // Strip a chomping indicator so `>-` and `|-` are handled uniformly.
    }

    while (this.index < this.lines.length) {
      const next = this.lines[this.index]!;
      if (next.indent <= indent) break;
      if (blockIndent === -1) blockIndent = next.indent;
      collected.push(' '.repeat(Math.max(0, next.indent - blockIndent)) + next.content);
      this.index++;
    }

    if (collected.length === 0) return indicator.startsWith('>') || indicator.startsWith('|') ? '' : null;

    if (indicator.startsWith('>')) {
      // Folded: join lines with spaces, blank lines become newlines.
      const text = collected.join(' ').replace(/\s+\n/g, '\n').trimEnd();
      return indicator.includes('-') ? text : `${text}\n`;
    }
    const text = collected.join('\n');
    return indicator.includes('-') ? text : `${text}\n`;
  }

  private splitKey(content: string, line: Line): { key: string; value: string } | null {
    let quote: string | null = null;
    let depth = 0;
    for (let i = 0; i < content.length; i++) {
      const ch = content[i]!;
      if (quote) {
        if (ch === '\\' && quote === '"') {
          i++;
          continue;
        }
        if (ch === quote) quote = null;
        continue;
      }
      if (ch === '"' || ch === "'") {
        quote = ch;
        continue;
      }
      if (ch === '[' || ch === '{') depth++;
      else if (ch === ']' || ch === '}') depth--;
      else if (ch === ':' && depth === 0) {
        const next = content[i + 1];
        if (next === undefined || next === ' ' || next === '\t') {
          const key = unquote(content.slice(0, i).trim());
          if (key === '') return null;
          return { key, value: content.slice(i + 1).trim() };
        }
      }
    }
    void line;
    return null;
  }

  private parseScalarOrBlock(rest: string, line: Line, indent: number): YamlValue {
    if (rest === '|' || rest === '>' || /^[|>][-+]$/.test(rest)) return this.parseBlockScalar(rest, line, indent);
    return parseScalar(rest, line, this.file);
  }
}

function parseScalar(raw: string, line?: Line, file?: string): YamlValue {
  const text = raw.trim();
  if (text === '' || text === '~' || text === 'null' || text === 'Null' || text === 'NULL') return null;
  if (text === 'true' || text === 'True' || text === 'TRUE' || text === 'yes' || text === 'on') return true;
  if (text === 'false' || text === 'False' || text === 'FALSE' || text === 'no' || text === 'off') return false;

  if (text.startsWith('[') || text.startsWith('{')) return parseFlow(text, line, file);

  if ((text.startsWith('"') && text.endsWith('"') && text.length > 1) ||
      (text.startsWith("'") && text.endsWith("'") && text.length > 1)) {
    return unquote(text);
  }

  if (/^[-+]?\d+$/.test(text)) {
    const n = Number(text);
    return Number.isSafeInteger(n) ? n : text;
  }
  if (/^[-+]?(\d+\.\d*|\.\d+|\d+)([eE][-+]?\d+)?$/.test(text)) {
    const n = Number(text);
    return Number.isFinite(n) ? n : text;
  }
  return text;
}

function parseFlow(text: string, line?: Line, file?: string): YamlValue {
  let i = 0;
  const skipWs = () => {
    while (i < text.length && /\s/.test(text[i]!)) i++;
  };

  const parseValue = (): YamlValue => {
    skipWs();
    const ch = text[i];
    if (ch === '[') {
      i++;
      const arr: YamlValue[] = [];
      skipWs();
      if (text[i] === ']') {
        i++;
        return arr;
      }
      for (;;) {
        arr.push(parseValue());
        skipWs();
        if (text[i] === ',') {
          i++;
          skipWs();
          if (text[i] === ']') {
            i++;
            return arr;
          }
          continue;
        }
        if (text[i] === ']') {
          i++;
          return arr;
        }
        throw new YamlParseError('malformed flow sequence', line?.number ?? 0, file);
      }
    }
    if (ch === '{') {
      i++;
      const obj: Record<string, YamlValue> = {};
      skipWs();
      if (text[i] === '}') {
        i++;
        return obj;
      }
      for (;;) {
        skipWs();
        const key = parseScalarToken(':,}]');
        skipWs();
        if (text[i] !== ':') throw new YamlParseError('malformed flow mapping', line?.number ?? 0, file);
        i++;
        // Keys in flow mappings stay strings; numeric-looking keys must not
        // be coerced to numbers (JSON object keys are always strings).
        obj[key] = parseValue();
        skipWs();
        if (text[i] === ',') {
          i++;
          skipWs();
          if (text[i] === '}') {
            i++;
            return obj;
          }
          continue;
        }
        if (text[i] === '}') {
          i++;
          return obj;
        }
        throw new YamlParseError('malformed flow mapping', line?.number ?? 0, file);
      }
    }
    return parseScalarToken(',]}:');
  };

  const parseScalarToken = (stop: string): string => {
    skipWs();
    if (text[i] === '"' || text[i] === "'") {
      const quote = text[i]!;
      i++;
      let out = '';
      while (i < text.length) {
        const c = text[i]!;
        if (c === '\\' && quote === '"') {
          out += unescapeChar(text[i + 1] ?? '');
          i += 2;
          continue;
        }
        if (c === quote) {
          if (quote === "'" && text[i + 1] === "'") {
            out += "'";
            i += 2;
            continue;
          }
          i++;
          return out;
        }
        out += c;
        i++;
      }
      throw new YamlParseError('unterminated quoted scalar', line?.number ?? 0, file);
    }
    let start = i;
    while (i < text.length && !stop.includes(text[i]!)) i++;
    return text.slice(start, i).trim();
  };

  const value = parseValue();
  skipWs();
  if (i < text.length) {
    throw new YamlParseError(`trailing content "${text.slice(i)}"`, line?.number ?? 0, file);
  }
  return value;
}

function unescapeChar(ch: string): string {
  switch (ch) {
    case 'n':
      return '\n';
    case 't':
      return '\t';
    case 'r':
      return '\r';
    case '0':
      return '\0';
    case '\\':
      return '\\';
    case '"':
      return '"';
    case "'":
      return "'";
    case '/':
      return '/';
    default:
      return ch;
  }
}

function unquote(text: string): string {
  if (text.length < 2) return text;
  const quote = text[0];
  if ((quote !== '"' && quote !== "'") || text[text.length - 1] !== quote) return text;
  const inner = text.slice(1, -1);
  if (quote === "'") return inner.replace(/''/g, "'");
  return inner.replace(/\\(.)/g, (_, ch: string) => unescapeChar(ch));
}

/** Minimal YAML emitter, used by `--fix` to write corrected configs. */
export function stringifyYaml(value: YamlValue, indent = 0): string {
  const pad = ' '.repeat(indent);
  if (value === null) return 'null\n';
  if (typeof value === 'boolean' || typeof value === 'number') return `${value}\n`;
  if (typeof value === 'string') return `${quoteIfNeeded(value)}\n`;
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]\n';
    let out = '';
    for (const item of value) {
      if (item !== null && typeof item === 'object') {
        const nested = stringifyYaml(item, indent + 2);
        out += `${pad}- ${nested.slice(indent + 2)}`;
      } else {
        out += `${pad}- ${stringifyYaml(item, indent + 2).trimStart()}`;
      }
    }
    return out;
  }
  const entries = Object.entries(value);
  if (entries.length === 0) return '{}\n';
  let out = '';
  for (const [key, val] of entries) {
    if (val !== null && typeof val === 'object' && Object.keys(val as object).length > 0) {
      out += `${pad}${quoteIfNeeded(key)}:\n${stringifyYaml(val, indent + 2)}`;
    } else {
      out += `${pad}${quoteIfNeeded(key)}: ${stringifyYaml(val, 0).trimEnd()}\n`;
    }
  }
  return out;
}

function quoteIfNeeded(text: string): string {
  if (text === '') return '""';
  if (/^[\w./@-]+$/.test(text) && !/^\d+$/.test(text)) return text;
  if (/^[A-Za-z]:[\\/]/.test(text)) return `"${text}"`;
  return `"${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}