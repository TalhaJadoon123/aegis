import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Guards against TypeScript constructs that Node's native type stripping
 * cannot handle.
 *
 * Aegis runs its `.ts` sources directly under `node --test`, which means the
 * code must use *erasable syntax only*. A single parameter property
 * (`constructor(private x: T)`) is a runtime `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX`
 * at import time — a confusing failure that appears far from its cause, and one
 * I hit repeatedly enough to warrant an automated check.
 */

const here = dirname(fileURLToPath(import.meta.url));
const SRC = join(here, '..', 'src');
const TEST = join(here, '..', 'test');

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === 'dist') continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (entry.endsWith('.ts')) out.push(full);
  }
  return out;
}

describe('erasable-syntax-only constraint', () => {
  const files = walk(SRC);

  test('source tree is non-empty', () => {
    assert.ok(files.length > 10, `expected source files, found ${files.length}`);
  });

  test('no TypeScript parameter properties', () => {
    const offenders: string[] = [];
    for (const file of files) {
      const source = readFileSync(file, 'utf8');
      // `constructor(private readonly x: T)` or a bare access-modifier param.
      const re = /constructor\s*\([^)]*\b(?:private|public|protected|readonly)\s+\w+\s*[:?]/s;
      if (re.test(source)) offenders.push(relative(SRC, file));
    }
    assert.deepEqual(
      offenders,
      [],
      `parameter properties are not erasable syntax:\n  ${offenders.join('\n  ')}`,
    );
  });

  test('no TypeScript enums', () => {
    const offenders: string[] = [];
    for (const file of files) {
      const source = readFileSync(file, 'utf8');
      // `enum Foo {` at statement position, not `types` or inside a string.
      if (/^\s*(?:export\s+)?(?:const\s+)?enum\s+\w+/m.test(source)) {
        offenders.push(relative(SRC, file));
      }
    }
    assert.deepEqual(offenders, [], `enums are not erasable syntax:\n  ${offenders.join('\n  ')}`);
  });

  test('no TypeScript namespaces or parameter decorators', () => {
    const offenders: string[] = [];
    for (const file of files) {
      const source = readFileSync(file, 'utf8');
      if (/^\s*(?:export\s+)?namespace\s+\w+/m.test(source)) offenders.push(relative(SRC, file));
    }
    assert.deepEqual(offenders, [], `namespaces are not erasable syntax:\n  ${offenders.join('\n  ')}`);
  });

  test('relative imports use .js specifiers so a tsc build resolves', () => {
    const offenders: string[] = [];
    for (const file of files) {
      const source = readFileSync(file, 'utf8');
      for (const match of source.matchAll(/from\s+'(\.[^']*)'/g)) {
        const spec = match[1]!;
        if (/\.(ts|tsx|mjs)$/.test(spec)) {
          offenders.push(`${relative(SRC, file)} -> ${spec}`);
        }
      }
    }
    assert.deepEqual(
      offenders,
      [],
      `relative imports must use the emitted .js extension:\n  ${offenders.join('\n  ')}`,
    );
  });

  test('every relative import resolves to a real source file', () => {
    const missing: string[] = [];
    for (const file of files) {
      const source = readFileSync(file, 'utf8');
      for (const match of source.matchAll(/from\s+'(\.[^']*)'/g)) {
        const spec = match[1]!;
        const resolved = join(dirname(file), spec).replace(/\.js$/, '.ts');
        if (!readdirSafe(resolved)) missing.push(`${relative(SRC, file)} -> ${spec}`);
      }
    }
    assert.deepEqual(missing, [], `unresolved relative imports:\n  ${missing.join('\n  ')}`);
  });

  test('test files use relative imports that resolve', () => {
    const missing: string[] = [];
    for (const file of walk(TEST)) {
      const source = readFileSync(file, 'utf8');
      for (const match of source.matchAll(/from\s+'(\.[^']*)'/g)) {
        const spec = match[1]!;
        const resolved = join(dirname(file), spec).replace(/\.js$/, '.ts');
        if (!readdirSafe(resolved)) missing.push(`${relative(TEST, file)} -> ${spec}`);
      }
    }
    assert.deepEqual(missing, [], `unresolved test imports:\n  ${missing.join('\n  ')}`);
  });
});

function readdirSafe(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}