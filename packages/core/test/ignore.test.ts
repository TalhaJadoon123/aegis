import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { IgnoreMatcher, globToRegExp, parseIgnoreFile, parseSuppressions, applySuppressions } from '../src/ignore.js';

/**
 * Regression coverage for ignore-file handling.
 *
 * The self-scan found 159 findings on Aegis's own source, 96 of them in
 * directories that are intentionally vulnerable: the demo workspace, the test
 * fixtures, and the rule packs (which necessarily contain the literal attack
 * strings they detect). A scanner that flags its own attack corpus is
 * unusable in a demo, so ignore files are a first-class feature rather than a
 * workaround.
 */

describe('glob translation', () => {
  test('a directory pattern covers everything beneath it', () => {
    const re = globToRegExp('demos/');
    assert.ok(re.test('demos/mcp.json'));
    assert.ok(re.test('demos/nested/deep/file.ts'));
    assert.ok(!re.test('demos-other/file.ts'));
  });

  test('an unanchored pattern matches at any depth', () => {
    const re = globToRegExp('build');
    assert.ok(re.test('build'));
    assert.ok(re.test('packages/x/build'));
    assert.ok(re.test('packages/x/build/out.js'));
    assert.ok(!re.test('builds'));
  });

  test('a leading slash anchors to the scan root', () => {
    const re = globToRegExp('/only-here');
    assert.ok(re.test('only-here/x.ts'));
    assert.ok(!re.test('nested/only-here/x.ts'));
  });

  test('double star crosses directories', () => {
    const re = globToRegExp('**/*.log');
    assert.ok(re.test('a.log'));
    assert.ok(re.test('a/b/c.log'));
  });

  test('a single star stays within one path segment', () => {
    // gitignore semantics: a bare `*.log` matches at any depth, but the `*`
    // itself must not cross a `/`. Verified by the anchored form below.
    const re = globToRegExp('/*.log');
    assert.ok(re.test('a.log'));
    assert.ok(!re.test('deep/a.log'));
  });

  test('a question mark matches one character', () => {
    const re = globToRegExp('file?.ts');
    assert.ok(re.test('file1.ts'));
    assert.ok(!re.test('file.ts'));
    assert.ok(!re.test('file12.ts'));
  });

  test('regex metacharacters in a pattern are literal', () => {
    const re = globToRegExp('a+b(c).ts');
    assert.ok(re.test('a+b(c).ts'));
    assert.ok(!re.test('aab(c).ts'));
  });
});

describe('ignore file parsing', () => {
  test('skips comments and blank lines', () => {
    const rules = parseIgnoreFile('# comment\n\n  \nfoo/\n', 'test');
    assert.equal(rules.length, 1);
    assert.equal(rules[0]!.pattern, 'foo/');
  });

  test('records negation', () => {
    const rules = parseIgnoreFile('*.log\n!keep.log\n', 'test');
    assert.equal(rules.filter((r) => r.negated).length, 1);
    assert.equal(rules.find((r) => r.negated)!.pattern, 'keep.log');
  });
});

describe('IgnoreMatcher', () => {
  test('honours .aegisignore', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aegis-ign-'));
    try {
      await writeFile(join(dir, '.aegisignore'), 'skipped/\n*.log\n');
      await mkdir(join(dir, 'skipped'), { recursive: true });
      const m = new IgnoreMatcher(dir);
      assert.equal(m.ignores(join(dir, 'skipped', 'x.ts')), true);
      assert.equal(m.ignores(join(dir, 'notes.log')), true);
      assert.equal(m.ignores(join(dir, 'src', 'app.ts')), false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test('honours .gitignore', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aegis-ign-'));
    try {
      await writeFile(join(dir, '.gitignore'), 'node_modules/\n');
      const m = new IgnoreMatcher(dir);
      assert.equal(m.ignores(join(dir, 'node_modules', 'x', 'y.js')), true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test('ignores build output by default', () => {
    const dir = resolve('tmp-scan-root');
    const m = new IgnoreMatcher(dir);
    for (const built of ['node_modules', 'dist', '.next', 'coverage', '.aegis']) {
      assert.equal(m.ignores(join(dir, built, 'x.js')), true, `${built} should be ignored`);
    }
  });

  test('a nested .aegisignore scopes to its own directory', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aegis-ign-'));
    try {
      await mkdir(join(dir, 'vendor', 'rules'), { recursive: true });
      await writeFile(join(dir, 'vendor', 'rules', '.aegisignore'), '*\n');
      const m = new IgnoreMatcher(dir);

      // Enter the directory so the nested file is loaded, as the walker does.
      const enter = (m as unknown as { enterDirectory(p: string, d: boolean): boolean }).enterDirectory.bind(m);
      assert.equal(enter(join(dir, 'vendor'), true), false, 'vendor/ itself is not ignored');
      // `enterDirectory` only reports "stop descending"; the rules take effect
      // on the children, which is what `ignores` is for.
      enter(join(dir, 'vendor', 'rules'), true);

      assert.equal(m.ignores(join(dir, 'vendor', 'rules', 'attack.yaml')), true);
      // A sibling outside the scoped directory is unaffected.
      assert.equal(m.ignores(join(dir, 'vendor', 'other.ts')), false);
      assert.equal(m.ignores(join(dir, 'src', 'app.ts')), false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test('later rules win, matching gitignore semantics', () => {
    const dir = resolve('tmp-scan-root');
    const m = new IgnoreMatcher(dir);
    // Re-add the public list with a negation to prove ordering.
    (m as unknown as { rules: Array<{ pattern: string; negated: boolean; regex: RegExp; dirOnly: boolean; source: string; line: number }> }).rules.push(
      { pattern: 'keep/', negated: false, regex: globToRegExp('keep/'), dirOnly: true, source: 't', line: 1 },
      { pattern: 'keep/', negated: true, regex: globToRegExp('keep/'), dirOnly: true, source: 't', line: 2 },
    );
    assert.equal(m.ignores(join(dir, 'keep', 'a.ts')), false, 'negation after the rule should win');
  });
});

describe('inline suppressions', () => {
  test('parses a bare aegis:ignore', () => {
    const s = parseSuppressions('a.ts', 'const x = 1; // aegis:ignore');
    assert.equal(s.length, 1);
    assert.equal(s[0]!.line, 1);
    assert.equal(s[0]!.ruleId, undefined);
  });

  test('parses named rules and a reason', () => {
    const s = parseSuppressions('a.ts', 'foo(); // aegis:ignore[ASI02-001] -- false positive, value is internal\n');
    assert.equal(s[0]!.ruleId, 'ASI02-001');
    assert.match(s[0]!.reason ?? '', /false positive/);
  });

  test('ignores unrelated comments', () => {
    assert.equal(parseSuppressions('a.ts', '// just a comment').length, 0);
  });

  test('removes suppressed findings and reports them', () => {
    const contents = new Map([
      ['a.ts', 'dangerous(); // aegis:ignore[ASI02-001] -- reviewed, not user input'],
      ['b.ts', 'dangerous();'],
    ]);
    const findings = [
      { ruleId: 'ASI02-001', location: { file: 'a.ts', line: 1 } },
      { ruleId: 'ASI02-001', location: { file: 'b.ts', line: 1 } },
    ];
    const { kept, suppressed } = applySuppressions(findings, contents);
    assert.equal(kept.length, 1);
    assert.equal(kept[0]!.location.file, 'b.ts');
    assert.equal(suppressed.length, 1);
    assert.match(suppressed[0]!.reason ?? '', /reviewed/);
  });

  test('a suppression for one rule does not silence another on the same line', () => {
    const contents = new Map([['a.ts', 'x(); // aegis:ignore[ASI02-001]']]);
    const findings = [
      { ruleId: 'ASI02-001', location: { file: 'a.ts', line: 1 } },
      { ruleId: 'ASI08-001', location: { file: 'a.ts', line: 1 } },
    ];
    const { kept } = applySuppressions(findings, contents);
    assert.equal(kept.length, 1);
    assert.equal(kept[0]!.ruleId, 'ASI08-001');
  });
});