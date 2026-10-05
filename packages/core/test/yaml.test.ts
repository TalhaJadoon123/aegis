import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseYaml, parseYamlDocuments, stringifyYaml, YamlParseError } from '../src/yaml.js';
import { parseRulePack, normalizeRegexFlags } from '../src/rules/loader.js';

const here = dirname(fileURLToPath(import.meta.url));
const RULES_DIR = join(here, '..', '..', 'rules', 'rules');

const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const VALID_CONFIDENCE = new Set(['confirmed', 'high', 'medium', 'low']);
const VALID_PATTERN_TYPES = new Set([
  'regex',
  'literal',
  'contains-all',
  'contains-any',
  'call',
  'assignment',
  'jsonpath',
  'entropy',
]);
const VALID_FRAMEWORKS = new Set([
  'owasp-agentic',
  'owasp-llm',
  'soc2',
  'iso27001',
  'gdpr',
  'eu-ai-act',
  'nist-ai-rmf',
  'mitre-atlas',
]);

describe('yaml parser', () => {
  test('parses scalars with correct types', () => {
    assert.deepEqual(parseYaml('a: 1\nb: true\nc: text\nd: null\ne: 1.5'), {
      a: 1,
      b: true,
      c: 'text',
      d: null,
      e: 1.5,
    });
  });

  test('parses nested mappings', () => {
    assert.deepEqual(parseYaml('a:\n  b:\n    c: 1\n'), { a: { b: { c: 1 } } });
  });

  test('parses block sequences', () => {
    assert.deepEqual(parseYaml('items:\n  - one\n  - two\n'), { items: ['one', 'two'] });
  });

  test('parses sequences of mappings', () => {
    const doc = parseYaml('rules:\n  - id: A\n    severity: high\n  - id: B\n    severity: low\n');
    assert.deepEqual(doc, {
      rules: [
        { id: 'A', severity: 'high' },
        { id: 'B', severity: 'low' },
      ],
    });
  });

  test('parses flow sequences and mappings', () => {
    assert.deepEqual(parseYaml('langs: [python, typescript]\nmap: {a: 1, b: "two"}'), {
      langs: ['python', 'typescript'],
      map: { a: '1', b: 'two' },
    });
  });

  test('handles quoted scalars containing colons and hashes', () => {
    const doc = parseYaml(`a: "ignore previous: # not a comment"\nb: 'it''s fine: yes'`);
    assert.deepEqual(doc, { a: 'ignore previous: # not a comment', b: "it's fine: yes" });
  });

  test('strips comments but keeps # inside quotes', () => {
    const doc = parseYaml('# leading comment\nkey: value # trailing\nother: "has # inside"');
    assert.deepEqual(doc, { key: 'value', other: 'has # inside' });
  });

  test('supports folded and literal block scalars', () => {
    const doc = parseYaml('folded: >-\n  one\n  two\nliteral: |-\n  line1\n  line2\n') as Record<
      string,
      unknown
    >;
    assert.equal(doc['folded'], 'one two');
    assert.equal(doc['literal'], 'line1\nline2');
  });

  test('preserves indentation inside block scalars', () => {
    const doc = parseYaml('patch: |-\n  a:\n    b: 1\n') as Record<string, unknown>;
    assert.equal(doc['patch'], 'a:\n  b: 1');
  });

  test('rejects tabs used for indentation', () => {
    assert.throws(() => parseYaml('a:\n\tb: 1'), YamlParseError);
  });

  test('rejects anchors rather than mis-parsing', () => {
    assert.throws(() => parseYaml('a: &anchor\nb: *anchor\n'), /anchors and aliases are not supported/);
  });

  test('handles multi-document streams', () => {
    const docs = parseYamlDocuments('a: 1\n---\nb: 2\n');
    assert.deepEqual(docs, [{ a: 1 }, { b: 2 }]);
  });

  test('round-trips through stringifyYaml', () => {
    const original = {
      id: 'pack',
      version: '1.0.0',
      rules: [{ id: 'A', tags: ['x', 'y'], nested: { deep: true } }],
    };
    assert.deepEqual(parseYaml(stringifyYaml(original)), original);
  });
});

describe('shipped rule packs', () => {
  const files = existsSync(RULES_DIR)
    ? readdirSync(RULES_DIR).filter((f) => f.endsWith('.yaml'))
    : [];
  const seenIds = new Set();

  test('all six packs are present', () => {
    assert.equal(files.length, 6, `expected 6 rule packs, found ${files.join(', ')}`);
  });

  for (const file of files) {
    describe(file, () => {
      const source = readFileSync(join(RULES_DIR, file), 'utf8');

      test('parses and declares metadata', () => {
        const pack = parseRulePack(source, file);
        const id = file.replace(/\.yaml$/, '');
        assert.equal(pack.id, id);
        assert.match(pack.version, /^\d+\.\d+\.\d+$/);
        assert.ok(pack.name);
        assert.ok(Array.isArray(pack.rules) && pack.rules.length > 0);
      });

      test('every rule is well formed', () => {
        const pack = parseRulePack(source, file);
        for (const rule of pack.rules) {
          assert.match(rule.id, /^AEGIS-[A-Z0-9]+-\d{3}$/, `bad id: ${rule.id}`);
          assert.ok(!seenIds.has(rule.id), `duplicate rule id: ${rule.id}`);
          seenIds.add(rule.id);

          assert.ok(rule.title?.length > 5, `${rule.id}: title too short`);
          assert.ok(rule.description?.length > 40, `${rule.id}: description too thin`);
          assert.ok(VALID_SEVERITIES.has(rule.severity), `${rule.id}: bad severity`);
          if (rule.confidence !== undefined) {
            assert.ok(VALID_CONFIDENCE.has(rule.confidence), `${rule.id}: bad confidence`);
          }

          assert.ok(Array.isArray(rule.patterns) && rule.patterns.length > 0, `${rule.id}: no patterns`);
          for (const pattern of rule.patterns) {
            assert.ok(VALID_PATTERN_TYPES.has(pattern.type), `${rule.id}: bad pattern type`);
            if (pattern.type === 'regex') {
              assert.doesNotThrow(
                () => new RegExp(pattern.pattern, pattern.flags ?? 'gm'),
                `${rule.id}: invalid regex ${pattern.pattern}`,
              );
              assert.ok(
                !/\([^)]*[+*]\)[+*]/.test(pattern.pattern),
                `${rule.id}: nested quantifier (ReDoS)`,
              );
            }
            if (pattern.type === 'jsonpath') {
              assert.ok(['equals', 'not-equals', 'exists', 'contains'].includes(pattern.operator));
            }
          }

          // Guards are compiled through the same normaliser the engine uses,
          // so `(?i)`-style inline flags in rule packs stay valid.
          const compiles = (src: string) => {
            const { pattern: body, flags } = normalizeRegexFlags(src, 'gm');
            return new RegExp(body, flags);
          };
          for (const p of rule.requires ?? []) assert.doesNotThrow(() => compiles(p), `${rule.id} requires`);
          for (const p of rule.unless ?? []) assert.doesNotThrow(() => compiles(p), `${rule.id} unless`);

          assert.ok(rule.remediation?.title, `${rule.id}: remediation.title required`);
          assert.ok(rule.remediation?.description, `${rule.id}: remediation.description required`);
          assert.equal(typeof rule.remediation?.automated, 'boolean', `${rule.id}: remediation.automated`);

          assert.ok(Array.isArray(rule.compliance) && rule.compliance.length > 0, `${rule.id}: no compliance`);
          for (const c of rule.compliance) {
            assert.ok(VALID_FRAMEWORKS.has(c.framework), `${rule.id}: bad framework ${c.framework}`);
            assert.ok(c.control?.length > 0, `${rule.id}: control required`);
            assert.equal(typeof c.relevant, 'boolean', `${rule.id}: compliance.relevant required`);
          }
        }
      });
    });
  }

  test('rule ids are globally unique', () => {
    assert.ok(seenIds.size > 40, `expected a substantial rule set, found ${seenIds.size}`);
  });
});