import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { redactCredentials } from '../src/rules/evaluator.js';
import { FAKE, FAKE_PRIVATE_KEY } from './synthetic-secrets.js';

/**
 * A scanner that copies the secret it found into its own report has widened the
 * very exposure it exists to find. Evidence and metadata flow into JSON, SARIF,
 * Markdown, HTML and CSV — and into PR comments and PDFs, which get forwarded.
 */

describe('credential redaction', () => {
  test('masks vendor-prefixed keys but keeps them identifiable', () => {
    const cases: Array<[string, string]> = [
      [FAKE.openai, 'sk-proj-'],
      [FAKE.anthropic, 'sk-ant-'],
      [FAKE.github, 'ghp_'],
      [FAKE.githubPat, 'github_pat_'],
      [FAKE.aws, 'AKIA'],
      [FAKE.google, 'AIza'],
      ['xoxb-1234567890-abcdefghijkl', 'xoxb-'],
      [FAKE.gitlab, 'glpat-'],
      [FAKE.stripe, 'sk_live_'],
      [FAKE.npm, 'npm_'],
    ];
    for (const [secret, prefix] of cases) {
      const out = redactCredentials(secret);
      assert.notEqual(out, secret, `${prefix} key was not redacted`);
      assert.ok(out.startsWith(prefix), `${prefix} prefix was lost: ${out}`);
      assert.ok(out.includes('****'), `${prefix} key was not masked: ${out}`);
    }
  });

  test('masks a private key block', () => {
    const key = FAKE_PRIVATE_KEY;
    const out = redactCredentials(key);
    assert.ok(!out.includes('MIIEowIBAAKCAQEA'), 'private key body survived redaction');
  });

  test('leaves ordinary text untouched', () => {
    const text = [
      'def read_file(path):',
      '    return open(path).read()',
      '# See https://example.com/docs for details',
      'timeout = 30000',
      'user_id = 12345',
    ].join('\n');
    assert.equal(redactCredentials(text), text);
  });

  test('does not mangle short identifiers that look like keys', () => {
    for (const text of ['sk-1234', 'AKIA123', 'ghp_short']) {
      assert.equal(redactCredentials(text), text, `over-redacted: ${text}`);
    }
  });

  test('is idempotent', () => {
    const once = redactCredentials(FAKE.openai);
    assert.equal(redactCredentials(once), once);
  });

  test('redacts multiple secrets in one line', () => {
    const line = `A=${FAKE.openai} B=${FAKE.github}`;
    const out = redactCredentials(line);
    assert.ok(!out.includes('abcdefghijklmnopqrstuvwx'));
    assert.ok(!out.includes('ABCDEFGHIJKLMNOPQRSTU'));
  });
});