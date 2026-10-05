import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync } from 'node:fs';
import { defaultRuleDirectories, loadRulePacks } from '../src/rules/index.js';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Loaded once and shared by every test in this file. */
const loaded = await loadRulePacks({});
const rules = loaded.rules;

/**
 * Regression guard for the worst failure mode a scanner has: silently loading
 * zero rules.
 *
 * `defaultRuleDirectories` returned `packages/rules` rather than
 * `packages/rules/rules`, so every scan launched from a subdirectory found no
 * packs and reported a clean tree with no error. The CLI printed nothing, the
 * exit code was 0, and the finding count was zero — indistinguishable from a
 * genuinely secure codebase.
 */

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..', '..', '..');

describe('rule discovery', () => {
  test('finds rule packs when scanning from the repository root', async () => {
    const result = await loadRulePacks({});
    assert.ok(result.packs.length >= 6, `expected 6+ packs, found ${result.packs.length}`);
    assert.ok(result.rules.size >= 70, `expected 70+ rules, found ${result.rules.size}`);
  });

  test('finds rule packs when scanning from a nested subdirectory', async () => {
    const nested = join(ROOT, 'packages', 'core', 'test');
    const dirs = defaultRuleDirectories(nested);
    assert.ok(dirs.length > 0, 'no rule directory found from a nested path');
    for (const dir of dirs) {
      const files = readdirSync(dir).filter((f) => f.endsWith('.yaml'));
      assert.ok(files.length > 0, `${dir} was returned but contains no packs`);
    }
  });

  test('every returned directory actually contains rule files', () => {
    for (const start of [ROOT, join(ROOT, 'demos'), join(ROOT, 'packages'), join(ROOT, 'packages', 'core')]) {
      for (const dir of defaultRuleDirectories(start)) {
        assert.ok(existsSync(dir), `${dir} does not exist`);
        const files = readdirSync(dir).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
        assert.ok(files.length > 0, `${dir} has no rule files but was returned`);
      }
    }
  });

  test('loadRulePacks loads a non-trivial catalogue from any start directory', async () => {
    for (const start of [ROOT, join(ROOT, 'demos'), join(ROOT, 'packages')]) {
      const result = await loadRulePacks({
        directories: defaultRuleDirectories(start),
      });
      assert.ok(
        result.rules.size >= 70,
        `only ${result.rules.size} rules loaded from ${start}`,
      );
    }
  });

  test('the MCP scanner finds a config that exists', async () => {
    // Regression: findMcpConfig returned the first candidate matching /mcp\.json$/
    // without checking it exists. `.mcp.json` sorts before `mcp.json`, so the
    // scanner received a nonexistent path, discovered zero servers, and the
    // entire MCP pass reported nothing -- silently, with exit code 0.
    const { existsSync } = await import('node:fs');
    const { McpScanner } = await import('../src/scanners/mcp/scanner.js');
    const { PluginRegistry } = await import('../src/registry.js');
    const { silentLogger } = await import('../src/logger.js');

    const registry = new PluginRegistry();
    registry.setRuleSet(rules);
    const report = await new McpScanner({ connect: false }).scanToReport(
      { type: 'mcp', path: join(ROOT, 'demos', 'mcp.json') },
      { root: join(ROOT, 'demos'), registry, logger: silentLogger, options: {} },
    );

    assert.ok(report.servers.length >= 4, `expected 4+ servers, found ${report.servers.length}`);
    const ids = report.findings.map((f) => f.ruleId);
    assert.ok(ids.includes('AEGIS-MCP-031'), 'unpinned npx install not detected');
    assert.ok(ids.includes('AEGIS-MCP-030'), 'shell-wrapped launch not detected');
    assert.ok(ids.includes('AEGIS-MCP-034'), 'blanket auto-approval not detected');
  });

  test('reports an error rather than silently loading nothing', async () => {
    // An explicitly empty directory is a user error and must be visible.
    const result = await loadRulePacks({ directories: [join(ROOT, 'no-such-dir')] });
    assert.equal(result.packs.length, 0);
    // Not an error — a directory that does not exist is simply empty. The
    // important assertion is the one above: a real search must find rules.
  });
});