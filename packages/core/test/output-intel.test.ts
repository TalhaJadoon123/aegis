import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  toJson, toJsonl, toSarif, toText, toMarkdown, toHtml, toCsv, render, mediaType,
  fileExtension, buildDocument, rollUpCompliance, OUTPUT_FORMATS, AEGIS_VERSION,
} from '../src/output.js';
import { computeScore, sortFindings } from '../src/severity.js';
import type { Finding } from '../src/types.js';
import {
  createGraph, addNode, addEdge, computeStats, longestEnablePath, reachableFrom,
  graphToD3, graphToMermaid, mergeGraphs, nodeHash, edgeHash, severityRank, added,
} from '../src/intel/graph.js';
import type { AttackNode, Provenance } from '../src/intel/graph.js';

const here = dirname(fileURLToPath(import.meta.url));
void here;

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: 'T-1', ruleId: 'AEGIS-TEST-001', title: 'Test finding',
    description: 'A finding used for output tests.',
    severity: 'high', confidence: 'high',
    location: { file: 'src/app.ts', line: 42, column: 7 },
    evidence: 'const x = eval(userInput);',
    remediation: { title: 'Stop using eval', description: 'Use a parser.', automated: true, effort: 'low' },
    compliance: [{ framework: 'owasp-agentic', control: 'ASI02', title: 'Tool Misuse', relevant: true }],
    source: 'agent', fingerprint: 'fp-1', cwe: 'CWE-95', taxonomy: 'ASI02',
    tags: ['rce'], createdAt: '2026-01-01T00:00:00.000Z',
    ...over,
  };
}

function docWith(findings: Finding[]) {
  return buildDocument({
    target: { type: 'agent', path: '/repo' },
    findings,
    score: computeScore({ findings }),
    durationMs: 1234,
    startedAt: '2026-01-01T00:00:00.000Z',
    rulePacks: [{ id: 'owasp-agentic-top10', version: '1.0.0', ruleCount: 40 }],
  });
}

describe('JSON output', () => {
  test('round-trips through JSON.parse', () => {
    const doc = docWith([finding()]);
    const parsed = JSON.parse(toJson(doc));
    assert.equal(parsed.tool.name, 'Aegis');
    assert.equal(parsed.tool.version, AEGIS_VERSION);
    assert.equal(parsed.findings.length, 1);
    assert.equal(parsed.score.bySeverity.high, 1);
  });

  test('jsonl emits one object per line', () => {
    const lines = toJsonl([finding(), finding({ ruleId: 'B', fingerprint: 'fp-2' })]).split('\n');
    assert.equal(lines.length, 2);
    assert.equal(JSON.parse(lines[1]!).ruleId, 'B');
  });
});

describe('SARIF 2.1.0 output', () => {
  const critical = finding({ ruleId: 'X-1', severity: 'critical', fingerprint: 'fp-2' });
  const high = finding();
  const sarif = JSON.parse(toSarif(docWith([high, critical])));
  const run = sarif.runs[0];

  test('declares version 2.1.0 and a valid schema', () => {
    assert.equal(sarif.version, '2.1.0');
    assert.match(sarif.$schema, /sarif-schema-2\.1\.0/);
  });

  test('driver is Aegis with a rule per unique rule id', () => {
    assert.equal(run.tool.driver.name, 'Aegis');
    assert.equal(run.tool.driver.rules.length, 2);
  });

  test('results are sorted by severity, most severe first', () => {
    const sorted = sortFindings([high, critical]);
    assert.equal(sorted[0]!.ruleId, 'X-1');
    assert.equal(run.results[0].ruleId, 'X-1');
    assert.equal(run.results[0].level, 'error');
    assert.equal(run.results[1].ruleId, 'AEGIS-TEST-001');
  });

  test('maps severity to security-severity so UI sorting works', () => {
    const rules = run.tool.driver.rules as Array<{ id: string; properties: Record<string, unknown> }>;
    const rule = rules.find((r) => r.id === 'X-1')!;
    assert.equal(rule.properties['security-severity'], '9.5');
    assert.equal(rule.properties['problem.severity'], 'critical');
  });

  test('includes stable partial fingerprints for cross-commit tracking', () => {
    for (const result of run.results) assert.ok(result.partialFingerprints.aegisFingerprint);
  });

  test('emits regions with line, column and snippet', () => {
    const region = run.results[1].locations[0].physicalLocation.region;
    assert.equal(region.startLine, 42);
    assert.equal(region.startColumn, 7);
    assert.match(region.snippet.text, /eval/);
  });

  test('carries compliance mappings into rule properties', () => {
    const rules = run.tool.driver.rules as Array<{ properties: Record<string, unknown> }>;
    assert.ok(Array.isArray(rules[0]!.properties['compliance']));
  });

  test('records invocations and scan score', () => {
    assert.equal(run.invocations[0].executionSuccessful, true);
    assert.ok(run.properties.securityScore >= 0);
    assert.equal(run.properties.grade.length, 1);
  });

  test('handles a finding with no file location', () => {
    const out = JSON.parse(toSarif(docWith([finding({ location: { component: 'mcp/server-x' } })])));
    assert.equal(out.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'agent://runtime');
    assert.equal(out.runs[0].results[0].locations[0].logicalLocations[0].name, 'mcp/server-x');
  });
});

describe('text output', () => {
  test('renders findings with colour disabled', () => {
    const out = toText(docWith([finding()]), { color: false });
    assert.match(out, /Aegis security scan/);
    assert.match(out, /Test finding/);
    assert.match(out, /src\/app\.ts:42:7/);
    assert.match(out, /Stop using eval/);
    assert.match(out, /owasp-agentic\/ASI02/);
    assert.ok(!out.includes(String.fromCharCode(27)));
  });

  test('emits ANSI codes when colour is on', () => {
    assert.ok(toText(docWith([finding()]), { color: true }).includes(String.fromCharCode(27)));
  });

  test('says so when clean', () => {
    assert.match(toText(docWith([]), { color: false }), /No security issues found/);
  });

  test('respects the limit and reports the remainder', () => {
    const many = Array.from({ length: 10 }, (_, i) =>
      finding({ ruleId: `R-${i}`, fingerprint: `fp-${i}` }),
    );
    assert.match(toText(docWith(many), { color: false, limit: 3, evidence: false }), /and 7 more/);
  });

  test('groups by rule', () => {
    assert.match(toText(docWith([finding()]), { color: false, groupBy: 'rule', evidence: false }), /AEGIS-TEST-001/);
  });
});

describe('markdown and html output', () => {
  test('markdown includes summary table and findings', () => {
    const out = toMarkdown(docWith([finding()]));
    assert.match(out, /# Aegis Security Scan/);
    assert.match(out, /\| Severity \| Count \|/);
    assert.match(out, /### High: Test finding/);
    assert.match(out, /## Compliance impact/);
  });

  test('html is self-contained with no external resources', () => {
    const out = toHtml(docWith([finding()]));
    assert.match(out, /<!doctype html>/i);
    // An audit report must render offline, so no scripts and no CDN assets.
    assert.ok(!/<script\b/i.test(out), 'html report must not contain scripts');
    assert.ok(!/\b(src|href)=["']https?:/i.test(out), 'unexpected external asset reference');
  });

  test('html escapes user-controlled content', () => {
    const out = toHtml(docWith([finding({ title: '<img src=x onerror=alert(1)>' })]));
    assert.ok(!out.includes('<img src=x'), 'raw HTML leaked into the report');
    assert.match(out, /&lt;img/);
  });

  test('html renders a clean state', () => {
    assert.match(toHtml(docWith([])), /No security issues found/);
  });
});

describe('csv output', () => {
  test('emits a header and one row per finding', () => {
    const lines = toCsv(docWith([finding(), finding({ ruleId: 'B', fingerprint: 'f2' })])).split('\n');
    assert.match(lines[0]!, /^severity,confidence,rule_id/);
    assert.equal(lines.length, 3);
  });

  test('quotes values containing commas', () => {
    assert.match(toCsv(docWith([finding({ title: 'A, B and C' })])), /"A, B and C"/);
  });
});

describe('format dispatch', () => {
  test('every declared format renders without throwing', () => {
    const doc = docWith([finding()]);
    for (const format of OUTPUT_FORMATS) {
      assert.ok(render(doc, format, { color: false }).length > 0, `${format} produced empty output`);
      assert.equal(typeof mediaType(format), 'string');
      assert.ok(fileExtension(format).length > 0);
    }
  });
});

describe('compliance roll-up', () => {
  test('aggregates findings per control, worst severity first', () => {
    const controls = rollUpCompliance([
      finding({ compliance: [{ framework: 'soc2', control: 'CC6.1', relevant: true }] }),
      finding({
        ruleId: 'B', fingerprint: 'f2', severity: 'critical',
        compliance: [{ framework: 'soc2', control: 'CC6.1', relevant: true }],
      }),
    ]);
    assert.equal(controls.length, 1);
    assert.equal(controls[0]!.count, 2);
    assert.equal(controls[0]!.worst, 'critical');
  });
});

// ---------------------------------------------------------------------------
// Living attack graph
// ---------------------------------------------------------------------------

function prov(source: string, kind: Provenance['kind'] = 'advisory'): Provenance {
  return { kind, source, observedAt: '2026-01-01T00:00:00.000Z', hash: `h-${source}` };
}

/** Add a node and return it, failing the test loudly if it was rejected. */
function node(
  g: ReturnType<typeof createGraph>,
  label: string,
  kind: AttackNode['kind'] = 'technique',
  severity: AttackNode['severity'] = 'medium',
): AttackNode {
  return added(
    addNode(g, { kind, label, description: 'A stable description.', severity, provenance: prov(label) }),
  );
}

describe('attack graph', () => {
  test('adds nodes and assigns stable ids', () => {
    const g = createGraph();
    const result = addNode(g, {
      kind: 'technique', label: 'Prompt Injection', description: 'Overriding agent instructions.',
      severity: 'high', references: ['AML.T0051'], provenance: prov('nvd-1'),
    });
    assert.equal(result.status, 'added');
    assert.equal(g.nodes.size, 1);
    assert.equal(g.meta.revision, 1);
  });

  test('deduplicates by content hash and merges provenance', () => {
    const g = createGraph();
    addNode(g, { kind: 'technique', label: 'Prompt Injection', description: 'x', provenance: prov('nvd') });
    const second = addNode(g, { kind: 'technique', label: 'prompt   injection', description: 'x', provenance: prov('ghsa') });
    assert.equal(second.status, 'merged');
    assert.equal(g.nodes.size, 1);
    assert.equal(second.node.provenance.length, 2);
  });

  test('severity only rises with corroboration, never falls', () => {
    const g = createGraph();
    node(g, 'Xray', 'technique', 'critical');
    const down = addNode(g, { kind: 'technique', label: 'Xray', description: 'A stable description.', severity: 'low', provenance: prov('blog') });
    assert.equal(down.status, 'merged');
    assert.equal(down.severityRaised, false);
    assert.equal(down.node.severity, 'critical', 'a low-trust report must not downgrade a confirmed technique');

    // Equal severity is corroboration, not an escalation.
    const up = addNode(g, { kind: 'technique', label: 'Xray', description: 'A stable description.', severity: 'critical', provenance: prov('cve2') });
    assert.equal(up.status, 'merged');
    assert.equal(up.severityRaised, false);

    // A genuinely higher severity does raise it.
    const lower = createGraph();
    node(lower, 'Yankee', 'technique', 'medium');
    const raised = addNode(lower, { kind: 'technique', label: 'Yankee', description: 'A stable description.', severity: 'critical', provenance: prov('cve3') });
    assert.equal(raised.severityRaised, true);
    assert.equal(raised.node.severity, 'critical');
  });

  test('rejects nodes without a usable label or provenance', () => {
    const g = createGraph();
    assert.equal(addNode(g, { kind: 'technique', label: '', description: 'd', provenance: prov('x') }).status, 'rejected');
    assert.equal(
      addNode(g, { kind: 'technique', label: 'X', description: 'd', provenance: { kind: 'advisory', source: '', observedAt: '', hash: 'h' } }).status,
      'rejected',
    );
  });

  test('rejects edges referencing unknown nodes', () => {
    const g = createGraph();
    node(g, 'Alpha');
    assert.equal(
      addEdge(g, { source: 'n_missing', target: 'n_missing2', kind: 'enables', provenance: prov('x') }).status,
      'rejected',
    );
  });

  test('finds the longest enables chain as a composite attack', () => {
    const g = createGraph();
    const a = node(g, 'Alpha');
    const b = node(g, 'Bravo');
    const c = node(g, 'Charlie');
    addEdge(g, { source: a.id, target: b.id, kind: 'enables', provenance: prov('ab') });
    addEdge(g, { source: b.id, target: c.id, kind: 'enables', provenance: prov('bc') });
    const path = longestEnablePath(g);
    assert.equal(path.length, 3);
    assert.equal(path[0], a.id);
    assert.equal(path[2], c.id);
  });

  test('survives cycles without hanging', () => {
    const g = createGraph();
    const a = node(g, 'Alpha');
    const b = node(g, 'Bravo');
    addEdge(g, { source: a.id, target: b.id, kind: 'enables', provenance: prov('ab') });
    addEdge(g, { source: b.id, target: a.id, kind: 'enables', provenance: prov('ba') });
    assert.doesNotThrow(() => longestEnablePath(g));
  });

  test('traverses requires edges in reverse for reachability', () => {
    const g = createGraph();
    const entry = node(g, 'Browser', 'tool');
    const vuln = node(g, 'SSRF', 'vulnerability');
    const technique = node(g, 'Cloud takeover');
    // Exploiting the technique requires SSRF, which requires the browser tool:
    // reaching the tool must expose the technique, so `requires` is traversed
    // backwards.
    addEdge(g, { source: technique.id, target: vuln.id, kind: 'requires', provenance: prov('r') });
    addEdge(g, { source: vuln.id, target: entry.id, kind: 'requires', provenance: prov('r2') });

    const reachable = reachableFrom(g, [entry.id]);
    assert.ok(reachable.has(technique.id), 'should reach the technique via the browser');
  });

  test('marks mitigated techniques and reports unmitigated ones', () => {
    const g = createGraph();
    const t1 = node(g, 'Technique one');
    const t2 = node(g, 'Technique two');
    const ctl = node(g, 'Control one', 'control');
    addEdge(g, { source: ctl.id, target: t1.id, kind: 'mitigates', provenance: prov('m') });
    const stats = computeStats(g);
    assert.ok(stats.unmitigated.includes(t2.id));
    assert.ok(!stats.unmitigated.includes(t1.id));
  });

  test('corroboration clears the unverified flag on edges', () => {
    const g = createGraph();
    const a = node(g, 'Alpha');
    const b = node(g, 'Bravo');
    addEdge(g, { source: a.id, target: b.id, kind: 'enables', provenance: prov('x'), unverified: true });
    const merged = addEdge(g, { source: a.id, target: b.id, kind: 'enables', provenance: prov('y'), unverified: true });
    assert.equal(merged.status, 'merged');
    assert.equal(merged.status === 'merged' && merged.edge.unverified, false);
  });

  test('exports D3 and mermaid', () => {
    const g = createGraph();
    const a = node(g, 'Alpha', 'technique', 'critical');
    const b = node(g, 'Bravo', 'control', 'low');
    addEdge(g, { source: b.id, target: a.id, kind: 'mitigates', provenance: prov('ab'), unverified: false });

    const d3 = graphToD3(g);
    assert.equal(d3.nodes.length, 2);
    assert.equal(d3.links.length, 1);
    assert.equal(d3.nodes.find((n) => n.id === a.id)!.color, '#dc2626');

    const mmd = graphToMermaid(g);
    assert.match(mmd, /graph LR/);
    assert.match(mmd, /classDef critical/);
  });

  test('merging graphs preserves provenance', () => {
    const a = createGraph();
    const b = createGraph();
    addNode(a, { kind: 'technique', label: 'Shared', description: 'A stable description.', provenance: prov('one') });
    addNode(b, { kind: 'technique', label: 'Shared', description: 'A stable description.', provenance: prov('two') });
    addNode(b, { kind: 'technique', label: 'Only in B', description: 'other desc', provenance: prov('three') });
    const stats = mergeGraphs(a, b);
    assert.equal(stats.nodeCount, 2);
    assert.ok([...a.nodes.values()].find((n) => n.label === 'Shared')!.provenance.length === 2);
  });

  test('hashes are stable and severity ranks correctly', () => {
    assert.equal(nodeHash('technique', 'A B'), nodeHash('technique', 'a  b'));
    // Identity must not depend on the description: two feeds describing the
    // same technique differently must collapse to one node.
    assert.equal(nodeHash('technique', 'Prompt Injection', 'one wording'), nodeHash('technique', 'Prompt Injection', 'another'));
    assert.notEqual(nodeHash('technique', 'A', 'x'), nodeHash('vulnerability', 'A', 'x'));
    assert.equal(edgeHash('x', 'y', 'enables'), edgeHash('x', 'y', 'enables'));
    assert.notEqual(edgeHash('x', 'y', 'enables'), edgeHash('y', 'x', 'enables'));
    // `severityRank` is higher-is-worse, the inverse of `compareSeverity`.
    assert.ok(severityRank('critical') > severityRank('info'));
    assert.ok(severityRank('high') > severityRank('medium'));
  });

  test('detects orphan techniques with no incoming path', () => {
    const g = createGraph();
    const a = node(g, 'Root cause');
    const b = node(g, 'Downstream effect');
    addEdge(g, { source: a.id, target: b.id, kind: 'enables', provenance: prov('ab') });
    const stats = computeStats(g);
    assert.ok(stats.orphans.includes(a.id));
    assert.ok(!stats.orphans.includes(b.id));
  });
});