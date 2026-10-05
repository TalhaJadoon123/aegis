import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseNvd, parseGhsa, parseOsv, parseNdjson, parseFeed, dedupeRecords,
  severityFromScore, severityFromLabel, isAgentRelevant, agentTags,
} from '../src/feeds.js';
import { ingestFeed, summariseFeed } from '../src/ingest.js';
import { seedGraph } from '../../core/src/intel/seed.js';
import { computeStats } from '../../core/src/intel/graph.js';

describe('NVD parsing', () => {
  const payload = {
    vulnerabilities: [
      {
        cve: {
          id: 'CVE-2026-1234',
          published: '2026-01-15T00:00:00.000Z',
          lastModified: '2026-02-01T00:00:00.000Z',
          descriptions: [{ lang: 'en', value: 'Remote code execution in the MCP filesystem server via path traversal.' }],
          metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, vectorString: 'CVSS:3.1/AV:N/AC:L' } }] },
          weaknesses: [{ description: [{ value: 'CWE-22' }] }],
          references: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1234' }],
          configurations: [
            { nodes: [{ cpeMatch: [{ criteria: 'cpe:2.3:a:acme:mcp_filesystem:1.2.3:*:*:*:*:*:*:*', versionStartIncluding: '1.0.0', versionEndExcluding: '1.4.0' }] }] },
          ],
        },
      },
      {
        cve: {
          id: 'CVE-2026-5678',
          descriptions: [{ lang: 'en', value: 'Buffer overflow in an unrelated image library.' }],
          metrics: { cvssMetricV31: [{ cvssData: { baseScore: 5.3 } }] },
        },
      },
    ],
  };

  test('parses id, description, severity and CVSS', () => {
    const records = parseNvd(payload);
    assert.equal(records.length, 2);
    assert.equal(records[0]!.id, 'CVE-2026-1234');
    assert.equal(records[0]!.severity, 'critical');
    assert.equal(records[0]!.score, 9.8);
    assert.match(records[0]!.cvss!, /CVSS:3.1/);
  });

  test('extracts CWE identifiers', () => {
    assert.deepEqual(parseNvd(payload)[0]!.cwes, ['CWE-22']);
  });

  test('derives a package from CPE criteria', () => {
    const pkg = parseNvd(payload)[0]!.package;
    assert.ok(pkg);
    assert.match(pkg!.name, /mcp-filesystem/);
    assert.match(pkg!.vulnerableRange ?? '', />=1\.0\.0/);
  });

  test('flags agent-relevant records and leaves others alone', () => {
    const records = parseNvd(payload);
    assert.equal(records[0]!.agentRelevant, true);
    assert.equal(records[1]!.agentRelevant, false);
  });

  test('assigns MCP and prompt-injection tags', () => {
    const tags = parseNvd(payload)[0]!.tags;
    assert.ok(tags.includes('mcp'));
  });

  test('tolerates a minimal record', () => {
    const records = parseNvd({ vulnerabilities: [{ cve: { id: 'CVE-2026-0000' } }] });
    assert.equal(records.length, 1);
    assert.equal(records[0]!.severity, 'medium');
    assert.equal(records[0]!.description, '');
  });

  test('tolerates an empty or malformed payload', () => {
    assert.deepEqual(parseNvd({}), []);
    assert.deepEqual(parseNvd({ vulnerabilities: [] }), []);
  });
});

describe('GitHub Advisory parsing', () => {
  const advisories = [
    {
      ghsaId: 'GHSA-abcd-1234-efgh',
      summary: 'Path traversal in the langchain filesystem loader',
      description: 'An MCP-adjacent loader permits arbitrary file reads.',
      severity: 'HIGH',
      cvss: { score: 7.5, vectorString: 'CVSS:3.1/AV:N' },
      cwes: [{ cweId: 'CWE-22' }],
      publishedAt: '2026-01-10T00:00:00Z',
      updatedAt: '2026-01-20T00:00:00Z',
      references: [{ url: 'https://github.com/advisories/GHSA-abcd' }],
      vulnerabilities: [
        { package: { ecosystem: 'npm', name: '@acme/loader' }, firstPatchedVersion: { identifier: '2.0.1' }, vulnerableVersionRange: '< 2.0.1' },
      ],
    },
  ];

  test('parses the advisory into a feed record', () => {
    const record = parseGhsa(advisories)[0]!;
    assert.equal(record.id, 'GHSA-abcd-1234-efgh');
    assert.equal(record.severity, 'high');
    assert.equal(record.score, 7.5);
    assert.deepEqual(record.cwes, ['CWE-22']);
    assert.equal(record.package?.name, '@acme/loader');
    assert.equal(record.package?.fixedIn, '2.0.1');
    assert.equal(record.agentRelevant, true);
  });

  test('drops advisories with no id', () => {
    assert.deepEqual(parseGhsa([{ summary: 'x' }]), []);
  });
});

describe('OSV parsing', () => {
  const entry = {
    id: 'GHSA-zzzz-9999-yyyy',
    summary: 'Prompt injection in an MCP tool description',
    details: 'A malicious tool description can override the agent system prompt.',
    published: '2026-02-01T00:00:00Z',
    modified: '2026-02-02T00:00:00Z',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    affected: [
      {
        package: { ecosystem: 'npm', name: 'mcp-toolkit' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '3.1.0' }] }],
        database_specific: { severity: 'HIGH' },
      },
    ],
    database_specific: { cwe_ids: ['CWE-1427'] },
    references: [{ type: 'ADVISORY', url: 'https://osv.dev/GHSA-zzzz' }],
  };

  test('parses ranges and fixed version', () => {
    const record = parseOsv([entry])[0]!;
    assert.equal(record.id, 'GHSA-zzzz-9999-yyyy');
    assert.equal(record.package?.fixedIn, '3.1.0');
    assert.match(record.package!.vulnerableRange!, /<3\.1\.0/);
    assert.deepEqual(record.cwes, ['CWE-1427']);
    assert.equal(record.severity, 'high');
  });

  test('detects agent relevance from the description', () => {
    const record = parseOsv([entry])[0]!;
    assert.equal(record.agentRelevant, true);
    assert.ok(record.tags.includes('prompt-injection'));
  });
});

describe('NDJSON and generic feed parsing', () => {
  test('parses newline-delimited records and skips malformed lines', () => {
    const ndjson = [
      '{"id":"OSV-1","summary":"MCP prompt injection","details":"agent tool poisoning"}',
      'not json',
      '{"id":"OSV-2","summary":"unrelated buffer overflow"}',
    ].join('\n');
    const records = parseNdjson(ndjson);
    assert.equal(records.length, 2);
    assert.equal(records[0]!.source, 'community');
  });

  test('dispatch by format name', () => {
    assert.equal(parseFeed('{"vulnerabilities":[]}', 'nvd').length, 0);
    assert.equal(parseFeed('[{"ghsaId":"GHSA-1","summary":"mcp agent"}]', 'ghsa').length, 1);
    assert.equal(parseFeed('[{"id":"OSV-1","summary":"mcp agent"}]', 'osv').length, 1);
    assert.equal(parseFeed('garbage', 'osv').length, 0);
    assert.equal(parseFeed('garbage', 'ndjson').length, 0);
  });
});

describe('helpers', () => {
  test('maps CVSS scores to severities', () => {
    assert.equal(severityFromScore(9.5), 'critical');
    assert.equal(severityFromScore(7.2), 'high');
    assert.equal(severityFromScore(4.9), 'medium');
    assert.equal(severityFromScore(2.1), 'low');
    assert.equal(severityFromScore(undefined), 'medium');
  });

  test('maps severity labels, treating MODERATE as medium', () => {
    assert.equal(severityFromLabel('CRITICAL'), 'critical');
    assert.equal(severityFromLabel('MODERATE'), 'medium');
    assert.equal(severityFromLabel('nonsense'), 'medium');
  });

  test('detects agent relevance across phrasings', () => {
    assert.ok(isAgentRelevant('exploit in the Model Context Protocol server'));
    assert.ok(isAgentRelevant('vulnerability in an LLM agent'));
    assert.ok(isAgentRelevant('prompt injection in tool descriptions'));
    assert.ok(!isAgentRelevant('buffer overflow in an image codec'));
  });

  test('maps text onto tags', () => {
    assert.ok(agentTags('MCP prompt injection in a langchain agent').includes('mcp'));
    assert.ok(agentTags('MCP prompt injection in a langchain agent').includes('agent-framework'));
  });

  test('dedupe keeps the highest severity and merges references', () => {
    const base = {
      title: 't', description: 'd', cwes: [], published: '', updated: '',
      references: ['a'], tags: ['mcp'], agentRelevant: false, cvss: undefined, score: undefined,
      package: undefined,
    };
    const merged = dedupeRecords([
      { ...base, id: 'CVE-1', severity: 'low', source: 'nvd' },
      { ...base, id: 'CVE-1', severity: 'critical', source: 'ghsa', references: ['b'] },
    ]);
    assert.equal(merged.length, 1);
    assert.equal(merged[0]!.severity, 'critical');
    assert.deepEqual(merged[0]!.references.sort(), ['a', 'b']);
  });
});

describe('feed ingestion into the attack graph', () => {
  const records = [
    {
      id: 'CVE-2026-1111', title: 'MCP server prompt injection',
      description: 'An MCP tool description can inject instructions into the agent.',
      severity: 'critical' as const, cwes: ['CWE-1427'], published: '2026-01-01', updated: '',
      references: [], source: 'nvd', agentRelevant: true, tags: ['mcp', 'prompt-injection'],
      cvss: undefined, score: 9.1, package: undefined,
    },
    {
      id: 'CVE-2026-2222', title: 'Unrelated image parser bug',
      description: 'Heap overflow in a JPEG decoder.', severity: 'high' as const, cwes: [],
      published: '2026-01-02', updated: '', references: [], source: 'nvd',
      agentRelevant: false, tags: [], cvss: undefined, score: 7.5, package: undefined,
    },
  ];

  test('adds agent-relevant records as CVE nodes', () => {
    const graph = seedGraph();
    const result = ingestFeed(graph, records);
    assert.equal(result.added, 1);
    assert.equal(result.skipped, 1);
    assert.ok([...graph.nodes.values()].some((n) => n.label === 'CVE-2026-1111'));
  });

  test('creates unverified edges to inferred techniques', () => {
    const graph = seedGraph();
    const result = ingestFeed(graph, records);
    assert.ok(result.edges >= 1);
    for (const edge of graph.edges.values()) {
      // Only the machine-inferred edges are unverified.
      if (edge.source.includes('CVE') || edge.source.includes('OSV')) {
        assert.equal(edge.unverified, true, 'inferred edges must be marked unverified');
      }
    }
  });

  test('re-ingesting the same feed merges rather than duplicating', () => {
    const graph = seedGraph();
    ingestFeed(graph, records);
    const before = graph.nodes.size;
    const second = ingestFeed(graph, records);
    assert.equal(second.added, 0);
    assert.equal(second.merged, 1);
    assert.equal(graph.nodes.size, before);
  });

  test('respects the severity floor', () => {
    const graph = seedGraph();
    const result = ingestFeed(graph, records, { minSeverity: 'critical' });
    assert.equal(result.added, 1, 'the high-severity unrelated CVE should be skipped');
  });

  test('summarises a feed for reporting', () => {
    const summary = summariseFeed(records);
    assert.equal(summary.total, 2);
    assert.equal(summary.agentRelevant, 1);
    assert.equal(summary.critical, 1);
  });

  test('ingesting does not corrupt graph statistics', () => {
    const graph = seedGraph();
    const before = computeStats(graph);
    ingestFeed(graph, records);
    const after = computeStats(graph);
    assert.ok(after.nodeCount > before.nodeCount);
    assert.ok(after.edgeCount >= before.edgeCount);
  });
});