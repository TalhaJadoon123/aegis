# Plan: Core Scanning Engine

**Feature ID:** 001-core-scanner  
**Version:** 1.0.0  
**Status:** Implemented  
**Spec:** `specs/001-core-scanner/spec.md`

---

## Technical Strategy

The Core Scanning Engine follows a streaming, plugin-based architecture:

```
Scan Target → Discovery → Config Pass → Introspection Pass → Graph Build → Score → Output
```

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Streaming `AsyncIterable<Finding>` | Memory efficiency for large repos; live rendering |
| Plugin Registry | Extensible scanners without core modification |
| YAML Rule Packs | Declarative, versionable, CC0-licensed rules |
| Dual-pass MCP scan | Config-only (fast, CI-safe) + Live introspection (deep) |
| Unified `Finding` type | Single currency for all consumers (SARIF, HTML, CLI, Dashboard) |

---

## Data Model

### Core Types (`packages/core/src/types.ts`)

```typescript
interface Finding {
  id: string;                    // Stable: ruleId:file:line
  ruleId: string;                // e.g., AEGIS-MCP-001
  title: string;
  description: string;
  severity: Severity;            // critical | high | medium | low | info
  confidence: Confidence;        // confirmed | high | medium | low
  location: { file, line, column, component? };
  evidence: string;              // Redacted snippet
  remediation: { title, description, automated, effort, risks };
  compliance: ComplianceMapping[]; // framework, control, title, relevant
  fingerprint: string;           // Stable cross-commit ID
  source: 'mcp' | 'agent' | 'redteam' | 'sandbox';
  tags: string[];
  createdAt: string;             // ISO 8601
}

interface ScanTarget {
  type: 'mcp' | 'agent' | 'repo' | 'http';
  path?: string;
  url?: string;
}

interface ScanResult {
  target: ScanTarget;
  findings: Finding[];
  score: SecurityScore;
  artifacts?: Record<string, unknown>;
  errors: string[];
  durationMs: number;
}
```

### Rule Pack Structure (`packages/rules/rules/*.yaml`)

```yaml
rules:
  - id: AEGIS-MCP-001
    title: HTTP MCP server exposed without authentication
    severity: critical
    confidence: high
    scanners: ['mcp']
    taxonomy: ASI03
    cwe: CWE-306
    patterns:
      - type: jsonpath
        path: '$.mcpServers.*.auth'
        operator: 'not-equals'
        value: 'required'
    remediation:
      title: Require authentication on HTTP MCP transport
      automated: false
      effort: medium
    compliance:
      - framework: owasp-agentic
        control: ASI03
        relevant: true
```

---

## Interface Contracts

### Scanner Interface (`packages/core/src/registry.ts`)

```typescript
interface Scanner<O extends ScanOptions = ScanOptions> {
  readonly name: string;
  readonly targetType: 'mcp' | 'agent' | 'repo';
  readonly sideEffects: 'none' | 'local-exec' | 'network';
  readonly options: O;
  scan(target: ScanTarget, ctx: ScannerContext): AsyncIterable<Finding>;
  scanToReport(target: ScanTarget, ctx: ScannerContext): Promise<ScanReport>;
}
```

### Plugin Registry

```typescript
class PluginRegistry {
  registerScanner(scanner: Scanner): void;
  registerRenderer(format: OutputFormat, fn: RenderFn): void;
  registerRemediator(ruleId: string, fn: RemediatorFn): void;
  ruleSet(): RuleSet;
}
```

---

## Implementation Phases

### Phase 1: Core Engine (Done)
- [x] Streaming engine (`engine.ts`)
- [x] Plugin registry (`registry.ts`)
- [x] Rule loader + evaluator (`rules/`)
- [x] Finding deduplication + sorting (`severity.ts`)

### Phase 2: MCP Scanner (Done)
- [x] Config discovery (`discovery.ts`)
- [x] Config analysis (`analyzers.ts`)
- [x] Live introspection (`connectors.ts`, `protocol.ts`)
- [x] Supply chain graph (`graph.ts`)

### Phase 3: Agent Scanner (Done)
- [x] Framework detection (16 frameworks)
- [x] Prompt injection analysis (`prompt-injection.ts`)
- [x] Threat modeling (`threat-model.ts`)
- [x] Secret detection (`secrets.ts`)

### Phase 4: Output & Compliance (Done)
- [x] 7 output formats (`output.ts`)
- [x] SARIF 2.1.0 with security-severity
- [x] Compliance engine (40+ controls)
- [x] Remediation engine (`remediation.ts`)

### Phase 5: Red Team (Done - see spec 002)
- [x] GA engine, fitness, attacks, targets, report

### Phase 6: Sandbox (Done)
- [x] Runtime observation (`sandbox/runner.ts`)
- [x] Behavioral fingerprinting (`sandbox/fingerprint.ts`)
- [x] Policy enforcement (deny/require-approval)

### Phase 7: Intel Feeds (Done)
- [x] OSV, GHSA, NVD parsers
- [x] Feed ingestion → attack graph

### Phase 8: Dashboard & Action (Done)
- [x] Zero-dep HTTP server (`packages/web/src/server.ts`)
- [x] GitHub Action (`packages/action/src/index.ts`)

---

## Research Decisions

| Decision | Status | Notes |
|----------|--------|-------|
| Zero runtime deps | ✅ Confirmed | Native Node 22 `--experimental-strip-types` |
| Streaming findings | ✅ Confirmed | `AsyncIterable<Finding>` |
| YAML rule packs | ✅ Confirmed | 8 pattern types, ReDoS validation |
| SARIF 2.1.0 | ✅ Confirmed | GitHub Code Scanning compatible |
| Zero runtime deps in tarball | ✅ Verified | `npm run package:verify` confirms |

---

## Constitution Check

- ✅ Article I: Zero deps, security by design, findings currency, determinism, decision support
- ✅ Article II: TypeScript strict, no forbidden patterns, import conventions
- ✅ Article III: Supply chain, input handling, secrets, network
- ✅ Article IV: Performance targets documented
- ✅ Article V: Coding conventions, testing conventions
- ✅ Article VI: 40+ controls, 7 frameworks, reporting rules
- ✅ Article VII: Spec-first, linear workflow, CI gates
- ✅ Article VIII: Amendment process documented

---

## Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| ReDoS in custom rules | Medium | High | Pattern validation at load time |
| MCP server exploits scanner | Low | Critical | `shell:false`, timeouts, `--no-spawn` |
| False positives erode trust | Medium | High | Self-scan ceiling (120 findings, 40 criticals) |
| Supply chain via dev deps | Low | High | Lockfile committed; `npm audit` in CI |

---

## Next Steps

- [ ] Create `tasks.md` with dependency-ordered implementation tasks
- [ ] Create `checklist.md` with declarative acceptance criteria
- [ ] Add `/speckit.checklist` gate to CI