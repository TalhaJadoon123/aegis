# Spec: Core Scanning Engine

**Feature ID:** 001-core-scanner  
**Version:** 1.0.0  
**Status:** Draft  
**Author:** Aegis Team  
**Created:** 2026-10-11

---

## Overview

The Core Scanning Engine is the heart of Aegis. It provides a streaming, zero-dependency scanning pipeline that discovers, analyzes, and reports security findings across MCP servers, agent codebases, and runtime behaviour.

---

## User Stories

### US-001: Scan MCP Server Configuration
**As a** security engineer  
**I want to** scan MCP server configurations for misconfigurations  
**So that** I can find unpinned installs, shell wrappers, inline credentials, and plaintext transports before deployment

**Acceptance Criteria:**
- [ ] Discovers MCP configs in standard locations (`.mcp.json`, `mcp.json`, `mcpServers` in package.json, VS Code settings)
- [ ] Parses JSON/JSONC/YAML configs
- [ ] Flags unpinned `npx -y` / `pip install` / `uv run` launches
- [ ] Flags shell-wrapped launches (`bash -c`, `sh -c`)
- [ ] Flags inline credentials in `env` / `headers`
- [ ] Flags plaintext HTTP on non-loopback hosts
- [ ] Flags blanket `alwaysAllow: ["*"]` auto-approval
- [ ] Produces findings with file, line, column, evidence, remediation
- [ ] Maps findings to OWASP ASI03, ASI04, ASI09; SOC2 CC6.1; ISO A.5.17

---

### US-002: Introspect Live MCP Servers
**As a** security engineer  
**I want to** connect to running MCP servers and introspect their actual capabilities  
**So that** I can detect tool poisoning, credential-bearing resources, and exfiltration chains that config-only analysis misses

**Acceptance Criteria:**
- [ ] Connects via stdio (spawns server) and HTTP/SSE transports
- [ ] Performs MCP handshake (`initialize` + `initialized` notification)
- [ ] Lists tools, resources, resource templates, prompts
- [ ] Detects poisoned tool descriptions (model-directed instructions)
- [ ] Detects credential-bearing resources (`file://~/.env`, `file://~/.aws/credentials`)
- [ ] Detects exfiltration chains (credential read + network egress)
- [ ] Flags missing input schemas, capability mismatches
- [ ] Respects `--no-spawn` / `--no-connect` for static-only audits
- [ ] Timeouts: 20s total, 8s per request, configurable

---

### US-003: Scan Agent Codebases
**As a** security engineer  
**I want to** scan agent codebases for prompt injection, tool abuse, data exfiltration, and supply chain risks  
**So that** I can find vulnerabilities that traditional SAST misses

**Acceptance Criteria:**
- [ ] Detects 16+ frameworks (LangChain, Vercel AI SDK, AutoGPT, BabyAGI, CrewAI, etc.)
- [ ] Flags prompt injection: unseparated user input, hidden instructions, indirect injection via RAG
- [ ] Flags tool abuse: path traversal, shell injection, SSRF, unrestricted file read/write
- [ ] Flags data exfiltration: secret disclosure, external channel exfil, context disclosure
- [ ] Flags supply chain: unpinned installs, hallucinated tools, config override, plugin install requests
- [ ] Flags DoS: unbounded generation, tool loops
- [ ] Detects hardcoded secrets (20+ vendor prefixes + entropy-based)
- [ ] Redacts secrets in ALL output formats (JSON, SARIF, HTML, MD, CSV, JSONL, text)
- [ ] Maps to OWASP ASI01–ASI10, CWE, compliance frameworks

---

### US-004: Unified Finding Model
**As a** consumer of scan results  
**I want** every scanner to emit the same `Finding` type  
**So that** I can compose scanners, renderers, and remediation without transformation

**Acceptance Criteria:**
- [ ] Single `Finding` interface in `packages/core/src/types.ts`
- [ ] All scanners (MCP, agent, redteam, sandbox) emit `Finding`
- [ ] Stable fingerprint: `ruleId:file:line` for config, `secret:kind:file:line` for secrets
- [ ] Evidence never contains raw secrets (redacted at detection)
- [ ] Compliance mappings per finding (framework, control, title, relevant)
- [ ] Remediation with title, description, automated flag, effort, risks
- [ ] SARIF 2.1.0 output with stable `partialFingerprints.aegisFingerprint`

---

### US-005: Output Formats
**As a** CI engineer / auditor / developer  
**I want** scan results in multiple formats  
**So that** I can integrate with my toolchain

**Acceptance Criteria:**
| Format | Use Case | Requirements |
|--------|----------|--------------|
| JSON | Programmatic consumption | Complete document with score, findings, artifacts |
| SARIF 2.1.0 | GitHub Code Scanning | Valid schema, security-severity, rule indexing aligned |
| Markdown | Human review / PR comments | Summary table, findings grouped by severity, compliance rollup |
| HTML | Standalone report | Self-contained, no CDN, dark mode, collapsible findings |
| CSV | Spreadsheet / BI tools | Header + one row per finding, quoted values |
| JSONL | Log pipelines | One JSON object per line |
| Text | Terminal | Coloured, grouped, limited, scored |

---

### US-006: Compliance Mapping
**As a** compliance engineer  
**I want** findings mapped to regulatory frameworks  
**So that** I can generate attestations for auditors

**Acceptance Criteria:**
- [ ] 40+ controls across 7 frameworks (OWASP Agentic, OWASP LLM, SOC2, ISO27001, GDPR, EU AI Act, NIST AI RMF, MITRE ATLAS)
- [ ] Roll-up: control → findings count, worst severity
- [ ] Attestation: "no findings ≠ pass", limitations explicit, auditor decision support
- [ ] Output: Markdown + HTML attestation with organisation, system, owner, frameworks

---

### US-007: Remediation
**As a** developer  
**I want** actionable remediation for findings  
**So that** I can fix issues efficiently

**Acceptance Criteria:**
- [ ] Auto-applied (unambiguous): secrets → env vars, `additionalProperties: true` → `false`, blanket auto-approval → explicit list, shell-wrapped → direct binary
- [ ] Proposed (requires judgement): pin dependency, replace `shell:true`, add iteration ceiling
- [ ] Every remediation: title, description, automated flag, effort, **risks section**, verification steps
- [ ] `--apply` writes changes; fails closed if file changed since scan

---

## Functional Requirements

### FR-001: Streaming Engine
The engine MUST process files as a stream (`AsyncIterable<Finding>`), not buffer all findings in memory.

### FR-002: Rule Engine
- YAML rule packs loaded from `packages/rules/rules/*.yaml`
- 8 pattern types: regex, jsonpath, ast, entropy, assignment, import, config, composite
- ReDoS validation at load time (nested quantifier detection)
- Rule packs filterable by ownership (core vs custom)

### FR-003: Plugin Registry
- Scanners, renderers, remediators registered via `PluginRegistry`
- Extensible without core modification
- Core owns no I/O policy, no CLI concerns

### FR-004: Ignore System
- `.aegisignore` + `.gitignore` honoured
- Nested `.aegisignore` scopes to its directory
- Inline suppressions: `// aegis:ignore[RULE-ID] -- reason`
- Suppressions reported, not hidden

---

## Non-Functional Requirements

### NFR-001: Zero Runtime Dependencies
The published npm package MUST have `"dependencies": {}`.
- Verified by CI: `npm run package:verify` checks `Object.keys(p.dependencies).length === 0`

### NFR-002: Node 22+ Native Type Stripping
- No build step for development: `node --experimental-strip-types --import ./tools/register-ts.mjs`
- Published tarball ships compiled JS (`build/publish/**`) because Node cannot strip types under `node_modules`

### NFR-003: Security
- **Secrets never echoed** — Verified by readiness gate (secret fixture with synthetic keys)
- **No shell interpretation** — `shell: false` enforced in all `spawn` calls
- **ReDoS protection** — Pattern validation at load time rejects catastrophic backtracking

### NFR-004: Performance
- Scan 10k LOC < 30s
- Memory < 200 MB RSS
- Cold start < 2s

### NFR-005: Determinism
- Red team seed (`--seed`) produces identical results
- Test fixtures deterministic
- CI runs serially (`--test-concurrency=1`)

### NFR-006: Zero Telemetry
- No outbound requests unless explicitly configured
- `AEGIS_TELEMETRY` accepted and ignored

---

## Acceptance Criteria Summary

| ID | Criterion | Verification |
|----|-----------|--------------|
| AC-001 | Discovers MCP configs in standard locations | `scripts/readiness.mts` [3] CLI surface |
| AC-002 | Introspects live MCP servers | `scripts/readiness.mts` [7] Safety modes |
| AC-003 | Scans agent code for 8 OWASP categories | `scripts/readiness.mts` [4] Output formats |
| AC-004 | Unified Finding model | `packages/core/src/types.ts` |
| AC-005 | 7 output formats | `scripts/readiness.mts` [4] |
| AC-006 | 40+ compliance controls | `scripts/readiness.mts` [4] + `packages/core/src/compliance.ts` |
| AC-007 | Auto + proposed remediation | `scripts/readiness.mts` [7] Safety modes |
| AC-008 | Zero runtime deps | `.github/workflows/ci.yml` package job |
| AC-009 | Security: secrets never echoed | `scripts/readiness.mts` [5] Secret safety |
| AC-010 | Performance targets | Benchmarks in CI |

---

## Out of Scope

- Organisational/procedural safeguards (policies, training, incident response)
- Vulnerabilities in Node.js itself
- Denial of service against scanner at scale (mitigated but not eliminated)
- Findings in code being scanned (Aegis reports them; cannot fix your application)

---

## Dependencies

- **Internal:** `packages/core` (engine, rules, scanners), `packages/rules` (76 rules, 6 packs), `packages/cli` (argument parsing)
- **External:** Node.js 22+ standard library only (zero runtime deps)
- **Dev:** TypeScript 5.7.2, @types/node 22.10.2, pnpm 9.15.0

---

## Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| ReDoS in custom rules | Medium | High | Pattern validation at load time; reject nested quantifiers |
| MCP server exploits scanner | Low | Critical | `shell:false`, timeouts, bounded buffers, `--no-spawn` option |
| False positives erode trust | Medium | High | Readiness gate: self-scan ceiling (120 findings, 40 criticals) |
| Supply chain via dev deps | Low | High | Lockfile committed; `npm audit --omit=dev` in CI |

---

## Constitution Check

This spec aligns with all Articles of the Constitution:
- ✅ Article I: Zero deps, security by design, findings as currency, determinism, decision support
- ✅ Article II: TypeScript standards, forbidden patterns, import conventions
- ✅ Article III: Supply chain, input handling, secrets, network
- ✅ Article IV: Performance targets documented
- ✅ Article V: Coding conventions, testing conventions
- ✅ Article VI: 40+ controls across 7 frameworks, reporting rules
- ✅ Article VII: Spec-first, linear workflow, CI gates
- ✅ Article VIII: Amendment process documented

---

## Next Steps

1. Create `plan.md` — technical strategy, data model, interface contracts
2. Create `tasks.md` — dependency-ordered tasks mapped to user stories
3. Create `checklist.md` — declarative acceptance criteria, performance targets
4. Implement `/speckit.checklist` gate in CI