# Aegis Constitution

**Version:** 1.0.0  
**Status:** Active  
**Last Updated:** 2026-10-11

---

## Preamble

Aegis is a security platform for AI agents. It scans MCP servers, agent codebases, and runtime behaviour with automated evolutionary red teaming, behavioural fingerprinting, self-healing remediation, and a living threat graph.

This constitution codifies the principles, technology standards, security requirements, performance expectations, coding conventions, and compliance needs that govern all development on Aegis. Every spec, plan, task, and implementation must align with these principles.

---

## Article I — Core Principles

### 1. Zero Runtime Dependencies
**Principle:** The published package must have zero runtime dependencies.

**Rationale:** A security tool that pulls transitive packages to read its own command line has a supply-chain problem. Zero dependencies means:
- Installable in air-gapped networks in minutes
- No `npm audit` noise for downstream users
- SBOM is trivial
- Supply-chain surface is the standard library only

**Enforcement:** `aegis.package.json` MUST have `"dependencies": {}`. CI verifies this.

---

### 2. Security by Design, Not by Configuration
**Principle:** Security properties must hold by construction, not by optional flags.

**Rationale:** A security tool that requires configuration to be secure is not a security tool.

**Mandatory Properties:**
- **Zero trust input handling:** All external input (MCP tool descriptions, agent prompts, file contents, network responses) is untrusted by default
- **No shell interpretation:** `shell: false` for ALL `spawn`/`exec` calls. A shell in the path is a finding, not a feature
- **Secrets never retained:** Raw credentials are dropped at detection. Redaction happens at detection site, not in output formatters
- **Fail closed:** Auto-remediation refuses stale changes rather than applying blindly
- **No telemetry:** Zero outbound requests unless explicitly configured by operator
- **ReDoS resistance:** Patterns validated for catastrophic backtracking at load time

---

### 3. Findings Are the Only Currency
**Principle:** Every scanner emits `Finding`. Every consumer renders the same `Finding`.

**Rationale:** A unified finding model enables composability: `aegis scan | aegis report | aegis fix` works without transformation.

**Consequences:**
- New fields added to `Finding` in `types.ts`, never parallel shapes
- `Scanner.scan()` returns `AsyncIterable<Finding>` — never buffer into arrays
- `scanToReport()` exists only when the whole picture is genuinely needed

---

### 4. Determinism Over Convenience
**Principle:** Same input → same output. Always.

**Rationale:** A red team report that cannot be reproduced is an anecdote, not evidence.

**Requirements:**
- Genetic algorithm seeded (`--seed`), deterministic crossover/mutation
- Test fixtures deterministic, no randomness
- CI runs serially (`--test-concurrency=1`) to avoid flakiness
- `--dry-run` makes no network requests

---

### 5. Security Findings Are Decision Support, Not Verdicts
**Principle:** Aegis reports evidence; auditors make judgments.

**Rationale:** A scanner that claims compliance is worse than no scanner — people act on the claim.

**Distinctions Maintained:**
- "No findings" ≠ "pass" — only an auditor can attest a control operates effectively
- "Not operating effectively" asserted only for critical findings with concrete evidence
- Limitations listed explicitly (organisational/procedural safeguards out of scope)

---

## Article II — Technology Standards

### Language & Runtime
| Standard | Value |
|----------|-------|
| Language | TypeScript (ESM) |
| Runtime | Node.js 22+ (native `--experimental-strip-types`) |
| Module System | ESM only (`"type": "module"`) |
| Package Manager | pnpm 9.x (workspace) |

### TypeScript Configuration
| Setting | Value | Rationale |
|---------|-------|-----------|
| `strict` | `true` | Catch errors at compile time |
| `noUncheckedIndexedAccess` | `true` | Prevent undefined access |
| `noImplicitOverride` | `true` | Explicit overrides |
| `noFallthroughCasesInSwitch` | `true` | Prevent fallthrough bugs |
| `isolatedModules` | `true` | Fast single-file compilation |
| `skipLibCheck` | `true` | Speed up typecheck |

### Forbidden Patterns
| Pattern | Reason |
|---------|--------|
| Parameter properties (`constructor(public x: T)`) | Node type stripping rejects at import time |
| `enum` | Node type stripping rejects at import time |
| `namespace` | Node type stripping rejects at import time |
| `any` without comment | Defeats type safety; automated test enforces |
| `eval` / `Function()` / `new Function()` | Code execution from untrusted input |

### Import Conventions
- Relative imports use `.js` specifiers: `from './foo.js'` → resolves to `foo.ts`
- No path aliases — explicit relative paths
- `import type` for type-only imports

---

## Article III — Security Requirements

### Supply Chain
- **Zero runtime dependencies** (enforced by `aegis.package.json` + CI)
- **Lockfile committed** (`package-lock.json` tracked)
- **No post-install scripts** in dependencies
- **Integrity hashes** in lockfile
- **SBOM generation** on publish (CycloneDX)

### Input Handling
- **All external input untrusted** — MCP tool descriptions, agent prompts, file contents, network responses
- **Validation at boundary** — Zod schemas for config, CLI args, API payloads
- **Path traversal protection** — `resolve()` + containment check for all file operations
- **Size limits** — Bounded buffers for stdout/stderr, MCP messages, HTTP responses

### Secrets Management
- **Never echo raw secrets** — Redaction at detection site
- **No hardcoded secrets** — GitHub push protection enforced; test fixtures use synthetic credentials assembled at runtime
- **Environment-only** — Production secrets via env vars or secret manager
- **Rotation guidance** — Every secret finding includes remediation with rotation steps

### Network
- **No outbound requests by default** — `AEGIS_TELEMETRY=0` accepted and ignored
- **Explicit opt-in** — `--budget` for red team, `--upload` for dashboard
- **Timeouts on all requests** — Default 30s, configurable
- **AbortController** — All `fetch` cancellable via signal

---

## Article IV — Performance Expectations

| Metric | Target | Measurement |
|--------|--------|-------------|
| Cold start (CLI) | < 2s | `time aegis --version` |
| Scan 10k LOC | < 30s | `aegis scan ./large-repo` |
| MCP introspection | < 15s/server | `aegis scan --include-processes` |
| Red team (budget 200) | < 60s | `aegis redteam --budget 200` |
| Memory (CLI) | < 200 MB | RSS during scan |
| Memory (Dashboard) | < 100 MB | RSS idle |
| Typecheck | < 10s | `npm run typecheck` |
| Full test suite | < 180s | `npm run test:all` |

### Resource Limits (Container)
| Resource | Limit |
|----------|-------|
| Memory | 512 MB (scanner), 1 GB (redteam) |
| CPU | 1.0 (scanner), 2.0 (redteam) |
| PIDs | 256 |
| tmpfs | 64 MB (scanner), 128 MB (MCP) |
| Network | `none` (scanner), isolated bridge (MCP/redteam) |

---

## Article V — Coding Conventions

### Style
- **Formatter:** Prettier (single quotes, trailing commas, 100 col, LF)
- **Linter:** ESLint + typescript-eslint (recommended + type-checked)
- **Line length:** 100
- **Quotes:** Single
- **Semicolons:** Yes
- **Trailing commas:** All

### Naming
| Construct | Convention |
|-----------|------------|
| Files | kebab-case (`scanner.ts`, `agent-scanner.test.ts`) |
| Classes | PascalCase (`McpScanner`, `Finding`) |
| Functions | camelCase (`scanSecrets`, `runRedTeam`) |
| Constants | UPPER_SNAKE_CASE (`DEFAULT_TIMEOUT`) |
| Types/Interfaces | PascalCase (`Finding`, `ScanOptions`) |
| Type parameters | PascalCase (`T`, `TFinding`) |

### Error Handling
- **No silent failures** — Every `catch` logs or rethrows
- **Structured errors** — Custom error classes with `code`, `metadata`
- **Graceful degradation** — Feed ingestion continues on malformed records
- **Fail fast on config** — Invalid config fails at startup, not at scan time

### Testing
- **Framework:** `node:test` (zero deps)
- **Fixtures over inline strings** — `test/fixtures/` for anything with line numbers
- **Behaviour over implementation** — Test what the scanner finds, not which regex matched
- **Regression tests for bugs** — Named after the behaviour, not the fix
- **E2E tests spawn CLI** — Real subprocess, real exit codes, real stdout/stderr
- **Serial e2e** — Dashboard tests bind ports, cannot run concurrently

---

## Article VI — Compliance Needs

### Frameworks Covered
| Framework | Controls | Evidence Type |
|-----------|----------|---------------|
| OWASP Agentic Top 10 | 10 | Findings mapped to ASI01–ASI10 |
| OWASP LLM Top 10 | 10 | Findings mapped to LLM01–LLM10 |
| SOC 2 | 8 | CC6.1, CC6.6, CC6.7, CC7.1–7.3 |
| ISO 27001:2022 Annex A | 10 | A.5.15, A.5.17, A.8.3, A.8.6, A.8.8, A.8.15, A.8.19, A.8.20, A.8.26, A.8.28 |
| GDPR | 5 | Art. 5, 25, 30, 32, 35 |
| EU AI Act | 7 | Art. 9, 10, 12, 13, 14, 15 |
| NIST AI RMF | 5 | GOVERN 1.2, 4.1; MAP 5.1; MEASURE 2.7; MANAGE 2.2 |
| MITRE ATLAS | 3 | AML.T0050, T0051, T0054 |

### Compliance Reporting Rules
1. **Never claim "pass"** — Only "findings intersect control" or "no findings"
2. **Evidence per finding** — Every mapped finding includes file, line, snippet
3. **Limitations explicit** — Organisational/procedural safeguards out of scope
4. **Auditor decision support** — Report structured for human review

---

## Article VII — Governance

### Change Process
1. **Spec first** — No implementation without spec (Spec Kit workflow)
2. **Spec → Plan → Tasks → Implement** — Linear, no skipping
3. **Constitution check** — Every plan includes constitution check section
4. **Tests first** — Regression test before fix; behaviour test before feature
5. **CI gate** — All checks pass before merge (typecheck, test, smoke, readiness, package)

### Versioning
- **Semantic Versioning** — MAJOR.MINOR.PATCH
- **Breaking changes** — MAJOR bump, migration guide in `DELIVERY.md`
- **Release tags** — `v<version>` annotated tags
- **Changelog** — `DELIVERY.md` per version

### Deprecation
- **6-month notice** — Deprecation warning in CLI + docs
- **Migration path** — Automated fix where possible, manual steps documented
- **Removal** — Next MAJOR version

---

## Article VIII — Amendment

This constitution may be amended by:
1. Proposal in `constitution.md` PR with `constitution:` prefix
2. Review by maintainers (2 approvals required)
3. Constitution check in dependent plans updated
4. Version bump in this document

---

**End of Constitution**

*This document is the supreme governance document for Aegis. All specs, plans, tasks, and implementations must conform. In case of conflict, this constitution prevails.*