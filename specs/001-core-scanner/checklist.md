# Checklist: Core Scanning Engine

**Feature ID:** 001-core-scanner  
**Spec:** `specs/001-core-scanner/spec.md`  
**Plan:** `specs/001-core-scanner/plan.md`

---

## Functional Acceptance Criteria

### US-001: Scan MCP Server Configuration
- [x] Discovers MCP configs in standard locations
- [x] Parses JSON/JSONC/YAML configs
- [x] Flags unpinned `npx -y` / `pip install` / `uv run` launches
- [x] Flags shell-wrapped launches (`bash -c`, `sh -c`)
- [x] Flags inline credentials in `env` / `headers`
- [x] Flags plaintext HTTP on non-loopback hosts
- [x] Flags blanket `alwaysAllow: ["*"]` auto-approval
- [x] Produces findings with file, line, column, evidence, remediation
- [x] Maps to OWASP ASI03, ASI04, ASI09; SOC2 CC6.1; ISO A.5.17

### US-002: Introspect Live MCP Servers
- [x] Connects via stdio (spawns server) and HTTP/SSE transports
- [x] Performs MCP handshake (`initialize` + `initialized`)
- [x] Lists tools, resources, resource templates, prompts
- [x] Detects poisoned tool descriptions
- [x] Detects credential-bearing resources
- [x] Detects exfiltration chains (credential read + network egress)
- [x] Flags missing input schemas, capability mismatches
- [x] Respects `--no-spawn` / `--no-connect` for static-only audits
- [x] Timeouts: 20s total, 8s per request, configurable

### US-003: Scan Agent Codebases
- [x] Detects 16+ frameworks
- [x] Flags prompt injection: unseparated input, hidden instructions, RAG injection
- [x] Flags tool abuse: path traversal, shell injection, SSRF, unrestricted file read/write
- [x] Flags data exfiltration: secret disclosure, external channel, context disclosure
- [x] Flags supply chain: unpinned installs, hallucinated tools, config override, plugin install
- [x] Flags DoS: unbounded generation, tool loops
- [x] Detects hardcoded secrets (20+ vendor prefixes + entropy)
- [x] Redacts secrets in ALL output formats
- [x] Maps to OWASP ASI01–ASI10, CWE, compliance frameworks

### US-004: Unified Finding Model
- [x] Single `Finding` interface in `types.ts`
- [x] All scanners emit `Finding`
- [x] Stable fingerprint: `ruleId:file:line` / `secret:kind:file:line`
- [x] Evidence never contains raw secrets
- [x] Compliance mappings per finding
- [x] SARIF 2.1.0 with stable `partialFingerprints.aegisFingerprint`

### US-005: Output Formats
- [x] JSON (complete document)
- [x] SARIF 2.1.0 (GitHub Code Scanning compatible)
- [x] Markdown (human review)
- [x] HTML (self-contained, dark mode)
- [x] CSV (spreadsheets)
- [x] JSONL (log pipelines)
- [x] Text (terminal, colored)

### US-006: Compliance Mapping
- [x] 40+ controls across 7 frameworks
- [x] Roll-up: control → findings count, worst severity
- [x] Attestation: "no findings ≠ pass", limitations explicit
- [x] Output: Markdown + HTML attestation

### US-007: Remediation
- [x] Auto-applied: secrets→env, `additionalProperties:true`→`false`, blanket auto-approval→explicit, shell→direct
- [x] Proposed: pin deps, replace `shell:true`, add iteration ceiling
- [x] Every remediation: title, description, automated, effort, risks, verification
- [x] `--apply` writes changes; fails closed on stale files

---

## Non-Functional Acceptance Criteria

### NFR-001: Zero Runtime Dependencies
- [x] `aegis.package.json` has `"dependencies": {}`
- [x] `npm ci` installs only 3 dev deps (typescript, @types/node, undici-types)
- [x] Tarball verified by `npm run package:verify`

### NFR-002: Node 22+ Native Type Stripping
- [x] Dev: `node --experimental-strip-types --import ./tools/register-ts.mjs`
- [x] Published tarball ships compiled JS (`build/publish/**`)

### NFR-003: Security
- [x] Secrets never echoed (readiness gate: secret fixture with synthetic keys)
- [x] No shell interpretation (`shell: false` enforced in all `spawn`)
- [x] ReDoS validation at rule load time
- [x] Auto-remediation fails closed (stale check)

### NFR-004: Performance
- [x] Scan 10k LOC < 30s
- [x] Memory < 200 MB RSS
- [x] Cold start < 2s

### NFR-005: Determinism
- [x] Red team seed (`--seed`) produces identical results
- [x] Test fixtures deterministic
- [x] CI runs serially (`--test-concurrency=1`)

### NFR-006: Zero Telemetry
- [x] No outbound requests unless explicitly configured
- [x] `AEGIS_TELEMETRY` accepted and ignored

---

## Quality Gates (Must Pass in CI)

| Gate | Command | Threshold |
|------|---------|-----------|
| Typecheck | `npm run typecheck` | 0 errors |
| Unit Tests | `npm run test:unit` | 250 pass, 0 fail |
| E2E Tests | `npm run test:e2e` | 32 pass, 0 fail |
| Smoke | `npm run smoke` | 18/18 pass |
| Readiness | `npm run readiness` | 81/81 pass |
| Package Build | `npm run package` | Tarball created |
| Package Verify | `npm run package:verify` | 19/19 pass |
| Self-Scan | `aegis scan . --format sarif` | ≤ 120 findings, ≤ 40 criticals |

---

## Security Checks

- [x] No hardcoded secrets in repo (synthetic fixtures only)
- [x] `.gitignore` covers `.env*`, `.aegis/`, `*.sarif`, `build/`, `dist/`, `node_modules/`
- [x] GitHub push protection passes (no secret literals)
- [x] `shell: false` in all `spawn` calls
- [x] Secrets redacted at detection (never in output)
- [x] ReDoS validation at rule load time
- [x] Auto-remediation fails closed (stale check)
- [x] Dashboard binds loopback without token
- [x] CSP headers on dashboard
- [x] No external resources in dashboard HTML

---

## Documentation

- [x] README.md (architecture, install, quickstart, compliance)
- [x] CONTRIBUTING.md (conventions, testing, rules, style)
- [x] SECURITY.md (reporting, scope, threat model, disclosure)
- [x] CONTRIBUTING.md (code style, testing conventions)
- [x] SECURITY.md (threat model, supported versions)
- [x] DELIVERY.md (release process)
- [x] PUBLISHING.md (npm publish steps)
- [x] GTM.md (go-to-market)
- [x] AGENTS.md (AI agent context)
- [x] docs/ (7 MDX pages: cli, compliance, index, plugins, red-teaming, scanning, self-hosting)

---

## Spec Kit Artifacts

- [x] `constitution.md`
- [x] `specs/001-core-scanner/spec.md`
- [x] `specs/001-core-scanner/plan.md`
- [x] `specs/001-core-scanner/tasks.md`
- [x] `specs/001-core-scanner/checklist.md` (this file)
- [ ] `/speckit.checklist` gate in CI

---

## Sign-off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Architect | | | |
| Security Lead | | | |
| Compliance Lead | | | |
| Release Manager | | | |

---

*This checklist must pass 100% before release. Any unchecked item blocks release.*