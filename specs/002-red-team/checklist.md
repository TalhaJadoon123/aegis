# Checklist: Evolutionary Red Teaming

**Feature ID:** 002-red-team  
**Spec:** `specs/002-red-team/spec.md`  
**Plan:** `specs/002-red-team/plan.md`

---

## Functional Acceptance Criteria

### US-001: Red Team an HTTP Agent Endpoint
- [x] Target specified via `--target http://host:port/endpoint`
- [x] Configurable message field (`--message-field`), extra body, headers
- [x] Maintains conversation history for multi-turn attacks
- [x] Extracts assistant text from multiple response shapes
- [x] Reports: attacks run, successful bypasses, success rate (ASR), risk level
- [x] Supports `--dry-run` (no requests sent, canned responses)
- [x] Supports `--redact-prompts` (shareable report without exploits)

### US-002: Red Team an MCP Server
- [x] Target specified via `--target ./mcp.json` or `--target mcp://server-name`
- [x] Discovers server config, introspects live server
- [x] Infers capabilities from advertised tools
- [x] Selects applicable attacks based on capabilities
- [x] Uses `__aegis_redteam__` probe tool, falls back to first conversational tool
- [x] Reports tool calls attempted by agent

### US-003: Red Team a Local Agent Script
- [x] Target specified via `--command "python agent.py"` + `--arg`
- [x] Spawns process with `shell: false`, pipes stdin/stdout/stderr
- [x] Extracts response from stdout (configurable extractor)
- [x] Reports tool calls from structured JSON lines in stdout
- [x] Supports timeout, capabilities inference

### US-004: Dry-Run Mode
- [x] `--dry-run` makes zero network requests
- [x] Uses canned responses (configurable or default)
- [x] Produces full report with `dryRun: true`
- [x] Simulated latency (`--latency-ms`)
- [x] Zero model cost, zero attack traffic

### US-005: Genetic Algorithm Evolution
- [x] Population-based (default 12), generational (default 6)
- [x] Slot-based templates with crossover at slot level
- [x] Mutation: slot substitution, encoding transforms, encoding wrapper
- [x] Fitness: partial credit for engagement, full credit for confirmed bypass
- [x] Budget: max evaluations (default 200), respects `--budget`
- [x] Reproducible: `--seed` produces identical results
- [x] Early stopping: stagnation detection

### US-006: Attack Catalogue
- [x] 25+ templates across 6 categories:
  - Prompt Injection (direct, encoded, unicode, spaced)
  - Jailbreak (roleplay, DAN, debug, prefix, refusal suppression)
  - Tool Abuse (path traversal, encoded traversal, SSRF, port scan, shell)
  - Data Exfiltration (secret disclosure, external channel, context disclosure)
  - Denial of Service (unbounded generation, tool loop)
  - Supply Chain (fabricated tool, config override, plugin install)
- [x] Each attack: stable ID, category, name, template, success indicator, severity, taxonomy, remediation
- [x] Success indicators: regex, notRegex, contains, custom, manual
- [x] Capability filtering: only runs attacks applicable to target's capabilities
- [x] Slot vocabularies: authority, secrecy, instruction, delimiter, pathTarget, dataType, exfilChannel, ssrfTarget, dosRequest, fakeTool, encoding, unicodeObfuscation

### US-007: Fitness Evaluation
- [x] Refusal detection: common phrasings ("I cannot", "I won't", "against my guidelines")
- [x] Refusal mentioning refused thing is NOT a bypass (disambiguation)
- [x] Partial credit for engagement without refusal
- [x] Target errors score zero and are explained
- [x] Manual indicators never claim confirmed bypass on their own
- [x] Custom checks can escalate a result

### US-008: Red Team Report
- [x] Summary: attacks run, successful bypasses, ASR %, risk level
- [x] Per-attack: prompt, response, succeeded, score, latency, category, severity
- [x] Compliance impact: findings mapped to OWASP ASI, SOC2, ISO, GDPR, EU AI Act, NIST, MITRE ATLAS
- [x] `--redact-prompts`: replaces prompts with stable hashes, keeps evidence
- [x] `--include-prompts` (default true) / `--no-include-prompts`
- [x] Incident response indicator: GDPR Art. 34 trigger for data exfiltration bypass

### US-009: Sandbox Integration
- [x] `--sandbox` flag runs attacks in Docker (`aegis-runner` profile)
- [x] Container: read-only, no-new-privileges, cap-drop ALL, tmpfs, pids-limit, memory/CPU limits
- [x] Network: isolated bridge for MCP, egress-only for redteam
- [x] Reports sandbox findings alongside red team results

---

## Non-Functional Acceptance Criteria

### NFR-001: Determinism
- [x] `--seed` produces identical evolution across runs
- [x] All RNG uses seeded PRNG (no `Math.random()`)

### NFR-002: Budget Control
- [x] `--budget` caps total target requests
- [x] `--population` × `--generations` ≤ budget (enforced)
- [x] Early stop on stagnation saves budget

### NFR-003: Safety
- [x] `--dry-run` makes zero requests
- [x] `--redact-prompts` for shareable reports
- [x] Sandbox mode isolates target

### NFR-004: Performance
- [x] Default budget 200 completes < 60s
- [x] Population 12, generations 6 → 72 genomes evaluated
- [x] Serial evaluation (determinism over parallelism)

---

## Quality Gates (Must Pass in CI)

| Gate | Command | Threshold |
|------|---------|-----------|
| Typecheck | `npm run typecheck` | 0 errors |
| Unit Tests | `npm run test:unit` | Red team tests pass |
| E2E Tests | `npm run test:e2e` | Red team e2e tests pass |
| Smoke | `npm run smoke` | `redteam --dry-run` passes |
| Readiness | `npm run readiness` | Red team dry-run check passes |
| Package Verify | `npm run package:verify` | `redteam --dry-run` works |

---

## Security Checks

- [x] `--dry-run` makes zero network requests
- [x] `--redact-prompts` replaces prompts with stable hashes
- [x] Sandbox mode: read-only, no-new-privileges, cap-drop ALL
- [x] No secrets in prompts (redacted in reports)
- [x] Refusal disambiguation prevents false positives
- [x] Budget enforcement prevents runaway costs
- [x] Sandbox network isolation (MCP: isolated bridge; redteam: egress-only)
- [x] Container: read-only, no-new-privileges, cap-drop ALL

---

## Spec Kit Artifacts

- [x] `specs/002-red-team/spec.md`
- [x] `specs/002-red-team/plan.md`
- [x] `specs/002-red-team/tasks.md`
- [x] `specs/002-red-team/checklist.md` (this file)
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