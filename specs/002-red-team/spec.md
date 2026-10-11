# Spec: Evolutionary Red Teaming

**Feature ID:** 002-red-team  
**Version:** 1.0.0  
**Status:** Draft  
**Author:** Aegis Team  
**Created:** 2026-10-11

---

## Overview

The Evolutionary Red Team engine evolves attack prompts using a genetic algorithm to find bypasses in AI agents. Unlike static jailbreak lists, it searches the space of prompt combinations by fitness, discovering novel attack chains that hand-written lists miss.

---

## User Stories

### US-001: Red Team an HTTP Agent Endpoint
**As a** security engineer  
**I want to** red-team an HTTP agent endpoint  
**So that** I can find prompt injection, jailbreak, and tool abuse bypasses before deployment

**Acceptance Criteria:**
- [ ] Target specified via `--target http://host:port/endpoint`
- [ ] Configurable message field (`--message-field`), extra body, headers
- [ ] Maintains conversation history for multi-turn attacks
- [ ] Extracts assistant text from multiple response shapes
- [ ] Reports: attacks run, successful bypasses, success rate (ASR), risk level
- [ ] Supports `--dry-run` (no requests sent, canned responses)
- [ ] Supports `--redact-prompts` (shareable report without exploits)

---

### US-002: Red Team an MCP Server
**As a** security engineer  
**I want to** red-team an MCP server  
**So that** I can find tool poisoning, credential theft, and exfiltration chains

**Acceptance Criteria:**
- [ ] Target specified via `--target ./mcp.json` or `--target mcp://server-name`
- [ ] Discovers server config, introspects live server
- [ ] Infers capabilities from advertised tools (filesystem, shell, network, database, email, code-execution)
- [ ] Selects applicable attacks based on capabilities
- [ ] Uses `__aegis_redteam__` probe tool, falls back to first conversational tool
- [ ] Reports tool calls attempted by agent

---

### US-003: Red Team a Local Agent Script
**As a** security engineer  
**I want to** red-team a local agent script  
**So that** I can test agents that run locally without HTTP/MCP

**Acceptance Criteria:**
- [ ] Target specified via `--command "python agent.py"` + `--arg`
- [ ] Spawns process with `shell: false`, pipes stdin/stdout/stderr
- [ ] Extracts response from stdout (configurable extractor)
- [ ] Reports tool calls from structured JSON lines in stdout
- [ ] Supports timeout, capabilities inference

---

### US-004: Dry-Run Mode
**As a** security engineer  
**I want to** validate red-team configuration without sending attacks  
**So that** I can validate configuration in CI without model costs or traffic

**Acceptance Criteria:**
- [ ] `--dry-run` makes zero network requests
- [ ] Uses canned responses (configurable or default)
- [ ] Produces full report structure with `dryRun: true`
- [ ] Simulated latency (`--latency-ms`)
- [ ] Zero model cost, zero attack traffic

---

### US-005: Genetic Algorithm Evolution
**As a** security engineer  
**I want** the engine to evolve attacks by fitness  
**So that** it finds combinations no hand-written list contains

**Acceptance Criteria:**
- [ ] Population-based (default 12), generational (default 6)
- [ ] Slot-based templates with crossover at slot level
- [ ] Mutation: slot substitution, encoding transforms, encoding wrapper
- [ ] Fitness: partial credit for engagement, full credit for confirmed bypass
- [ ] Budget: max evaluations (default 200), respects `--budget`
- [ ] Reproducible: `--seed` produces identical results
- [ ] Early stopping: stagnation detection
- [ ] Tournament selection prefers fitter genomes

---

### US-006: Attack Catalogue
**As a** security engineer  
**I want** a comprehensive, extensible attack catalogue  
**So that** the engine tests relevant attacks for my target

**Acceptance Criteria:**
- [ ] 25+ attack templates across 6 categories:
  - Prompt Injection (direct, encoded, unicode, spaced)
  - Jailbreak (roleplay, DAN, debug, prefix, refusal suppression)
  - Tool Abuse (path traversal, encoded traversal, SSRF, port scan, shell)
  - Data Exfiltration (secret disclosure, external channel, context disclosure)
  - Denial of Service (unbounded generation, tool loop)
  - Supply Chain (fabricated tool, config override, plugin install)
- [ ] Each attack: stable ID, category, name, template, success indicator, severity, taxonomy, remediation
- [ ] Success indicators: regex, notRegex, contains, custom, manual
- [ ] Capability filtering: only runs attacks applicable to target's capabilities
- [ ] Slot vocabularies: authority, secrecy, instruction, delimiter, pathTarget, dataType, exfilChannel, ssrfTarget, dosRequest, fakeTool, encoding, unicodeObfuscation

---

### US-007: Fitness Evaluation
**As a** security engineer  
**I want** accurate fitness scoring  
**So that** the GA evolves toward real bypasses, not false positives

**Acceptance Criteria:**
- [ ] Refusal detection: common phrasings ("I cannot", "I won't", "against my guidelines")
- [ ] Refusal mentioning refused thing is NOT a bypass (disambiguation)
- [ ] Partial credit: engagement without refusal scores > 0
- [ ] Confirmed bypass: success indicator matches → score 1.0
- [ ] Target errors: score 0, explained in reasoning
- [ ] Manual indicators: never claim confirmed bypass on their own
- [ ] Custom checks: can escalate result

---

### US-008: Red Team Report
**As a** security engineer / auditor  
**I want** a comprehensive, shareable report  
**So that** I can communicate risk and track remediation

**Acceptance Criteria:**
- [ ] Summary: attacks run, successful bypasses, ASR %, overall risk (LOW/MEDIUM/HIGH/CRITICAL)
- [ ] Per-attack: prompt, response, succeeded, score, latency, category, severity
- [ ] Compliance impact: findings mapped to OWASP ASI, SOC2, ISO, GDPR, EU AI Act, NIST, MITRE ATLAS
- [ ] `--redact-prompts`: replaces prompts with stable hashes, keeps evidence
- [ ] JSON output for programmatic consumption
- [ ] `--include-prompts` (default true) / `--no-include-prompts`
- [ ] Incident response indicator: GDPR Art. 34 trigger for data exfiltration bypass

---

### US-009: Sandbox Integration
**As a** security engineer  
**I want** to run attacks inside an isolated sandbox  
**So that** I can test agents safely in production-like environments

**Acceptance Criteria:**
- [ ] `--sandbox` flag runs attacks in Docker container (via `aegis-runner` profile)
- [ ] Container: read-only, no-new-privileges, cap-drop ALL, tmpfs, pids-limit, memory/CPU limits
- [ ] Network: isolated bridge for MCP, egress-only for redteam
- [ ] Reports sandbox findings alongside red team results

---

## Functional Requirements

### FR-001: Target Abstraction
All targets implement `RedTeamTarget` interface:
```typescript
interface RedTeamTarget {
  kind: 'http' | 'mcp' | 'script';
  name: string;
  capabilities: ToolCapability[];
  send(prompt, options?): Promise<TargetResponse>;
  close(): Promise<void>;
  supportsMultiTurn: boolean;
  reset?(): Promise<void>;
}
```

### FR-002: Genetic Engine
- `EvolutionEngine` with configurable population, generations, budget
- `Genome`: attackId, category, slots, prompt, severity
- `FitnessFunction`: target-aware, returns `EvaluationDetail`
- Deterministic RNG: `seedrandom` or equivalent, seeded by `--seed`

### FR-003: Attack Templates
- Template strings with `{{slot}}` placeholders
- `fillTemplate()` substitutes slots, defaults to neutral noun
- `templateSlots()` extracts referenced slots for generator
- Derived slots: `encodedInstruction`, `spacedInstruction`, `encodedPath`

### FR-004: Success Indicators
```typescript
type SuccessIndicator =
  | { kind: 'regex'; pattern: string; description: string }
  | { kind: 'notRegex'; pattern: string; description: string }
  | { kind: 'contains'; values: string[]; description: string }
  | { kind: 'custom'; name: string; description: string }
  | { kind: 'manual'; description: string };
```

### FR-005: Capability Filtering
- Target declares `capabilities: ToolCapability[]`
- `selectAttacks(capabilities)` filters catalogue
- Unknown capabilities → full catalogue (fail-open for safety)

---

## Non-Functional Requirements

### NFR-001: Determinism
- `--seed` produces identical evolution across runs
- All RNG uses seeded PRNG (no `Math.random()`)

### NFR-002: Budget Control
- `--budget` caps total target requests
- `--population` × `--generations` ≤ budget (enforced)
- Early stop on stagnation saves budget

### NFR-003: Safety
- `--dry-run` makes zero requests
- `--redact-prompts` for shareable reports
- Sandbox mode isolates target

### NFR-004: Performance
- Default budget 200 completes < 60s
- Population 12, generations 6 → 72 genomes evaluated
- Parallel evaluation not required (serial for determinism)

---

## Acceptance Criteria Summary

| ID | Criterion | Verification |
|----|-----------|--------------|
| AC-001 | HTTP target with history | `scripts/readiness.mts` [7] Safety modes |
| AC-002 | MCP target with introspection | `scripts/readiness.mts` [7] Safety modes |
| AC-003 | Script target with JSON extraction | `scripts/readiness.mts` [7] Safety modes |
| AC-004 | Dry-run mode | `scripts/readiness.mts` [7] Safety modes |
| AC-005 | GA evolution with budget | `packages/core/src/redteam/engine.ts` |
| AC-006 | 25+ attacks, 6 categories | `packages/core/src/redteam/attacks.ts` |
| AC-007 | Fitness with refusal disambiguation | `packages/core/src/redteam/fitness.ts` |
| AC-009 | Report with ASR, risk, compliance | `packages/core/src/redteam/report.ts` |
| AC-010 | Sandbox integration | `docker-compose.sandbox.yml` profile |

---

## Non-Goals

- Training/fine-tuning models
- Automated exploit generation beyond prompt evolution
- Social engineering / human-targeted attacks
- Vulnerability exploitation beyond agent behaviour

---

## Dependencies

- **Internal:** `packages/core` (engine, GA, fitness, attacks, targets, report), `packages/rules` (for compliance mapping)
- **External:** Target endpoints (HTTP, MCP, script), optional Docker for sandbox
- **Dev:** TypeScript 5.7.2, @types/node 22.10.2

---

## Constitution Check

- ✅ Article I: Zero deps (target uses only stdlib), security by design (shell:false, sandbox), findings currency, determinism (seed), decision support (ASR + risk + compliance)
- ✅ Article II: TypeScript strict, no forbidden patterns, import conventions
- ✅ Article III: Input handling (untrusted prompts), secrets never echoed (redacted prompts), network (budget, timeouts)
- ✅ Article IV: Performance targets (budget 200 < 60s)
- ✅ Article V: Coding conventions, testing (dry-run tests behaviour)
- ✅ Article VI: Compliance mapping (OWASP ASI01/ASI09, MITRE ATLAS T0051/T0054)
- ✅ Article VII: Spec-first, linear workflow, CI gates

---

## Next Steps

1. Create `plan.md` — technical strategy, GA configuration, target contracts
2. Create `tasks.md` — tasks for HTTP target, MCP target, script target, GA engine, fitness, report
3. Create `checklist.md` — acceptance criteria, performance targets, safety checks