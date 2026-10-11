# Spec: Compliance Attestation Engine

**Feature ID:** 003-compliance  
**Version:** 1.0.0  
**Status:** Draft  
**Author:** Aegis Team  
**Created:** 2026-10-11

---

## Overview

The Compliance Attestation Engine transforms security findings into auditor-ready attestations. It maps findings to 40+ controls across 7 frameworks, rolls up evidence per control, and generates structured attestations that explicitly refuse to overclaim compliance.

---

## User Stories

### US-001: Map Findings to Compliance Controls
**As a** compliance engineer  
**I want** every finding automatically mapped to relevant controls  
**So that** I can see which regulations are impacted by technical findings

**Acceptance Criteria:**
- [ ] 40+ controls across 7 frameworks: OWASP Agentic (10), OWASP LLM (10), SOC 2 (8), ISO 27001 (10), GDPR (5), EU AI Act (7), NIST AI RMF (5), MITRE ATLAS (3)
- [ ] Each finding carries `compliance: ComplianceMapping[]` with framework, control, title, relevance
- [ ] Finding-to-control mapping is explicit in finding definition, not inferred
- [ ] Over-mapping prevented: finding only maps to controls it genuinely evidences

---

### US-002: Control-Level Roll-Up
**As a** compliance engineer  
**I want** a per-control summary of findings  
**So that** I can assess control operating effectiveness at a glance

**Acceptance Criteria:**
- [ ] Roll-up aggregates findings by `framework:control`
- [ ] Per control: finding count, worst severity, list of finding IDs
- [ ] Sorted by worst severity (critical → info) then count descending
- [ ] Output in JSON, Markdown, HTML attestation

---

### US-003: Compliance Attestation Report
**As a** compliance engineer / auditor  
**I want** a formal attestation document  
**So that** I can present evidence to auditors and stakeholders

**Acceptance Criteria:**
- [ ] Header: organisation, system, owner, scan date, Aegis version
- [ ] Disclaimer: "This is an automated assessment of technical control evidence. It is not a certification."
- [ ] Three distinctions maintained throughout:
  - "No findings" ≠ "pass" — only auditor can attest
  - "Not operating effectively" only for critical findings with concrete evidence
  - Limitations explicit (organisational/procedural out of scope)
- [ ] Per-framework section: control table with findings, worst severity, status
- [ ] Status values: `fail` | `risk` | `no-findings` | `not-assessed`
- [ ] Evidence expected per control listed
- [ ] Output: Markdown + HTML (self-contained, no CDN)
- [ ] CLI: `aegis report . --compliance --organisation "Acme" --system "Support Agent" --owner "SecTeam"`

---

### US-004: Control Status Assessment
**As a** compliance engine  
**I want** to assess control status from findings  
**So that** the attestation reflects actual operating effectiveness

**Acceptance Criteria:**
| Status | Condition |
|--------|-----------|
| `fail` | ≥ 1 critical finding mapped to control with `failureSeverity: critical` |
| `risk` | ≥ 1 high finding mapped to control, no critical |
| `no-findings` | No findings mapped, but control is in scope for scanned target |
| `not-assessed` | Control not mapped by any finding (out of scope for this scan) |

**Requirements:**
- [ ] `failureSeverity` threshold configurable per control (default: critical)
- [ ] Control definition includes `evidenceExpected` for auditor
- [ ] Assessment text explains what Aegis did/did not observe

---

### US-005: Evidence Collection
**As an** auditor  
**I want** evidence linked to each control finding  
**So that** I can verify the assessment without re-scanning

**Acceptance Criteria:**
- [ ] Each finding includes: file, line, column, evidence snippet (redacted), remediation
- [ ] Attestation includes finding IDs per control for traceability
- [ ] SARIF output includes compliance properties for GitHub code scanning
- [ ] HTML attestation: collapsible findings with evidence, remediation, compliance pills

---

### US-006: Framework Coverage Matrix
**As a** compliance engineer  
**I want** a matrix showing which controls are covered  
**So that** I can identify gaps in scan coverage

**Acceptance Criteria:**
- [ ] Matrix: Framework × Control → Covered (findings possible) / Not Applicable
- [ ] "Covered" = at least one rule in rule packs maps to this control
- [ ] "Not Applicable" = control requires organisational evidence (e.g., SOC2 CC7.3 incident runbooks)
- [ ] Matrix output in Markdown + HTML
- [ ] Documented in `docs/compliance.mdx`

---

## Functional Requirements

### FR-001: Control Catalogue
```typescript
interface ControlDefinition {
  id: string;                    // e.g., "CC6.1"
  framework: ComplianceFramework; // e.g., "soc2"
  title: string;                  // Human-readable
  text: string;                   // Verbatim control text (trimmed)
  relatedTaxonomy?: string;       // e.g., "ASI03"
  failureSeverity?: Severity;     // Threshold for "fail" (default: critical)
  evidenceExpected: string;       // What auditor needs to see
}
```

### FR-002: Finding-to-Control Mapping
```typescript
interface ComplianceMapping {
  framework: ComplianceFramework;
  control: string;                // e.g., "CC6.1"
  title: string;
  relevant: boolean;              // True if finding genuinely evidences this control
}
```

Every `Finding` carries `compliance: ComplianceMapping[]`.

### FR-003: Attestation Builder
```typescript
interface AttestationInput {
  findings: Finding[];
  organisation: string;
  system: string;
  owner: string;
  frameworks?: ComplianceFramework[]; // Default: all with findings
}
```

Outputs: `AttestationDocument` → `toMarkdown()`, `toHtml()`

### FR-004: Roll-Up Function
```typescript
function rollUpCompliance(findings: Finding[]): ControlRollUp[] {
  // Groups by framework:control
  // Counts findings, determines worst severity
  // Sorts by severity then count
}
```

---

## Non-Functional Requirements

### NFR-001: No Overclaiming
- Attestation MUST include explicit disclaimer
- "No findings" MUST render as "no findings" not "pass"
- Limitations section mandatory (organisational/procedural out of scope)

### NFR-002: Auditor Decision Support
- Attestation provides evidence, not conclusions
- Evidence expected per control listed
- Finding evidence (file, line, snippet) included

### NFR-003: Performance
- Attestation generation < 500ms for 1000 findings
- Memory < 50 MB additional

### NFR-003: Output Formats
- Markdown (human review, PR comments)
- HTML (self-contained, printable, dark mode)
- JSON (programmatic, CI integration)

---

## Acceptance Criteria Summary

| ID | Criterion | Verification |
|----|-----------|--------------|
| AC-001 | 40+ controls across 7 frameworks | `packages/core/src/compliance.ts` CONTROLS array |
| AC-002 | Per-finding compliance mapping | `Finding.compliance` in `types.ts` |
| AC-003 | Control roll-up with severity | `scripts/readiness.mts` [4] Output formats |
| AC-004 | Attestation with disclaimers | `scripts/readiness.mts` [11] docs + `packages/core/src/compliance.ts` |
| AC-005 | Status assessment logic | `packages/core/src/compliance.ts` assessCompliance |
| AC-006 | Evidence per control | Attestation output includes finding IDs |
| AC-007 | Framework coverage matrix | `docs/compliance.mdx` |

---

## Non-Functional Requirements

### NFR-001: No Overclaiming
- Disclaimer mandatory in every attestation
- "No findings" → "no-findings" status, never "pass"
- Limitations section: organisational/procedural out of scope

### NFR-002: Auditor-Centric
- Evidence expected per control explicitly listed
- Finding evidence (file, line, redacted snippet) included
- Traceability: finding ID → control → framework

### NFR-003: Performance
- Attestation generation < 500ms for 1000 findings
- Memory overhead < 50 MB

---

## Acceptance Criteria Summary

| ID | Criterion | Verification |
|----|-----------|--------------|
| AC-001 | 40+ controls, 7 frameworks | `CONTROLS` array length + framework keys |
| AC-002 | Finding → control mapping | `Finding.compliance` populated |
| AC-003 | Roll-up aggregates correctly | `rollUpCompliance()` unit tests |
| AC-004 | Attestation has disclaimers | Output contains "not a certification" |
| AC-005 | Status logic correct | Unit tests for `fail`/`risk`/`no-findings`/`not-assessed` |
| AC-008 | HTML self-contained | No external resources in HTML output |

---

## Non-Goals

- Certifying compliance (only auditors can attest)
- Organisational/procedural evidence collection (policies, training, runbooks)
- Continuous compliance monitoring (point-in-time scan only)
- Custom framework definitions (extensible via rule packs only)

---

## Dependencies

- **Internal:** `packages/core` (findings, severity, types), `packages/rules` (rule-to-control mappings)
- **External:** None (zero runtime deps)
- **Dev:** TypeScript 5.7.2, @types/node 22.10.2

---

## Constitution Check

- ✅ Article I: Zero deps, security by design (no overclaiming), findings currency, determinism, decision support
- ✅ Article II: TypeScript strict, no forbidden patterns
- ✅ Article III: No secrets in output, no telemetry, fail closed
- ✅ Article IV: Performance targets (500ms for 1000 findings)
- ✅ Article V: Coding conventions, testing conventions
- ✅ Article VI: 40+ controls, 7 frameworks, reporting rules (no overclaiming)
- ✅ Article VII: Spec-first, linear workflow
- ✅ Article VIII: Amendment process

---

## Next Steps

1. Create `plan.md` — technical strategy, control catalogue structure, attestation builder
2. Create `tasks.md` — tasks for control catalogue, mapping, roll-up, attestation builder, CLI command
3. Create `checklist.md` — acceptance criteria, performance targets, no-overclaiming checks