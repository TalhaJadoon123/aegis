# Checklist: Compliance Attestation Engine

**Feature ID:** 003-compliance  
**Spec:** `specs/003-compliance/spec.md`  
**Plan:** `specs/003-compliance/plan.md`

---

## Functional Acceptance Criteria

### US-001: Map Findings to Compliance Controls
- [x] 40+ controls across 7 frameworks
  - OWASP Agentic Top 10 (10)
  - OWASP LLM Top 10 (10)
  - SOC 2 (8): CC6.1, CC6.6, CC6.7, CC7.1, CC7.2, CC7.3
  - ISO 27001:2022 Annex A (10): A.5.15, A.5.17, A.8.3, A.8.6, A.8.8, A.8.15, A.8.19, A.8.20, A.8.26, A.8.28
  - GDPR (5): Art. 5, 25, 30, 32, 35
  - EU AI Act (7): Art. 9, 10, 12, 13, 14, 15
  - NIST AI RMF (5): GOVERN 1.2, 4.1; MAP 5.1; MEASURE 2.7; MANAGE 2.2
  - MITRE ATLAS (3): AML.T0050, T0051, T0054
- [x] Each finding carries `compliance: ComplianceMapping[]`
- [x] Finding-to-control mapping is explicit in finding definition
- [x] Over-mapping prevented: finding only maps to controls it genuinely evidences

### US-002: Control-Level Roll-Up
- [x] Roll-up aggregates findings by `framework:control`
- [x] Per control: finding count, worst severity, list of finding IDs
- [x] Sorted by worst severity (critical → info) then count descending
- [x] Output in JSON, Markdown, HTML attestation

### US-003: Compliance Attestation Report
- [x] Header: organisation, system, owner, scan date, Aegis version
- [x] Disclaimer: "This is an automated assessment of technical control evidence. It is not a certification."
- [x] Three distinctions maintained:
  - "No findings" ≠ "pass" — only auditor can attest
  - "Not operating effectively" only for critical findings with concrete evidence
  - Limitations explicit (organisational/procedural out of scope)
- [x] Per-framework section: control table with findings, worst severity, status
- [x] Status values: `fail` | `risk` | `no-findings` | `not-assessed`
- [x] Evidence expected per control listed
- [x] Output: Markdown + HTML (self-contained, no CDN)
- [x] CLI: `aegis report . --compliance --organisation "Acme Inc" --system "Support Agent" --owner "SecTeam"`

### US-004: Control Status Assessment
- [x] Status logic:
  - `fail`: ≥ 1 critical finding mapped to control with `failureSeverity: critical`
  - `risk`: ≥ 1 high finding mapped to control, no critical
  - `no-findings`: No findings mapped, but control in scope
  - `not-assessed`: No findings mapped, control out of scope
- [x] `failureSeverity` threshold configurable per control (default: critical)
- [x] Control definition includes `evidenceExpected` for auditor
- [x] Assessment text explains what Aegis did/did not observe

### US-005: Evidence Collection
- [x] Each finding includes: file, line, column, evidence snippet (redacted), remediation
- [x] Attestation includes finding IDs per control for traceability
- [x] SARIF output includes compliance properties for GitHub code scanning
- [x] HTML attestation: collapsible findings with evidence, remediation, compliance pills

### US-006: Framework Coverage Matrix
- [x] Matrix: Framework × Control → Covered / Not Applicable
- [x] "Covered" = at least one rule in rule packs maps to this control
- [x] "Not Applicable" = control requires organisational evidence
- [x] Matrix output in Markdown + HTML
- [x] Documented in `docs/compliance.mdx`

---

## Non-Functional Acceptance Criteria

### NFR-001: No Overclaiming
- [x] Disclaimer mandatory in every attestation
- [x] "No findings" → "no-findings" status, never "pass"
- [x] Limitations section: organisational/procedural out of scope

### NFR-002: Auditor-Centric
- [x] Evidence expected per control explicitly listed
- [x] Finding evidence (file, line, redacted snippet) included
- [x] Traceability: finding ID → control → framework

### NFR-003: Performance
- [x] Attestation generation < 500ms for 1000 findings
- [x] Memory overhead < 50 MB

### NFR-004: Output Formats
- [x] Markdown (human review, PR comments)
- [x] HTML (self-contained, printable, dark mode)
- [x] JSON (programmatic, CI integration)

---

## Quality Gates (Must Pass in CI)

| Gate | Command | Threshold |
|------|---------|-----------|
| Typecheck | `npm run typecheck` | 0 errors |
| Unit Tests | `npm run test:unit` | Compliance tests pass |
| E2E Tests | `npm run test:e2e` | Report command works |
| Smoke | `npm run smoke` | `report --compliance` passes |
| Readiness | `npm run readiness` | Compliance attestation renders |
| Package Verify | `npm run package:verify` | Report command works in installed tarball |

---

## Security Checks

- [x] No secrets in attestation output (redacted at detection)
- [x] SARIF includes compliance properties for GitHub code scanning
- [x] HTML attestation self-contained (no CDN, no external resources)
- [x] No telemetry in attestation generation

---

## Spec Kit Artifacts

- [x] `specs/003-compliance/spec.md`
- [x] `specs/003-compliance/plan.md`
- [x] `specs/003-compliance/tasks.md`
- [x] `specs/003-compliance/checklist.md` (this file)
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