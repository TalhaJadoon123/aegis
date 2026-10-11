# Changelog

All notable changes to Aegis will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-10-11

### Added
- **Core Scanning Engine**: Streaming `AsyncIterable<Finding>` engine with plugin registry
- **MCP Scanner**: Config discovery, live introspection, supply chain graph with exfiltration paths
- **Agent Code Scanner**: 16+ framework detection, prompt injection, tool abuse, data exfiltration, supply chain, DoS detection
- **76 Rules** across 6 packs (CC0): MCP Security, OWASP Agentic Top 10, Prompt Injection, Secrets, Supply Chain, General Code Security
- **8 Output Formats**: JSON, SARIF 2.1.0, Markdown, HTML, CSV, JSONL, Text
- **Compliance Engine**: 40+ controls across 7 frameworks (OWASP Agentic, OWASP LLM, SOC2, ISO27001, GDPR, EU AI Act, NIST AI RMF, MITRE ATLAS)
- **Remediation Engine**: Auto-applied fixes + proposed changes with risks/verification
- **Evolutionary Red Team**: Genetic algorithm with 25+ attack templates across 6 categories
- **Sandbox Runtime**: Behavioral fingerprinting, shadow mode, policy enforcement
- **Intel Feeds**: OSV, GHSA, NVD, MITRE ATLAS parsers with attack graph ingestion
- **Dashboard**: Zero-dep HTTP server with scan history, graph, findings, compliance
- **GitHub Action**: SARIF upload, PR comments, zero deps
- **Desktop App**: Chrome/Edge `--app` mode with isolated profile

### Security
- Zero runtime dependencies (published tarball has zero deps)
- Secret redaction at detection (never in output)
- `shell: false` everywhere, ReDoS validation, auto-remediation fails closed
- CSP headers on dashboard, no external resources
- Self-scan regression gate (120 findings / 40 criticals ceiling)

### Compliance
- 40+ controls across 7 frameworks: OWASP Agentic, OWASP LLM, SOC2, ISO27001, GDPR, EU AI Act, NIST AI RMF, MITRE ATLAS
- Attestation with explicit "no findings ≠ pass" disclaimer
- SARIF compliance properties for GitHub Code Scanning

### Developer Experience
- Zero-runtime-dep install: `git clone && node packages/cli/src/bin.ts --version`
- TypeScript strict mode, ESLint + Prettier, Turbo monorepo
- Comprehensive test suite (282 tests: 250 unit + 32 e2e)
- Smoke checks (18), Readiness gate (81), Package verify (19)

### Spec Kit Foundation
- Constitution with 8 articles (principles, tech standards, security, performance, coding, compliance, governance, amendment)
- 3 feature specs: Core Scanner, Red Team, Compliance
- Plan/Tasks/Checklist for each spec
- Constitution check in every plan

---

## [Unreleased]

### Planned
- Helm chart for K8s deployment
- Circuit breakers for external integrations
- Prompt registry + models.json for LLM config
- Spec Kit agents/prompts for SDD workflow automation
- Measured ASR benchmarks for GTM
- Cost estimation docs for red team runs