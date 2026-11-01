# Changelog

All notable changes to Aegis will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.1] - 2026-10-24

### Added
- **Audit logging** (`packages/core/src/audit`): append-only JSONL audit trail with actor/resource/action/result records, query filters, statistics, and export for SOC 2, ISO 27001, EU AI Act and GDPR evidence requests
- **Dashboard audit API**: `/api/audit` and `/api/audit/stats`, with access events recorded automatically
- **Enterprise layer**: REST API with rate limiting and webhooks, usage metering with plan quotas, cron scheduler, circuit breakers, Slack/Jira integrations, compliance export, OpenAPI description
- **Observability**: structured logger, no-op-capable OpenTelemetry tracer, `/readyz` and Prometheus `/metrics` on the dashboard
- **Config validation**: schema-validated CLI/environment configuration (`config/index.ts`, `--config`)
- **Deployment**: Helm chart (`infra/helm/aegis`), release workflow with SBOM and provenance, Docker image under `infra/sandbox/Dockerfile`
- **Prompt registry**: 12 versioned attack templates plus model/cost configuration (`prompts/`)
- **npm distribution**: scoped package `@talhajadoon123/aegis` with zero runtime dependencies

### Changed
- Published package renamed to `@talhajadoon123/aegis` (the unscoped `aegis` name is owned by another project)
- Root package marked `"type": "module"` for ESM consistency inside the container image

### Fixed
- Package verification resolves scoped install paths and asserts zero transitive dependencies
- Recovery of the publication build after the scope rename

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