# Aegis — AI Agent Context

This file provides context for AI agents (Copilot, Cursor, Spec Kit agents, etc.) working on the Aegis codebase.

---

## Project Overview

**Aegis** — The security platform for AI agents.

Scans MCP servers, agent codebases, and runtime behaviour with:
- Evolutionary red teaming (genetic algorithm)
- Behavioural fingerprinting + shadow mode
- Self-healing remediation
- Living threat graph (OSV/GHSA/NVD feeds)
- Compliance attestation (SOC2, ISO27001, GDPR, EU AI Act, NIST AI RMF, MITRE ATLAS)

**Key Differentiator:** Zero runtime npm dependencies. Runs on Node 22+ alone.

---

## Architecture

```
packages/
├── core/           # Scanning engine (MIT)
│   ├── scanners/   # MCP scanner, Agent scanner
│   ├── redteam/    # GA engine, attacks, fitness, targets
│   ├── sandbox/    # Runtime observation + policy enforcement
│   ├── rules/      # YAML rule engine (8 pattern types)
│   ├── compliance/ # 40+ controls, attestation
│   ├── observability/ # pino + OpenTelemetry
│   └── ...
├── cli/            # Argument parsing + command wiring (MIT)
├── rules/          # 76 rules / 6 packs (CC0)
├── web/            # Dashboard + static reports (Proprietary)
├── action/         # GitHub Action (MIT)
└── intel-feeds/    # OSV/GHSA/NVD parsers (MIT)
```

---

## Key Conventions

### 1. `Finding` is the Only Currency
Every scanner emits `Finding`. Every consumer renders it.
- Add fields to `Finding` in `types.ts`, not parallel shapes
- `Scanner.scan()` returns `AsyncIterable<Finding>` — stream, don't buffer

### 2. Zero Runtime Dependencies
- `aegis.package.json` has `"dependencies": {}`
- Only dev deps: `typescript`, `@types/node`
- Node 22+ native `--experimental-strip-types` for dev
- Published tarball ships compiled JS (`build/publish/**`)

### 3. Security by Design
- **Never** `shell: true` in `spawn` — `shell: false` everywhere
- Secrets **never** echoed — redacted at detection site
- ReDoS validation at rule load time
- Auto-remediation fails closed (stale check)
- CSP headers on dashboard, no external resources

### 4. Determinism
- Red team: `--seed` produces identical results
- Tests: `--test-concurrency=1` (serial e2e)
- Test fixtures deterministic, no randomness

### 4. Code Style
- TypeScript strict mode, no `any` without comment
- No parameter properties, `enum`, or `namespace` (Node strips types)
- Relative imports use `.js` specifiers (`from './foo.js'`)
- Prettier: single quotes, trailing commas, 100 cols, LF
- ESLint: typescript-eslint recommended + type-checked

---

## Commands

```bash
# Development (no install needed)
node --experimental-strip-types --import ./tools/register-ts.mjs packages/cli/src/bin.ts scan ./target

# With pnpm (for typecheck/lint)
pnpm install
pnpm run typecheck
pnpm run test:all

# Build
npm run package          # Creates dist/aegis-0.1.0.tgz
npm run package:verify   # Installs tarball + exercises it

# CI gates
npm run verify           # typecheck + test:all + smoke + readiness

# Dashboard
npm run dashboard        # Starts on 127.0.0.1:8080

# Desktop app
node --experimental-strip-types --import ./tools/register-ts.mjs packages/cli/src/bin.ts desktop
```

---

## Testing

```bash
# Unit + integration (fast, parallel-safe)
npm run test:unit

# E2E (spawns CLI, serial)
npm run test:e2e

# All
npm run test:all

# Smoke (every CLI command + format)
npm run smoke

# Readiness (81 production gates)
npm run readiness
```

### Test Conventions
- `node:test` — zero framework deps
- Fixtures over inline strings (`test/fixtures/`)
- Test behaviour, not implementation
- Regression test named after behaviour
- E2E spawns CLI as subprocess (real exit codes, stdout/stderr)

---

## Key Files

| File | Purpose |
|------|---------|
| `constitution.md` | Project principles, tech standards, security reqs |
| `packages/core/src/types.ts` | `Finding` interface, core types |
| `packages/core/src/rules/` | YAML rule engine (8 pattern types) |
| `packages/core/src/scanners/` | MCP + Agent scanners |
| `packages/core/src/redteam/` | GA engine, attacks, fitness, targets |
| `packages/core/src/sandbox/` | Runtime observation + policy enforcement |
| `packages/core/src/compliance.ts` | 40+ controls, attestation |
| `packages/core/src/observability/` | pino + OpenTelemetry |
| `scripts/readiness.mts` | 81 production gates |
| `scripts/smoke.mts` | 18 product smoke checks |
| `scripts/verify-package.mts` | Installs tarball + exercises as consumer |

---

## CI/CD Pipeline (`.github/workflows/ci.yml`)

1. **Verify** → typecheck → unit → e2e → smoke → readiness
2. **Package** → `npm run package` → `npm run package:verify` → upload artifact
3. **Self-scan** → SARIF upload to GitHub Code Scanning

---

## Security Model

| Threat | Mitigation |
|--------|------------|
| Supply chain | Zero runtime deps; lockfile committed; `npm audit` in CI |
| Secret leakage | Redaction at detection; never in output; synthetic test fixtures |
| MCP server exploits | `shell: false`; timeouts; bounded buffers; `--no-spawn` |
| ReDoS | Pattern validation at load time |
| Auto-remediation | Fails closed (stale check) |
| Dashboard exposure | Loopback-only without token; CSP headers; no external resources |
| Telemetry | None (`AEGIS_TELEMETRY` accepted and ignored) |

---

## Red Teaming

```bash
# Dry run (no requests)
aegis redteam --dry-run --population 6 --generations 2 --budget 16

# HTTP target
aegis redteam --target http://localhost:8000/agent --budget 200

# MCP target
aegis redteam --target ./mcp.json

# Local script
aegis redteam --command "python agent.py"

# With sandbox (Docker)
aegis redteam --target http://target --sandbox
```

---

## Compliance

```bash
# Generate attestation
aegis report . --compliance \
  --organisation "Acme Inc" \
  --system "Support Agent" \
  --owner "Security Team" \
  --format html > attestation.html
```

Frameworks: OWASP Agentic, OWASP LLM, SOC2, ISO27001, GDPR, EU AI Act, NIST AI RMF, MITRE ATLAS

---

## Configuration

| Source | Priority | Example |
|--------|----------|---------|
| CLI args | Highest | `aegis scan --format sarif` |
| Environment | Medium | `AEGIS_DASHBOARD_TOKEN=xxx` |
| Config file | Lower | `aegis.config.json` |
| Defaults | Lowest | Built-in defaults |

---

## Extending Aegis

### Add a Rule
1. Edit `packages/rules/rules/<pack>.yaml`
2. Follow pattern types: regex, jsonpath, ast, entropy, assignment, import, config, composite
3. Include: `remediation` with code example, `compliance` mappings, ReDoS-safe patterns

### Add a Scanner
1. Implement `Scanner` interface in `packages/core/src/scanners/`
2. Register in `PluginRegistry`
3. Emit `Finding` stream

### Add Red Team Attack
1. Add template to `packages/core/src/redteam/attacks.ts`
2. Define slots, success indicator, severity, taxonomy, remediation
2. Add capability filter if needed

---

## Debugging

```bash
# Verbose logging
LOG_LEVEL=debug aegis scan .

# Typecheck only
npm run typecheck

# Single test file
node --experimental-strip-types --import ./tools/register-ts.mjs --test packages/core/test/agent-scanner.test.ts

# Debug dashboard
AEGIS_DASHBOARD_TOKEN=dev node --experimental-strip-types --import ./tools/register-ts.mjs packages/web/src/bin.mts --data .aegis/dashboard --port 8080
```

---

## Common Pitfalls

| Issue | Solution |
|-------|----------|
| `ERR_UNKNOWN_FILE_EXTENSION` | Use `--experimental-strip-types` flag |
| Tests hang | Dashboard tests bind ports — run serially (`--test-concurrency=1`) |
| Typecheck fails on `any` | Add comment: `// eslint-disable-next-line @typescript-eslint/no-explicit-any` |
| MCP server not found | Check `--include-processes` or explicit config path |
| Dashboard blank | Check CSP `connect-src 'self'` — no external resources allowed |

---

## Key Contacts

- Security: `security@aegis.dev`
- Maintainers: See `CODEOWNERS`

---

*This file is the single source of truth for AI agents working on Aegis. Update it when conventions change.*