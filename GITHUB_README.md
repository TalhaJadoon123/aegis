# Aegis

**The security platform for AI agents.**

Scan MCP servers, agent codebases, and runtime behaviour — with automated
evolutionary red teaming, behavioural fingerprinting, self-healing remediation,
and a living community threat graph.

```
node packages/cli/src/bin.ts scan ./your-agent
```

Zero runtime dependencies. Runs air-gapped. MIT (rules are CC0).

---

## Why this exists

Every tool in application security assumes a human chose the arguments they
passed to a function. Agents break that assumption completely: the caller is a
language model, the arguments are generated, and the input often came from a web
page, a document, or another tool's output.

Aegis is built for that class of vulnerability — prompt injection in an MCP tool
description, an agent reading `~/.ssh/id_rsa` because something asked it to, two
individually-harmless tools that jointly form an exfiltration chain.

## Install

Node 22 or later. Nothing to install.

```bash
git clone https://github.com/TalhaJadoon123/aegis
cd aegis
node packages/cli/src/bin.ts --version
```

Or from npm:

```bash
npx aegis --help
```

## Commands

| Command | What it does |
|---|---|
| `aegis scan` | Scan MCP servers, agent code, and repositories |
| `aegis redteam` | Evolutionary red teaming against an agent |
| `aegis sandbox` | Observe an agent's runtime behaviour under policy |
| `aegis desktop` | Open the dashboard as a native application window |
| `aegis deps` | Check dependencies against OSV |
| `aegis fix` | Generate and optionally apply remediations |
| `aegis report` | Compliance attestation for an auditor |
| `aegis intel` | Query the living attack graph |

## Six capabilities

1. **MCP Supply Chain Graph** — maps every server, tool, resource, and data
   flow. Finds the credential→network chains that per-tool review cannot see.
2. **Genetic-algorithm red teaming** — evolves attack prompts by fitness rather
   than shipping a static jailbreak list. Deterministic from a seed.
3. **Behavioural fingerprinting** — a signature of what an agent *does*.
4. **Shadow mode** — predicts what an agent *would* do without doing it.
5. **Self-healing policies** — turns a finding into a runtime rule.
6. **Living attack graph** — continuously updated, with provenance on every node.

## What it will not do

Aegis never asserts that you are compliant. It reports which controls your
findings intersect, and it separates "no findings" from "pass" throughout,
because people make decisions based on these documents.

It never echoes a raw secret. Not in a finding, not in evidence, not in any
output format.

## Compliance coverage

SOC 2 · ISO/IEC 27001 Annex A · GDPR · EU AI Act · NIST AI RMF ·
OWASP Agentic Top 10 · MITRE ATLAS

## In CI

```yaml
- uses: TalhaJadoon123/aegis@v0.1.0
  with:
    path: .
    format: sarif
    fail-on: high
```

Or directly: `aegis scan . --format sarif --output aegis.sarif --fail-on high`

Exit codes: `0` clean · `1` threshold crossed · `2` usage error.

## Suppressing findings

`.aegisignore` and `.gitignore` are honoured, including nested files scoped to
their own directory. Inline suppressions report themselves rather than hiding:

```python
dangerous(user_input)  # aegis:ignore[ASI02-001] -- value is internal, reviewed
```

## Testing

```bash
npm test              # 282 tests
npm run smoke         # every command and output format
npm run readiness     # 75-check production gate
npm run package:verify # install the tarball and exercise it as a consumer
```

## Licence

- Engine, CLI, dashboard, feed parsers: **MIT**
- Rule definitions in `packages/rules`: **CC0 1.0** (public domain)

Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) ·
Security: [SECURITY.md](SECURITY.md) ·
Code of conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)