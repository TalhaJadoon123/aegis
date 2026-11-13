# @aegis/rules

Aegis' declarative rule definitions.

Rules are plain YAML so that security engineers can read, review, fork, and
extend them without touching TypeScript. Each rule has a stable id, a severity,
a confidence, machine-checkable patterns, remediation guidance, and compliance
mappings.

## Packs

| Pack | File | Scope |
| --- | --- | --- |
| OWASP Agentic Top 10 | `rules/owasp-agentic-top10.yaml` | ASI01–ASI10 agentic risks |
| MCP Security | `rules/mcp-security.yaml` | MCP transport, tools, poisoning, exfiltration |
| Prompt Injection | `rules/prompt-injection.yaml` | Injection-prone prompts and output handling |
| Supply Chain | `rules/supply-chain.yaml` | Dependency, model, and plugin provenance |
| Secrets | `rules/secrets.yaml` | Credentials, entropy sweep, PII |
| General Code Security | `rules/general-code-security.yaml` | Classic vulns at agent severity |

## Pattern types

```yaml
patterns:
  - type: regex              # RE2-ish JS regex, defaults to `gm`
    pattern: 'subprocess\.run\([^)]*shell\s*=\s*True'
  - type: literal            # exact substring
    value: 'trust_remote_code'
  - type: contains-all       # all substrings present in the file
    values: ['read_file', 'fetch']
  - type: contains-any       # any substring present
    values: ['ignore previous', 'DAN mode']
  - type: call               # callee(...) with argument constraints
    callee: requests.post
    argsContain: ['+']
    argsNotContain: ['timeout']
  - type: assignment         # `var = <value matching regex>`
    variable: shell
    valueMatches: 'True'
  - type: jsonpath           # for JSON configs
    path: '$.mcpServers.*.command'
    operator: equals         # equals | not-equals | exists | contains
    value: bash
  - type: entropy            # shannon entropy sweep for secrets
    min: 4.3
    pattern: '(?i)token\s*[:=]\s*["'']?([A-Za-z0-9+/=_-]{24,})'
```

`requires` and `unless` are arrays of regexes evaluated against the whole file.
A rule only fires when every `requires` pattern matches and no `unless` pattern
matches — this is how "shell=True is fine here" suppressions are expressed.

## Writing a rule

```yaml
- id: AEGIS-YOURORG-001
  title: Short imperative title
  description: What is wrong, why it matters to an agent, and how it is exploited.
  severity: high            # critical | high | medium | low | info
  confidence: high          # confirmed | high | medium | low
  languages: [python]       # omit for all languages
  scanners: [agent]         # omit for all scanners
  taxonomy: ASI02
  cwe: CWE-78
  tags: [rce]
  patterns:
    - type: regex
      pattern: 'dangerous\('
  remediation:
    title: What to do
    description: Why, and how.
    automated: false
    effort: low
  compliance:
    - framework: owasp-agentic
      control: ASI02
      relevant: true
```

Validate and test with `pnpm --filter @aegis/rules test`.

## License

CC0 1.0 Universal — these rules are public domain. See `LICENSE`.
