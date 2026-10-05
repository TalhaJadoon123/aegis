# Contributing to Aegis

Thanks for helping. This document covers what a good contribution looks like
here, and the few conventions that are not obvious.

## Getting set up

Aegis has **zero runtime dependencies**. You do not need `pnpm install` to run
the tests.

```bash
git clone https://github.com/aegis-security/aegis
cd aegis

# Optional: only for typechecking and linting
pnpm install

# Run everything
node --import ./tools/register-ts.mjs --test packages/*/test/*.test.ts

# Typecheck
npx tsc --noEmit -p packages/core/tsconfig.json
```

Requires Node 22+ (native TypeScript execution, no build step).

## Architecture

```
packages/core      The engine. No I/O policy, no CLI concerns.
packages/cli       Argument parsing and command wiring.
packages/rules     YAML rule packs. CC0 — fork freely.
packages/web       Dashboard and static report renderers.
packages/action    GitHub Action. Bundles no third-party code.
packages/intel-feeds Feed parsers.
```

Two conventions worth knowing before you touch anything:

### 1. `Finding` is the only currency

Every scanner emits `Finding`. Every consumer — terminal, SARIF, HTML, PDF,
dashboard row — renders it. If you need a new field, add it to `Finding` in
`types.ts` rather than inventing a parallel shape. This is what makes
`aegis scan | aegis report` work today.

### 2. Findings stream

`Scanner.scan()` returns `AsyncIterable<Finding>`. Do not buffer into an array
and return at the end — that defeats the memory profile on large repositories
and breaks live rendering in the CLI. `scanToReport()` exists for when you
genuinely need the whole picture.

## Testing conventions

Tests use `node:test`. No framework dependency.

**Test the behaviour, not the implementation.** A test that asserts a specific
regex was compiled passes long after the rule stopped matching real code.

**Every bug fix needs a regression test named after the behaviour.** Several
tests in this repo exist purely because a shipped bug was found by writing them:
sort order, SARIF rule indexing, node identity in the attack graph, refusal
disambiguation in the fitness function. If you fix a bug, add the test first
and watch it fail.

**Use fixtures, not inline strings, for anything with line numbers.** A
vulnerability fixture directory (`test/fixtures/`) makes the evidence readable
and the scan reproducible.

## Rules

Rules are CC0. For the rules themselves:

- Write the `description` for a reader deciding whether to act, not for a
  scanner. Explain the *consequence*, not the syntax.
- Include a real `remediation` with a code example. A finding whose remediation
  is "fix this" is a finding nobody acts on.
- Mind ReDoS. Rule patterns are validated for nested quantifiers at load time,
  but a pattern that is merely *slow* still hurts every user.
- Add `compliance` mappings only where the finding genuinely evidences that
  control. Over-mapping is how a scanner loses an audit.

## Style

- TypeScript with `strict` mode. No `any` without a comment saying why.
- **No `any` in new code.**
- Comments explain *why*, not *what*. The diff already says what.
- Line length 100, single quotes, semicolons, trailing commas. Run
  `pnpm format` if you have prettier installed.
- **No parameter properties, `enum`, or `namespace`.** Node's native type
  stripping rejects them at import time, and the failure appears far from its
  cause. There is an automated test (`erasable-syntax.test.ts`) that enforces
  this — keep it passing.

Relative imports use `.js` specifiers so a `tsc` build resolves them
(`from './foo.js'` → `foo.ts`).

## Commit messages

Explain the reasoning. A reviewer who cannot tell why a change was made will
not review it well.

```
fix(sarif): order rules by sorted findings, not input order

SARIF consumers match results[].ruleId against
tool.driver.rules[ruleIndex]. Building the rule map by iterating unsorted
input meant every finding was mislabelled in GitHub code scanning whenever
the input was not already severity-ordered.

Fixes a bug where critical findings were rendered with the wrong rule
metadata.
```

## Pull requests

- One concern per PR.
- Tests that fail before your change.
- If you change a rule's severity, say why — it may break someone's CI gate.

## Reporting security issues

Not a public issue. See [SECURITY.md](SECURITY.md).

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).