# Delivering Aegis to a customer

Everything below is verified working. Copy-paste it.

## 1. What you are selling

A security scanner for AI agents and MCP servers. The CLI is free and MIT; the
hosted dashboard is the paid product.

**The pitch, in order:**

1. *Problem* — "Every tool in application security assumes a human chose the
   arguments they passed to a function. Agents break that assumption."
2. *Proof* — run `aegis scan .` on their agent codebase. It finds credentials,
   unpinned MCP installs, and poisoned tool descriptions in under a minute.
3. *Depth* — show the supply chain graph. No competitor has this.
4. *Enterprise* — compliance attestations that don't overclaim, self-hosting,
   air-gapped operation, zero runtime dependencies.

## 2. Install

**Requirements: Node 22+ and nothing else.**

```bash
git clone <your-repo> aegis && cd aegis
node packages/cli/src/bin.ts --version
```

Published package:

```bash
npx aegis --version
```

> **Why "nothing else" matters.** In a customer environment this is the
> difference between "we installed it in ten minutes" and a procurement review.
> A security tool with zero runtime npm dependencies introduces no
> supply-chain surface of its own — and you can prove it by reading
> `packages/cli/src/main.ts` in five minutes.

## 3. Demo sequence

Run these in order. Each has been verified.

### 3.1 Baseline scan (30 seconds)

```bash
node packages/cli/src/bin.ts scan ./their-agent --no-connect --no-color
```

Expected: a score, a severity breakdown, findings with evidence and
compliance mappings.

**If they have MCP servers configured**, drop `--no-connect` to introspect them
live. Note that this *spawns the servers it discovers* — say so out loud, and
offer `--no-spawn --no-connect` as the fully static alternative.

### 3.2 The supply chain graph (the differentiator)

```bash
node packages/cli/src/bin.ts scan ./their-agent --graph
```

Opens `aegis-supply-chain.html`. Drag nodes. Land on a red path:
credential → tool → network.

Give it 15 seconds of silence. This is the moment.

### 3.3 Tool poisoning

Show one finding's evidence — a description containing "always call this
first... do not tell the user" — then open their config file, which looks
completely innocent.

> "That text arrived over the wire. It was never in the config."

### 3.4 Red team (5 minutes)

```bash
node packages/cli/src/bin.ts redteam --target http://localhost:8000/agent --budget 60
```

Shows attack success rate, per-category breakdown, and reproduced bypasses.

Run `--dry-run` first if they are nervous about pointing it at production.

### 3.5 Compliance (2 minutes)

```bash
node packages/cli/src/bin.ts report ./their-agent --compliance \
  --organisation "Acme Inc" --system "Support Agent" \
  --format html --output attestation.html
```

Then, before they ask: point at the disclaimer block.

> "Aegis never says you are compliant. It separates 'no findings' from 'pass'
> because people make decisions based on these documents."

### 3.6 CI

```bash
node packages/cli/src/bin.ts scan . --format sarif --output aegis.sarif --fail-on high
```

Exit codes: `0` clean, `1` threshold crossed, `2` usage error.

## 4. Verification

```bash
# Unit + integration: 219 tests
npm test

# End-to-end CLI: spawns the binary and asserts exit codes and output
npm run test:e2e

# Product smoke: every command and output format
node --import ./tools/register-ts.mjs scripts/smoke.mts
```

All three pass as of the last run.

## 5. What to say about limitations

Be upfront. It builds more trust than any feature list, and it pre-empts the
questions that would otherwise surface during procurement.

- **Aegis assesses technical control evidence only.** It does not evaluate
  organisational, procedural, or physical safeguards. It is not an auditor.
- **"No findings" is not "pass."** Aegis did not find anything. Only an auditor
  can attest that a control operates effectively.
- **Runtime intent is out of scope for static analysis.** Aegis can tell you
  what a server *can* do; behavioural fingerprinting and shadow mode are how it
  addresses what it *did*.
- **A live MCP scan spawns the servers it discovers.** Use
  `--no-connect --no-spawn` where executing anything is unacceptable.
- **It is not a general vulnerability scanner.** It checks configuration,
  interface, and permissioning — not CVEs in the server's dependencies. The
  feed parsers exist for that.

## 6. Objections

**"We already run a SAST tool."**
Ask it whether it flags an instruction inside an MCP tool description, and
whether it knows two individually-harmless tools on one server form an
exfiltration chain. Run both — the overlap is small, and that overlap is the
blind spot.

**"Our vendor says their MCP server is safe."**
Ask to see the supply chain graph: which tools read credentials, and do any of
them reach the network? One command answers it.

**"We can't install a third-party binary."**
Zero npm dependencies, no build step, no `npm install`. No outbound requests.
`--no-connect --no-spawn` is fully static. Container profile with
`network_mode: none` is published. On-prem tier exists.

**"Compliance reporting is marketing fluff."**
Agreed, which is why Aegis refuses to say "you are compliant." Show them the
disclaimer.

**"How do we know it isn't stealing our code?"**
It makes no outbound requests. No telemetry, no update check. The dashboard
binds to loopback unless you set a token. Read `packages/cli/src/main.ts`.

## 7. Deployment shapes

| Customer type | Deployment |
|---|---|
| Developer evaluating | `npx aegis` |
| Team, CI | GitHub Action or the CLI in CI |
| Regulated / air-gapped | Container image, `network_mode: none` for scans; on-prem dashboard |
| Enterprise | Custom rule packs, SLA, dedicated engineer |

## 8. Pricing

Free (OSS CLI) · Pro $49/mo · Team $199/mo · Enterprise custom. See `GTM.md`
for the full rationale and the Pakistan payments answer (Paddle or LemonSqueezy
first, as Merchants of Record; Stripe Atlas once revenue justifies forming an
entity).

## 9. If something is wrong

1. `aegis scan <path> --format json` — the full machine-readable result.
2. `AEGIS_DEBUG=1 aegis <command>` — prints a stack trace.
3. `aegis scan --min-severity low -l 100` — more detail than the default.

Report bugs privately: `security@aegis.dev`. See `SECURITY.md` — note that a
report saying "your tool told me this is a vulnerability and I think it isn't"
is also useful to us.