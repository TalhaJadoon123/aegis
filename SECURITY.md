# Security Policy

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Email `security@aegis.dev` with:

- What you found and how to reproduce it
- The Aegis version (`aegis --version`) and Node version
- The impact you believe it has

We acknowledge within 2 business days and aim to have a fix or mitigation
within 14 days. We will credit you in the advisory unless you prefer otherwise.

## Scope

In scope:

- The scanning engine (`packages/core`)
- The CLI (`packages/cli`)
- The rule packs (`packages/rules`)
- The feed parsers (`packages/intel-feeds`)
- The GitHub Action (`packages/action`)
- The dashboard's authentication and authorisation
- Container configurations

Out of scope:

- Findings in code the scanner is *scanning*. Aegis reports those; we cannot fix
  your application.
- Denial of service against a scanner running against attacker-controlled input
  at scale. We mitigate this, but a scanner reading untrusted trees will always
  consume resources.
- Vulnerabilities in Node.js itself.

## Threat model

Aegis reads hostile input by design. It scans:

- Untrusted repositories and source trees
- Untrusted MCP servers, which execute as child processes
- Untrusted MCP tool descriptions, resources, and prompts, which contain text
  designed to manipulate a language model

So the properties we hold ourselves to are stronger than "we handle untrusted
input":

| Property | Why it matters here |
|---|---|
| **Secrets are never retained** | A scanner that copies credentials into its own output has widened the exposure it exists to find. Raw values are dropped at detection. |
| **MCP servers are never shell-interpreted** | Commands are spawned directly with `shell: false`. A shell in the path is reported as a finding, not used. |
| **Rule matching is linear-time** | Patterns are validated for nested quantifiers at load time and rejected if they can backtrack catastrophically. |
| **Auto-remediation fails closed** | If a file changed since the scan, the fix is refused as stale rather than applied blind. |
| **The dashboard binds to loopback by default** | It renders scan evidence, including code and file paths. Exposure requires an explicit token *and* an explicit host. |
| **No telemetry** | Aegis makes no outbound requests. `AEGIS_TELEMETRY` is accepted and ignored. |
| **No runtime dependencies** | The CLI and dashboard install zero npm packages, so running Aegis adds no npm supply-chain surface. |

## Handling MCP servers during a scan

A live scan (`aegis scan` without `--no-connect`) **spawns MCP server processes**
as discovered. This is necessary to introspect them, and it is why:

- Servers are spawned with `shell: false`
- Stdin/stdout are bounded and time-limited
- Servers are always terminated, including on timeout or error
- `--no-spawn` and `--no-connect` disable process execution entirely

Use `--no-spawn --no-connect` for a fully static audit of an environment where
executing anything is unacceptable.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Disclosure

We follow coordinated disclosure. We will not pursue legal action against
researchers who:

- Test against infrastructure they own or have written permission to test
- Avoid privacy violations, data destruction, and denial of service
- Give us reasonable time to fix before public disclosure
- Do not misrepresent findings

Report what the tool tells you is a vulnerability. If it does not, say so —
that report is also useful to us.