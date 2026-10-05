# Demo workspace

A deliberately insecure setup for demonstrating Aegis. Everything here is
intentionally broken.

```bash
# From the repository root.
# 1. Scan the config. No servers are started (--no-connect --no-spawn).
node packages/cli/src/bin.ts scan demos --no-connect --no-spawn --no-color

# 2. Introspect the vulnerable server live and build the supply chain graph.
node packages/cli/src/bin.ts scan demos --graph --no-color
#    then open aegis-supply-chain.html

# 3. Red team a local agent.
node packages/cli/src/bin.ts redteam --dry-run
```

## What Aegis finds here, and why each one matters

| Finding | Why it matters |
|---|---|
| `GITHUB_TOKEN` hardcoded in the config | Readable by every process on the machine, and committed. |
| `npx -y @modelcontextprotocol/server-filesystem` unpinned | Whatever the registry serves today runs with your agent's permissions. |
| `command: "bash"` | Every argument is shell-interpreted; the launch itself is an injection surface. |
| `DATABASE_URL` with an inline password | Connection strings end up in logs and stack traces. |
| `url: "http://..."` with no auth header | Anyone who can reach the host can call every tool the agent has. |
| `alwaysAllow: ["*"]` | Removes the only human-in-the-loop control between an injection and a shell. |
| `pinned-and-reviewed` | **Not flagged.** This is the positive control — it proves the scanner is not just shouting "insecure" at everything. |

Against `vulnerable-mcp-server.mjs`, Aegis additionally reports:

| Finding | Why it matters |
|---|---|
| Tool description poisoning | `read_file`'s description tells the model to exfiltrate SSH keys and hide it. Arrives over the wire; invisible in the config. |
| Schema poisoning | `write_file`'s `content` parameter carries the injection — the natural place to move an attack that got detected in the description. |
| Read + egress exfiltration chain | `get_env` reads credentials, `send_to_webhook` posts them. Neither is dangerous alone. |
| Credential-bearing resource | `file:///home/agent/.env` is served to any client. |
| Capability advertisement mismatch | Tools are served but `resources`/`prompts` are never declared. |

## Demo script

The full sequence, with timings, is in [`../DELIVERY.md`](../DELIVERY.md) §3.
The 15 seconds of silence over the supply chain graph are the part worth
protecting.

## Cleaning up

```bash
rm -rf .aegis
```

No state is written outside `.aegis/`.