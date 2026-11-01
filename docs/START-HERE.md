# Start here

Aegis checks AI agents for security problems: prompt injection, dangerous tool
access, secrets in the source, and MCP servers that can leak data. You do not
need to be a developer to run it.

## The fastest way (Windows)

1. Double-click **`Start-Aegis.cmd`** in this folder.
2. A window opens with the Aegis dashboard.
3. Close the window when you are done.

That is the whole install. It uses the copy of Aegis in this folder and does not
change anything else on your machine.

## Installing it as a command

If you want to type `aegis` in any folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

The installer downloads the verified release from GitHub and asks npm to install
it. No npm account is needed. When it finishes:

```powershell
aegis --version
aegis scan C:\path\to\your\agent
aegis desktop
```

On macOS or Linux use `sh install.sh` instead.

## Scanning something

```powershell
aegis scan .                     # scan the current folder
aegis scan . --format sarif      # output for GitHub code scanning
aegis report --compliance        # compliance attestation for auditors
```

Aegis exits with a non-zero code when it finds issues, so it can be used in CI.
Nothing is uploaded: the scan runs locally.

## The dashboard

```powershell
aegis desktop
```

The dashboard shows scan history, findings, the MCP attack graph and compliance
status. It binds to `127.0.0.1` only unless you set `AEGIS_DASHBOARD_TOKEN`, so
it is not reachable from another machine by default.

## Docker

```powershell
docker build -t aegis:0.1.2 -f infra/sandbox/Dockerfile .
docker run --rm -v "${PWD}:/workspace:ro" aegis:0.1.2 scan /workspace
```

The image runs as a non-root user, has no network access to your host files
beyond the folder you mount, and contains no npm dependencies.

## Kubernetes

```bash
helm install aegis infra/helm/aegis \
  --set image.repository=<your-registry>/aegis \
  --set image.tag=0.1.2
```

The chart defaults to serving the dashboard on port 8080 with `/healthz`,
`/readyz` and `/metrics`. See `infra/helm/aegis/values.yaml` for ingress,
persistence and autoscaling.

## Where things are

| Path | What |
|---|---|
| `packages/cli` | the `aegis` command |
| `packages/core` | scanners, rules, red team, compliance |
| `packages/rules` | 76 detection rules |
| `packages/web` | dashboard |
| `infra/helm` | Kubernetes chart |
| `specs` | specification, plan and checklist for each capability |
| `CHANGELOG.md` | what changed in each release |

## If something goes wrong

- **"Node.js is not installed"** — install Node.js 22 or newer from
  <https://nodejs.org>.
- **Port already in use** — run `aegis desktop --port 8080` with another port,
  for example `--port 8090`.
- **Scan finds nothing** — point it at a folder that contains agent code or an
  MCP configuration (`mcp.json`, `claude_desktop_config.json`).
- **A finding is wrong** — every finding includes a rule id such as
  `AEGIS-PI-003`; use `--ignore` to suppress it and please report it.

## Getting help

Open an issue: <https://github.com/TalhaJadoon123/aegis/issues>