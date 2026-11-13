# Publishing Aegis

## What gets published

One package, `aegis`, with **zero runtime dependencies**. It contains:

| Path | What |
|---|---|
| `build/publish/packages/cli/src/bin.js` | the `aegis` executable |
| `build/publish/packages/core/src/**` | the scanning engine, with `.d.ts` |
| `build/publish/packages/web/src/**` | the dashboard server |
| `packages/rules/rules/*.yaml` | 76 rules, CC0 |
| `packages/web/public/**` | dashboard UI and the static report renderer |

## Build and verify

```bash
npm run package          # compile, stage, verify, pack
npm run package:verify   # install into a temp dir and exercise it
npm publish dist/aegis-0.1.0.tgz
```

`npm run package` refuses to produce a tarball unless the staged package passes
its own checks:

- the manifest declares **no dependencies**
- `bin.aegis`, `main` and `types` all point at files that exist
- **`bin.aegis` is JavaScript, not TypeScript**
- the rule packs and dashboard assets are present

That last one is not pedantry. Node refuses to strip types for files under
`node_modules` (`ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING`), so a package
whose entry point is `.mts` installs cleanly and then fails on first run. It was
found by actually installing the tarball, which is why `package:verify` exists.

## Why there are two build shapes

| Shape | Entry | Used by |
|---|---|---|
| Source | `packages/cli/src/bin.ts` | git clone — no build step |
| Compiled | `build/publish/.../bin.js` | npm tarball |

The source shape is the primary install path for a security tool: a team
evaluating Aegis clones it and runs `node packages/cli/src/bin.ts scan .` with no
`npm install` at all. The compiled shape exists because npm installs *into*
`node_modules`, where Node will not type-strip.

`packages/cli/src/bin.ts` picks whichever is present, so the same command works
in both.

## Verifying a release

```bash
npm run verify          # typecheck + all tests + smoke + readiness
npm run package:verify  # install-and-run the published artifact
```

`package:verify` installs into a throwaway directory and checks that a consumer
can:

- run `npx aegis --version` and `--help`
- scan a deliberately vulnerable agent and get findings
- **not** see the raw secret in the output
- emit valid SARIF 2.1.0
- render a compliance attestation
- run a red-team dry run
- read the bundled rule packs
- install with **zero transitive dependencies**

## Before the first publish

- [ ] `npm view aegis` resolves once published
- [ ] Confirm the tarball size (currently ~264 KB)
- [ ] Confirm `npm install -g aegis` puts a working `aegis` on PATH
- [ ] Tag the release: `git tag v0.1.0`
- [ ] Add the integrity hash to the release notes

## Registry

The package is named `aegis`. If the name is taken on npm, publish under a
scoped name instead and update `bin` and `keywords` in `aegis.package.json`:

```bash
npm publish dist/aegis-0.1.0.tgz --access public --registry https://registry.npmjs.org
```

For a scope, set `"name": "@aegis-security/aegis"` and publish with
`--access public`.

## Licence

- Engine, CLI, dashboard, feed parsers: **MIT**
- Rule packs in `packages/rules`: **CC0 1.0**, public domain

The dashboard source ships with the package so buyers can self-host. See
`DELIVERY.md` §7 for the hosted-versus-on-prem split.