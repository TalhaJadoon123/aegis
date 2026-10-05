#!/usr/bin/env node
/**
 * Aegis CLI entry point.
 *
 * Two build shapes have to work:
 *
 *  - From a git clone, running TypeScript directly on Node 22 with no build
 *    step. This is the primary install path for a security tool and the reason
 *    the engine has no runtime dependencies.
 *  - From an npm tarball, where the same sources are compiled to JavaScript.
 *    Node refuses to type-strip anything under `node_modules`
 *    (ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING), so the published package
 *    must ship real `.js`.
 *
 * So: prefer a sibling `main.js` when one exists next to this file, and fall
 * back to `main.ts` otherwise.
 */
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

const compiled = join(here, 'main.js');
const source = join(here, 'main.ts');
const entry = existsSync(compiled) ? compiled : source;

if (!existsSync(entry)) {
  process.stderr.write('aegis: cannot locate the CLI entry point (main.js or main.ts)\n');
  process.exit(70);
}

const { main } = (await import(pathToFileURL(entry).href)) as {
  main: (argv: readonly string[]) => Promise<number>;
};

process.exitCode = await main(process.argv.slice(2));