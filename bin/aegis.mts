#!/usr/bin/env node
/**
 * Published entry point for `npx aegis` / `npm install -g aegis`.
 *
 * Registers the TypeScript resolve hook before importing the CLI, so the
 * published package works without a build step. This is what makes "zero
 * dependencies, runs anywhere" true for an npm-installed copy, not just a git
 * clone.
 */
import { register } from 'node:module';
import { pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

// `tools/register-ts.mjs` lives at the package root in the published tarball.
try {
  register(pathToFileURL(join(root, 'tools', 'register-ts.mjs')).href);
} catch {
  // Already registered, or running from source; either is fine.
}

const { main } = (await import(pathToFileURL(join(root, 'packages', 'cli', 'src', 'main.ts')).href)) as {
  main: (argv: readonly string[]) => Promise<number>;
};

process.exitCode = await main(process.argv.slice(2));