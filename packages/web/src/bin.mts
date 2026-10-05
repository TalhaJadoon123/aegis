#!/usr/bin/env node
/**
 * Aegis dashboard entry point.
 *
 * Usage: node packages/web/src/bin.mjs [--port 8080] [--data .aegis/dashboard]
 */
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

// On Windows a bare `E:\path` is parsed as a URL scheme, so resolve relative to
// this module and convert to a file URL before importing.
const here = dirname(fileURLToPath(import.meta.url));
const { startDashboard } = (await import(pathToFileURL(join(here, 'server.ts')).href)) as {
  startDashboard: (options: Record<string, unknown>) => Promise<{ url: string }>;
};

const argv = process.argv.slice(2);
function flag(name, fallback) {
  const i = argv.indexOf(`--${name}`);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : fallback;
}

const { url } = await startDashboard({
  dataDir: flag('data', '.aegis/dashboard'),
  port: Number(flag('port', '8080')),
  logger: {
    info: (m) => process.stdout.write(`${m}\n`),
    warn: (m) => process.stderr.write(`${m}\n`),
    error: (m) => process.stderr.write(`${m}\n`),
  },
});

process.stdout.write(`\n  Aegis dashboard: ${url}\n\n`);