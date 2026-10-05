#!/usr/bin/env node
/**
 * Aegis desktop launcher.
 *
 * Starts the dashboard and opens it as a chromeless application window, then
 * stays in the foreground so closing the window is what stops the process.
 *
 *   node packages/web/src/bin-desktop.mts --port 8080 --data .aegis/dashboard
 */
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));
const { launchDesktop } = (await import(
  pathToFileURL(join(here, 'desktop.ts')).href
)) as typeof import('./desktop.js');

const argv = process.argv.slice(2);
function flag(name: string, fallback?: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : fallback;
}
const has = (name: string) => argv.includes(`--${name}`);

const port = Number(flag('port', '8080'));
const dataDir = resolve(flag('data', join(process.cwd(), '.aegis', 'dashboard'))!);
const token = process.env['AEGIS_DASHBOARD_TOKEN'];
if (!existsSync(dataDir)) mkdirSync(dataDir, { recursive: true });

process.stdout.write(`\n  Aegis — starting\n`);

const { launch } = await launchDesktop({
  dataDir,
  port,
  ...(token ? { token } : {}),
  ...(has('browser') ? { browser: flag('browser') as never } : {}),
  ...(has('no-open') ? { open: false } : {}),
});

const modeNote = {
  'app-window': `application window via ${launch.browser}`,
  browser: 'your default browser (no app-mode browser found)',
  headless: 'no window opened',
}[launch.mode];

process.stdout.write(`  ${launch.url}\n  ${modeNote}\n`);
if (!token) {
  process.stdout.write('  no AEGIS_DASHBOARD_TOKEN set — bound to loopback only\n');
}

if (launch.mode === 'headless' && !has('no-open')) {
  process.stdout.write(`\n  Open ${launch.url} in a browser.\n`);
}

// Write a small launcher so the desktop entry point is discoverable from a
// double-click rather than only from a terminal.
writeFileSync(
  join(dataDir, 'open-dashboard.html'),
  `<!doctype html><meta charset="utf-8"><title>Aegis</title>` +
    `<script>location.replace(${JSON.stringify(launch.url)})</script>`,
  'utf8',
);

process.stdout.write('\n  Close the window (or press Ctrl+C) to stop.\n\n');

if (!has('no-open') && launch.mode !== 'headless') {
  // Hold the process open. Without this the server would exit with the script.
  await new Promise<void>((resolvePromise) => {
    const stop = (): void => {
      process.stdout.write('\n  Aegis stopped.\n');
      resolvePromise();
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    if (has('exit-after-open')) {
      // For CI and scripted checks: verify the server, then exit.
      setTimeout(stop, 1500);
    }
  });
}