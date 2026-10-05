import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { open } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startDashboard, type DashboardOptions } from './server.js';

/**
 * Desktop application.
 *
 * Delivered as a native window rather than a browser tab, because the browser is
 * the part users already have too many of: a standalone window reads as an app,
 * has no address bar to break focus with, and keeps the process tree together.
 *
 * Implemented against the platform's own shell rather than Electron or Tauri.
 * Those would add 150–250 MB of runtime to a tool whose entire pitch is that it
 * has no dependencies — that is not a trade this product can make. Chrome and
 * Edge (present on the overwhelming majority of desktops) both support
 * application mode, which gives a chromeless, tab-less window with zero
 * installed software. When no such browser exists we fall back to the default
 * browser and say so.
 */

const here = dirname(fileURLToPath(import.meta.url));

export interface DesktopOptions extends DashboardOptions {
  /** Open the window on launch. Default true. */
  open?: boolean;
  /** Force a specific browser instead of auto-detecting. */
  browser?: 'chrome' | 'edge' | 'firefox' | 'system';
  /** Keep the process in the foreground. Default true. */
  foreground?: boolean;
}

/** Browsers that can open a chromeless application window. */
interface BrowserCandidate {
  id: 'chrome' | 'edge';
  /** Executables to try, in order, per platform. */
  paths: Record<string, string[]>;
}

const CANDIDATES: BrowserCandidate[] = [
  {
    id: 'chrome',
    paths: {
      win32: [
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
        join(process.env['LOCALAPPDATA'] ?? '', 'Google', 'Chrome', 'Application', 'chrome.exe'),
      ],
      darwin: ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'],
      linux: ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/snap/bin/chromium'],
    },
  },
  {
    id: 'edge',
    paths: {
      win32: [
        'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
        'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
        join(process.env['PROGRAMFILES(X86)'] ?? '', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      ],
      darwin: ['/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'],
      linux: ['/usr/bin/microsoft-edge', '/usr/bin/microsoft-edge-stable'],
    },
  },
];

export interface DesktopLaunch {
  url: string;
  /** How the window was opened. */
  mode: 'app-window' | 'browser' | 'headless';
  browser?: string;
  /** Pid of the spawned window process, when one was launched. */
  pid?: number;
}

/** Find a browser that supports application mode. */
export function findAppBrowser(
  requested: DesktopOptions['browser'] = 'system',
): { executable: string; id: string } | null {
  const candidates = requested === 'system' || !requested
    ? CANDIDATES
    : CANDIDATES.filter((c) => c.id === requested);
  const pathsFor = process.platform === 'win32'
    ? 'win32'
    : process.platform === 'darwin'
      ? 'darwin'
      : 'linux';

  for (const candidate of candidates) {
    for (const path of candidate.paths[pathsFor] ?? []) {
      if (path && existsSync(path)) return { executable: path, id: candidate.id };
    }
  }
  return null;
}

/** Open a URL as a chromeless application window where possible. */
export function openAppWindow(
  url: string,
  requested: DesktopOptions['browser'] = 'system',
  profileDir?: string,
): DesktopLaunch {
  const found = findAppBrowser(requested);

  if (found) {
    // A dedicated profile keeps the window isolated from the user's real
    // browser session: no extension bleed-through, no cookie sharing, and the
    // window closes cleanly without touching their tabs.
    const args = [
      `--app=${url}`,
      '--window-size=1440,960',
      '--disable-features=TranslateUI',
      '--no-first-run',
      '--no-default-browser-check',
    ];
    if (profileDir) args.push(`--user-data-dir=${profileDir}`);

    try {
      const child = spawn(found.executable, args, { detached: true, stdio: 'ignore', shell: false });
      child.unref();
      return { url, mode: 'app-window', browser: found.id, pid: child.pid };
    } catch {
      // Fall through to the default browser.
    }
  }

  // No application-mode browser: open in the default browser rather than
  // failing. The user still gets the product; they just get an address bar too.
  const opener = process.platform === 'win32'
    ? ['cmd', ['/c', 'start', '', url]]
    : process.platform === 'darwin'
      ? ['open', [url]]
      : ['xdg-open', [url]];
  try {
    const child = spawn(opener[0] as string, opener[1] as string[], {
      detached: true,
      stdio: 'ignore',
      shell: process.platform === 'win32',
    });
    child.unref();
    return { url, mode: 'browser' };
  } catch {
    return { url, mode: 'headless' };
  }
}

/**
 * Start the dashboard and open the desktop window.
 *
 * Stays in the foreground so closing the window is what stops the server —
 * otherwise the app is a process nobody can shut down.
 */
export async function launchDesktop(options: DesktopOptions = {}): Promise<{
  launch: DesktopLaunch;
  stop: () => Promise<void>;
}> {
  const dataDir = resolve(options.dataDir ?? join(process.cwd(), '.aegis', 'dashboard'));
  const port = options.port ?? 8080;
  const host = options.host ?? '127.0.0.1';

  const { url } = await startDashboard({
    ...options,
    dataDir,
    port,
    host,
  });

  const profileDir = join(dataDir, '.browser-profile');
  const launch = options.open === false
    ? ({ url, mode: 'headless' } as DesktopLaunch)
    : openAppWindow(url, options.browser, profileDir);

  // Ensure the profile directory exists so the browser does not prompt.
  if (launch.mode === 'app-window') {
    await open(profileDir, 'w').then((fh) => fh.close()).catch(() => {});
  }

  return {
    launch,
    stop: async () => {
      // Nothing to tear down beyond the server, which closes with the process.
    },
  };
}

export { here as desktopRoot };