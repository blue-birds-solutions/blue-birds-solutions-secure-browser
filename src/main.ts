import {
  app,
  BrowserWindow,
  ipcMain,
  globalShortcut,
  screen,
  clipboard,
  IpcMainEvent,
} from 'electron';
import path from 'path';
import { exec } from 'child_process';
import { autoUpdater } from 'electron-updater';

// ─── Type Definitions ────────────────────────────────────────────────────────

interface SecurityStatus {
  hasViolation: boolean;
  type: string | null;
  process?: string;
  message: string | null;
}

interface SystemStatus {
  kioskMode: boolean;
  antiScreenshot: boolean;
  multipleMonitors: boolean;
  os: NodeJS.Platform;
}

// ─── Constants ────────────────────────────────────────────────────────────────

/** Determine if we are in development mode. */
const IS_DEV: boolean =
  process.env.NODE_ENV === 'development' || process.argv.includes('--dev');

/** Blacklisted processes: remote control, screen capture, communication, and sharing tools. */
const BLACKLIST: readonly string[] = [
  'discord',
  'zoom',
  'skype',
  'teams',
  'slack',
  'teamviewer',
  'anydesk',
  'obs',
  'obs64',
  'snippingtool',
  'screenshot',
  'whatsapp',
  'telegram',
  'vncviewer',
  'webex',
  'gotomeeting',
  'chrome-remote-desktop',
  'parsec',
  'teamviewer_service',
  'dwagent',
  'getscreen',
  'ultraviewer',
  'rustdesk',
  'ammyy',
  'supremo',
  'splashtop',
  'logmein',
  'joinme',
  'gotomypc',
  'tightvnc',
  'ultravnc',
  'realvnc',
];

/** Virtual machine processes/drivers to detect virtualized environments. */
const VM_INDICATORS: readonly string[] = [
  'vboxservice',
  'vboxtray',
  'vmtoolsd',
  'vmware',
  'qemu',
  'prl_tools_service', // Parallels
  'hyperv',
];

/** Keyboard shortcuts to suppress at the OS level in production. */
const BLOCKED_SHORTCUTS: readonly string[] = [
  'Alt+Tab',
  'Alt+F4',
  'Command+Tab',
  'Command+Alt+Escape',
  'Ctrl+Alt+Delete',
];

// ─── State ───────────────────────────────────────────────────────────────────

let mainWindow: BrowserWindow | null = null;
let processMonitorInterval: ReturnType<typeof setInterval> | null = null;
let clipboardWiperInterval: ReturnType<typeof setInterval> | null = null;
let isExamActive = false;

// ─── Window Creation ─────────────────────────────────────────────────────────

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    fullscreen: !IS_DEV,
    kiosk: !IS_DEV,        // Locks user into foreground, intercepts OS commands
    alwaysOnTop: !IS_DEV,
    skipTaskbar: !IS_DEV,
    frame: IS_DEV,         // No title bar/frame in production
    icon: path.join(__dirname, '..', 'desktop_icon_256x256.ico'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      // In production the compiled preload lives in dist/preload.js
      preload: path.join(__dirname, 'preload.js'),
      sandbox: true,
    },
  });

  // Anti-Screenshot / Screen Capture blocking.
  // setContentProtection(true) makes the window render as black in OS capture tools.
  if (!IS_DEV) {
    mainWindow.setContentProtection(true);
  }

  // Resolve the target URL: env override → dev server → production URL
  const targetUrl: string =
    process.env.APP_URL ??
    (IS_DEV ? 'http://localhost:5173' : 'https://tests.bluebirdstraining.com');

  console.log(`[SecureBrowser] Loading target: ${targetUrl}`);
  mainWindow.loadURL(targetUrl);

  // Open DevTools only in developer mode
  if (IS_DEV) {
    mainWindow.webContents.openDevTools();
  }

  // Force window focus back to the app when it loses focus (production only)
  mainWindow.on('blur', (): void => {
    if (!IS_DEV && mainWindow) {
      mainWindow.focus();
      mainWindow.webContents.send('window-blur');
    }
  });

  mainWindow.on('focus', (): void => {
    mainWindow?.webContents.send('window-focus');
  });

  mainWindow.on('closed', (): void => {
    mainWindow = null;
  });

  // Intercept and block common cheat keyboard shortcuts inside the renderer
  mainWindow.webContents.on('before-input-event', (_event, input): void => {
    if (IS_DEV) return;

    const key: string = input.key.toLowerCase();
    const cmdOrCtrl: boolean = input.meta || input.control;

    // Block DevTools shortcuts: F12, Ctrl+Shift+I, Cmd+Option+I
    if (key === 'f12' || (cmdOrCtrl && input.shift && key === 'i')) {
      _event.preventDefault();
    }

    // Block page-reload shortcuts: Ctrl+R, Cmd+R, F5
    if (key === 'f5' || (cmdOrCtrl && key === 'r')) {
      _event.preventDefault();
    }

    // Block OS-level shortcuts: Alt+F4, Alt+Tab, Cmd+Alt+Esc
    if (
      (input.alt && key === 'f4') ||
      (input.alt && key === 'tab') ||
      (cmdOrCtrl && input.alt && key === 'escape')
    ) {
      _event.preventDefault();
    }
  });
}

// ─── Global Shortcut Blocker ─────────────────────────────────────────────────

function registerGlobalShortcuts(): void {
  if (IS_DEV) return;

  for (const shortcut of BLOCKED_SHORTCUTS) {
    try {
      globalShortcut.register(shortcut, (): void => {
        console.log(`[SecureBrowser] Blocked OS shortcut: ${shortcut}`);
        // Intentionally a no-op to suppress the shortcut
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.warn(`[SecureBrowser] Failed to block shortcut "${shortcut}": ${message}`);
    }
  }
}

// ─── Process Monitor ─────────────────────────────────────────────────────────

/**
 * Parse process names from the raw output of:
 *  - Windows: `tasklist /FO CSV /NH`
 *  - macOS/Linux: `ps -ax -o comm=`
 */
function parseProcessNames(stdout: string, isWindows: boolean): string[] {
  const lines = stdout.split('\n');

  if (isWindows) {
    return lines
      .map((line): string => {
        const match = line.match(/^"([^"]+)"/);
        return match ? match[1].toLowerCase() : '';
      })
      .filter(Boolean);
  }

  return lines
    .map((line): string => path.basename(line.trim()).toLowerCase())
    .filter(Boolean);
}

/**
 * Check a list of process names against the blacklist and VM indicator lists.
 * Returns the first violation found, or null if the environment is clean.
 */
function detectViolation(processes: string[]): SecurityStatus | null {
  for (const proc of processes) {
    if (BLACKLIST.some((black) => proc.includes(black))) {
      return {
        hasViolation: true,
        type: 'blacklisted-app',
        process: proc,
        message: `Forbidden application running: "${proc}". Please close it to proceed with the test.`,
      };
    }

    if (VM_INDICATORS.some((vm) => proc.includes(vm))) {
      return {
        hasViolation: true,
        type: 'vm-detected',
        process: proc,
        message: 'Virtual Machine environment detected. This test must be taken on physical hardware.',
      };
    }
  }

  return null;
}

/** Send a security status event to the renderer window. */
function sendSecurityStatus(status: SecurityStatus): void {
  if (mainWindow) {
    mainWindow.webContents.send('security-status-update', status);
  }
}

function startProcessMonitor(): void {
  const isWindows: boolean = process.platform === 'win32';
  const queryCommand: string = isWindows ? 'tasklist /FO CSV /NH' : 'ps -ax -o comm=';

  processMonitorInterval = setInterval((): void => {
    // Check for multiple connected displays before querying processes
    const displays = screen.getAllDisplays();
    const multipleMonitors: boolean = displays.length > 1;

    if (multipleMonitors && !IS_DEV) {
      sendSecurityStatus({
        hasViolation: true,
        type: 'multiple-monitors',
        message: 'Multiple monitors detected. Please disconnect external screens to continue.',
      });
      return;
    }

    exec(queryCommand, (err, stdout): void => {
      if (err) {
        console.error('[SecureBrowser] Failed to query system processes:', err.message);
        return;
      }

      const processes = parseProcessNames(stdout, isWindows);
      const violation = detectViolation(processes);

      if (violation) {
        console.warn(
          `[SecureBrowser] Security violation — type: ${violation.type}, process: ${violation.process ?? 'N/A'}`,
        );
        sendSecurityStatus(violation);
      } else {
        sendSecurityStatus({ hasViolation: false, type: null, message: null });
      }
    });
  }, 3_000); // Audit every 3 seconds
}

// ─── Clipboard Wiper ─────────────────────────────────────────────────────────

function startClipboardWiper(): void {
  if (IS_DEV) return;

  clipboardWiperInterval = setInterval((): void => {
    try {
      const currentText = clipboard.readText();
      if (currentText.trim().length > 0) {
        clipboard.clear();
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error('[SecureBrowser] Failed to clear clipboard:', message);
    }
  }, 1_000); // Wipe clipboard every second
}

// ─── IPC Handlers ────────────────────────────────────────────────────────────

ipcMain.handle('get-system-status', (): SystemStatus => {
  const displays = screen.getAllDisplays();
  return {
    kioskMode: !IS_DEV,
    antiScreenshot: !IS_DEV,
    multipleMonitors: displays.length > 1,
    os: process.platform,
  };
});

ipcMain.on('close-browser', (_event: IpcMainEvent): void => {
  console.log('[SecureBrowser] Closing application on renderer request...');
  app.quit();
});

ipcMain.on('exam-started', (): void => {
  console.log('[SecureBrowser] Exam started. Auto-updates and restarts disabled.');
  isExamActive = true;
});

ipcMain.on('exam-finished', (): void => {
  console.log('[SecureBrowser] Exam finished. Auto-updates enabled.');
  isExamActive = false;
});

// ─── Deep Link & Single Instance Handler ──────────────────────────────────────

function handleDeepLink(urlStr: string): void {
  console.log(`[SecureBrowser] Deep link received: ${urlStr}`);
  try {
    const parsedUrl = new URL(urlStr);
    const attemptId = parsedUrl.searchParams.get('attemptId');
    const token = parsedUrl.searchParams.get('token');

    if (attemptId && token && mainWindow) {
      const origin =
        process.env.APP_URL ??
        (IS_DEV ? 'http://localhost:5173' : 'https://tests.bluebirdstraining.com');
      const targetUrl = `${origin}/quiz/${attemptId}`;

      console.log(`[SecureBrowser] Launching quiz attempt via deep link: ${attemptId}`);

      // Navigate to origin root first to ensure correct domain context for localStorage
      mainWindow.loadURL(origin).then((): void => {
        if (!mainWindow) return;
        // Inject token into localStorage
        mainWindow.webContents
          .executeJavaScript(
            `
            try {
              localStorage.setItem('accessToken', '${token}');
              console.log('[SecureBrowser] Deep link token injected successfully.');
            } catch (e) {
              console.error('[SecureBrowser] Deep link token injection failed:', e);
            }
            `
          )
          .then((): void => {
            // Navigate directly to the quiz page
            mainWindow?.loadURL(targetUrl);
          });
      });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error('[SecureBrowser] Failed to parse deep link URL:', message);
  }
}

const gotTheLock = app.requestSingleInstanceLock();

if (!gotTheLock) {
  console.log('[SecureBrowser] Another instance is already running. Quitting.');
  app.quit();
} else {
  app.on('second-instance', (event, commandLine): void => {
    // Focus the main window
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }

    // Parse deep link url on Windows/Linux
    const url = commandLine.pop();
    if (url && url.startsWith('bluebirds-sb://')) {
      handleDeepLink(url);
    }
  });

  // Register the protocol handler on startup
  if (process.defaultApp) {
    if (process.argv.length >= 2) {
      app.setAsDefaultProtocolClient('bluebirds-sb', process.execPath, [
        path.resolve(process.argv[1]),
      ]);
    }
  } else {
    app.setAsDefaultProtocolClient('bluebirds-sb');
  }

  // Handle URL events on macOS
  app.on('open-url', (event, url): void => {
    event.preventDefault();
    handleDeepLink(url);
  });

  // ─── App Lifecycle ───────────────────────────────────────────────────────────

  app.whenReady().then((): void => {
    createWindow();
    registerGlobalShortcuts();
    startProcessMonitor();
    startClipboardWiper();

    // Check if launched via deep link (Windows/Linux)
    const deepLinkArg = process.argv.find((arg): boolean =>
      arg.startsWith('bluebirds-sb://')
    );
    if (deepLinkArg) {
      setTimeout((): void => {
        handleDeepLink(deepLinkArg);
      }, 1000);
    }

    // Setup Auto-Updater
    autoUpdater.autoDownload = true;
    autoUpdater.autoInstallOnAppQuit = true;

    autoUpdater.on('update-downloaded', (): void => {
      if (!isExamActive) {
        console.log('[SecureBrowser] Update downloaded and student is not in exam. Installing...');
        autoUpdater.quitAndInstall();
      } else {
        console.log('[SecureBrowser] Update downloaded during an active exam session. Postponing installation.');
      }
    });

    if (!IS_DEV) {
      autoUpdater.checkForUpdatesAndNotify().catch((err: Error): void => {
        console.error('[SecureBrowser] Failed to check for updates:', err.message);
      });
    }

    // Re-create window on macOS when the dock icon is clicked and no windows are open
    app.on('activate', (): void => {
      if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
      }
    });
  });
}

// On non-macOS platforms, quit the app when all windows are closed
app.on('window-all-closed', (): void => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// Clean up on quit
app.on('will-quit', (): void => {
  globalShortcut.unregisterAll();
  if (processMonitorInterval !== null) clearInterval(processMonitorInterval);
  if (clipboardWiperInterval !== null) clearInterval(clipboardWiperInterval);
  console.log('[SecureBrowser] Application terminated and resources cleaned up.');
});
