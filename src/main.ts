import {
  app,
  BrowserWindow,
  ipcMain,
  globalShortcut,
  screen,
  clipboard,
  session,
  IpcMainEvent,
  dialog,
  desktopCapturer,
  systemPreferences,
  shell,
} from 'electron';
import path from 'path';
import { exec } from 'child_process';
import https from 'https';
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
let overlayWindow: BrowserWindow | null = null;
let splashWindow: BrowserWindow | null = null;
let processMonitorInterval: ReturnType<typeof setInterval> | null = null;
let clipboardWiperInterval: ReturnType<typeof setInterval> | null = null;
let wifiMonitorInterval: ReturnType<typeof setInterval> | null = null;
let isExamActive = false;
let wasOpenedViaDeepLink = false;
let consecutiveOfflineCount = 0;
let isInitialized = false;
let pendingDeepLinkUrl: string | null = null;
/**
 * When true the app is waiting for the user to configure a macOS permission
 * (Screen Recording, Camera, Microphone) in System Settings. In this state we
 * MUST NOT steal focus back from System Settings or other OS dialogs, and kiosk /
 * fullscreen must be suspended so those dialogs are reachable.
 */
let isRequestingPermission = false;
/** Credentials injected from deep link — made available to preload synchronously */
let activeAttemptId: string | null = null;
let activeToken: string | null = null;

// ─── Helpers: kiosk / fullscreen lockout management ──────────────────────────

/**
 * Temporarily lifts all kiosk/always-on-top constraints so that macOS system
 * dialogs and System Settings can appear above the window.
 */
function suspendKioskLockout(): void {
  if (IS_DEV || !mainWindow || mainWindow.isDestroyed()) return;
  console.log('[SecureBrowser] Suspending kiosk lockout for permission dialog.');
  mainWindow.setKiosk(false);
  mainWindow.setFullScreen(false);
  mainWindow.setAlwaysOnTop(false);
}

/**
 * Restores all kiosk/always-on-top constraints after a permission dialog is
 * resolved. Only call when the app should be in full lockout mode.
 */
function restoreKioskLockout(): void {
  if (IS_DEV || !mainWindow || mainWindow.isDestroyed()) return;
  console.log('[SecureBrowser] Restoring kiosk lockout.');
  mainWindow.setAlwaysOnTop(true, 'screen-saver');
  mainWindow.setFullScreen(true);
  mainWindow.setKiosk(true);
  mainWindow.focus();
}

// ─── Window Creation ─────────────────────────────────────────────────────────

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    show: false,           // Start hidden to prevent white flash
    backgroundColor: '#0a0b0f', // Dark background matches theme
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

  // Build the initial URL — if launched via deep link, go directly to system-check
  const origin: string =
    process.env.APP_URL ??
    (IS_DEV ? 'http://localhost:5173' : 'https://tests.bluebirdstraining.com');

  const initialUrl = activeAttemptId
    ? `${origin}/system-check/${activeAttemptId}`
    : origin;

  console.log(`[SecureBrowser] Loading initial URL: ${initialUrl}`);
  mainWindow.loadURL(initialUrl);

  // Show window only when content is ready (prevents white flash)
  mainWindow.once('ready-to-show', (): void => {
    if (mainWindow) {
      mainWindow.show();
      if (!IS_DEV) {
        mainWindow.setAlwaysOnTop(true, 'screen-saver');
        mainWindow.focus();
        bringAppToFront();
      }
      // In dev mode (no native fullscreen) show overlay immediately.
      if (IS_DEV && overlayWindow && !overlayWindow.isDestroyed()) {
        overlayWindow.show();
        overlayWindow.setAlwaysOnTop(true, 'screen-saver');
        syncOverlayPosition();
      }
      // Close splash screen
      if (splashWindow) {
        splashWindow.destroy();
        splashWindow = null;
      }

      if (!IS_DEV) {
        // ── Resilient overlay show loop ─────────────────────────────────────
        // On macOS, kiosk mode moves the window to a native fullscreen Space.
        // The 'enter-full-screen' event may fire before the Space transition
        // settles, causing the overlay to appear on the OLD desktop Space
        // (invisible to the user). We fix this by retrying every 500 ms for
        // up to 10 seconds. Once the overlay is confirmed visible on the
        // correct Space, we stop retrying.
        //
        // setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true }) ensures
        // the overlay is eligible to appear in the fullscreen Space; the loop
        // forces macOS to re-evaluate its placement after the Space settles.
        let retryCount = 0;
        const MAX_RETRIES = 20; // 20 × 500ms = 10 seconds
        const showOverlayRetry = setInterval((): void => {
          if (!overlayWindow || overlayWindow.isDestroyed()) {
            clearInterval(showOverlayRetry);
            return;
          }
          retryCount++;
          syncOverlayPosition();
          overlayWindow.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
          overlayWindow.show();
          overlayWindow.setAlwaysOnTop(true, 'screen-saver');
          console.log(`[SecureBrowser] Overlay show attempt ${retryCount}/${MAX_RETRIES}`);
          if (retryCount >= MAX_RETRIES) {
            clearInterval(showOverlayRetry);
            console.log('[SecureBrowser] Overlay show retry loop complete.');
          }
        }, 500);

        // Additionally, keep re-asserting alwaysOnTop every 2 seconds forever
        // so kiosk mode cannot bury the overlay if focus bounces.
        setInterval((): void => {
          if (overlayWindow && !overlayWindow.isDestroyed()) {
            overlayWindow.setAlwaysOnTop(true, 'screen-saver');
          }
        }, 2000);
      }
    }
  });

  // ── macOS native fullscreen Space transition ──────────────────────────────
  // 'enter-full-screen' fires AFTER macOS finishes animating the window into
  // its own Space. Re-assert overlay here as an additional safety net.
  mainWindow.on('enter-full-screen', (): void => {
    if (overlayWindow && !overlayWindow.isDestroyed()) {
      // Give the Space animation a brief moment to settle (500ms)
      setTimeout((): void => {
        if (!overlayWindow || overlayWindow.isDestroyed()) return;
        syncOverlayPosition();
        overlayWindow.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
        overlayWindow.show();
        overlayWindow.setAlwaysOnTop(true, 'screen-saver');
        console.log('[SecureBrowser] Overlay re-asserted in enter-full-screen handler.');
      }, 500);
    }
  });

  // Re-assert overlay whenever the main window gains focus so kiosk cannot bury it.
  mainWindow.on('focus', (): void => {
    mainWindow?.webContents.send('window-focus');
    if (!IS_DEV && overlayWindow && !overlayWindow.isDestroyed()) {
      overlayWindow.setAlwaysOnTop(true, 'screen-saver');
    }
    // When returning focus after a permission request, check if permission
    // has now been granted. If so, restore full lockout automatically.
    if (!IS_DEV && isRequestingPermission) {
      (async (): Promise<void> => {
        try {
          if (process.platform === 'darwin') {
            const status = systemPreferences.getMediaAccessStatus('screen');
            if (status === 'granted') {
              const sources = await desktopCapturer.getSources({ types: ['screen'] });
              if (sources.length > 0) {
                console.log('[SecureBrowser] Screen permission confirmed on focus return. Restoring lockout.');
                isRequestingPermission = false;
                restoreKioskLockout();
              }
            }
          } else {
            isRequestingPermission = false;
            restoreKioskLockout();
          }
        } catch (e) {
          console.warn('[SecureBrowser] Error checking permission on focus return:', e);
        }
      })();
    }
  });

  // Handle load failure to avoid hanging splash screen
  mainWindow.webContents.on('did-fail-load', (_event, errorCode, errorDescription, validatedURL): void => {
    console.error(`[SecureBrowser] Failed to load URL: ${validatedURL} (${errorCode}: ${errorDescription})`);
    if (splashWindow) {
      splashWindow.destroy();
      splashWindow = null;
    }
    if (mainWindow) {
      mainWindow.show();
    }
  });

  // Open DevTools only in developer mode
  if (IS_DEV) {
    mainWindow.webContents.openDevTools();
  }

  // Force window focus back to the app when it loses focus (production only).
  // IMPORTANT: Do NOT steal focus when the app is in "permission request" mode —
  // that is when the user needs to interact with a macOS dialog or System Settings.
  mainWindow.on('blur', (): void => {
    if (!IS_DEV && mainWindow && !isRequestingPermission) {
      mainWindow.focus();
      mainWindow.webContents.send('window-blur');
    } else if (!IS_DEV && mainWindow && isRequestingPermission) {
      // Send blur so the UI knows focus was lost, but do NOT steal it back
      mainWindow.webContents.send('window-blur');
    }
  });



  mainWindow.on('closed', (): void => {
    mainWindow = null;
  });

  mainWindow.on('moved', syncOverlayPosition);
  mainWindow.on('resized', syncOverlayPosition);

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

// ─── Splash Window ─────────────────────────────────────────────────────────────

function createSplashWindow(): void {
  splashWindow = new BrowserWindow({
    width: 450,
    height: 300,
    frame: false,
    transparent: true,
    alwaysOnTop: true,
    resizable: false,
    movable: false,
    center: true,
    skipTaskbar: true,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
  });

  if (process.platform === 'darwin') {
    splashWindow.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
  }

  const splashPath = path.join(__dirname, '..', 'src', 'splash.html');
  splashWindow.loadFile(splashPath);

  splashWindow.on('closed', (): void => {
    splashWindow = null;
  });

  console.log('[SecureBrowser] Splash window created.');
}

// ─── Overlay Window ─────────────────────────────────────────────────────────────

function createOverlayWindow(): void {
  // Use physical screen bounds so the bar spans the full screen width
  // even when the Dock/menu bar is on a side.
  const { bounds } = screen.getPrimaryDisplay();
  console.log(`[SecureBrowser] Primary display bounds: x=${bounds.x} y=${bounds.y} w=${bounds.width} h=${bounds.height}`);

  // ── Standalone window — NO parent relationship ───────────────────────────
  // macOS parent-child semantics on kiosk+fullscreen windows are unreliable:
  // a child added before the parent enters fullscreen stays on the old Space.
  // We use setVisibleOnAllWorkspaces(true, {visibleOnFullScreen:true}) so macOS
  // renders it in every Space including native fullscreen ones.
  overlayWindow = new BrowserWindow({
    width: bounds.width,
    height: 36,
    x: bounds.x,
    y: bounds.y,
    frame: false,
    transparent: true,
    alwaysOnTop: true,
    skipTaskbar: true,
    resizable: false,
    movable: false,
    focusable: true,    // Must be true — IPC from close button requires focus
    hasShadow: false,
    show: false,        // Hidden until the retry loop shows it after ready-to-show
    type: 'panel',      // 'panel' windows float above kiosk/fullscreen on macOS
    webPreferences: {
      nodeIntegration: true,    // Trusted local file — IPC via require('electron')
      contextIsolation: false,
      sandbox: false,
    },
  });

  overlayWindow.setIgnoreMouseEvents(false);
  overlayWindow.setAlwaysOnTop(true, 'screen-saver');

  // This is the key call: tells macOS this window must appear in ALL Spaces
  // including native fullscreen ones — without needing a parent relationship.
  overlayWindow.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });

  const overlayPath = path.join(__dirname, '..', 'src', 'overlay.html');
  overlayWindow.loadFile(overlayPath);

  overlayWindow.on('closed', (): void => {
    overlayWindow = null;
  });

  console.log('[SecureBrowser] Overlay window created (standalone, all-workspaces, panel type).');
}


/** Keep overlay bar pinned to the absolute top of the physical screen. */
function syncOverlayPosition(): void {
  if (!overlayWindow || overlayWindow.isDestroyed()) return;
  const { bounds } = screen.getPrimaryDisplay();
  // Always use physical screen x:0, y:0 and full physical width.
  // In kiosk/fullscreen mode the main window covers the whole screen so the
  // overlay should too.  workAreaSize excludes the Dock which we do NOT want.
  overlayWindow.setBounds({ x: bounds.x, y: bounds.y, width: bounds.width, height: 36 });
}

// ─── WiFi Monitor ────────────────────────────────────────────────────────────────

/**
 * Measures round-trip latency to the target server using a lightweight HTTPS HEAD
 * request. Returns the ms value on success, or null on failure/timeout.
 */
function pingTarget(targetUrl: string): Promise<number | null> {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(null), 5000);
    const start = Date.now();

    try {
      const url = new URL(targetUrl);
      const req = https.request(
        {
          method: 'HEAD',
          hostname: url.hostname,
          port: url.port || 443,
          path: '/',
          timeout: 5000,
          rejectUnauthorized: false, // Self-signed certs on internal deployments
        },
        () => {
          clearTimeout(timeout);
          resolve(Date.now() - start);
        },
      );

      req.on('error', () => {
        clearTimeout(timeout);
        resolve(null);
      });

      req.on('timeout', () => {
        req.destroy();
        clearTimeout(timeout);
        resolve(null);
      });

      req.end();
    } catch {
      clearTimeout(timeout);
      resolve(null);
    }
  });
}

function startWifiMonitor(): void {
  const targetUrl =
    process.env.APP_URL ??
    (IS_DEV ? 'https://tests.bluebirdstraining.com' : 'https://tests.bluebirdstraining.com');

  const sendStatus = (ms: number | null): void => {
    if (overlayWindow) {
      overlayWindow.webContents.send('wifi-status', { ms });
    }
  };

  // Run an immediate check, then repeat every 3 seconds
  const runCheck = async (): Promise<void> => {
    const ms = await pingTarget(targetUrl);
    sendStatus(ms);

    if (ms === null) {
      consecutiveOfflineCount += 1;
      console.warn(
        `[SecureBrowser] WiFi check failed. Consecutive offline count: ${consecutiveOfflineCount}`,
      );

      // Auto-exit after 2 consecutive offline checks (~6 seconds of no connectivity)
      if (consecutiveOfflineCount >= 2 && !IS_DEV) {
        console.error('[SecureBrowser] Network lost for 2 consecutive checks. Forcing exit.');
        showModalDialog(mainWindow, {
          type: 'error',
          title: 'Network Connection Lost',
          message:
            'The secure browser has lost its network connection for more than 6 seconds.\n\nFor exam integrity, the session will now close. Please contact your administrator.',
          buttons: ['Exit Secure Browser'],
        });
        app.quit();
      }
    } else {
      consecutiveOfflineCount = 0;
    }
  };

  runCheck();
  wifiMonitorInterval = setInterval(runCheck, 3_000);
  console.log('[SecureBrowser] WiFi monitor started.');
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

/** Get list of all running processes in a unified promise-wrapped format. */
function getSystemProcesses(isWindows: boolean): Promise<string[]> {
  const queryCommand = isWindows ? 'tasklist /FO CSV /NH' : 'ps -ax -o comm=';
  return new Promise((resolve) => {
    exec(queryCommand, (err, stdout) => {
      if (err) {
        console.error('[SecureBrowser] Failed to query system processes:', err.message);
        resolve([]);
        return;
      }
      resolve(parseProcessNames(stdout, isWindows));
    });
  });
}

/** Collect list of running blacklisted apps and detect VM presence. */
function getRunningViolations(processes: string[]): { forbiddenApps: string[]; vmDetected: boolean } {
  const forbiddenAppsSet = new Set<string>();
  let vmDetected = false;

  for (const proc of processes) {
    for (const black of BLACKLIST) {
      if (proc.includes(black)) {
        forbiddenAppsSet.add(proc);
      }
    }

    if (VM_INDICATORS.some((vm) => proc.includes(vm))) {
      vmDetected = true;
    }
  }

  return {
    forbiddenApps: Array.from(forbiddenAppsSet),
    vmDetected,
  };
}

/** Cross-platform command executor to force close running processes. */
function killProcess(name: string, isWindows: boolean): Promise<void> {
  return new Promise((resolve) => {
    const cmd = isWindows 
      ? `taskkill /F /IM "${name}"`
      : `pkill -9 -f -i "${name}"`;
    
    console.log(`[SecureBrowser] Attempting to close forbidden process: ${name} (cmd: ${cmd})`);
    exec(cmd, (err) => {
      if (err) {
        console.warn(`[SecureBrowser] Failed to force close process ${name}:`, err.message);
      }
      resolve();
    });
  });
}

/** Helper function to show a sync message box modal to a parent window if present. */
function showModalDialog(
  parent: BrowserWindow | null | undefined,
  options: Electron.MessageBoxSyncOptions
): number {
  if (parent && !parent.isDestroyed()) {
    return dialog.showMessageBoxSync(parent, options);
  }
  return dialog.showMessageBoxSync(options);
}

/**
 * Reliably brings the app to the foreground.
 * On macOS, app.focus({ steal: true }) may fail when the app is in the background.
 * Using AppleScript as a fallback is the most reliable approach.
 */
function bringAppToFront(): void {
  app.focus({ steal: true });
  if (process.platform === 'darwin') {
    // AppleScript activate is the most reliable foreground steal on macOS.
    // It works even when the app hasn't previously been in the foreground.
    const appName = app.name || 'BluebirdsSecureBrowser';
    exec(`osascript -e 'tell application "${appName}" to activate'`, (err) => {
      if (err) {
        // Fallback: use generic NSApp activation via system events
        exec(`osascript -e 'tell application "System Events" to set frontmost of process "${appName}" to true'`, (err2) => {
          if (err2) console.warn('[SecureBrowser] AppleScript foreground steal failed:', err2.message);
        });
      }
    });
  }
}

/** Checks for monitor count, blacklisted apps, and VM state on launch. Offers options to auto-close. */
async function checkAndCleanSystem(parentWindow?: BrowserWindow): Promise<boolean> {
  const isWindows = process.platform === 'win32';

  if (IS_DEV) {
    return true;
  }

  // 1. Check Displays
  const displays = screen.getAllDisplays();
  if (displays.length > 1) {
    const choice = showModalDialog(parentWindow, {
      type: 'warning',
      title: 'Multiple Displays Connected',
      message: 'Multiple monitors detected. External screens must be disconnected before starting the exam.',
      buttons: ['Retry / Recheck', 'Quit Secure Browser'],
      defaultId: 0,
      cancelId: 1,
    });

    if (choice === 0) {
      return checkAndCleanSystem(parentWindow);
    }
    return false;
  }

  // 2. Query Processes
  const processes = await getSystemProcesses(isWindows);
  const { forbiddenApps, vmDetected } = getRunningViolations(processes);

  if (vmDetected) {
    showModalDialog(parentWindow, {
      type: 'error',
      title: 'Virtualization Detected',
      message: 'Virtual Machine / Sandbox environment detected. The assessment must be taken on a physical machine.',
      buttons: ['Quit Secure Browser'],
      defaultId: 0,
    });
    return false;
  }

  if (forbiddenApps.length > 0) {
    const appList = forbiddenApps.map((a) => `  • ${a}`).join('\n');
    const choice = showModalDialog(parentWindow, {
      type: 'warning',
      title: 'Forbidden Applications Running',
      message: `The following forbidden applications are currently running on your system:\n\n${appList}\n\nThey must be closed before you can enter the assessment.\n\nWould you like the Secure Browser to force close them for you?`,
      buttons: ['Force Close All', 'Quit Secure Browser'],
      defaultId: 0,
      cancelId: 1,
    });

    if (choice === 0) {
      // Force kill each app
      for (const proc of forbiddenApps) {
        await killProcess(proc, isWindows);
      }
      // Give system processes a short delay to terminate completely
      await new Promise((resolve) => setTimeout(resolve, 1500));
      // Re-evaluate recursively
      return checkAndCleanSystem(parentWindow);
    }
    return false;
  }

  return true;
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

// ─── Permission Handler ───────────────────────────────────────────────────────
// macOS shows native system dialogs for screen-capture / camera / microphone.
// Because our window runs at 'screen-saver' alwaysOnTop level (kiosk mode),
// those OS dialogs would normally be hidden BEHIND our window, blocking the user.
//
// Fix: When a media permission is requested, we temporarily lower the window level
// so the macOS permission dialog can appear on top and be clickable.
// We restore alwaysOnTop right after the callback fires.

function installPermissionHandler(): void {
  const MEDIA_PERMISSIONS = ['media', 'camera', 'microphone', 'display-capture', 'screen'];

  // Track how many permission dialogs are currently pending
  // so we only restore lockout when all dialogs are done.
  let pendingPermissions = 0;

  const restoreAfterPermissionDelayed = (delayMs: number): void => {
    setTimeout(() => {
      pendingPermissions = Math.max(0, pendingPermissions - 1);
      if (pendingPermissions === 0 && !isRequestingPermission && mainWindow && !mainWindow.isDestroyed() && !IS_DEV) {
        restoreKioskLockout();
        console.log('[SecureBrowser] Kiosk lockout restored after permission dialog.');
      }
    }, delayMs);
  };

  session.defaultSession.setPermissionRequestHandler(
    (_webContents, permission, callback) => {
      const isMediaPermission = MEDIA_PERMISSIONS.some(
        (p) => permission === p || permission.includes(p)
      );

      console.log(`[SecureBrowser] Permission requested: ${permission} | isMedia: ${isMediaPermission}`);

      if (isMediaPermission && mainWindow && !mainWindow.isDestroyed()) {
        // Suspend kiosk so the macOS system dialog can appear above the window
        pendingPermissions += 1;
        suspendKioskLockout();
        console.log(`[SecureBrowser] Kiosk suspended for permission dialog: ${permission}`);

        // Grant the permission — Electron/Chromium will then trigger the
        // macOS system permission dialog independently of the window level
        callback(true);

        // Restore kiosk lockout after a delay sufficient for the OS dialog
        // to be shown and acknowledged (20 s gives user time to see the dialog)
        restoreAfterPermissionDelayed(20_000);
      } else {
        // Non-media permission: grant by default
        callback(true);
      }
    }
  );

  // Also handle the check handler (queried before showing the request dialog)
  session.defaultSession.setPermissionCheckHandler(
    (_webContents, permission) => {
      // Allow all permission checks — actual grant decision is above
      console.log(`[SecureBrowser] Permission check: ${permission} → allowed`);
      return true;
    }
  );

  // Electron 22+ handler for getDisplayMedia().
  // When the renderer calls getDisplayMedia(), this handler fires.
  // We check the real OS-level screen permission status:
  //   - 'granted': use the real screen source.
  //   - 'not-determined': trigger the OS prompt and respond accordingly.
  //   - 'denied' / 'restricted' / no sources on Windows: reject with callback({})
  //     so the renderer gets a real error and can show the "Open Settings" UI.
  //
  // IMPORTANT: We do NOT silently fall back to self-capture (request.frame)
  // because that would hide a genuine permission failure from the student.
  session.defaultSession.setDisplayMediaRequestHandler(
    async (request, callback) => {
      console.log('[SecureBrowser] setDisplayMediaRequestHandler fired');

      try {
        const sources = await desktopCapturer.getSources({ types: ['screen'] });
        console.log(`[SecureBrowser] desktopCapturer returned ${sources.length} screen sources`);

        if (sources.length > 0) {
          // Real screen capture — TCC permission is available
          console.log('[SecureBrowser] Using real screen source:', sources[0].name);
          // Temporarily suspend kiosk to let the OS finish the stream handshake
          if (mainWindow && !mainWindow.isDestroyed() && !IS_DEV) {
            pendingPermissions += 1;
            suspendKioskLockout();
          }
          callback({ video: sources[0] });
          restoreAfterPermissionDelayed(3000);
        } else {
          console.log('[SecureBrowser] No screen sources available. Rejecting getDisplayMedia.');
          callback({} as any);
        }
      } catch (err) {
        console.error('[SecureBrowser] desktopCapturer.getSources failed:', err);
        callback({} as any);
      }
    }
  );

  console.log('[SecureBrowser] Permission handler installed.');
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

/**
 * IPC: request-screen-permission
 * Called by the renderer BEFORE getDisplayMedia().
 *
 * Returns the REAL OS-level screen recording permission status.
 * - macOS: checks TCC via systemPreferences.getMediaAccessStatus('screen').
 *   If 'not-determined', triggers the native OS prompt by probing desktopCapturer.
 * - Windows: probes desktopCapturer.getSources to check actual access.
 * - Linux: returns granted (no TCC equivalent).
 *
 * Returns: { granted: boolean; status: string; platform: string }
 */
ipcMain.handle('request-screen-permission', async (): Promise<{ granted: boolean; status: string; platform: string }> => {
  const platform = process.platform;

  if (platform === 'darwin') {
    const status = systemPreferences.getMediaAccessStatus('screen');
    console.log(`[SecureBrowser] macOS Screen Recording TCC status: ${status}`);

    if (status === 'granted') {
      return { granted: true, status, platform };
    }

    // On macOS, screen recording permissions return 'denied' even if the user hasn't been prompted yet.
    // If status is 'not-determined', we trigger the desktopCapturer probe to force the OS prompt.
    if (status === 'not-determined') {
      console.log('[SecureBrowser] Screen Recording status is not-determined. Probing desktopCapturer to trigger macOS prompt/registration.');
      isRequestingPermission = true;
      suspendKioskLockout();
      try {
        await desktopCapturer.getSources({ types: ['screen'] });
      } catch (e) {
        console.warn('[SecureBrowser] desktopCapturer probe failed:', e);
      }
      isRequestingPermission = false;
      restoreKioskLockout();
    }

    // Always return granted: true for non-determined or denied states on macOS to allow
    // the frontend to attempt actual getDisplayMedia. If permission is enabled in System Settings,
    // getDisplayMedia will succeed and the check will pass.
    return { granted: true, status, platform };
  }

  if (platform === 'win32') {
    try {
      const sources = await desktopCapturer.getSources({ types: ['screen'] });
      const granted = sources.length > 0;
      console.log(`[SecureBrowser] Windows screen capture probe: ${sources.length} source(s).`);
      return { granted, status: granted ? 'granted' : 'denied', platform };
    } catch (e) {
      console.warn('[SecureBrowser] Windows desktopCapturer probe failed:', e);
      return { granted: false, status: 'denied', platform };
    }
  }

  // Linux / other — no TCC equivalent, assume granted
  return { granted: true, status: 'granted', platform };
});

/**
 * IPC: open-permission-settings
 * Opens the OS-specific permission settings page for the given permission type.
 *
 * macOS → System Settings → Privacy & Security → (Screen Recording / Camera / Microphone)
 * Windows → Settings → Privacy & Security → (Screen capture / Camera / Microphone)
 *
 * Kiosk mode is suspended on macOS so System Settings can appear above the window.
 * It is restored automatically in the 'focus' handler when the student returns.
 */
ipcMain.handle('open-permission-settings', async (_event, permType: 'screen' | 'camera' | 'microphone'): Promise<void> => {
  const platform = process.platform;

  if (platform === 'darwin') {
    const urlMap: Record<string, string> = {
      screen:     'x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture',
      camera:     'x-apple.systempreferences:com.apple.preference.security?Privacy_Camera',
      microphone: 'x-apple.systempreferences:com.apple.preference.security?Privacy_Microphone',
    };
    const url = urlMap[permType] ?? urlMap.screen;
    console.log(`[SecureBrowser] Opening macOS System Settings for '${permType}': ${url}`);
    // Suspend kiosk so System Settings can appear above the secure browser window.
    isRequestingPermission = true;
    suspendKioskLockout();
    await shell.openExternal(url);
    // Kiosk will be restored inside mainWindow 'focus' handler when student returns.
  } else if (platform === 'win32') {
    const urlMap: Record<string, string> = {
      screen:     'ms-settings:privacy-broadfilesystemaccess',
      camera:     'ms-settings:privacy-webcam',
      microphone: 'ms-settings:privacy-microphone',
    };
    const url = urlMap[permType] ?? urlMap.screen;
    console.log(`[SecureBrowser] Opening Windows Settings for '${permType}': ${url}`);
    await shell.openExternal(url);
  } else {
    console.log(`[SecureBrowser] open-permission-settings: platform '${platform}' not supported.`);
  }
});


// Synchronous IPC: preload reads this before React mounts so token is in localStorage immediately
ipcMain.on('get-boot-tokens', (event): void => {
  event.returnValue = {
    attemptId: activeAttemptId ?? null,
    token: activeToken ?? null,
  };
});

ipcMain.on('close-browser', (_event: IpcMainEvent): void => {
  console.log('[SecureBrowser] Closing application on renderer request...');
  app.quit();
});

// Overlay close button — show native confirm dialog then quit
ipcMain.on('overlay-request-close', (): void => {
  const choice = showModalDialog(mainWindow, {
    type: 'question',
    title: 'Close Secure Browser',
    message: 'Are you sure you want to close the Secure Browser?\n\nThis will end your current session.',
    buttons: ['Cancel', 'Yes, Close'],
    defaultId: 0,
    cancelId: 0,
  });

  if (choice === 1) {
    console.log('[SecureBrowser] User confirmed close via overlay button.');
    app.quit();
  }
});

ipcMain.on('exam-started', (): void => {
  console.log('[SecureBrowser] Exam started. Auto-updates and restarts disabled.');
  isExamActive = true;
  // Clear permission-request mode and ensure full lockout is active when exam begins
  isRequestingPermission = false;
  restoreKioskLockout();
});

ipcMain.on('exam-finished', (): void => {
  console.log('[SecureBrowser] Exam finished. Auto-updates enabled.');
  isExamActive = false;
});

// ─── Deep Link & Single Instance Handler ──────────────────────────────────────

async function initializeApp(): Promise<void> {
  if (isInitialized) return;
  isInitialized = true;

  // Show splash immediately so the user sees something while system checks run.
  // Bring to foreground before any blocking dialog (checkAndCleanSystem uses sync dialogs).
  createSplashWindow();
  if (splashWindow) {
    splashWindow.show();
    bringAppToFront();
  }

  const clean = await checkAndCleanSystem(splashWindow ?? undefined);
  if (!clean) {
    console.log('[SecureBrowser] Startup requirements not met. Quitting.');
    app.quit();
    return;
  }

  createWindow();
  createOverlayWindow();
  installPermissionHandler(); // Must run after createWindow so session is ready
  registerGlobalShortcuts();
  startProcessMonitor();
  startClipboardWiper();
  startWifiMonitor();
}

function handleDeepLink(urlStr: string): void {
  console.log(`[SecureBrowser] Deep link received: ${urlStr}`);
  wasOpenedViaDeepLink = true;

  try {
    const parsedUrl = new URL(urlStr);
    const attemptId = parsedUrl.searchParams.get('attemptId');
    const token = parsedUrl.searchParams.get('token');

    if (attemptId && token) {
      // Store credentials so preload can inject them synchronously before React boots
      activeAttemptId = attemptId;
      activeToken = token;
      console.log(`[SecureBrowser] Deep link credentials stored for attempt: ${attemptId}`);
    } else {
      console.warn('[SecureBrowser] Deep link missing attemptId or token. Ignoring.');
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error('[SecureBrowser] Failed to parse deep link URL:', message);
  }

  if (!isInitialized) {
    console.log('[SecureBrowser] App not initialized yet. Starting initialization now.');
    initializeApp();
    return;
  }

  // Already initialized — navigate the live window directly
  if (mainWindow) {
    const origin =
      process.env.APP_URL ??
      (IS_DEV ? 'http://localhost:5173' : 'https://tests.bluebirdstraining.com');

    if (activeAttemptId && activeToken) {
      const systemCheckUrl = `${origin}/system-check/${activeAttemptId}`;
      console.log(`[SecureBrowser] Navigating live window to system check: ${systemCheckUrl}`);

      // Navigate to origin first to ensure same-origin localStorage access
      mainWindow.loadURL(origin).then((): void => {
        if (!mainWindow) return;
        mainWindow.webContents
          .executeJavaScript(
            `try { localStorage.setItem('accessToken', '${activeToken}'); } catch(e) {}`
          )
          .then((): void => {
            mainWindow?.loadURL(systemCheckUrl);
          });
      });
    }

    // Bring to foreground
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.setAlwaysOnTop(true, 'screen-saver');
    mainWindow.focus();
    bringAppToFront();
  }
}

const gotTheLock = app.requestSingleInstanceLock();

if (!gotTheLock) {
  console.log('[SecureBrowser] Another instance is already running. Quitting.');
  app.quit();
} else {
  app.on('second-instance', (event, commandLine): void => {
    // Parse deep link URL from the new instance's command line
    const url = commandLine.find((arg) => arg.startsWith('bluebirds-sb://'));
    if (url) {
      handleDeepLink(url);
    }

    // Force the existing window to the foreground immediately
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.setAlwaysOnTop(true, 'screen-saver');
      mainWindow.focus();
      bringAppToFront();
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
    // Check if launched via deep link (Windows/Linux)
    const deepLinkArg = process.argv.find((arg): boolean =>
      arg.startsWith('bluebirds-sb://')
    );

    if (deepLinkArg) {
      handleDeepLink(deepLinkArg);
    } else {
      // Opened directly (double-click the icon / Start Menu / npm start) without a deep link.
      // Set a short delay to allow open-url event to fire on macOS if launched via deep link.
      setTimeout((): void => {
        if (!wasOpenedViaDeepLink && !isInitialized) {
          const buttons = IS_DEV
            ? ['Quit Secure Browser', 'Bypass (Dev Mode Only)']
            : ['Quit Secure Browser'];

          bringAppToFront();

          const choice = showModalDialog(null, {
            type: 'warning',
            title: 'Launch via Student Portal Required',
            message:
              'This secure exam browser must be launched from your student dashboard.\n\nPlease log in to the portal and click "Start Test" to begin.',
            buttons: buttons,
            defaultId: 0,
          });

          if (!IS_DEV || choice === 0) {
            console.log('[SecureBrowser] Direct launch detected. Quitting.');
            app.quit();
          } else {
            console.log('[SecureBrowser] Direct launch warning bypassed in DEV mode.');
            initializeApp();
          }
        }
      }, 800);
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
      if (BrowserWindow.getAllWindows().length === 0 && isInitialized) {
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
  if (wifiMonitorInterval !== null) clearInterval(wifiMonitorInterval);
  console.log('[SecureBrowser] Application terminated and resources cleaned up.');
});
