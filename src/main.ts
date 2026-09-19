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
  powerMonitor,
} from 'electron';
import path from 'path';
import os from 'os';
import fs from 'fs';
import { exec, spawn } from 'child_process';
import http from 'http';
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
  version?: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

/** Determine if we are in development mode. */
const IS_DEV: boolean =
  process.env.NODE_ENV === 'development' || process.argv.includes('--dev');

// Enforce hardening flags in production to prevent remote debugging & script injection
if (!IS_DEV) {
  app.commandLine.appendSwitch('disable-remote-debugging');
  app.commandLine.appendSwitch('disable-remote-extensions');
}

/** Blacklisted processes: remote control, screen capture, communication, reverse engineering & cheat tools. */
const BLACKLIST: readonly string[] = [
  // Communication & Meeting Tools
  'discord',
  'zoom',
  'zoom.us',
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

  // Web Browsers (Must be closed to prevent background meetings and unauthorized browsing)
  'chrome',
  'google chrome',
  'google chrome helper',
  'brave',
  'brave browser',
  'msedge',
  'microsoft edge',
  'firefox',
  'opera',
  'safari',
  'vivaldi',
  'arc',

  // Non-Essential Background Apps & Terminals
  'code',
  'cursor',
  'terminal',
  'iterm',
  'iterm2',
  'notes',
  'textedit',

  // Anti-Reverse Engineering, Debuggers, Decompilers & Macro Cheat Engines
  'cheatengine',
  'cheatengine-x86_64',
  'cheatengine-i386',
  'x64dbg',
  'x32dbg',
  'ida',
  'ida64',
  'idag',
  'idag64',
  'processhacker',
  'procmon',
  'procmon64',
  'procexp',
  'procexp64',
  'wireshark',
  'fiddler',
  'charles',
  'autohotkey',
  'autoit3',
  'dnspy',
  'httpdebugger',
  'ghidra',
  'scylla',
  'ollydbg',
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
  'Alt+Escape',
  'Alt+Space',
  'Command+Tab',
  'Command+Alt+Escape',
  'Command+Space',
  'Ctrl+Escape',
  'Ctrl+Shift+Escape',
  'Ctrl+Alt+Delete',
];

// ─── State ───────────────────────────────────────────────────────────────────

let mainWindow: BrowserWindow | null = null;
let overlayWindow: BrowserWindow | null = null; // kept for type-compat but not used as separate window
let splashWindow: BrowserWindow | null = null;
let prohibitedWindow: BrowserWindow | null = null;
let processMonitorInterval: ReturnType<typeof setInterval> | null = null;
let clipboardWiperInterval: ReturnType<typeof setInterval> | null = null;
let wifiMonitorInterval: ReturnType<typeof setInterval> | null = null;
let hudMonitorInterval: ReturnType<typeof setInterval> | null = null;
let isExamActive = false;
let isUpdateDownloaded = false;
let isUpdating = false;
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
let isConfirmingExit = false;
/** Credentials injected from deep link — made available to preload synchronously */
let activeAttemptId: string | null = null;
let activeAssessmentId: string | null = null;
let activeToken: string | null = null;

// ─── Helpers: kiosk / fullscreen lockout management ──────────────────────────

/**
 * Temporarily lifts all kiosk/always-on-top constraints so that macOS system
 * dialogs and System Settings can appear above the window.
 *
 * NOTE: On Windows, Chromium handles camera/microphone access internally
 * via the browser-level permission bar — there is NO native OS modal that
 * needs to sit above the window. Therefore, on Windows we must NEVER drop
 * fullscreen or kiosk or the window collapses to its fallback size (1280x800)
 * for the full restore-delay duration (was 20 s), ruining the user experience.
 */
function suspendKioskLockout(): void {
  if (IS_DEV || !mainWindow || mainWindow.isDestroyed()) return;
  // Windows: never exit fullscreen — no OS-level dialog needs to appear.
  if (process.platform === 'win32') {
    console.log('[SecureBrowser] Skipping kiosk suspend on Windows (not required).');
    return;
  }
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
    skipTaskbar: !IS_DEV && process.platform === 'darwin',
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

  // Inject official BluebirdsSecureApp signature into User-Agent for platform detection
  const customUserAgent = `${mainWindow.webContents.getUserAgent()} BluebirdsSecureApp/${app.getVersion()} BluebirdsApp`;
  mainWindow.webContents.setUserAgent(customUserAgent);
  session.defaultSession.setUserAgent(customUserAgent);

  // Build the initial URL — if launched via deep link, go directly to system-check
  const origin: string =
    process.env.APP_URL ??
    (IS_DEV ? 'http://localhost:5173' : 'https://tests.bluebirdstraining.com');

  const targetId = activeAttemptId || activeAssessmentId;
  let initialUrl = targetId
    ? `${origin}/system-check/${targetId}`
    : origin;

  if (targetId && activeToken) {
    initialUrl += `?token=${encodeURIComponent(activeToken)}`;
  }

  console.log(`[SecureBrowser] Loading initial URL: ${initialUrl}`);
  mainWindow.loadURL(initialUrl);

  // Show window only when content is ready (prevents white flash)
  mainWindow.once('ready-to-show', (): void => {
    if (mainWindow) {
      if (process.platform === 'win32') {
        const primaryDisplay = screen.getPrimaryDisplay();
        mainWindow.setBounds(primaryDisplay.bounds);
      }
      mainWindow.show();
      if (!IS_DEV) {
        mainWindow.setAlwaysOnTop(true, 'screen-saver', 1);
        mainWindow.focus();
        bringAppToFront();
      }

      // Close and destroy splash screen now that exam window is rendered and visible
      if (splashWindow && !splashWindow.isDestroyed()) {
        splashWindow.destroy();
        splashWindow = null;
      }

      // Start preload-injected HUD monitor (battery + latency pushed via IPC)
      startHudMonitor();
    }
  });

  mainWindow.on('enter-full-screen', (): void => {
    // Re-send HUD status so the injected dock updates on fullscreen transition
    sendHudStatusToRenderer();
  });

  mainWindow.on('resize', (): void => {
    // Nothing needed for DOM-injected dock
  });

  // Synchronize HUD on route navigations (re-inject if SPA navigated away)
  mainWindow.webContents.on('did-navigate', (): void => {
    sendHudStatusToRenderer();
  });
  mainWindow.webContents.on('did-navigate-in-page', (): void => {
    sendHudStatusToRenderer();
  });

  mainWindow.on('focus', (): void => {
    mainWindow?.webContents.send('window-focus');
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

  // Open DevTools only in developer mode; proactively close if opened in production
  if (IS_DEV) {
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.webContents.on('devtools-opened', () => {
      mainWindow?.webContents.closeDevTools();
    });
  }

  // Force window focus back to the app when it loses focus (production only).
  // IMPORTANT: Do NOT steal focus when the app is in "permission request" mode —
  // that is when the user needs to interact with a macOS dialog or System Settings.
  mainWindow.on('blur', (): void => {
    if (isConfirmingExit) return;
    if (!IS_DEV && mainWindow && !isRequestingPermission) {
      if (process.platform === 'win32') {
        mainWindow.setAlwaysOnTop(true, 'screen-saver', 1);
        mainWindow.moveTop();
        mainWindow.show();
      }
      mainWindow.focus();
      mainWindow.webContents.send('window-blur');
    } else if (!IS_DEV && mainWindow && isRequestingPermission) {
      // Send blur so the UI knows focus was lost, but do NOT steal it back
      mainWindow.webContents.send('window-blur');
    }
  });



  mainWindow.on('closed', (): void => {
    mainWindow = null;
    stopHudMonitor();
  });

  // Intercept and block common cheat keyboard shortcuts inside the renderer
  mainWindow.webContents.on('before-input-event', (_event, input): void => {
    if (IS_DEV) return;

    const key: string = input.key.toLowerCase();
    const cmdOrCtrl: boolean = input.meta || input.control;

    // Block DevTools & inspection shortcuts: F12, PrintScreen, Ctrl+Shift+I/J/C, Ctrl+U
    if (
      key === 'f12' ||
      key === 'printscreen' ||
      (cmdOrCtrl && input.shift && (key === 'i' || key === 'j' || key === 'c')) ||
      (cmdOrCtrl && key === 'u')
    ) {
      _event.preventDefault();
    }

    // Block page-reload shortcuts: Ctrl+R, Cmd+R, F5
    if (key === 'f5' || (cmdOrCtrl && key === 'r')) {
      _event.preventDefault();
    }

    // Block OS-level shortcuts & keys that switch tasks / expose desktop:
    // Alt+F4, Alt+Tab, Alt+Esc, Alt+Space, Ctrl+Esc, Ctrl+Shift+Esc, Windows / Command key
    if (
      (input.alt && key === 'f4') ||
      (input.alt && key === 'tab') ||
      (input.alt && key === 'escape') ||
      (input.alt && key === ' ') ||
      (input.control && key === 'escape') ||
      (input.control && input.shift && key === 'escape') ||
      (cmdOrCtrl && input.alt && key === 'escape') ||
      input.meta
    ) {
      _event.preventDefault();
    }
  });
}

// ─── Splash Window ─────────────────────────────────────────────────────────────

function createSplashWindow(): void {
  splashWindow = new BrowserWindow({
    width: 520,
    height: 330,
    frame: false,
    transparent: true,
    alwaysOnTop: true,
    resizable: false,
    movable: false,
    center: true,
    skipTaskbar: true,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      sandbox: false,
    },
  });

  if (process.platform === 'darwin') {
    splashWindow.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
  }

  const splashPath = path.join(__dirname, '..', 'src', 'splash.html');
  splashWindow.loadFile(splashPath, { hash: app.getVersion() });

  splashWindow.on('closed', (): void => {
    splashWindow = null;
  });

  console.log('[SecureBrowser] Splash window created.');
}

export interface UpdateStatusPayload {
  status: 'checking' | 'available' | 'not-available' | 'downloading' | 'downloaded' | 'error';
  version?: string;
  percent?: number;
  speed?: string;
  bytesPerSecond?: number;
  transferred?: number;
  total?: number;
  etaSeconds?: number | null;
  etaString?: string;
  error?: string;
}

function sendUpdateStatus(payload: UpdateStatusPayload): void {
  if (splashWindow && !splashWindow.isDestroyed()) {
    const jsonStr = JSON.stringify(payload);
    splashWindow.webContents
      .executeJavaScript(
        `if (typeof window.onUpdateStatus === 'function') { window.onUpdateStatus(${jsonStr}); }`
      )
      .catch((): void => {});
  }

  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('auto-update-status', payload);
  }
}


// ─── Prohibited-Apps Native Modal ────────────────────────────────────────────

/**
 * Creates and shows a native Electron window styled after the MSB/SEB security gate.
 * Displays detected prohibited applications and provides Auto-Close / Re-Check / Quit.
 * The window is modal to the splash screen (centered on screen) and is destroyed once
 * the environment is clean. Returns a promise that resolves true when clean.
 */
function createProhibitedWindow(forbiddenApps: string[]): void {
  if (prohibitedWindow && !prohibitedWindow.isDestroyed()) {
    prohibitedWindow.focus();
    return;
  }

  prohibitedWindow = new BrowserWindow({
    width: 480,
    height: 520,
    frame: false,
    transparent: true,
    alwaysOnTop: true,
    resizable: false,
    movable: false,
    center: true,
    skipTaskbar: true,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      sandbox: false,
    },
  });

  if (process.platform === 'darwin') {
    prohibitedWindow.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
  }

  const possiblePaths = [
    path.join(__dirname, '..', 'src', 'prohibited-modal.html'),
    path.join(__dirname, 'src', 'prohibited-modal.html'),
    path.join(process.resourcesPath, 'app.asar', 'src', 'prohibited-modal.html'),
  ];
  let modalPath = possiblePaths[0];
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      modalPath = p;
      break;
    }
  }

  prohibitedWindow.webContents.on('did-fail-load', (_e, code, desc) => {
    console.error('[SecureBrowser] prohibited-modal.html failed to load:', code, desc, 'path was:', modalPath);
  });

  prohibitedWindow.loadFile(modalPath, { hash: app.getVersion() }).catch((err) => {
    console.error('[SecureBrowser] loadFile exception for prohibited-modal:', err);
  });

  prohibitedWindow.webContents.once('did-finish-load', () => {
    if (!prohibitedWindow || prohibitedWindow.isDestroyed()) return;
    prohibitedWindow.webContents.send('init-processes', { forbiddenApps });
  });

  prohibitedWindow.on('closed', (): void => {
    prohibitedWindow = null;
  });

  prohibitedWindow.show();
  console.log('[SecureBrowser] Prohibited-apps modal displayed with', forbiddenApps.length, 'violations.');
}

/**
 * Displays the native prohibited-applications security gate modal (Image 3 layout)
 * and blocks startup until all forbidden applications are closed or candidate quits.
 * Returns true if the system is clean, false if candidate chose to quit.
 */
function showProhibitedModalGate(initialForbiddenApps: string[]): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const isWindows = process.platform === 'win32';
    let isResolved = false;

    let autoWatchInterval: NodeJS.Timeout | null = null;

    const finalize = (result: boolean) => {
      if (isResolved) return;
      isResolved = true;
      if (autoWatchInterval) {
        clearInterval(autoWatchInterval);
        autoWatchInterval = null;
      }
      ipcMain.removeListener('prohibited-modal-auto-close', handleAutoClose);
      ipcMain.removeListener('prohibited-modal-recheck', handleRecheck);
      ipcMain.removeListener('prohibited-modal-quit', handleQuit);
      resolve(result);
    };

    const handleAutoClose = async () => {
      console.log('[SecureBrowser] Modal auto-close initiated for forbidden apps...');
      const procs = await getSystemProcesses(isWindows);
      const { forbiddenApps } = getRunningViolations(procs);
      for (const proc of forbiddenApps) {
        await killProcess(proc, isWindows);
      }
      await new Promise((r) => setTimeout(r, 1000));

      const afterProcs = await getSystemProcesses(isWindows);
      const { forbiddenApps: remaining } = getRunningViolations(afterProcs);

      if (remaining.length === 0) {
        if (prohibitedWindow && !prohibitedWindow.isDestroyed()) {
          prohibitedWindow.webContents.send('check-result', { clean: true, forbiddenApps: [] });
          setTimeout(() => {
            if (prohibitedWindow && !prohibitedWindow.isDestroyed()) {
              prohibitedWindow.close();
            }
            finalize(true);
          }, 900);
        } else {
          finalize(true);
        }
      } else {
        if (prohibitedWindow && !prohibitedWindow.isDestroyed()) {
          prohibitedWindow.webContents.send('check-result', { clean: false, forbiddenApps: remaining });
        }
      }
    };

    const handleRecheck = async () => {
      console.log('[SecureBrowser] Modal re-check initiated...');
      const procs = await getSystemProcesses(isWindows);
      const { forbiddenApps: remaining } = getRunningViolations(procs);

      if (remaining.length === 0) {
        if (prohibitedWindow && !prohibitedWindow.isDestroyed()) {
          prohibitedWindow.webContents.send('check-result', { clean: true, forbiddenApps: [] });
          setTimeout(() => {
            if (prohibitedWindow && !prohibitedWindow.isDestroyed()) {
              prohibitedWindow.close();
            }
            finalize(true);
          }, 900);
        } else {
          finalize(true);
        }
      } else {
        if (prohibitedWindow && !prohibitedWindow.isDestroyed()) {
          prohibitedWindow.webContents.send('check-result', { clean: false, forbiddenApps: remaining });
        }
      }
    };

    const handleQuit = () => {
      console.log('[SecureBrowser] Candidate requested quit from prohibited modal.');
      if (prohibitedWindow && !prohibitedWindow.isDestroyed()) {
        prohibitedWindow.close();
      }
      finalize(false);
      app.exit(0);
    };

    ipcMain.on('prohibited-modal-auto-close', handleAutoClose);
    ipcMain.on('prohibited-modal-recheck', handleRecheck);
    ipcMain.on('prohibited-modal-quit', handleQuit);

    createProhibitedWindow(initialForbiddenApps);

    // Real-time background watchdog timer (like SafeExamBrowser's 250ms/1s GCD timer)
    // If the candidate manually closes the apps outside, auto-detect and proceed
    autoWatchInterval = setInterval(async () => {
      if (isResolved || !prohibitedWindow || prohibitedWindow.isDestroyed()) {
        if (autoWatchInterval) clearInterval(autoWatchInterval);
        return;
      }
      try {
        const procs = await getSystemProcesses(isWindows);
        const { forbiddenApps: remaining } = getRunningViolations(procs);
        if (remaining.length === 0) {
          if (autoWatchInterval) {
            clearInterval(autoWatchInterval);
            autoWatchInterval = null;
          }
          if (prohibitedWindow && !prohibitedWindow.isDestroyed()) {
            prohibitedWindow.webContents.send('check-result', { clean: true, forbiddenApps: [] });
            setTimeout(() => {
              if (prohibitedWindow && !prohibitedWindow.isDestroyed()) {
                prohibitedWindow.close();
              }
              finalize(true);
            }, 900);
          } else {
            finalize(true);
          }
        } else {
          if (prohibitedWindow && !prohibitedWindow.isDestroyed()) {
            prohibitedWindow.webContents.send('check-result', { clean: false, forbiddenApps: remaining });
          }
        }
      } catch {}
    }, 1200);

    if (prohibitedWindow) {
      prohibitedWindow.on('closed', () => {
        finalize(false);
      });
    }
  });
}

// ─── Preload-Injected HUD (Battery + Latency → Renderer) ─────────────────────

let lastHudLatencyMs: number | null = null;

let cachedBatteryPercent = 100;
let cachedIsCharging = false;

/**
 * Sends current battery and latency state to the mainWindow renderer.
 * The preload script injects a DOM dock that listens for this IPC event.
 */
function sendHudStatusToRenderer(): void {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  try {
    mainWindow.webContents.send('hud-status', {
      batteryPercent: cachedBatteryPercent,
      isCharging: cachedIsCharging,
      latencyMs: lastHudLatencyMs,
      appVersion: app.getVersion(),
    });
  } catch (e) {
    console.warn('[SecureBrowser] sendHudStatusToRenderer error:', e);
  }
}

/** Reads battery percentage from macOS ioreg and caches it, then notifies renderer. */
function refreshMacOSBattery(): void {
  exec(
    "ioreg -rn AppleSmartBattery | grep -E '\"CurrentCapacity\"|\"MaxCapacity\"|\"ExternalConnected\"'",
    (err, stdout) => {
      if (err || !stdout || !mainWindow || mainWindow.isDestroyed()) return;
      try {
        const currentMatch = stdout.match(/"CurrentCapacity"\s*=\s*(\d+)/);
        const maxMatch     = stdout.match(/"MaxCapacity"\s*=\s*(\d+)/);
        const chargingMatch = stdout.match(/"ExternalConnected"\s*=\s*(Yes|No|true|false)/i);
        const current = currentMatch ? parseInt(currentMatch[1], 10) : 0;
        const max     = maxMatch     ? parseInt(maxMatch[1], 10) : 1;
        cachedBatteryPercent = max > 0 ? Math.min(100, Math.round((current / max) * 100)) : 100;
        cachedIsCharging = chargingMatch ? /yes|true/i.test(chargingMatch[1]) : !powerMonitor.isOnBatteryPower();

        sendHudStatusToRenderer();
      } catch {}
    }
  );
}

/** Reads battery percentage from Windows WMIC and caches it. */
function refreshWindowsBattery(): void {
  exec('wmic path win32_battery get estimatedchargeremaining /format:value', (err, stdout) => {
    if (err || !stdout || !mainWindow || mainWindow.isDestroyed()) return;
    try {
      const match = stdout.match(/EstimatedChargeRemaining=(\d+)/);
      cachedBatteryPercent = match ? parseInt(match[1], 10) : 100;
      cachedIsCharging = !powerMonitor.isOnBatteryPower();
      sendHudStatusToRenderer();
    } catch {}
  });
}

function startHudMonitor(): void {
  if (hudMonitorInterval !== null) return;

  const refresh = (): void => {
    if (process.platform === 'darwin') {
      refreshMacOSBattery();
    } else if (process.platform === 'win32') {
      refreshWindowsBattery();
    } else {
      sendHudStatusToRenderer();
    }
  };

  // Immediate first read
  refresh();
  hudMonitorInterval = setInterval(refresh, 10_000); // every 10 seconds
  console.log('[SecureBrowser] HUD monitor started (battery refresh every 10s).');
}

function stopHudMonitor(): void {
  if (hudMonitorInterval !== null) {
    clearInterval(hudMonitorInterval);
    hudMonitorInterval = null;
  }
}



const pingAgent = new https.Agent({
  keepAlive: true,
  keepAliveMsecs: 2000,
  maxSockets: 8,
});

/**
 * Measures round-trip latency to the target server using a lightweight HTTPS HEAD
 * request with browser User-Agent. Returns the ms value on success, or null on failure/timeout.
 */
function pingTarget(targetUrl: string): Promise<number | null> {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(null), 6000);
    const start = Date.now();

    try {
      const parsed = new URL(targetUrl);
      const isHttps = parsed.protocol === 'https:';
      const transport = isHttps ? https : http;

      const req = transport.request(
        {
          hostname: parsed.hostname,
          port: parsed.port || (isHttps ? 443 : 80),
          path: '/favicon.ico',
          method: 'HEAD',
          agent: isHttps ? pingAgent : undefined,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) BluebirdsSecureApp/1.1.22 Chrome/120.0.0.0 Safari/537.36',
            'Cache-Control': 'no-cache',
            'Accept': '*/*',
          },
        },
        (res: http.IncomingMessage) => {
          clearTimeout(timeout);
          res.resume(); // Consume response to free socket back to agent pool
          // Any HTTP status (200, 304, 404, etc.) proves connectivity to the host
          resolve(Math.max(1, Date.now() - start));
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
    lastHudLatencyMs = ms;
    sendHudStatusToRenderer();
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('wifi-status', { ms });
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

      // Auto-exit after 10 consecutive offline checks (~30 seconds of no connectivity)
      if (consecutiveOfflineCount >= 10 && !IS_DEV) {
        console.error('[SecureBrowser] Network lost for 10 consecutive checks. Forcing exit.');
        showModalDialog(mainWindow, {
          type: 'error',
          title: 'Network Connection Lost',
          message:
            'The secure browser has lost its network connection for more than 30 seconds.\n\nFor exam integrity, the session will now close. Please contact your administrator.',
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

let keyboardLockChild: ReturnType<typeof spawn> | null = null;

/**
 * Windows Low-Level OS Lockdown:
 * 1. Enables Explorer NoWinKeys policy via Windows Registry and broadcasts WM_SETTINGCHANGE.
 * 2. Spawns scripts/keyboard-lock.ps1 in a hidden background process (WH_KEYBOARD_LL)
 *    which intercepts and suppresses WinKey, Alt+Tab, Alt+Esc, Ctrl+Esc, Alt+Space.
 *
 * Packaging note: scripts/ is declared as extraResources so it is unpacked next to
 * the app.asar at process.resourcesPath — PowerShell can execute it directly from disk.
 */
function startWindowsKeyboardLock(): void {
  if (process.platform !== 'win32' || IS_DEV) return;

  // 1. Apply NoWinKeys registry policy and broadcast to Explorer immediately
  exec(
    'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoWinKeys /t REG_DWORD /d 1 /f',
    (err) => {
      if (err) {
        console.warn('[SecureBrowser] Failed to set NoWinKeys registry policy:', err.message);
      } else {
        console.log('[SecureBrowser] NoWinKeys registry policy applied.');
        // Broadcast WM_SETTINGCHANGE so Explorer respects the policy without a restart
        exec(
          `powershell -NonInteractive -WindowStyle Hidden -Command "[System.Environment]::SetEnvironmentVariable('BB_POLICY','1','User')"`,
          () => {}
        );
      }
    }
  );

  // 2. Resolve script path — extraResources unpacks scripts/ to process.resourcesPath/scripts
  let scriptPath: string;
  if (app.isPackaged) {
    scriptPath = path.join(process.resourcesPath, 'scripts', 'keyboard-lock.ps1');
  } else {
    scriptPath = path.join(__dirname, '..', 'scripts', 'keyboard-lock.ps1');
  }

  // 3. Fail-safe: if script is missing (edge case in ASAR extraction), copy to tmpdir
  if (!fs.existsSync(scriptPath)) {
    console.warn('[SecureBrowser] keyboard-lock.ps1 missing at:', scriptPath, '— writing tmpdir fallback.');
    const tmpScript = path.join(os.tmpdir(), 'bb-keyboard-lock.ps1');
    const srcInDev = path.join(__dirname, '..', 'scripts', 'keyboard-lock.ps1');
    try {
      if (fs.existsSync(srcInDev)) {
        fs.copyFileSync(srcInDev, tmpScript);
      } else {
        // Absolute last resort: write a minimal inline WinKey suppressor
        fs.writeFileSync(tmpScript, [
          '$sig = @"',
          'using System; using System.Runtime.InteropServices;',
          'public class BB { const int WH_KEYBOARD_LL=13;',
          'delegate IntPtr H(int n,IntPtr w,IntPtr l);',
          '[DllImport("user32")] static extern IntPtr SetWindowsHookEx(int i,H p,IntPtr m,uint t);',
          '[DllImport("user32")] static extern IntPtr CallNextHookEx(IntPtr h,int n,IntPtr w,IntPtr l);',
          '[DllImport("kernel32")] static extern IntPtr GetModuleHandle(string m);',
          'struct MSG { public IntPtr hw; public uint msg; public IntPtr wp,lp; public uint t; public int x,y; }',
          '[DllImport("user32")] static extern int GetMessage(out MSG m,IntPtr h,uint a,uint b);',
          '[DllImport("user32")] static extern bool TranslateMessage(ref MSG m);',
          '[DllImport("user32")] static extern IntPtr DispatchMessage(ref MSG m);',
          '[DllImport("user32")] static extern short GetKeyState(int k);',
          'static H _cb; static IntPtr _hk=IntPtr.Zero;',
          'static IntPtr CB(int n,IntPtr w,IntPtr l){',
          'if(n>=0){int v=System.Runtime.InteropServices.Marshal.ReadInt32(l);',
          'if(v==0x5B||v==0x5C) return (IntPtr)1;}',
          'return CallNextHookEx(_hk,n,w,l);}',
          'public static void Run(){using(var p=System.Diagnostics.Process.GetCurrentProcess())',
          'using(var mm=p.MainModule){_cb=CB;_hk=SetWindowsHookEx(WH_KEYBOARD_LL,_cb,GetModuleHandle(mm.ModuleName),0);}',
          'MSG msg; while(GetMessage(out msg,IntPtr.Zero,0,0)>0){TranslateMessage(ref msg);DispatchMessage(ref msg);}}}',
          '"@',
          'Add-Type -TypeDefinition $sig',
          '[BB]::Run()',
        ].join('\n'));
      }
      scriptPath = tmpScript;
      console.log('[SecureBrowser] keyboard-lock.ps1 fallback written to:', tmpScript);
    } catch (writeErr: unknown) {
      const msg = writeErr instanceof Error ? writeErr.message : String(writeErr);
      console.error('[SecureBrowser] Could not write keyboard-lock fallback script:', msg);
      return;
    }
  }

  // 4. Spawn the hook in a completely hidden background process
  try {
    console.log('[SecureBrowser] Spawning Windows low-level keyboard hook:', scriptPath);
    keyboardLockChild = spawn(
      'powershell.exe',
      [
        '-NoProfile',
        '-NonInteractive',
        '-WindowStyle', 'Hidden',
        '-ExecutionPolicy', 'Bypass',
        '-File', scriptPath,
      ],
      { windowsHide: true, stdio: 'ignore' }
    );

    keyboardLockChild.on('error', (err) => {
      console.warn('[SecureBrowser] Keyboard lock process error:', err.message);
    });

    keyboardLockChild.on('exit', (code) => {
      console.log(`[SecureBrowser] Keyboard lock process exited with code ${code}`);
      keyboardLockChild = null;
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error('[SecureBrowser] Failed to spawn keyboard hook:', msg);
  }
}

function stopWindowsKeyboardLock(): void {
  if (process.platform !== 'win32') return;

  // 1. Reset / Delete Registry Policy
  exec(
    'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoWinKeys /f',
    () => {}
  );

  // 2. Kill keyboard lock child process
  if (keyboardLockChild) {
    try {
      keyboardLockChild.kill();
    } catch {}
    keyboardLockChild = null;
  }
}

// ─── Emergency Exit Shortcut ─────────────────────────────────────────────────

/**
 * Registers an unconditional emergency exit shortcut for administrators/developers.
 *
 * - macOS: Command + L
 * - Windows/Linux: Ctrl + Shift + L
 *
 * This shortcut is ALWAYS registered so the app can always be exited during
 * testing without requiring a physical machine restart. It is registered once
 * during app initialisation and survives unregisterGlobalShortcuts() calls.
 */
function registerEmergencyExitShortcut(): void {
  const shortcuts = process.platform === 'darwin'
    ? ['Command+Q', 'Command+Shift+Q', 'Command+L']
    : ['CommandOrControl+Shift+L', 'Alt+F4'];

  for (const shortcut of shortcuts) {
    try {
      const registered = globalShortcut.register(shortcut, (): void => {
        console.log(`[SecureBrowser] Emergency exit shortcut triggered (${shortcut}) — performing clean shutdown.`);
        performCleanExit();
      });
      if (registered) {
        console.log(`[SecureBrowser] Emergency exit shortcut registered: ${shortcut}`);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`[SecureBrowser] Could not register emergency exit shortcut ${shortcut}:`, msg);
    }
  }
}

/** Performs a clean, ordered emergency application shutdown. */
function performCleanExit(): void {
  console.log('[SecureBrowser] performCleanExit: tearing down all locks and exiting.');
  try { stopProcessMonitor(); } catch {}
  try { stopClipboardWiper(); } catch {}
  try { stopWindowsKeyboardLock(); } catch {}
  try { globalShortcut.unregisterAll(); } catch {}
  try {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.setKiosk(false);
      mainWindow.setFullScreen(false);
      mainWindow.setAlwaysOnTop(false);
    }
  } catch {}
  // Force process exit — app.quit() may not flush if kiosk prevents it
  app.exit(0);
}

// ─── Global Shortcut Blocker ─────────────────────────────────────────────────

function registerGlobalShortcuts(): void {
  if (IS_DEV) return;

  // Windows: Activate low-level keyboard hook FIRST before registering Electron shortcuts
  // so the WH_KEYBOARD_LL hook is in place even if globalShortcut.register() fails.
  startWindowsKeyboardLock();

  for (const shortcut of BLOCKED_SHORTCUTS) {
    try {
      globalShortcut.register(shortcut, (): void => {
        console.log(`[SecureBrowser] Blocked OS shortcut: ${shortcut}`);
        // Intentionally a no-op — suppresses the shortcut at Electron level
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.warn(`[SecureBrowser] Failed to block shortcut "${shortcut}": ${message}`);
    }
  }

  console.log('[SecureBrowser] Global lockdown shortcuts registered.');
}

function unregisterGlobalShortcuts(): void {
  // 1. Release all lockdown shortcuts (Alt+Tab, Cmd+Tab, etc.)
  globalShortcut.unregisterAll();
  stopWindowsKeyboardLock();

  // 2. Re-register the emergency exit shortcut so testing can always exit cleanly
  registerEmergencyExitShortcut();

  console.log('[SecureBrowser] Global lockdown shortcuts unregistered. Emergency exit shortcut re-registered.');
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

  // On macOS, ps -ax -o comm= returns the full path or binary name.
  // We keep the FULL path so the daemon whitelist can filter on path prefixes,
  // but also compute the basename for blacklist matching.
  return lines
    .map((line): string => line.trim().toLowerCase())
    .filter(Boolean);
}

/**
 * Returns true when the process string is a known macOS/Windows OS daemon
 * that must never be flagged as a violation, regardless of its name.
 *
 * Rules:
 *  - Apple system daemons: paths under /System/, /usr/libexec/, /usr/sbin/
 *  - Reverse-DNS Apple bundle identifiers: com.apple.*
 *  - Known mis-matchable OS agents: searchpartyd, passcodesettings*, trialarchivingservice
 *  - Electron/app own helpers: chrome_crashpad_handler, bluebirds, securebrowser
 */
function isSystemDaemon(proc: string): boolean {
  const p = proc.toLowerCase().trim();

  // Path-based whitelist (macOS & system directories)
  if (
    p.startsWith('/system/') ||
    p.startsWith('/usr/libexec/') ||
    p.startsWith('/usr/sbin/') ||
    p.startsWith('/usr/bin/') ||
    p.startsWith('/sbin/') ||
    p.startsWith('/bin/') ||
    p.includes('/system/library/') ||
    p.includes('/library/apple/') ||
    p.includes('/privateframeworks/')
  ) {
    return true;
  }

  // Reverse-DNS Apple bundle ID style names
  if (p.startsWith('com.apple.') || p.startsWith('com.google.chrome.')) {
    if (p.startsWith('com.apple.')) return true;
  }

  // Name-based whitelist: known daemon base names that substring-match blacklist words
  const daemonBasenames = [
    'chrome_crashpad_handler',   // Electron/Chrome internal crash reporter
    'searchpartyd',              // Apple Find My / SearchParty daemon
    'searchpartyuseragent',      // Apple SearchParty user agent
    'findmy',                    // Apple Find My service
    'findmyd',                   // Apple Find My daemon
    'trialarchivingservice',     // macOS system service
    'passcodesettingssubscriber', // macOS passcode subscriber
    'com.apple.safebrowsing',    // Apple Safe Browsing
    'safebrowsing',              // Apple Safe Browsing
    'softwareupdate',            // OS update daemon
    'securityd',                 // macOS security daemon
    'codesign',                  // Apple code signing tool (not VS Code)
    'codesigninghelper',         // Apple codesigning helper
    'ksfetch',                   // Google Software Update daemon (not Chrome app)
    'keyboardservicesd',         // Apple keyboard services daemon
    'diskspacediagnostic',       // Apple diagnostic daemon
    'cloudd',                    // Apple iCloud daemon
    'bird',                      // Apple iCloud Documents daemon
    'identityservicesd',         // Apple IDS daemon
    'rapportd',                  // Apple device communication daemon
  ];

  const basename = (p.includes('/') ? p.split('/').pop()! : p).toLowerCase();
  if (
    daemonBasenames.some((d) => basename === d || basename.startsWith(d)) ||
    basename.startsWith('searchparty') ||
    basename.startsWith('findmy')
  ) {
    return true;
  }

  // Whitelist the secure browser's own helpers
  if (
    basename.includes('bluebird') ||
    basename.includes('securebrowser') ||
    basename === 'electron'
  ) {
    return true;
  }

  return false;
}

/**
 * Returns true when process `proc` matches blacklist entry `black` using
 * exact word-boundary matching instead of naive substring matching.
 *
 * Strategy:
 *   - Extract the basename (binary filename without path).
 *   - Match only if the blacklist term equals the basename exactly,
 *     OR if the basename starts/ends with the term at a word boundary
 *     (separated by a space, hyphen, dot, or underscore).
 *   - This prevents 'arc' from matching 'trialarchivingservice'
 *     and 'code' from matching 'com.apple.codesigninghelper'.
 */
function matchesBlacklist(proc: string, black: string): boolean {
  const basename = (proc.includes('/') ? proc.split('/').pop()! : proc).toLowerCase();
  const term = black.toLowerCase();

  // Exact match (e.g. 'safari', 'code', 'arc')
  if (basename === term) return true;

  // Match with common executable suffixes (.exe, .app)
  if (basename === `${term}.exe` || basename === `${term}.app`) return true;

  // Word-boundary match: term must be surrounded by a non-word character or string boundary.
  // Uses a regex to ensure the term isn't embedded inside a longer identifier.
  // e.g. 'arc' matches 'arc browser' but NOT 'searchpartyd' or 'trialarchivingservice'
  const wordBoundaryRegex = new RegExp(`(?<![a-z0-9])${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![a-z0-9])`);
  return wordBoundaryRegex.test(basename);
}

/**
 * Check a list of process names against the blacklist and VM indicator lists.
 * Returns the first violation found, or null if the environment is clean.
 */
function detectViolation(processes: string[]): SecurityStatus | null {
  for (const proc of processes) {
    // Skip OS system daemons — they must never be flagged
    if (isSystemDaemon(proc)) continue;

    if (BLACKLIST.some((black) => matchesBlacklist(proc, black))) {
      const basename = proc.includes('/') ? proc.split('/').pop()! : proc;
      return {
        hasViolation: true,
        type: 'blacklisted-app',
        process: basename,
        message: `Forbidden application running: "${basename}". Please close it to proceed with the test.`,
      };
    }

    if (VM_INDICATORS.some((vm) => proc.includes(vm))) {
      const basename = proc.includes('/') ? proc.split('/').pop()! : proc;
      return {
        hasViolation: true,
        type: 'vm-detected',
        process: basename,
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
  if (processMonitorInterval !== null) return;
  const isWindows: boolean = process.platform === 'win32';
  const queryCommand: string = isWindows ? 'tasklist /FO CSV /NH' : 'ps -ax -o comm=';
  console.log('[SecureBrowser] Starting periodic process monitor.');

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

/**
 * Collect list of running blacklisted apps and detect VM presence.
 * Uses exact word-boundary matching and filters out macOS OS daemons
 * to prevent false positives from system processes.
 */
function getRunningViolations(processes: string[]): { forbiddenApps: string[]; vmDetected: boolean } {
  const forbiddenAppsSet = new Set<string>();
  let vmDetected = false;

  for (const proc of processes) {
    // Skip OS daemons — never flag system processes
    if (isSystemDaemon(proc)) continue;

    const basename = proc.includes('/') ? proc.split('/').pop()! : proc;

    for (const black of BLACKLIST) {
      if (matchesBlacklist(proc, black)) {
        // Use the human-readable basename for the violation report
        forbiddenAppsSet.add(basename);
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

/** Cross-platform command executor to force close running processes.
 * On Windows, /T kills the entire process tree (parent + all children) to
 * ensure packaged apps like WhatsApp (which spawn whatsapp.root.exe as a
 * child process) are fully terminated.
 */
function killProcess(name: string, isWindows: boolean): Promise<void> {
  return new Promise((resolve) => {
    // Safety check: NEVER kill system daemons!
    if (isSystemDaemon(name)) {
      console.warn(`[SecureBrowser] Refusing to kill protected system daemon: ${name}`);
      resolve();
      return;
    }

    // /T = terminate process and all of its children (process tree kill)
    // On macOS: use exact-name match or app bundle match, not broad substring
    const cmd = isWindows
      ? `taskkill /F /T /IM "${name}"`
      : `pkill -9 -i -x "${name}" 2>/dev/null || pkill -9 -i -f "${name}.app" 2>/dev/null`;

    console.log(`[SecureBrowser] Force-closing process: ${name} (cmd: ${cmd})`);
    exec(cmd, (err) => {
      if (err) {
        // Error code 128 means process not found — acceptable if already closed
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
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.setAlwaysOnTop(true, 'screen-saver', 1);
    mainWindow.moveTop();
    mainWindow.show();
    mainWindow.focus();
  }
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

/** Automatically closes/terminates all other active visible GUI applications on startup.
 * Whitelists crucial OS shells and the secure browser itself.
 *
 * CRITICAL: This function resolves within MAX_KILL_TIMEOUT_MS regardless of
 * system responsiveness — it must never block the splash screen indefinitely.
 */
function closeAllOtherGUIApps(): Promise<void> {
  const MAX_KILL_TIMEOUT_MS = 5_000;

  return new Promise<void>((resolve) => {
    // Hard timeout: no matter what, we move on after MAX_KILL_TIMEOUT_MS
    const timeoutHandle = setTimeout(() => {
      console.warn('[SecureBrowser] closeAllOtherGUIApps: hit hard timeout, continuing startup.');
      resolve();
    }, MAX_KILL_TIMEOUT_MS);

    const done = (): void => {
      clearTimeout(timeoutHandle);
      resolve();
    };

    if (process.platform === 'win32') {
      const whitelist = ['explorer', 'bluebirdssecurebrowser', 'electron'];

      exec(
        `powershell -NonInteractive -WindowStyle Hidden -Command "Get-Process | Where-Object {$_.MainWindowTitle -ne ''} | Select-Object -Unique -ExpandProperty ProcessName"`,
        (err, stdout) => {
          if (err || !stdout) { done(); return; }

          const lines = stdout.split('\r\n').map(l => l.trim().toLowerCase()).filter(Boolean);
          const toKill = lines.filter(name => !whitelist.some(w => name.includes(w)));

          if (toKill.length === 0) { done(); return; }

          console.log('[SecureBrowser] Auto-closing Windows GUI processes:', toKill);

          // Batch-kill all in a single taskkill call via PowerShell to avoid spawning N processes
          const killCmd = toKill.map(n => `taskkill /F /IM "${n}.exe"`).join(' & ');
          exec(killCmd, () => done());
        }
      );
    } else if (process.platform === 'darwin') {
      // Fire all pkill calls in parallel — no blocking osascript calls
      const killTargets = [
        'Google Chrome', 'Google Chrome Helper', 'Google Chrome Helper (Renderer)',
        'Brave Browser', 'Brave Browser Helper', 'Brave Browser Helper (Renderer)',
        'Microsoft Edge', 'Firefox', 'Safari',
        'Opera', 'Vivaldi', 'Arc', 'Slack', 'zoom.us', 'Discord', 'Microsoft Teams',
        'Telegram', 'WhatsApp', 'Skype', 'TeamViewer', 'AnyDesk', 'obs', 'chrome-devtools-mcp',
      ];

      let pending = killTargets.length;
      const check = (): void => {
        pending--;
        if (pending <= 0) done();
      };

      killTargets.forEach((proc) => {
        exec(`pkill -9 -i -x "${proc}" 2>/dev/null; pkill -9 -i -f "${proc}" 2>/dev/null`, check);
      });
    } else {
      done();
    }
  });
}


/** Checks for monitor count, blacklisted apps, and VM state on launch. Offers options to auto-close. */
async function checkAndCleanSystem(parentWindow?: BrowserWindow): Promise<boolean> {
  const isWindows = process.platform === 'win32';

  if (IS_DEV) {
    return true;
  }

  // Auto-close all other user GUI applications silently first
  await closeAllOtherGUIApps();
  // Give system process/window closing events 1.5 seconds to settle
  await new Promise((resolve) => setTimeout(resolve, 1500));

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
    console.log('[SecureBrowser] Startup security gate: detected forbidden apps:', forbiddenApps);
    const passed = await showProhibitedModalGate(forbiddenApps);
    if (!passed) {
      return false;
    }
  }

  return true;
}


function stopProcessMonitor(): void {
  if (processMonitorInterval !== null) {
    clearInterval(processMonitorInterval);
    processMonitorInterval = null;
    console.log('[SecureBrowser] Process monitor stopped.');
  }
}

// ─── Clipboard Wiper ─────────────────────────────────────────────────────────

function startClipboardWiper(): void {
  if (IS_DEV || clipboardWiperInterval !== null) return;
  console.log('[SecureBrowser] Starting clipboard wiper.');

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

function stopClipboardWiper(): void {
  if (clipboardWiperInterval !== null) {
    clearInterval(clipboardWiperInterval);
    clipboardWiperInterval = null;
    console.log('[SecureBrowser] Clipboard wiper stopped.');
  }
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
        // On Windows, Chromium handles media permissions internally with no OS dialog.
        // We must NOT suspend fullscreen/kiosk on Windows — it collapses the window.
        // On macOS, we suspend so the TCC system dialog can appear above the window.
        const isWin = process.platform === 'win32';
        if (!isWin) {
          pendingPermissions += 1;
          suspendKioskLockout();
          console.log(`[SecureBrowser] Kiosk suspended for permission dialog (macOS): ${permission}`);
        } else {
          console.log(`[SecureBrowser] Permission granted without kiosk suspend (Windows): ${permission}`);
        }

        // Grant the permission immediately
        callback(true);

        // macOS only: restore kiosk after OS dialog duration.
        // 5 s is sufficient — macOS TCC prompt appears almost instantly.
        if (!isWin) {
          restoreAfterPermissionDelayed(5_000);
        }
      } else if (permission === 'notifications') {
        console.log(`[SecureBrowser] Blocking permission request: ${permission}`);
        callback(false);
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
    version: app.getVersion(),
  };
});

ipcMain.handle('get-app-version', (): string => {
  return app.getVersion();
});

// ─── Process Management IPC Handlers ────────────────────────────────────────

/** IPC: check-processes
 * Queries running system processes and returns forbidden/VM violations.
 * Called by the pre-flight system-check page before entry.
 */
ipcMain.handle('check-processes', async (): Promise<{
  clean: boolean;
  forbiddenApps: string[];
  vmDetected: boolean;
}> => {
  const isWindows = process.platform === 'win32';
  try {
    const processes = await getSystemProcesses(isWindows);
    const { forbiddenApps, vmDetected } = getRunningViolations(processes);
    return { clean: forbiddenApps.length === 0 && !vmDetected, forbiddenApps, vmDetected };
  } catch (err) {
    console.error('[SecureBrowser] check-processes failed:', err);
    return { clean: true, forbiddenApps: [], vmDetected: false };
  }
});

/** IPC: kill-forbidden-processes
 * Force-closes all detected forbidden applications and returns updated status.
 * Called by the pre-flight UI when the user clicks "Auto-Close All Apps".
 */
ipcMain.handle('kill-forbidden-processes', async (): Promise<{
  success: boolean;
  remaining: string[];
}> => {
  const isWindows = process.platform === 'win32';
  try {
    const processes = await getSystemProcesses(isWindows);
    const { forbiddenApps } = getRunningViolations(processes);

    // Kill all forbidden apps
    for (const proc of forbiddenApps) {
      await killProcess(proc, isWindows);
    }

    // Wait for processes to terminate
    await new Promise((resolve) => setTimeout(resolve, 1500));

    // Re-check
    const afterProcesses = await getSystemProcesses(isWindows);
    const { forbiddenApps: remaining } = getRunningViolations(afterProcesses);
    return { success: remaining.length === 0, remaining };
  } catch (err) {
    console.error('[SecureBrowser] kill-forbidden-processes failed:', err);
    return { success: false, remaining: [] };
  }
});

/** IPC: kill-process-by-name
 * Force-closes a single named process. Used from the mid-exam violation modal
 * so candidates can terminate a rogue app and immediately resume their exam.
 */
ipcMain.handle('kill-process-by-name', async (_event, processName: string): Promise<boolean> => {
  if (!processName || typeof processName !== 'string') return false;
  const isWindows = process.platform === 'win32';
  try {
    await killProcess(processName, isWindows);
    console.log(`[SecureBrowser] Successfully killed process: ${processName}`);
    return true;
  } catch (err) {
    console.error(`[SecureBrowser] kill-process-by-name failed for ${processName}:`, err);
    return false;
  }
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

ipcMain.on('app-force-quit', (): void => {
  console.log('[SecureBrowser] app-force-quit received from in-app dock modal.');
  performCleanExit();
});

ipcMain.on('close-browser', (_event: IpcMainEvent): void => {
  console.log('[SecureBrowser] Closing application on renderer request...');
  performCleanExit();
});

// Overlay close button — show native dialog box to cleanly confirm exit
ipcMain.on('overlay-request-close', async (): Promise<void> => {
  console.log('[SecureBrowser] overlay-request-close received from native HUD.');

  isConfirmingExit = true;
  try {
    if (isExamActive && mainWindow && !mainWindow.isDestroyed()) {
      const { response } = await dialog.showMessageBox(mainWindow, {
        type: 'warning',
        title: 'Exit Secure Browser',
        message: 'Are you sure you want to exit the examination?',
        detail: 'If you exit now, your assessment will remain in-progress and must be completed before the deadline. Do you wish to quit the application?',
        buttons: ['Return to Exam', 'Exit App'],
        defaultId: 0,
        cancelId: 0,
        noLink: true,
      });

      if (response === 1) {
        console.log('[SecureBrowser] User confirmed exit from native HUD during exam.');
        performCleanExit();
      }
    } else {
      const opts: Electron.MessageBoxOptions = {
        type: 'question',
        title: 'Exit Secure Browser',
        message: 'Do you want to quit the Secure Browser application?',
        buttons: ['Cancel', 'Quit App'],
        defaultId: 1,
        cancelId: 0,
        noLink: true,
      };
      const { response } = mainWindow && !mainWindow.isDestroyed()
        ? await dialog.showMessageBox(mainWindow, opts)
        : await dialog.showMessageBox(opts);

      if (response === 1) {
        console.log('[SecureBrowser] User confirmed exit from native HUD.');
        performCleanExit();
      }
    }
  } finally {
    isConfirmingExit = false;
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.focus();
    }
  }
});

// Splash screen cancel/exit button
ipcMain.on('splash-cancel-exit', (): void => {
  console.log('[SecureBrowser] Splash cancel/exit requested by user.');
  performCleanExit();
});

ipcMain.on('exam-started', (): void => {
  console.log('[SecureBrowser] Exam started. Activating security lockout, shortcuts & process monitoring.');
  isExamActive = true;
  // Clear permission-request mode and ensure full lockout is active when exam begins
  isRequestingPermission = false;
  restoreKioskLockout();
  registerGlobalShortcuts();
  startProcessMonitor();
  startClipboardWiper();
});

ipcMain.on('exam-finished', (): void => {
  console.log('[SecureBrowser] Exam finished. Deactivating aggressive security hooks while keeping fullscreen shell active.');
  isExamActive = false;
  unregisterGlobalShortcuts();
  stopProcessMonitor();
  stopClipboardWiper();
  // DO NOT call suspendKioskLockout() here — the browser must strictly maintain fullscreen kiosk on macOS.
  if (isUpdateDownloaded) {
    console.log('[SecureBrowser] Installing postponed update after exam finished...');
    autoUpdater.quitAndInstall();
  }
});

ipcMain.on('restore-fullscreen', (): void => {
  console.log('[SecureBrowser] Explicit restore-fullscreen IPC requested.');
  restoreKioskLockout();
});

// ─── Deep Link & Single Instance Handler ──────────────────────────────────────

/**
 * Synchronous update gate executed while the splash screen is strictly front and center.
 * If an update is detected, it stays on the splash screen, downloads the update with live
 * progress, and restarts the app via autoUpdater.quitAndInstall().
 *
 * Returns true if an update was found and is downloading/restarting (mainWindow must NOT be created).
 * Returns false if no update is available, dev mode, or check times out/errors (proceed to exam).
 */
function checkAndApplyUpdates(splash: BrowserWindow | null): Promise<boolean> {
  if (IS_DEV) {
    console.log('[AutoUpdater] Bypassing update check in DEV mode.');
    return Promise.resolve(false);
  }

  return new Promise<boolean>((resolve) => {
    let resolved = false;
    const finish = (result: boolean): void => {
      if (!resolved) {
        resolved = true;
        clearTimeout(safetyTimeout);
        resolve(result);
      }
    };

    // Safety timeout: never block a student forever if Cloudflare or network is unreachable
    const safetyTimeout = setTimeout((): void => {
      console.warn('[AutoUpdater] Update check timed out after 5000ms. Continuing to exam.');
      finish(false);
    }, 5000);

    sendUpdateStatus({ status: 'checking' });

    autoUpdater.once('update-available', (info): void => {
      console.log(`[AutoUpdater] Update available: v${info.version}. Retaining splash and downloading...`);
      isUpdating = true;
      clearTimeout(safetyTimeout);
      sendUpdateStatus({
        status: 'available',
        version: info.version,
      });
      // Update is downloading on splash screen — prevent mainWindow creation
      finish(true);
    });

    autoUpdater.once('update-not-available', (info): void => {
      console.log(`[AutoUpdater] Client is up to date (v${app.getVersion()}).`);
      isUpdating = false;
      sendUpdateStatus({
        status: 'not-available',
        version: app.getVersion(),
      });
      finish(false);
    });

    autoUpdater.once('error', (err: Error): void => {
      console.error('[AutoUpdater] Update check error:', err.message);
      isUpdating = false;
      sendUpdateStatus({
        status: 'error',
        error: err.message,
      });
      finish(false);
    });

    autoUpdater.checkForUpdates().catch((err: Error): void => {
      console.error('[AutoUpdater] Error initiating update check:', err.message);
      finish(false);
    });
  });
}

async function initializeApp(): Promise<void> {
  if (isInitialized) return;
  isInitialized = true;

  // Register emergency exit shortcut FIRST — before any blocking operations.
  // This ensures Cmd+L / Ctrl+Shift+L can exit the app even during a stuck splash.
  registerEmergencyExitShortcut();

  // Windows: apply keyboard lockdown immediately so the WinKey is blocked from
  // the very first frame of the app's lifecycle (not just after exam-started).
  if (process.platform === 'win32' && !IS_DEV) {
    startWindowsKeyboardLock();
  }

  // 1. Show splash immediately so the user sees something while checks run.
  createSplashWindow();
  if (splashWindow) {
    splashWindow.show();
    bringAppToFront();
  }

  // 2. Synchronous update gate: check and apply updates while candidate is strictly on splash
  if (!IS_DEV) {
    const isRestartingForUpdate = await checkAndApplyUpdates(splashWindow);
    if (isRestartingForUpdate) {
      console.log('[SecureBrowser] Update in progress. Halting window creation to prevent premature UI loading.');
      return;
    }
  }

  // 3. Update check passed or bypassed: Run system checks & clean forbidden processes
  const clean = await checkAndCleanSystem(splashWindow ?? undefined);
  if (!clean) {
    console.log('[SecureBrowser] Startup requirements not met. Quitting.');
    app.quit();
    return;
  }

  // 4. Everything verified & updated — create and display the exam window
  createWindow();
  startHudMonitor();
  installPermissionHandler(); // Must run after createWindow so session is ready
  startWifiMonitor();
  console.log('[SecureBrowser] Application initialized. High-impact security hooks deferred to exam start.');
}


function handleDeepLink(urlStr: string): void {
  console.log(`[SecureBrowser] Deep link received: ${urlStr}`);
  wasOpenedViaDeepLink = true;

  try {
    const parsedUrl = new URL(urlStr);
    const attemptId = parsedUrl.searchParams.get('attemptId');
    const assessmentId = parsedUrl.searchParams.get('assessmentId');
    const token = parsedUrl.searchParams.get('token');

    if ((attemptId || assessmentId) && token) {
      // Store credentials so preload can inject them synchronously before React boots
      activeAttemptId = attemptId;
      activeAssessmentId = assessmentId;
      activeToken = token;
      console.log(`[SecureBrowser] Deep link credentials stored: attempt=${attemptId}, assessment=${assessmentId}`);
    } else {
      console.warn('[SecureBrowser] Deep link missing attemptId/assessmentId or token. Ignoring.');
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

  // Already initialized — verify system is clean first, then navigate the live window
  if (mainWindow) {
    (async () => {
      const clean = await checkAndCleanSystem(mainWindow);
      if (!clean) {
        console.log('[SecureBrowser] Startup gate rejected deep link navigation because system was not clean.');
        return;
      }

      const origin =
        process.env.APP_URL ??
        (IS_DEV ? 'http://localhost:5173' : 'https://tests.bluebirdstraining.com');

      const targetId = activeAttemptId || activeAssessmentId;
      if (targetId) {
        let systemCheckUrl = `${origin}/system-check/${targetId}`;
        if (activeToken) {
          systemCheckUrl += `?token=${encodeURIComponent(activeToken)}`;
        }
        console.log(`[SecureBrowser] Navigating live window to system check: ${systemCheckUrl}`);

        if (activeToken) {
          mainWindow.webContents
            .executeJavaScript(
              `try { localStorage.setItem('accessToken', '${activeToken}'); sessionStorage.setItem('accessToken', '${activeToken}'); } catch(e) {}`
            )
            .catch(() => {});
        }
        mainWindow.loadURL(systemCheckUrl);
      }

      // Bring to foreground
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.setAlwaysOnTop(true, 'screen-saver');
      mainWindow.focus();
      bringAppToFront();
    })();
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

    autoUpdater.on('checking-for-update', (): void => {
      console.log('[AutoUpdater] Checking for updates on remote repository...');
      sendUpdateStatus({ status: 'checking' });
    });

    autoUpdater.on('update-available', (info): void => {
      console.log(`[AutoUpdater] Update available: v${info.version}`);
      isUpdating = true;
      if (splashWindow && !splashWindow.isDestroyed()) {
        splashWindow.show();
        bringAppToFront();
      }
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.hide();
      }
      sendUpdateStatus({
        status: 'available',
        version: info.version,
      });
    });

    autoUpdater.on('download-progress', (progressObj): void => {
      isUpdating = true;
      const percent = Math.min(100, Math.max(0, progressObj.percent || 0));
      const bytesPerSecond = progressObj.bytesPerSecond || 0;
      const speed = bytesPerSecond > 0
        ? (bytesPerSecond >= 1024 * 1024
            ? `${(bytesPerSecond / (1024 * 1024)).toFixed(2)} MB/s`
            : `${(bytesPerSecond / 1024).toFixed(1)} KB/s`)
        : '0.00 MB/s';

      const transferred = progressObj.transferred || 0;
      const total = progressObj.total || 0;
      const remainingBytes = Math.max(0, total - transferred);

      let etaSeconds: number | null = null;
      let etaString = 'Calculating...';

      if (bytesPerSecond > 1024 && remainingBytes > 0) {
        etaSeconds = Math.ceil(remainingBytes / bytesPerSecond);
        if (etaSeconds < 60) {
          etaString = `~${etaSeconds}s remaining`;
        } else {
          const mins = Math.floor(etaSeconds / 60);
          const secs = etaSeconds % 60;
          etaString = `~${mins}m ${secs}s remaining`;
        }
      } else if (remainingBytes === 0 && total > 0) {
        etaString = 'Finalizing package...';
      }

      console.log(`[AutoUpdater] Progress: ${percent.toFixed(1)}% | ${speed} | ETA: ${etaString}`);

      sendUpdateStatus({
        status: 'downloading',
        percent,
        speed,
        bytesPerSecond,
        transferred,
        total,
        etaSeconds,
        etaString,
      });
    });

    autoUpdater.on('update-downloaded', (info): void => {
      console.log(`[AutoUpdater] Update v${info.version} downloaded successfully.`);
      isUpdateDownloaded = true;
      sendUpdateStatus({
        status: 'downloaded',
        version: info.version,
        percent: 100,
        etaString: 'Restarting in 1s...',
      });

      if (!isExamActive) {
        console.log('[AutoUpdater] Installing update and restarting client...');
        setTimeout((): void => {
          autoUpdater.quitAndInstall(false, true);
        }, 1500);
      } else {
        console.log('[AutoUpdater] Update downloaded during an active exam session. Postponing installation until exam finish.');
      }
    });

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
  unregisterGlobalShortcuts();
  stopProcessMonitor();
  stopClipboardWiper();
  if (wifiMonitorInterval !== null) {
    clearInterval(wifiMonitorInterval);
    wifiMonitorInterval = null;
  }
  console.log('[SecureBrowser] Application terminated and resources cleaned up.');
});
