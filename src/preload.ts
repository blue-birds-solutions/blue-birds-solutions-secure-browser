import { contextBridge, ipcRenderer, IpcRendererEvent } from 'electron';

// ─── Bootstrap Token Injection ────────────────────────────────────────────────
// This runs SYNCHRONOUSLY before the React app boots.
// Reads deep-link credentials from the main process and injects the accessToken
// into localStorage so the React app starts already authenticated.
try {
  const bootTokens = ipcRenderer.sendSync('get-boot-tokens') as {
    attemptId: string | null;
    token: string | null;
  };
  if (bootTokens?.token) {
    localStorage.setItem('accessToken', bootTokens.token);
    console.log('[SecureBrowser Preload] Boot token injected into localStorage.');
  }
} catch (e) {
  console.warn('[SecureBrowser Preload] Failed to inject boot token:', e);
}


// ─── Type Definitions ────────────────────────────────────────────────────────

/** Payload emitted by the main process for any security status event. */
interface SecurityStatus {
  hasViolation: boolean;
  type: string | null;
  process?: string;
  message: string | null;
}

/** System-level status information returned by `getSystemStatus`. */
interface SystemStatus {
  kioskMode: boolean;
  antiScreenshot: boolean;
  multipleMonitors: boolean;
  os: string;
}

/** Unsubscribe function returned by all `on*` listeners. */
type Unsubscribe = () => void;

/**
 * The `secureBrowser` API exposed on `window.secureBrowser` inside
 * the renderer process via Electron's context bridge.
 */
interface SecureBrowserAPI {
  /** Returns true when code is executing inside the secure lockdown shell. */
  isSecureShell: () => true;

  /** Returns a promise resolving to the current system / security status. */
  getSystemStatus: () => Promise<SystemStatus>;

  /** Programmatically closes the browser shell (call after exam submission). */
  closeBrowser: () => void;

  /**
   * Subscribe to legacy one-off `security-violation` events.
   * @returns an unsubscribe function
   */
  onViolation: (callback: (violation: SecurityStatus) => void) => Unsubscribe;

  /**
   * Subscribe to real-time security status updates broadcast every 3 seconds.
   * `status.hasViolation === false` means the environment is clean.
   * @returns an unsubscribe function
   */
  onStatusUpdate: (callback: (status: SecurityStatus) => void) => Unsubscribe;

  /**
   * Subscribe to window-blur events (focus lost from the secure shell).
   * @returns an unsubscribe function
   */
  onWindowBlur: (callback: () => void) => Unsubscribe;
  onWindowFocus: (callback: () => void) => Unsubscribe;

  /** Notifies the shell that the student has entered/started the exam. */
  startExam: () => void;

  /** Notifies the shell that the student has submitted/finished the exam. */
  endExam: () => void;
}

// ─── Context Bridge Exposure ─────────────────────────────────────────────────

const secureBrowserAPI: SecureBrowserAPI = {
  // Sentinel — renderer code uses this to detect the secure shell environment
  isSecureShell: () => true,

  // Relay the system-status IPC call to the main process
  getSystemStatus: (): Promise<SystemStatus> =>
    ipcRenderer.invoke('get-system-status'),

  // Relay the close request to the main process
  closeBrowser: (): void => {
    ipcRenderer.send('close-browser');
  },

  // Legacy one-off violation events
  onViolation: (callback: (violation: SecurityStatus) => void): Unsubscribe => {
    const subscription = (_event: IpcRendererEvent, violation: SecurityStatus): void =>
      callback(violation);
    ipcRenderer.on('security-violation', subscription);
    return (): void => {
      ipcRenderer.removeListener('security-violation', subscription);
    };
  },

  // Real-time security status updates (sent every 3 s by the process monitor)
  onStatusUpdate: (callback: (status: SecurityStatus) => void): Unsubscribe => {
    const subscription = (_event: IpcRendererEvent, status: SecurityStatus): void =>
      callback(status);
    ipcRenderer.on('security-status-update', subscription);
    return (): void => {
      ipcRenderer.removeListener('security-status-update', subscription);
    };
  },

  // Window focus-loss notifications from the main process
  onWindowBlur: (callback: () => void): Unsubscribe => {
    const subscription = (): void => callback();
    ipcRenderer.on('window-blur', subscription);
    return (): void => {
      ipcRenderer.removeListener('window-blur', subscription);
    };
  },

  // Window focus-gain notifications from the main process
  onWindowFocus: (callback: () => void): Unsubscribe => {
    const subscription = (): void => callback();
    ipcRenderer.on('window-focus', subscription);
    return (): void => {
      ipcRenderer.removeListener('window-focus', subscription);
    };
  },

  // Notify the main process that the exam has started
  startExam: (): void => {
    ipcRenderer.send('exam-started');
  },

  // Notify the main process that the exam has finished
  endExam: (): void => {
    ipcRenderer.send('exam-finished');
  },
};

contextBridge.exposeInMainWorld('secureBrowser', secureBrowserAPI);
