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

// ─── getDisplayMedia Fallback Injection ──────────────────────────────────────
// Wraps navigator.mediaDevices.getDisplayMedia in the main world so that if the
// OS-level Screen Recording permission is denied (TCC) or the request is cancelled,
// we automatically return a dummy canvas MediaStream. This means the screen-share
// system check ALWAYS passes inside the Electron secure shell, because the
// kiosk/alwaysOnTop/contentProtection mechanisms are the real security layer.
//
// We inject via a <script> tag so the code runs in the MAIN world (not the
// isolated preload world), giving it access to the real navigator.mediaDevices.
try {
  const injectionScript = `
(function() {
  if (window.__secureBrowserGDMPatched) return;
  window.__secureBrowserGDMPatched = true;

  const _original = navigator.mediaDevices.getDisplayMedia.bind(navigator.mediaDevices);

  navigator.mediaDevices.getDisplayMedia = async function(constraints) {
    try {
      const stream = await _original(constraints);
      // ── Keep the live stream alive ──────────────────────────────────────
      // Once permission is granted and a real stream is running, ensure it
      // never drops mid-exam due to inactivity. We store it on the window so
      // it is never GC'd. The health-check in use-proctoring-engine will detect
      // if the track ends and trigger the "resume screen sharing" modal.
      window.__secureBrowserActiveStream = stream;
      return stream;
    } catch (err) {
      // Propagate the real error to the caller so system-check.$id.tsx
      // can mark the check as 'fail' and show the "Open Settings" button.
      // Do NOT silently return a canvas stream here — that would mask a
      // genuine OS-level permission denial.
      console.warn('[SecureBrowser] getDisplayMedia failed (' + err + '). Propagating error to UI.');
      throw err;
    }
  };

  console.log('[SecureBrowser] getDisplayMedia wrapper installed (permission-enforcing mode).');
})();
  `.trim();

  // Inject a <script> tag into the document so it runs in the main world
  // Use (globalThis as any) throughout to avoid tsconfig lib conflicts.
  /* eslint-disable @typescript-eslint/no-explicit-any */
  const inject = () => {
    const _doc: any = (globalThis as any).document;
    if (!_doc) {
      setTimeout(inject, 2);
      return;
    }
    const parent = _doc.head || _doc.documentElement;
    if (parent) {
      const el: any = _doc.createElement('script');
      el.textContent = injectionScript;
      parent.appendChild(el);
      el.remove();
      console.log('[SecureBrowser Preload] getDisplayMedia wrapper injected successfully.');
    } else {
      const MutationObserverClass = (globalThis as any).MutationObserver;
      if (MutationObserverClass) {
        const observer = new MutationObserverClass(() => {
          const p = _doc.head || _doc.documentElement;
          if (p) {
            observer.disconnect();
            const el: any = _doc.createElement('script');
            el.textContent = injectionScript;
            p.appendChild(el);
            el.remove();
            console.log('[SecureBrowser Preload] getDisplayMedia wrapper injected via MutationObserver.');
          }
        });
        observer.observe(_doc, { childList: true, subtree: true });
      } else {
        setTimeout(inject, 10);
      }
    }
  };

  inject();
  /* eslint-enable @typescript-eslint/no-explicit-any */
} catch (e) {
  console.warn('[SecureBrowser Preload] Failed to inject getDisplayMedia wrapper:', e);
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

  /**
   * Checks OS Screen Recording permission and guides the user to grant it
   * if not yet granted. Must be called BEFORE getDisplayMedia().
   * Returns { granted: boolean, status: string, platform: string }.
   */
  requestScreenPermission: () => Promise<{ granted: boolean; status: string; platform: string }>;

  /**
   * Opens the OS-specific permission settings panel for the given permission type.
   * - macOS: System Settings → Privacy & Security → Screen Recording / Camera / Microphone
   * - Windows: Settings → Privacy & Security → Screen capture / Camera / Microphone
   * Kiosk mode is automatically suspended on macOS so the settings window can appear.
   */
  openPermissionSettings: (permType: 'screen' | 'camera' | 'microphone') => Promise<void>;
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

  // Ask the main process to verify/request Screen Recording permission
  requestScreenPermission: (): Promise<{ granted: boolean; status: string; platform: string }> =>
    ipcRenderer.invoke('request-screen-permission'),

  // Ask the main process to open the OS-specific permission settings panel
  openPermissionSettings: (permType: 'screen' | 'camera' | 'microphone'): Promise<void> =>
    ipcRenderer.invoke('open-permission-settings', permType),
};

contextBridge.exposeInMainWorld('secureBrowser', secureBrowserAPI);
