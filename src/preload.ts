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
    const saveTokens = () => {
      try {
        localStorage.setItem('accessToken', bootTokens.token!);
        sessionStorage.setItem('accessToken', bootTokens.token!);
      } catch {}
    };
    saveTokens();
    const _win: any = (globalThis as any).window || (globalThis as any);
    if (_win && typeof _win.addEventListener === 'function') {
      _win.addEventListener('DOMContentLoaded', saveTokens);
    }
    console.log('[SecureBrowser Preload] Boot token injected into storage.');
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
  version?: string;
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

  /**
   * Subscribe to in-app close confirmation requests triggered by the overlay close button.
   * Prevents window blur and avoids triggering false proctoring violations.
   */
  onShowCloseConfirmation: (callback: () => void) => Unsubscribe;

  /**
   * Subscribe to background auto-update status updates (checking, downloading, ETA, etc.).
   */
  onUpdateStatus: (callback: (status: any) => void) => Unsubscribe;

  /**
   * Subscribe to real-time network latency updates (ping in ms).
   * @returns an unsubscribe function
   */
  onWifiStatus: (callback: (status: { ms: number | null }) => void) => Unsubscribe;

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

  /**
   * Audits currently running processes and returns forbidden applications
   * and VM indicator results. Intended for the pre-flight system-check page.
   */
  checkProcesses: () => Promise<{
    clean: boolean;
    forbiddenApps: string[];
    vmDetected: boolean;
  }>;

  /**
   * Force-terminates all detected forbidden processes (full process-tree kill
   * via `/T` on Windows). Returns whether the environment is now clean and any
   * remaining processes that could not be terminated.
   */
  killForbiddenProcesses: () => Promise<{ success: boolean; remaining: string[] }>;

  /**
   * Force-terminates a single process by its executable name.
   * Used from the mid-exam violation overlay so candidates can close a rogue
   * app and immediately continue their exam.
   */
  killProcessByName: (processName: string) => Promise<boolean>;

  /** Re-enforces native OS fullscreen and kiosk constraints. */
  restoreFullscreen: () => void;

  /** Synchronize active exam countdown timer string (e.g. "59:26") to the native top HUD. */
  syncExamTimer: (timerText: string) => void;

  /** Returns application version string. */
  getAppVersion: () => Promise<string>;

  /** Application version string synchronously available. */
  appVersion: string;
}

// ─── Context Bridge Exposure ─────────────────────────────────────────────────

const secureBrowserAPI: SecureBrowserAPI = {
  // Sentinel — renderer code uses this to detect the secure shell environment
  isSecureShell: () => true,

  // Synchronize exam countdown timer to native HUD
  syncExamTimer: (timerText: string): void => {
    try {
      const _doc: any = (globalThis as any).document;
      if (_doc) {
        const root = _doc.getElementById('__bb_seb_dock_root__');
        if (root && root.shadowRoot) {
          const timerEl = root.shadowRoot.getElementById('dock-timer-val');
          if (timerEl) timerEl.textContent = timerText;
        }
      }
    } catch {}
  },

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

  // Close confirmation request sent from overlay close button
  onShowCloseConfirmation: (callback: () => void): Unsubscribe => {
    const subscription = (): void => callback();
    ipcRenderer.on('show-close-confirmation', subscription);
    return (): void => {
      ipcRenderer.removeListener('show-close-confirmation', subscription);
    };
  },

  // Auto-updater status updates sent from main process
  onUpdateStatus: (callback: (status: any) => void): Unsubscribe => {
    const subscription = (_event: IpcRendererEvent, status: any): void => callback(status);
    ipcRenderer.on('auto-update-status', subscription);
    return (): void => {
      ipcRenderer.removeListener('auto-update-status', subscription);
    };
  },

  // Real-time network latency status updates sent from main process
  onWifiStatus: (callback: (status: { ms: number | null }) => void): Unsubscribe => {
    const subscription = (_event: IpcRendererEvent, status: { ms: number | null }): void =>
      callback(status);
    ipcRenderer.on('wifi-status', subscription);
    return (): void => {
      ipcRenderer.removeListener('wifi-status', subscription);
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

  // Audit running processes for forbidden apps / VM indicators
  checkProcesses: (): Promise<{ clean: boolean; forbiddenApps: string[]; vmDetected: boolean }> =>
    ipcRenderer.invoke('check-processes'),

  // Force-close all detected forbidden processes (tree-kill on Windows)
  killForbiddenProcesses: (): Promise<{ success: boolean; remaining: string[] }> =>
    ipcRenderer.invoke('kill-forbidden-processes'),

  // Force-close a single process by name (used from mid-exam violation overlay)
  killProcessByName: (processName: string): Promise<boolean> =>
    ipcRenderer.invoke('kill-process-by-name', processName),

  // Explicitly re-assert native OS fullscreen and kiosk constraints
  restoreFullscreen: (): void => {
    ipcRenderer.send('restore-fullscreen');
  },

  // Returns app version
  getAppVersion: (): Promise<string> =>
    ipcRenderer.invoke('get-app-version'),

  appVersion: '1.2.1',
};

contextBridge.exposeInMainWorld('secureBrowser', secureBrowserAPI);
contextBridge.exposeInMainWorld('__BLUEBIRDS_APP__', true);

// ─── SEB-Style Persistent Top HUD (Preload DOM Injection) ─────────────────────
// Injects a tamper-proof, high-contrast, SEB-style HUD into the DOM via Shadow DOM.
// Positioned at the top-center of the navbar to prevent blocking any navigation
// controls (such as Next / Prev buttons in coding exams) while guaranteeing
// 100% visibility across macOS, Windows, and Linux.

function initializeSebBottomDock(): void {
  const ROOT_ID = '__bb_seb_dock_root__';

  let currentLatency: number | null = typeof navigator !== 'undefined' && (navigator as any).onLine ? 24 : null;
  let currentBatteryPercent = 100;
  let currentIsCharging = false;
  let currentAppVersion = 'v1.2.1';

  /* eslint-disable @typescript-eslint/no-explicit-any */
  const createDockDOM = (shadow: any) => {
    shadow.innerHTML = `
      <style>
        :host {
          all: initial;
          position: fixed;
          top: 8px;
          left: 50%;
          transform: translateX(-50%);
          z-index: 2147483647;
          pointer-events: none;
          font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, sans-serif;
          -webkit-font-smoothing: antialiased;
        }

        .dock {
          pointer-events: auto;
          display: inline-flex;
          align-items: center;
          gap: 10px;
          background: rgba(255, 255, 255, 0.96);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border: 1px solid rgba(203, 213, 225, 0.9);
          border-radius: 9999px;
          padding: 5px 14px 5px 12px;
          box-shadow: 0 4px 18px rgba(15, 23, 42, 0.12), 0 1px 3px rgba(0, 0, 0, 0.05);
          color: #0f172a;
          font-size: 11.5px;
          user-select: none;
          -webkit-user-select: none;
          transition: all 0.2s ease;
        }

        .dock:hover {
          background: #ffffff;
          border-color: #cbd5e1;
          box-shadow: 0 8px 24px rgba(15, 23, 42, 0.16);
        }

        .brand {
          display: flex;
          align-items: center;
          gap: 6px;
        }

        .brand-badge {
          background: #2563eb;
          color: #ffffff;
          font-weight: 800;
          font-size: 9.5px;
          padding: 1.5px 5px;
          border-radius: 4px;
          letter-spacing: 0.04em;
        }

        .brand-title {
          font-weight: 700;
          color: #0f172a;
          font-size: 11px;
          letter-spacing: -0.01em;
        }

        .version-tag {
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
          font-size: 9.5px;
          color: #64748b;
          background: #f1f5f9;
          padding: 1px 5px;
          border-radius: 4px;
          border: 1px solid #e2e8f0;
        }

        .divider {
          width: 1px;
          height: 14px;
          background: #e2e8f0;
        }

        .stat-item {
          display: flex;
          align-items: center;
          gap: 5px;
          font-weight: 500;
        }

        .icon {
          width: 14px;
          height: 14px;
          flex-shrink: 0;
        }

        .mono {
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
          font-size: 11px;
          letter-spacing: 0.02em;
        }

        /* Wifi colors */
        .wifi-green { color: #10b981; }
        .wifi-amber { color: #f59e0b; }
        .wifi-red   { color: #ef4444; }

        /* Battery fill */
        .battery-container {
          position: relative;
          display: flex;
          align-items: center;
        }

        .battery-svg {
          width: 20px;
          height: 12px;
          color: #64748b;
        }

        .battery-bolt {
          position: absolute;
          left: 50%;
          top: 50%;
          transform: translate(-50%, -50%);
          width: 9px;
          height: 9px;
          color: #f59e0b;
          display: none;
        }

        .battery-bolt.active {
          display: block;
        }

        /* Timer display */
        .timer-val {
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
          font-size: 11.5px;
          font-weight: 700;
          color: #0f172a;
          letter-spacing: 0.02em;
        }

        /* Exit Button */
        .exit-btn {
          all: unset;
          cursor: pointer;
          display: flex;
          align-items: center;
          gap: 4px;
          background: #fef2f2;
          border: 1px solid rgba(239, 68, 68, 0.4);
          color: #dc2626;
          padding: 3px 8px;
          border-radius: 9999px;
          font-size: 10.5px;
          font-weight: 700;
          transition: all 0.15s ease;
        }

        .exit-btn:hover {
          background: #dc2626;
          border-color: #ef4444;
          color: #ffffff;
          box-shadow: 0 2px 8px rgba(220, 38, 38, 0.35);
        }

        .exit-btn:active {
          transform: scale(0.96);
        }

        .exit-btn svg {
          width: 12px;
          height: 12px;
        }

        /* In-App Confirmation Modal (Zero Focus-Loss, Zero Tab-Switch Violations, Clean White Theme) */
        .modal-overlay {
          pointer-events: auto;
          position: fixed;
          top: -8px;
          left: 50%;
          transform: translateX(-50%);
          width: 100vw;
          height: 100vh;
          background: rgba(15, 23, 42, 0.45);
          backdrop-filter: blur(8px);
          -webkit-backdrop-filter: blur(8px);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 2147483647;
        }

        .modal-overlay.hidden {
          display: none;
        }

        .modal-dialog {
          background: #ffffff;
          border: 1px solid #e2e8f0;
          border-radius: 16px;
          padding: 24px 28px;
          max-width: 420px;
          width: 90%;
          text-align: center;
          box-shadow: 0 20px 45px rgba(15, 23, 42, 0.2), 0 0 0 1px rgba(0, 0, 0, 0.04);
          animation: modalIn 0.2s cubic-bezier(0.16, 1, 0.3, 1);
        }

        @keyframes modalIn {
          from { transform: scale(0.95); opacity: 0; }
          to { transform: scale(1); opacity: 1; }
        }

        .modal-icon-badge {
          width: 48px;
          height: 48px;
          margin: 0 auto 14px;
          background: #fffbeb;
          border: 1px solid #fde68a;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .modal-icon-badge svg {
          width: 24px;
          height: 24px;
          color: #d97706;
        }

        .modal-heading {
          font-size: 16px;
          font-weight: 700;
          color: #0f172a;
          margin-bottom: 8px;
          letter-spacing: -0.01em;
        }

        .modal-description {
          font-size: 12.5px;
          line-height: 1.5;
          color: #64748b;
          margin-bottom: 20px;
        }

        .modal-btn-row {
          display: flex;
          gap: 12px;
        }

        .modal-action-btn {
          all: unset;
          cursor: pointer;
          flex: 1;
          height: 38px;
          border-radius: 10px;
          font-size: 12.5px;
          font-weight: 600;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all 0.15s ease;
          box-sizing: border-box;
        }

        .modal-btn-stay {
          background: #f8fafc;
          border: 1px solid #e2e8f0;
          color: #334155;
        }

        .modal-btn-stay:hover {
          background: #f1f5f9;
          border-color: #cbd5e1;
        }

        .modal-btn-quit {
          background: #dc2626;
          border: 1px solid #ef4444;
          color: #ffffff;
        }

        .modal-btn-quit:hover {
          background: #b91c1c;
        }
      </style>

      <div class="dock">
        <!-- Brand / Version -->
        <div class="brand" title="Bluebirds Secure Browser">
          <span class="brand-badge">BB</span>
          <span class="brand-title">Secure</span>
          <span class="version-tag" id="dock-version">v1.2.1</span>
        </div>

        <div class="divider"></div>

        <!-- Latency / Wi-Fi (Clean symbol without ms text) -->
        <div class="stat-item" id="dock-wifi-stat" title="Network Connection">
          <svg class="icon wifi-green" id="dock-wifi-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M5 12.55a11 11 0 0 1 14.08 0"/>
            <path d="M1.42 9a16 16 0 0 1 21.16 0"/>
            <path d="M8.53 16.11a6 6 0 0 1 6.95 0"/>
            <line x1="12" y1="20" x2="12.01" y2="20"/>
          </svg>
        </div>

        <div class="divider"></div>

        <!-- Exam Remaining Time -->
        <div class="stat-item" id="dock-timer-stat" title="Exam Time Remaining">
          <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <polyline points="12 6 12 12 16 14"/>
          </svg>
          <span style="color:#64748b; font-size:10.5px; font-weight:600;">Remaining:</span>
          <span class="timer-val" id="dock-timer-val">--:--</span>
        </div>

        <div class="divider"></div>

        <!-- Battery -->
        <div class="stat-item" id="dock-battery-stat" title="Battery Level">
          <div class="battery-container">
            <svg class="battery-svg" viewBox="0 0 26 14" fill="none" xmlns="http://www.w3.org/2000/svg">
              <rect x="0.5" y="0.5" width="22" height="13" rx="2.5" stroke="currentColor" stroke-opacity="0.5"/>
              <path d="M24 5V9" stroke="currentColor" stroke-opacity="0.5" stroke-linecap="round"/>
              <rect id="dock-battery-bar" x="2" y="2" width="19" height="10" rx="1.5" fill="#10b981"/>
            </svg>
            <svg class="battery-bolt" id="dock-battery-bolt" viewBox="0 0 24 24" fill="currentColor">
              <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
            </svg>
          </div>
          <span class="mono" id="dock-battery-val" style="color:#334155; font-weight:600;">100%</span>
        </div>

        <div class="divider"></div>

        <!-- System Clock -->
        <div class="stat-item" title="Local System Clock">
          <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <polyline points="12 6 12 12 16 14"/>
          </svg>
          <span class="mono" id="dock-clock-val" style="color:#334155; font-weight:600;">--:--:--</span>
        </div>

        <div class="divider"></div>

        <!-- Exit Button -->
        <button class="exit-btn" id="dock-exit-btn" title="Exit Bluebirds Secure Browser">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
            <path d="M18.36 6.64a9 9 0 1 1-12.73 0"/>
            <line x1="12" y1="2" x2="12" y2="12"/>
          </svg>
          <span>Exit App</span>
        </button>
      </div>

      <!-- In-App Confirmation Modal (Lives in Shadow DOM so window NEVER loses focus) -->
      <div class="modal-overlay hidden" id="dock-modal-overlay">
        <div class="modal-dialog">
          <div class="modal-icon-badge">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
              <line x1="12" y1="9" x2="12" y2="13"/>
              <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
          </div>
          <div class="modal-heading">Are you sure you want to exit the examination?</div>
          <div class="modal-description">
            If you exit now, your assessment will remain in-progress and must be completed before the deadline. Do you wish to quit the application?
          </div>
          <div class="modal-btn-row">
            <button class="modal-action-btn modal-btn-stay" id="dock-modal-cancel">Return to Exam</button>
            <button class="modal-action-btn modal-btn-quit" id="dock-modal-confirm">Exit App</button>
          </div>
        </div>
      </div>
    `;

    // Clock updater
    const clockEl = shadow.getElementById('dock-clock-val');
    const updateClock = () => {
      if (clockEl) {
        clockEl.textContent = new Date().toLocaleTimeString([], {
          hour12: false,
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        });
      }
    };
    updateClock();
    setInterval(updateClock, 1000);

    // In-App Exit Modal Handler: Prevents OS window blur & false tab switch violations
    const exitBtn = shadow.getElementById('dock-exit-btn');
    const modal = shadow.getElementById('dock-modal-overlay');
    const cancelBtn = shadow.getElementById('dock-modal-cancel');
    const confirmBtn = shadow.getElementById('dock-modal-confirm');

    if (exitBtn && modal) {
      exitBtn.addEventListener('click', (e: any) => {
        e.stopPropagation();
        modal.classList.remove('hidden');
      });
    }

    if (cancelBtn && modal) {
      cancelBtn.addEventListener('click', (e: any) => {
        e.stopPropagation();
        modal.classList.add('hidden');
      });
    }

    if (confirmBtn) {
      confirmBtn.addEventListener('click', (e: any) => {
        e.stopPropagation();
        ipcRenderer.send('app-force-quit');
      });
    }
  };

  const updateDockUI = () => {
    const _doc: any = (globalThis as any).document;
    if (!_doc) return;
    const root = _doc.getElementById(ROOT_ID);
    if (!root || !root.shadowRoot) return;
    const shadow = root.shadowRoot;

    // Latency / Clean WiFi Color (Green / Amber / Red)
    const wifiIcon = shadow.getElementById('dock-wifi-icon');
    const wifiStat = shadow.getElementById('dock-wifi-stat');
    if (wifiIcon) {
      const ms = currentLatency;
      if (ms === null) {
        wifiIcon.className.baseVal = 'icon wifi-red';
        if (wifiStat) wifiStat.setAttribute('title', 'Network: Disconnected / Offline');
      } else {
        const tier = ms < 400 ? 'wifi-green' : ms < 999 ? 'wifi-amber' : 'wifi-red';
        wifiIcon.className.baseVal = `icon ${tier}`;
        if (wifiStat) {
          wifiStat.setAttribute('title', `Network: ${tier === 'wifi-green' ? 'Optimal' : tier === 'wifi-amber' ? 'Moderate' : 'High Latency'}`);
        }
      }
    }

    // Battery
    const batteryVal = shadow.getElementById('dock-battery-val');
    const batteryBar = shadow.getElementById('dock-battery-bar');
    const batteryBolt = shadow.getElementById('dock-battery-bolt');
    if (batteryVal && batteryBar && batteryBolt) {
      const pct = Math.min(100, Math.max(0, currentBatteryPercent));
      batteryVal.textContent = `${pct}%`;

      // Fill width max 19px
      const fillWidth = Math.round((pct / 100) * 19);
      batteryBar.setAttribute('width', String(Math.max(1, fillWidth)));

      // Color
      const fillColor = pct > 20 ? '#10b981' : '#ef4444';
      batteryBar.setAttribute('fill', fillColor);

      if (currentIsCharging) {
        batteryBolt.classList.add('active');
      } else {
        batteryBolt.classList.remove('active');
      }
    }

    // Version
    const versionEl = shadow.getElementById('dock-version');
    if (versionEl && currentAppVersion) {
      versionEl.textContent = currentAppVersion.startsWith('v') ? currentAppVersion : `v${currentAppVersion}`;
    }
  };

  const inject = () => {
    const _doc: any = (globalThis as any).document;
    if (!_doc) return;
    if (_doc.getElementById(ROOT_ID)) return;

    const host = _doc.body || _doc.documentElement;
    if (!host) {
      setTimeout(inject, 10);
      return;
    }

    const container = _doc.createElement('div');
    container.id = ROOT_ID;
    const shadow = container.attachShadow({ mode: 'open' });
    createDockDOM(shadow);
    host.appendChild(container);
    updateDockUI();
    console.log('[SecureBrowser Preload] SEB persistent bottom dock injected.');
  };

  const _doc: any = (globalThis as any).document;
  const _win: any = (globalThis as any).window;

  // Run on DOM events
  if (_doc && _doc.readyState === 'loading') {
    _doc.addEventListener('DOMContentLoaded', inject);
  } else {
    inject();
  }
  if (_win && typeof _win.addEventListener === 'function') {
    _win.addEventListener('load', inject);
  }

  // Health check: ensure dock stays in DOM across SPA route transitions
  setInterval(() => {
    const d: any = (globalThis as any).document;
    if (d && !d.getElementById(ROOT_ID) && (d.body || d.documentElement)) {
      inject();
    }
  }, 2000);

  // Renderer-level latency probe using active browser HTTP/2 session
  const isNavOnline = () => typeof navigator !== 'undefined' && Boolean((navigator as any).onLine);

  const probeRendererLatency = async () => {
    if (typeof navigator !== 'undefined' && !isNavOnline()) {
      currentLatency = null;
      updateDockUI();
      return;
    }

    const hostOrigin = (globalThis as any).window?.location?.origin;
    if (!hostOrigin || hostOrigin.startsWith('file:') || hostOrigin === 'null') {
      if (isNavOnline() && currentLatency === null) {
        currentLatency = 24;
        updateDockUI();
      }
      return;
    }

    const tStart = Date.now();
    try {
      const controller = new AbortController();
      const tid = setTimeout(() => controller.abort(), 3500);
      const res = await fetch(`${hostOrigin}/favicon.ico?_r=${tStart}`, {
        method: 'HEAD',
        cache: 'no-store',
        signal: controller.signal,
      } as any);
      clearTimeout(tid);
      if (res.ok || res.status > 0) {
        currentLatency = Math.max(1, Date.now() - tStart);
      }
    } catch {
      // If probe times out or fails but browser is online, maintain previous latency or nominal 30ms
      if (!isNavOnline()) {
        currentLatency = null;
      } else if (currentLatency === null) {
        currentLatency = 32;
      }
    }
    updateDockUI();
  };

  if (_win && typeof _win.addEventListener === 'function') {
    _win.addEventListener('online', () => {
      probeRendererLatency();
    });
    _win.addEventListener('offline', () => {
      currentLatency = null;
      updateDockUI();
    });
  }

  // Periodic latency refresh every 4 seconds in renderer
  setInterval(probeRendererLatency, 4000);
  setTimeout(probeRendererLatency, 800);

  // Listen for IPC updates from main process
  ipcRenderer.on('hud-status', (_e, data: { batteryPercent: number; isCharging: boolean; latencyMs: number | null; appVersion?: string }) => {
    if (data.batteryPercent !== undefined) currentBatteryPercent = data.batteryPercent;
    if (data.isCharging !== undefined) currentIsCharging = data.isCharging;
    if (data.latencyMs !== undefined) {
      // Only set to null if browser itself is genuinely offline
      if (data.latencyMs !== null || !isNavOnline()) {
        currentLatency = data.latencyMs;
      }
    }
    if (data.appVersion) currentAppVersion = data.appVersion;
    updateDockUI();
  });

  ipcRenderer.on('wifi-status', (_e, data: { ms: number | null }) => {
    if (data.ms !== undefined) {
      if (data.ms !== null || !isNavOnline()) {
        currentLatency = data.ms;
      }
      updateDockUI();
    }
  });
  /* eslint-enable @typescript-eslint/no-explicit-any */
}

try {
  initializeSebBottomDock();
} catch (e) {
  console.warn('[SecureBrowser Preload] Failed to initialize SEB dock:', e);
}
