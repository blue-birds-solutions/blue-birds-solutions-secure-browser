/**
 * Integration tests: Quit → Re-launch lifecycle
 *
 * These tests simulate the full sequence a real user experiences:
 *
 * Scenario A: Normal quit → re-launch (the bug that was fixed)
 *   1. App starts, deep link arrives, session is saved.
 *   2. User quits from tray/taskbar — performCleanExit() fires.
 *   3. On next launch, restoreActiveSessionState() returns false (no stale session).
 *   4. App starts cleanly without false crash-recovery.
 *
 * Scenario B: Crash → re-launch (should be detected and recovered)
 *   1. App starts, deep link arrives, session is saved.
 *   2. Process is killed hard (no performCleanExit).
 *   3. On next launch, restoreActiveSessionState() returns true and restores creds.
 *
 * Scenario C: Double-quit is safe
 *   1. clearActiveSessionState() called twice does not throw.
 *
 * Scenario D: Session older than 4 hours is not restored
 *   1. Crash-recovery file exists but is stale (> 4h).
 *   2. restoreActiveSessionState() returns false.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';

// ─── Replicated session-state helpers ─────────────────────────────────────────

interface SavedSessionState {
  attemptId: string | null;
  assessmentId: string | null;
  token: string | null;
  timestamp: number;
}

const HOUR_MS = 60 * 60 * 1000;
const SESSION_TTL_MS = 4 * HOUR_MS;

class AppState {
  activeAttemptId: string | null = null;
  activeAssessmentId: string | null = null;
  activeToken: string | null = null;
  isInitialized: boolean = false;
  wasOpenedViaDeepLink: boolean = false;

  constructor(private sessionFile: string) {}

  saveActiveSessionState(): void {
    const state: SavedSessionState = {
      attemptId: this.activeAttemptId,
      assessmentId: this.activeAssessmentId,
      token: this.activeToken,
      timestamp: Date.now(),
    };
    fs.writeFileSync(this.sessionFile, JSON.stringify(state, null, 2), 'utf-8');
  }

  clearActiveSessionState(): void {
    if (fs.existsSync(this.sessionFile)) {
      fs.unlinkSync(this.sessionFile);
    }
  }

  restoreActiveSessionState(): boolean {
    if (!fs.existsSync(this.sessionFile)) return false;
    try {
      const raw = fs.readFileSync(this.sessionFile, 'utf-8');
      const state: SavedSessionState = JSON.parse(raw);
      if (state && Date.now() - state.timestamp < SESSION_TTL_MS) {
        if ((state.attemptId || state.assessmentId) && state.token) {
          this.activeAttemptId = state.attemptId;
          this.activeAssessmentId = state.assessmentId;
          this.activeToken = state.token;
          return true;
        }
      }
    } catch {}
    return false;
  }

  /** Simulates performCleanExit() as implemented after the fix */
  performCleanExit(): void {
    this.clearActiveSessionState();
    this.activeAttemptId = null;
    this.activeAssessmentId = null;
    this.activeToken = null;
    this.isInitialized = false;
    this.wasOpenedViaDeepLink = false;
  }
}

// ─── Test fixture factory ──────────────────────────────────────────────────────

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-lifecycle-'));
const SESSION_FILE = path.join(tmpDir, 'active_exam_session.json');

function freshState(): AppState {
  // Remove session file between tests
  if (fs.existsSync(SESSION_FILE)) fs.unlinkSync(SESSION_FILE);
  return new AppState(SESSION_FILE);
}

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
});

// ─── Scenario A: Normal quit → re-launch ─────────────────────────────────────

describe('Scenario A: Normal quit does NOT leave stale session', () => {
  test('session file is absent after performCleanExit', () => {
    const state = freshState();
    // Simulate exam launch via deep link
    state.activeAttemptId = 'attempt-A';
    state.activeToken = 'tok-A';
    state.isInitialized = true;
    state.saveActiveSessionState();

    expect(fs.existsSync(SESSION_FILE)).toBe(true);

    // User clicks Quit
    state.performCleanExit();

    expect(fs.existsSync(SESSION_FILE)).toBe(false);
  });

  test('next launch does NOT enter crash-recovery after normal quit', () => {
    const state1 = freshState();
    state1.activeAttemptId = 'attempt-A2';
    state1.activeToken = 'tok-A2';
    state1.saveActiveSessionState();
    state1.performCleanExit(); // clean quit

    // New process boot — fresh state object (simulates Electron restart)
    const state2 = new AppState(SESSION_FILE);
    const recovered = state2.restoreActiveSessionState();

    expect(recovered).toBe(false);
    expect(state2.activeAttemptId).toBeNull();
  });

  test('state variables are reset to null by performCleanExit', () => {
    const state = freshState();
    state.activeAttemptId = 'attempt-A3';
    state.activeToken = 'tok-A3';
    state.isInitialized = true;
    state.wasOpenedViaDeepLink = true;

    state.performCleanExit();

    expect(state.activeAttemptId).toBeNull();
    expect(state.activeToken).toBeNull();
    expect(state.isInitialized).toBe(false);
    expect(state.wasOpenedViaDeepLink).toBe(false);
  });
});

// ─── Scenario B: Crash → re-launch ───────────────────────────────────────────

describe('Scenario B: Crash leaves session file, next launch recovers it', () => {
  test('session file persists after hard crash (no performCleanExit)', () => {
    const state = freshState();
    state.activeAttemptId = 'attempt-B';
    state.activeToken = 'tok-B';
    state.saveActiveSessionState();
    // Simulate hard crash: no performCleanExit(), process just dies
    // state goes out of scope; file remains on disk

    const state2 = new AppState(SESSION_FILE);
    const recovered = state2.restoreActiveSessionState();

    expect(recovered).toBe(true);
    expect(state2.activeAttemptId).toBe('attempt-B');
    expect(state2.activeToken).toBe('tok-B');
  });
});

// ─── Scenario C: Double-quit is safe ─────────────────────────────────────────

describe('Scenario C: Calling clearActiveSessionState twice is idempotent', () => {
  test('does not throw on second call', () => {
    const state = freshState();
    state.activeAttemptId = 'attempt-C';
    state.activeToken = 'tok-C';
    state.saveActiveSessionState();

    expect(() => {
      state.clearActiveSessionState();
      state.clearActiveSessionState(); // second call — file already gone
    }).not.toThrow();
  });
});

// ─── Scenario D: Stale session (>4h) is ignored ──────────────────────────────

describe('Scenario D: Stale crash-recovery file (>4h) is not restored', () => {
  test('returns false for session older than 4 hours', () => {
    const staleState: SavedSessionState = {
      attemptId: 'attempt-D',
      assessmentId: null,
      token: 'tok-D',
      timestamp: Date.now() - (SESSION_TTL_MS + 60_000), // 4h + 1min ago
    };
    fs.writeFileSync(SESSION_FILE, JSON.stringify(staleState), 'utf-8');

    const state = new AppState(SESSION_FILE);
    const recovered = state.restoreActiveSessionState();

    expect(recovered).toBe(false);
    expect(state.activeAttemptId).toBeNull();
  });

  test('session exactly at the TTL boundary is not restored (exclusive boundary)', () => {
    const staleState: SavedSessionState = {
      attemptId: 'attempt-D2',
      assessmentId: null,
      token: 'tok-D2',
      timestamp: Date.now() - SESSION_TTL_MS, // exactly 4h
    };
    fs.writeFileSync(SESSION_FILE, JSON.stringify(staleState), 'utf-8');

    const state = new AppState(SESSION_FILE);
    // Date.now() - timestamp === SESSION_TTL_MS → NOT < SESSION_TTL_MS → false
    const recovered = state.restoreActiveSessionState();
    expect(recovered).toBe(false);
  });

  test('session just within the 4-hour window IS restored', () => {
    const state = freshState();
    // Manually write a file that is 1 minute shy of the TTL
    const recentState: SavedSessionState = {
      attemptId: 'attempt-D3',
      assessmentId: null,
      token: 'tok-D3',
      timestamp: Date.now() - (SESSION_TTL_MS - 60_000), // 3h59m ago
    };
    fs.writeFileSync(SESSION_FILE, JSON.stringify(recentState), 'utf-8');

    const recovered = state.restoreActiveSessionState();
    expect(recovered).toBe(true);
    expect(state.activeAttemptId).toBe('attempt-D3');
  });
});
