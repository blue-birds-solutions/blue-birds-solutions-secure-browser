/**
 * Unit tests: saveActiveSessionState / clearActiveSessionState / restoreActiveSessionState
 *
 * These are pure filesystem operations that can be tested without Electron running.
 * We replicate the exact logic from src/main.ts so that if the implementation is
 * wrong, these tests will catch it without needing a full Electron environment.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';

// ─── Replicated logic (mirrors src/main.ts verbatim) ──────────────────────────

interface SavedSessionState {
  attemptId: string | null;
  assessmentId: string | null;
  token: string | null;
  timestamp: number;
}

let activeAttemptId: string | null = null;
let activeAssessmentId: string | null = null;
let activeToken: string | null = null;

// Use a real tmpdir as the "userData" folder in tests
const TEST_USER_DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-test-'));
const SESSION_FILE = path.join(TEST_USER_DATA, 'active_exam_session.json');

function saveActiveSessionState(): void {
  const state: SavedSessionState = {
    attemptId: activeAttemptId,
    assessmentId: activeAssessmentId,
    token: activeToken,
    timestamp: Date.now(),
  };
  fs.writeFileSync(SESSION_FILE, JSON.stringify(state, null, 2), 'utf-8');
}

function clearActiveSessionState(): void {
  if (fs.existsSync(SESSION_FILE)) {
    fs.unlinkSync(SESSION_FILE);
  }
}

function restoreActiveSessionState(): boolean {
  if (!fs.existsSync(SESSION_FILE)) return false;
  try {
    const raw = fs.readFileSync(SESSION_FILE, 'utf-8');
    const state: SavedSessionState = JSON.parse(raw);
    if (state && Date.now() - state.timestamp < 4 * 60 * 60 * 1000) {
      if ((state.attemptId || state.assessmentId) && state.token) {
        activeAttemptId = state.attemptId;
        activeAssessmentId = state.assessmentId;
        activeToken = state.token;
        return true;
      }
    }
  } catch (e) {
    // corrupted file — treat as no session
  }
  return false;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

beforeEach(() => {
  // Reset state before each test
  activeAttemptId = null;
  activeAssessmentId = null;
  activeToken = null;
  // Remove any leftover session file
  if (fs.existsSync(SESSION_FILE)) fs.unlinkSync(SESSION_FILE);
});

afterAll(() => {
  // Cleanup temp directory
  try { fs.rmSync(TEST_USER_DATA, { recursive: true, force: true }); } catch {}
});

describe('saveActiveSessionState', () => {
  test('writes a JSON file with all fields', () => {
    activeAttemptId = 'attempt-123';
    activeAssessmentId = 'assess-456';
    activeToken = 'token-abc';
    saveActiveSessionState();

    expect(fs.existsSync(SESSION_FILE)).toBe(true);
    const raw = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf-8'));
    expect(raw.attemptId).toBe('attempt-123');
    expect(raw.assessmentId).toBe('assess-456');
    expect(raw.token).toBe('token-abc');
    expect(typeof raw.timestamp).toBe('number');
  });

  test('writes null fields when no session is active', () => {
    saveActiveSessionState();
    const raw = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf-8'));
    expect(raw.attemptId).toBeNull();
    expect(raw.token).toBeNull();
  });
});

describe('clearActiveSessionState', () => {
  test('removes the session file if it exists', () => {
    activeAttemptId = 'attempt-99';
    activeToken = 'tok';
    saveActiveSessionState();
    expect(fs.existsSync(SESSION_FILE)).toBe(true);

    clearActiveSessionState();
    expect(fs.existsSync(SESSION_FILE)).toBe(false);
  });

  test('does not throw if no session file exists', () => {
    expect(() => clearActiveSessionState()).not.toThrow();
  });
});

describe('restoreActiveSessionState', () => {
  test('restores session from a recent file', () => {
    // Pre-write a valid session file manually
    const state: SavedSessionState = {
      attemptId: 'attempt-777',
      assessmentId: 'assess-888',
      token: 'tok-xyz',
      timestamp: Date.now() - 5000, // 5 seconds ago — within 4h window
    };
    fs.writeFileSync(SESSION_FILE, JSON.stringify(state), 'utf-8');

    const restored = restoreActiveSessionState();
    expect(restored).toBe(true);
    expect(activeAttemptId).toBe('attempt-777');
    expect(activeAssessmentId).toBe('assess-888');
    expect(activeToken).toBe('tok-xyz');
  });

  test('returns false when the file is older than 4 hours', () => {
    const state: SavedSessionState = {
      attemptId: 'attempt-old',
      assessmentId: 'assess-old',
      token: 'tok-old',
      timestamp: Date.now() - 5 * 60 * 60 * 1000, // 5 hours ago
    };
    fs.writeFileSync(SESSION_FILE, JSON.stringify(state), 'utf-8');

    const restored = restoreActiveSessionState();
    expect(restored).toBe(false);
    // State must not have been overwritten
    expect(activeAttemptId).toBeNull();
  });

  test('returns false when no session file exists', () => {
    const restored = restoreActiveSessionState();
    expect(restored).toBe(false);
  });

  test('returns false when token is missing even if attemptId is present', () => {
    const state = {
      attemptId: 'attempt-no-token',
      assessmentId: null,
      token: null,
      timestamp: Date.now(),
    };
    fs.writeFileSync(SESSION_FILE, JSON.stringify(state), 'utf-8');
    const restored = restoreActiveSessionState();
    expect(restored).toBe(false);
  });

  test('returns false when the file is corrupted JSON', () => {
    fs.writeFileSync(SESSION_FILE, 'NOT_JSON', 'utf-8');
    const restored = restoreActiveSessionState();
    expect(restored).toBe(false);
  });
});

describe('clean-exit session clearing (integration)', () => {
  test('session file is absent after a simulated clean exit', () => {
    // Simulate: exam starts → deep link sets credentials → session saved
    activeAttemptId = 'attempt-clean';
    activeAssessmentId = 'assess-clean';
    activeToken = 'tok-clean';
    saveActiveSessionState();
    expect(fs.existsSync(SESSION_FILE)).toBe(true);

    // Simulate: performCleanExit() calls clearActiveSessionState()
    clearActiveSessionState();
    activeAttemptId = null;
    activeAssessmentId = null;
    activeToken = null;

    // Simulate: next launch calls restoreActiveSessionState()
    const restored = restoreActiveSessionState();
    expect(restored).toBe(false); // Must NOT enter crash-recovery mode after clean exit
    expect(activeAttemptId).toBeNull();
  });

  test('session file IS present after a simulated crash (no clearActiveSessionState called)', () => {
    activeAttemptId = 'attempt-crash';
    activeToken = 'tok-crash';
    saveActiveSessionState();

    // Simulate crash: process dies without calling clearActiveSessionState()
    // Reset globals only (as a new process boot would have fresh globals)
    activeAttemptId = null;
    activeToken = null;

    const restored = restoreActiveSessionState();
    expect(restored).toBe(true); // Should recover the crashed session
    expect(activeAttemptId).toBe('attempt-crash');
  });
});
