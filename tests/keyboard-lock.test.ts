/**
 * Unit tests: stopWindowsKeyboardLock process-kill behaviour
 *
 * We mock Node's child_process.exec and the ChildProcess object to verify that:
 * 1. keyboardLockChild.kill() is called
 * 2. taskkill /F /T /PID <pid> is called to kill the entire process tree
 * 3. The belt-and-suspenders powershell cleanup command is issued
 * 4. keyboardLockChild is set to null afterwards
 *
 * These tests run in Node (not Electron) so we cannot import main.ts directly.
 * Instead we replicate stopWindowsKeyboardLock() exactly as it is written in
 * src/main.ts to validate the new logic without booting Electron.
 */

import { exec } from 'child_process';
import { EventEmitter } from 'events';

// ─── Replicated logic ──────────────────────────────────────────────────────────

// Mimic the keyboardLockChild module-level variable
type MockChild = EventEmitter & {
  pid: number | undefined;
  kill: jest.Mock;
};

let execCalls: string[] = [];

// Replacement for exec that records calls instead of executing them
function mockExec(cmd: string, _cb?: Function): any {
  execCalls.push(cmd);
}

function stopWindowsKeyboardLock(
  keyboardLockChildRef: { value: MockChild | null },
  platform: string = 'win32'
): void {
  if (platform !== 'win32') return;

  mockExec(
    'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoWinKeys /f'
  );

  if (keyboardLockChildRef.value) {
    const pid = keyboardLockChildRef.value.pid;
    try {
      keyboardLockChildRef.value.kill();
    } catch {}
    keyboardLockChildRef.value = null;

    if (pid !== undefined) {
      mockExec(`taskkill /F /T /PID ${pid} 2>nul`);
    }
  }

  mockExec(
    'powershell -NoProfile -NonInteractive -Command "Get-Process powershell -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like \'*keyboard-lock*\' -or $_.CommandLine -like \'*bb-keyboard-lock*\' } | Stop-Process -Force -ErrorAction SilentlyContinue" 2>nul'
  );
}

// ─── Tests ────────────────────────────────────────────────────────────────────

function makeMockChild(pid: number): MockChild {
  const child = new EventEmitter() as MockChild;
  child.pid = pid;
  child.kill = jest.fn();
  return child;
}

beforeEach(() => {
  execCalls = [];
});

describe('stopWindowsKeyboardLock', () => {
  test('calls child.kill() and sets ref to null', () => {
    const child = makeMockChild(12345);
    const ref = { value: child as MockChild | null };

    stopWindowsKeyboardLock(ref);

    expect(child.kill).toHaveBeenCalledTimes(1);
    expect(ref.value).toBeNull();
  });

  test('issues taskkill /F /T /PID with the child PID', () => {
    const child = makeMockChild(9999);
    const ref = { value: child as MockChild | null };

    stopWindowsKeyboardLock(ref);

    const taskkillCmd = execCalls.find((c) => c.includes('taskkill'));
    expect(taskkillCmd).toBeDefined();
    expect(taskkillCmd).toMatch(/taskkill \/F \/T \/PID 9999/);
  });

  test('issues the belt-and-suspenders powershell cleanup command', () => {
    const child = makeMockChild(1111);
    const ref = { value: child as MockChild | null };

    stopWindowsKeyboardLock(ref);

    const psCmd = execCalls.find((c) => c.includes('Get-Process powershell'));
    expect(psCmd).toBeDefined();
    expect(psCmd).toMatch(/keyboard-lock/);
  });

  test('does NOT issue taskkill if child has no PID', () => {
    const child = makeMockChild(undefined as unknown as number);
    child.pid = undefined;
    const ref = { value: child as MockChild | null };

    stopWindowsKeyboardLock(ref);

    const taskkillCmd = execCalls.find((c) => c.includes('taskkill'));
    expect(taskkillCmd).toBeUndefined();
  });

  test('does nothing when keyboardLockChild is null (idempotent)', () => {
    const ref: { value: MockChild | null } = { value: null };

    stopWindowsKeyboardLock(ref);

    // Registry delete and belt-and-suspenders still run; taskkill does not
    const taskkillCmd = execCalls.find((c) => c.includes('taskkill'));
    expect(taskkillCmd).toBeUndefined();
    expect(ref.value).toBeNull();
  });

  test('is a no-op on non-Windows platforms', () => {
    const child = makeMockChild(5555);
    const ref = { value: child as MockChild | null };

    stopWindowsKeyboardLock(ref, 'darwin');

    expect(child.kill).not.toHaveBeenCalled();
    expect(ref.value).not.toBeNull(); // ref unchanged
    expect(execCalls).toHaveLength(0);
  });
});
