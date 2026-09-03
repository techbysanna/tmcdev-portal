import { describe, expect, it } from "vitest";
import { isLocked, nextLockoutState, LOCKOUT_CONFIG } from "../src/lib/lockout";

describe("lockout", () => {
  it("does not lock before the max attempt threshold", () => {
    let state = { failedLoginAttempts: 0, lockedUntil: null as Date | null };
    for (let i = 0; i < LOCKOUT_CONFIG.MAX_FAILED_ATTEMPTS - 1; i++) {
      state = nextLockoutState(state.failedLoginAttempts);
      expect(state.lockedUntil).toBeNull();
    }
  });

  it("locks once attempts reach the threshold", () => {
    const state = nextLockoutState(LOCKOUT_CONFIG.MAX_FAILED_ATTEMPTS - 1);
    expect(state.failedLoginAttempts).toBe(LOCKOUT_CONFIG.MAX_FAILED_ATTEMPTS);
    expect(state.lockedUntil).not.toBeNull();
    expect(isLocked(state.lockedUntil)).toBe(true);
  });

  it("treats a past lockedUntil as not locked", () => {
    expect(isLocked(new Date(Date.now() - 1000))).toBe(false);
  });

  it("treats null as not locked", () => {
    expect(isLocked(null)).toBe(false);
  });
});
