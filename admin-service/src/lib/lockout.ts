const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000;

export function isLocked(lockedUntil: Date | null): boolean {
  return lockedUntil !== null && lockedUntil.getTime() > Date.now();
}

export function nextLockoutState(failedLoginAttempts: number): {
  failedLoginAttempts: number;
  lockedUntil: Date | null;
} {
  const attempts = failedLoginAttempts + 1;
  if (attempts >= MAX_FAILED_ATTEMPTS) {
    return { failedLoginAttempts: attempts, lockedUntil: new Date(Date.now() + LOCKOUT_DURATION_MS) };
  }
  return { failedLoginAttempts: attempts, lockedUntil: null };
}

export const LOCKOUT_CONFIG = { MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION_MS };
