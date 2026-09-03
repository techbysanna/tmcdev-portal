import jwt from "jsonwebtoken";
import { env } from "../config/env";

const SESSION_COOKIE_TTL_SECONDS = 30 * 60; // 30 min inactivity timeout, matches doc
const MFA_CHALLENGE_TTL_SECONDS = 5 * 60;
const IDENTITY_ASSERTION_TTL_SECONDS = 5 * 60;

export interface AdminSessionClaims {
  purpose: "admin_ui_session";
  sub: string; // userId
  email: string;
  name: string;
}

export function signAdminSessionToken(claims: Omit<AdminSessionClaims, "purpose">): string {
  return jwt.sign({ ...claims, purpose: "admin_ui_session" }, env.SESSION_SECRET, {
    expiresIn: SESSION_COOKIE_TTL_SECONDS,
  });
}

export function verifyAdminSessionToken(token: string): AdminSessionClaims | null {
  try {
    const decoded = jwt.verify(token, env.SESSION_SECRET) as AdminSessionClaims;
    if (decoded.purpose !== "admin_ui_session") return null;
    return decoded;
  } catch {
    return null;
  }
}

export interface MfaChallengeClaims {
  purpose: "mfa_challenge";
  sub: string; // userId
  challengeId: string;
}

export function signMfaChallengeToken(claims: Omit<MfaChallengeClaims, "purpose">): string {
  return jwt.sign({ ...claims, purpose: "mfa_challenge" }, env.SESSION_SECRET, {
    expiresIn: MFA_CHALLENGE_TTL_SECONDS,
  });
}

export function verifyMfaChallengeToken(token: string): MfaChallengeClaims | null {
  try {
    const decoded = jwt.verify(token, env.SESSION_SECRET) as MfaChallengeClaims;
    if (decoded.purpose !== "mfa_challenge") return null;
    return decoded;
  } catch {
    return null;
  }
}

const PENDING_LOGIN_TTL_SECONDS = 10 * 60;

export interface PendingLoginClaims {
  purpose: "pending_login";
  sub: string; // userId
}

export function signPendingLoginToken(userId: string): string {
  return jwt.sign({ sub: userId, purpose: "pending_login" }, env.SESSION_SECRET, {
    expiresIn: PENDING_LOGIN_TTL_SECONDS,
  });
}

export function verifyPendingLoginToken(token: string): PendingLoginClaims | null {
  try {
    const decoded = jwt.verify(token, env.SESSION_SECRET) as PendingLoginClaims;
    if (decoded.purpose !== "pending_login") return null;
    return decoded;
  } catch {
    return null;
  }
}

// Handed back to calling apps (e.g. portal-app) after a successful password+MFA
// verification via POST /internal/authenticate. Deliberately short-lived: the
// calling app is expected to mint and own its own longer-lived session on top of
// this, per the "separate login per app, shared directory only" decision.
export interface IdentityAssertionClaims {
  purpose: "identity_assertion";
  sub: string; // userId
  email: string;
  name: string;
  roles: Record<string, string>; // applicationKey -> role
}

export function signIdentityAssertion(claims: Omit<IdentityAssertionClaims, "purpose">): string {
  return jwt.sign({ ...claims, purpose: "identity_assertion" }, env.INTERNAL_JWT_SECRET, {
    expiresIn: IDENTITY_ASSERTION_TTL_SECONDS,
  });
}
