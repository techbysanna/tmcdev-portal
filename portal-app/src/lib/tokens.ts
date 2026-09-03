import jwt from "jsonwebtoken";
import { env } from "../config/env";

const SESSION_COOKIE_TTL_SECONDS = 30 * 60; // 30 min inactivity timeout, per requirements doc

export interface PortalSessionClaims {
  purpose: "portal_session";
  sub: string; // PortalUser id (== admin-service user id)
  email: string;
  name: string;
  role: string;
}

export function signPortalSessionToken(claims: Omit<PortalSessionClaims, "purpose">): string {
  return jwt.sign({ ...claims, purpose: "portal_session" }, env.SESSION_SECRET, {
    expiresIn: SESSION_COOKIE_TTL_SECONDS,
  });
}

export function verifyPortalSessionToken(token: string): PortalSessionClaims | null {
  try {
    const decoded = jwt.verify(token, env.SESSION_SECRET) as PortalSessionClaims;
    if (decoded.purpose !== "portal_session") return null;
    return decoded;
  } catch {
    return null;
  }
}

// Verifies the identity assertion admin-service hands back after a successful
// password+MFA login. ADMIN_SERVICE_JWT_SECRET must match admin-service's
// INTERNAL_JWT_SECRET exactly (shared out of band, not over the network).
export interface IdentityAssertionClaims {
  purpose: "identity_assertion";
  sub: string;
  email: string;
  name: string;
  roles: Record<string, string>;
}

export function verifyIdentityAssertion(token: string): IdentityAssertionClaims | null {
  try {
    const decoded = jwt.verify(token, env.ADMIN_SERVICE_JWT_SECRET) as IdentityAssertionClaims;
    if (decoded.purpose !== "identity_assertion") return null;
    return decoded;
  } catch {
    return null;
  }
}
