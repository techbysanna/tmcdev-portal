import { env } from "../config/env";

// Thin client for admin-service's /internal/* API. Every call carries the shared
// service-to-service API key — never anything a browser could see. This module is
// the only place in portal-app that talks to admin-service.

async function callInternalApi<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${env.ADMIN_SERVICE_URL}/internal${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-internal-api-key": env.ADMIN_SERVICE_INTERNAL_API_KEY,
    },
    body: JSON.stringify(body),
  });

  if (!res.ok && res.status !== 400) {
    throw new Error(`admin-service internal API error: ${path} returned ${res.status}`);
  }

  return (await res.json()) as T;
}

export type StartLoginResponse =
  | { status: "invalid_credentials" }
  | { status: "locked"; lockedUntil: string }
  | { status: "password_change_required"; loginToken: string }
  | { status: "mfa_enrollment_required"; loginToken: string }
  | { status: "mfa_required"; loginToken: string; availableMethods: Array<"TOTP" | "SMS"> };

export function startLogin(email: string, password: string): Promise<StartLoginResponse> {
  return callInternalApi("/auth/start", { email, password });
}

export function changePassword(loginToken: string, password: string): Promise<{ status: "ok"; loginToken: string } | { status: string }> {
  return callInternalApi("/auth/password/change", { loginToken, password });
}

export function beginTotpEnrollment(loginToken: string): Promise<{ status: "ok"; secret: string; qrCodeDataUrl: string }> {
  return callInternalApi("/auth/mfa-setup/totp/begin", { loginToken });
}

export interface IdentityResult {
  status: "ok";
  identityAssertion: string;
  user: { id: string; name: string; email: string; roles: Record<string, string> };
}
export type CodeVerifyResponse = IdentityResult | { status: "invalid_code" | "locked" | "invalid_or_expired_login_token" };

export function confirmTotpEnrollment(loginToken: string, code: string): Promise<CodeVerifyResponse> {
  return callInternalApi("/auth/mfa-setup/totp/confirm", { loginToken, code });
}

export function beginSmsEnrollment(loginToken: string, phoneNumber: string): Promise<{ status: string }> {
  return callInternalApi("/auth/mfa-setup/sms/begin", { loginToken, phoneNumber });
}

export function resendSmsEnrollmentCode(loginToken: string): Promise<{ status: string }> {
  return callInternalApi("/auth/mfa-setup/sms/resend", { loginToken });
}

export function confirmSmsEnrollment(loginToken: string, code: string): Promise<CodeVerifyResponse> {
  return callInternalApi("/auth/mfa-setup/sms/confirm", { loginToken, code });
}

export function sendMfaSms(loginToken: string): Promise<{ status: string }> {
  return callInternalApi("/auth/mfa/send-sms", { loginToken });
}

export function verifyMfa(loginToken: string, method: "TOTP" | "SMS", code: string): Promise<CodeVerifyResponse> {
  return callInternalApi("/auth/mfa/verify", { loginToken, method, code });
}

export function requestPasswordReset(email: string): Promise<{ status: "ok" }> {
  return callInternalApi("/auth/password/forgot", { email, applicationKey: "investor-portal" });
}

export function completePasswordReset(token: string, password: string): Promise<{ status: "ok" | "invalid_or_expired" }> {
  return callInternalApi("/auth/password/reset", { token, password });
}
