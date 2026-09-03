import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db/prisma";
import {
  startLogin,
  setPassword,
  beginTotpEnrollment,
  confirmTotpEnrollment,
  beginSmsEnrollment,
  confirmSmsEnrollment,
  resendSmsEnrollmentCode,
  sendLoginSmsCode,
  verifyMfa,
  requestPasswordReset,
  completePasswordReset,
} from "../lib/authService";
import { signPendingLoginToken, verifyPendingLoginToken, signIdentityAssertion } from "../lib/tokens";

// JSON API for other apps (e.g. portal-app) to authenticate their users against the
// shared directory, guarded by requireInternalApiKey (mounted in app.ts). Every route
// here mirrors the browser flow in auth.routes.ts step-for-step, but the calling app
// owns its own UI and its own eventual session — this service only ever verifies
// credentials/MFA and hands back a short-lived identity assertion.
export const internalRouter = Router();

function requireLoginToken(token: unknown): string | null {
  if (typeof token !== "string") return null;
  return verifyPendingLoginToken(token)?.sub ?? null;
}

async function buildIdentityAssertion(userId: string) {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: userId }, include: { roles: { include: { application: true } } } });
  const roles: Record<string, string> = {};
  for (const r of user.roles) roles[r.application.key] = r.role;
  return {
    identityAssertion: signIdentityAssertion({ sub: user.id, email: user.email, name: user.name, roles }),
    user: { id: user.id, name: user.name, email: user.email, roles },
  };
}

const startSchema = z.object({ email: z.string().email(), password: z.string().min(1) });

internalRouter.post("/auth/start", async (req, res, next) => {
  try {
    const parsed = startSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ status: "invalid_request" });
      return;
    }
    const result = await startLogin(parsed.data.email, parsed.data.password, req);

    switch (result.outcome) {
      case "invalid_credentials":
        res.json({ status: "invalid_credentials" });
        return;
      case "inactive":
        res.json({ status: "invalid_credentials" }); // don't distinguish, mirrors browser flow
        return;
      case "locked":
        res.json({ status: "locked", lockedUntil: result.lockedUntil });
        return;
      case "password_change_required":
        res.json({ status: "password_change_required", loginToken: signPendingLoginToken(result.userId) });
        return;
      case "mfa_enrollment_required":
        res.json({ status: "mfa_enrollment_required", loginToken: signPendingLoginToken(result.userId) });
        return;
      case "mfa_required":
        res.json({ status: "mfa_required", loginToken: signPendingLoginToken(result.userId), availableMethods: result.availableMethods });
        return;
    }
  } catch (err) {
    next(err);
  }
});

const passwordChangeSchema = z.object({ loginToken: z.string(), password: z.string().min(12) });

internalRouter.post("/auth/password/change", async (req, res, next) => {
  try {
    const parsed = passwordChangeSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ status: "invalid_request" });
      return;
    }
    const userId = requireLoginToken(parsed.data.loginToken);
    if (!userId) {
      res.status(400).json({ status: "invalid_or_expired_login_token" });
      return;
    }
    await setPassword(userId, parsed.data.password);
    res.json({ status: "ok", loginToken: signPendingLoginToken(userId) });
  } catch (err) {
    next(err);
  }
});

internalRouter.post("/auth/mfa-setup/totp/begin", async (req, res, next) => {
  try {
    const userId = requireLoginToken(req.body.loginToken);
    if (!userId) {
      res.status(400).json({ status: "invalid_or_expired_login_token" });
      return;
    }
    const { secret, qrCodeDataUrl } = await beginTotpEnrollment(userId);
    res.json({ status: "ok", secret, qrCodeDataUrl });
  } catch (err) {
    next(err);
  }
});

internalRouter.post("/auth/mfa-setup/totp/confirm", async (req, res, next) => {
  try {
    const userId = requireLoginToken(req.body.loginToken);
    const code = String(req.body.code ?? "");
    if (!userId) {
      res.status(400).json({ status: "invalid_or_expired_login_token" });
      return;
    }
    const ok = await confirmTotpEnrollment(userId, code, req);
    if (!ok) {
      res.json({ status: "invalid_code" });
      return;
    }
    const { identityAssertion, user } = await buildIdentityAssertion(userId);
    res.json({ status: "ok", identityAssertion, user });
  } catch (err) {
    next(err);
  }
});

internalRouter.post("/auth/mfa-setup/sms/begin", async (req, res, next) => {
  try {
    const userId = requireLoginToken(req.body.loginToken);
    const phoneNumber = String(req.body.phoneNumber ?? "");
    if (!userId || phoneNumber.length < 8) {
      res.status(400).json({ status: "invalid_request" });
      return;
    }
    await beginSmsEnrollment(userId, phoneNumber);
    res.json({ status: "ok" });
  } catch (err) {
    next(err);
  }
});

internalRouter.post("/auth/mfa-setup/sms/resend", async (req, res, next) => {
  try {
    const userId = requireLoginToken(req.body.loginToken);
    if (!userId) {
      res.status(400).json({ status: "invalid_or_expired_login_token" });
      return;
    }
    await resendSmsEnrollmentCode(userId);
    res.json({ status: "ok" });
  } catch (err) {
    next(err);
  }
});

internalRouter.post("/auth/mfa-setup/sms/confirm", async (req, res, next) => {
  try {
    const userId = requireLoginToken(req.body.loginToken);
    const code = String(req.body.code ?? "");
    if (!userId) {
      res.status(400).json({ status: "invalid_or_expired_login_token" });
      return;
    }
    const ok = await confirmSmsEnrollment(userId, code, req);
    if (!ok) {
      res.json({ status: "invalid_code" });
      return;
    }
    const { identityAssertion, user } = await buildIdentityAssertion(userId);
    res.json({ status: "ok", identityAssertion, user });
  } catch (err) {
    next(err);
  }
});

internalRouter.post("/auth/mfa/send-sms", async (req, res, next) => {
  try {
    const userId = requireLoginToken(req.body.loginToken);
    if (!userId) {
      res.status(400).json({ status: "invalid_or_expired_login_token" });
      return;
    }
    await sendLoginSmsCode(userId);
    res.json({ status: "ok" });
  } catch (err) {
    next(err);
  }
});

internalRouter.post("/auth/mfa/verify", async (req, res, next) => {
  try {
    const userId = requireLoginToken(req.body.loginToken);
    const method = req.body.method === "SMS" ? "SMS" : "TOTP";
    const code = String(req.body.code ?? "");
    if (!userId) {
      res.status(400).json({ status: "invalid_or_expired_login_token" });
      return;
    }
    const result = await verifyMfa(userId, method, code, req);
    if (!result.ok) {
      res.json({ status: result.reason === "locked" ? "locked" : "invalid_code" });
      return;
    }
    const { identityAssertion, user } = await buildIdentityAssertion(userId);
    res.json({ status: "ok", identityAssertion, user });
  } catch (err) {
    next(err);
  }
});

internalRouter.post("/auth/password/forgot", async (req, res, next) => {
  try {
    const email = String(req.body.email ?? "");
    const applicationKey = typeof req.body.applicationKey === "string" ? req.body.applicationKey : undefined;
    if (email) await requestPasswordReset(email, req, applicationKey);
    res.json({ status: "ok" });
  } catch (err) {
    next(err);
  }
});

internalRouter.post("/auth/password/reset", async (req, res, next) => {
  try {
    const token = String(req.body.token ?? "");
    const password = String(req.body.password ?? "");
    if (!token || password.length < 12) {
      res.status(400).json({ status: "invalid_request" });
      return;
    }
    const outcome = await completePasswordReset(token, password, req);
    res.json({ status: outcome });
  } catch (err) {
    next(err);
  }
});

// Lets a calling app sync/display the set of users holding a role in its application
// (e.g. portal-app populating an "assign to investor" picker).
internalRouter.get("/applications/:key/users", async (req, res) => {
  const application = await prisma.application.findUnique({ where: { key: req.params.key } });
  if (!application) {
    res.status(404).json({ status: "unknown_application" });
    return;
  }
  const roles = await prisma.userApplicationRole.findMany({
    where: { applicationId: application.id },
    include: { user: true },
  });
  res.json({
    status: "ok",
    users: roles
      .filter((r) => r.user.isActive)
      .map((r) => ({ id: r.user.id, name: r.user.name, email: r.user.email, role: r.role })),
  });
});
