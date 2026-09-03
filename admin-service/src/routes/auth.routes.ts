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
import { signPendingLoginToken, verifyPendingLoginToken, signAdminSessionToken } from "../lib/tokens";
import { decryptSecret } from "../lib/crypto";
import { buildProvisioningQrCodeDataUrl } from "../lib/totp";
import { canAccessAdminUi } from "../lib/permissions";
import { SESSION_COOKIE_NAME, SESSION_COOKIE_OPTIONS } from "../middleware/requireAdminSession";
import { recordAuditEntry } from "../audit/auditLog";

export const authRouter = Router();

const PENDING_COOKIE = "pending_login";
const PENDING_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax" as const,
  maxAge: 10 * 60 * 1000,
};

function setPendingCookie(res: import("express").Response, userId: string) {
  res.cookie(PENDING_COOKIE, signPendingLoginToken(userId), PENDING_COOKIE_OPTIONS);
}

function clearPendingCookie(res: import("express").Response) {
  const { maxAge: _maxAge, ...clearOptions } = PENDING_COOKIE_OPTIONS;
  res.clearCookie(PENDING_COOKIE, clearOptions);
}

function requirePendingUserId(req: import("express").Request): string | null {
  const token = req.cookies?.[PENDING_COOKIE];
  if (!token) return null;
  const claims = verifyPendingLoginToken(token);
  return claims?.sub ?? null;
}

async function establishAdminSession(res: import("express").Response, userId: string): Promise<"ok" | "forbidden"> {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: userId }, include: { roles: true } });
  if (!canAccessAdminUi(user)) return "forbidden";
  clearPendingCookie(res);
  res.cookie(SESSION_COOKIE_NAME, signAdminSessionToken({ sub: user.id, email: user.email, name: user.name }), SESSION_COOKIE_OPTIONS);
  return "ok";
}

// --- Step 1: email + password ---

authRouter.get("/login", (req, res) => {
  res.render("login", { error: null, email: "" });
});

const loginSchema = z.object({ email: z.string().email(), password: z.string().min(1) });

authRouter.post("/login", async (req, res, next) => {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      res.render("login", { error: "Enter a valid email and password.", email: req.body.email ?? "" });
      return;
    }
    const { email, password } = parsed.data;
    const result = await startLogin(email, password, req);

    switch (result.outcome) {
      case "invalid_credentials":
      case "inactive":
        res.render("login", { error: "Invalid email or password.", email });
        return;
      case "locked":
        res.render("login", { error: "Too many failed attempts. Try again in 15 minutes.", email });
        return;
      case "password_change_required":
        setPendingCookie(res, result.userId);
        res.redirect("/login/change-password");
        return;
      case "mfa_enrollment_required":
        setPendingCookie(res, result.userId);
        res.redirect("/login/mfa-setup");
        return;
      case "mfa_required": {
        setPendingCookie(res, result.userId);
        const preferred = result.availableMethods.includes("TOTP") ? "TOTP" : result.availableMethods[0];
        res.redirect(`/login/mfa?method=${preferred}`);
        return;
      }
    }
  } catch (err) {
    next(err);
  }
});

// --- Forced password change (first login) ---

authRouter.get("/login/change-password", (req, res) => {
  if (!requirePendingUserId(req)) {
    res.redirect("/login");
    return;
  }
  res.render("login-change-password", { error: null });
});

const changePasswordSchema = z
  .object({ password: z.string().min(12), confirmPassword: z.string().min(12) })
  .refine((d) => d.password === d.confirmPassword, { message: "Passwords do not match." });

authRouter.post("/login/change-password", async (req, res, next) => {
  try {
    const userId = requirePendingUserId(req);
    if (!userId) {
      res.redirect("/login");
      return;
    }
    const parsed = changePasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      res.render("login-change-password", { error: parsed.error.issues[0]?.message ?? "Invalid password." });
      return;
    }
    await setPassword(userId, parsed.data.password);
    res.redirect("/login/mfa-setup");
  } catch (err) {
    next(err);
  }
});

// --- Mandatory MFA enrollment (first login) ---

authRouter.get("/login/mfa-setup", (req, res) => {
  if (!requirePendingUserId(req)) {
    res.redirect("/login");
    return;
  }
  res.render("login-mfa-setup-choice");
});

authRouter.get("/login/mfa-setup/totp", async (req, res, next) => {
  try {
    const userId = requirePendingUserId(req);
    if (!userId) {
      res.redirect("/login");
      return;
    }
    const { secret, qrCodeDataUrl } = await beginTotpEnrollment(userId);
    res.render("login-mfa-setup-totp", { secret, qrCodeDataUrl, error: null });
  } catch (err) {
    next(err);
  }
});

authRouter.post("/login/mfa-setup/totp", async (req, res, next) => {
  try {
    const userId = requirePendingUserId(req);
    if (!userId) {
      res.redirect("/login");
      return;
    }
    const code = String(req.body.code ?? "");
    const ok = await confirmTotpEnrollment(userId, code, req);
    if (!ok) {
      const user = await prisma.user.findUniqueOrThrow({ where: { id: userId } });
      const secret = decryptSecret(user.totpSecretEncrypted as string);
      const qrCodeDataUrl = await buildProvisioningQrCodeDataUrl(user.email, secret, "Michael's Company Admin");
      res.render("login-mfa-setup-totp", { secret, qrCodeDataUrl, error: "That code didn't match. Try again." });
      return;
    }
    const sessionResult = await establishAdminSession(res, userId);
    res.redirect(sessionResult === "ok" ? "/" : "/login");
  } catch (err) {
    next(err);
  }
});

authRouter.get("/login/mfa-setup/sms", (req, res) => {
  if (!requirePendingUserId(req)) {
    res.redirect("/login");
    return;
  }
  res.render("login-mfa-setup-sms", { codeSent: false, error: null });
});

const phoneSchema = z.object({ phoneNumber: z.string().min(8).max(20) });

authRouter.post("/login/mfa-setup/sms", async (req, res, next) => {
  try {
    const userId = requirePendingUserId(req);
    if (!userId) {
      res.redirect("/login");
      return;
    }
    const parsed = phoneSchema.safeParse(req.body);
    if (!parsed.success) {
      res.render("login-mfa-setup-sms", { codeSent: false, error: "Enter a valid phone number, e.g. +15555550123." });
      return;
    }
    await beginSmsEnrollment(userId, parsed.data.phoneNumber);
    res.render("login-mfa-setup-sms", { codeSent: true, error: null });
  } catch (err) {
    next(err);
  }
});

authRouter.post("/login/mfa-setup/sms/resend", async (req, res, next) => {
  try {
    const userId = requirePendingUserId(req);
    if (!userId) {
      res.redirect("/login");
      return;
    }
    await resendSmsEnrollmentCode(userId);
    res.render("login-mfa-setup-sms", { codeSent: true, error: null, resent: true });
  } catch (err) {
    next(err);
  }
});

authRouter.post("/login/mfa-setup/sms/verify", async (req, res, next) => {
  try {
    const userId = requirePendingUserId(req);
    if (!userId) {
      res.redirect("/login");
      return;
    }
    const code = String(req.body.code ?? "");
    const ok = await confirmSmsEnrollment(userId, code, req);
    if (!ok) {
      res.render("login-mfa-setup-sms", { codeSent: true, error: "That code didn't match or has expired." });
      return;
    }
    const sessionResult = await establishAdminSession(res, userId);
    res.redirect(sessionResult === "ok" ? "/" : "/login");
  } catch (err) {
    next(err);
  }
});

// --- Step 2: MFA challenge (returning login) ---

authRouter.get("/login/mfa", async (req, res, next) => {
  try {
    const userId = requirePendingUserId(req);
    if (!userId) {
      res.redirect("/login");
      return;
    }
    const user = await prisma.user.findUniqueOrThrow({ where: { id: userId } });
    const availableMethods: Array<"TOTP" | "SMS"> = [];
    if (user.totpEnabled) availableMethods.push("TOTP");
    if (user.smsEnabled) availableMethods.push("SMS");
    if (availableMethods.length === 0) {
      res.redirect("/login/mfa-setup");
      return;
    }
    const requested = req.query.method === "SMS" ? "SMS" : req.query.method === "TOTP" ? "TOTP" : null;
    const method = requested && availableMethods.includes(requested) ? requested : availableMethods[0];

    if (method === "SMS") {
      await sendLoginSmsCode(userId);
    }

    res.render("login-mfa", { method, availableMethods, error: null });
  } catch (err) {
    next(err);
  }
});

authRouter.post("/login/mfa", async (req, res, next) => {
  try {
    const userId = requirePendingUserId(req);
    if (!userId) {
      res.redirect("/login");
      return;
    }
    const method = req.body.method === "SMS" ? "SMS" : "TOTP";
    const code = String(req.body.code ?? "");

    const user = await prisma.user.findUniqueOrThrow({ where: { id: userId } });
    const availableMethods: Array<"TOTP" | "SMS"> = [];
    if (user.totpEnabled) availableMethods.push("TOTP");
    if (user.smsEnabled) availableMethods.push("SMS");

    const result = await verifyMfa(userId, method, code, req);
    if (!result.ok) {
      const message = result.reason === "locked" ? "Too many failed attempts. Try again in 15 minutes." : "That code didn't match. Try again.";
      res.render("login-mfa", { method, availableMethods, error: message });
      return;
    }

    const sessionResult = await establishAdminSession(res, userId);
    res.redirect(sessionResult === "ok" ? "/" : "/login");
  } catch (err) {
    next(err);
  }
});

authRouter.post("/login/mfa/resend-sms", async (req, res, next) => {
  try {
    const userId = requirePendingUserId(req);
    if (!userId) {
      res.redirect("/login");
      return;
    }
    await sendLoginSmsCode(userId);
    res.redirect("/login/mfa?method=SMS");
  } catch (err) {
    next(err);
  }
});

// --- Logout ---

authRouter.post("/logout", async (req, res) => {
  if (req.currentUser) {
    await recordAuditEntry({ action: "admin_ui.logout", actorUserId: req.currentUser.id, actorEmail: req.currentUser.email, req });
  }
  const { maxAge: _maxAge, ...clearOptions } = SESSION_COOKIE_OPTIONS;
  res.clearCookie(SESSION_COOKIE_NAME, clearOptions);
  res.redirect("/login");
});

// --- Forgot / reset password ---

authRouter.get("/forgot-password", (req, res) => {
  res.render("forgot-password", { submitted: false });
});

authRouter.post("/forgot-password", async (req, res, next) => {
  try {
    const email = String(req.body.email ?? "");
    if (email) {
      await requestPasswordReset(email, req);
    }
    res.render("forgot-password", { submitted: true });
  } catch (err) {
    next(err);
  }
});

authRouter.get("/reset-password/:token", (req, res) => {
  res.render("reset-password", { token: req.params.token, invalid: false, error: null });
});

authRouter.post("/reset-password/:token", async (req, res, next) => {
  try {
    const parsed = changePasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      res.render("reset-password", { token: req.params.token, invalid: false, error: parsed.error.issues[0]?.message ?? "Invalid password." });
      return;
    }
    const outcome = await completePasswordReset(req.params.token, parsed.data.password, req);
    if (outcome === "invalid_or_expired") {
      res.render("reset-password", { token: req.params.token, invalid: true, error: null });
      return;
    }
    res.render("login", { error: "Password updated. Sign in with your new password.", email: "" });
  } catch (err) {
    next(err);
  }
});
