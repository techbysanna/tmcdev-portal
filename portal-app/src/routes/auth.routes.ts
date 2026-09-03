import { Router, type Request, type Response } from "express";
import { z } from "zod";
import { prisma } from "../db/prisma";
import * as adminService from "../lib/adminServiceClient";
import { verifyIdentityAssertion, signPortalSessionToken } from "../lib/tokens";
import { SESSION_COOKIE_NAME, SESSION_COOKIE_OPTIONS } from "../middleware/requireSession";
import { recordAuditEntry } from "../audit/auditLog";

export const authRouter = Router();

const PENDING_COOKIE = "pending_login";
const PENDING_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax" as const,
  maxAge: 10 * 60 * 1000,
};

function setPendingCookie(res: Response, loginToken: string) {
  res.cookie(PENDING_COOKIE, loginToken, PENDING_COOKIE_OPTIONS);
}
function clearPendingCookie(res: Response) {
  const { maxAge: _maxAge, ...clearOptions } = PENDING_COOKIE_OPTIONS;
  res.clearCookie(PENDING_COOKIE, clearOptions);
}
function pendingLoginToken(req: Request): string | null {
  return req.cookies?.[PENDING_COOKIE] ?? null;
}

// Finalizes a login: verifies the identity assertion admin-service handed back,
// requires the user hold a recognized role in investor-portal specifically (an
// admin-service super admin with no investor-portal role does not get in here — that's
// an admin-service-only concept portal-app doesn't need to know about), upserts the
// local PortalUser cache, and mints this app's own session cookie.
async function establishSession(res: Response, identityAssertion: string, req?: Request): Promise<"ok" | "forbidden"> {
  const claims = verifyIdentityAssertion(identityAssertion);
  const role = claims?.roles["investor-portal"];
  if (!claims || !role) return "forbidden";

  const user = await prisma.portalUser.upsert({
    where: { id: claims.sub },
    create: { id: claims.sub, email: claims.email, name: claims.name, role },
    update: { email: claims.email, name: claims.name, role, lastSyncedAt: new Date() },
  });

  clearPendingCookie(res);
  res.cookie(SESSION_COOKIE_NAME, signPortalSessionToken({ sub: user.id, email: user.email, name: user.name, role: user.role }), SESSION_COOKIE_OPTIONS);
  await recordAuditEntry({ action: "login.success", actorUserId: user.id, actorEmail: user.email, req });
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
    const result = await adminService.startLogin(email, password);

    switch (result.status) {
      case "invalid_credentials":
        await recordAuditEntry({ action: "login.failure", actorEmail: email, req });
        res.render("login", { error: "Invalid email or password.", email });
        return;
      case "locked":
        await recordAuditEntry({ action: "login.locked_out", actorEmail: email, req });
        res.render("login", { error: "Too many failed attempts. Try again in 15 minutes.", email });
        return;
      case "password_change_required":
        setPendingCookie(res, result.loginToken);
        res.redirect("/login/change-password");
        return;
      case "mfa_enrollment_required":
        setPendingCookie(res, result.loginToken);
        res.redirect("/login/mfa-setup");
        return;
      case "mfa_required": {
        setPendingCookie(res, result.loginToken);
        const preferred = result.availableMethods.includes("TOTP") ? "TOTP" : result.availableMethods[0];
        res.redirect(`/login/mfa?method=${preferred}&methods=${result.availableMethods.join(",")}`);
        return;
      }
    }
  } catch (err) {
    next(err);
  }
});

// --- Forced password change (first login) ---

authRouter.get("/login/change-password", (req, res) => {
  if (!pendingLoginToken(req)) {
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
    const loginToken = pendingLoginToken(req);
    if (!loginToken) {
      res.redirect("/login");
      return;
    }
    const parsed = changePasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      res.render("login-change-password", { error: parsed.error.issues[0]?.message ?? "Invalid password." });
      return;
    }
    const result = await adminService.changePassword(loginToken, parsed.data.password);
    if (result.status !== "ok" || !("loginToken" in result)) {
      res.redirect("/login");
      return;
    }
    setPendingCookie(res, result.loginToken);
    res.redirect("/login/mfa-setup");
  } catch (err) {
    next(err);
  }
});

// --- Mandatory MFA enrollment (first login) ---

authRouter.get("/login/mfa-setup", (req, res) => {
  if (!pendingLoginToken(req)) {
    res.redirect("/login");
    return;
  }
  res.render("login-mfa-setup-choice");
});

authRouter.get("/login/mfa-setup/totp", async (req, res, next) => {
  try {
    const loginToken = pendingLoginToken(req);
    if (!loginToken) {
      res.redirect("/login");
      return;
    }
    const result = await adminService.beginTotpEnrollment(loginToken);
    res.render("login-mfa-setup-totp", { secret: result.secret, qrCodeDataUrl: result.qrCodeDataUrl, error: null });
  } catch (err) {
    next(err);
  }
});

authRouter.post("/login/mfa-setup/totp", async (req, res, next) => {
  try {
    const loginToken = pendingLoginToken(req);
    if (!loginToken) {
      res.redirect("/login");
      return;
    }
    const code = String(req.body.code ?? "");
    const result = await adminService.confirmTotpEnrollment(loginToken, code);
    if (result.status !== "ok") {
      // A retry re-provisions a fresh secret (admin-service has no "resume pending
      // enrollment" endpoint), so the user rescans — a minor rough edge, not a bug.
      const retry = await adminService.beginTotpEnrollment(loginToken);
      res.render("login-mfa-setup-totp", { secret: retry.secret, qrCodeDataUrl: retry.qrCodeDataUrl, error: "That code didn't match. Scan the new code below and try again." });
      return;
    }
    const sessionResult = await establishSession(res, result.identityAssertion, req);
    res.redirect(sessionResult === "ok" ? "/" : "/login");
  } catch (err) {
    next(err);
  }
});

authRouter.get("/login/mfa-setup/sms", (req, res) => {
  if (!pendingLoginToken(req)) {
    res.redirect("/login");
    return;
  }
  res.render("login-mfa-setup-sms", { codeSent: false, error: null });
});

const phoneSchema = z.object({ phoneNumber: z.string().min(8).max(20) });

authRouter.post("/login/mfa-setup/sms", async (req, res, next) => {
  try {
    const loginToken = pendingLoginToken(req);
    if (!loginToken) {
      res.redirect("/login");
      return;
    }
    const parsed = phoneSchema.safeParse(req.body);
    if (!parsed.success) {
      res.render("login-mfa-setup-sms", { codeSent: false, error: "Enter a valid phone number, e.g. +15555550123." });
      return;
    }
    await adminService.beginSmsEnrollment(loginToken, parsed.data.phoneNumber);
    res.render("login-mfa-setup-sms", { codeSent: true, error: null });
  } catch (err) {
    next(err);
  }
});

authRouter.post("/login/mfa-setup/sms/resend", async (req, res, next) => {
  try {
    const loginToken = pendingLoginToken(req);
    if (!loginToken) {
      res.redirect("/login");
      return;
    }
    await adminService.resendSmsEnrollmentCode(loginToken);
    res.render("login-mfa-setup-sms", { codeSent: true, error: null, resent: true });
  } catch (err) {
    next(err);
  }
});

authRouter.post("/login/mfa-setup/sms/verify", async (req, res, next) => {
  try {
    const loginToken = pendingLoginToken(req);
    if (!loginToken) {
      res.redirect("/login");
      return;
    }
    const code = String(req.body.code ?? "");
    const result = await adminService.confirmSmsEnrollment(loginToken, code);
    if (result.status !== "ok") {
      res.render("login-mfa-setup-sms", { codeSent: true, error: "That code didn't match or has expired." });
      return;
    }
    const sessionResult = await establishSession(res, result.identityAssertion, req);
    res.redirect(sessionResult === "ok" ? "/" : "/login");
  } catch (err) {
    next(err);
  }
});

// --- Step 2: MFA challenge (returning login) ---

function parseAvailableMethods(raw: unknown): Array<"TOTP" | "SMS"> {
  const methods = String(raw ?? "TOTP")
    .split(",")
    .filter((m): m is "TOTP" | "SMS" => m === "TOTP" || m === "SMS");
  return methods.length > 0 ? methods : ["TOTP"];
}

authRouter.get("/login/mfa", async (req, res, next) => {
  try {
    const loginToken = pendingLoginToken(req);
    if (!loginToken) {
      res.redirect("/login");
      return;
    }
    const availableMethods = parseAvailableMethods(req.query.methods);
    const requested = req.query.method === "SMS" && availableMethods.includes("SMS") ? "SMS" : availableMethods[0]!;
    if (requested === "SMS") {
      await adminService.sendMfaSms(loginToken);
    }
    res.render("login-mfa", { method: requested, availableMethods, error: null });
  } catch (err) {
    next(err);
  }
});

authRouter.post("/login/mfa", async (req, res, next) => {
  try {
    const loginToken = pendingLoginToken(req);
    if (!loginToken) {
      res.redirect("/login");
      return;
    }
    const method = req.body.method === "SMS" ? "SMS" : "TOTP";
    const code = String(req.body.code ?? "");
    const availableMethods = parseAvailableMethods(req.body.methods);

    const result = await adminService.verifyMfa(loginToken, method, code);
    if (result.status !== "ok") {
      const message = result.status === "locked" ? "Too many failed attempts. Try again in 15 minutes." : "That code didn't match. Try again.";
      res.render("login-mfa", { method, availableMethods, error: message });
      return;
    }

    const sessionResult = await establishSession(res, result.identityAssertion, req);
    res.redirect(sessionResult === "ok" ? "/" : "/login");
  } catch (err) {
    next(err);
  }
});

authRouter.post("/login/mfa/resend-sms", async (req, res, next) => {
  try {
    const loginToken = pendingLoginToken(req);
    if (!loginToken) {
      res.redirect("/login");
      return;
    }
    await adminService.sendMfaSms(loginToken);
    const methods = parseAvailableMethods(req.body.methods).join(",");
    res.redirect(`/login/mfa?method=SMS&methods=${methods}`);
  } catch (err) {
    next(err);
  }
});

// --- Logout ---

authRouter.post("/logout", async (req, res) => {
  if (req.currentUser) {
    await recordAuditEntry({ action: "logout", actorUserId: req.currentUser.id, actorEmail: req.currentUser.email, req });
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
      await adminService.requestPasswordReset(email);
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
    const result = await adminService.completePasswordReset(req.params.token, parsed.data.password);
    if (result.status === "invalid_or_expired") {
      res.render("reset-password", { token: req.params.token, invalid: true, error: null });
      return;
    }
    res.render("login", { error: "Password updated. Sign in with your new password.", email: "" });
  } catch (err) {
    next(err);
  }
});
