import type { Request } from "express";
import { prisma } from "../db/prisma";
import { verifyPassword, hashPassword, decryptSecret, encryptSecret, generateNumericCode, hashOpaqueToken, generateOpaqueToken, timingSafeEqual } from "./crypto";
import { verifyTotpCode, generateTotpSecret, buildProvisioningQrCodeDataUrl } from "./totp";
import { sendSmsCode } from "./sms";
import { emailProvider } from "./email";
import { isLocked, nextLockoutState } from "./lockout";
import { recordAuditEntry } from "../audit/auditLog";
import { env } from "../config/env";

const SMS_CODE_TTL_MS = 5 * 60 * 1000;
const PASSWORD_RESET_TTL_MS = 60 * 60 * 1000;
const ACCOUNT_SETUP_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_MFA_ATTEMPTS = 5;

// New accounts are created with an unusable random password hash — nobody, including
// staff who create the account, ever knows or emails a real password. The new user's
// only way in is the account-setup link below, which lets them set their own password.
export async function createUserWithSetupLink(input: { name: string; email: string; req?: Request; actorUserId: string | null; actorEmail: string; applicationKey?: string }) {
  const unusablePassword = generateOpaqueToken(32);
  const user = await prisma.user.create({
    data: {
      name: input.name,
      email: input.email.toLowerCase().trim(),
      passwordHash: await hashPassword(unusablePassword),
      mustChangePassword: true,
    },
  });

  await recordAuditEntry({ action: "user.created", actorUserId: input.actorUserId, actorEmail: input.actorEmail, req: input.req, targetType: "User", targetId: user.id });

  await sendAccountSetupEmail(user.id, input.applicationKey);

  return user;
}

async function resolveLoginBaseUrl(applicationKey?: string): Promise<string> {
  if (!applicationKey) return env.APP_BASE_URL;
  const application = await prisma.application.findUnique({ where: { key: applicationKey } });
  return application?.loginBaseUrl || env.APP_BASE_URL;
}

export async function sendAccountSetupEmail(userId: string, applicationKey?: string): Promise<void> {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: userId } });

  const rawToken = generateOpaqueToken(32);
  await prisma.passwordResetToken.create({
    data: {
      userId: user.id,
      tokenHash: hashOpaqueToken(rawToken),
      expiresAt: new Date(Date.now() + ACCOUNT_SETUP_TTL_MS),
    },
  });

  const baseUrl = await resolveLoginBaseUrl(applicationKey);
  const setupUrl = `${baseUrl}/reset-password/${rawToken}`;
  await emailProvider.send({
    to: user.email,
    subject: "Set up your account",
    text: `An account was created for you. Set your password to get started (this link expires in 7 days and can be used once):\n\n${setupUrl}\n\nYou'll be asked to set up two-factor authentication the first time you sign in.`,
  });
}

export type StartLoginResult =
  | { outcome: "invalid_credentials" }
  | { outcome: "inactive" }
  | { outcome: "locked"; lockedUntil: Date }
  | { outcome: "password_change_required"; userId: string }
  | { outcome: "mfa_enrollment_required"; userId: string }
  | { outcome: "mfa_required"; userId: string; availableMethods: Array<"TOTP" | "SMS"> };

export async function startLogin(email: string, password: string, req?: Request): Promise<StartLoginResult> {
  const user = await prisma.user.findUnique({ where: { email: email.toLowerCase().trim() } });

  if (!user) {
    // Constant-shape response so login can't be used to enumerate valid emails.
    await verifyPassword("$argon2id$v=19$m=65536,t=3,p=4$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000", password);
    await recordAuditEntry({ action: "login.failure", actorEmail: email, req, metadata: { reason: "no_such_user" } });
    return { outcome: "invalid_credentials" };
  }

  if (!user.isActive) {
    await recordAuditEntry({ action: "login.failure", actorUserId: user.id, actorEmail: user.email, req, metadata: { reason: "inactive" } });
    return { outcome: "inactive" };
  }

  if (isLocked(user.lockedUntil)) {
    await recordAuditEntry({ action: "login.locked_out", actorUserId: user.id, actorEmail: user.email, req });
    return { outcome: "locked", lockedUntil: user.lockedUntil as Date };
  }

  const passwordOk = await verifyPassword(user.passwordHash, password);
  if (!passwordOk) {
    const { failedLoginAttempts, lockedUntil } = nextLockoutState(user.failedLoginAttempts);
    await prisma.user.update({ where: { id: user.id }, data: { failedLoginAttempts, lockedUntil } });
    await recordAuditEntry({ action: "login.failure", actorUserId: user.id, actorEmail: user.email, req, metadata: { reason: "bad_password" } });
    return { outcome: "invalid_credentials" };
  }

  // Password correct: reset the failure counter regardless of what happens next.
  await prisma.user.update({ where: { id: user.id }, data: { failedLoginAttempts: 0, lockedUntil: null } });

  if (user.mustChangePassword) {
    return { outcome: "password_change_required", userId: user.id };
  }

  if (!user.totpEnabled && !user.smsEnabled) {
    return { outcome: "mfa_enrollment_required", userId: user.id };
  }

  const availableMethods: Array<"TOTP" | "SMS"> = [];
  if (user.totpEnabled) availableMethods.push("TOTP");
  if (user.smsEnabled) availableMethods.push("SMS");

  await recordAuditEntry({ action: "mfa.challenge_sent", actorUserId: user.id, actorEmail: user.email, req, metadata: { availableMethods } });

  return { outcome: "mfa_required", userId: user.id, availableMethods };
}

export async function setPassword(userId: string, newPassword: string): Promise<void> {
  const passwordHash = await hashPassword(newPassword);
  await prisma.user.update({ where: { id: userId }, data: { passwordHash, mustChangePassword: false } });
}

export async function beginTotpEnrollment(userId: string): Promise<{ secret: string; qrCodeDataUrl: string }> {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: userId } });
  const secret = generateTotpSecret();
  await prisma.user.update({ where: { id: userId }, data: { totpSecretEncrypted: encryptSecret(secret) } });
  const qrCodeDataUrl = await buildProvisioningQrCodeDataUrl(user.email, secret, "Michael's Company Admin");
  return { secret, qrCodeDataUrl };
}

export async function confirmTotpEnrollment(userId: string, code: string, req?: Request): Promise<boolean> {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: userId } });
  if (!user.totpSecretEncrypted) return false;
  const secret = decryptSecret(user.totpSecretEncrypted);
  if (!(await verifyTotpCode(secret, code))) return false;

  await prisma.user.update({ where: { id: userId }, data: { totpEnabled: true } });
  await recordAuditEntry({ action: "mfa.totp_enrolled", actorUserId: userId, actorEmail: user.email, req });
  return true;
}

export async function beginSmsEnrollment(userId: string, phoneNumber: string): Promise<void> {
  await prisma.user.update({ where: { id: userId }, data: { phoneNumber } });
  await issueSmsCode(userId, phoneNumber);
}

export async function resendSmsEnrollmentCode(userId: string): Promise<void> {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: userId } });
  if (!user.phoneNumber) throw new Error("No phone number on file to resend a code to — call beginSmsEnrollment first");
  await issueSmsCode(userId, user.phoneNumber);
}

export async function confirmSmsEnrollment(userId: string, code: string, req?: Request): Promise<boolean> {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: userId } });
  const ok = await consumeSmsCode(userId, code);
  if (!ok) return false;
  await prisma.user.update({ where: { id: userId }, data: { smsEnabled: true } });
  await recordAuditEntry({ action: "mfa.sms_enrolled", actorUserId: userId, actorEmail: user.email, req });
  return true;
}

async function issueSmsCode(userId: string, phoneNumber: string): Promise<void> {
  const code = generateNumericCode(6);
  await prisma.mfaChallenge.create({
    data: {
      userId,
      method: "SMS",
      codeHash: hashOpaqueToken(code),
      expiresAt: new Date(Date.now() + SMS_CODE_TTL_MS),
    },
  });
  await sendSmsCode(phoneNumber, code);
}

export async function sendLoginSmsCode(userId: string): Promise<void> {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: userId } });
  if (!user.smsEnabled || !user.phoneNumber) throw new Error("SMS MFA is not enrolled for this user");
  await issueSmsCode(userId, user.phoneNumber);
}

async function consumeSmsCode(userId: string, code: string): Promise<boolean> {
  const challenge = await prisma.mfaChallenge.findFirst({
    where: { userId, method: "SMS", consumedAt: null, expiresAt: { gt: new Date() } },
    orderBy: { createdAt: "desc" },
  });
  if (!challenge || !challenge.codeHash) return false;
  if (challenge.attempts >= MAX_MFA_ATTEMPTS) return false;

  const matches = timingSafeEqual(challenge.codeHash, hashOpaqueToken(code));
  if (!matches) {
    await prisma.mfaChallenge.update({ where: { id: challenge.id }, data: { attempts: { increment: 1 } } });
    return false;
  }

  await prisma.mfaChallenge.update({ where: { id: challenge.id }, data: { consumedAt: new Date() } });
  return true;
}

export type VerifyMfaResult = { ok: true; user: NonNullable<Awaited<ReturnType<typeof loadUserWithRoles>>> } | { ok: false; reason: "invalid_code" | "locked" };

async function loadUserWithRoles(userId: string) {
  return prisma.user.findUnique({ where: { id: userId }, include: { roles: { include: { application: true } } } });
}

export async function verifyMfa(userId: string, method: "TOTP" | "SMS", code: string, req?: Request): Promise<VerifyMfaResult> {
  const user = await loadUserWithRoles(userId);
  if (!user) return { ok: false, reason: "invalid_code" };

  if (isLocked(user.lockedUntil)) {
    return { ok: false, reason: "locked" };
  }

  let valid = false;
  if (method === "TOTP") {
    if (user.totpEnabled && user.totpSecretEncrypted) {
      valid = await verifyTotpCode(decryptSecret(user.totpSecretEncrypted), code);
    }
  } else {
    if (user.smsEnabled) {
      valid = await consumeSmsCode(userId, code);
    }
  }

  if (!valid) {
    const { failedLoginAttempts, lockedUntil } = nextLockoutState(user.failedLoginAttempts);
    await prisma.user.update({ where: { id: userId }, data: { failedLoginAttempts, lockedUntil } });
    await recordAuditEntry({ action: "mfa.verify_failure", actorUserId: user.id, actorEmail: user.email, req, metadata: { method } });
    return { ok: false, reason: "invalid_code" };
  }

  await prisma.user.update({ where: { id: userId }, data: { failedLoginAttempts: 0, lockedUntil: null } });
  await recordAuditEntry({ action: "mfa.verify_success", actorUserId: user.id, actorEmail: user.email, req, metadata: { method } });
  await recordAuditEntry({ action: "login.success", actorUserId: user.id, actorEmail: user.email, req });

  return { ok: true, user };
}

export async function requestPasswordReset(email: string, req?: Request, applicationKey?: string): Promise<void> {
  const user = await prisma.user.findUnique({ where: { email: email.toLowerCase().trim() } });
  // Always behave the same whether or not the account exists, to avoid email enumeration.
  if (!user || !user.isActive) {
    await recordAuditEntry({ action: "password.reset_requested", actorEmail: email, req, metadata: { userFound: Boolean(user) } });
    return;
  }

  const rawToken = generateOpaqueToken(32);
  await prisma.passwordResetToken.create({
    data: {
      userId: user.id,
      tokenHash: hashOpaqueToken(rawToken),
      expiresAt: new Date(Date.now() + PASSWORD_RESET_TTL_MS),
    },
  });

  const baseUrl = await resolveLoginBaseUrl(applicationKey);
  const resetUrl = `${baseUrl}/reset-password/${rawToken}`;
  await emailProvider.send({
    to: user.email,
    subject: "Reset your password",
    text: `We received a request to reset your password. This link expires in 1 hour and can be used once:\n\n${resetUrl}\n\nIf you didn't request this, you can ignore this email.`,
  });

  await recordAuditEntry({ action: "password.reset_requested", actorUserId: user.id, actorEmail: user.email, req });
}

export async function resetMfaEnrollment(userId: string, actorUserId: string, actorEmail: string, req?: Request): Promise<void> {
  await prisma.user.update({
    where: { id: userId },
    data: { totpEnabled: false, totpSecretEncrypted: null, smsEnabled: false, phoneNumber: null },
  });
  await recordAuditEntry({ action: "mfa.reset", actorUserId, actorEmail, req, targetType: "User", targetId: userId });
}

export type CompletePasswordResetResult = "ok" | "invalid_or_expired";

export async function completePasswordReset(rawToken: string, newPassword: string, req?: Request): Promise<CompletePasswordResetResult> {
  const tokenHash = hashOpaqueToken(rawToken);
  const record = await prisma.passwordResetToken.findUnique({ where: { tokenHash } });

  if (!record || record.consumedAt || record.expiresAt.getTime() < Date.now()) {
    return "invalid_or_expired";
  }

  await prisma.$transaction([
    prisma.passwordResetToken.update({ where: { id: record.id }, data: { consumedAt: new Date() } }),
    prisma.user.update({
      where: { id: record.userId },
      data: { passwordHash: await hashPassword(newPassword), mustChangePassword: false, failedLoginAttempts: 0, lockedUntil: null },
    }),
  ]);

  const user = await prisma.user.findUnique({ where: { id: record.userId } });
  await recordAuditEntry({ action: "password.reset_completed", actorUserId: record.userId, actorEmail: user?.email, req });

  return "ok";
}
