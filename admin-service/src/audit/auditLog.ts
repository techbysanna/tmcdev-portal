import type { Request } from "express";
import { prisma } from "../db/prisma";
import { logger } from "../lib/logger";

export type AuditAction =
  | "login.success"
  | "login.failure"
  | "login.locked_out"
  | "mfa.challenge_sent"
  | "mfa.verify_success"
  | "mfa.verify_failure"
  | "mfa.totp_enrolled"
  | "mfa.sms_enrolled"
  | "mfa.reset"
  | "password.reset_requested"
  | "password.reset_completed"
  | "user.created"
  | "user.deactivated"
  | "user.reactivated"
  | "user.role_assigned"
  | "user.role_removed"
  | "admin_ui.logout";

export interface AuditEntryInput {
  action: AuditAction;
  actorUserId?: string | null;
  actorEmail?: string | null;
  targetType?: string | null;
  targetId?: string | null;
  metadata?: Record<string, unknown> | null;
  req?: Request;
}

// Every entry passes through here so "who / what / when" is always populated and
// nothing beyond small, non-sensitive metadata is ever persisted. Callers must not
// put document contents, credentials, MFA codes/secrets, or full tokens in metadata.
export async function recordAuditEntry(input: AuditEntryInput): Promise<void> {
  try {
    await prisma.auditLogEntry.create({
      data: {
        action: input.action,
        actorUserId: input.actorUserId ?? null,
        actorEmail: input.actorEmail ?? null,
        targetType: input.targetType ?? null,
        targetId: input.targetId ?? null,
        metadata: (input.metadata as any) ?? undefined,
        ipAddress: input.req?.ip ?? null,
        userAgent: input.req?.get("user-agent") ?? null,
      },
    });
  } catch (err) {
    // Audit logging must never take down the request path, but a failure here is
    // itself significant — surface it loudly in application logs.
    logger.error({ err, action: input.action }, "failed to write audit log entry");
  }
}
