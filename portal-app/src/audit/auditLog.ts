import type { Request } from "express";
import { prisma } from "../db/prisma";
import { logger } from "../lib/logger";

export type AuditAction =
  | "login.success"
  | "login.failure"
  | "login.locked_out"
  | "logout"
  | "document.viewed"
  | "document.downloaded"
  | "document.uploaded"
  | "document.assigned"
  | "document.unassigned"
  | "document.published"
  | "document.archived"
  | "sync.completed"
  | "sync.flagged";

export interface AuditEntryInput {
  action: AuditAction;
  actorUserId?: string | null;
  actorEmail?: string | null;
  targetType?: string | null;
  targetId?: string | null;
  metadata?: Record<string, unknown> | null;
  req?: Request;
}

// Every document view/download and login event passes through here so "who / what /
// when" (the non-negotiable requirement) is always populated. Callers must never put
// document contents, tax details, or full tokens/codes in metadata — only ids and
// small descriptive fields.
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
    logger.error({ err, action: input.action }, "failed to write audit log entry");
  }
}
