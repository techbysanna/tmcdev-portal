import { Router } from "express";
import { prisma } from "../db/prisma";
import { APPLICATION_ROLES, isValidRole } from "../config/applications";
import {
  canManageBaseUsersForApplication,
  canManageUsersForApplication,
  canViewAuditLog,
} from "../lib/permissions";
import { createUserWithSetupLink, resetMfaEnrollment } from "../lib/authService";
import { recordAuditEntry } from "../audit/auditLog";

export const adminRouter = Router();

// requireAdminSession (mounted ahead of this router) guarantees req.currentUser is set.
function currentUser(req: import("express").Request) {
  return req.currentUser!;
}

adminRouter.get("/", (req, res) => {
  const user = currentUser(req);
  res.render("dashboard", { currentUser: user, canViewAuditLog: canViewAuditLog(user) });
});

// --- Users ---

adminRouter.get("/users", async (req, res) => {
  const user = currentUser(req);
  const users = await prisma.user.findMany({
    include: { roles: { include: { application: true } } },
    orderBy: { createdAt: "desc" },
  });
  res.render("users/list", { currentUser: user, canViewAuditLog: canViewAuditLog(user), users });
});

async function assignableApplicationsFor(user: ReturnType<typeof currentUser>) {
  const applications = await prisma.application.findMany();
  return applications
    .map((app) => {
      const allRoles = APPLICATION_ROLES[app.key] ?? [];
      let assignableRoles: string[] = [];
      if (canManageUsersForApplication(user, app.id)) {
        assignableRoles = allRoles;
      } else if (canManageBaseUsersForApplication(user, app.id)) {
        assignableRoles = allRoles.slice(0, 1); // lowest-privilege role only, e.g. "investor"
      }
      return { id: app.id, key: app.key, name: app.name, assignableRoles };
    })
    .filter((app) => app.assignableRoles.length > 0);
}

adminRouter.get("/users/new", async (req, res) => {
  const user = currentUser(req);
  const applications = await assignableApplicationsFor(user);
  res.render("users/new", { currentUser: user, canViewAuditLog: canViewAuditLog(user), applications, error: null });
});

adminRouter.post("/users", async (req, res, next) => {
  try {
    const user = currentUser(req);
    const name = String(req.body.name ?? "").trim();
    const email = String(req.body.email ?? "").trim();
    const applicationRole = String(req.body.applicationRole ?? "");
    const wantsSuperAdmin = req.body.isSuperAdmin === "true" && user.isSuperAdmin;

    if (!name || !email) {
      const applications = await assignableApplicationsFor(user);
      res.render("users/new", { currentUser: user, canViewAuditLog: canViewAuditLog(user), applications, error: "Name and email are required." });
      return;
    }

    let applicationId: string | null = null;
    let applicationKey: string | undefined;
    let role: string | null = null;
    if (applicationRole) {
      const [appId, roleName] = applicationRole.split("::");
      const applications = await assignableApplicationsFor(user);
      const matchedApp = applications.find((a) => a.id === appId);
      const allowed = matchedApp?.assignableRoles.includes(roleName ?? "");
      if (!appId || !roleName || !allowed) {
        res.render("users/new", { currentUser: user, canViewAuditLog: canViewAuditLog(user), applications, error: "You are not permitted to assign that role." });
        return;
      }
      applicationId = appId;
      applicationKey = matchedApp!.key;
      role = roleName;
    }

    const created = await createUserWithSetupLink({ name, email, actorUserId: user.id, actorEmail: user.email, req, applicationKey });

    if (applicationId && role) {
      await prisma.userApplicationRole.create({ data: { userId: created.id, applicationId, role } });
      await recordAuditEntry({ action: "user.role_assigned", actorUserId: user.id, actorEmail: user.email, req, targetType: "User", targetId: created.id, metadata: { applicationId, role } });
    }

    if (wantsSuperAdmin) {
      await prisma.user.update({ where: { id: created.id }, data: { isSuperAdmin: true } });
    }

    res.redirect(`/users/${created.id}`);
  } catch (err) {
    next(err);
  }
});

adminRouter.get("/users/:id", async (req, res) => {
  const user = currentUser(req);
  const target = await prisma.user.findUnique({
    where: { id: req.params.id },
    include: { roles: { include: { application: true } } },
  });
  if (!target) {
    res.status(404).send("User not found");
    return;
  }
  const canManage = target.roles.some((r) => canManageBaseUsersForApplication(user, r.applicationId)) || user.isSuperAdmin || target.roles.length === 0;
  const assignableApplications = await assignableApplicationsFor(user);
  res.render("users/show", { currentUser: user, canViewAuditLog: canViewAuditLog(user), user: target, canManage, assignableApplications });
});

adminRouter.post("/users/:id/roles", async (req, res, next) => {
  try {
    const user = currentUser(req);
    const applicationRole = String(req.body.applicationRole ?? "");
    const [applicationId, role] = applicationRole.split("::");
    if (!applicationId || !role) {
      res.redirect(`/users/${req.params.id}`);
      return;
    }
    const application = await prisma.application.findUnique({ where: { id: applicationId } });
    if (!application || !isValidRole(application.key, role)) {
      res.status(400).send("Invalid application or role");
      return;
    }
    const allowed = canManageUsersForApplication(user, applicationId) || (canManageBaseUsersForApplication(user, applicationId) && role === (APPLICATION_ROLES[application.key] ?? [])[0]);
    if (!allowed) {
      res.status(403).send("Not permitted to assign that role");
      return;
    }
    await prisma.userApplicationRole.upsert({
      where: { userId_applicationId: { userId: req.params.id, applicationId } },
      create: { userId: req.params.id, applicationId, role },
      update: { role },
    });
    await recordAuditEntry({ action: "user.role_assigned", actorUserId: user.id, actorEmail: user.email, req, targetType: "User", targetId: req.params.id, metadata: { applicationId, role } });
    res.redirect(`/users/${req.params.id}`);
  } catch (err) {
    next(err);
  }
});

adminRouter.post("/users/:id/roles/:roleId/remove", async (req, res, next) => {
  try {
    const user = currentUser(req);
    const roleRow = await prisma.userApplicationRole.findUnique({ where: { id: req.params.roleId } });
    if (!roleRow) {
      res.redirect(`/users/${req.params.id}`);
      return;
    }
    if (!canManageBaseUsersForApplication(user, roleRow.applicationId)) {
      res.status(403).send("Not permitted to remove that role");
      return;
    }
    await prisma.userApplicationRole.delete({ where: { id: req.params.roleId } });
    await recordAuditEntry({ action: "user.role_removed", actorUserId: user.id, actorEmail: user.email, req, targetType: "User", targetId: req.params.id, metadata: { applicationId: roleRow.applicationId, role: roleRow.role } });
    res.redirect(`/users/${req.params.id}`);
  } catch (err) {
    next(err);
  }
});

adminRouter.post("/users/:id/deactivate", async (req, res, next) => {
  try {
    const user = currentUser(req);
    if (req.params.id === user.id) {
      res.status(400).send("You cannot deactivate your own account");
      return;
    }
    await prisma.user.update({ where: { id: req.params.id }, data: { isActive: false } });
    await recordAuditEntry({ action: "user.deactivated", actorUserId: user.id, actorEmail: user.email, req, targetType: "User", targetId: req.params.id });
    res.redirect(`/users/${req.params.id}`);
  } catch (err) {
    next(err);
  }
});

adminRouter.post("/users/:id/reactivate", async (req, res, next) => {
  try {
    const user = currentUser(req);
    await prisma.user.update({ where: { id: req.params.id }, data: { isActive: true } });
    await recordAuditEntry({ action: "user.reactivated", actorUserId: user.id, actorEmail: user.email, req, targetType: "User", targetId: req.params.id });
    res.redirect(`/users/${req.params.id}`);
  } catch (err) {
    next(err);
  }
});

adminRouter.post("/users/:id/reset-mfa", async (req, res, next) => {
  try {
    const user = currentUser(req);
    await resetMfaEnrollment(req.params.id, user.id, user.email, req);
    res.redirect(`/users/${req.params.id}`);
  } catch (err) {
    next(err);
  }
});

// --- Audit log ---

adminRouter.get("/audit-log", async (req, res) => {
  const user = currentUser(req);
  if (!canViewAuditLog(user)) {
    res.status(403).send("Not permitted to view the audit log");
    return;
  }
  const page = Math.max(1, parseInt(String(req.query.page ?? "1"), 10) || 1);
  const pageSize = 50;
  const entries = await prisma.auditLogEntry.findMany({
    orderBy: { createdAt: "desc" },
    skip: (page - 1) * pageSize,
    take: pageSize + 1,
  });
  const hasNext = entries.length > pageSize;
  res.render("audit-log", {
    currentUser: user,
    canViewAuditLog: true,
    entries: entries.slice(0, pageSize),
    page,
    hasPrev: page > 1,
    hasNext,
  });
});
