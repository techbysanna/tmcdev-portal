import type { UserApplicationRole } from "@prisma/client";

export interface PermissionSubject {
  isSuperAdmin: boolean;
  roles: Pick<UserApplicationRole, "applicationId" | "role">[];
}

// Access to admin-service's own admin UI: any super admin, or anyone holding
// "staff" or "admin" in at least one registered application.
export function canAccessAdminUi(user: PermissionSubject): boolean {
  if (user.isSuperAdmin) return true;
  return user.roles.some((r) => r.role === "staff" || r.role === "admin");
}

// Only application-level "admin" (or a super admin) may create/deactivate users and
// assign roles for that application — mirrors the doc's "Admin ... manage staff
// accounts" vs. "Staff ... manage investor accounts" split.
export function canManageUsersForApplication(user: PermissionSubject, applicationId: string): boolean {
  if (user.isSuperAdmin) return true;
  return user.roles.some((r) => r.applicationId === applicationId && r.role === "admin");
}

// Staff may create/manage the lowest-privilege role only (e.g. "investor") for an
// application they hold "staff" in.
export function canManageBaseUsersForApplication(user: PermissionSubject, applicationId: string): boolean {
  if (canManageUsersForApplication(user, applicationId)) return true;
  return user.roles.some((r) => r.applicationId === applicationId && r.role === "staff");
}

// Full audit log view is restricted to super admins and anyone holding "admin" in
// any application — matches "Admin (Michael) ... view full audit log."
export function canViewAuditLog(user: PermissionSubject): boolean {
  if (user.isSuperAdmin) return true;
  return user.roles.some((r) => r.role === "admin");
}

export function canManageApplications(user: PermissionSubject): boolean {
  return user.isSuperAdmin;
}
