import { describe, expect, it } from "vitest";
import {
  canAccessAdminUi,
  canManageBaseUsersForApplication,
  canManageUsersForApplication,
  canViewAuditLog,
} from "../src/lib/permissions";

const APP_ID = "app-1";

describe("permissions", () => {
  it("super admins can access the admin UI regardless of roles", () => {
    expect(canAccessAdminUi({ isSuperAdmin: true, roles: [] })).toBe(true);
  });

  it("investor-only accounts cannot access the admin UI", () => {
    expect(
      canAccessAdminUi({ isSuperAdmin: false, roles: [{ applicationId: APP_ID, role: "investor" }] as any }),
    ).toBe(false);
  });

  it("staff and admin roles can access the admin UI", () => {
    expect(canAccessAdminUi({ isSuperAdmin: false, roles: [{ applicationId: APP_ID, role: "staff" }] as any })).toBe(true);
    expect(canAccessAdminUi({ isSuperAdmin: false, roles: [{ applicationId: APP_ID, role: "admin" }] as any })).toBe(true);
  });

  it("only app-admin (or super admin) can manage all roles for that app", () => {
    const staff = { isSuperAdmin: false, roles: [{ applicationId: APP_ID, role: "staff" }] as any };
    const admin = { isSuperAdmin: false, roles: [{ applicationId: APP_ID, role: "admin" }] as any };
    expect(canManageUsersForApplication(staff, APP_ID)).toBe(false);
    expect(canManageUsersForApplication(admin, APP_ID)).toBe(true);
  });

  it("staff can manage base users but not full user management", () => {
    const staff = { isSuperAdmin: false, roles: [{ applicationId: APP_ID, role: "staff" }] as any };
    expect(canManageBaseUsersForApplication(staff, APP_ID)).toBe(true);
    expect(canManageUsersForApplication(staff, APP_ID)).toBe(false);
  });

  it("audit log is restricted to admins and super admins", () => {
    const investor = { isSuperAdmin: false, roles: [{ applicationId: APP_ID, role: "investor" }] as any };
    const staff = { isSuperAdmin: false, roles: [{ applicationId: APP_ID, role: "staff" }] as any };
    const admin = { isSuperAdmin: false, roles: [{ applicationId: APP_ID, role: "admin" }] as any };
    expect(canViewAuditLog(investor)).toBe(false);
    expect(canViewAuditLog(staff)).toBe(false);
    expect(canViewAuditLog(admin)).toBe(true);
  });
});
