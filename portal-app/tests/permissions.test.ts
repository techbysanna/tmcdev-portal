import { describe, expect, it } from "vitest";
import { canManageDocuments, canViewAuditLog, isAdmin, isStaffOrAdmin } from "../src/lib/permissions";

describe("permissions", () => {
  it("investor is neither staff nor admin", () => {
    expect(isStaffOrAdmin("investor")).toBe(false);
    expect(isAdmin("investor")).toBe(false);
  });

  it("staff can manage documents but is not admin", () => {
    expect(isStaffOrAdmin("staff")).toBe(true);
    expect(isAdmin("staff")).toBe(false);
    expect(canManageDocuments("staff")).toBe(true);
  });

  it("admin can manage documents and is admin", () => {
    expect(isStaffOrAdmin("admin")).toBe(true);
    expect(isAdmin("admin")).toBe(true);
    expect(canManageDocuments("admin")).toBe(true);
  });

  it("audit log is admin-only, per the requirements doc", () => {
    expect(canViewAuditLog("investor")).toBe(false);
    expect(canViewAuditLog("staff")).toBe(false);
    expect(canViewAuditLog("admin")).toBe(true);
  });
});
