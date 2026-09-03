// Portal-app only ever deals with its own roles (unlike admin-service, which is
// shared across apps), so these take the role string directly rather than a
// per-application lookup.
export type PortalRole = "investor" | "staff" | "admin";

export function isStaffOrAdmin(role: string): boolean {
  return role === "staff" || role === "admin";
}

export function isAdmin(role: string): boolean {
  return role === "admin";
}

// "Admin (Michael) ... view full audit log" — admin-only per the requirements doc.
export function canViewAuditLog(role: string): boolean {
  return isAdmin(role);
}

// "Staff: Upload documents, assign them to investor(s), manage investor accounts"
export function canManageDocuments(role: string): boolean {
  return isStaffOrAdmin(role);
}
