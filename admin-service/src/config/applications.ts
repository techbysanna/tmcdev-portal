// Registry of applications that authenticate against this admin-service, and the
// roles each one defines. Roles are per-application by design: "Investor/Staff/Admin"
// is meaningful for the investor portal but the invoice app (and future apps) will
// likely need a different role set on the same shared user directory.
//
// Add an entry here (and a matching row via the seed script) whenever a new app
// starts authenticating against this service.
export const APPLICATION_ROLES: Record<string, string[]> = {
  "investor-portal": ["investor", "staff", "admin"],
};

export function isValidRole(applicationKey: string, role: string): boolean {
  return APPLICATION_ROLES[applicationKey]?.includes(role) ?? false;
}

// Where each app's own branded login/reset pages live, read from env so it can differ
// per environment (local dev vs. Railway). Used only by the seed script to populate
// Application.loginBaseUrl — see the comment on that column for why it matters.
export const APPLICATION_LOGIN_BASE_URLS: Record<string, string | undefined> = {
  "investor-portal": process.env.INVESTOR_PORTAL_BASE_URL,
};
