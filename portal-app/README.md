# portal-app

The investor document portal itself. Same stack as `../admin-service`
(Node/TypeScript/Express/Prisma/Postgres). Owns documents, assignments, and its own
audit log — but owns **no** identity data (no passwords, no MFA secrets). All of that
lives in `admin-service`, which this app calls over its internal API.

## Local setup

```bash
npm install
cp .env.example .env
# ADMIN_SERVICE_INTERNAL_API_KEY must exactly match admin-service's INTERNAL_API_KEY
# ADMIN_SERVICE_JWT_SECRET must exactly match admin-service's INTERNAL_JWT_SECRET
npx prisma migrate dev
npm run dev
```

Requires admin-service running (`../admin-service`, default `http://localhost:4000`)
and reachable at `ADMIN_SERVICE_URL`.

## How login works here

Portal-app hosts its own branded login/MFA/password pages (investors should never see
"admin-service" branding) but never touches a password or MFA secret directly:

1. `POST /login` forwards email+password to admin-service's `/internal/auth/start`.
2. Depending on the response, the user is walked through mandatory MFA enrollment
   (first login) or an MFA challenge (returning login) — every step is a thin proxy to
   the matching `/internal/auth/*` endpoint on admin-service (see
   `src/lib/adminServiceClient.ts`).
3. On success, admin-service hands back a short-lived **identity assertion** JWT.
   Portal-app verifies it (`ADMIN_SERVICE_JWT_SECRET`), upserts a local `PortalUser`
   cache row, and mints its **own** session cookie — independent of admin-service's
   session, per the "separate login per app, shared directory only" decision.
4. A user is let in only if their identity assertion carries a role for
   `investor-portal` specifically — an admin-service super admin with no
   investor-portal role does not get in here.

The 10-minute `pending_login` cookie between steps holds the opaque `loginToken`
admin-service issues — portal-app never decodes it, just carries it back on each call.

## Staff/investor account management lives in admin-service, not here

Creating investor or staff accounts, assigning roles, resetting MFA, and viewing the
directory all happen in admin-service's own admin UI (`/users`, `/users/new`) — staff
and admin accounts already have access there because they hold `staff`/`admin` in
investor-portal. Portal-app deliberately does not duplicate that UI.

## Database

- `PortalUser` — a cache of admin-service identity, keyed by admin-service's user id.
  Upserted on every login; never the source of truth for who can log in.
- `Document` / `DocumentVersion` — category, year, project, publish status
  (`PENDING_REVIEW` until a staff member publishes it — see the "staff must approve
  before publish" decision), and version history for corrected/superseded documents.
- `DocumentAssignment` — which investor(s) a document is assigned to.
- `AuditLogEntry` — append-only; no update/delete route exists for it.

Dropbox sync, the investor dashboard, and signed-URL downloads are the next build
steps (3–4) — the schema above is scaffolded for them but not yet populated or wired
into any UI beyond a placeholder home page.

## A bug worth knowing about (fixed, but explains a schema choice)

Early on, account-setup and password-reset emails sent by admin-service always linked
back to admin-service's own domain, regardless of which app the user belonged to —
meaning an investor's first-ever email would point at "Admin Service." Fixed by adding
`Application.loginBaseUrl` in admin-service and threading an `applicationKey` through
`createUserWithSetupLink` / `requestPasswordReset` so those emails link to the right
app's own pages. `adminServiceClient.requestPasswordReset` here always passes
`applicationKey: "investor-portal"` for that reason.
