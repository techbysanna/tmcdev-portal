# admin-service

Shared identity/directory service for Michael's apps (investor portal, invoice
automation, and future apps). Owns user accounts, password/MFA login, and
per-application roles. Other apps never see or store passwords/MFA secrets — they
call this service's internal API to authenticate their users.

## What lives here vs. in each app

- **Here:** who a person is, their password, their MFA enrollment, and what role they
  hold in each application (e.g. `investor-portal: investor`).
- **Not here:** anything app-specific (documents, assignments, audit trail for
  document access, etc.) — that belongs in each app's own database, keyed by the
  user id this service hands back.

Each app mints and owns its own session after verifying credentials here — there is
no cross-app single sign-on by design (see the architecture note in the repo root
`investor-portal-requirements.md` discussion).

## Local setup

```bash
npm install
cp .env.example .env   # fill in SESSION_SECRET, INTERNAL_JWT_SECRET,
                        # INTERNAL_API_KEY, MFA_ENCRYPTION_KEY (see comments in the file
                        # for how to generate each)
npx prisma migrate dev
SEED_ADMIN_EMAIL=you@example.com npm run seed   # creates the investor-portal
                                                 # application row + a super admin
npm run dev
```

With `EMAIL_PROVIDER=console` (the dev default), account-setup and password-reset
links are printed to the server console instead of emailed — copy the link from
there to continue.

## Auth flow (browser — admin-service's own admin UI)

1. Staff/admin creates a user (`/users/new`). No password is ever set by staff or
   emailed — the user gets a one-time account-setup link instead.
2. New user visits the link, sets their own password.
3. First login after that forces MFA enrollment (TOTP or SMS, user's choice) before
   they reach anything else.
4. Every subsequent login is password + MFA code.
5. Session is a signed, httpOnly cookie with a 30-minute sliding inactivity window.

Only users holding `staff` or `admin` in at least one application (or flagged
`isSuperAdmin`) can reach this admin UI at all — an investor-only account is bounced
back to `/login` even with correct credentials.

## Auth flow (other apps, e.g. portal-app)

Other apps call the JSON API under `/internal/*`, authenticated with a shared secret
sent as the `x-internal-api-key` header (never exposed to browsers). It mirrors the
browser flow step-for-step: `POST /internal/auth/start` → (password
change / MFA enrollment / MFA verify as needed) → a short-lived (5 min) signed
**identity assertion** JWT containing the user's id, name, email, and per-application
roles. The calling app verifies that JWT (via `INTERNAL_JWT_SECRET`, shared out of
band) and then mints its own session — this service is not involved in that app's
day-to-day session management.

See `src/routes/internal.routes.ts` for the full endpoint list.

## Roles are per-application

`Investor` / `Staff` / `Admin` are meaningful for the investor portal specifically —
the invoice app (and future apps) will likely need a different role set. Add new
applications and their allowed roles in `src/config/applications.ts`, then seed the
`Application` row (see `prisma/seed.ts`).

## Security notes

- Passwords: argon2id. TOTP secrets: AES-256-GCM at rest (`MFA_ENCRYPTION_KEY`).
- Account lockout: 5 failed attempts (password or MFA code) locks the account for 15
  minutes, independent of source IP. A per-route HTTP rate limiter adds a second layer
  against distributed attempts.
- Logging: `src/lib/logger.ts` redacts passwords/secrets/tokens/codes/phone numbers by
  key name, and `app.ts` overrides pino-http's default request/response serializers so
  headers and bodies are never logged at all — only method, URL, and status code.
- Audit log (`AuditLogEntry`) is append-only by construction: no update/delete route
  exists for it anywhere in the app.

## Not yet built

- Automated tests cover the pure logic (`tests/`) but not the full HTTP flow
  end-to-end (verified manually via curl during development — see project notes).
- No UI yet for managing `Application` rows or cross-app super-admin bootstrapping
  beyond the seed script.
