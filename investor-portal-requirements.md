# Investor Document Portal — Requirements & Architecture

## Overview
A secure web portal for Michael's company where investors can log in and download
sensitive documents (tax forms, project reports) assigned specifically to them.

**Scale:** Under 50 investors. US-only.

---

## User Roles

| Role | Permissions |
|---|---|
| **Investor** | View/download only documents assigned to their own account |
| **Staff** | Upload documents, assign them to investor(s), manage investor accounts |
| **Admin** (Michael) | All staff permissions + manage staff accounts, view full audit log |

---

## Functional Requirements

### Authentication
- Email/password + MFA (TOTP or SMS) required for **all** accounts, investors included
- Password reset flow via email
- Session auto-expires after a period of inactivity (e.g., 30 minutes)
- Account lockout / rate limiting after repeated failed login attempts

### Document Management
- Staff upload documents (PDF primary; confirm if other formats needed)
- Each document assigned to one or more specific investors
- Documents categorized by type (tax document, project report, statement) and year/project
- Investor dashboard: filter/sort by year, type, project
- Version handling: ability to replace/supersede a document (e.g., corrected tax form) while preserving history
- Retention: define how long documents remain available (tax records often need years of retention — confirm requirement with an accountant/legal advisor)

### Downloads
- No permanent public URLs — all downloads via short-lived signed URLs
- Every download logged (who, what, when, IP address)

### Notifications
- Email notification to investor when a new document is uploaded for them

### Audit Log (Admin-only view)
- Login attempts (success/failure)
- Document uploads, assignments, deletions
- Document views/downloads

---

## Non-Functional Requirements

- **Encryption:** TLS in transit; encryption at rest for stored files and database
- **No sensitive data in logs:** application/error logs must never contain document contents, SSNs, or full tax details
- **Uptime:** standard best-effort (no need for multi-region redundancy at this scale)
- **Backups:** automated daily backups of database + file storage

---

## Proposed Architecture

**Hosting:** Railway (consistent with existing infrastructure — Michael's invoice automation app)

**Components:**
- **App/backend:** Node.js or Python (your call) — handles auth, permissions, signed URL generation
- **Database:** Postgres on Railway — stores users, roles, document metadata, audit log entries (never raw files)
- **File storage:** Dropbox (Business account, API access) — see "Dropbox as File Source" below. No separate S3/R2 needed.
- **Auth/Identity:** Shared internal admin service — see "Shared Admin Service" below
- **Email:** Transactional email provider (Postmark, Resend, SES) for notifications and password resets

**Why not self-host everything:** At <50 users, the cost savings of rolling your own auth or file storage aren't worth the security risk. Managed/shared services here are cheap and dramatically reduce what can go wrong.

---

## Dropbox as File Source

Rather than building a custom upload interface, the app reads documents directly from a
Dropbox folder Michael maintains — no new tool for him to learn.

**How it works:**
- Folder structure encodes assignment: `/Investors/[Investor Name]/[Year]/document.pdf`
- Backend uses the Dropbox API (not public share links) with a scoped service account/app token
- Dropbox webhooks (or periodic polling) detect new/changed files and sync metadata into Postgres
- **Investors never get raw Dropbox links.** The app fetches the file from Dropbox server-side and serves it through its own short-lived signed URL — this preserves audit logging and access control
- Basic validation on sync (e.g., flag files that land outside the expected folder structure) to catch misfiled documents before they reach an investor

**Requirements this adds:**
- Dropbox Business account with API access enabled
- A defined, documented folder-naming convention Michael's team commits to following
- Handling for edge cases: file renamed/moved, investor name doesn't match an existing account, duplicate filenames

---

## Shared Admin Service (used across Michael's apps)

Since the same people need the same access across every app built for Michael (not
per-app roles), a single shared internal service handles user identity and admin
management — used by the investor portal, the invoice automation app, and future apps.

**What it manages:**
- User directory: name, email, role, MFA enrollment
- Single admin UI for adding/removing users and resetting access — reused, not rebuilt, per app
- Each app authenticates against this shared service rather than maintaining its own user table

**Build note:** This is worth building as its own small service now, since the investor
portal is only the first of multiple apps planned. Retrofitting shared auth after two or
three apps already have their own user tables is considerably more painful than starting
with it.

---

## Open Questions to Resolve Before Build

1. What file types besides PDF, if any?
2. Required retention period for tax documents (check with accountant/legal)?
3. Should investors be able to see a history of past-year documents indefinitely, or should access be restricted after some period?
4. Any existing system (CRM, accounting software) this needs to pull investor data from, or will investor accounts be created manually by staff?
5. Branding/white-label requirements for the portal's look?

---

## Suggested Build Order (for Claude Code)

1. Build/stand up the shared admin service first (user directory, roles, MFA, admin UI) — this becomes reusable for future apps
2. Scaffold the investor portal app + database schema (documents, audit_log tables), authenticating against the shared admin service
3. Integrate Dropbox API: folder sync, webhook/polling for changes, metadata ingestion into Postgres
4. Build investor dashboard + signed-URL download flow (app fetches from Dropbox, serves via its own signed URL)
5. Add audit logging middleware (logins, document views/downloads, sync events)
6. Add email notifications
7. Security pass: rate limiting, session timeout, log sanitization review, Dropbox token scoping review
