# ShareLab

Trusted sharing of underused campus equipment and spaces. Zero-dependency Node.js backend with SQLite, plus a single-page frontend. Built to the ShareLab PRD.

## Run it

Requires **Node 22.5 or newer** (uses the built-in `node:sqlite`). No `npm install` needed.

    npm start            # http://localhost:3000
    npm test             # 21 end-to-end checks on a temporary database

Environment: `PORT` (default 3000), `DB_PATH` (default `./sharelab.db`), `DEMO_PASSWORD` (default `demo1234`, applied when the database is first seeded).

## Deploy free for a hackathon

A Render Blueprint is included in `render.yaml`. Push this repository to GitHub, then in Render choose **New → Blueprint** and connect the repository. Render will run `npm test` during build and `npm start` to launch the app.

**Important:** the free Render web service has an ephemeral filesystem. This app uses local SQLite, so its database and any changes can be lost after a restart, spin-down, or redeploy. This setup is suitable for a demo with seeded fictional accounts, not reliable persistent data. Free web services may also sleep after inactivity and take about a minute to wake up.

Node.js 22.5 or newer is required for the built-in `node:sqlite` module. Do not commit `sharelab.db`, `sharelab.db-wal`, or `sharelab.db-shm`; the `.gitignore` excludes them.

## Test credentials (password `demo1234`)

| Email | Role |
|---|---|
| student@demo | Student, verified for safety and electronics |
| student2@demo | Student, verified for safety, high usage (hits quota) |
| owner@demo | Verified resource owner |
| manager@demo | Lab manager (reviews, check-in, credentials) |
| admin@demo | Administrator (owner verification, global audit) |
| owner2@demo | Owner awaiting verification |

## Judge walkthrough (about 8 minutes)

1. Sign in as `owner2@demo`: listing is blocked. Sign in as `admin@demo`, open Admin, verify the owner. Back as `owner2@demo`, list a resource.
2. As `student@demo`, open the 3D Printer, pick a slot, watch the live checklist, submit. It goes to review.
3. As `manager@demo`, approve it. As the student, check in (record condition), then return it as "Worn".
4. Report a Damage incident. As `owner@demo`, decide it with reasoning. Open History on the booking for the hash-chained timeline.
5. Fairness: as `student2@demo`, request the same slot. The request is waitlisted with a stated reason. Cancel the original booking and the waitlisted request is promoted and notified.
6. Negative paths: request the CNC Router without credentials (blocked), or an overlapping slot (waitlisted, never double booked).
7. As `admin@demo`, use Verify chain in the Admin tab.

## Architecture

- `server.js`: HTTP server, SQLite schema, business rules, role checks, audit chain, background jobs.
- `public/index.html`: single-page UI. It only renders state and calls the API.
- All rules (eligibility, quota, conflicts, waiting-list order, permissions) run on the server. Each action runs in one transaction, so concurrent requests cannot double-book a slot.

API: `POST /api/login`, `POST /api/logout`, `GET /api/state` (filtered by role), `GET /api/precheck`, `GET /api/verify` (admin), `POST /api/act` with `a` = submit, approve, reject, wl, cancel, ci, co, inc, resolve, credreq, credok, credno, vown, newres, readnotif, reset.

## PRD coverage

Listings, search and filters, verified owners, credential verification, eligibility checks, approval / rejection / waiting list, conflict prevention, quotas and fair-use score, check-in and return with condition records, incidents with human decisions, in-app notifications (including reminder and overdue jobs), role-based access, hash-chained audit log, privacy by data filtering.

## Security and privacy

scrypt password hashing, random session tokens with expiry, login rate limiting, server-side authorisation on every action, input validation and length limits, parameterised SQL, output escaping in the UI, users only receive their own bookings and records. Demo data is fictional.

## Known limitations

No file or photo upload (condition notes are text), no email delivery (in-app notifications only), no SSO, single institution, simple heuristic fair-use formula, manager assignment uses the first manager. Rule-based only: no AI features are included, so every access, safety and penalty decision is made by a person.

## Disclosure

No templates or pre-existing code. Google Fonts are loaded from a CDN for typography. Built with AI assistance (Claude), to be disclosed in the submission.
