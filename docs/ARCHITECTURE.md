# Architecture

```
                         ┌─────────────────────────────┐
  Browser ──────────────▶│  FastAPI app (app.main)      │
   (vanilla-JS SPA        │                              │
    served at / )         │  api/   auth, targets,       │
                          │         scans, findings,     │
                          │         reports, system      │
                          │                              │
                          │  core/  config               │
                          │         security  (RBAC)     │
                          │         scope     (GATE) ◀────┼─ deny-by-default
                          │         audit     (hash chain)│
                          │                              │
                          │  scanners/ base (registry)   │
                          │            runner            │
                          │            checks/*          │
                          │                              │
                          │  db/    SQLAlchemy models    │
                          └───────────────┬──────────────┘
                                          │
                                 ┌────────▼─────────┐
                                 │ Platform DB      │  (SQLite dev / Postgres prod)
                                 │ targets, scans,  │  SEPARATE from any game DB
                                 │ findings, assets,│
                                 │ users, tokens,   │
                                 │ audit_events     │
                                 └──────────────────┘
```

## Request/scan flow

1. **Auth** — `POST /api/auth/login` → bearer token (random, stored hashed with
   expiry). `deps.current_user` resolves it; `require_role(...)` guards each route.
2. **Register target** — operator creates a `Target` (scope + authorization record).
   Created targets are **unapproved** and therefore out of scope.
3. **Approve** — an admin approves (requires attestation/authorization ref). Now the
   scope is live.
4. **Create scan** — `scans.create_scan` validates modules, then calls
   `scope.assert_in_scope()` for each explicit host **before** queueing.
5. **Run** — `runner.run_scan` re-enforces scope per host (defence in depth), runs
   checks in deterministic order (discovery first), persists `Finding`s and `Asset`s,
   and honours cancel/emergency-stop between checks.
6. **Report** — findings feed the posture score, the dashboard, and JSON/CSV/HTML exports.

## Plugin model

A check subclasses `scanners.base.Check`, sets metadata (`id`, `category`,
`order`, `safe`), and yields `CheckFinding`s from `run(ctx)`. `@register` adds it to
the registry; importing `scanners.checks` registers the bundled set. The runner
**refuses to run any check with `safe is False`** — this platform ships safe checks only.

To add a check: create `backend/app/scanners/checks/my_check.py`, subclass `Check`,
`register(MyCheck)`, and import it in `checks/__init__.py`. It appears automatically
in `GET /api/checks` and the scan UI.

## Data model (platform metadata only)

`User`, `AuthToken`, `Target`, `Scan`, `Asset`, `Finding`, `AuditEvent`. No
production/game data is stored or proxied. See `backend/app/db/models.py`.

## Frontend

A dependency-free SPA (`frontend/index.html` + `app.js` + `styles.css`) served by
FastAPI. It is intentionally build-step-free so the platform runs from one process.
The spec's React/TypeScript option can replace `frontend/` and call the same REST API
(`/api/*`); no backend change is required — point a Vite/React build's `dist/` at the
static mount or serve it separately and enable CORS.

## Production notes

- Use PostgreSQL (`PTEST_DATABASE_URL=postgresql+psycopg://...`).
- Front the API with a reverse proxy (TLS, request limits). The compose file binds
  the API to loopback by default.
- Run background scans via the included FastAPI `BackgroundTasks`; for heavier
  concurrency, move `runner.run_scan` behind a task queue (e.g. Celery/RQ) — the
  runner is already an `async` function taking a session + scan id.
