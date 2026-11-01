# Deployment Guide

## Option A — Local (SQLite, no containers)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env         # set PTEST_SECRET_KEY + bootstrap admin password
uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

First run creates the schema and the bootstrap admin (only if no users exist).

## Option B — Docker Compose (PostgreSQL)

```bash
export PTEST_SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')"
export PTEST_BOOTSTRAP_ADMIN_PASSWORD="$(python3 -c 'import secrets;print(secrets.token_urlsafe(18))')"
docker compose up --build
```

- API is published on `127.0.0.1:8000` (loopback) by design — put a reverse proxy
  (nginx/Caddy/Traefik) in front for TLS and request limits before exposing it.
- The Postgres volume `ptest_pgdata` persists the platform DB. This DB is **separate**
  from any game/production database — keep it that way.

## Reverse proxy (example, Caddy)

```
assess.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

## Hardening the platform itself

- Change `PTEST_SECRET_KEY` and the bootstrap admin password immediately; create
  per-user accounts and demote/disable the bootstrap admin.
- Give operators the `operator` role, read-only stakeholders `viewer`.
- Keep `PTEST_REQUIRE_AUTHORIZATION_RECORD=true`.
- Restrict network egress of the container to the ranges you are authorized to test.
- Back up the Postgres volume; the audit chain lets you prove the log is intact.

## Optional tool integration

`nmap` is used automatically **if present** on the host; the platform works without
it (native async TCP connect scanner is the default). To enable it in the image,
uncomment the `apt-get install nmap` line in the `Dockerfile`. Integrations with
OWASP ZAP, Nuclei, OpenVAS, Trivy, and Semgrep are **not** bundled — see
`docs/LIMITATIONS.md` for how they would be added as gated plugins.

## PDF reports

HTML, CSV, and JSON exports are built in (`/api/scans/{id}/report.{html,csv,json}`).
For PDF, open the HTML report and use the browser's **Print → Save as PDF**, or
render headless:

```bash
# Chromium (already present in many environments)
chromium --headless --no-sandbox --print-to-pdf=report.pdf \
  "http://127.0.0.1:8000/api/scans/1/report.html"
```

## Backups & recovery

- Postgres: `pg_dump`/`pg_restore` the `ptest` database on a schedule.
- SQLite (dev): copy the `*.db` file while the service is stopped.
- Verify audit integrity after restore: `GET /api/audit` → `chain_intact: true`.
