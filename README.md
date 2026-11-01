# P-Test — Authorized Assessment Platform

A modular, **non-destructive** security-assessment platform for infrastructure
you **own or are explicitly authorized to test**. It performs safe discovery and
detection (TCP service discovery, TLS/certificate checks, HTTP security-header
and cookie hygiene), tracks findings and remediation, and enforces authorization
**in the backend** — not just in the UI.

> ### Scope & intent
> This tool is for **defensive security assessment of your own systems**.
> It deliberately **does not** include automated exploitation, data-destructive
> payloads, game item/currency manipulation, credential theft, or denial-of-service
> / load-generation tooling. It *detects* weaknesses and tells you how to fix them;
> it does not weaponize them. Deny-by-default: nothing is contacted unless it
> falls inside an **approved** target's scope.

## What's implemented and tested

| Area | Status |
|------|--------|
| Auth (login, bearer tokens) + RBAC (admin/operator/viewer) | ✅ tested |
| Target registration with authorization record + admin approval gate | ✅ tested |
| Backend scope enforcement (deny-by-default, IP/CIDR/hostname) | ✅ tested |
| Emergency stop (global kill switch) | ✅ tested |
| Tamper-evident hash-chained audit log | ✅ tested |
| Plugin check engine with deterministic ordering | ✅ tested |
| Checks: TCP discovery, TLS/cert, HTTP headers & cookies | ✅ tested (loopback e2e) |
| Findings model (severity, confidence, evidence, repro, impact, remediation, refs, status) | ✅ |
| Posture score (transparent methodology) | ✅ tested |
| Reports: JSON / CSV / HTML (PDF via browser print) | ✅ tested |
| Web dashboard (overview, targets, scans, findings, audit) | ✅ (browser-verified) |

See [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) for what is **not** built and why.

## Quick start (local, SQLite)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # edit secrets + bootstrap admin password
uvicorn app.main:app --app-dir backend --reload
```

Open http://127.0.0.1:8000/ and sign in with the bootstrap admin
(`PTEST_BOOTSTRAP_ADMIN_*`). Then:

1. **Targets →** register your host (e.g. scope `203.0.113.10`), attest ownership.
2. As admin, **Approve** the target (this is the authorization gate).
3. **Scans →** pick the target + modules → **Start scan**.
4. **Findings / Overview** show results; export from `/api/scans/{id}/report.html`.

## Run the tests

```bash
pip install -r requirements.txt
pytest -q          # 17 tests: scope, RBAC, emergency stop, audit chain, e2e scan, reports
```

## Docs

- [`docs/SAFETY.md`](docs/SAFETY.md) — the 12 safety controls and how each is enforced.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — threat model for the target environment.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system design.
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — Docker/Compose, Postgres, reverse proxy, PDF.
- [`docs/REMEDIATION_PLAYBOOK.md`](docs/REMEDIATION_PLAYBOOK.md) — fixing findings.
- [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) — known limits & unsupported checks.
- [`docs/sample-report/`](docs/sample-report/) — a real report from a loopback scan.

## Tech

FastAPI · SQLAlchemy 2.0 · SQLite (dev) / PostgreSQL (prod) · vanilla-JS dashboard
(no build step). The frontend is intentionally dependency-free so the whole
platform runs from one process; swap in React/TS per `docs/ARCHITECTURE.md` if desired.
