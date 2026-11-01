"""P-Test Assessment Platform — FastAPI entrypoint."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import auth, findings, reports, scans, system, targets
from app.core.config import get_settings
from app.db.base import SessionLocal, init_db
from app.core.security import ensure_bootstrap_admin
from app.scanners import checks as _checks  # noqa: F401  (registers checks)

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, version="0.1.0")

    @app.on_event("startup")
    def _startup() -> None:
        init_db()
        session = SessionLocal()
        try:
            ensure_bootstrap_admin(session)
        finally:
            session.close()

    @app.get("/healthz", tags=["system"])
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(auth.router)
    app.include_router(targets.router)
    app.include_router(scans.router)
    app.include_router(reports.router)
    app.include_router(findings.router)
    app.include_router(system.router)

    if FRONTEND_DIR.exists():
        app.mount("/app", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")

        @app.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(str(FRONTEND_DIR / "index.html"))

    return app


app = create_app()
