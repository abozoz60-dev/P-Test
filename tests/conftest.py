"""Pytest fixtures. Sets an isolated temp SQLite DB BEFORE importing app code
(the engine is created at import time)."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

# Isolated DB + known bootstrap creds, set before app import.
_tmp = tempfile.mkdtemp(prefix="ptest-test-")
os.environ["PTEST_DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["PTEST_AUDIT_LOG_FILE"] = f"{_tmp}/audit.log"
os.environ["PTEST_BOOTSTRAP_ADMIN_USERNAME"] = "admin"
os.environ["PTEST_BOOTSTRAP_ADMIN_PASSWORD"] = "admin-pass"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import create_app  # noqa: E402


@pytest.fixture()
def client() -> TestClient:
    app = create_app()
    with TestClient(app) as c:
        yield c


def _token(client: TestClient, username: str, password: str) -> str:
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture()
def admin_headers(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(client, 'admin', 'admin-pass')}"}


@pytest.fixture()
def operator_headers(client: TestClient, admin_headers) -> dict[str, str]:
    client.post("/api/auth/users",
                json={"username": "op", "password": "op-pass", "role": "operator"},
                headers=admin_headers)
    return {"Authorization": f"Bearer {_token(client, 'op', 'op-pass')}"}
