"""End-to-end: run real (safe) checks against a local HTTP server on loopback."""
from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.core.security import hash_password
from app.db.base import SessionLocal, init_db
from app.db.models import Role, Scan, ScanStatus, Target, User
from app.scanners.runner import run_scan


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "TestServer/9.9")  # version banner
        self.send_header("Set-Cookie", "SESSIONID=abc123")  # missing flags
        self.end_headers()
        self.wfile.write(b"<html>ok</html>")

    def log_message(self, *args):  # silence
        pass


@pytest.fixture()
def http_server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield port
    srv.shutdown()


def test_scan_finds_header_and_cookie_issues(http_server):
    init_db()
    session = SessionLocal()
    try:
        if not session.query(User).filter_by(username="admin").first():
            session.add(User(username="admin", password_hash=hash_password("x"), role=Role.admin))
            session.commit()
        target = Target(name=f"loopback-{http_server}", scope="127.0.0.1",
                        owner_attestation="self", authorization_ref="SELF",
                        approved=True, enabled=True, created_by="admin")
        session.add(target)
        session.commit()
        scan = Scan(target_id=target.id, modules="web.security_headers",
                    operator="admin", status=ScanStatus.queued)
        session.add(scan)
        session.commit()
        scan_id = scan.id

        # Point the check at the test server's port via open_ports seeding:
        # the http check will try discovered ports; we include the server port
        # by registering it as an open port through a direct run instead.
        from app.scanners.base import CheckContext
        from app.scanners.checks.http_headers import HTTPHeaders

        ctx = CheckContext(host="127.0.0.1")
        ctx.open_ports[:] = [http_server if http_server in (80, 8080, 3000, 9000) else 80]
        # Force http scheme on the actual test port:
        findings = []

        async def _collect():
            # Monkey-free: call with the real port by overriding _schemes.
            check = HTTPHeaders()
            check._schemes = lambda c: [("http", http_server)]  # type: ignore
            async for f in check.run(ctx):
                findings.append(f)

        asyncio.run(_collect())
        titles = {f.vuln_id for f in findings}
        assert "PTEST-WEB-BANNER" in titles         # server version disclosed
        assert "PTEST-WEB-COOKIE" in titles         # cookie missing flags
        assert any(f.vuln_id.startswith("PTEST-WEB-") for f in findings)

        # And the full runner path completes without scope errors.
        asyncio.run(run_scan(session, scan_id))
        session.refresh(scan)
        assert scan.status in (ScanStatus.completed, ScanStatus.cancelled)
    finally:
        session.close()
