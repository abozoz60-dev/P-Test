"""The hash-chained audit log must detect tampering."""
from __future__ import annotations

from app.core import audit
from app.db.base import SessionLocal, init_db
from app.db.models import AuditEvent


def test_tamper_detected():
    init_db()
    session = SessionLocal()
    try:
        a = audit.record(session, actor="admin", action="t.one")
        audit.record(session, actor="admin", action="t.two")
        audit.record(session, actor="admin", action="t.three")

        ok, bad = audit.verify_chain(session)
        assert ok and bad is None

        # Tamper with an earlier row's detail.
        row = session.get(AuditEvent, a.id)
        row.detail = "secretly edited"
        session.commit()

        ok, bad = audit.verify_chain(session)
        assert ok is False
        assert bad == a.id
    finally:
        session.close()
