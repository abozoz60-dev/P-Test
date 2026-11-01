"""Tamper-evident audit logging via a SHA-256 hash chain.

Every security-relevant action (auth, target approval, scan start/stop, scope
decisions) is recorded. Each entry chains to the previous entry's hash, so any
later insertion, deletion, or edit breaks the chain and is detectable with
`verify_chain()`. Entries are also mirrored to an append-only file.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import AuditEvent, utcnow

GENESIS = "0" * 64


def _ts_key(ts: datetime) -> str:
    """Stable timestamp key independent of DB tz round-trip quirks.

    SQLite returns naive datetimes; we created them tz-aware UTC. Normalise to
    naive-UTC microsecond isoformat so the hash is identical on both sides.
    """
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    return ts.isoformat(timespec="microseconds")


def _canonical(actor: str, action: str, target_ref: str, detail: str, ts: datetime) -> str:
    return json.dumps(
        {"ts": _ts_key(ts), "actor": actor, "action": action,
         "target_ref": target_ref, "detail": detail},
        sort_keys=True,
        separators=(",", ":"),
    )


def _last_hash(session: Session) -> str:
    row = session.execute(
        select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)
    ).scalar_one_or_none()
    return row.entry_hash if row else GENESIS


def record(session: Session, *, actor: str, action: str, target_ref: str = "", detail: str = "") -> AuditEvent:
    ts = utcnow()
    prev = _last_hash(session)
    payload = _canonical(actor, action, target_ref, detail, ts)
    entry_hash = hashlib.sha256((prev + payload).encode()).hexdigest()
    event = AuditEvent(
        ts=ts, actor=actor, action=action, target_ref=target_ref,
        detail=detail, prev_hash=prev, entry_hash=entry_hash,
    )
    session.add(event)
    session.commit()
    session.refresh(event)
    _mirror_to_file(event)
    return event


def _mirror_to_file(event: AuditEvent) -> None:
    try:
        with open(get_settings().audit_log_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "id": event.id, "ts": event.ts.isoformat(), "actor": event.actor,
                "action": event.action, "target_ref": event.target_ref,
                "detail": event.detail, "entry_hash": event.entry_hash,
            }) + "\n")
    except OSError:
        pass  # file mirror is best-effort; DB chain is authoritative


def verify_chain(session: Session) -> tuple[bool, int | None]:
    """Return (ok, first_bad_id). ok=True means the chain is intact."""
    prev = GENESIS
    for event in session.execute(select(AuditEvent).order_by(AuditEvent.id.asc())).scalars():
        payload = _canonical(event.actor, event.action, event.target_ref, event.detail, event.ts)
        expected = hashlib.sha256((prev + payload).encode()).hexdigest()
        if event.prev_hash != prev or event.entry_hash != expected:
            return False, event.id
        prev = event.entry_hash
    return True, None
