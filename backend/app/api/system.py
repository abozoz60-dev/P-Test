"""System routes: available checks, audit log + integrity, emergency stop,
and the security-posture summary used by the dashboard."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import db, require_role
from app.core import audit
from app.core.config import get_settings
from app.db.models import Finding, Role, Scan, Severity, Target, User
from app.scanners.base import all_checks
from app.schemas.models import CheckOut

router = APIRouter(prefix="/api", tags=["system"])

# Posture scoring weights per severity (higher = worse).
_WEIGHTS = {
    Severity.critical: 40, Severity.high: 20, Severity.medium: 8,
    Severity.low: 3, Severity.informational: 0,
}


@router.get("/checks", response_model=list[CheckOut])
def list_checks(_: User = Depends(require_role(Role.viewer))) -> list[CheckOut]:
    return [
        CheckOut(id=c.id, name=c.name, category=c.category,
                 description=c.description, safe=c.safe)
        for c in all_checks().values()
    ]


@router.get("/audit")
def list_audit(session: Session = Depends(db), _: User = Depends(require_role(Role.admin))):
    ok, bad = audit.verify_chain(session)
    from app.db.models import AuditEvent
    events = session.execute(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(200)).scalars()
    return {
        "chain_intact": ok,
        "first_bad_id": bad,
        "events": [
            {"id": e.id, "ts": e.ts.isoformat(), "actor": e.actor, "action": e.action,
             "target_ref": e.target_ref, "detail": e.detail, "entry_hash": e.entry_hash}
            for e in events
        ],
    }


@router.get("/emergency-stop")
def emergency_status(_: User = Depends(require_role(Role.viewer))):
    return {"emergency_stop": get_settings().emergency_stop}


@router.post("/emergency-stop")
def set_emergency_stop(engage: bool, session: Session = Depends(db),
                       admin: User = Depends(require_role(Role.admin))):
    # Runtime-mutable flag on the cached settings instance.
    get_settings().emergency_stop = engage
    audit.record(session, actor=admin.username, action="system.emergency_stop",
                 detail=f"engage={engage}")
    return {"emergency_stop": engage}


@router.get("/posture")
def posture(session: Session = Depends(db), _: User = Depends(require_role(Role.viewer))):
    """Transparent posture score: 100 minus weighted active findings, floored at 0.

    Only non-false-positive, non-fixed findings count.
    """
    from app.db.models import ValidationStatus
    rows = session.execute(
        select(Finding.severity, func.count()).where(
            Finding.status.notin_([ValidationStatus.false_positive, ValidationStatus.fixed])
        ).group_by(Finding.severity)
    ).all()
    by_sev = {sev.value: count for sev, count in rows}
    penalty = sum(_WEIGHTS[sev] * by_sev.get(sev.value, 0) for sev in Severity)
    score = max(0, 100 - penalty)
    return {
        "score": score,
        "methodology": "100 - sum(weight[severity] * active_findings); "
                       "weights critical=40 high=20 medium=8 low=3 info=0; floored at 0.",
        "by_severity": by_sev,
        "totals": {
            "targets": session.scalar(select(func.count()).select_from(Target)),
            "scans": session.scalar(select(func.count()).select_from(Scan)),
            "findings": session.scalar(select(func.count()).select_from(Finding)),
        },
    }
