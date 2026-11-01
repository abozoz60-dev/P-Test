"""Scan lifecycle: create (with backend scope re-check), run, cancel, inspect."""
from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import db, require_role
from app.core import audit
from app.core.config import get_settings
from app.core.scope import ScopeViolation, assert_in_scope, parse_scope
from app.db.base import SessionLocal
from app.db.models import Role, Scan, ScanStatus, Target, User
from app.scanners.base import all_checks
from app.scanners.runner import run_scan_sync
from app.schemas.models import ScanCreate, ScanOut

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _background_run(scan_id: int) -> None:
    session = SessionLocal()
    try:
        run_scan_sync(session, scan_id)
    finally:
        session.close()


@router.post("", response_model=ScanOut, status_code=201)
def create_scan(
    body: ScanCreate,
    background: BackgroundTasks,
    session: Session = Depends(db),
    operator: User = Depends(require_role(Role.operator)),
) -> Scan:
    if get_settings().emergency_stop:
        raise HTTPException(status.HTTP_423_LOCKED, "Emergency stop is engaged")

    target = session.get(Target, body.target_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")

    valid = set(all_checks())
    unknown = [m for m in body.modules if m not in valid]
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"Unknown modules: {', '.join(unknown)}")

    # Backend scope gate at creation time (not only in the UI).
    hosts = [e if isinstance(e, str) else str(e.network_address)
             for e in parse_scope(target.scope)
             if isinstance(e, str) or e.num_addresses == 1]
    if not hosts:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "Target scope has no explicit host/IP to scan.")
    try:
        for host in hosts:
            assert_in_scope(session, host)
    except ScopeViolation as exc:
        audit.record(session, actor=operator.username, action="scan.rejected_scope",
                     target_ref=target.name, detail=str(exc))
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc

    scan = Scan(target_id=target.id, modules=",".join(body.modules),
                operator=operator.username, status=ScanStatus.queued)
    session.add(scan)
    session.commit()
    session.refresh(scan)
    audit.record(session, actor=operator.username, action="scan.queued",
                 target_ref=target.name, detail=f"modules={scan.modules}")
    background.add_task(_background_run, scan.id)
    return scan


@router.get("", response_model=list[ScanOut])
def list_scans(session: Session = Depends(db), _: User = Depends(require_role(Role.viewer))) -> list[Scan]:
    return list(session.execute(select(Scan).order_by(Scan.id.desc())).scalars())


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, session: Session = Depends(db),
             _: User = Depends(require_role(Role.viewer))) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return scan


@router.post("/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(scan_id: int, session: Session = Depends(db),
                operator: User = Depends(require_role(Role.operator))) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    scan.cancel_requested = True
    if scan.status == ScanStatus.queued:
        scan.status = ScanStatus.cancelled
    session.commit()
    session.refresh(scan)
    audit.record(session, actor=operator.username, action="scan.cancel_requested",
                 target_ref=str(scan.target_id))
    return scan
