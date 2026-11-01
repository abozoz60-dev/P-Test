"""Findings retrieval, filtering, and validation-status updates."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import db, require_role
from app.core import audit
from app.db.models import Finding, Role, Severity, User, ValidationStatus
from app.schemas.models import FindingOut, FindingStatusUpdate

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("", response_model=list[FindingOut])
def list_findings(
    session: Session = Depends(db),
    _: User = Depends(require_role(Role.viewer)),
    scan_id: int | None = None,
    severity: Severity | None = None,
    category: str | None = None,
    valstatus: ValidationStatus | None = Query(default=None),
) -> list[Finding]:
    stmt = select(Finding)
    if scan_id is not None:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if severity is not None:
        stmt = stmt.where(Finding.severity == severity)
    if category is not None:
        stmt = stmt.where(Finding.category == category)
    if valstatus is not None:
        stmt = stmt.where(Finding.status == valstatus)
    return list(session.execute(stmt.order_by(Finding.id.desc())).scalars())


@router.patch("/{finding_id}", response_model=FindingOut)
def update_status(
    finding_id: int,
    body: FindingStatusUpdate,
    session: Session = Depends(db),
    operator: User = Depends(require_role(Role.operator)),
) -> Finding:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    finding.status = body.status
    session.commit()
    session.refresh(finding)
    audit.record(session, actor=operator.username, action="finding.status_update",
                 target_ref=finding.vuln_id, detail=f"status={body.status.value}")
    return finding
