"""Target registration & authorization-record management.

Creating a target does NOT authorize scanning. An admin must explicitly approve
the authorization record. Scope is validated when parsed.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import db, require_role
from app.core import audit
from app.core.scope import parse_scope
from app.db.models import Role, Target, User
from app.schemas.models import TargetCreate, TargetOut

router = APIRouter(prefix="/api/targets", tags=["targets"])


@router.post("", response_model=TargetOut, status_code=201)
def create_target(
    body: TargetCreate,
    session: Session = Depends(db),
    operator: User = Depends(require_role(Role.operator)),
) -> Target:
    if not parse_scope(body.scope):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "Scope must contain at least one valid IP, CIDR, or hostname")
    if session.execute(select(Target).where(Target.name == body.name)).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Target name already exists")
    target = Target(
        name=body.name, scope=body.scope, owner_attestation=body.owner_attestation,
        authorization_ref=body.authorization_ref, created_by=operator.username,
        approved=False, enabled=True,
    )
    session.add(target)
    session.commit()
    session.refresh(target)
    audit.record(session, actor=operator.username, action="target.create",
                 target_ref=target.name, detail=f"scope={target.scope}")
    return target


@router.get("", response_model=list[TargetOut])
def list_targets(
    session: Session = Depends(db),
    _: User = Depends(require_role(Role.viewer)),
) -> list[Target]:
    return list(session.execute(select(Target)).scalars())


@router.post("/{target_id}/approve", response_model=TargetOut)
def approve_target(
    target_id: int,
    session: Session = Depends(db),
    admin: User = Depends(require_role(Role.admin)),
) -> Target:
    target = session.get(Target, target_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")
    if not target.owner_attestation and not target.authorization_ref:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Cannot approve without an owner attestation or authorization reference.",
        )
    target.approved = True
    target.approved_by = admin.username
    session.commit()
    session.refresh(target)
    audit.record(session, actor=admin.username, action="target.approve", target_ref=target.name)
    return target


@router.post("/{target_id}/disable", response_model=TargetOut)
def disable_target(
    target_id: int,
    session: Session = Depends(db),
    admin: User = Depends(require_role(Role.admin)),
) -> Target:
    target = session.get(Target, target_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")
    target.enabled = False
    session.commit()
    session.refresh(target)
    audit.record(session, actor=admin.username, action="target.disable", target_ref=target.name)
    return target
