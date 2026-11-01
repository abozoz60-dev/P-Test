"""Shared FastAPI dependencies: DB session, current user, RBAC guards."""
from __future__ import annotations

from collections.abc import Iterator

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.core.security import resolve_token, role_at_least
from app.db.base import get_session
from app.db.models import Role, User


def db() -> Iterator[Session]:
    yield from get_session()


def current_user(
    authorization: str | None = Header(default=None),
    session: Session = Depends(db),
) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    user = resolve_token(session, token)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    return user


def require_role(required: Role):
    def _guard(user: User = Depends(current_user)) -> User:
        if not role_at_least(user, required):
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"Requires role >= {required.value}")
        return user
    return _guard
