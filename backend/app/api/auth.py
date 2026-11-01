"""Authentication and user-management routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import current_user, db, require_role
from app.core import audit
from app.core.security import authenticate, hash_password, issue_token
from app.db.models import Role, User
from app.schemas.models import LoginRequest, TokenResponse, UserCreate, UserOut

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, session: Session = Depends(db)) -> TokenResponse:
    user = authenticate(session, body.username, body.password)
    if user is None:
        audit.record(session, actor=body.username, action="auth.login_failed")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    token = issue_token(session, user)
    audit.record(session, actor=user.username, action="auth.login_ok")
    return TokenResponse(access_token=token, role=user.role)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)) -> User:
    return user


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreate,
    session: Session = Depends(db),
    admin: User = Depends(require_role(Role.admin)),
) -> User:
    if session.execute(select(User).where(User.username == body.username)).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already exists")
    user = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    session.add(user)
    session.commit()
    session.refresh(user)
    audit.record(session, actor=admin.username, action="user.create",
                 target_ref=user.username, detail=f"role={user.role.value}")
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(
    session: Session = Depends(db),
    admin: User = Depends(require_role(Role.admin)),
) -> list[User]:
    return list(session.execute(select(User)).scalars())
