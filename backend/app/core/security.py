"""Authentication, token issuance, and RBAC primitives."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import AuthToken, Role, User, utcnow

# Role hierarchy for permission checks (higher includes lower).
_ROLE_RANK = {Role.viewer: 0, Role.operator: 1, Role.admin: 2}

# PBKDF2-HMAC-SHA256 password hashing (stdlib; no fragile native deps).
_PBKDF2_ITER = 240_000
_PBKDF2_ALGO = "pbkdf2_sha256"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITER)
    return f"{_PBKDF2_ALGO}${_PBKDF2_ITER}${salt.hex()}${dk.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algo, iter_s, salt_hex, dk_hex = password_hash.split("$")
        if algo != _PBKDF2_ALGO:
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iter_s))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except (ValueError, AttributeError):
        return False


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def role_at_least(user: User, required: Role) -> bool:
    return _ROLE_RANK[user.role] >= _ROLE_RANK[required]


def authenticate(session: Session, username: str, password: str) -> User | None:
    user = session.execute(
        select(User).where(User.username == username, User.is_active.is_(True))
    ).scalar_one_or_none()
    if user and verify_password(password, user.password_hash):
        return user
    return None


def issue_token(session: Session, user: User) -> str:
    raw = secrets.token_urlsafe(32)
    ttl = get_settings().token_ttl_minutes
    token = AuthToken(
        user_id=user.id,
        token_hash=_hash_token(raw),
        expires_at=utcnow() + timedelta(minutes=ttl),
    )
    session.add(token)
    session.commit()
    return raw


def resolve_token(session: Session, raw: str) -> User | None:
    row = session.execute(
        select(AuthToken).where(AuthToken.token_hash == _hash_token(raw))
    ).scalar_one_or_none()
    if row is None:
        return None
    exp = row.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp <= utcnow():
        return None
    return row.user


def ensure_bootstrap_admin(session: Session) -> None:
    """Create the bootstrap admin only if no users exist yet."""
    if session.execute(select(User).limit(1)).scalar_one_or_none() is not None:
        return
    s = get_settings()
    session.add(User(
        username=s.bootstrap_admin_username,
        password_hash=hash_password(s.bootstrap_admin_password),
        role=Role.admin,
    ))
    session.commit()
