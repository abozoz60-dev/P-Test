"""Scope enforcement — the backend safety gate.

Deny-by-default. A host may only be contacted by a check if it falls within the
scope of an *approved, enabled* Target. This is validated here, in the backend,
independently of any UI control. The scan runner calls `assert_in_scope()`
immediately before every network operation.

Scope entries may be:
  - an IPv4/IPv6 address            (e.g. 203.0.113.10)
  - a CIDR network                  (e.g. 203.0.113.0/24)
  - a hostname                      (e.g. game.example.com)

Hostnames are matched literally AND by resolved address against IP/CIDR entries
so a hostname cannot be used to smuggle traffic outside the authorized ranges.
"""
from __future__ import annotations

import ipaddress
import socket

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import Target


class ScopeViolation(Exception):
    """Raised when a host is not covered by an approved target's scope."""


def _parse_entry(entry: str):
    entry = entry.strip()
    if not entry:
        return None
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return entry.lower()  # treat as hostname


def parse_scope(scope: str) -> list:
    return [p for e in scope.split(",") if (p := _parse_entry(e)) is not None]


def _resolve(host: str) -> set[str]:
    try:
        infos = socket.getaddrinfo(host, None)
        return {i[4][0] for i in infos}
    except OSError:
        return set()


def host_in_scope(host: str, scope: str) -> bool:
    host = host.strip().lower()
    entries = parse_scope(scope)
    networks = [e for e in entries if not isinstance(e, str)]
    hostnames = [e for e in entries if isinstance(e, str)]

    if host in hostnames:
        return True

    candidate_ips: set[str] = set()
    try:
        candidate_ips.add(str(ipaddress.ip_address(host)))
    except ValueError:
        candidate_ips |= _resolve(host)

    for ip_str in candidate_ips:
        ip = ipaddress.ip_address(ip_str)
        for net in networks:
            if ip in net:
                return True
    return False


def resolve_authorized_target(session: Session, host: str) -> Target | None:
    """Return the approved/enabled Target whose scope covers `host`, else None."""
    settings = get_settings()
    stmt = select(Target).where(Target.enabled.is_(True))
    if settings.require_authorization_record:
        stmt = stmt.where(Target.approved.is_(True))
    for target in session.execute(stmt).scalars():
        if host_in_scope(host, target.scope):
            return target
    return None


def assert_in_scope(session: Session, host: str) -> Target:
    """Raise ScopeViolation unless `host` is within an approved target's scope.

    Also honours the global emergency stop.
    """
    if get_settings().emergency_stop:
        raise ScopeViolation("Emergency stop is engaged; no targets may be contacted.")
    target = resolve_authorized_target(session, host)
    if target is None:
        raise ScopeViolation(
            f"Host {host!r} is not within the scope of any approved, enabled target. "
            "Register and approve an authorization record first."
        )
    return target
