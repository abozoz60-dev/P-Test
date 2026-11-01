"""Scan runner: orchestrates checks with scope enforcement, cancellation,
and audit logging.

Flow per scan:
  1. Re-validate scope in the backend for the target host (defence in depth).
  2. For each selected check, run it, honouring the emergency stop and the
     per-scan cancel flag between checks.
  3. Persist findings and discovered assets; record audit events.
"""
from __future__ import annotations

import asyncio

from sqlalchemy.orm import Session

from app.core import audit
from app.core.config import get_settings
from app.core.scope import ScopeViolation, assert_in_scope, parse_scope
from app.db.models import (
    Asset,
    Finding,
    Scan,
    ScanStatus,
    Severity,
    Target,
    ValidationStatus,
    utcnow,
)
from app.scanners.base import CheckContext, get_check


def _scope_hosts(target: Target) -> list[str]:
    """Explicit single hosts/IPs in scope (we do not expand CIDRs to avoid
    sweeping large ranges automatically)."""
    hosts: list[str] = []
    for entry in parse_scope(target.scope):
        if isinstance(entry, str):
            hosts.append(entry)
        elif entry.num_addresses == 1:
            hosts.append(str(entry.network_address))
    return hosts


async def run_scan(session: Session, scan_id: int) -> None:
    scan = session.get(Scan, scan_id)
    if scan is None:
        return
    target = session.get(Target, scan.target_id)
    scan.status = ScanStatus.running
    session.commit()
    audit.record(session, actor=scan.operator, action="scan.start",
                 target_ref=target.name, detail=f"modules={scan.modules}")

    settings = get_settings()
    try:
        hosts = _scope_hosts(target)
        if not hosts:
            raise ScopeViolation(
                "Target scope has no explicit host/IP to scan. Add a single IP or "
                "hostname (CIDR ranges are not auto-expanded for safety)."
            )

        module_ids = [m.strip() for m in scan.modules.split(",") if m.strip()]
        # Deterministic order: discovery first (lower `order` runs first).
        module_ids.sort(key=lambda m: (get_check(m).order if get_check(m) else 100, m))
        for host in hosts:
            # Defence in depth: enforce scope again right before contact.
            assert_in_scope(session, host)
            ctx = CheckContext(
                host=host,
                http_rate_per_sec=settings.http_rate_per_sec,
                connect_timeout_sec=settings.connect_timeout_sec,
            )
            for module_id in module_ids:
                session.refresh(scan)
                if scan.cancel_requested or settings.emergency_stop:
                    scan.status = ScanStatus.cancelled
                    session.commit()
                    audit.record(session, actor=scan.operator, action="scan.cancelled",
                                 target_ref=target.name)
                    return
                check_cls = get_check(module_id)
                if check_cls is None:
                    continue
                check = check_cls()
                if not check.safe:
                    # This platform ships safe checks only; refuse anything else.
                    continue
                async for cf in check.run(ctx):
                    session.add(Finding(
                        scan_id=scan.id, vuln_id=cf.vuln_id, asset=cf.asset,
                        service=cf.service, category=cf.category,
                        severity=Severity(cf.severity), confidence=cf.confidence,
                        title=cf.title, evidence=cf.evidence, reproduction=cf.reproduction,
                        impact=cf.impact, remediation=cf.remediation, references=cf.references,
                        status=ValidationStatus(cf.status),
                    ))
                session.commit()

            # Record discovered open ports as assets.
            for port in ctx.open_ports:
                existing = session.query(Asset).filter_by(
                    target_id=target.id, host=host, port=port
                ).first()
                if existing:
                    existing.last_seen = utcnow()
                else:
                    session.add(Asset(target_id=target.id, host=host, port=port))
            session.commit()

        scan.status = ScanStatus.completed
        scan.finished_at = utcnow()
        session.commit()
        audit.record(session, actor=scan.operator, action="scan.complete",
                     target_ref=target.name,
                     detail=f"findings={session.query(Finding).filter_by(scan_id=scan.id).count()}")
    except ScopeViolation as exc:
        scan.status = ScanStatus.failed
        scan.error = f"scope violation: {exc}"
        scan.finished_at = utcnow()
        session.commit()
        audit.record(session, actor=scan.operator, action="scan.scope_violation",
                     target_ref=target.name, detail=str(exc))
    except Exception as exc:  # pragma: no cover - defensive
        scan.status = ScanStatus.failed
        scan.error = str(exc)
        scan.finished_at = utcnow()
        session.commit()
        audit.record(session, actor=scan.operator, action="scan.failed",
                     target_ref=target.name, detail=str(exc))


def run_scan_sync(session: Session, scan_id: int) -> None:
    asyncio.run(run_scan(session, scan_id))
