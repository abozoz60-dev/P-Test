"""Plugin architecture for security checks.

A Check is a self-contained, non-destructive assessment module. Each check
declares metadata and yields CheckFinding objects. Checks must only touch hosts
passed to them by the runner (which has already enforced scope) and must never
perform destructive, exploitative, or denial-of-service actions.
"""
from __future__ import annotations

import abc
from collections.abc import AsyncIterator
from dataclasses import dataclass, field


@dataclass
class CheckContext:
    host: str
    # Open ports discovered so far this scan (populated by discovery check).
    open_ports: list[int] = field(default_factory=list)
    http_rate_per_sec: float = 5.0
    connect_timeout_sec: float = 3.0


@dataclass
class CheckFinding:
    vuln_id: str
    asset: str
    category: str
    severity: str            # informational|low|medium|high|critical
    title: str
    confidence: str = "medium"
    service: str = ""
    evidence: str = ""
    reproduction: str = ""
    impact: str = ""
    remediation: str = ""
    references: str = ""
    status: str = "suspected"


class Check(abc.ABC):
    id: str = ""
    name: str = ""
    category: str = ""
    description: str = ""
    # Lower runs first. Discovery checks (which populate open_ports that later
    # checks depend on) use a low value so ordering is deterministic regardless
    # of the order the operator selected modules.
    order: int = 100
    # If True, the check is read-only / non-destructive. Only safe checks run
    # unless an intrusive check is explicitly approved (not implemented here by
    # design — this platform ships safe checks only).
    safe: bool = True

    @abc.abstractmethod
    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckFinding]:  # pragma: no cover
        raise NotImplementedError
        yield  # type: ignore[unreachable]


_REGISTRY: dict[str, type[Check]] = {}


def register(cls: type[Check]) -> type[Check]:
    if not cls.id:
        raise ValueError(f"Check {cls.__name__} must define an id")
    if cls.id in _REGISTRY:
        raise ValueError(f"Duplicate check id: {cls.id}")
    _REGISTRY[cls.id] = cls
    return cls


def all_checks() -> dict[str, type[Check]]:
    return dict(_REGISTRY)


def get_check(check_id: str) -> type[Check] | None:
    return _REGISTRY.get(check_id)
