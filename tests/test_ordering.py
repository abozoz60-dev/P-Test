"""Discovery checks must run before checks that consume their output."""
from __future__ import annotations

from app.scanners.base import get_check


def test_discovery_orders_first():
    disc = get_check("net.port_discovery")
    web = get_check("web.security_headers")
    tls = get_check("net.tls")
    assert disc.order < web.order
    assert disc.order < tls.order


def test_runner_sorts_modules_discovery_first():
    modules = ["web.security_headers", "net.tls", "net.port_discovery"]
    modules.sort(key=lambda m: (get_check(m).order if get_check(m) else 100, m))
    assert modules[0] == "net.port_discovery"
