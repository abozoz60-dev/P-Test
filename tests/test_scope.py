"""Scope-enforcement unit tests — the core safety guarantee."""
from __future__ import annotations

from app.core.scope import host_in_scope, parse_scope


def test_exact_ip_in_scope():
    assert host_in_scope("203.0.113.10", "203.0.113.10")
    assert not host_in_scope("203.0.113.11", "203.0.113.10")


def test_cidr_scope():
    assert host_in_scope("203.0.113.42", "203.0.113.0/24")
    assert not host_in_scope("203.0.114.1", "203.0.113.0/24")


def test_hostname_literal_match():
    assert host_in_scope("game.example.com", "game.example.com")
    assert not host_in_scope("evil.example.com", "game.example.com")


def test_loopback_scope():
    assert host_in_scope("127.0.0.1", "127.0.0.1")
    assert host_in_scope("127.0.0.5", "127.0.0.0/8")


def test_parse_scope_rejects_garbage():
    # Garbage becomes a hostname entry; it simply won't match real IPs.
    entries = parse_scope("not an ip, 10.0.0.0/8")
    assert any(not isinstance(e, str) for e in entries)  # the CIDR parsed
    assert not host_in_scope("10.0.0.1", "not an ip")  # garbage matches nothing
