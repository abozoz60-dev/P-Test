"""TLS / certificate assessment (read-only).

Inspects the certificate and negotiated protocol on TLS ports. Flags expired or
near-expiry certificates and the availability of deprecated protocol versions
(TLS 1.0 / 1.1). Uses only standard handshakes; nothing destructive.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import socket
import ssl
from collections.abc import AsyncIterator

from app.scanners.base import Check, CheckContext, CheckFinding, register

TLS_PORTS = {443, 8443, 993, 995, 465}
LEGACY_PROTOCOLS = [
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
]


def _get_cert(host: str, port: int, timeout: float):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we inspect, we don't reject
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(binary_form=False), ssock.version(), ssock.getpeercert(binary_form=True)


def _legacy_supported(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except ValueError:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except (ssl.SSLError, OSError):
        return False


class TLSCheck(Check):
    id = "net.tls"
    name = "TLS/certificate assessment"
    category = "tls"
    description = "Certificate validity and deprecated protocol detection."
    safe = True

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckFinding]:
        tls_ports = [p for p in (ctx.open_ports or []) if p in TLS_PORTS] or (
            [443] if not ctx.open_ports else []
        )
        for port in tls_ports:
            asset = f"{ctx.host}:{port}"
            try:
                cert, version, _ = await asyncio.to_thread(
                    _get_cert, ctx.host, port, ctx.connect_timeout_sec
                )
            except (ssl.SSLError, OSError) as exc:
                yield CheckFinding(
                    vuln_id="PTEST-TLS-000", asset=asset, category="tls",
                    severity="informational", confidence="low",
                    title="TLS endpoint not reachable / handshake failed",
                    evidence=str(exc), status="suspected",
                )
                continue

            not_after = cert.get("notAfter")
            if not_after:
                try:
                    expiry = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=dt.timezone.utc
                    )
                    days = (expiry - dt.datetime.now(dt.timezone.utc)).days
                    if days < 0:
                        yield CheckFinding(
                            vuln_id="PTEST-TLS-001", asset=asset, category="tls",
                            severity="high", confidence="high",
                            title="TLS certificate expired",
                            evidence=f"notAfter={not_after} ({-days} days ago)",
                            impact="Clients see certificate errors; MITM harder to distinguish from outage.",
                            remediation="Renew the certificate and automate renewal (e.g. ACME).",
                            references="CWE-298; OWASP TLS Cheat Sheet", status="confirmed",
                        )
                    elif days < 21:
                        yield CheckFinding(
                            vuln_id="PTEST-TLS-002", asset=asset, category="tls",
                            severity="medium", confidence="high",
                            title="TLS certificate expiring soon",
                            evidence=f"notAfter={not_after} ({days} days remaining)",
                            impact="Imminent outage / trust errors if not renewed.",
                            remediation="Renew now and automate renewal.",
                            references="CWE-298", status="confirmed",
                        )
                except ValueError:
                    pass

            for label, ver in LEGACY_PROTOCOLS:
                if await asyncio.to_thread(_legacy_supported, ctx.host, port, ver, ctx.connect_timeout_sec):
                    yield CheckFinding(
                        vuln_id=f"PTEST-TLS-003-{label}", asset=asset, category="tls",
                        severity="medium", confidence="high",
                        title=f"Deprecated protocol {label} supported",
                        evidence=f"{label} handshake succeeded on {asset}.",
                        impact="Deprecated TLS versions have known weaknesses (BEAST, POODLE-class).",
                        remediation="Disable TLS 1.0/1.1; require TLS 1.2+ (prefer 1.3).",
                        references="CWE-327; OWASP TLS Cheat Sheet; PCI-DSS 4.0", status="confirmed",
                    )


register(TLSCheck)
