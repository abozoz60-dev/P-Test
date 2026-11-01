"""Non-destructive TCP service discovery.

Performs rate-limited async TCP *connect* probes (full 3-way handshake, then
immediate close) against a bounded list of common ports. This is a standard
discovery technique, equivalent to `nmap -sT`, and is read-only. It records
open ports into the context so later checks (TLS, HTTP) know where to look.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from app.scanners.base import Check, CheckContext, CheckFinding, register

# Common service ports (incl. typical Metin2 login/game/db/web/admin ports).
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 1433: "mssql",
    3000: "http-alt", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9000: "http-alt", 11000: "metin2-auth", 13000: "metin2-game",
    13001: "metin2-game", 13002: "metin2-game", 27015: "game",
}

# Ports that are risky to expose to the public internet.
RISKY_EXPOSED = {
    23: ("Telnet exposed", "critical", "CWE-319"),
    3306: ("MySQL/MariaDB exposed", "high", "CWE-668"),
    5432: ("PostgreSQL exposed", "high", "CWE-668"),
    6379: ("Redis exposed (often unauthenticated)", "critical", "CWE-306"),
    1433: ("MSSQL exposed", "high", "CWE-668"),
    5900: ("VNC exposed", "high", "CWE-284"),
    3389: ("RDP exposed", "medium", "CWE-284"),
    445: ("SMB exposed", "high", "CWE-668"),
}


class PortDiscovery(Check):
    id = "net.port_discovery"
    name = "TCP service discovery"
    category = "infrastructure"
    description = "Rate-limited TCP connect discovery of common service ports."
    safe = True
    order = 0  # must run before TLS/HTTP checks that consume open_ports

    async def _probe(self, host: str, port: int, timeout: float, sem: asyncio.Semaphore) -> bool:
        async with sem:
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return True
            except (asyncio.TimeoutError, OSError):
                return False

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckFinding]:
        sem = asyncio.Semaphore(max(1, int(ctx.http_rate_per_sec * 2)))
        ports = list(COMMON_PORTS)
        results = await asyncio.gather(
            *(self._probe(ctx.host, p, ctx.connect_timeout_sec, sem) for p in ports)
        )
        open_ports = [p for p, is_open in zip(ports, results) if is_open]
        ctx.open_ports[:] = open_ports

        for port in open_ports:
            service = COMMON_PORTS.get(port, "unknown")
            if port in RISKY_EXPOSED:
                title, sev, cwe = RISKY_EXPOSED[port]
                yield CheckFinding(
                    vuln_id=f"PTEST-NET-{port}",
                    asset=f"{ctx.host}:{port}",
                    service=service,
                    category="infrastructure",
                    severity=sev,
                    confidence="high",
                    title=title,
                    evidence=f"TCP connect to {ctx.host}:{port} ({service}) succeeded.",
                    reproduction=f"Connect to {ctx.host}:{port} with a TCP client (e.g. `nc {ctx.host} {port}`).",
                    impact="Administrative/data services reachable from untrusted networks "
                           "increase attack surface for brute force and known-CVE exploitation.",
                    remediation="Bind the service to localhost or a private interface, restrict "
                                "with a firewall/allowlist, and require a VPN/bastion for admin access.",
                    references=f"{cwe}; OWASP ASVS V1.14; CIS network hardening",
                    status="confirmed",
                )
            else:
                yield CheckFinding(
                    vuln_id=f"PTEST-NET-INV-{port}",
                    asset=f"{ctx.host}:{port}",
                    service=service,
                    category="infrastructure",
                    severity="informational",
                    confidence="high",
                    title=f"Open port {port}/{service}",
                    evidence=f"TCP connect to {ctx.host}:{port} succeeded.",
                    impact="Inventory item for attack-surface review.",
                    remediation="Confirm the service is required and intentionally exposed.",
                    references="OWASP ASVS V1.14",
                    status="confirmed",
                )


register(PortDiscovery)
