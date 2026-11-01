"""HTTP security-hygiene checks (read-only GET requests).

Fetches the root document over HTTP/HTTPS and evaluates response security
headers and cookie flags. All requests are single, rate-limited GETs — no
fuzzing, no injection, no state change.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import httpx

from app.scanners.base import Check, CheckContext, CheckFinding, register

SECURITY_HEADERS = {
    "strict-transport-security": (
        "PTEST-WEB-HSTS", "medium",
        "Missing HSTS (Strict-Transport-Security)",
        "Browsers may use plaintext HTTP, enabling SSL-strip downgrade.",
        "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
        "CWE-319; OWASP Secure Headers Project",
    ),
    "content-security-policy": (
        "PTEST-WEB-CSP", "medium",
        "Missing Content-Security-Policy",
        "No CSP increases XSS blast radius and data-exfiltration risk.",
        "Define a restrictive CSP (default-src 'self'; avoid 'unsafe-inline').",
        "CWE-1021; OWASP Secure Headers Project",
    ),
    "x-content-type-options": (
        "PTEST-WEB-XCTO", "low",
        "Missing X-Content-Type-Options",
        "MIME sniffing can turn uploads/responses into script execution.",
        "Send `X-Content-Type-Options: nosniff`.",
        "CWE-16; OWASP Secure Headers Project",
    ),
    "x-frame-options": (
        "PTEST-WEB-XFO", "low",
        "Missing X-Frame-Options / frame-ancestors",
        "Page may be framed for clickjacking.",
        "Send `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.",
        "CWE-1021; OWASP Clickjacking Defense",
    ),
}


class HTTPHeaders(Check):
    id = "web.security_headers"
    name = "HTTP security headers & cookie flags"
    category = "web"
    description = "Evaluates response security headers and session cookie flags."
    safe = True

    def _schemes(self, ctx: CheckContext) -> list[tuple[str, int]]:
        pairs: list[tuple[str, int]] = []
        for p in (ctx.open_ports or [80, 443]):
            if p in (80, 8080, 3000, 9000):
                pairs.append(("http", p))
            elif p in (443, 8443):
                pairs.append(("https", p))
        return pairs or [("https", 443), ("http", 80)]

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckFinding]:
        async with httpx.AsyncClient(
            verify=False, timeout=ctx.connect_timeout_sec + 4,
            follow_redirects=True, headers={"User-Agent": "P-Test/1.0 (+authorized-assessment)"},
        ) as client:
            for scheme, port in self._schemes(ctx):
                url = f"{scheme}://{ctx.host}:{port}/"
                try:
                    resp = await client.get(url)
                except (httpx.HTTPError, OSError):
                    continue
                await asyncio.sleep(1.0 / max(ctx.http_rate_per_sec, 0.1))

                headers = {k.lower(): v for k, v in resp.headers.items()}
                for hdr, meta in SECURITY_HEADERS.items():
                    if hdr not in headers:
                        vid, sev, title, impact, remediation, refs = meta
                        yield CheckFinding(
                            vuln_id=vid, asset=url, category="web", service="http",
                            severity=sev, confidence="high", title=title,
                            evidence=f"GET {url} -> {resp.status_code}; header '{hdr}' absent.",
                            reproduction=f"curl -skI {url}",
                            impact=impact, remediation=remediation, references=refs,
                            status="confirmed",
                        )

                if "server" in headers and any(c.isdigit() for c in headers["server"]):
                    yield CheckFinding(
                        vuln_id="PTEST-WEB-BANNER", asset=url, category="web", service="http",
                        severity="informational", confidence="high",
                        title="Server version disclosed in banner",
                        evidence=f"Server: {headers['server']}",
                        impact="Version disclosure aids targeted exploitation of known CVEs.",
                        remediation="Suppress or genericise the Server header.",
                        references="CWE-200", status="confirmed",
                    )

                for raw in resp.headers.get_list("set-cookie"):
                    low = raw.lower()
                    name = raw.split("=", 1)[0].strip()
                    missing = [f for f in ("secure", "httponly") if f not in low]
                    if "samesite" not in low:
                        missing.append("samesite")
                    if missing:
                        yield CheckFinding(
                            vuln_id="PTEST-WEB-COOKIE", asset=url, category="web", service="http",
                            severity="medium", confidence="high",
                            title=f"Cookie '{name}' missing flags: {', '.join(missing)}",
                            evidence=f"Set-Cookie: {raw[:120]}",
                            impact="Session cookies without Secure/HttpOnly/SameSite are exposed "
                                   "to theft via XSS or plaintext transport and to CSRF.",
                            remediation="Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies.",
                            references="CWE-614; CWE-1004; OWASP Session Management Cheat Sheet",
                            status="confirmed",
                        )


register(HTTPHeaders)
