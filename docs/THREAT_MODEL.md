# Threat Model — Game-Server / Web Infrastructure (owner self-assessment)

This models a self-hosted game-server environment (login server, game server,
website/control panel, database, and host OS) from the perspective of an **owner
assessing their own infrastructure**. It frames what the platform helps you find
and, just as importantly, the design principles the platform's findings point you
toward.

## Assets

| Asset | Why it matters |
|-------|----------------|
| Player accounts / credentials | Account takeover, fraud |
| Session tokens / auth server | Impersonation, privilege escalation |
| Game state (position, inventory, currency) | Economy integrity, fairness |
| Database (MySQL/MariaDB) | Mass data exposure, integrity loss |
| Website / control panel / payment pages | Fraud, defacement, data theft |
| Host OS / admin interfaces | Full compromise, persistence |

## Trust boundaries

1. **Client ↔ servers** — the game/web client is **untrusted**. This is the single
   most important boundary. The client can be modified; its claims about position,
   damage, speed, currency, inventory, and permissions must be re-validated
   server-side. Obfuscation and client-side anti-cheat are *not* a substitute.
2. **Internet ↔ exposed services** — only the services that must be public should be.
   Admin panels, DB ports, cache ports (Redis), and management services belong
   behind a VPN/bastion/firewall. (The `net.port_discovery` check surfaces risky
   exposed ports.)
3. **App ↔ database** — the app should connect with least privilege; the DB should
   not be reachable from the internet; secrets should not live in logs/config in cleartext.
4. **Player ↔ moderator ↔ admin** — privilege separation must be enforced server-side.

## Principal threats (STRIDE-ish)

- **Spoofing:** stolen/guessed credentials; missing rate-limiting/lockout; weak
  password-reset flows. → strong auth, lockout, safe recovery flows.
- **Tampering:** client-forged game state (speed/damage/currency/item dupe);
  malformed packets. → authoritative server-side validation of all critical state.
- **Repudiation:** no audit trail of abnormal movement/economy events. → server-side
  anomaly logging.
- **Information disclosure:** verbose banners, missing security headers, exposed DB,
  secrets in config/logs. → header hardening, banner suppression, secret hygiene.
- **Denial of service:** resource exhaustion, unthrottled endpoints. → connection
  limits, rate limits, upstream DDoS protection. (This platform assesses *readiness*;
  it does not generate attack traffic.)
- **Elevation of privilege:** IDOR/broken access control, admin interfaces exposed. →
  server-side authz checks, restricted admin surface.

## How this platform maps to the model (today)

| Threat area | Check / feature |
|-------------|-----------------|
| Exposed admin/DB/cache services | `net.port_discovery` (flags telnet/MySQL/Redis/RDP/VNC/SMB/MSSQL/Postgres exposure) |
| Transport weaknesses | `net.tls` (expired/near-expiry certs, TLS 1.0/1.1) |
| Web hygiene / disclosure | `web.security_headers` (HSTS, CSP, XCTO, XFO, cookie flags, server banner) |
| Authorization governance | RBAC + target approval + audit log |

Deeper game-protocol, database-privilege, and OS-hardening checks are described as
**review checklists** (not live-attack modules) in `docs/REMEDIATION_PLAYBOOK.md`
and tracked in `docs/LIMITATIONS.md` as future plugin work.
