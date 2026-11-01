# Remediation Playbook

How to act on findings, plus review checklists for areas the automated checks
flag but that ultimately need human/server-side verification. Mark each finding's
status in the UI (`suspected → confirmed → fixed`, or `false_positive`).

## Automated findings

| Finding | Fix |
|---------|-----|
| `PTEST-NET-*` risky exposed service (telnet/MySQL/Redis/RDP/VNC/SMB/MSSQL/Postgres) | Bind to localhost/private interface; firewall/allowlist; require VPN/bastion for admin. Disable telnet entirely (use SSH). |
| `PTEST-TLS-001/002` cert expired / expiring | Renew; automate with ACME (certbot/caddy). |
| `PTEST-TLS-003` TLS 1.0/1.1 supported | Require TLS 1.2+ (prefer 1.3); disable legacy protocols/ciphers. |
| `PTEST-WEB-HSTS/CSP/XCTO/XFO` missing headers | Add the headers (values are in the finding's remediation). Start CSP in report-only, then enforce. |
| `PTEST-WEB-COOKIE` missing cookie flags | Set `Secure; HttpOnly; SameSite=Lax` (or `Strict`) on session cookies. |
| `PTEST-WEB-BANNER` version disclosure | Suppress/genericise the `Server` header and framework banners. |

## Server-side game integrity (review checklist)

The golden rule: **never trust the client** for authoritative state.

- **Movement/speed:** validate position deltas against max speed and elapsed time
  server-side; reject/clamp impossible moves; log repeat violations.
- **Combat:** compute damage, attack speed, and cooldowns on the server; the client
  only *requests* actions.
- **Economy:** make currency/drop/reward transactions atomic and server-authoritative;
  reconcile inventories; log large/abnormal swings.
- **Items/trading:** server owns item creation and trade settlement; guard against
  duplication via transactional, idempotent operations.
- **Packets:** validate size/structure/sequence; drop malformed input; rate-limit per
  connection; never deserialize untrusted data into executable paths.
- **Privilege separation:** enforce player/mod/admin checks server-side on every
  privileged action; never rely on hidden client UI.
- **Anomaly logging:** record abnormal movement/attack/inventory patterns and repeated
  protocol violations for review.

## Database (review checklist)

- Not reachable from the internet; app connects with least-privilege accounts.
- No wildcard `GRANT ALL`; separate read-only accounts for assessment/reporting.
- Credentials in a secret store, never in code/logs; TLS for remote connections.
- Parameterized queries everywhere (no string-built SQL); review app queries.
- Tested, access-controlled backups with a documented restore procedure.

## Host / OS (review checklist)

- Patch cadence; remove unused services; least-privilege service accounts.
- SSH: key-only auth, no root login, restricted source IPs. RDP behind VPN.
- Review scheduled tasks/startup services for unexpected persistence.
- Centralized security logging; time sync; file-integrity monitoring on key paths.

## DDoS readiness (defensive review — no attack traffic)

- Upstream/provider DDoS protection enabled; reverse proxy with connection and
  request-rate limits; SYN protections.
- Resource limits per connection; autoscaling or graceful-degradation plan.
- Monitoring on CPU/memory/bandwidth/connection counts with alerting.
- Written incident-response and recovery runbook; practice it.
> Any load/resilience test must have explicitly approved scope, rate limits, and a
> stop condition. This platform does **not** generate load.
