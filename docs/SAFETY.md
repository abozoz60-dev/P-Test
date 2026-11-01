# Safety Controls

These are the mandatory controls and exactly how each is enforced in this
codebase. Scope restrictions are validated in the **backend**, never only in the UI.

| # | Control | Where it lives | Enforced how |
|---|---------|----------------|--------------|
| 1 | Explicit target allowlisting | `app/core/scope.py`, `Target` model | Deny-by-default. A host is in scope only if it falls within an **approved, enabled** target's scope (IP/CIDR/hostname). |
| 2 | Written authorization & scope records | `Target.owner_attestation`, `Target.authorization_ref` | Approval (`POST /api/targets/{id}/approve`) is refused unless an attestation or authorization reference is present. |
| 3 | Deny-by-default network access | `scope.assert_in_scope()` | Called at scan-creation **and** again in the runner immediately before each host is contacted (defence in depth). |
| 4 | No scanning of out-of-scope IPs/domains | `scope.host_in_scope()` | Hostnames are matched literally **and** by resolved IP against CIDRs, so a hostname can't smuggle traffic outside the ranges. |
| 5 | Configurable scan intensity & concurrency | `config.Settings` | `max_scan_concurrency`, `port_scan_rate_per_sec`, `http_rate_per_sec`, `max_ports_per_host`. |
| 6 | Rate limits & timeouts | checks + `config` | HTTP checks sleep between requests; connect timeouts bound every probe. |
| 7 | Safe, non-destructive checks by default | `Check.safe`, runner | The runner **skips any check where `safe is False`**. All bundled checks are read-only. |
| 8 | Approval gates for intrusive validation | `Target.approved`, RBAC | Only `admin` can approve targets; only `operator`+ can launch scans. Intrusive/exploit checks are not shipped at all. |
| 9 | Emergency stop & cancellation | `config.emergency_stop`, `Scan.cancel_requested` | Global kill switch blocks new scans and halts running ones between checks; per-scan cancel via `POST /api/scans/{id}/cancel`. |
| 10 | Scan audit logs (operator, target, time, modules, results) | `app/core/audit.py` | Every auth event, target change, scan lifecycle event, and scope decision is recorded. |
| 11 | Protection against credential/PII exposure | design | Platform DB stores assessment metadata only; it never stores or proxies production/game data. Tokens and passwords are stored **hashed** (PBKDF2 / SHA-256). Runtime DBs and logs are git-ignored. |
| 12 | No auto-exploitation / persistence / destructive payloads / uncontrolled DoS | design | Not implemented by design. See `docs/LIMITATIONS.md`. |

## Tamper-evident audit log

`audit_events` is a SHA-256 **hash chain**: each row's `entry_hash =
sha256(prev_hash + canonical(payload))`. Any later insert/delete/edit breaks the
chain. `GET /api/audit` reports `chain_intact` and the first bad id; the test
`tests/test_audit_tamper.py` proves tampering is detected.

## Operating rules (for the human operator)

- Only register and approve targets you **own** or have **written authorization** to test.
- Keep the platform DB separate from any game/production DB (the default config does).
- Review the audit log after each engagement; export reports for your records.
- If anything looks wrong, hit **Emergency stop** (admin) — it blocks new scans and
  stops running ones at the next check boundary.
