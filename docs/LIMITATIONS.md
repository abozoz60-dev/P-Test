# Known Limitations & Unsupported Checks

Being explicit about what this platform does **not** do is part of using it responsibly.

## Deliberately not built (out of scope by design)

These are excluded on purpose — this is a defensive/authorized-assessment tool, not
an attack framework:

- **Automated exploitation** of any vulnerability (SQLi data extraction/modification,
  RCE, auth bypass execution, etc.). The platform *detects* and *advises*; it does not
  weaponize.
- **Game item duplication / currency manipulation / speed-hack exploitation.** The
  platform describes how to *validate server-side* against these (see the remediation
  playbook); it does not perform them.
- **Credential theft / brute-force / password spraying.**
- **Persistence, backdoors, or destructive payloads.**
- **Denial-of-service / load generation / stress testing.** Readiness is assessed via
  review checklists only.
- **Detection/AV/EDR evasion.**

## Not yet implemented (reasonable future plugins)

These fit the plugin model and could be added as **safe, gated** checks, but are not
in this build:

- Active web checks beyond headers: safe reflected-XSS markers, CSRF-token presence,
  directory-listing detection, security.txt, CORS misconfig. (Would be new `web.*` checks.)
- Full cipher-suite enumeration (currently protocol-version detection only). A
  `sslscan`/`testssl.sh` integration would extend `net.tls`.
- `nmap` service/version detection and OS fingerprinting (nmap is used opportunistically
  for port discovery only if present; richer parsing is not wired up).
- Third-party tool integrations: **OWASP ZAP, Nuclei (non-destructive templates),
  OpenVAS/Greenbone, Trivy, Semgrep.** Each would be a plugin that shells out to a
  verified, installed binary and imports results as `Finding`s. None are bundled;
  availability/licensing must be verified per environment before integration.
- Authenticated web scanning with safe test accounts.
- Database/OS assessment as *live* modules (currently review checklists in the playbook).
- Client binary / dependency inventory (SBOM, Trivy/Semgrep) as a module.

## Operational limitations

- **CIDR scope is not auto-expanded.** Scans only run against explicit single hosts/IPs
  or hostnames in a target's scope. This is intentional (prevents accidental
  range-sweeps). To scan several hosts, register them explicitly.
- **Scheduling / recurring scans** are not built in; trigger scans via the API/UI.
- **Background execution** uses FastAPI `BackgroundTasks` (in-process). For many
  concurrent large scans, move the runner behind a task queue (see ARCHITECTURE.md).
- **Posture scoring** is a transparent heuristic (weighted active-finding penalty), not
  a risk-quantification standard like CVSS environmental scoring.
- **No multi-tenant isolation** beyond RBAC; intended for a single team/operator group.

## Verified / tested surface

17 automated tests cover scope enforcement, RBAC, approval + emergency-stop gates,
audit-chain tampering detection, check ordering, an end-to-end loopback scan, and
report exports. The dashboard flow was verified in a headless browser. Checks were
exercised against local loopback services only.
