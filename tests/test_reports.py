"""Report export endpoints produce JSON, CSV, and HTML for a scan."""
from __future__ import annotations

from app.db.base import SessionLocal
from app.db.models import (
    Finding,
    Scan,
    ScanStatus,
    Severity,
    Target,
    ValidationStatus,
)


def _seed_scan_with_finding() -> int:
    session = SessionLocal()
    try:
        t = Target(name="rep-target", scope="127.0.0.1", owner_attestation="self",
                   authorization_ref="SELF", approved=True, enabled=True, created_by="admin")
        session.add(t)
        session.commit()
        s = Scan(target_id=t.id, modules="web.security_headers", operator="admin",
                 status=ScanStatus.completed)
        session.add(s)
        session.commit()
        session.add(Finding(
            scan_id=s.id, vuln_id="PTEST-WEB-HSTS", asset="http://127.0.0.1/",
            category="web", severity=Severity.medium, confidence="high",
            title="Missing HSTS", impact="downgrade", remediation="add HSTS",
            references="CWE-319", status=ValidationStatus.confirmed))
        session.commit()
        return s.id
    finally:
        session.close()


def test_report_json_csv_html(client, admin_headers):
    scan_id = _seed_scan_with_finding()

    j = client.get(f"/api/scans/{scan_id}/report.json", headers=admin_headers)
    assert j.status_code == 200
    body = j.json()
    assert body["target"]["authorization_ref"] == "SELF"
    assert any(f["vuln_id"] == "PTEST-WEB-HSTS" for f in body["findings"])

    c = client.get(f"/api/scans/{scan_id}/report.csv", headers=admin_headers)
    assert c.status_code == 200
    assert "PTEST-WEB-HSTS" in c.text
    assert c.headers["content-type"].startswith("text/csv")

    h = client.get(f"/api/scans/{scan_id}/report.html", headers=admin_headers)
    assert h.status_code == 200
    assert "P-Test Assessment Report" in h.text
    assert "Missing HSTS" in h.text
