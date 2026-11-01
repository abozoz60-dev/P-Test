"""Report export: JSON, CSV, and a self-contained HTML report.

PDF is produced by printing the HTML report from a browser (documented in
docs/DEPLOYMENT.md) to avoid a heavyweight PDF dependency in the core service.
"""
from __future__ import annotations

import csv
import html
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import db, require_role
from app.db.models import Finding, Role, Scan, Severity, Target, User

router = APIRouter(prefix="/api/scans", tags=["reports"])

_SEV_ORDER = {s: i for i, s in enumerate(
    [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.informational])}


def _load(session: Session, scan_id: int) -> tuple[Scan, Target, list[Finding]]:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    target = session.get(Target, scan.target_id)
    findings = list(session.execute(
        select(Finding).where(Finding.scan_id == scan_id)).scalars())
    findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 99))
    return scan, target, findings


@router.get("/{scan_id}/report.json")
def report_json(scan_id: int, session: Session = Depends(db),
                _: User = Depends(require_role(Role.viewer))):
    scan, target, findings = _load(session, scan_id)
    return {
        "scan": {"id": scan.id, "status": scan.status.value, "operator": scan.operator,
                 "modules": scan.modules, "started_at": scan.started_at.isoformat(),
                 "finished_at": scan.finished_at.isoformat() if scan.finished_at else None},
        "target": {"name": target.name, "scope": target.scope,
                   "authorization_ref": target.authorization_ref,
                   "owner_attestation": target.owner_attestation},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": [{
            "vuln_id": f.vuln_id, "asset": f.asset, "service": f.service,
            "category": f.category, "severity": f.severity.value, "confidence": f.confidence,
            "title": f.title, "evidence": f.evidence, "reproduction": f.reproduction,
            "impact": f.impact, "remediation": f.remediation, "references": f.references,
            "status": f.status.value,
        } for f in findings],
    }


@router.get("/{scan_id}/report.csv")
def report_csv(scan_id: int, session: Session = Depends(db),
               _: User = Depends(require_role(Role.viewer))):
    _, _, findings = _load(session, scan_id)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["vuln_id", "asset", "service", "category", "severity", "confidence",
                "title", "status", "impact", "remediation", "references"])
    for f in findings:
        w.writerow([f.vuln_id, f.asset, f.service, f.category, f.severity.value,
                    f.confidence, f.title, f.status.value, f.impact, f.remediation, f.references])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.csv"'})


@router.get("/{scan_id}/report.html", response_class=HTMLResponse)
def report_html(scan_id: int, session: Session = Depends(db),
                _: User = Depends(require_role(Role.viewer))):
    scan, target, findings = _load(session, scan_id)
    e = html.escape
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    colors = {"critical": "#d1304a", "high": "#e8590c", "medium": "#e0a400",
              "low": "#2f9e44", "informational": "#539bf5"}
    summary = " ".join(
        f'<span style="color:{colors[s]}">■</span> {s}: {counts.get(s,0)}'
        for s in ["critical", "high", "medium", "low", "informational"])
    rows = "".join(f"""
      <div style="border-left:4px solid {colors.get(f.severity.value,'#999')};
                  padding:10px 14px;margin:10px 0;background:#f7f8fa;border-radius:6px">
        <h3 style="margin:0 0 4px">{e(f.title)}
          <span style="font-size:12px;color:{colors.get(f.severity.value,'#999')}">
            [{e(f.severity.value.upper())}]</span></h3>
        <div style="font-size:12px;color:#666;margin-bottom:6px">
          {e(f.vuln_id)} · {e(f.asset)} · {e(f.category)} · confidence {e(f.confidence)} · status {e(f.status.value)}</div>
        {f'<p><b>Evidence:</b> {e(f.evidence)}</p>' if f.evidence else ''}
        {f'<p><b>Impact:</b> {e(f.impact)}</p>' if f.impact else ''}
        {f'<p><b>Remediation:</b> {e(f.remediation)}</p>' if f.remediation else ''}
        {f'<p style="font-size:12px;color:#666"><b>References:</b> {e(f.references)}</p>' if f.references else ''}
      </div>""" for f in findings) or "<p>No findings recorded.</p>"
    doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>P-Test Report — scan {scan.id}</title>
<style>body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1c232d}}
h1{{margin-bottom:0}} .meta{{color:#666;font-size:13px}} hr{{border:0;border-top:1px solid #e1e4e8;margin:1rem 0}}</style></head>
<body>
<h1>P-Test Assessment Report</h1>
<p class="meta">Scan #{scan.id} · target <b>{e(target.name)}</b> ({e(target.scope)}) ·
   operator {e(scan.operator)} · status {e(scan.status.value)}<br>
   Authorization: {e(target.authorization_ref) or '—'} · Attestation: {e(target.owner_attestation) or '—'}<br>
   Modules: {e(scan.modules)} · Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')}</p>
<hr><p><b>Summary:</b> {summary}</p><hr>
{rows}
<hr><p class="meta">This report covers only the authorized scope above. All checks were
non-destructive. To save as PDF, use your browser's Print → Save as PDF.</p>
</body></html>"""
    return HTMLResponse(doc)
