"""
Export endpoints for Tableau and other BI tools.
"""
import csv
import io
import os
from datetime import date
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from models import get_db
from models.finding import Finding
from api.routes.auth import get_current_user

router = APIRouter(prefix="/export", tags=["export"])

VALID_STATUSES = {"open", "in_progress", "resolved", "accepted_risk"}


@router.get(
    "/tableau/findings.csv",
    response_class=StreamingResponse,
    summary="Download all findings as CSV",
)
def export_findings_csv(
    status: Optional[str] = Query(default="open,in_progress"),
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    statuses = [s.strip() for s in status.split(",") if s.strip() in VALID_STATUSES]
    if not statuses:
        statuses = ["open", "in_progress"]

    findings = (
        db.query(Finding)
        .filter(Finding.status.in_(statuses))
        .order_by(Finding.risk_score.desc())
        .all()
    )

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "id", "cve_id", "title", "severity", "risk_score", "cvss_score", "epss_score",
        "in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use",
        "asset_name", "asset_ip", "asset_environment", "asset_criticality",
        "finding_type", "primary_source", "all_sources", "status", "owner",
        "ticket_id", "sla_due_date", "sla_overdue", "days_open",
        "nist_csf_controls", "cis_controls", "remediation_action",
        "first_seen", "last_seen", "resolved_at",
    ])

    today = date.today()
    for f in findings:
        sla_overdue = "Yes" if (
            f.sla_due_date and f.sla_due_date < today and f.status in ("open", "in_progress")
        ) else "No"
        days_open = (today - f.first_seen.date()).days if f.first_seen else ""

        writer.writerow([
            str(f.id), f.cve_id or "", f.title, f.severity or "",
            f.risk_score or "", f.cvss_score or "", f.epss_score or "",
            "Yes" if f.in_kev else "No",
            str(f.kev_date_added) if f.kev_date_added else "",
            str(f.kev_due_date) if f.kev_due_date else "",
            f.kev_ransomware_use or "",
            f.asset_name, f.asset_ip or "", f.asset_environment or "",
            f.asset_criticality or "", f.finding_type or "",
            f.primary_source or "", ", ".join(f.all_sources or []),
            f.status, f.owner or "", f.ticket_id or "",
            str(f.sla_due_date) if f.sla_due_date else "",
            sla_overdue, days_open,
            ", ".join(f.nist_csf_controls or []),
            ", ".join(f.cis_controls or []),
            (f.remediation_action or "").replace("\n", " ")[:200],
            f.first_seen.isoformat() if f.first_seen else "",
            f.last_seen.isoformat() if f.last_seen else "",
            f.resolved_at.isoformat() if f.resolved_at else "",
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=warden-findings.csv"},
    )


@router.get(
    "/tableau/kev-summary.csv",
    response_class=StreamingResponse,
    summary="KEV-only summary CSV",
)
def export_kev_summary_csv(
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    findings = (
        db.query(Finding)
        .filter(Finding.in_kev == True, Finding.status.in_(["open", "in_progress"]))
        .order_by(Finding.risk_score.desc())
        .all()
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "cve_id", "severity", "risk_score", "asset_name", "asset_environment",
        "kev_due_date", "days_until_due", "kev_ransomware_use",
        "status", "owner", "ticket_id", "sla_overdue",
    ])

    today = date.today()
    for f in findings:
        days_until = (f.kev_due_date - today).days if f.kev_due_date else ""
        sla_overdue = "Yes" if (f.kev_due_date and f.kev_due_date < today) else "No"

        writer.writerow([
            f.cve_id or "", f.severity or "", f.risk_score or "",
            f.asset_name, f.asset_environment or "",
            str(f.kev_due_date) if f.kev_due_date else "",
            days_until, f.kev_ransomware_use or "Unknown",
            f.status, f.owner or "Unassigned", f.ticket_id or "", sla_overdue,
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=warden-kev-summary.csv"},
    )


@router.get("/tableau/connection-info")
def tableau_connection_info(_: str = Depends(get_current_user)):
    """
    Returns PostgreSQL connection info for Tableau (no credentials — use your .env values).
    """
    db_url = os.getenv("DATABASE_URL", "")
    parsed = urlparse(db_url)

    return {
        "method": "PostgreSQL Live Connection",
        "instructions": "In Tableau Desktop: Connect > To a Server > PostgreSQL",
        "connection": {
            "server": parsed.hostname or "localhost",
            "port": parsed.port or 5432,
            "database": (parsed.path or "/vuln_orchestrator").lstrip("/"),
            "username": parsed.username or "vuln",
            # Password intentionally omitted — use your DB credentials from .env
        },
        "recommended_tables": ["findings", "kev_entries"],
        "recommended_views": {
            "open_findings": "SELECT * FROM findings WHERE status IN ('open', 'in_progress')",
            "kev_active": "SELECT * FROM findings WHERE in_kev = true AND status IN ('open', 'in_progress')",
            "kev_overdue": "SELECT * FROM findings WHERE in_kev = true AND kev_due_date < CURRENT_DATE AND status IN ('open', 'in_progress')",
        },
    }
