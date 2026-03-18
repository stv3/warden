import re
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import cast, or_
from sqlalchemy.dialects.postgresql import JSONB
from typing import Optional
from uuid import UUID
from datetime import datetime, timezone, date, timedelta
from pydantic import BaseModel

from models import get_db
from models.finding import Finding
from api.routes.auth import get_current_user

router = APIRouter(prefix="/findings", tags=["findings"])

VALID_STATUSES = {"open", "in_progress", "resolved", "accepted_risk"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_ENVIRONMENTS = {"production", "staging", "development", "unknown"}
VALID_FINDING_TYPES = {"network", "application", "code", "configuration", "dependency"}
VALID_SLA_STATUSES = {"overdue", "due_soon", "ok", "none"}

# CVE-YYYY-NNNNN format  (4-digit year, 4+ digit ID)
_CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)
# Owner: email address or simple identifier (alphanumeric, dots, dashes, underscores, @)
_OWNER_RE = re.compile(r'^[\w.@+\-]{1,200}$')


@router.get("/filter-options")
def get_filter_options(
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    """Returns distinct values for filter dropdowns."""
    finding_types = sorted(
        r[0] for r in db.query(Finding.finding_type).distinct().all() if r[0]
    )

    sources_raw = db.query(Finding.all_sources).all()
    sources: set[str] = set()
    for (all_sources,) in sources_raw:
        if all_sources:
            sources.update(all_sources)

    owners = sorted(r[0] for r in db.query(Finding.owner).distinct().all() if r[0])

    return {
        "finding_types": finding_types,
        "sources": sorted(sources),
        "owners": owners[:100],
    }


@router.get("/")
def list_findings(
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    in_kev: Optional[bool] = Query(default=None),
    environment: Optional[str] = Query(default=None),
    source: Optional[str] = Query(default=None),
    finding_type: Optional[str] = Query(default=None),
    nist_control: Optional[str] = Query(default=None),
    cis_control: Optional[str] = Query(default=None),
    min_risk_score: Optional[float] = Query(default=None, ge=0),
    max_risk_score: Optional[float] = Query(default=None, le=100),
    cve_id: Optional[str] = Query(default=None),
    asset_name: Optional[str] = Query(default=None),
    sla_status: Optional[str] = Query(default=None),
    owner: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    query = db.query(Finding)

    if status:
        statuses = [s.strip() for s in status.split(",") if s.strip() in VALID_STATUSES]
        if statuses:
            query = query.filter(Finding.status.in_(statuses))

    if severity:
        if severity not in VALID_SEVERITIES:
            raise HTTPException(status_code=400, detail=f"Invalid severity. Must be one of: {sorted(VALID_SEVERITIES)}")
        query = query.filter(Finding.severity == severity)

    if in_kev is not None:
        query = query.filter(Finding.in_kev == in_kev)

    if environment:
        if environment not in VALID_ENVIRONMENTS:
            raise HTTPException(status_code=400, detail=f"Invalid environment. Must be one of: {sorted(VALID_ENVIRONMENTS)}")
        query = query.filter(Finding.asset_environment == environment)

    if source:
        if not source.replace("-", "").replace("_", "").isalnum():
            raise HTTPException(status_code=400, detail="Invalid source identifier")
        query = query.filter(cast(Finding.all_sources, JSONB).contains([source]))

    if finding_type:
        if finding_type not in VALID_FINDING_TYPES:
            raise HTTPException(status_code=400, detail=f"Invalid finding_type. Must be one of: {sorted(VALID_FINDING_TYPES)}")
        query = query.filter(Finding.finding_type == finding_type)

    if nist_control:
        if len(nist_control) > 50:
            raise HTTPException(status_code=400, detail="nist_control too long")
        query = query.filter(cast(Finding.nist_csf_controls, JSONB).contains([nist_control]))

    if cis_control:
        if len(cis_control) > 50:
            raise HTTPException(status_code=400, detail="cis_control too long")
        query = query.filter(cast(Finding.cis_controls, JSONB).contains([cis_control]))

    if min_risk_score is not None:
        query = query.filter(Finding.risk_score >= min_risk_score)

    if max_risk_score is not None:
        query = query.filter(Finding.risk_score <= max_risk_score)

    if cve_id:
        cve_id = cve_id.strip().upper()
        if not _CVE_RE.match(cve_id):
            raise HTTPException(status_code=400, detail="Invalid CVE ID format. Expected CVE-YYYY-NNNNN")
        query = query.filter(Finding.cve_id.ilike(f"%{cve_id}%"))

    if asset_name:
        if len(asset_name) > 200:
            raise HTTPException(status_code=400, detail="asset_name filter too long")
        query = query.filter(
            or_(
                Finding.asset_name.ilike(f"%{asset_name}%"),
                Finding.asset_ip.ilike(f"%{asset_name}%"),
            )
        )

    if owner:
        if not _OWNER_RE.match(owner):
            raise HTTPException(status_code=400, detail="Invalid owner format")
        query = query.filter(Finding.owner.ilike(f"%{owner}%"))

    if sla_status:
        if sla_status not in VALID_SLA_STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid sla_status. Must be one of: {sorted(VALID_SLA_STATUSES)}")
        today = date.today()
        if sla_status == "overdue":
            query = query.filter(
                Finding.sla_due_date < today,
                Finding.sla_due_date.isnot(None),
                Finding.status.in_(["open", "in_progress"]),
            )
        elif sla_status == "due_soon":
            query = query.filter(
                Finding.sla_due_date >= today,
                Finding.sla_due_date <= today + timedelta(days=7),
            )
        elif sla_status == "ok":
            query = query.filter(
                Finding.sla_due_date > today + timedelta(days=7),
            )
        elif sla_status == "none":
            query = query.filter(Finding.sla_due_date.is_(None))

    total = query.count()
    findings = query.order_by(Finding.risk_score.desc()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "findings": [_serialize(f) for f in findings],
    }


@router.get("/kev/active")
def list_kev_findings(
    environment: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    query = db.query(Finding).filter(
        Finding.in_kev == True,
        Finding.status.in_(["open", "in_progress"]),
    )
    if environment:
        if environment not in VALID_ENVIRONMENTS:
            raise HTTPException(status_code=400, detail=f"Invalid environment")
        query = query.filter(Finding.asset_environment == environment)

    findings = query.order_by(Finding.risk_score.desc()).all()
    return {"count": len(findings), "findings": [_serialize(f) for f in findings]}


@router.get("/{finding_id}")
def get_finding(
    finding_id: UUID,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _serialize(finding)


class StatusUpdate(BaseModel):
    status: str
    owner: Optional[str] = None


@router.patch("/{finding_id}/status")
def update_status(
    finding_id: UUID,
    body: StatusUpdate,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    if body.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Status must be one of: {sorted(VALID_STATUSES)}")

    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = body.status
    if body.owner is not None:
        owner_val = body.owner.strip()
        if owner_val and not _OWNER_RE.match(owner_val):
            raise HTTPException(status_code=400, detail="Invalid owner format")
        finding.owner = owner_val or None
    if body.status == "resolved":
        finding.resolved_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(finding)
    return _serialize(finding)


def _serialize(f: Finding) -> dict:
    return {
        "id": str(f.id),
        "cve_id": f.cve_id,
        "title": f.title,
        "severity": f.severity,
        "risk_score": f.risk_score,
        "cvss_score": f.cvss_score,
        "epss_score": f.epss_score,
        "in_kev": f.in_kev,
        "kev_due_date": str(f.kev_due_date) if f.kev_due_date else None,
        "kev_ransomware_use": f.kev_ransomware_use,
        "asset_name": f.asset_name,
        "asset_ip": f.asset_ip,
        "asset_environment": f.asset_environment,
        "asset_criticality": f.asset_criticality,
        "sources": f.all_sources,
        "finding_type": f.finding_type,
        "status": f.status,
        "owner": f.owner,
        "ticket_id": f.ticket_id,
        "ticket_url": f.ticket_url,
        "sla_due_date": str(f.sla_due_date) if f.sla_due_date else None,
        "nist_csf_controls": f.nist_csf_controls,
        "cis_controls": f.cis_controls,
        "remediation_action": f.remediation_action,
        "first_seen": f.first_seen.isoformat() if f.first_seen else None,
        "last_seen": f.last_seen.isoformat() if f.last_seen else None,
        "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
        # SSVC prioritization
        "ssvc_decision": f.ssvc_decision,
        "ssvc_exploitation": f.ssvc_exploitation,
        "has_public_exploit": f.has_public_exploit,
        # NVD enrichment
        "cwe_id": f.cwe_id,
        "nvd_published_date": str(f.nvd_published_date) if f.nvd_published_date else None,
        "patch_available": f.patch_available,
        "attack_vector": f.attack_vector,
    }
