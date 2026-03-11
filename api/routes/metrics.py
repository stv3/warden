from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import date, timedelta
from typing import Optional

from models import get_db
from models.finding import Finding
from api.routes.auth import get_current_user

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("/kev-exposure")
def kev_exposure(
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    total_open = db.query(func.count(Finding.id)).filter(Finding.status.in_(["open", "in_progress"])).scalar()

    kev_open = db.query(func.count(Finding.id)).filter(
        Finding.status.in_(["open", "in_progress"]),
        Finding.in_kev == True,
    ).scalar()

    kev_by_severity = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.status.in_(["open", "in_progress"]), Finding.in_kev == True)
        .group_by(Finding.severity)
        .all()
    )

    kev_by_env = (
        db.query(Finding.asset_environment, func.count(Finding.id))
        .filter(Finding.status.in_(["open", "in_progress"]), Finding.in_kev == True)
        .group_by(Finding.asset_environment)
        .all()
    )

    today = date.today()

    overdue_kev = db.query(func.count(Finding.id)).filter(
        Finding.status.in_(["open", "in_progress"]),
        Finding.in_kev == True,
        Finding.kev_due_date < today,
    ).scalar()

    due_within_7 = db.query(func.count(Finding.id)).filter(
        Finding.status.in_(["open", "in_progress"]),
        Finding.in_kev == True,
        Finding.kev_due_date >= today,
        Finding.kev_due_date <= today + timedelta(days=7),
    ).scalar()

    due_within_30 = db.query(func.count(Finding.id)).filter(
        Finding.status.in_(["open", "in_progress"]),
        Finding.in_kev == True,
        Finding.kev_due_date >= today,
        Finding.kev_due_date <= today + timedelta(days=30),
    ).scalar()

    open_by_severity = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.status.in_(["open", "in_progress"]))
        .group_by(Finding.severity)
        .all()
    )

    return {
        "total_open_findings": total_open,
        "in_kev": kev_open,
        "kev_percentage": round((kev_open / total_open * 100), 1) if total_open else 0,
        "overdue_kev": overdue_kev,
        "due_within_7_days": due_within_7,
        "due_within_30_days": due_within_30,
        "open_by_severity": dict(open_by_severity),
        "by_severity": dict(kev_by_severity),
        "by_environment": dict(kev_by_env),
    }


@router.get("/mttr")
def mean_time_to_remediate(
    days: int = Query(default=90, ge=1, le=365),
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    since = date.today() - timedelta(days=days)

    resolved = (
        db.query(Finding.severity, Finding.first_seen, Finding.resolved_at)
        .filter(
            Finding.status == "resolved",
            Finding.resolved_at.isnot(None),
            Finding.first_seen >= since,
        )
        .all()
    )

    mttr_by_severity: dict[str, list[float]] = {}
    for severity, first_seen, resolved_at in resolved:
        days_to_resolve = (resolved_at.date() - first_seen.date()).days
        mttr_by_severity.setdefault(severity, []).append(days_to_resolve)

    return {
        "window_days": days,
        "mttr_by_severity": {
            sev: round(sum(times) / len(times), 1)
            for sev, times in mttr_by_severity.items()
        },
        "total_resolved": len(resolved),
    }


@router.get("/sla-compliance")
def sla_compliance(
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    today = date.today()

    findings_with_sla = (
        db.query(Finding)
        .filter(Finding.sla_due_date.isnot(None))
        .filter(Finding.status.in_(["open", "in_progress", "resolved"]))
        .all()
    )

    stats: dict[str, dict] = {}
    for severity in ("critical", "high", "medium", "low"):
        group = [f for f in findings_with_sla if f.severity == severity]
        if not group:
            continue

        within_sla = sum(
            1 for f in group
            if f.status == "resolved" and f.resolved_at and f.resolved_at.date() <= f.sla_due_date
        )
        overdue = sum(
            1 for f in group
            if f.status in ("open", "in_progress") and f.sla_due_date < today
        )

        stats[severity] = {
            "total": len(group),
            "within_sla": within_sla,
            "overdue": overdue,
            "compliance_rate": round(within_sla / len(group) * 100, 1) if group else 0,
        }

    return {"sla_compliance": stats}


@router.get("/findings-by-control")
def findings_by_control(
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    open_findings = (
        db.query(Finding)
        .filter(Finding.status.in_(["open", "in_progress"]))
        .all()
    )

    nist_counts: dict[str, int] = {}
    cis_counts: dict[str, int] = {}

    for f in open_findings:
        for control in (f.nist_csf_controls or []):
            nist_counts[control] = nist_counts.get(control, 0) + 1
        for control in (f.cis_controls or []):
            cis_counts[control] = cis_counts.get(control, 0) + 1

    return {
        "nist_csf": dict(sorted(nist_counts.items(), key=lambda x: x[1], reverse=True)),
        "cis_controls": dict(sorted(cis_counts.items(), key=lambda x: x[1], reverse=True)),
    }


@router.get("/scanner-coverage")
def scanner_coverage(
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    total = db.query(func.count(Finding.id)).filter(Finding.status.in_(["open", "in_progress"])).scalar()

    all_open = db.query(Finding).filter(Finding.status.in_(["open", "in_progress"])).all()

    scanner_counts: dict[str, int] = {}
    multi_scanner = 0

    for f in all_open:
        sources = f.all_sources or []
        if len(sources) > 1:
            multi_scanner += 1
        for src in sources:
            scanner_counts[src] = scanner_counts.get(src, 0) + 1

    return {
        "total_open_findings": total,
        "by_scanner": scanner_counts,
        "multi_scanner_findings": multi_scanner,
        "deduplication_savings": multi_scanner,
    }


@router.get("/risk-trend")
def risk_trend(
    days: int = Query(default=30, ge=1, le=365),
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    since = date.today() - timedelta(days=days)

    results = (
        db.query(
            func.date(Finding.first_seen).label("day"),
            Finding.severity,
            func.count(Finding.id).label("count"),
        )
        .filter(Finding.first_seen >= since)
        .group_by(func.date(Finding.first_seen), Finding.severity)
        .order_by(func.date(Finding.first_seen))
        .all()
    )

    trend: dict = {}
    for day, severity, count in results:
        day_str = str(day)
        trend.setdefault(day_str, {})[severity] = count

    return {"days": days, "trend": trend}
