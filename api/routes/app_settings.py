"""
Application settings API — exposes risk model config for UI editing.

GET  /api/settings/risk-model   — read current risk model YAML as structured JSON
PUT  /api/settings/risk-model   — write updated values back to YAML
GET  /api/settings/system       — read-only system info (version, env, uptime)
"""
import os
import time
from pathlib import Path

import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.routes.auth import get_current_user
from config.settings import settings

router = APIRouter(prefix="/settings", tags=["settings"])

_start_time = time.time()
APP_VERSION = "1.0.0"


def _read_risk_model() -> dict:
    path = Path(settings.risk_model_path)
    if not path.exists():
        raise HTTPException(status_code=500, detail="Risk model config not found")
    with open(path) as f:
        return yaml.safe_load(f)


def _write_risk_model(data: dict) -> None:
    path = Path(settings.risk_model_path)
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


# ── Schemas ────────────────────────────────────────────────────────────────────

class ScoringWeights(BaseModel):
    cvss_base: float
    kev_active: float
    asset_criticality: float
    epss_score: float


class SlaConfig(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class RiskModelUpdate(BaseModel):
    weights: ScoringWeights
    kev_multiplier: float
    sla_days: SlaConfig


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("/risk-model")
def get_risk_model(_: str = Depends(get_current_user)):
    """Return the current risk scoring model configuration."""
    model = _read_risk_model()
    return {
        "weights": model.get("scoring", {}).get("weights", {}),
        "kev_multiplier": model.get("scoring", {}).get("kev_multiplier", 2.0),
        "severity_thresholds": model.get("scoring", {}).get("severity_thresholds", {}),
        "sla_days": model.get("sla_days", {}),
        "asset_criticality": model.get("asset_criticality", {}),
    }


@router.put("/risk-model")
def update_risk_model(body: RiskModelUpdate, _: str = Depends(get_current_user)):
    """Persist updated risk model weights and SLA targets."""
    # Validate weights sum to ~1.0 (allow small floating point error)
    weight_sum = (
        body.weights.cvss_base
        + body.weights.kev_active
        + body.weights.asset_criticality
        + body.weights.epss_score
    )
    if not (0.99 <= weight_sum <= 1.01):
        raise HTTPException(
            status_code=400,
            detail=f"Scoring weights must sum to 1.0 (got {weight_sum:.3f})",
        )

    if body.kev_multiplier < 1.0 or body.kev_multiplier > 10.0:
        raise HTTPException(status_code=400, detail="KEV multiplier must be between 1.0 and 10.0")

    for label, days in body.sla_days.model_dump().items():
        if days < 1 or days > 3650:
            raise HTTPException(status_code=400, detail=f"SLA days for {label} must be 1–3650")

    model = _read_risk_model()
    model.setdefault("scoring", {})
    model["scoring"]["weights"] = body.weights.model_dump()
    model["scoring"]["kev_multiplier"] = body.kev_multiplier
    model["sla_days"] = body.sla_days.model_dump()

    _write_risk_model(model)
    return {"saved": True, "message": "Risk model updated. Changes apply on the next pipeline run."}


@router.get("/system")
def system_info(_: str = Depends(get_current_user)):
    """Return read-only system and runtime information."""
    uptime_seconds = int(time.time() - _start_time)

    return {
        "version": APP_VERSION,
        "environment": settings.environment,
        "debug": settings.debug,
        "uptime_seconds": uptime_seconds,
        "uptime_human": _format_uptime(uptime_seconds),
        "connectors_configured": {
            "nessus": bool(settings.nessus_url and settings.nessus_username),
            "qualys": bool(settings.qualys_username and settings.qualys_api_url),
            "tenable": bool(settings.tenable_access_key),
            "jira": bool(settings.jira_url),
            "slack": bool(settings.slack_webhook_url),
        },
        "risk_model_path": settings.risk_model_path,
        "kev_poll_interval_hours": settings.kev_poll_interval_hours,
    }


def _format_uptime(seconds: int) -> str:
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m {secs}s"
