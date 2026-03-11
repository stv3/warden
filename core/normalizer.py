import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional

from connectors.base import RawFinding
from models.finding import Finding

logger = logging.getLogger(__name__)


def generate_fingerprint(
    cve_id: Optional[str],
    asset_id: str,
    finding_type: str,
    title: str = "",
    source_finding_id: str = "",
) -> str:
    """
    Deterministic fingerprint for deduplication.

    With CVE:
        CVE_ID :: asset_id :: type
        → Same CVE on same asset from any scanner = one finding (cross-scanner dedup)

    Without CVE, network/configuration finding:
        NOCVE :: title_hash :: asset_id :: type
        → Same plugin rule on same host merges across scans

    Without CVE, code/dependency finding (SAST/SCA/DAST):
        NOCVE :: title_hash :: asset_id :: type :: source_id_hash
        → Each unique file/location is a distinct finding, even for the same rule
    """
    if cve_id:
        key = f"{cve_id.upper()}::{asset_id.lower()}::{finding_type}"
    else:
        title_hash = hashlib.sha256(title.lower().encode()).hexdigest()[:16]
        if finding_type in ("code", "dependency"):
            # Include the source_finding_id so different file locations stay separate
            sid_hash = hashlib.sha256(source_finding_id.encode()).hexdigest()[:16]
            key = f"NOCVE:{title_hash}::{asset_id.lower()}::{finding_type}::{sid_hash}"
        else:
            key = f"NOCVE:{title_hash}::{asset_id.lower()}::{finding_type}"
    return hashlib.sha256(key.encode()).hexdigest()


def normalize(raw: RawFinding, asset_criticality: int = 2) -> Finding:
    """
    Converts a RawFinding into a Finding model ready for DB persistence.
    Does NOT save to DB — caller handles the session.
    """
    fingerprint = generate_fingerprint(raw.cve_id, raw.asset_id, raw.finding_type, raw.title or "", raw.source_finding_id or "")
    now = datetime.now(timezone.utc)

    finding = Finding(
        fingerprint=fingerprint,
        cve_id=raw.cve_id.upper() if raw.cve_id else None,
        title=raw.title[:500] if raw.title else "Unknown",
        description=raw.description,
        primary_source=raw.source,
        all_sources=[raw.source],
        source_ids={raw.source: raw.source_finding_id},
        finding_type=raw.finding_type,
        asset_id=raw.asset_id,
        asset_name=raw.asset_name,
        asset_ip=raw.asset_ip,
        asset_environment=raw.asset_environment or "unknown",
        asset_criticality=asset_criticality,
        cvss_score=raw.cvss_score,
        cvss_vector=raw.cvss_vector,
        severity=_normalize_severity(raw.severity_label, raw.cvss_score),
        remediation_action=raw.remediation_action,
        first_seen=raw.first_found or now,
        last_seen=raw.last_found or now,
        status="open",
    )

    return finding


def _normalize_severity(label: Optional[str], cvss_score: Optional[float]) -> str:
    """
    Normalize severity label to our standard values.
    Falls back to CVSS score if label is missing or unrecognized.
    """
    if label:
        label_lower = label.lower()
        if label_lower in ("critical",):
            return "critical"
        if label_lower in ("high",):
            return "high"
        if label_lower in ("medium", "moderate"):
            return "medium"
        if label_lower in ("low", "informational", "info"):
            return "low"

    # Fall back to CVSS
    if cvss_score is not None:
        if cvss_score >= 9.0:
            return "critical"
        if cvss_score >= 7.0:
            return "high"
        if cvss_score >= 4.0:
            return "medium"
        return "low"

    return "low"
