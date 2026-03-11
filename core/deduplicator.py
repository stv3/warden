import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from core.normalizer import normalize, generate_fingerprint
from connectors.base import RawFinding
from models.finding import Finding

logger = logging.getLogger(__name__)


class DeduplicationResult:
    def __init__(self):
        self.inserted: int = 0
        self.updated: int = 0
        self.skipped: int = 0

    def __repr__(self):
        return f"<DeduplicationResult inserted={self.inserted} updated={self.updated} skipped={self.skipped}>"


def upsert_findings(raw_findings: list[RawFinding], db: Session, asset_criticality_map: dict = None) -> DeduplicationResult:
    """
    Core deduplication logic.

    For each RawFinding:
    - If fingerprint exists in DB: update last_seen, merge source info
    - If new: normalize and insert

    Returns stats on what happened.
    """
    result = DeduplicationResult()
    asset_criticality_map = asset_criticality_map or {}
    now = datetime.now(timezone.utc)

    # Track fingerprints seen in THIS batch so within-batch duplicates merge
    # rather than causing a UniqueViolation on commit.
    batch_seen: dict[str, Finding] = {}

    for raw in raw_findings:
        try:
            fingerprint = generate_fingerprint(
                raw.cve_id, raw.asset_id, raw.finding_type,
                raw.title or "", raw.source_finding_id or ""
            )

            # 1. Check within-batch first
            if fingerprint in batch_seen:
                _merge_finding(batch_seen[fingerprint], raw, now)
                result.updated += 1
                continue

            # 2. Check DB
            existing = db.query(Finding).filter_by(fingerprint=fingerprint).first()
            if existing:
                _merge_finding(existing, raw, now)
                batch_seen[fingerprint] = existing
                result.updated += 1
            else:
                criticality = asset_criticality_map.get(raw.asset_id, 2)
                new_finding = normalize(raw, asset_criticality=criticality)
                db.add(new_finding)
                batch_seen[fingerprint] = new_finding
                result.inserted += 1

        except Exception as e:
            logger.warning(f"Deduplication error for finding {raw.source_finding_id}: {e}")
            result.skipped += 1

    db.commit()
    logger.info(f"Deduplication complete: {result}")
    return result


def _merge_finding(existing: Finding, raw: RawFinding, now: datetime) -> None:
    """
    Updates an existing finding with data from a new scan.
    Merges source tracking without overwriting history.
    """
    # Always update last seen
    existing.last_seen = now

    # Add this scanner to source tracking if not already there
    if raw.source not in existing.all_sources:
        existing.all_sources = existing.all_sources + [raw.source]

    source_ids = dict(existing.source_ids or {})
    source_ids[raw.source] = raw.source_finding_id
    existing.source_ids = source_ids

    # Update score if we now have a better one
    if raw.cvss_score and (not existing.cvss_score or raw.cvss_score > existing.cvss_score):
        existing.cvss_score = raw.cvss_score
        existing.cvss_vector = raw.cvss_vector

    # Re-open if it was previously resolved and scanner found it again
    if existing.status == "resolved":
        existing.status = "open"
        existing.resolved_at = None
        logger.info(f"Finding {existing.fingerprint[:12]}... re-opened (detected again by {raw.source})")
