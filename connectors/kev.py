import httpx
import json
import logging
from datetime import datetime, date, timezone
from typing import Optional

import redis

from config.settings import settings
from models.kev_entry import KEVEntry

logger = logging.getLogger(__name__)


class KEVClient:
    """
    Fetches and caches the CISA Known Exploited Vulnerabilities catalog.
    Handles polling, caching in Redis, and persisting to DB.
    """

    CACHE_KEY = "kev:full_catalog"

    def __init__(self):
        self._redis = redis.from_url(settings.redis_url, decode_responses=True)

    def fetch_catalog(self, force_refresh: bool = False) -> list[dict]:
        """Returns the full KEV catalog. Uses Redis cache unless force_refresh=True."""

        if not force_refresh:
            cached = self._redis.get(self.CACHE_KEY)
            if cached:
                logger.debug("KEV catalog loaded from cache")
                return json.loads(cached)

        logger.info("Fetching KEV catalog from CISA")
        try:
            with httpx.Client(timeout=30) as client:
                response = client.get(settings.kev_api_url)
                response.raise_for_status()
                data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            self._redis.setex(
                self.CACHE_KEY,
                settings.kev_cache_ttl_seconds,
                json.dumps(vulnerabilities),
            )
            logger.info(f"KEV catalog refreshed: {len(vulnerabilities)} entries")
            return vulnerabilities

        except Exception as e:
            logger.error(f"Failed to fetch KEV catalog: {e}")
            # Fall back to stale cache if available
            stale = self._redis.get(self.CACHE_KEY)
            if stale:
                logger.warning("Using stale KEV cache due to fetch error")
                return json.loads(stale)
            return []

    def get_cve_ids(self) -> set[str]:
        """Returns a set of all CVE IDs currently in KEV. Fast for membership checks."""
        catalog = self.fetch_catalog()
        return {entry["cveID"] for entry in catalog}

    def get_entry(self, cve_id: str) -> Optional[dict]:
        """Returns the full KEV entry for a specific CVE, or None if not in KEV."""
        catalog = self.fetch_catalog()
        for entry in catalog:
            if entry["cveID"] == cve_id:
                return entry
        return None

    def sync_to_db(self, db_session) -> dict:
        """
        Syncs the KEV catalog to the database.
        Returns stats: {"new": N, "updated": N, "total": N}
        """
        catalog = self.fetch_catalog(force_refresh=True)
        stats = {"new": 0, "updated": 0, "total": len(catalog)}

        for entry in catalog:
            cve_id = entry.get("cveID")
            if not cve_id:
                continue

            existing = db_session.query(KEVEntry).filter_by(cve_id=cve_id).first()

            due_date = self._parse_date(entry.get("dueDate"))
            date_added = self._parse_date(entry.get("dateAdded"))

            if existing:
                existing.due_date = due_date
                existing.date_added = date_added
                existing.last_updated = datetime.now(timezone.utc)
                stats["updated"] += 1
            else:
                kev_entry = KEVEntry(
                    cve_id=cve_id,
                    vendor_project=entry.get("vendorProject"),
                    product=entry.get("product"),
                    vulnerability_name=entry.get("vulnerabilityName"),
                    date_added=date_added,
                    short_description=entry.get("shortDescription"),
                    required_action=entry.get("requiredAction"),
                    due_date=due_date,
                    known_ransomware_use=entry.get("knownRansomwareCampaignUse"),
                    notes=entry.get("notes"),
                    is_new=True,
                )
                db_session.add(kev_entry)
                stats["new"] += 1

        db_session.commit()
        logger.info(f"KEV sync complete: {stats}")
        return stats

    @staticmethod
    def _parse_date(date_str: Optional[str]) -> Optional[date]:
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%Y-%m-%d").date()
        except (ValueError, TypeError):
            return None
