import logging
from datetime import date, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from connectors.kev import KEVClient
from models.finding import Finding
from models.kev_entry import KEVEntry

logger = logging.getLogger(__name__)


class KEVMatchResult:
    def __init__(self):
        self.newly_matched: list[Finding] = []   # Findings that just entered KEV
        self.already_matched: int = 0
        self.unmatched: int = 0

    @property
    def total_in_kev(self) -> int:
        return len(self.newly_matched) + self.already_matched


class KEVMatcher:
    """
    Cross-references open findings against the CISA KEV catalog.
    Identifies which of your vulnerabilities are being actively exploited in the wild.
    """

    def __init__(self, db: Session, kev_client: Optional[KEVClient] = None):
        self._db = db
        self._kev = kev_client or KEVClient()

    def run(self) -> KEVMatchResult:
        """
        Matches all open findings with CVE IDs against the current KEV catalog.
        Updates findings in place and returns match results.
        """
        result = KEVMatchResult()
        kev_ids = self._kev.get_cve_ids()

        open_findings = (
            self._db.query(Finding)
            .filter(Finding.status.in_(["open", "in_progress"]))
            .filter(Finding.cve_id.isnot(None))
            .all()
        )

        for finding in open_findings:
            if finding.cve_id not in kev_ids:
                if finding.in_kev:
                    # Was in KEV before but no longer (rare, KEV entries are rarely removed)
                    finding.in_kev = False
                result.unmatched += 1
                continue

            kev_entry = self._db.query(KEVEntry).filter_by(cve_id=finding.cve_id).first()

            if finding.in_kev:
                # Already flagged, just refresh dates
                if kev_entry:
                    finding.kev_due_date = kev_entry.due_date
                result.already_matched += 1
            else:
                # New KEV match — this is the critical alert path
                finding.in_kev = True
                finding.kev_ransomware_use = kev_entry.known_ransomware_use if kev_entry else None

                if kev_entry:
                    finding.kev_date_added = kev_entry.date_added
                    finding.kev_due_date = kev_entry.due_date or self._default_due_date()
                else:
                    finding.kev_due_date = self._default_due_date()

                result.newly_matched.append(finding)
                logger.warning(
                    f"KEV MATCH: {finding.cve_id} on {finding.asset_name} "
                    f"(criticality={finding.asset_criticality}) — due: {finding.kev_due_date}"
                )

        self._db.commit()
        logger.info(
            f"KEV matching complete: {len(result.newly_matched)} new matches, "
            f"{result.already_matched} existing, {result.unmatched} not in KEV"
        )
        return result

    @staticmethod
    def _default_due_date() -> date:
        """Default SLA when KEV entry has no due date — 15 days (federal standard)."""
        return date.today() + timedelta(days=15)
