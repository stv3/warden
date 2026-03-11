import logging
from datetime import date
from pathlib import Path

from sqlalchemy.orm import Session

from models import SessionLocal, create_tables
from models.finding import Finding
from connectors.kev import KEVClient
from connectors.tenable import TenableConnector
from connectors.qualys import QualysConnector
from connectors.nessus import NessusConnector
from connectors.defender import DefenderConnector
from connectors.crowdstrike import CrowdStrikeConnector
from connectors.rapid7 import Rapid7Connector
from connectors.sast import SASTConnector
from connectors.sca import SCAConnector
from connectors.dast import DASTConnector
from core.deduplicator import upsert_findings
from core.kev_matcher import KEVMatcher
from core.risk_engine import RiskEngine, EPSSEnricher
from orchestrator.alert_manager import AlertManager
from orchestrator.ticket_manager import TicketManager
from config.settings import settings

logger = logging.getLogger(__name__)


class IngestionPipeline:
    """
    Orchestrates the full vulnerability management pipeline.
    Entry point for both scheduled tasks and on-demand runs via API.
    """

    def __init__(self):
        self._db: Session = SessionLocal()
        self._kev_client = KEVClient()
        self._risk_engine = RiskEngine()
        self._epss = EPSSEnricher()
        self._alert_manager = AlertManager()
        self._ticket_manager = TicketManager()

    def run(self) -> dict:
        """Full pipeline run: ingest → deduplicate → KEV match → score → alert → ticket."""
        logger.info("=== Starting full ingestion pipeline ===")
        results = {}

        try:
            # 1. Sync KEV catalog
            kev_stats = self._kev_client.sync_to_db(self._db)
            results["kev_sync"] = kev_stats

            # 2. Fetch from all enabled connectors
            raw_findings = self._fetch_all_sources()
            results["raw_findings"] = len(raw_findings)

            # 3. Deduplicate and upsert to DB
            dedup_result = upsert_findings(raw_findings, self._db)
            results["dedup"] = {
                "inserted": dedup_result.inserted,
                "updated": dedup_result.updated,
                "skipped": dedup_result.skipped,
            }

            # 4. EPSS enrichment (probability of exploitation)
            open_findings = self._get_open_findings()
            enriched = self._epss.enrich(open_findings)
            self._db.commit()
            results["epss_enriched"] = len([f for f in enriched if f.epss_score])

            # 5. KEV matching — the core value
            kev_matcher = KEVMatcher(self._db, self._kev_client)
            kev_result = kev_matcher.run()
            results["kev_matches"] = {
                "new": len(kev_result.newly_matched),
                "total_in_kev": kev_result.total_in_kev,
            }

            # 6. Risk scoring for all open findings
            all_open = self._get_open_findings()
            self._risk_engine.score_all(all_open)
            self._db.commit()
            results["scored"] = len(all_open)

            # 7. Alert on new KEV matches (critical path)
            if kev_result.newly_matched:
                self._alert_manager.send_kev_alert(kev_result.newly_matched)

            # 8. Create tickets for critical/high KEV findings without tickets
            kev_no_ticket = [
                f for f in kev_result.newly_matched
                if f.severity in ("critical", "high") and not f.ticket_id
            ]
            if kev_no_ticket:
                ticket_results = self._ticket_manager.create_tickets_bulk(kev_no_ticket, self._db)
                results["tickets_created"] = ticket_results["created"]

            logger.info(f"=== Pipeline complete: {results} ===")
            return results

        except Exception as e:
            logger.error(f"Pipeline error: {e}", exc_info=True)
            self._db.rollback()
            raise
        finally:
            self._db.close()

    def run_kev_sync_only(self) -> dict:
        """Lightweight run: sync KEV + re-match existing findings. No scanner ingestion."""
        try:
            kev_stats = self._kev_client.sync_to_db(self._db)

            kev_matcher = KEVMatcher(self._db, self._kev_client)
            kev_result = kev_matcher.run()

            # Re-score findings whose KEV status changed
            if kev_result.newly_matched:
                self._risk_engine.score_all(kev_result.newly_matched)
                self._db.commit()
                self._alert_manager.send_kev_alert(kev_result.newly_matched)

            return {
                "kev_sync": kev_stats,
                "new_kev_matches": len(kev_result.newly_matched),
            }
        finally:
            self._db.close()

    def check_sla_breaches(self) -> dict:
        """Finds findings past SLA due date and sends alerts."""
        try:
            today = date.today()
            breached = (
                self._db.query(Finding)
                .filter(Finding.status.in_(["open", "in_progress"]))
                .filter(Finding.sla_due_date < today)
                .filter(Finding.sla_due_date.isnot(None))
                .order_by(Finding.risk_score.desc())
                .all()
            )

            if breached:
                self._alert_manager.send_sla_breach_alert(breached)
                logger.warning(f"SLA breach: {len(breached)} findings past due date")

            return {"breached_count": len(breached)}
        finally:
            self._db.close()

    def _fetch_all_sources(self) -> list:
        """Fetches from all enabled and configured connectors."""
        all_findings = []

        if settings.tenable_access_key:
            try:
                connector = TenableConnector()
                findings = connector.fetch_findings()
                all_findings.extend(findings)
                logger.info(f"Tenable: {len(findings)} findings")
            except Exception as e:
                logger.error(f"Tenable ingestion failed: {e}")

        if settings.qualys_username:
            try:
                connector = QualysConnector()
                findings = connector.fetch_findings()
                all_findings.extend(findings)
                logger.info(f"Qualys: {len(findings)} findings")
            except Exception as e:
                logger.error(f"Qualys ingestion failed: {e}")

        if settings.nessus_url and settings.nessus_username:
            try:
                connector = NessusConnector()
                findings = connector.fetch_findings()
                all_findings.extend(findings)
                logger.info(f"Nessus: {len(findings)} findings")
            except Exception as e:
                logger.error(f"Nessus ingestion failed: {e}")

        if settings.defender_tenant_id and settings.defender_client_id:
            try:
                connector = DefenderConnector()
                findings = connector.fetch_findings()
                all_findings.extend(findings)
                logger.info(f"Defender: {len(findings)} findings")
            except Exception as e:
                logger.error(f"Defender ingestion failed: {e}")

        if settings.crowdstrike_client_id and settings.crowdstrike_client_secret:
            try:
                connector = CrowdStrikeConnector()
                findings = connector.fetch_findings()
                all_findings.extend(findings)
                logger.info(f"CrowdStrike: {len(findings)} findings")
            except Exception as e:
                logger.error(f"CrowdStrike ingestion failed: {e}")

        if settings.rapid7_url and settings.rapid7_api_key:
            try:
                connector = Rapid7Connector()
                findings = connector.fetch_findings()
                all_findings.extend(findings)
                logger.info(f"Rapid7: {len(findings)} findings")
            except Exception as e:
                logger.error(f"Rapid7 ingestion failed: {e}")

        # --- AppSec sources (SAST / SCA / DAST) ---
        # These run if their output files exist in the project root

        bandit_file = Path("bandit_results.json")
        semgrep_file = Path("semgrep_results.json")
        if bandit_file.exists() or semgrep_file.exists():
            try:
                connector = SASTConnector(
                    bandit_file=str(bandit_file),
                    semgrep_file=str(semgrep_file),
                )
                findings = connector.fetch_findings()
                all_findings.extend(findings)
                logger.info(f"SAST: {len(findings)} findings")
            except Exception as e:
                logger.error(f"SAST ingestion failed: {e}")

        requirements_file = Path("requirements.txt")
        if requirements_file.exists():
            try:
                connector = SCAConnector(
                    requirements_file=str(requirements_file),
                    run_on_fetch=True,
                )
                findings = connector.fetch_findings()
                all_findings.extend(findings)
                logger.info(f"SCA: {len(findings)} findings")
            except Exception as e:
                logger.error(f"SCA ingestion failed: {e}")

        zap_xml = Path("zap_report.xml")
        zap_json = Path("zap_report.json")
        if zap_xml.exists() or zap_json.exists():
            try:
                connector = DASTConnector(
                    zap_xml_file=str(zap_xml),
                    zap_json_file=str(zap_json) if zap_json.exists() else None,
                    min_risk_level=1,  # Skip informational
                )
                findings = connector.fetch_findings()
                all_findings.extend(findings)
                logger.info(f"DAST: {len(findings)} findings")
            except Exception as e:
                logger.error(f"DAST ingestion failed: {e}")

        return all_findings

    def _get_open_findings(self) -> list[Finding]:
        return (
            self._db.query(Finding)
            .filter(Finding.status.in_(["open", "in_progress"]))
            .all()
        )
