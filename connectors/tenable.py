import logging
from datetime import datetime, timezone
from typing import Optional

from connectors.base import BaseConnector, RawFinding
from config.settings import settings

logger = logging.getLogger(__name__)


class TenableConnector(BaseConnector):
    """
    Fetches vulnerability findings from Tenable.sc or Tenable.io.
    Uses the official tenable-python SDK.
    """

    SEVERITY_MAP = {
        4: "critical",
        3: "high",
        2: "medium",
        1: "low",
        0: "info",
    }

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                from tenable.sc import TenableSC
                from tenable.io import TenableIO

                # Try Tenable.sc first (common in enterprise), fall back to Tenable.io
                if settings.tenable_access_key and settings.tenable_secret_key:
                    self._client = TenableIO(
                        access_key=settings.tenable_access_key,
                        secret_key=settings.tenable_secret_key,
                    )
                    logger.info("Tenable.io client initialized")
                else:
                    raise ValueError("Tenable credentials not configured")
            except ImportError:
                raise RuntimeError("tenable-python SDK not installed. Run: pip install tenable")
        return self._client

    def test_connection(self) -> bool:
        try:
            client = self._get_client()
            # Lightweight call to verify credentials
            client.session.get()
            logger.info("Tenable connection: OK")
            return True
        except Exception as e:
            logger.error(f"Tenable connection failed: {e}")
            return False

    def fetch_findings(self) -> list[RawFinding]:
        """Fetches all active vulnerabilities from Tenable."""
        client = self._get_client()
        findings = []

        logger.info("Fetching findings from Tenable")
        try:
            # Export all active vulnerabilities with CVE info
            for vuln in client.exports.vulns(
                filters={
                    "state": ["OPEN", "REOPENED"],
                    "severity": ["critical", "high", "medium", "low"],
                }
            ):
                raw_finding = self._map_to_raw_finding(vuln)
                if raw_finding:
                    findings.append(raw_finding)

        except Exception as e:
            logger.error(f"Error fetching Tenable findings: {e}")
            raise

        logger.info(f"Tenable: fetched {len(findings)} findings")
        return findings

    def _map_to_raw_finding(self, vuln: dict) -> Optional[RawFinding]:
        try:
            asset = vuln.get("asset", {})
            plugin = vuln.get("plugin", {})
            cves = plugin.get("cve", [])

            # Skip findings with no actionable CVE or severity
            severity_id = vuln.get("severity", {}).get("id", 0)
            if severity_id == 0:
                return None

            asset_id = asset.get("hostname") or asset.get("ipv4") or asset.get("id", "unknown")
            cve_id = cves[0] if cves else None

            return RawFinding(
                cve_id=cve_id,
                title=plugin.get("name", "Unknown"),
                description=plugin.get("description"),
                source="tenable",
                source_finding_id=str(vuln.get("plugin", {}).get("id", "")),
                finding_type=self._infer_finding_type(plugin),
                asset_id=asset_id,
                asset_name=asset.get("hostname", asset_id),
                asset_ip=asset.get("ipv4"),
                asset_environment=self._infer_environment(asset),
                cvss_score=plugin.get("cvss3_base_score") or plugin.get("cvss_base_score"),
                cvss_vector=plugin.get("cvss3_vector") or plugin.get("cvss_vector"),
                severity_label=self.SEVERITY_MAP.get(severity_id, "low"),
                remediation_action=plugin.get("solution"),
                first_found=self._parse_ts(vuln.get("first_found")),
                last_found=self._parse_ts(vuln.get("last_found")),
                raw=vuln,
            )
        except Exception as e:
            logger.warning(f"Could not map Tenable finding: {e}")
            return None

    @staticmethod
    def _infer_finding_type(plugin: dict) -> str:
        family = plugin.get("family", {}).get("name", "").lower()
        if any(k in family for k in ["web", "application", "http"]):
            return "application"
        if any(k in family for k in ["policy", "config", "compliance"]):
            return "configuration"
        return "network"

    @staticmethod
    def _infer_environment(asset: dict) -> str:
        tags = asset.get("tags", [])
        for tag in tags:
            val = tag.get("value", "").lower()
            if val in ("production", "prod"):
                return "production"
            if val in ("staging", "stage"):
                return "staging"
            if val in ("development", "dev"):
                return "development"
        return "unknown"

    @staticmethod
    def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
        if not ts:
            return None
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None
