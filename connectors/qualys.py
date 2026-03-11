import httpx
import logging
import defusedxml.ElementTree as ET        # safe parsing — prevents XXE attacks
from xml.etree.ElementTree import Element  # type hint only; parsing still uses defusedxml
from datetime import datetime
from typing import Optional

from connectors.base import BaseConnector, RawFinding
from config.settings import settings

logger = logging.getLogger(__name__)


class QualysConnector(BaseConnector):
    """
    Fetches vulnerability findings from Qualys VMDR via the Qualys API v2.
    Uses basic auth + XML responses (standard Qualys API).
    """

    SEVERITY_MAP = {
        5: "critical",
        4: "high",
        3: "medium",
        2: "low",
        1: "low",
    }

    def __init__(self):
        self._base_url = settings.qualys_api_url
        self._auth = (settings.qualys_username, settings.qualys_password)

    def _client(self) -> httpx.Client:
        return httpx.Client(
            auth=self._auth,
            headers={
                "X-Requested-With": "VulnOrchestrator",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout=60,
        )

    def test_connection(self) -> bool:
        try:
            with self._client() as client:
                response = client.get(f"{self._base_url}/api/2.0/fo/activity_log/", params={"action": "list", "truncation_limit": "1"})
                response.raise_for_status()
                logger.info("Qualys connection: OK")
                return True
        except Exception as e:
            logger.error(f"Qualys connection failed: {e}")
            return False

    def fetch_findings(self) -> list[RawFinding]:
        """Fetches active host detections from Qualys VMDR."""
        logger.info("Fetching findings from Qualys")
        raw_xml = self._fetch_host_detections()
        findings = self._parse_detections(raw_xml)
        logger.info(f"Qualys: fetched {len(findings)} findings")
        return findings

    def _fetch_host_detections(self) -> str:
        """Calls Qualys host detection API and returns raw XML."""
        params = {
            "action": "list",
            "show_results": "1",
            "status": "Active,New,Re-Opened",
            "show_igs": "0",
            "output_format": "XML",
            "truncation_limit": "0",  # Get all results
        }
        with self._client() as client:
            response = client.post(
                f"{self._base_url}/api/2.0/fo/asset/host/vm/detection/",
                data=params,
            )
            response.raise_for_status()
            return response.text

    def _parse_detections(self, xml_content: str) -> list[RawFinding]:
        findings = []
        try:
            root = ET.fromstring(xml_content)
            hosts = root.findall(".//HOST")

            for host in hosts:
                asset_id = host.findtext("IP", "unknown")
                asset_name = host.findtext("DNS", asset_id)
                asset_ip = host.findtext("IP")
                asset_env = self._infer_environment(asset_name)

                for detection in host.findall(".//DETECTION"):
                    raw_finding = self._map_detection(detection, asset_id, asset_name, asset_ip, asset_env)
                    if raw_finding:
                        findings.append(raw_finding)

        except ET.ParseError as e:
            logger.error(f"Failed to parse Qualys XML: {e}")

        return findings

    def _map_detection(
        self, detection: Element, asset_id: str, asset_name: str, asset_ip: Optional[str], asset_env: str
    ) -> Optional[RawFinding]:
        try:
            qid = detection.findtext("QID", "")
            severity = int(detection.findtext("SEVERITY", "0"))

            if severity == 0:
                return None

            cve_list = detection.findtext("CVE_IDS", "")
            cve_id = cve_list.split(",")[0].strip() if cve_list else None

            return RawFinding(
                cve_id=cve_id or None,
                title=detection.findtext("RESULTS", f"QID-{qid}")[:200],
                description=None,
                source="qualys",
                source_finding_id=f"{asset_id}:{qid}",
                finding_type=self._infer_finding_type(detection),
                asset_id=asset_id,
                asset_name=asset_name,
                asset_ip=asset_ip,
                asset_environment=asset_env,
                cvss_score=self._safe_float(detection.findtext("CVSS3_BASE")),
                cvss_vector=detection.findtext("CVSS3_TEMPORAL_VECTOR"),
                severity_label=self.SEVERITY_MAP.get(severity, "low"),
                remediation_action=detection.findtext("SOLUTION"),
                first_found=self._parse_ts(detection.findtext("FIRST_FOUND_DATETIME")),
                last_found=self._parse_ts(detection.findtext("LAST_FOUND_DATETIME")),
                raw={
                    "qid": qid,
                    "severity": severity,
                    "type": detection.findtext("TYPE"),
                },
            )
        except Exception as e:
            logger.warning(f"Could not map Qualys detection: {e}")
            return None

    @staticmethod
    def _infer_finding_type(detection: Element) -> str:
        detection_type = detection.findtext("TYPE", "").upper()
        if detection_type == "IG":
            return "configuration"
        return "network"

    @staticmethod
    def _infer_environment(hostname: str) -> str:
        hostname = hostname.lower()
        if any(k in hostname for k in ("prod", "prd")):
            return "production"
        if any(k in hostname for k in ("stg", "stage", "staging")):
            return "staging"
        if any(k in hostname for k in ("dev", "development")):
            return "development"
        return "unknown"

    @staticmethod
    def _safe_float(value: Optional[str]) -> Optional[float]:
        try:
            return float(value) if value else None
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
        if not ts:
            return None
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None
