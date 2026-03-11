"""
DAST Connector — parsea output de OWASP ZAP.
Convierte hallazgos de análisis dinámico a RawFindings normalizados.

ZAP genera alertas contra aplicaciones en ejecución — diferente a SAST que
analiza código fuente. Los hallazgos tienen riesks reales de red/HTTP.
"""
import json
import logging
import defusedxml.ElementTree as ET
from pathlib import Path
from typing import Optional

from connectors.base import BaseConnector, RawFinding

logger = logging.getLogger(__name__)

# ZAP risk levels → severity labels
ZAP_RISK_MAP = {
    "3": "high",
    "2": "medium",
    "1": "low",
    "0": "informational",
    "High":          "high",
    "Medium":        "medium",
    "Low":           "low",
    "Informational": "informational",
}

# ZAP confidence levels
ZAP_CONFIDENCE_MAP = {
    "3": "confirmed",
    "2": "medium",
    "1": "low",
    "0": "false_positive",
}

# Well-known ZAP alert IDs → CWE mapping
ZAP_CWE_MAP = {
    "40012": "CWE-79",   # Reflected XSS
    "40014": "CWE-79",   # Persistent XSS
    "40016": "CWE-79",   # XSS in HTTP response header
    "40017": "CWE-79",   # XSS in redirect
    "40018": "CWE-89",   # SQL Injection
    "40019": "CWE-89",   # SQL Injection - MySQL
    "40020": "CWE-89",   # SQL Injection - Hypersonic SQL
    "40021": "CWE-89",   # SQL Injection - Oracle
    "40022": "CWE-89",   # SQL Injection - PostgreSQL
    "40024": "CWE-89",   # SQL Injection - SQLite
    "40026": "CWE-89",   # SQL Injection - MsSQL
    "90022": "CWE-20",   # Application Error Disclosure
    "10021": "CWE-693",  # X-Content-Type-Options missing
    "10038": "CWE-693",  # Content Security Policy missing
    "10049": "CWE-693",  # Storable and Cacheable Content
    "10096": "CWE-16",   # Timestamp Disclosure
    "10202": "CWE-918",  # Absence of Anti-CSRF Tokens
    "20012": "CWE-209",  # Anti CSRF Tokens Scanner
    "90001": "CWE-829",  # Insecure JSF ViewState
    "90033": "CWE-829",  # Loosely Scoped Cookie
}


class DASTConnector(BaseConnector):
    """
    Parsea resultados de OWASP ZAP:
    - Formato XML:  zap -quickurl http://target -quickout report.xml
    - Formato JSON: zap -quickurl http://target -quickout report.json
    - ZAP Report:   via API o GUI export

    No hace conexiones de red — lee archivos de reporte locales.
    Puede parsear múltiples targets (múltiples archivos).
    """

    def __init__(
        self,
        zap_xml_file: str = "zap_report.xml",
        zap_json_file: Optional[str] = None,
        min_risk_level: int = 1,  # 0=info, 1=low, 2=medium, 3=high
    ):
        self.zap_xml_file = Path(zap_xml_file)
        self.zap_json_file = Path(zap_json_file) if zap_json_file else None
        self.min_risk_level = min_risk_level

    def test_connection(self) -> bool:
        has_xml = self.zap_xml_file.exists()
        has_json = self.zap_json_file and self.zap_json_file.exists()
        if not has_xml and not has_json:
            logger.error("No ZAP report files found. Run OWASP ZAP first.")
            return False
        logger.info(f"DAST files found — xml: {has_xml}, json: {has_json}")
        return True

    def fetch_findings(self) -> list[RawFinding]:
        findings = []

        if self.zap_xml_file.exists():
            findings.extend(self._parse_xml(self.zap_xml_file))

        if self.zap_json_file and self.zap_json_file.exists():
            findings.extend(self._parse_json(self.zap_json_file))

        # Filter by minimum risk level
        findings = [
            f for f in findings
            if self._severity_to_int(f.severity_label) >= self.min_risk_level
        ]

        logger.info(f"DAST: {len(findings)} findings (min_risk={self.min_risk_level})")
        return findings

    # -------------------------------------------------------------------------
    # XML parser (ZAP default report format)
    # -------------------------------------------------------------------------

    def _parse_xml(self, path: Path) -> list[RawFinding]:
        findings = []
        try:
            tree = ET.parse(str(path))
            root = tree.getroot()

            # ZAP XML structure: <OWASPZAPReport>/<site>/<alerts>/<alertitem>
            for site in root.findall(".//site"):
                target_host = site.get("name", "unknown")
                target_host = target_host.replace("https://", "").replace("http://", "").split("/")[0]

                for alert in site.findall(".//alertitem"):
                    finding = self._map_xml_alert(alert, target_host)
                    if finding:
                        findings.append(finding)

        except ET.ParseError as e:
            logger.error(f"Failed to parse ZAP XML: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing ZAP XML: {e}")
        return findings

    def _map_xml_alert(self, alert, target_host: str) -> Optional[RawFinding]:
        try:
            alert_id = alert.findtext("pluginid", "")
            name = alert.findtext("alert", alert.findtext("name", "Unknown Alert"))
            risk_code = alert.findtext("riskcode", "0")
            risk_desc = alert.findtext("riskdesc", "")
            confidence = alert.findtext("confidence", "1")
            desc = alert.findtext("desc", "")
            solution = alert.findtext("solution", "")
            reference = alert.findtext("reference", "")
            cweid = alert.findtext("cweid", "")
            wascid = alert.findtext("wascid", "")

            severity = ZAP_RISK_MAP.get(risk_code, "low")
            cwe_id = f"CWE-{cweid}" if cweid else ZAP_CWE_MAP.get(alert_id)

            # Collect affected URIs
            instances = alert.findall(".//instance")
            affected_uris = [inst.findtext("uri", "") for inst in instances[:5]]
            uri_sample = affected_uris[0] if affected_uris else ""

            description = (
                f"Alert: {name}\n"
                f"Risk: {risk_desc}\n"
                f"CWE: {cwe_id or 'N/A'} | WASC: {wascid or 'N/A'}\n"
                f"Confidence: {ZAP_CONFIDENCE_MAP.get(confidence, confidence)}\n"
                f"Description: {self._clean_html(desc)}\n"
                f"Affected URIs ({len(instances)} total): {', '.join(affected_uris[:3])}"
            )

            return RawFinding(
                cve_id=None,  # DAST alerts map to CWE, not CVE
                title=f"[DAST] {name}",
                description=description,
                source="zap",
                source_finding_id=f"{alert_id}::{target_host}",
                finding_type="application",
                asset_id=target_host,
                asset_name=target_host,
                asset_ip=None,
                asset_environment=self._infer_environment(target_host),
                cvss_score=None,
                cvss_vector=None,
                severity_label=severity,
                remediation_action=self._clean_html(solution) or reference,
                raw={
                    "alert_id": alert_id,
                    "risk_code": risk_code,
                    "confidence": confidence,
                    "cwe": cwe_id,
                    "wasc": wascid,
                    "uri_sample": uri_sample,
                    "instance_count": len(instances),
                },
            )
        except Exception as e:
            logger.warning(f"Could not map ZAP XML alert: {e}")
            return None

    # -------------------------------------------------------------------------
    # JSON parser (ZAP JSON report format)
    # -------------------------------------------------------------------------

    def _parse_json(self, path: Path) -> list[RawFinding]:
        findings = []
        try:
            with open(path) as f:
                data = json.load(f)

            # ZAP JSON: {"site": [{"@name": "...", "alerts": [...]}]}
            sites = data.get("site", [])
            if isinstance(sites, dict):
                sites = [sites]  # Single site case

            for site in sites:
                target_host = site.get("@name", "unknown")
                target_host = target_host.replace("https://", "").replace("http://", "").split("/")[0]

                for alert in site.get("alerts", []):
                    finding = self._map_json_alert(alert, target_host)
                    if finding:
                        findings.append(finding)

        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse ZAP JSON: {e}")
        return findings

    def _map_json_alert(self, alert: dict, target_host: str) -> Optional[RawFinding]:
        try:
            alert_id = alert.get("pluginid", "")
            name = alert.get("alert", alert.get("name", "Unknown Alert"))
            risk_code = str(alert.get("riskcode", "0"))
            confidence = str(alert.get("confidence", "1"))
            desc = alert.get("desc", "")
            solution = alert.get("solution", "")
            cweid = alert.get("cweid", "")
            wascid = alert.get("wascid", "")

            severity = ZAP_RISK_MAP.get(risk_code, "low")
            cwe_id = f"CWE-{cweid}" if cweid else ZAP_CWE_MAP.get(str(alert_id))

            instances = alert.get("instances", [])
            if isinstance(instances, dict):
                instances = instances.get("instance", [])
                if isinstance(instances, dict):
                    instances = [instances]

            affected_uris = [inst.get("uri", "") for inst in instances[:5]]
            uri_sample = affected_uris[0] if affected_uris else ""

            description = (
                f"Alert: {name}\n"
                f"CWE: {cwe_id or 'N/A'} | WASC: {wascid or 'N/A'}\n"
                f"Confidence: {ZAP_CONFIDENCE_MAP.get(confidence, confidence)}\n"
                f"Description: {self._clean_html(desc)}\n"
                f"Affected URIs ({len(instances)} total): {', '.join(affected_uris[:3])}"
            )

            return RawFinding(
                cve_id=None,
                title=f"[DAST] {name}",
                description=description,
                source="zap",
                source_finding_id=f"{alert_id}::{target_host}",
                finding_type="application",
                asset_id=target_host,
                asset_name=target_host,
                asset_ip=None,
                asset_environment=self._infer_environment(target_host),
                cvss_score=None,
                cvss_vector=None,
                severity_label=severity,
                remediation_action=self._clean_html(solution),
                raw={
                    "alert_id": alert_id,
                    "risk_code": risk_code,
                    "confidence": confidence,
                    "cwe": cwe_id,
                    "wasc": wascid,
                    "uri_sample": uri_sample,
                    "instance_count": len(instances),
                },
            )
        except Exception as e:
            logger.warning(f"Could not map ZAP JSON alert: {e}")
            return None

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _clean_html(text: str) -> str:
        """Strip basic HTML tags from ZAP descriptions."""
        import re
        if not text:
            return ""
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    @staticmethod
    def _infer_environment(hostname: str) -> str:
        hostname = hostname.lower()
        if any(k in hostname for k in ("prod", "prd")):
            return "production"
        if any(k in hostname for k in ("stg", "stage", "staging")):
            return "staging"
        if any(k in hostname for k in ("dev", "local", "localhost", "127.0.0.1")):
            return "development"
        return "unknown"

    @staticmethod
    def _severity_to_int(severity: str) -> int:
        return {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 3}.get(severity, 0)
