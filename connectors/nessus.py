"""
Connector for Nessus Professional (local/self-hosted).
Uses the Nessus REST API directly — no SDK dependency.

Auth flow: POST /session → token → X-Cookie header on all subsequent requests.
"""
import httpx
import logging
import urllib3
from datetime import datetime
from typing import Optional

from connectors.base import BaseConnector, RawFinding
from config.settings import settings

# Nessus uses self-signed certs by default — suppress warnings for local instances
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


SEVERITY_MAP = {
    4: "critical",
    3: "high",
    2: "medium",
    1: "low",
    0: "informational",
}


class NessusConnector(BaseConnector):
    """
    Connects to a local Nessus Professional instance.
    Fetches all completed scan results and maps them to RawFindings.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
    ):
        self.base_url = (url or settings.nessus_url or "").rstrip("/")
        self._username = username or settings.nessus_username
        self._password = password or settings.nessus_password
        self._verify_ssl = verify_ssl if verify_ssl is not None else settings.nessus_verify_ssl
        self._token: Optional[str] = None

    # -------------------------------------------------------------------------
    # Public interface
    # -------------------------------------------------------------------------

    def test_connection(self) -> bool:
        try:
            self._authenticate()
            logger.info(f"Nessus connection OK: {self.base_url}")
            return True
        except Exception as e:
            logger.error(f"Nessus connection failed: {e}")
            return False

    def fetch_findings(self) -> list[RawFinding]:
        self._authenticate()
        scans = self._list_completed_scans()
        logger.info(f"Nessus: found {len(scans)} completed scans")

        all_findings: list[RawFinding] = []
        for scan in scans:
            scan_id = scan["id"]
            scan_name = scan.get("name", f"scan-{scan_id}")
            try:
                findings = self._fetch_scan_findings(scan_id, scan_name)
                all_findings.extend(findings)
                logger.info(f"  Scan '{scan_name}': {len(findings)} findings")
            except Exception as e:
                logger.warning(f"  Scan '{scan_name}' failed: {e}")

        logger.info(f"Nessus total: {len(all_findings)} findings across {len(scans)} scans")
        return all_findings

    def list_scans(self) -> list[dict]:
        """Utility: returns all scans (any status) with summary info."""
        self._authenticate()
        response = self._get("/scans")
        scans = response.get("scans") or []
        return [
            {
                "id": s["id"],
                "name": s.get("name"),
                "status": s.get("status"),
                "last_modification_date": s.get("last_modification_date"),
            }
            for s in scans
        ]

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    def _authenticate(self) -> None:
        """Authenticates and stores the session token."""
        with self._client() as client:
            response = client.post(
                f"{self.base_url}/session",
                json={"username": self._username, "password": self._password},
            )
            response.raise_for_status()
            self._token = response.json()["token"]
            logger.debug("Nessus: authenticated")

    def _list_completed_scans(self) -> list[dict]:
        data = self._get("/scans")
        scans = data.get("scans") or []
        return [s for s in scans if s.get("status") in ("completed", "imported")]

    def _fetch_scan_findings(self, scan_id: int, scan_name: str) -> list[RawFinding]:
        data = self._get(f"/scans/{scan_id}")
        hosts = data.get("hosts") or []
        vulnerabilities_summary = {v["plugin_id"]: v for v in (data.get("vulnerabilities") or [])}

        findings: list[RawFinding] = []
        for host in hosts:
            host_id = host["host_id"]
            host_ip = host.get("hostname", str(host_id))
            host_name = host.get("hostname", host_ip)
            asset_env = self._infer_environment(host_name)

            host_detail = self._get(f"/scans/{scan_id}/hosts/{host_id}")
            for vuln in (host_detail.get("vulnerabilities") or []):
                severity = vuln.get("severity", 0)
                if severity < 0:
                    continue

                plugin_id = vuln["plugin_id"]
                plugin_detail = self._get_plugin_detail(scan_id, host_id, plugin_id)
                raw = self._map_vulnerability(
                    vuln, plugin_detail, host_ip, host_name, asset_env, scan_name
                )
                if raw:
                    findings.append(raw)

        return findings

    def _get_plugin_detail(self, scan_id: int, host_id: int, plugin_id: int) -> dict:
        try:
            return self._get(f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}")
        except Exception:
            return {}

    def _map_vulnerability(
        self,
        vuln: dict,
        plugin_detail: dict,
        host_ip: str,
        host_name: str,
        asset_env: str,
        scan_name: str,
    ) -> Optional[RawFinding]:
        try:
            plugin_id = vuln["plugin_id"]
            severity = vuln.get("severity", 0)
            plugin_name = vuln.get("plugin_name", f"Plugin {plugin_id}")

            # Extract CVEs from plugin detail
            attributes = plugin_detail.get("info", {}).get("pluginattributes", {})
            ref_info = attributes.get("ref_information", {})
            refs = ref_info.get("ref", []) if isinstance(ref_info.get("ref"), list) else []
            cve_id = self._extract_cve(refs, attributes)

            risk_info = attributes.get("risk_information", {})
            cvss_score = self._safe_float(
                risk_info.get("cvss3_base_score") or risk_info.get("cvss_base_score")
            )
            cvss_vector = risk_info.get("cvss3_vector") or risk_info.get("cvss_vector")

            plugin_info = attributes.get("plugin_information", {})
            solution = attributes.get("solution", {})
            solution_text = solution if isinstance(solution, str) else solution.get("#text", "")

            return RawFinding(
                cve_id=cve_id,
                title=plugin_name,
                description=str(attributes.get("description", {}).get("#text", ""))[:1000] or None,
                source="nessus",
                source_finding_id=f"{host_ip}:{plugin_id}",
                finding_type=self._infer_finding_type(attributes),
                asset_id=host_ip,
                asset_name=host_name,
                asset_ip=host_ip if host_ip != host_name else None,
                asset_environment=asset_env,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                severity_label=SEVERITY_MAP.get(severity, "low"),
                remediation_action=solution_text or None,
                raw={
                    "plugin_id": plugin_id,
                    "scan_name": scan_name,
                    "severity": severity,
                },
            )
        except Exception as e:
            logger.debug(f"Could not map plugin {vuln.get('plugin_id')}: {e}")
            return None

    # -------------------------------------------------------------------------
    # HTTP helpers
    # -------------------------------------------------------------------------

    def _client(self) -> httpx.Client:
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["X-Cookie"] = f"token={self._token}"
        return httpx.Client(
            headers=headers,
            verify=self._verify_ssl,
            timeout=30,
        )

    def _get(self, path: str) -> dict:
        with self._client() as client:
            response = client.get(f"{self.base_url}{path}")
            response.raise_for_status()
            return response.json()

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _extract_cve(refs: list, attributes: dict) -> Optional[str]:
        """Pulls the first CVE from plugin references."""
        for ref in refs:
            name = ref.get("@name", "").upper()
            if name == "CVE":
                values = ref.get("url", [])
                if isinstance(values, list) and values:
                    cve = values[0]
                elif isinstance(values, str):
                    cve = values
                else:
                    continue
                if cve.upper().startswith("CVE-"):
                    return cve.upper()
        # Fallback: check see_also
        see_also = attributes.get("see_also", "")
        if isinstance(see_also, str):
            for token in see_also.split():
                if token.upper().startswith("CVE-"):
                    return token.upper()
        return None

    @staticmethod
    def _infer_finding_type(attributes: dict) -> str:
        family = str(attributes.get("plugin_information", {}).get("plugin_family", "")).lower()
        if any(k in family for k in ("web", "application", "http")):
            return "application"
        if any(k in family for k in ("policy", "compliance", "config")):
            return "configuration"
        return "network"

    @staticmethod
    def _infer_environment(hostname: str) -> str:
        h = hostname.lower()
        if any(k in h for k in ("prod", "prd")):
            return "production"
        if any(k in h for k in ("stg", "stage")):
            return "staging"
        if any(k in h for k in ("dev",)):
            return "development"
        return "unknown"

    @staticmethod
    def _safe_float(value) -> Optional[float]:
        try:
            return float(value) if value else None
        except (ValueError, TypeError):
            return None
