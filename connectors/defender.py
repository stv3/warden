"""
Microsoft Defender for Endpoint connector.

Uses the Microsoft Graph Security API / Defender TVM API via OAuth2 client credentials.
Required env vars: DEFENDER_TENANT_ID, DEFENDER_CLIENT_ID, DEFENDER_CLIENT_SECRET
Optional:  DEFENDER_MACHINE_GROUPS (comma-separated list to filter by machine group)

Docs: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api-hello-world
"""
import logging
from datetime import datetime
from typing import Optional

import httpx

from connectors.base import BaseConnector, RawFinding
from config.settings import settings

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "Critical": "critical",
    "High":     "high",
    "Medium":   "medium",
    "Low":      "low",
    "None":     "low",
}


class DefenderConnector(BaseConnector):
    """
    Fetches vulnerability findings from Microsoft Defender for Endpoint
    Threat and Vulnerability Management (TVM).
    """

    _TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    _BASE_URL  = "https://api.securitycenter.microsoft.com/api"
    _SCOPE     = "https://api.securitycenter.microsoft.com/.default"

    def __init__(self):
        self._tenant_id     = settings.defender_tenant_id
        self._client_id     = settings.defender_client_id
        self._client_secret = settings.defender_client_secret
        self._machine_groups = [
            g.strip() for g in (settings.defender_machine_groups or "").split(",") if g.strip()
        ]
        self._access_token: Optional[str] = None

    def _authenticate(self) -> str:
        url = self._TOKEN_URL.format(tenant_id=self._tenant_id)
        resp = httpx.post(url, data={
            "grant_type":    "client_credentials",
            "client_id":     self._client_id,
            "client_secret": self._client_secret,
            "scope":         self._SCOPE,
        }, timeout=30)
        resp.raise_for_status()
        self._access_token = resp.json()["access_token"]
        return self._access_token

    def _client(self) -> httpx.Client:
        if not self._access_token:
            self._authenticate()
        return httpx.Client(
            headers={"Authorization": f"Bearer {self._access_token}"},
            timeout=60,
        )

    def test_connection(self) -> bool:
        try:
            token = self._authenticate()
            with httpx.Client(headers={"Authorization": f"Bearer {token}"}, timeout=15) as client:
                resp = client.get(f"{self._BASE_URL}/machines?$top=1")
                resp.raise_for_status()
            logger.info("Defender connection: OK")
            return True
        except Exception as e:
            logger.error("Defender connection failed: %s", e)
            return False

    def fetch_findings(self) -> list[RawFinding]:
        logger.info("Fetching findings from Microsoft Defender TVM")
        self._authenticate()
        findings: list[RawFinding] = []

        url = f"{self._BASE_URL}/vulnerabilities/machinesVulnerabilities"
        params = {"$top": 10000}

        with self._client() as client:
            while url:
                resp = client.get(url, params=params)
                resp.raise_for_status()
                data = resp.json()

                for item in data.get("value", []):
                    raw = self._map_finding(item)
                    if raw:
                        findings.append(raw)

                # Follow OData @odata.nextLink for pagination
                url = data.get("@odata.nextLink")
                params = {}

        logger.info("Defender: fetched %d findings", len(findings))
        return findings

    def _map_finding(self, item: dict) -> Optional[RawFinding]:
        try:
            machine_id   = item.get("machineId", "unknown")
            machine_name = item.get("computerDnsName") or machine_id
            cve_id       = item.get("cveId")
            severity_raw = item.get("severity", "Low")

            if not cve_id:
                return None

            asset_env = self._infer_environment(machine_name)

            return RawFinding(
                cve_id=cve_id,
                title=item.get("vulnerabilityDescription") or cve_id,
                description=item.get("vulnerabilityDescription"),
                source="defender",
                source_finding_id=f"{machine_id}:{cve_id}",
                finding_type="network",
                asset_id=machine_id,
                asset_name=machine_name,
                asset_ip=None,
                asset_environment=asset_env,
                cvss_score=item.get("cvssV3"),
                cvss_vector=None,
                severity_label=SEVERITY_MAP.get(severity_raw, "low"),
                remediation_action=item.get("recommendedProgram"),
                first_found=self._parse_ts(item.get("firstSeenTimestamp")),
                last_found=self._parse_ts(item.get("lastSeenTimestamp")),
                raw={
                    "machineId":      machine_id,
                    "severity":       severity_raw,
                    "productName":    item.get("productName"),
                    "productVersion": item.get("productVersion"),
                    "productVendor":  item.get("productVendor"),
                    "exploitability": item.get("exploitabilityLevel"),
                },
            )
        except Exception as e:
            logger.warning("Could not map Defender finding: %s", e)
            return None

    @staticmethod
    def _infer_environment(hostname: str) -> str:
        h = (hostname or "").lower()
        if any(k in h for k in ("prod", "prd")):
            return "production"
        if any(k in h for k in ("stg", "stage", "staging")):
            return "staging"
        if any(k in h for k in ("dev", "development")):
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
