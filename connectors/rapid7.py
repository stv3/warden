"""
Rapid7 InsightVM connector.

Uses the InsightVM REST API v3 with API key authentication.
Required env vars: RAPID7_URL, RAPID7_API_KEY
Optional:          RAPID7_SITE_ID (limit to a specific site; omit for all sites)

Docs: https://help.rapid7.com/insightvm/en-us/api/index.html
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
    "Severe":   "high",
    "Moderate": "medium",
    "Low":      "low",
    "Info":     "low",
    "None":     "low",
}


class Rapid7Connector(BaseConnector):
    """
    Fetches vulnerability findings from Rapid7 InsightVM via REST API v3.
    InsightVM combines asset discovery, vulnerability assessment, and risk prioritisation.
    """

    def __init__(self):
        self._base_url = (settings.rapid7_url or "").rstrip("/")
        self._api_key  = settings.rapid7_api_key
        self._site_id  = settings.rapid7_site_id  # optional filter

    def _client(self) -> httpx.Client:
        return httpx.Client(
            headers={
                "X-Api-Key": self._api_key,
                "Accept":    "application/json",
            },
            verify=False,  # InsightVM on-prem typically uses self-signed certs
            timeout=60,
        )

    def test_connection(self) -> bool:
        try:
            with self._client() as client:
                resp = client.get(f"{self._base_url}/api/3/administration/info")
                resp.raise_for_status()
            logger.info("Rapid7 InsightVM connection: OK")
            return True
        except Exception as e:
            logger.error("Rapid7 connection failed: %s", e)
            return False

    def fetch_findings(self) -> list[RawFinding]:
        logger.info("Fetching findings from Rapid7 InsightVM")
        findings: list[RawFinding] = []

        with self._client() as client:
            assets = self._fetch_assets(client)
            logger.info("InsightVM: scanning %d assets for vulnerabilities", len(assets))

            for asset in assets:
                asset_id   = str(asset.get("id", ""))
                asset_name = asset.get("hostName") or asset.get("ip") or asset_id
                asset_ip   = asset.get("ip")
                asset_env  = self._infer_environment(asset_name)

                for vuln in self._fetch_asset_vulns(client, asset_id):
                    raw = self._map_finding(vuln, asset_id, asset_name, asset_ip, asset_env)
                    if raw:
                        findings.append(raw)

        logger.info("Rapid7: fetched %d findings", len(findings))
        return findings

    def _fetch_assets(self, client: httpx.Client) -> list[dict]:
        assets: list[dict] = []
        page, size = 0, 500

        base = (
            f"{self._base_url}/api/3/sites/{self._site_id}/assets"
            if self._site_id
            else f"{self._base_url}/api/3/assets"
        )

        while True:
            resp = client.get(base, params={"page": page, "size": size})
            resp.raise_for_status()
            data = resp.json()
            resources = data.get("resources") or []
            assets.extend(resources)

            page_info = data.get("page", {})
            total_pages = page_info.get("totalPages", 1)
            if page + 1 >= total_pages:
                break
            page += 1

        return assets

    def _fetch_asset_vulns(self, client: httpx.Client, asset_id: str) -> list[dict]:
        vulns: list[dict] = []
        page = 0

        while True:
            resp = client.get(
                f"{self._base_url}/api/3/assets/{asset_id}/vulnerabilities",
                params={"page": page, "size": 500},
            )
            if resp.status_code == 404:
                break
            resp.raise_for_status()
            data = resp.json()
            vulns.extend(data.get("resources") or [])

            page_info = data.get("page", {})
            if page + 1 >= page_info.get("totalPages", 1):
                break
            page += 1

        return vulns

    def _map_finding(
        self,
        vuln: dict,
        asset_id: str,
        asset_name: str,
        asset_ip: Optional[str],
        asset_env: str,
    ) -> Optional[RawFinding]:
        try:
            vuln_id = vuln.get("id", "")
            severity_raw = vuln.get("severity", "Low")
            cvss_raw = vuln.get("cvssV3", {}) or vuln.get("cvss", {}) or {}

            cve_refs = [
                r.get("referenceId", "")
                for r in (vuln.get("references") or [])
                if r.get("source", "").upper() == "CVE"
            ]
            cve_id = cve_refs[0] if cve_refs else None

            cvss_score: Optional[float] = None
            raw_score = cvss_raw.get("score")
            if raw_score is not None:
                try:
                    cvss_score = float(raw_score)
                except (ValueError, TypeError):
                    pass

            return RawFinding(
                cve_id=cve_id,
                title=vuln.get("title") or str(vuln_id),
                description=vuln.get("description", {}).get("text") if isinstance(vuln.get("description"), dict) else None,
                source="rapid7",
                source_finding_id=f"{asset_id}:{vuln_id}",
                finding_type=self._infer_finding_type(vuln),
                asset_id=asset_id,
                asset_name=asset_name,
                asset_ip=asset_ip,
                asset_environment=asset_env,
                cvss_score=cvss_score,
                cvss_vector=cvss_raw.get("vector"),
                severity_label=SEVERITY_MAP.get(severity_raw, "low"),
                remediation_action=self._get_remediation(vuln),
                first_found=self._parse_ts(vuln.get("since")),
                last_found=None,
                raw={
                    "vuln_id":     vuln_id,
                    "severity":    severity_raw,
                    "risk_score":  vuln.get("riskScore"),
                    "exploits":    vuln.get("exploits", 0),
                    "malware_kits": vuln.get("malwareKits", 0),
                },
            )
        except Exception as e:
            logger.warning("Could not map Rapid7 finding: %s", e)
            return None

    @staticmethod
    def _infer_finding_type(vuln: dict) -> str:
        categories = [c.lower() for c in (vuln.get("categories") or [])]
        if any(c in categories for c in ("web", "application", "http")):
            return "application"
        if any(c in categories for c in ("policy", "configuration", "compliance")):
            return "configuration"
        return "network"

    @staticmethod
    def _get_remediation(vuln: dict) -> Optional[str]:
        sol = vuln.get("solution") or {}
        if isinstance(sol, dict):
            return sol.get("summary") or sol.get("text")
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
