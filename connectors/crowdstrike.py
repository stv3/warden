"""
CrowdStrike Falcon Spotlight connector.

Uses CrowdStrike OAuth2 API — Spotlight Vulnerabilities scope required.
Required env vars: CROWDSTRIKE_CLIENT_ID, CROWDSTRIKE_CLIENT_SECRET
Optional:          CROWDSTRIKE_BASE_URL (defaults to US-1 cloud)

Docs: https://developer.crowdstrike.com/crowdstrike/docs/spotlight-api-overview
"""
import logging
from datetime import datetime
from typing import Optional

import httpx

from connectors.base import BaseConnector, RawFinding
from config.settings import settings

logger = logging.getLogger(__name__)

# CrowdStrike severity is 0-100; map buckets to labels
def _cs_severity(score: Optional[float]) -> str:
    if score is None:
        return "low"
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


class CrowdStrikeConnector(BaseConnector):
    """
    Fetches vulnerability findings from CrowdStrike Falcon Spotlight.
    Spotlight provides real-time vulnerability visibility across all Falcon-enrolled endpoints.
    """

    _DEFAULT_BASE_URL = "https://api.crowdstrike.com"

    def __init__(self):
        self._client_id     = settings.crowdstrike_client_id
        self._client_secret = settings.crowdstrike_client_secret
        self._base_url      = (settings.crowdstrike_base_url or self._DEFAULT_BASE_URL).rstrip("/")
        self._access_token: Optional[str] = None

    def _authenticate(self) -> str:
        resp = httpx.post(
            f"{self._base_url}/oauth2/token",
            data={
                "client_id":     self._client_id,
                "client_secret": self._client_secret,
            },
            timeout=30,
        )
        resp.raise_for_status()
        self._access_token = resp.json()["access_token"]
        return self._access_token

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._access_token}"}

    def test_connection(self) -> bool:
        try:
            self._authenticate()
            resp = httpx.get(
                f"{self._base_url}/spotlight/queries/vulnerabilities/v1",
                headers=self._headers(),
                params={"limit": 1},
                timeout=15,
            )
            resp.raise_for_status()
            logger.info("CrowdStrike connection: OK")
            return True
        except Exception as e:
            logger.error("CrowdStrike connection failed: %s", e)
            return False

    def fetch_findings(self) -> list[RawFinding]:
        logger.info("Fetching findings from CrowdStrike Falcon Spotlight")
        self._authenticate()
        findings: list[RawFinding] = []

        # Step 1: get all vulnerability IDs (paginated)
        vuln_ids: list[str] = []
        after: Optional[str] = None

        with httpx.Client(headers=self._headers(), timeout=60) as client:
            while True:
                params: dict = {
                    "limit":  5000,
                    "filter": "status:'open'",
                }
                if after:
                    params["after"] = after

                resp = client.get(
                    f"{self._base_url}/spotlight/queries/vulnerabilities/v1",
                    params=params,
                )
                resp.raise_for_status()
                data = resp.json()
                resources = data.get("resources") or []
                vuln_ids.extend(resources)

                pagination = data.get("meta", {}).get("pagination", {})
                after = pagination.get("after")
                if not after or not resources:
                    break

            # Step 2: fetch details in batches of 400
            for i in range(0, len(vuln_ids), 400):
                batch = vuln_ids[i:i + 400]
                resp = client.get(
                    f"{self._base_url}/spotlight/entities/vulnerabilities/v2",
                    params=[("ids", vid) for vid in batch],
                )
                resp.raise_for_status()

                for item in resp.json().get("resources") or []:
                    raw = self._map_finding(item)
                    if raw:
                        findings.append(raw)

        logger.info("CrowdStrike: fetched %d findings", len(findings))
        return findings

    def _map_finding(self, item: dict) -> Optional[RawFinding]:
        try:
            cve     = item.get("cve") or {}
            cve_id  = cve.get("id")
            host    = item.get("host_info") or {}
            vuln_id = item.get("id", "unknown")

            hostname = host.get("hostname") or host.get("local_ip") or vuln_id
            asset_id = host.get("aid") or hostname

            cvss_raw = cve.get("base_score")
            try:
                cvss_score = float(cvss_raw) if cvss_raw else None
            except (ValueError, TypeError):
                cvss_score = None

            severity_score = item.get("severity_score")
            try:
                severity_score = float(severity_score) if severity_score else None
            except (ValueError, TypeError):
                severity_score = None

            return RawFinding(
                cve_id=cve_id,
                title=cve.get("description") or cve_id or f"Spotlight-{vuln_id}",
                description=cve.get("description"),
                source="crowdstrike",
                source_finding_id=vuln_id,
                finding_type="network",
                asset_id=asset_id,
                asset_name=hostname,
                asset_ip=host.get("local_ip"),
                asset_environment=self._infer_environment(hostname),
                cvss_score=cvss_score,
                cvss_vector=cve.get("vector"),
                severity_label=_cs_severity(severity_score),
                remediation_action=self._build_remediation(item),
                first_found=self._parse_ts(item.get("created_timestamp")),
                last_found=self._parse_ts(item.get("updated_timestamp")),
                raw={
                    "vuln_id":         vuln_id,
                    "severity_score":  severity_score,
                    "status":          item.get("status"),
                    "product_name":    item.get("app", {}).get("product_name_version"),
                    "remediation":     item.get("remediation", {}).get("ids"),
                },
            )
        except Exception as e:
            logger.warning("Could not map CrowdStrike finding: %s", e)
            return None

    @staticmethod
    def _build_remediation(item: dict) -> Optional[str]:
        rem = item.get("remediation") or {}
        entities = rem.get("entities") or []
        if entities:
            return "; ".join(
                e.get("action", "") for e in entities if e.get("action")
            ) or None
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
