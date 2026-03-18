"""
NVD (National Vulnerability Database) enricher.
Fetches authoritative CVE data from the NVD API v2.0:
  - CWE classification
  - Published date (original disclosure)
  - Patch availability (references tagged "Patch")
  - Attack vector (from CVSS vector string)
  - CVSS v3.1 / v4.0 base scores
"""
import logging
import time
from dataclasses import dataclass, field
from datetime import date
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Without an API key: 5 requests per 30 seconds.  With key: 50/30s.
_RATE_LIMIT_SLEEP = 6.5  # seconds between requests (conservative, no key)


@dataclass
class NVDData:
    cve_id: str
    cwe_id: Optional[str] = None
    nvd_published_date: Optional[date] = None
    patch_available: bool = False
    attack_vector: Optional[str] = None  # N | A | L | P


class NVDEnricher:
    """
    Enriches findings with NVD data.
    Each CVE is fetched individually to stay within NVD rate limits.
    Results are cached in-memory for the lifetime of the pipeline run.
    """

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key
        self._cache: dict[str, NVDData] = {}
        self._sleep_secs = 0.7 if api_key else _RATE_LIMIT_SLEEP

    def enrich(self, findings: list) -> list:
        """Enrich findings list in-place with NVD data. Returns findings."""
        cve_ids = list({f.cve_id for f in findings if f.cve_id})
        if not cve_ids:
            return findings

        logger.info(f"NVD: fetching data for {len(cve_ids)} unique CVEs")
        nvd_map = self._fetch_bulk(cve_ids)

        for finding in findings:
            if not finding.cve_id:
                continue
            data = nvd_map.get(finding.cve_id.upper())
            if not data:
                continue
            if data.cwe_id and not finding.cwe_id:
                finding.cwe_id = data.cwe_id
            if data.nvd_published_date and not finding.nvd_published_date:
                finding.nvd_published_date = data.nvd_published_date
            if data.patch_available and not finding.patch_available:
                finding.patch_available = data.patch_available
            if data.attack_vector and not finding.attack_vector:
                finding.attack_vector = data.attack_vector

        logger.info(f"NVD: enriched {len(nvd_map)}/{len(cve_ids)} CVEs")
        return findings

    def _fetch_bulk(self, cve_ids: list[str]) -> dict[str, NVDData]:
        result: dict[str, NVDData] = {}
        headers = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        for i, cve_id in enumerate(cve_ids):
            cve_upper = cve_id.upper()
            if cve_upper in self._cache:
                result[cve_upper] = self._cache[cve_upper]
                continue

            try:
                with httpx.Client(timeout=15) as client:
                    resp = client.get(
                        NVD_API_URL,
                        params={"cveId": cve_upper},
                        headers=headers,
                    )
                    if resp.status_code == 403:
                        logger.warning("NVD: rate limited — slowing down")
                        time.sleep(30)
                        continue
                    resp.raise_for_status()
                    data = resp.json()

                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    nvd_data = self._parse(cve_upper, vulnerabilities[0].get("cve", {}))
                    self._cache[cve_upper] = nvd_data
                    result[cve_upper] = nvd_data

            except Exception as e:
                logger.warning(f"NVD fetch failed for {cve_id}: {e}")

            # Respect rate limit between requests
            if i < len(cve_ids) - 1:
                time.sleep(self._sleep_secs)

        return result

    @staticmethod
    def _parse(cve_id: str, cve: dict) -> NVDData:
        data = NVDData(cve_id=cve_id)

        # CWE
        weaknesses = cve.get("weaknesses", [])
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    data.cwe_id = val
                    break
            if data.cwe_id:
                break

        # Published date
        published_str = cve.get("published", "")
        if published_str:
            try:
                data.nvd_published_date = date.fromisoformat(published_str[:10])
            except ValueError:
                pass

        # Patch availability — check reference tags
        references = cve.get("references", [])
        patch_tags = {"Patch", "Vendor Advisory", "Mitigation"}
        for ref in references:
            tags = set(ref.get("tags", []))
            if tags & patch_tags:
                data.patch_available = True
                break

        # Attack vector from CVSS v3.1 or v4.0 vector string
        metrics = cve.get("metrics", {})
        vector_string = None

        # Prefer v3.1, fall back to v4.0 or v2.0
        for metric_key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                vector_string = metric_list[0].get("cvssData", {}).get("vectorString")
                break

        if vector_string:
            data.attack_vector = _parse_attack_vector(vector_string)

        return data


def _parse_attack_vector(vector_string: str) -> Optional[str]:
    """Extract AV component: N (Network) | A (Adjacent) | L (Local) | P (Physical)."""
    for part in vector_string.split("/"):
        if part.startswith("AV:"):
            return part.split(":")[1]
    return None
