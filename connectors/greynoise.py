"""
GreyNoise enricher — adds internet-scanning context to CVE findings.

GreyNoise tracks which CVEs are being actively scanned and exploited by
internet-wide scanners. This provides a real-time "exploitation in the wild"
signal that complements CISA KEV (confirmed exploited) and EPSS (probability).

Signal interpretation:
  • malicious_count > 0  → actively exploited by known bad actors
  • noise_count > 0      → CVE is being probed broadly across the internet
  • Neither              → no known scanning activity

This enricher:
  1. Accepts a list of open findings
  2. Queries GreyNoise CVE Intelligence API for each unique CVE
  3. Sets has_public_exploit = True for CVEs with malicious scanning activity
  4. Stores noise/scan counts in the finding for dashboard display

API key: https://www.greynoise.io/plans  (free community tier available)
Set GREYNOISE_API_KEY in .env to enable.

Rate limits:
  • Community (free): 50 CVE lookups/day
  • Business:         unlimited

API docs: https://docs.greynoise.io/reference/get_v3-cve-cve-id
"""
import logging
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)

GREYNOISE_CVE_URL = "https://api.greynoise.io/v3/cve/{cve_id}"
_REQUEST_DELAY = 0.5   # seconds between requests — be a good API citizen


class GreyNoiseEnricher:
    """
    Enriches findings with GreyNoise CVE scanning intelligence.

    Usage:
        enricher = GreyNoiseEnricher(api_key=settings.greynoise_api_key)
        enricher.enrich(open_findings)
        db.commit()
    """

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key
        self._cache: dict[str, Optional[dict]] = {}
        self._enabled = bool(api_key)

        if not self._enabled:
            logger.info("GreyNoise: no API key configured — skipping CVE enrichment")

    def enrich(self, findings: list) -> list:
        """
        Enrich findings with GreyNoise data.
        Modifies findings in-place; returns the same list.
        """
        if not self._enabled:
            return findings

        # Collect unique CVE IDs
        cve_ids = {f.cve_id for f in findings if f.cve_id}
        if not cve_ids:
            return findings

        logger.info("GreyNoise: enriching %d unique CVEs", len(cve_ids))
        enriched_count = 0

        for cve_id in sorted(cve_ids):
            data = self._fetch_cve(cve_id)
            if data is None:
                continue

            malicious = data.get("malicious_count", 0) or 0
            noise     = data.get("noise_count", data.get("ips_seen", 0)) or 0
            exploited = data.get("is_exploited", False)

            if malicious > 0 or exploited:
                for f in findings:
                    if f.cve_id == cve_id:
                        # Mark as actively exploited — highest confidence signal
                        if not f.has_public_exploit:
                            f.has_public_exploit = True
                            enriched_count += 1
                        # Merge GreyNoise metadata into existing raw dict
                        if isinstance(f.raw, dict):
                            f.raw = {**f.raw, "greynoise_malicious": malicious, "greynoise_noise": noise}
                        logger.debug("GreyNoise: %s flagged — malicious=%d noise=%d", cve_id, malicious, noise)

            elif noise > 0:
                # Broad scanning, not confirmed malicious — just annotate
                for f in findings:
                    if f.cve_id == cve_id and isinstance(f.raw, dict):
                        f.raw = {**f.raw, "greynoise_noise": noise}

            time.sleep(_REQUEST_DELAY)

        logger.info("GreyNoise: %d findings updated (has_public_exploit set)", enriched_count)
        return findings

    def _fetch_cve(self, cve_id: str) -> Optional[dict]:
        if cve_id in self._cache:
            return self._cache[cve_id]

        try:
            resp = requests.get(
                GREYNOISE_CVE_URL.format(cve_id=cve_id),
                headers={
                    "key": self._api_key,
                    "Accept": "application/json",
                    "User-Agent": "warden-vuln-orchestrator/1.0",
                },
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                self._cache[cve_id] = data
                return data
            if resp.status_code == 404:
                # CVE not in GreyNoise — normal, not an error
                self._cache[cve_id] = None
                return None
            if resp.status_code == 429:
                logger.warning("GreyNoise rate limit hit — pausing 60s")
                time.sleep(60)
                return None
            if resp.status_code in (401, 403):
                logger.error("GreyNoise auth error (%d) — check GREYNOISE_API_KEY", resp.status_code)
                self._enabled = False  # Stop retrying on auth failure
                return None
            logger.warning("GreyNoise API returned %d for %s", resp.status_code, cve_id)
        except requests.RequestException as exc:
            logger.warning("GreyNoise request failed for %s: %s", cve_id, exc)

        return None
