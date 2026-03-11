import logging
import yaml
from datetime import date, timedelta
from pathlib import Path
from typing import Optional

import httpx

from models.finding import Finding

logger = logging.getLogger(__name__)


class RiskEngine:
    """
    Calculates the composite risk score for each finding.
    Replaces CVSS-only scoring with context-aware risk that reflects
    actual business impact and exploitability.

    Score formula:
        base = (cvss * w_cvss) + (kev * w_kev) + (criticality_norm * w_asset) + (epss * w_epss)
        final = base * kev_multiplier (if in KEV)
        normalized to 0-10 scale
    """

    def __init__(self, config_path: str = "config/risk_model.yaml"):
        self._config = self._load_config(config_path)
        self._weights = self._config["scoring"]["weights"]
        self._kev_multiplier = self._config["scoring"]["kev_multiplier"]
        self._severity_thresholds = self._config["scoring"]["severity_thresholds"]
        self._sla_days = self._config["sla_days"]
        self._nist_map = self._config["nist_csf_mapping"]
        self._cis_map = self._config["cis_controls_mapping"]

    def score_finding(self, finding: Finding) -> Finding:
        """Calculates and sets risk_score, severity, sla_due_date, and compliance mappings."""

        # Normalize each component to 0-1
        cvss_norm = (finding.cvss_score or 0) / 10.0
        kev_norm = 1.0 if finding.in_kev else 0.0
        criticality_norm = (finding.asset_criticality or 2) / 5.0
        epss_norm = finding.epss_score or 0.0

        # Weighted sum
        score = (
            cvss_norm * self._weights["cvss_base"] +
            kev_norm * self._weights["kev_active"] +
            criticality_norm * self._weights["asset_criticality"] +
            epss_norm * self._weights["epss_score"]
        )

        # KEV multiplier — being actively exploited changes everything
        if finding.in_kev:
            score = min(score * self._kev_multiplier, 1.0)

        # Scale to 0-10
        finding.risk_score = round(score * 10, 2)

        # Derive severity from score
        finding.severity = self._score_to_severity(finding.risk_score)

        # Set SLA due date based on severity
        if not finding.sla_due_date:
            finding.sla_due_date = self._calculate_sla(finding)

        # Compliance mapping
        finding.nist_csf_controls = self._nist_map.get(finding.finding_type, [])
        finding.cis_controls = self._cis_map.get(finding.finding_type, [])

        return finding

    def score_all(self, findings: list[Finding]) -> list[Finding]:
        return [self.score_finding(f) for f in findings]

    def _score_to_severity(self, score: float) -> str:
        thresholds = self._severity_thresholds
        if score >= thresholds["critical"]:
            return "critical"
        if score >= thresholds["high"]:
            return "high"
        if score >= thresholds["medium"]:
            return "medium"
        return "low"

    def _calculate_sla(self, finding: Finding) -> date:
        # KEV due date takes priority over internal SLA
        if finding.in_kev and finding.kev_due_date:
            return finding.kev_due_date

        days = self._sla_days.get(finding.severity, 90)
        return date.today() + timedelta(days=days)

    @staticmethod
    def _load_config(path: str) -> dict:
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Risk model config not found: {path}")
        with open(config_path) as f:
            return yaml.safe_load(f)


class EPSSEnricher:
    """
    Enriches findings with EPSS (Exploit Prediction Scoring System) scores.
    EPSS gives the probability that a CVE will be exploited in the wild in the next 30 days.
    """

    def __init__(self):
        self._api_url = "https://api.first.org/data/v1/epss"

    def enrich(self, findings: list[Finding]) -> list[Finding]:
        """Bulk fetches EPSS scores for all CVE findings."""
        cve_ids = list({f.cve_id for f in findings if f.cve_id})
        if not cve_ids:
            return findings

        epss_map = self._fetch_epss(cve_ids)

        for finding in findings:
            if finding.cve_id and finding.cve_id in epss_map:
                finding.epss_score = epss_map[finding.cve_id]

        return findings

    def _fetch_epss(self, cve_ids: list[str]) -> dict[str, float]:
        """Returns {cve_id: epss_score} for a list of CVEs."""
        epss_map = {}

        # EPSS API supports up to 100 CVEs per request
        for batch in self._chunk(cve_ids, 100):
            try:
                with httpx.Client(timeout=15) as client:
                    response = client.get(
                        self._api_url,
                        params={"cve": ",".join(batch)},
                    )
                    response.raise_for_status()
                    data = response.json()

                for entry in data.get("data", []):
                    cve = entry.get("cve")
                    score = entry.get("epss")
                    if cve and score:
                        epss_map[cve.upper()] = float(score)

            except Exception as e:
                logger.warning(f"EPSS fetch failed for batch: {e}")

        logger.info(f"EPSS enrichment: {len(epss_map)}/{len(cve_ids)} CVEs scored")
        return epss_map

    @staticmethod
    def _chunk(lst: list, size: int):
        for i in range(0, len(lst), size):
            yield lst[i:i + size]
