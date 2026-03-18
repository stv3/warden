"""
Nuclei connector — parses Nuclei scan output (JSONL format).

Nuclei is a fast, community-powered vulnerability scanner with thousands of
templates covering CVEs, misconfigurations, exposed panels, and more.

Generate the report file:
  nuclei -l targets.txt -je nuclei_report.json   # JSON Lines (recommended)
  nuclei -l targets.txt -o nuclei_report.txt      # text output (not supported)

Drop nuclei_report.json in the project root; the pipeline picks it up.

Nuclei: https://github.com/projectdiscovery/nuclei
"""
import json
import logging
import re
from pathlib import Path
from typing import Optional
from datetime import datetime

from connectors.base import BaseConnector, RawFinding

logger = logging.getLogger(__name__)

NUCLEI_SEVERITY_MAP = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "informational",
    "unknown":  "low",
}


class NucleiConnector(BaseConnector):
    """
    Parses Nuclei JSONL output (one JSON object per line, -je flag).
    Each result corresponds to one matched template against one target.
    """

    def __init__(
        self,
        report_file: str = "nuclei_report.json",
        min_severity: str = "low",
    ):
        self.report_file = Path(report_file)
        self._min_rank = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(min_severity, 1)

    def test_connection(self) -> bool:
        if not self.report_file.exists():
            logger.error("Nuclei report not found: %s. Run: nuclei -l targets.txt -je nuclei_report.json", self.report_file)
            return False
        logger.info("Nuclei report found: %s", self.report_file)
        return True

    def fetch_findings(self) -> list[RawFinding]:
        findings: list[RawFinding] = []
        skipped = 0

        try:
            text = self.report_file.read_text(encoding="utf-8")
            for i, line in enumerate(text.splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    # Try the whole file as a single JSON array (some exporters do this)
                    if i == 1:
                        try:
                            records = json.loads(text)
                            if isinstance(records, list):
                                for r in records:
                                    f = self._map_result(r)
                                    if f:
                                        findings.append(f)
                                break
                        except json.JSONDecodeError:
                            pass
                    skipped += 1
                    continue

                f = self._map_result(record)
                if f:
                    findings.append(f)

        except Exception as exc:
            logger.error("Nuclei parse error: %s", exc)
            return findings

        if skipped:
            logger.warning("Nuclei: %d unparseable lines skipped", skipped)

        filtered = [f for f in findings if self._rank(f.severity_label) >= self._min_rank]
        logger.info("Nuclei: %d findings (min_severity=%s)", len(filtered), self._min_rank)
        return filtered

    # ── Mapping ───────────────────────────────────────────────────────────────

    def _map_result(self, r: dict) -> Optional[RawFinding]:
        try:
            info         = r.get("info", {})
            template_id  = r.get("template-id", r.get("templateID", "unknown"))
            name         = info.get("name", template_id)
            severity     = (info.get("severity") or "unknown").lower()
            host         = r.get("host", "")
            matched_at   = r.get("matched-at", r.get("matched", host))
            ip           = r.get("ip", None)
            timestamp    = r.get("timestamp")

            norm_sev     = NUCLEI_SEVERITY_MAP.get(severity, "low")
            classification = info.get("classification") or {}

            cve_id    = self._extract_cve(classification, template_id, info)
            cvss_score = self._extract_cvss(classification)
            cvss_vec  = classification.get("cvss-metrics")
            cwe_raw   = classification.get("cwe-id") or classification.get("cwe")
            cwe_id    = self._normalize_cwe(cwe_raw)

            asset_id  = self._extract_hostname(host or matched_at)
            tags      = info.get("tags", [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]

            description_parts = [
                info.get("description") or f"Nuclei template match: {name}",
                f"Template: {template_id}",
                f"Matched at: {matched_at}",
                f"Tags: {', '.join(tags)}" if tags else "",
            ]
            if info.get("reference"):
                refs = info["reference"]
                if isinstance(refs, list):
                    refs = refs[:2]
                elif isinstance(refs, str):
                    refs = [refs]
                description_parts.append(f"References: {', '.join(refs)}")

            first_found = None
            if timestamp:
                try:
                    first_found = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except Exception:
                    pass

            return RawFinding(
                cve_id=cve_id,
                title=f"[Nuclei] {name}",
                description="\n".join(p for p in description_parts if p),
                source="nuclei",
                source_finding_id=f"{template_id}::{asset_id}",
                finding_type="network" if "network" in tags else "application",
                asset_id=asset_id,
                asset_name=asset_id,
                asset_ip=ip,
                asset_environment=self._infer_env(host),
                cvss_score=cvss_score,
                cvss_vector=cvss_vec,
                severity_label=norm_sev,
                remediation_action=info.get("remediation"),
                first_found=first_found,
                raw={
                    "template_id": template_id,
                    "matched_at": matched_at,
                    "tags": tags,
                    "cwe": cwe_id,
                    "type": r.get("type"),
                },
            )
        except Exception as exc:
            logger.warning("Nuclei result mapping failed: %s", exc)
            return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_cve(classification: dict, template_id: str, info: dict) -> Optional[str]:
        # classification.cve-id: "CVE-2021-44228" or list
        cve_raw = classification.get("cve-id") or classification.get("cve")
        if cve_raw:
            if isinstance(cve_raw, list):
                cve_raw = cve_raw[0]
            m = re.search(r"CVE-\d{4}-\d{4,}", str(cve_raw), re.IGNORECASE)
            if m:
                return m.group(0).upper()
        # Template IDs often start with "CVE-"
        m = re.match(r"(CVE-\d{4}-\d{4,})", template_id, re.IGNORECASE)
        if m:
            return m.group(1).upper()
        # Check tags
        for tag in info.get("tags", []):
            m = re.search(r"CVE-\d{4}-\d{4,}", str(tag), re.IGNORECASE)
            if m:
                return m.group(0).upper()
        return None

    @staticmethod
    def _extract_cvss(classification: dict) -> Optional[float]:
        score = classification.get("cvss-score") or classification.get("cvss_score")
        if score is not None:
            try:
                return float(score)
            except (ValueError, TypeError):
                pass
        return None

    @staticmethod
    def _normalize_cwe(cwe_raw) -> Optional[str]:
        if not cwe_raw:
            return None
        if isinstance(cwe_raw, list):
            cwe_raw = cwe_raw[0]
        cwe_raw = str(cwe_raw)
        m = re.search(r"(\d+)", cwe_raw)
        return f"CWE-{m.group(1)}" if m else None

    @staticmethod
    def _extract_hostname(url: str) -> str:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc or parsed.path or url
        except Exception:
            return url

    @staticmethod
    def _infer_env(host: str) -> str:
        h = host.lower()
        if any(k in h for k in ("prod", "prd", "live")):
            return "production"
        if any(k in h for k in ("stg", "stage", "staging", "uat")):
            return "staging"
        if any(k in h for k in ("dev", "local", "localhost", "127.0.0.1")):
            return "development"
        return "unknown"

    @staticmethod
    def _rank(severity: Optional[str]) -> int:
        return {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity or "", 0)
