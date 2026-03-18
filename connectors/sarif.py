"""
SARIF connector — Generic parser for SARIF 2.1.0 scan results.

SARIF (Static Analysis Results Interchange Format) is the industry-standard
output format for static analysis tools. One connector covers:

  • CodeQL         (GitHub)
  • Checkmarx      (--format sarif)
  • ESLint         (eslint-formatter-sarif)
  • Psalm          (PHP)
  • Semgrep        (semgrep --sarif)
  • Trivy SAST     (--format sarif)
  • Grype          (grype --output sarif)
  • Any tool with SARIF output

Usage:
  Drop any *.sarif or *.sarif.json file into the project root.
  The pipeline will pick up all SARIF files it finds.

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
"""
import json
import logging
import re
from pathlib import Path
from typing import Optional

from connectors.base import BaseConnector, RawFinding

logger = logging.getLogger(__name__)

# SARIF level → Warden severity
SARIF_LEVEL_MAP = {
    "error":   "high",
    "warning": "medium",
    "note":    "low",
    "none":    "informational",
}

# security-severity (0-10 CVSS-like) → severity label
def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "informational"


class SARIFConnector(BaseConnector):
    """
    Parses SARIF 2.1.0 files from any compliant static analysis tool.

    Discovers all *.sarif and *.sarif.json files in the project root
    automatically — no manual configuration required.
    """

    def __init__(self, search_dir: str = ".", min_severity: str = "low"):
        self.search_dir = Path(search_dir)
        self._min_rank = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 3}.get(min_severity, 1)

    def test_connection(self) -> bool:
        files = self._find_sarif_files()
        if not files:
            logger.error("No SARIF files found. Run a SARIF-compatible scanner first.")
            return False
        logger.info("SARIF files found: %s", [str(f) for f in files])
        return True

    def fetch_findings(self) -> list[RawFinding]:
        all_findings: list[RawFinding] = []
        for sarif_file in self._find_sarif_files():
            try:
                findings = self._parse_sarif(sarif_file)
                all_findings.extend(findings)
                logger.info("SARIF %s: %d findings", sarif_file.name, len(findings))
            except Exception as exc:
                logger.error("Failed to parse SARIF file %s: %s", sarif_file, exc)

        filtered = [f for f in all_findings if self._rank(f.severity_label) >= self._min_rank]
        logger.info("SARIF total: %d findings across %d files", len(filtered), len(self._find_sarif_files()))
        return filtered

    # ── Core parser ───────────────────────────────────────────────────────────

    def _parse_sarif(self, path: Path) -> list[RawFinding]:
        data = json.loads(path.read_text(encoding="utf-8"))
        findings: list[RawFinding] = []

        for run in data.get("runs", []):
            tool_name = (
                run.get("tool", {}).get("driver", {}).get("name", "sarif")
            ).lower().replace(" ", "_")

            # Build rule index: ruleId → rule metadata
            rules = self._index_rules(run)

            for result in run.get("results", []):
                f = self._map_result(result, rules, tool_name)
                if f:
                    findings.append(f)

        return findings

    def _index_rules(self, run: dict) -> dict[str, dict]:
        """Build ruleId → rule dict from tool.driver.rules."""
        rules: dict[str, dict] = {}
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            rid = rule.get("id", "")
            if rid:
                rules[rid] = rule
        # Also check extensions
        for ext in run.get("tool", {}).get("extensions", []):
            for rule in ext.get("rules", []):
                rid = rule.get("id", "")
                if rid:
                    rules[rid] = rule
        return rules

    def _map_result(self, result: dict, rules: dict[str, dict], tool: str) -> Optional[RawFinding]:
        try:
            rule_id   = result.get("ruleId", "")
            rule      = rules.get(rule_id, {})
            level     = result.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning")
            message   = result.get("message", {}).get("text", rule_id)

            # Short description from rule, falling back to message
            short_desc = (
                rule.get("shortDescription", {}).get("text")
                or rule.get("fullDescription", {}).get("text")
                or message
            )

            # Location
            locations    = result.get("locations", [])
            file_uri     = ""
            line_number  = None
            if locations:
                phys = locations[0].get("physicalLocation", {})
                file_uri    = phys.get("artifactLocation", {}).get("uri", "")
                line_number = phys.get("region", {}).get("startLine")

            # Severity — prefer security-severity property if present
            props        = result.get("properties", {}) or rule.get("properties", {})
            sec_score    = self._get_security_severity(props, rule)
            if sec_score is not None:
                severity = _score_to_severity(sec_score)
            else:
                severity = SARIF_LEVEL_MAP.get(level, "medium")

            # CWE — check tags, cwe, and properties
            cwe_id  = self._extract_cwe(props, rule)

            # CVE — some tools embed CVE in rule properties
            cve_id  = self._extract_cve(props, rule)

            # Asset = tool name (SAST results are code-level, not per-host)
            asset   = Path(file_uri).parts[0] if file_uri else tool

            remediation = (
                rule.get("help", {}).get("text")
                or rule.get("fullDescription", {}).get("text", "")
            )[:500]

            desc = "\n".join(filter(None, [
                f"Rule: {rule_id}",
                f"CWE: {cwe_id or 'N/A'}",
                f"File: {file_uri}:{line_number}" if file_uri else "",
                f"Detail: {message}",
            ]))

            return RawFinding(
                cve_id=cve_id,
                title=f"[SARIF:{tool}] {short_desc[:120]}",
                description=desc,
                source=f"sarif_{tool}",
                source_finding_id=f"{rule_id}::{file_uri}:{line_number}",
                finding_type="code",
                asset_id=asset,
                asset_name=asset,
                asset_ip=None,
                asset_environment="development",
                cvss_score=sec_score,
                cvss_vector=None,
                severity_label=severity,
                remediation_action=remediation or None,
                raw={
                    "tool": tool,
                    "rule_id": rule_id,
                    "file": file_uri,
                    "line": line_number,
                    "cwe": cwe_id,
                    "level": level,
                },
            )
        except Exception as exc:
            logger.warning("SARIF result mapping failed: %s", exc)
            return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_sarif_files(self) -> list[Path]:
        files = list(self.search_dir.glob("*.sarif"))
        files += list(self.search_dir.glob("*.sarif.json"))
        return sorted(files)

    @staticmethod
    def _get_security_severity(result_props: dict, rule: dict) -> Optional[float]:
        """Extract numeric security-severity (CVSS-like 0-10)."""
        for source in (result_props, rule.get("properties", {})):
            val = source.get("security-severity") or source.get("securitySeverity")
            if val is not None:
                try:
                    return float(val)
                except (ValueError, TypeError):
                    pass
        return None

    @staticmethod
    def _extract_cwe(result_props: dict, rule: dict) -> Optional[str]:
        for source in (result_props, rule.get("properties", {})):
            # tags array: ["security", "CWE-89"]
            for tag in source.get("tags", []):
                m = re.match(r"CWE-\d+", str(tag), re.IGNORECASE)
                if m:
                    return m.group(0).upper()
            # direct cwe key
            cwe = source.get("cwe") or source.get("CWE")
            if cwe:
                m = re.search(r"(\d+)", str(cwe))
                if m:
                    return f"CWE-{m.group(1)}"
        return None

    @staticmethod
    def _extract_cve(result_props: dict, rule: dict) -> Optional[str]:
        for source in (result_props, rule.get("properties", {})):
            cve = source.get("cve") or source.get("CVE")
            if cve:
                m = re.search(r"CVE-\d{4}-\d{4,}", str(cve), re.IGNORECASE)
                if m:
                    return m.group(0).upper()
            for tag in source.get("tags", []):
                m = re.search(r"CVE-\d{4}-\d{4,}", str(tag), re.IGNORECASE)
                if m:
                    return m.group(0).upper()
        return None

    @staticmethod
    def _rank(severity: Optional[str]) -> int:
        return {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 3}.get(severity or "", 0)
