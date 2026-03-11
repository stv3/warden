"""
SAST Connector — parsea output de Bandit y Semgrep.
Convierte hallazgos de código estático a RawFindings normalizados.
"""
import json
import logging
from pathlib import Path
from typing import Optional

from connectors.base import BaseConnector, RawFinding

logger = logging.getLogger(__name__)

BANDIT_SEVERITY_MAP = {
    "HIGH":   "high",
    "MEDIUM": "medium",
    "LOW":    "low",
}

SEMGREP_SEVERITY_MAP = {
    "ERROR":   "high",
    "WARNING": "medium",
    "INFO":    "low",
}

# CWE → CVE no existe para SAST, pero podemos mapear CWEs conocidos
# a descripciones de remediación estándar
CWE_REMEDIATION = {
    "CWE-20":  "Validate and sanitize all input. Use safe XML parsers (defusedxml).",
    "CWE-78":  "Avoid shell=True in subprocess calls. Use argument lists.",
    "CWE-89":  "Use parameterized queries or ORM. Never concatenate SQL strings.",
    "CWE-94":  "Avoid eval()/exec() with user input. Use AST or safe alternatives.",
    "CWE-330": "Use secrets.token_hex() or os.urandom() for security-sensitive values.",
    "CWE-400": "Add rate limiting and input size validation.",
    "CWE-502": "Avoid pickle/yaml.load with untrusted data. Use safe_load().",
    "CWE-611": "Use defusedxml to prevent XXE attacks.",
}


class SASTConnector(BaseConnector):
    """
    Parsea resultados de herramientas SAST:
    - Bandit (bandit -r . -f json -o bandit_results.json)
    - Semgrep (semgrep --json > semgrep_results.json)

    No hace conexiones de red — lee archivos JSON locales.
    """

    def __init__(self, bandit_file: str = "bandit_results.json", semgrep_file: str = "semgrep_results.json"):
        self.bandit_file = Path(bandit_file)
        self.semgrep_file = Path(semgrep_file)

    def test_connection(self) -> bool:
        has_bandit = self.bandit_file.exists()
        has_semgrep = self.semgrep_file.exists()
        if not has_bandit and not has_semgrep:
            logger.error("No SAST result files found. Run Bandit or Semgrep first.")
            return False
        logger.info(f"SAST files found — bandit: {has_bandit}, semgrep: {has_semgrep}")
        return True

    def fetch_findings(self) -> list[RawFinding]:
        findings = []
        if self.bandit_file.exists():
            findings.extend(self._parse_bandit())
        if self.semgrep_file.exists():
            findings.extend(self._parse_semgrep())
        logger.info(f"SAST: {len(findings)} findings total")
        return findings

    # -------------------------------------------------------------------------
    # Bandit parser
    # -------------------------------------------------------------------------

    def _parse_bandit(self) -> list[RawFinding]:
        findings = []
        try:
            with open(self.bandit_file) as f:
                data = json.load(f)

            repo_name = str(Path.cwd().name)  # project name as "asset"

            for issue in data.get("results", []):
                # Skip if suppressed with #nosec
                if issue.get("issue_confidence") == "LOW":
                    continue

                cwe_id = self._extract_cwe(issue.get("issue_cwe", {}).get("id"))
                severity = BANDIT_SEVERITY_MAP.get(issue.get("issue_severity", "LOW"), "low")

                findings.append(RawFinding(
                    cve_id=None,  # SAST findings don't have CVEs — they have CWEs
                    title=f"[SAST] {issue.get('issue_text', 'Unknown issue')}",
                    description=(
                        f"Test: {issue.get('test_id')} — {issue.get('test_name')}\n"
                        f"CWE: {cwe_id or 'N/A'}\n"
                        f"Confidence: {issue.get('issue_confidence')}\n"
                        f"More info: {issue.get('more_info', '')}"
                    ),
                    source="bandit",
                    source_finding_id=f"{issue.get('test_id')}::{issue.get('filename')}:{issue.get('line_number')}",
                    finding_type="code",
                    asset_id=repo_name,
                    asset_name=repo_name,
                    asset_ip=None,
                    asset_environment="development",
                    cvss_score=None,
                    cvss_vector=None,
                    severity_label=severity,
                    remediation_action=CWE_REMEDIATION.get(cwe_id, issue.get("more_info", "")),
                    raw={
                        "file": issue.get("filename"),
                        "line": issue.get("line_number"),
                        "code": issue.get("code", ""),
                        "test_id": issue.get("test_id"),
                        "cwe": cwe_id,
                    },
                ))
        except Exception as e:
            logger.error(f"Failed to parse Bandit results: {e}")
        return findings

    # -------------------------------------------------------------------------
    # Semgrep parser
    # -------------------------------------------------------------------------

    def _parse_semgrep(self) -> list[RawFinding]:
        findings = []
        try:
            with open(self.semgrep_file) as f:
                data = json.load(f)

            repo_name = str(Path.cwd().name)

            for result in data.get("results", []):
                extra = result.get("extra", {})
                severity = SEMGREP_SEVERITY_MAP.get(extra.get("severity", "INFO"), "low")
                metadata = extra.get("metadata", {})
                cwe_raw = metadata.get("cwe", [])
                cwe_id = cwe_raw[0] if cwe_raw else None

                findings.append(RawFinding(
                    cve_id=None,
                    title=f"[SAST] {extra.get('message', result.get('check_id', 'Unknown'))}",
                    description=(
                        f"Rule: {result.get('check_id')}\n"
                        f"CWE: {cwe_id or 'N/A'}\n"
                        f"OWASP: {', '.join(metadata.get('owasp', []))}\n"
                        f"References: {', '.join(metadata.get('references', [])[:2])}"
                    ),
                    source="semgrep",
                    source_finding_id=f"{result.get('check_id')}::{result.get('path')}:{result.get('start', {}).get('line')}",
                    finding_type="code",
                    asset_id=repo_name,
                    asset_name=repo_name,
                    asset_ip=None,
                    asset_environment="development",
                    cvss_score=None,
                    cvss_vector=None,
                    severity_label=severity,
                    remediation_action=extra.get("fix", metadata.get("message", "")),
                    raw={
                        "file": result.get("path"),
                        "line": result.get("start", {}).get("line"),
                        "rule": result.get("check_id"),
                        "cwe": cwe_id,
                    },
                ))
        except Exception as e:
            logger.error(f"Failed to parse Semgrep results: {e}")
        return findings

    @staticmethod
    def _extract_cwe(cwe_id) -> Optional[str]:
        if not cwe_id:
            return None
        return f"CWE-{cwe_id}" if isinstance(cwe_id, int) else str(cwe_id)
