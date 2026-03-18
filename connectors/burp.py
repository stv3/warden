"""
Burp Suite connector — parses Burp Pro and Enterprise scan exports.

Supported formats:
  • XML  (File → Save copy → XML) — Burp Pro and Enterprise
  • JSON (Enterprise REST API export)

Usage:
  burp_report.xml  — drop in project root; pipeline picks it up automatically
  burp_report.json — same

Generate from Burp Pro:
  Scan → right-click results → Report → XML
Generate from Burp Enterprise:
  API: GET /api/v1/scans/{id}/report  (Accept: application/xml)
"""
import json
import logging
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import defusedxml.ElementTree as ET

from connectors.base import BaseConnector, RawFinding

logger = logging.getLogger(__name__)

BURP_SEVERITY_MAP = {
    "high":        "high",
    "medium":      "medium",
    "low":         "low",
    "information": "informational",
    "info":        "informational",
}

# Burp type IDs for common issues → CWE
BURP_TYPE_CWE: dict[str, str] = {
    "1049088":  "CWE-89",   # SQL injection
    "1048832":  "CWE-89",   # SQL injection (second order)
    "2097920":  "CWE-79",   # Reflected XSS
    "2097921":  "CWE-79",   # Stored XSS
    "2097936":  "CWE-116",  # DOM-based XSS
    "2097944":  "CWE-79",   # XSS (various)
    "4194560":  "CWE-918",  # SSRF
    "8389632":  "CWE-611",  # XXE
    "134217728": "CWE-22",  # Path traversal
    "2097152":  "CWE-601",  # Open redirect
    "16777472":  "CWE-77",  # OS command injection
    "33554432":  "CWE-94",  # Server-side template injection
    "8388608":  "CWE-502",  # Deserialization
    "4194304":  "CWE-352",  # CSRF
    "33554688":  "CWE-200",  # Information disclosure
}

# Severity → approximate CVSS score (used when no CVSS is available)
SEVERITY_CVSS: dict[str, float] = {
    "high":        7.5,
    "medium":      5.0,
    "low":         3.0,
    "informational": 0.0,
}

_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    if not text:
        return ""
    text = _HTML_TAG_RE.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()


def _host_from_url(url: str) -> str:
    """Extract hostname from a URL, falling back to the raw string."""
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path or url
    except Exception:
        return url


class BurpConnector(BaseConnector):
    """
    Parses Burp Suite scan exports (XML or JSON).
    File-based — no network connection required.
    """

    def __init__(
        self,
        xml_file: str = "burp_report.xml",
        json_file: Optional[str] = "burp_report.json",
        min_severity: str = "low",  # low | medium | high
    ):
        self.xml_file = Path(xml_file)
        self.json_file = Path(json_file) if json_file else None
        self._min_level = list(BURP_SEVERITY_MAP.keys()).index(min_severity.lower()) if min_severity.lower() in BURP_SEVERITY_MAP else 0

    def test_connection(self) -> bool:
        has_xml = self.xml_file.exists()
        has_json = self.json_file and self.json_file.exists()
        if not has_xml and not has_json:
            logger.error("No Burp report files found. Export a scan from Burp Suite first.")
            return False
        logger.info("Burp report files found — xml: %s, json: %s", has_xml, bool(has_json))
        return True

    def fetch_findings(self) -> list[RawFinding]:
        findings: list[RawFinding] = []

        if self.xml_file.exists():
            findings.extend(self._parse_xml(self.xml_file))

        if self.json_file and self.json_file.exists():
            findings.extend(self._parse_json(self.json_file))

        filtered = [f for f in findings if self._severity_rank(f.severity_label) >= self._min_level]
        logger.info("Burp: %d findings after severity filter (min=%s)", len(filtered), self._min_level)
        return filtered

    # ── XML parser ────────────────────────────────────────────────────────────

    def _parse_xml(self, path: Path) -> list[RawFinding]:
        findings: list[RawFinding] = []
        try:
            tree = ET.parse(str(path))
            root = tree.getroot()

            # Support both <issues> root (Pro) and <OWASPZAPReport>-style variants
            issues = root.findall("issue") if root.tag == "issues" else root.findall(".//issue")

            for issue in issues:
                f = self._map_xml_issue(issue)
                if f:
                    findings.append(f)

            logger.info("Burp XML: %d issues parsed from %s", len(findings), path)
        except ET.ParseError as exc:
            logger.error("Burp XML parse error: %s", exc)
        except Exception as exc:
            logger.error("Burp XML unexpected error: %s", exc)
        return findings

    def _map_xml_issue(self, issue) -> Optional[RawFinding]:
        try:
            issue_type  = issue.findtext("type", "")
            name        = issue.findtext("name", "Unknown issue")
            severity    = (issue.findtext("severity") or "information").lower()
            confidence  = (issue.findtext("confidence") or "").lower()
            host_el     = issue.find("host")
            host_url    = host_el.text if host_el is not None and host_el.text else "unknown"
            host_ip     = host_el.get("ip") if host_el is not None else None
            path        = issue.findtext("path", "/")
            location    = issue.findtext("location", "")
            detail      = _strip_html(issue.findtext("issueDetail") or "")
            background  = _strip_html(issue.findtext("issueBackground") or "")
            remediation = _strip_html(issue.findtext("remediationDetail") or issue.findtext("remediationBackground") or "")
            refs        = _strip_html(issue.findtext("references") or "")
            vuln_class  = issue.findtext("vulnerabilityClassifications", "")

            hostname    = _host_from_url(host_url)
            norm_sev    = BURP_SEVERITY_MAP.get(severity, "informational")
            cwe_id      = BURP_TYPE_CWE.get(issue_type) or self._extract_cwe(vuln_class)

            description = "\n".join(filter(None, [
                f"Issue: {name}",
                f"Location: {location or path}",
                f"Confidence: {confidence}",
                f"CWE: {cwe_id or 'N/A'}",
                f"Detail: {detail}" if detail else "",
                f"Background: {background[:500]}" if background else "",
                f"References: {refs[:200]}" if refs else "",
            ]))

            return RawFinding(
                cve_id=None,
                title=f"[Burp] {name}",
                description=description,
                source="burp",
                source_finding_id=f"{issue_type or name}::{hostname}{path}",
                finding_type="application",
                asset_id=hostname,
                asset_name=hostname,
                asset_ip=host_ip,
                asset_environment=self._infer_env(hostname),
                cvss_score=SEVERITY_CVSS.get(norm_sev),
                cvss_vector=None,
                severity_label=norm_sev,
                remediation_action=remediation or None,
                raw={
                    "burp_type": issue_type,
                    "confidence": confidence,
                    "location": location,
                    "cwe": cwe_id,
                    "path": path,
                },
            )
        except Exception as exc:
            logger.warning("Could not map Burp XML issue: %s", exc)
            return None

    # ── JSON parser (Burp Enterprise API export) ──────────────────────────────

    def _parse_json(self, path: Path) -> list[RawFinding]:
        findings: list[RawFinding] = []
        try:
            data = json.loads(path.read_text())

            # Enterprise format: {"issue_events": [{"type": "issue_found", "issue": {...}}]}
            events = data.get("issue_events") or data.get("issues") or []
            if isinstance(events, list):
                for entry in events:
                    issue = entry.get("issue") if isinstance(entry, dict) and "issue" in entry else entry
                    if isinstance(issue, dict):
                        f = self._map_json_issue(issue)
                        if f:
                            findings.append(f)

            logger.info("Burp JSON: %d issues parsed from %s", len(findings), path)
        except json.JSONDecodeError as exc:
            logger.error("Burp JSON parse error: %s", exc)
        except Exception as exc:
            logger.error("Burp JSON unexpected error: %s", exc)
        return findings

    def _map_json_issue(self, issue: dict) -> Optional[RawFinding]:
        try:
            name        = issue.get("name", "Unknown issue")
            severity    = (issue.get("severity") or "info").lower()
            confidence  = (issue.get("confidence") or "").lower()
            origin      = issue.get("origin", "")
            path        = issue.get("path", "/")
            description = _strip_html(issue.get("description") or issue.get("detail") or "")
            remediation = _strip_html(issue.get("remediation") or "")
            issue_type  = str(issue.get("type_index", issue.get("type", "")))

            hostname    = _host_from_url(origin) if origin else "unknown"
            norm_sev    = BURP_SEVERITY_MAP.get(severity, "informational")
            cwe_id      = BURP_TYPE_CWE.get(issue_type)

            return RawFinding(
                cve_id=None,
                title=f"[Burp] {name}",
                description=f"Issue: {name}\nSeverity: {norm_sev}\nConfidence: {confidence}\n{description[:800]}",
                source="burp",
                source_finding_id=f"{issue_type or name}::{hostname}{path}",
                finding_type="application",
                asset_id=hostname,
                asset_name=hostname,
                asset_ip=None,
                asset_environment=self._infer_env(hostname),
                cvss_score=SEVERITY_CVSS.get(norm_sev),
                cvss_vector=None,
                severity_label=norm_sev,
                remediation_action=remediation or None,
                raw={"burp_type": issue_type, "confidence": confidence, "cwe": cwe_id},
            )
        except Exception as exc:
            logger.warning("Could not map Burp JSON issue: %s", exc)
            return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_cwe(vuln_classifications: str) -> Optional[str]:
        """Extract first CWE reference from Burp's vulnerability classifications HTML."""
        if not vuln_classifications:
            return None
        match = re.search(r"CWE-(\d+)", vuln_classifications)
        return f"CWE-{match.group(1)}" if match else None

    @staticmethod
    def _infer_env(hostname: str) -> str:
        h = hostname.lower()
        if any(k in h for k in ("prod", "prd", "live")):
            return "production"
        if any(k in h for k in ("stg", "stage", "staging", "uat")):
            return "staging"
        if any(k in h for k in ("dev", "local", "localhost", "127.0.0.1")):
            return "development"
        return "unknown"

    @staticmethod
    def _severity_rank(severity: Optional[str]) -> int:
        return {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 3}.get(severity or "", 0)
