"""
Trivy connector — parses Trivy scan results (JSON format).

Trivy covers containers, filesystems, git repositories, Kubernetes manifests,
IaC (Terraform, CloudFormation), and more. One tool, one connector.

Generate the report:
  trivy image  --format json -o trivy_report.json nginx:latest
  trivy fs     --format json -o trivy_report.json .
  trivy repo   --format json -o trivy_report.json https://github.com/org/repo
  trivy k8s    --format json -o trivy_report.json --report all cluster

Drop trivy_report.json in the project root; the pipeline picks it up.

Trivy: https://github.com/aquasecurity/trivy
"""
import json
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime

from connectors.base import BaseConnector, RawFinding

logger = logging.getLogger(__name__)

TRIVY_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "UNKNOWN":  "low",
}

# Trivy class → Warden finding type
TRIVY_CLASS_TYPE = {
    "os-pkgs":     "network",      # OS package CVEs (container/host)
    "lang-pkgs":   "code",         # Language package CVEs (npm, pip, etc.)
    "config":      "configuration", # Misconfigurations (IaC, k8s)
    "secret":      "configuration", # Secrets detection
    "license":     "configuration", # License violations
}


class TrivyConnector(BaseConnector):
    """
    Parses Trivy JSON output for containers, filesystems, and IaC.

    Handles both vulnerability findings (CVEs in packages) and
    misconfiguration findings (IaC, Kubernetes, Docker).
    """

    def __init__(
        self,
        report_file: str = "trivy_report.json",
        min_severity: str = "low",
        include_misconfigs: bool = True,
    ):
        self.report_file = Path(report_file)
        self._min_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(min_severity, 1)
        self.include_misconfigs = include_misconfigs

    def test_connection(self) -> bool:
        if not self.report_file.exists():
            logger.error(
                "Trivy report not found: %s. Run: trivy image --format json -o %s <target>",
                self.report_file, self.report_file,
            )
            return False
        logger.info("Trivy report found: %s", self.report_file)
        return True

    def fetch_findings(self) -> list[RawFinding]:
        findings: list[RawFinding] = []
        try:
            data = json.loads(self.report_file.read_text(encoding="utf-8"))
            findings.extend(self._parse_report(data))
        except json.JSONDecodeError as exc:
            logger.error("Trivy JSON parse error: %s", exc)
        except Exception as exc:
            logger.error("Trivy parse failed: %s", exc)

        filtered = [f for f in findings if self._rank(f.severity_label) >= self._min_rank]
        logger.info("Trivy: %d findings (min_severity=%s)", len(filtered), self._min_rank)
        return filtered

    # ── Core parser ───────────────────────────────────────────────────────────

    def _parse_report(self, data: dict) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Top-level metadata
        artifact_name = data.get("ArtifactName", "unknown")
        artifact_type = data.get("ArtifactType", "unknown")  # container_image | filesystem | repository
        created_at    = data.get("CreatedAt") or data.get("Metadata", {}).get("ImageConfig", {}).get("created")

        scan_time: Optional[datetime] = None
        if created_at:
            try:
                scan_time = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            except Exception:
                pass

        for result in data.get("Results", []):
            target    = result.get("Target", artifact_name)
            res_class = result.get("Class", "")
            res_type  = result.get("Type", "")

            # Vulnerabilities (CVEs in packages)
            for vuln in result.get("Vulnerabilities") or []:
                f = self._map_vuln(vuln, target, artifact_name, artifact_type, res_class, res_type, scan_time)
                if f:
                    findings.append(f)

            # Misconfigurations (IaC, k8s, Docker)
            if self.include_misconfigs:
                for misconfig in result.get("Misconfigurations") or []:
                    f = self._map_misconfig(misconfig, target, artifact_name, artifact_type, res_class)
                    if f:
                        findings.append(f)

        return findings

    def _map_vuln(
        self,
        v: dict,
        target: str,
        artifact: str,
        artifact_type: str,
        res_class: str,
        res_type: str,
        scan_time: Optional[datetime],
    ) -> Optional[RawFinding]:
        try:
            cve_id          = v.get("VulnerabilityID", "")
            pkg_name        = v.get("PkgName", "")
            installed_ver   = v.get("InstalledVersion", "")
            fixed_ver       = v.get("FixedVersion", "")
            severity        = v.get("Severity", "UNKNOWN")
            title           = v.get("Title") or cve_id
            description     = v.get("Description", "")
            published_date  = v.get("PublishedDate")

            # CVSS — prefer NVD V3, fall back to V2
            cvss_score: Optional[float] = None
            cvss_vector: Optional[str]  = None
            for source in ("nvd", "redhat"):
                cvss_data = v.get("CVSS", {}).get(source, {})
                if cvss_data.get("V3Score"):
                    cvss_score  = float(cvss_data["V3Score"])
                    cvss_vector = cvss_data.get("V3Vector")
                    break
                if cvss_data.get("V2Score") and cvss_score is None:
                    cvss_score = float(cvss_data["V2Score"])

            norm_sev    = TRIVY_SEVERITY_MAP.get(severity, "low")
            finding_type = TRIVY_CLASS_TYPE.get(res_class, "network")

            remediation = f"Upgrade {pkg_name} to {fixed_ver}" if fixed_ver else f"No fixed version available for {pkg_name} {installed_ver}"

            first_found = None
            if published_date:
                try:
                    first_found = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
                except Exception:
                    pass

            return RawFinding(
                cve_id=cve_id if cve_id.startswith("CVE-") else None,
                title=f"[Trivy] {title}",
                description="\n".join(filter(None, [
                    f"Package: {pkg_name} {installed_ver}" + (f" → fix: {fixed_ver}" if fixed_ver else " (no fix)"),
                    f"Target: {target} ({artifact_type})",
                    f"Type: {res_type}",
                    description[:500] if description else "",
                ])),
                source="trivy",
                source_finding_id=f"{cve_id}::{pkg_name}::{artifact}",
                finding_type=finding_type,
                asset_id=artifact,
                asset_name=artifact,
                asset_ip=None,
                asset_environment=self._infer_env(artifact),
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                severity_label=norm_sev,
                remediation_action=remediation,
                first_found=first_found or scan_time,
                raw={
                    "package": pkg_name,
                    "installed_version": installed_ver,
                    "fixed_version": fixed_ver,
                    "target": target,
                    "artifact_type": artifact_type,
                    "class": res_class,
                },
            )
        except Exception as exc:
            logger.warning("Trivy vuln mapping failed: %s", exc)
            return None

    def _map_misconfig(
        self,
        m: dict,
        target: str,
        artifact: str,
        artifact_type: str,
        res_class: str,
    ) -> Optional[RawFinding]:
        try:
            misconfig_id = m.get("ID", "")
            title        = m.get("Title", "Misconfiguration")
            severity     = m.get("Severity", "UNKNOWN")
            description  = m.get("Description", "")
            message      = m.get("Message", "")
            resolution   = m.get("Resolution", "")
            avd_id       = m.get("AVDID", "")

            norm_sev = TRIVY_SEVERITY_MAP.get(severity, "low")

            return RawFinding(
                cve_id=None,
                title=f"[Trivy] {title}",
                description="\n".join(filter(None, [
                    f"Check: {misconfig_id} ({avd_id})" if avd_id else f"Check: {misconfig_id}",
                    f"Target: {target} ({artifact_type})",
                    f"Description: {description}",
                    f"Finding: {message}" if message else "",
                ])),
                source="trivy",
                source_finding_id=f"{misconfig_id}::{target}::{artifact}",
                finding_type="configuration",
                asset_id=artifact,
                asset_name=artifact,
                asset_ip=None,
                asset_environment=self._infer_env(artifact),
                cvss_score=None,
                cvss_vector=None,
                severity_label=norm_sev,
                remediation_action=resolution or None,
                raw={
                    "check_id": misconfig_id,
                    "avd_id": avd_id,
                    "target": target,
                    "class": res_class,
                },
            )
        except Exception as exc:
            logger.warning("Trivy misconfig mapping failed: %s", exc)
            return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _infer_env(name: str) -> str:
        n = name.lower()
        if any(k in n for k in ("prod", "prd", "live")):
            return "production"
        if any(k in n for k in ("stg", "stage", "staging")):
            return "staging"
        if any(k in n for k in ("dev", "local", "localhost")):
            return "development"
        return "unknown"

    @staticmethod
    def _rank(severity: Optional[str]) -> int:
        return {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity or "", 0)
