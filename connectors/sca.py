"""
SCA Connector — parsea output de pip-audit y Safety.
A diferencia de SAST, los findings de SCA SÍ tienen CVE IDs
lo que permite KEV matching real.
"""
import json
import logging
import subprocess  # nosec B404 — intentional: runs pip-audit as a subprocess
from pathlib import Path
from typing import Optional

from connectors.base import BaseConnector, RawFinding

logger = logging.getLogger(__name__)


class SCAConnector(BaseConnector):
    """
    Analiza dependencias Python en busca de CVEs conocidos.
    Soporta pip-audit y Safety como fuentes.
    Puede correr las herramientas directamente o parsear archivos JSON existentes.
    """

    def __init__(
        self,
        requirements_file: str = "requirements.txt",
        pip_audit_file: Optional[str] = None,
        safety_file: Optional[str] = None,
        run_on_fetch: bool = True,
    ):
        self.requirements_file = Path(requirements_file)
        self.pip_audit_file = Path(pip_audit_file) if pip_audit_file else None
        self.safety_file = Path(safety_file) if safety_file else None
        self.run_on_fetch = run_on_fetch

    def test_connection(self) -> bool:
        if not self.requirements_file.exists():
            logger.error(f"requirements.txt not found: {self.requirements_file}")
            return False
        logger.info(f"SCA: requirements.txt found ({self.requirements_file})")
        return True

    def fetch_findings(self) -> list[RawFinding]:
        findings = []

        # pip-audit
        if self.pip_audit_file and self.pip_audit_file.exists():
            findings.extend(self._parse_pip_audit_file(self.pip_audit_file))
        elif self.run_on_fetch:
            findings.extend(self._run_pip_audit())

        # Safety (complementario)
        if self.safety_file and self.safety_file.exists():
            findings.extend(self._parse_safety_file(self.safety_file))

        logger.info(f"SCA: {len(findings)} vulnerable dependencies found")
        return findings

    # -------------------------------------------------------------------------
    # pip-audit
    # -------------------------------------------------------------------------

    def _run_pip_audit(self) -> list[RawFinding]:
        """Corre pip-audit en el entorno actual y parsea los resultados."""
        try:
            result = subprocess.run(  # nosec B603 B607 — args are hardcoded, no user input, no shell=True
                ["python3", "-m", "pip_audit", "-r", str(self.requirements_file), "-f", "json"],
                capture_output=True, text=True, timeout=120
            )
            if result.stdout:
                return self._parse_pip_audit_json(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"pip-audit run failed: {e}")
        return []

    def _parse_pip_audit_file(self, path: Path) -> list[RawFinding]:
        with open(path) as f:
            return self._parse_pip_audit_json(f.read())

    def _parse_pip_audit_json(self, content: str) -> list[RawFinding]:
        findings = []
        try:
            data = json.loads(content)
            dependencies = data.get("dependencies", [])

            for dep in dependencies:
                package = dep.get("name", "unknown")
                version = dep.get("version", "unknown")

                for vuln in dep.get("vulns", []):
                    cve_id = self._extract_cve(vuln.get("aliases", []) + [vuln.get("id", "")])
                    severity = self._severity_from_fix(vuln.get("fix_versions", []))

                    findings.append(RawFinding(
                        cve_id=cve_id,
                        title=f"[SCA] {package}=={version} — {vuln.get('id')}",
                        description=(
                            f"Package: {package} version {version}\n"
                            f"Vulnerability: {vuln.get('id')}\n"
                            f"Description: {vuln.get('description', 'N/A')}\n"
                            f"Fix versions: {', '.join(vuln.get('fix_versions', ['unknown']))}"
                        ),
                        source="pip-audit",
                        source_finding_id=f"{package}:{version}:{vuln.get('id')}",
                        finding_type="dependency",
                        asset_id="application",
                        asset_name="application",
                        asset_ip=None,
                        asset_environment="production",
                        cvss_score=None,
                        cvss_vector=None,
                        severity_label=severity,
                        remediation_action=(
                            f"Upgrade {package} to {', '.join(vuln.get('fix_versions', ['latest']))}. "
                            f"Run: pip install --upgrade {package}"
                        ),
                        raw={
                            "package": package,
                            "version": version,
                            "vuln_id": vuln.get("id"),
                            "aliases": vuln.get("aliases", []),
                        },
                    ))
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse pip-audit output: {e}")
        return findings

    # -------------------------------------------------------------------------
    # Safety
    # -------------------------------------------------------------------------

    def _parse_safety_file(self, path: Path) -> list[RawFinding]:
        try:
            with open(path) as f:
                data = json.load(f)
            return self._parse_safety_json(data)
        except Exception as e:
            logger.error(f"Failed to parse Safety file: {e}")
            return []

    def _parse_safety_json(self, data: dict) -> list[RawFinding]:
        findings = []
        for vuln in data.get("vulnerabilities", []):
            package = vuln.get("package_name", "unknown")
            version = vuln.get("analyzed_version", "unknown")
            cve_id = vuln.get("CVE") or self._extract_cve([vuln.get("vulnerability_id", "")])

            findings.append(RawFinding(
                cve_id=cve_id,
                title=f"[SCA] {package}=={version} — {vuln.get('vulnerability_id')}",
                description=vuln.get("advisory", ""),
                source="safety",
                source_finding_id=f"{package}:{version}:{vuln.get('vulnerability_id')}",
                finding_type="dependency",
                asset_id="application",
                asset_name="application",
                asset_ip=None,
                asset_environment="production",
                cvss_score=None,
                cvss_vector=None,
                severity_label=vuln.get("severity", "medium").lower(),
                remediation_action=f"Upgrade {package} to {vuln.get('fixed_versions', ['latest'])}",
                raw=vuln,
            ))
        return findings

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _extract_cve(aliases: list) -> Optional[str]:
        """Extrae el primer CVE ID de una lista de aliases."""
        for alias in aliases:
            if alias and alias.upper().startswith("CVE-"):
                return alias.upper()
        return None

    @staticmethod
    def _severity_from_fix(fix_versions: list) -> str:
        """Sin score CVSS disponible, asume high si hay fix disponible."""
        return "high" if fix_versions else "medium"
