import httpx
import logging
from typing import Optional

from models.finding import Finding
from config.settings import settings

logger = logging.getLogger(__name__)


class TicketManager:
    """
    Creates and updates Jira tickets for vulnerability findings.
    One ticket per finding — enriched with full context so engineers
    don't need to look anything up.
    """

    SEVERITY_PRIORITY_MAP = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }

    def __init__(self):
        self._base_url = settings.jira_url
        self._project_key = settings.jira_project_key
        self._auth = (settings.jira_username, settings.jira_api_token)

    def create_ticket(self, finding: Finding) -> Optional[str]:
        """Creates a Jira ticket and returns the ticket key (e.g. 'VULN-123')."""
        if not self._is_configured():
            logger.info("Jira not configured, skipping ticket creation")
            return None

        if finding.ticket_id:
            logger.debug(f"Finding {finding.fingerprint[:12]}... already has ticket {finding.ticket_id}")
            return finding.ticket_id

        payload = self._build_ticket_payload(finding)

        try:
            with httpx.Client(timeout=15) as client:
                response = client.post(
                    f"{self._base_url}/rest/api/3/issue",
                    auth=self._auth,
                    json=payload,
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                )
                response.raise_for_status()
                data = response.json()
                ticket_key = data["key"]
                ticket_url = f"{self._base_url}/browse/{ticket_key}"
                logger.info(f"Jira ticket created: {ticket_url}")
                return ticket_key

        except httpx.HTTPError as e:
            logger.error(f"Failed to create Jira ticket for {finding.cve_id}: {e}")
            return None

    def create_tickets_bulk(self, findings: list[Finding], db_session) -> dict:
        """Creates tickets for a list of findings, updates DB with ticket IDs."""
        results = {"created": 0, "skipped": 0, "failed": 0}

        for finding in findings:
            ticket_key = self.create_ticket(finding)
            if ticket_key:
                finding.ticket_id = ticket_key
                finding.ticket_url = f"{self._base_url}/browse/{ticket_key}"
                results["created"] += 1
            elif finding.ticket_id:
                results["skipped"] += 1
            else:
                results["failed"] += 1

        db_session.commit()
        return results

    def _build_ticket_payload(self, finding: Finding) -> dict:
        kev_section = ""
        if finding.in_kev:
            kev_section = (
                f"\n*⚠️ CISA KEV MATCH*\n"
                f"This CVE is in the CISA Known Exploited Vulnerabilities catalog.\n"
                f"It is being actively exploited in the wild.\n"
                f"*KEV Due Date: {finding.kev_due_date}*\n"
                f"Ransomware Use: {finding.kev_ransomware_use or 'Unknown'}\n"
            )

        nist_controls = ", ".join(finding.nist_csf_controls or [])
        cis_controls = ", ".join(finding.cis_controls or [])

        description = (
            f"*Vulnerability:* {finding.cve_id or 'N/A'} — {finding.title}\n\n"
            f"*Asset:* {finding.asset_name} ({finding.asset_ip or 'IP unknown'})\n"
            f"*Environment:* {finding.asset_environment}\n"
            f"*Asset Criticality:* {finding.asset_criticality}/5\n\n"
            f"*Scoring*\n"
            f"Risk Score: *{finding.risk_score}* | CVSS: {finding.cvss_score} | EPSS: {finding.epss_score}\n\n"
            f"{kev_section}"
            f"*SLA Due Date:* {finding.sla_due_date}\n\n"
            f"*Detected by:* {', '.join(finding.all_sources or [])}\n\n"
            f"*Compliance*\n"
            f"NIST CSF: {nist_controls or 'N/A'}\n"
            f"CIS Controls: {cis_controls or 'N/A'}\n\n"
            f"*Recommended Action*\n"
            f"{finding.remediation_action or 'See CVE details for remediation guidance.'}"
        )

        return {
            "fields": {
                "project": {"key": self._project_key},
                "summary": f"[{finding.severity.upper()}] {finding.cve_id or 'VULN'} — {finding.asset_name}",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{"type": "paragraph", "content": [{"type": "text", "text": description}]}],
                },
                "issuetype": {"name": "Bug"},
                "priority": {"name": self.SEVERITY_PRIORITY_MAP.get(finding.severity, "Medium")},
                "labels": self._build_labels(finding),
            }
        }

    def _build_labels(self, finding: Finding) -> list[str]:
        labels = ["vulnerability-management", finding.severity]
        if finding.in_kev:
            labels.append("kev-match")
        if finding.asset_environment:
            labels.append(finding.asset_environment)
        for source in (finding.all_sources or []):
            labels.append(f"scanner-{source}")
        return labels

    def _is_configured(self) -> bool:
        return all([self._base_url, self._project_key, settings.jira_username, settings.jira_api_token])
