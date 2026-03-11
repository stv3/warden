import httpx
import logging
from datetime import date

from models.finding import Finding
from config.settings import settings

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}


class AlertManager:
    """Sends notifications for critical events — new KEV matches, SLA breaches, etc."""

    def send_kev_alert(self, findings: list[Finding]) -> None:
        """Called when new findings match against KEV. One alert per batch."""
        if not findings or not settings.slack_webhook_url:
            return

        # Separate critical/high from the rest for urgency
        critical = [f for f in findings if f.severity in ("critical", "high")]
        others = [f for f in findings if f.severity not in ("critical", "high")]

        blocks = self._build_kev_blocks(critical, others)
        self._post_to_slack(blocks)

    def send_sla_breach_alert(self, findings: list[Finding]) -> None:
        """Alert when findings breach their SLA due date."""
        if not findings or not settings.slack_webhook_url:
            return

        text = f":alarm_clock: *SLA Breach Alert* — {len(findings)} finding(s) past due date\n"
        for f in findings[:10]:
            text += f"• `{f.cve_id or f.title[:40]}` | {f.asset_name} | Due: {f.sla_due_date}\n"
        if len(findings) > 10:
            text += f"_...and {len(findings) - 10} more_\n"

        self._post_to_slack([{"type": "section", "text": {"type": "mrkdwn", "text": text}}])

    def _build_kev_blocks(self, critical: list[Finding], others: list[Finding]) -> list[dict]:
        total = len(critical) + len(others)
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"⚠️ KEV Alert — {total} New Match(es)"},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*{total}* vulnerabilities in your environment just entered the "
                        f"CISA Known Exploited Vulnerabilities catalog.\n"
                        f"These are being *actively exploited in the wild*."
                    ),
                },
            },
            {"type": "divider"},
        ]

        for f in (critical + others)[:15]:
            emoji = SEVERITY_EMOJI.get(f.severity, "⚪")
            ransomware = " | 🎯 Ransomware" if f.kev_ransomware_use == "Known" else ""
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} *{f.cve_id or f.title[:40]}*{ransomware}\n"
                        f"Asset: `{f.asset_name}` | Env: `{f.asset_environment}`\n"
                        f"Risk Score: *{f.risk_score}* | SLA Due: *{f.kev_due_date}*"
                    ),
                },
            })

        if total > 15:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"_...and {total - 15} more. Check the dashboard._"},
            })

        return blocks

    def _post_to_slack(self, blocks: list[dict]) -> None:
        if not settings.slack_webhook_url:
            logger.info("Slack webhook not configured, skipping alert")
            return
        try:
            with httpx.Client(timeout=10) as client:
                response = client.post(
                    settings.slack_webhook_url,
                    json={"blocks": blocks},
                )
                response.raise_for_status()
                logger.info(f"Slack alert sent ({len(blocks)} blocks)")
        except httpx.HTTPError as e:
            logger.error(f"Failed to send Slack alert: {e}")
