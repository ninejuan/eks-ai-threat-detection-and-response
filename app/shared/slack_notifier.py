import json
import logging
from urllib.request import Request, urlopen

from app.shared.secrets import get_secret

logger = logging.getLogger(__name__)


SLACK_MAX_TEXT_LENGTH = 2900


class SlackNotifier:
    def __init__(self, project: str):
        self._project = project

    def _get_webhook_url(self) -> str:
        secret = get_secret(f"{self._project}/slack/bot-token")
        return secret.get("webhook_url", "")

    def send_incident(self, incident: dict, mode: str = "normal") -> None:
        webhook_url = self._get_webhook_url()
        if not webhook_url:
            logger.warning("Slack webhook URL not configured, skipping notification")
            return

        blocks = self._build_degraded_blocks(incident) if mode == "degraded" else self._build_normal_blocks(incident)

        payload = json.dumps({"blocks": blocks}).encode()
        req = Request(webhook_url, data=payload, headers={"Content-Type": "application/json"})  # noqa: S310

        with urlopen(req, timeout=10) as resp:  # noqa: S310
            logger.info("Slack notification sent: %s", resp.status)

    def _build_normal_blocks(self, incident: dict) -> list[dict]:
        severity = incident.get("severity", "UNKNOWN")
        source = incident.get("source", "UNKNOWN")
        summary = incident.get("summary", "No summary available")
        incident_id = incident.get("incident_id", "N/A")

        return [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"ATDR Incident: {incident_id}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:* {severity}"},
                    {"type": "mrkdwn", "text": f"*Source:* {source}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Summary:*\n{summary}"},
            },
        ]

    def _build_degraded_blocks(self, incident: dict) -> list[dict]:
        source = incident.get("source", "UNKNOWN")
        reason = incident.get("error", {}).get("Cause", "Unknown failure")
        raw_alert = json.dumps(incident.get("raw_event", {}), indent=2, ensure_ascii=False)

        if len(raw_alert) > SLACK_MAX_TEXT_LENGTH:
            raw_alert = raw_alert[:SLACK_MAX_TEXT_LENGTH] + "\n..."

        return [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "ATDR Degraded Alert"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Source:* {source}"},
                    {"type": "mrkdwn", "text": "*Mode:* DEGRADED"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Reason:* {reason}\n\nAI analysis unavailable. Human review required.",
                },
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Raw Event:*\n```{raw_alert}```"},
            },
        ]
