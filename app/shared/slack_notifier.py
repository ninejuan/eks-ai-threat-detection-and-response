import json
import logging
import re
import time
from datetime import UTC, datetime
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from app.shared.secrets import get_secret

logger = logging.getLogger(__name__)


SLACK_MAX_TEXT_LENGTH = 2900
SEVERITY_COLORS = {"P1": "danger", "P2": "warning", "P3": "warning", "P4": "#9CA3AF"}
SEVERITY_EMOJI = {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "⚪"}


def to_slack_mrkdwn(text: str) -> str:
    result = text.strip()
    result = re.sub(r"\*\*(.+?)\*\*", r"*\1*", result)
    result = re.sub(r"__(.+?)__", r"_\1_", result)
    result = re.sub(r"```(\w*)\n", "```\n", result)
    return re.sub(r"#{1,6}\s+(.+)", r"*\1*", result)


def severity_emoji(severity: str | None) -> str:
    return SEVERITY_EMOJI.get(str(severity or "").upper(), "⚪")


def severity_color(severity: str | None) -> str:
    return SEVERITY_COLORS.get(str(severity or "").upper(), "#9CA3AF")


def slack_date(value: object, fallback: str = "unknown") -> str:
    timestamp = _epoch_seconds(value)
    if timestamp is None:
        return fallback
    return f"<!date^{timestamp}^{{date_short_pretty}} {{time}}|{fallback}>"


def slack_api_call(method: str, payload: dict[str, Any], config: Any) -> dict[str, Any]:
    secret = get_secret(f"{config.project}/slack/bot-token")
    bot_token = secret.get("token", "")
    if not bot_token:
        logger.warning("Slack bot token not configured for %s", method)
        return {"ok": False, "error": "missing_bot_token"}

    request = Request(
        f"https://slack.com/api/{method}",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {bot_token}",
        },
    )
    try:
        with urlopen(request, timeout=10) as response:  # noqa: S310
            result: dict[str, Any] = json.loads(response.read().decode())
    except (URLError, TimeoutError, json.JSONDecodeError) as error:
        logger.warning("Slack API call failed for %s: %s", method, error)
        return {"ok": False, "error": "request_failed"}

    if not result.get("ok"):
        logger.warning("Slack API error for %s: %s", method, result.get("error"))
    return result


class SlackNotifier:
    def __init__(self, project: str):
        self._project: str = project

    def _get_webhook_url(self) -> str:
        secret = get_secret(f"{self._project}/slack/bot-token")
        return secret.get("webhook_url", "")

    def send_incident(self, incident: dict[str, Any], mode: str = "normal") -> None:
        webhook_url = self._get_webhook_url()
        if not webhook_url:
            logger.warning("Slack webhook URL not configured, skipping notification")
            return

        blocks = self._build_degraded_blocks(incident) if mode == "degraded" else self._build_normal_blocks(incident)

        payload = json.dumps({"blocks": blocks}).encode()
        if mode == "normal":
            color = severity_color(incident.get("severity", "UNKNOWN"))
            payload = json.dumps({"attachments": [{"color": color, "blocks": blocks}]}).encode()
        else:
            payload = json.dumps({"blocks": blocks}).encode()
        req = Request(webhook_url, data=payload, headers={"Content-Type": "application/json"})  # noqa: S310

        with urlopen(req, timeout=10) as resp:  # noqa: S310
            logger.info("Slack notification sent: %s", resp.status)

    def _build_normal_blocks(self, incident: dict[str, Any]) -> list[dict[str, Any]]:
        severity = incident.get("severity", "UNKNOWN")
        source = incident.get("source", "UNKNOWN")
        summary = to_slack_mrkdwn(incident.get("summary", "No summary available"))
        incident_id = incident.get("incident_id", "N/A")
        title = to_slack_mrkdwn(incident.get("title", "Security incident"))
        mitre = _mitre_display(incident)
        resources = _affected_resources(incident)
        escalation = ""
        if str(severity).upper() == "P1" and not incident.get("acknowledged_at"):
            escalation = "\n<!channel> if not acknowledged within 5 minutes."

        return [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"ATDR Incident: {incident_id}"},
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:* {severity} {severity_emoji(severity)} ({severity_color(severity)})",
                    },
                    {"type": "mrkdwn", "text": f"*Source:* {source}"},
                    {"type": "mrkdwn", "text": f"*Created:* {slack_date(incident.get('created_at'), 'created')}"},
                    {"type": "mrkdwn", "text": f"*MITRE:* {mitre}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{title}*\n{summary}{escalation}"},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Affected resources:*\n{resources}"},
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Acknowledge"},
                        "action_id": "ack_incident",
                        "value": incident_id,
                        "style": "primary",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Investigate"},
                        "action_id": "investigate_incident",
                        "value": incident_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Escalate"},
                        "action_id": "escalate_incident",
                        "value": incident_id,
                        "style": "danger",
                    },
                ],
            },
        ]

    def _build_degraded_blocks(self, incident: dict[str, Any]) -> list[dict[str, Any]]:
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


def _mitre_display(incident: dict[str, Any]) -> str:
    value = (
        incident.get("mitre")
        or incident.get("mitre_attack")
        or incident.get("technique")
        or incident.get("technique_id")
        or "Not mapped"
    )
    if isinstance(value, dict):
        value = value.get("id") or value.get("technique_id") or ", ".join(str(v) for v in value.values())
    if isinstance(value, list):
        value = ", ".join(str(item) for item in value)
    return to_slack_mrkdwn(str(value))


def _affected_resources(incident: dict[str, Any]) -> str:
    resources = incident.get("affected_resources") or incident.get("resources") or []
    if isinstance(resources, str):
        resources = [resources]
    if not resources:
        resources = [
            value
            for value in [
                f"pod/{incident.get('pod') or incident.get('pod_name')}"
                if incident.get("pod") or incident.get("pod_name")
                else None,
                f"node/{incident.get('node') or incident.get('node_name')}"
                if incident.get("node") or incident.get("node_name")
                else None,
                f"namespace/{incident.get('namespace')}" if incident.get("namespace") else None,
            ]
            if value
        ]
    evidence_count = len(set(re.findall(r"s3://[^\s\"'<>]+", json.dumps(incident, ensure_ascii=False))))
    lines = [f"• `{resource}`" for resource in resources[:8]] or ["• Not recorded"]
    if evidence_count:
        lines.append(f"• {evidence_count} forensic evidence object(s) attached")
    return "\n".join(lines)


def _epoch_seconds(value: object) -> int | None:
    if value is None or value == "":
        return int(time.time())
    if isinstance(value, int | float):
        return int(value)
    if isinstance(value, datetime):
        return int(value.timestamp())
    text = str(value).replace("Z", "+00:00")
    try:
        return int(float(text))
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return int(parsed.timestamp())
    except ValueError:
        return None
