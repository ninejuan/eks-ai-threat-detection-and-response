import json
import logging
import os

from app.shared.config import Config
from app.shared.secrets import get_secret

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    task_token = event.get("task_token", "")
    execution = event.get("execution", {})

    summary = execution.get("summary", {}).get("body", {})
    triage = execution.get("triage", {}).get("body", {})
    solution = execution.get("solution", {}).get("body", {})

    incident_id = summary.get("incident_id", "unknown")
    severity = triage.get("severity", "UNKNOWN")
    title = summary.get("title", "Security Incident")
    reasoning = triage.get("reasoning", "")

    actions = solution.get("recommended_actions", [])
    actions_text = "\n".join(
        f"  {i + 1}. {a.get('action', '?')} → {a.get('target', '?')} ({a.get('reason', '')})"
        for i, a in enumerate(actions[:5])
    )

    _send_approval_request(
        config=config,
        incident_id=incident_id,
        severity=severity,
        title=title,
        reasoning=reasoning,
        actions_text=actions_text,
        task_token=task_token,
    )

    logger.info("Approval request sent for incident %s (token: %s...)", incident_id, task_token[:20])
    return {"status": "approval_requested", "incident_id": incident_id}


def _send_approval_request(
    config: Config,
    incident_id: str,
    severity: str,
    title: str,
    reasoning: str,
    actions_text: str,
    task_token: str,
) -> None:
    from urllib.request import Request, urlopen

    secret = get_secret(f"{config.project}/slack/bot-token")
    webhook_url = secret.get("webhook_url", "")
    if not webhook_url:
        logger.warning("Slack webhook URL not configured")
        return

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"Approval Required: {incident_id}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Severity:* {severity}"},
                {"type": "mrkdwn", "text": f"*Title:* {title}"},
            ],
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Reasoning:* {reasoning}"},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Recommended Actions:*\n{actions_text}"},
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "style": "primary",
                    "action_id": "approve_remediation",
                    "value": f"{incident_id}|{task_token}",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Reject"},
                    "style": "danger",
                    "action_id": "reject_remediation",
                    "value": f"{incident_id}|{task_token}",
                },
            ],
        },
    ]

    payload = json.dumps({"blocks": blocks}).encode()
    req = Request(webhook_url, data=payload, headers={"Content-Type": "application/json"})  # noqa: S310

    with urlopen(req, timeout=10) as resp:  # noqa: S310
        logger.info("Approval request sent to Slack: %s", resp.status)
