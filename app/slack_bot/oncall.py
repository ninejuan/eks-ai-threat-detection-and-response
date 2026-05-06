import json
import logging
import time
from urllib.request import Request, urlopen

from app.shared.config import Config
from app.shared.dynamodb import IncidentStore
from app.shared.secrets import get_secret
from app.slack_bot.blocks import action_result_blocks, blocks_response, error_blocks, oncall_blocks

logger = logging.getLogger(__name__)


def oncall_response(config: Config) -> dict:
    return blocks_response(oncall_blocks(config.oncall_user, config.oncall_channel))


def ack_response(config: Config, incident_id: str, user: str = "responder") -> dict:
    return _transition_response(
        config,
        incident_id,
        {"status": "acknowledged", "acknowledged_at": _now(), "acknowledged_by": user, "owner": user},
        "✅ Incident Acknowledged",
        f"Acknowledged by {user}. Status moved to *acknowledged*.",
        config.oncall_channel,
    )


def investigate_response(config: Config, incident_id: str, user: str = "responder") -> dict:
    return _transition_response(
        config,
        incident_id,
        {"status": "investigating", "investigating_at": _now(), "investigating_by": user, "owner": user},
        "🔎 Investigation Started",
        f"{user} started investigation. Status moved to *investigating*.",
        config.oncall_channel,
    )


def resolve_response(config: Config, incident_id: str, note: str = "", user: str = "responder") -> dict:
    message = f"Resolved by {user}."
    if note:
        message += f"\n*Resolution note:* {note}"
    return _transition_response(
        config,
        incident_id,
        {"status": "resolved", "resolved_at": _now(), "resolved_by": user, "resolution_note": note},
        "✅ Incident Resolved",
        message,
        config.oncall_channel,
    )


def assign_response(config: Config, incident_id: str, assignee: str, user: str = "responder") -> dict:
    return _transition_response(
        config,
        incident_id,
        {"status": "investigating", "assigned_at": _now(), "assigned_by": user, "owner": assignee},
        "👤 Incident Assigned",
        f"Assigned to {assignee} by {user}. Status moved to *investigating*.",
        config.oncall_channel,
    )


def escalate_response(config: Config, incident_id: str, user: str = "responder") -> dict:
    channel = config.escalation_channel or config.oncall_channel
    return _transition_response(
        config,
        incident_id,
        {"status": "investigating", "escalated_at": _now(), "escalated_by": user, "escalation_channel": channel},
        "🚨 Incident Escalated",
        f"Escalated by {user} to {channel or 'the configured escalation path'}.",
        channel,
    )


def _transition_response(
    config: Config, incident_id: str, updates: dict, title: str, message: str, channel: str
) -> dict:
    if not incident_id:
        return blocks_response(error_blocks("Missing incident ID", "Provide an incident ID."), ephemeral=True)
    blocks = action_result_blocks(title, incident_id, message)
    try:
        IncidentStore(config.dynamodb_table_name).update_incident(incident_id, updates)
        _post_channel(config, channel, blocks)
    except Exception as error:
        logger.warning("Incident transition failed for %s: %s", incident_id, error)
        return blocks_response(
            error_blocks(title, f"Could not update DynamoDB. Requested action: {message}"), ephemeral=True
        )
    return blocks_response(blocks)


def _post_channel(config: Config, channel: str, blocks: list[dict]) -> None:
    if not channel:
        return
    secret = get_secret(f"{config.project}/slack/bot-token")
    token = secret.get("token", "")
    if not token:
        return
    payload = json.dumps({"channel": channel, "blocks": blocks}).encode()
    request = Request(
        "https://slack.com/api/chat.postMessage",
        data=payload,
        headers={"Content-Type": "application/json; charset=utf-8", "Authorization": f"Bearer {token}"},
    )
    try:
        with urlopen(request, timeout=3) as response:  # noqa: S310
            result = json.loads(response.read().decode())
            if not result.get("ok"):
                logger.warning("Slack API post failed: %s", result.get("error"))
    except Exception as error:
        logger.warning("Failed to post on-call update: %s", error)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
