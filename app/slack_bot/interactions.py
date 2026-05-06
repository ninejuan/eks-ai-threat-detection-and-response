import json
import logging
import os
import time
from typing import Any
from urllib.parse import parse_qs
from urllib.request import Request, urlopen

import boto3

from app.shared.config import Config
from app.slack_bot import modals
from app.slack_bot.oncall import ack_response, escalate_response, investigate_response

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
Block = dict[str, Any]


def handle_interactions(body: str, config: Config) -> dict[str, Any]:
    parsed = parse_qs(body)
    payload_str = parsed.get("payload", [""])[0]
    if not payload_str:
        return {"statusCode": 400, "body": "Missing payload"}

    payload = json.loads(payload_str)
    action_type = payload.get("type", "")

    if action_type == "block_actions":
        return _handle_approval_action(payload, config)
    if action_type == "view_submission":
        return modals.handle_view_submission(payload, config)
    if action_type == "shortcut":
        return _handle_shortcut(payload, config)

    return {"statusCode": 200, "body": "ok"}


def _handle_approval_action(payload: dict[str, Any], config: Config) -> dict[str, Any]:
    actions = payload.get("actions", [])
    if not actions:
        return {"statusCode": 200, "body": "ok"}

    action = actions[0]
    action_id = action.get("action_id", "")
    value = action.get("value", "")
    user = payload.get("user", {}).get("username", "unknown")
    response_url = payload.get("response_url", "")

    if action_id in {"view_all_incidents", "generate_report", "view_oncall", "open_incident_detail"}:
        return _handle_home_action(payload, config, action_id, value)

    if action_id in {"ack_incident", "investigate_incident", "escalate_incident"}:
        incident_id = value or "unknown"
        if action_id == "ack_incident":
            return ack_response(config, incident_id, user=f"<@{user}>")
        if action_id == "investigate_incident":
            return investigate_response(config, incident_id, user=f"<@{user}>")
        return escalate_response(config, incident_id, user=f"<@{user}>")

    parts = value.split("|") if value else []
    incident_id = parts[0] if parts else "unknown"
    task_token = parts[1] if len(parts) > 1 else ""

    approved = action_id == "approve_remediation"
    response_blocks = _approval_response_blocks(incident_id, user, approved=approved)

    if response_url:
        _post_response_url(response_url, response_blocks)

    _process_approval(config, incident_id, task_token, user, action_id, approved)

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"blocks": response_blocks, "replace_original": True}),
    }


def _open_modal_response(opener: Any, payload: dict[str, Any], config: Config) -> dict[str, Any]:
    trigger_id = payload.get("trigger_id", "")
    user_id = payload.get("user", {}).get("id", "")
    channel_id = payload.get("channel", {}).get("id", "")
    opener(trigger_id, config, channel_id, user_id)
    return {"statusCode": 200, "body": "ok"}


def _handle_home_action(payload: dict[str, Any], config: Config, action_id: str, value: str) -> dict[str, Any]:
    if action_id == "view_all_incidents":
        return _open_modal_response(modals.open_incident_filter_modal, payload, config)
    if action_id == "generate_report":
        return _open_modal_response(modals.open_report_modal, payload, config)
    if action_id == "open_incident_detail":
        modals.open_incident_detail_modal(payload.get("trigger_id", ""), config, value)
        return {"statusCode": 200, "body": "ok"}

    user_id = payload.get("user", {}).get("id", "")
    channel_id = payload.get("channel", {}).get("id", "")
    modals.post_oncall_status(config, user_id, channel_id)
    return {"statusCode": 200, "body": "ok"}


def _handle_shortcut(payload: dict[str, Any], config: Config) -> dict[str, Any]:
    callback_id = payload.get("callback_id", "")
    trigger_id = payload.get("trigger_id", "")
    user_id = payload.get("user", {}).get("id", "")
    channel_id = payload.get("channel", {}).get("id", "")

    if callback_id == "atdr_view_status":
        modals.open_status_modal(trigger_id, config)
    elif callback_id == "atdr_ack_incident":
        modals.open_ack_incident_modal(trigger_id, config, channel_id, user_id)

    return {"statusCode": 200, "body": "ok"}


def _post_response_url(response_url: str, blocks: list[Block]) -> None:
    payload = json.dumps({"blocks": blocks, "replace_original": True}).encode()
    req = Request(response_url, data=payload, headers={"Content-Type": "application/json"})  # noqa: S310
    try:
        with urlopen(req, timeout=3) as resp:  # noqa: S310
            logger.info("Posted to response_url: %s", resp.status)
    except Exception:
        logger.warning("Failed to post to response_url")


def _process_approval(
    config: Config, incident_id: str, task_token: str, user: str, action_id: str, approved: bool
) -> None:
    try:
        dynamodb: Any = boto3.resource("dynamodb")
        table = dynamodb.Table(f"{config.project}-approval-audit")

        audit_record: dict[str, Any] = {
            "approval_id": f"{incident_id}-{user}-{int(time.time())}",
            "incident_id": incident_id,
            "action": action_id,
            "user": user,
            "timestamp": int(time.time()),
            "decision": "approved" if approved else "rejected",
        }
        table.put_item(Item=audit_record)

        if task_token:
            sfn = boto3.client("stepfunctions")
            decision_key = "approved_by" if approved else "rejected_by"
            sfn.send_task_success(
                taskToken=task_token,
                output=json.dumps({"decision": "approved" if approved else "rejected", decision_key: user}),
            )

        logger.info("Approval processed: %s by %s for %s", action_id, user, incident_id)
    except Exception:
        logger.exception("Failed to process approval for %s", incident_id)


def _approval_response_blocks(incident_id: str, user: str, approved: bool) -> list[Block]:
    if approved:
        emoji = "✅"
        action_text = "approved"
    else:
        emoji = "🚫"
        action_text = "rejected"

    now_ts = int(time.time())
    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{emoji} Remediation *{action_text}* by <@{user}>\n`{incident_id}`",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Decision recorded at <!date^{now_ts}^{{date_short_pretty}} {{time}}|now>",
                }
            ],
        },
    ]
