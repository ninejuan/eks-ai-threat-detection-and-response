import json
import logging
import os
import time
from typing import Any
from urllib.parse import parse_qs
from urllib.request import Request, urlopen

import boto3

from app.shared.config import Config

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def handle_interactions(body: str, config: Config) -> dict:
    parsed = parse_qs(body)
    payload_str = parsed.get("payload", [""])[0]
    if not payload_str:
        return {"statusCode": 400, "body": "Missing payload"}

    payload = json.loads(payload_str)
    action_type = payload.get("type", "")

    if action_type == "block_actions":
        return _handle_approval_action(payload, config)

    return {"statusCode": 200, "body": "ok"}


def _handle_approval_action(payload: dict, config: Config) -> dict:
    actions = payload.get("actions", [])
    if not actions:
        return {"statusCode": 200, "body": "ok"}

    action = actions[0]
    action_id = action.get("action_id", "")
    value = action.get("value", "")
    user = payload.get("user", {}).get("username", "unknown")
    response_url = payload.get("response_url", "")

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


def _post_response_url(response_url: str, blocks: list[dict]) -> None:
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
        dynamodb = boto3.resource("dynamodb")
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


def _approval_response_blocks(incident_id: str, user: str, approved: bool) -> list[dict]:
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
