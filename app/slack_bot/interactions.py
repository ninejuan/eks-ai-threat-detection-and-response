import json
import logging
import os
import time
from typing import Any
from urllib.parse import parse_qs

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

    parts = value.split("|") if value else []
    incident_id = parts[0] if parts else "unknown"
    task_token = parts[1] if len(parts) > 1 else ""

    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(f"{config.project}-approval-audit")

    audit_record: dict[str, Any] = {
        "approval_id": f"{incident_id}-{user}-{int(time.time())}",
        "incident_id": incident_id,
        "action": action_id,
        "user": user,
        "timestamp": int(time.time()),
    }

    sfn = boto3.client("stepfunctions")

    if action_id == "approve_remediation":
        audit_record["decision"] = "approved"
        table.put_item(Item=audit_record)
        if task_token:
            sfn.send_task_success(
                taskToken=task_token,
                output=json.dumps({"decision": "approved", "approved_by": user}),
            )
        response_blocks = _approval_response_blocks(incident_id, user, approved=True)
    elif action_id == "reject_remediation":
        audit_record["decision"] = "rejected"
        table.put_item(Item=audit_record)
        if task_token:
            sfn.send_task_success(
                taskToken=task_token,
                output=json.dumps({"decision": "rejected", "rejected_by": user}),
            )
        response_blocks = _approval_response_blocks(incident_id, user, approved=False)
    else:
        response_blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": f"❓ Unknown action: `{action_id}`"}}]

    logger.info("Approval action: %s by %s for %s", action_id, user, incident_id)

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"blocks": response_blocks, "replace_original": True}),
    }


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
