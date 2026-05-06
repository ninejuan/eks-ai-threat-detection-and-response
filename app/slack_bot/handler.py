import base64
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any
from urllib.parse import parse_qs

import boto3

from app.shared.config import Config
from app.shared.secrets import get_secret

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

SLACK_TIMESTAMP_MAX_AGE = 300


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    path = event.get("rawPath", "")
    body = event.get("body", "")
    headers = event.get("headers", {})

    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode()

    if not _verify_slack_signature(body, headers, config.project):
        return {"statusCode": 401, "body": "Invalid signature"}

    if path.endswith("/events"):
        return _handle_events(body)
    if path.endswith("/interactions"):
        return _handle_interactions(body, config)
    if path.endswith("/commands"):
        return _handle_commands(body, config)

    return {"statusCode": 404, "body": "Not found"}


def _verify_slack_signature(body: str, headers: dict, project: str) -> bool:
    signing_secret_data = get_secret(f"{project}/slack/signing-secret")
    signing_secret = signing_secret_data.get("secret", "")

    timestamp = headers.get("x-slack-request-timestamp", "")
    signature = headers.get("x-slack-signature", "")

    if not timestamp or not signature:
        return False

    if abs(time.time() - int(timestamp)) > SLACK_TIMESTAMP_MAX_AGE:
        logger.warning("Slack request timestamp too old")
        return False

    sig_basestring = f"v0:{timestamp}:{body}"
    computed = (
        "v0="
        + hmac.new(
            signing_secret.encode(),
            sig_basestring.encode(),
            hashlib.sha256,
        ).hexdigest()
    )

    return hmac.compare_digest(computed, signature)


def _handle_events(body: str) -> dict:
    payload = json.loads(body)

    if payload.get("type") == "url_verification":
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "text/plain"},
            "body": payload["challenge"],
        }

    return {"statusCode": 200, "body": "ok"}


def _handle_interactions(body: str, config: Config) -> dict:
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
        response_text = f"Remediation approved by @{user}"
    elif action_id == "reject_remediation":
        audit_record["decision"] = "rejected"
        table.put_item(Item=audit_record)
        if task_token:
            sfn.send_task_success(
                taskToken=task_token,
                output=json.dumps({"decision": "rejected", "rejected_by": user}),
            )
        response_text = f"Remediation rejected by @{user}"
    else:
        response_text = f"Unknown action: {action_id}"

    logger.info("Approval action: %s by %s for %s", action_id, user, incident_id)

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"text": response_text}),
    }


def _handle_commands(body: str, config: Config) -> dict:
    parsed = parse_qs(body)
    command = parsed.get("command", [""])[0]
    text = parsed.get("text", [""])[0]

    if command == "/atdr":
        return _handle_atdr_command(text, config)

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"text": f"Unknown command: {command}"}),
    }


def _handle_atdr_command(text: str, _config: Config) -> dict:
    parts = text.strip().split(maxsplit=1)
    subcommand = parts[0] if parts else "help"

    if subcommand == "status":
        response_text = "ATDR is operational."
    elif subcommand == "incidents":
        response_text = "Use the ATDR dashboard to view incidents."
    elif subcommand == "help":
        response_text = (
            "*ATDR Commands:*\n"
            "`/atdr status` - Check system status\n"
            "`/atdr incidents` - View recent incidents\n"
            "`/atdr help` - Show this help message"
        )
    else:
        response_text = f"Unknown subcommand: {subcommand}. Try `/atdr help`."

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"text": response_text}),
    }
