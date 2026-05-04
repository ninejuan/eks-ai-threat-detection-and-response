import base64
import hashlib
import hmac
import json
import time
from urllib.parse import quote

from app.slack_bot import handler


def _signature(body, timestamp, secret="slack-signing-secret"):
    return "v0=" + hmac.new(secret.encode(), f"v0:{timestamp}:{body}".encode(), hashlib.sha256).hexdigest()


def _signed_event(path, body):
    timestamp = str(int(time.time()))
    return {
        "rawPath": path,
        "body": body,
        "headers": {"x-slack-request-timestamp": timestamp, "x-slack-signature": _signature(body, timestamp)},
    }


def test_verify_slack_signature_accepts_valid_signature(aws_mocks):
    body = "command=%2Fatdr&text=status"
    timestamp = str(int(time.time()))

    assert handler._verify_slack_signature(
        body,
        {"x-slack-request-timestamp": timestamp, "x-slack-signature": _signature(body, timestamp)},
        "test-atdr",
    )


def test_verify_slack_signature_rejects_missing_or_old_signature(aws_mocks):
    body = "payload={}"
    assert not handler._verify_slack_signature(body, {}, "test-atdr")
    old_timestamp = str(int(time.time()) - handler.SLACK_TIMESTAMP_MAX_AGE - 10)
    assert not handler._verify_slack_signature(
        body,
        {"x-slack-request-timestamp": old_timestamp, "x-slack-signature": _signature(body, old_timestamp)},
        "test-atdr",
    )


def test_lambda_handler_rejects_invalid_signature(aws_mocks, context):
    result = handler.lambda_handler({"rawPath": "/slack/events", "body": "{}", "headers": {}}, context)

    assert result == {"statusCode": 401, "body": "Invalid signature"}


def test_events_url_verification_returns_challenge(aws_mocks, context):
    body = json.dumps({"type": "url_verification", "challenge": "challenge-token"})

    result = handler.lambda_handler(_signed_event("/slack/events", body), context)

    assert result["statusCode"] == 200
    assert result["headers"] == {"Content-Type": "text/plain"}
    assert result["body"] == "challenge-token"


def test_events_non_verification_returns_ok(aws_mocks, context):
    body = json.dumps({"type": "event_callback", "event": {"type": "app_mention"}})

    result = handler.lambda_handler(_signed_event("/slack/events", body), context)

    assert result == {"statusCode": 200, "body": "ok"}


def test_interactions_missing_payload_returns_bad_request(aws_mocks, context):
    body = "not_payload=1"

    result = handler.lambda_handler(_signed_event("/slack/interactions", body), context)

    assert result == {"statusCode": 400, "body": "Missing payload"}


def test_interactions_approve_action_writes_audit(aws_mocks, dynamodb_table, context):
    payload = {
        "type": "block_actions",
        "user": {"username": "alice"},
        "actions": [{"action_id": "approve_remediation", "value": "inc-1|isolate"}],
    }
    body = "payload=" + quote(json.dumps(payload))

    result = handler.lambda_handler(_signed_event("/slack/interactions", body), context)

    assert result["statusCode"] == 200
    assert json.loads(result["body"])["text"] == "Remediation approved by @alice"
    item = dynamodb_table.put_item.call_args.kwargs["Item"]
    assert item["incident_id"] == "inc-1"
    assert item["decision"] == "approved"


def test_interactions_reject_action_writes_audit(aws_mocks, dynamodb_table, context):
    payload = {
        "type": "block_actions",
        "user": {"username": "bob"},
        "actions": [{"action_id": "reject_remediation", "value": "inc-2|isolate"}],
    }
    body = "payload=" + quote(json.dumps(payload))

    result = handler.lambda_handler(_signed_event("/slack/interactions", body), context)

    assert json.loads(result["body"])["text"] == "Remediation rejected by @bob"
    assert dynamodb_table.put_item.call_args.kwargs["Item"]["decision"] == "rejected"


def test_commands_status_help_and_unknown(aws_mocks, context):
    status = handler.lambda_handler(_signed_event("/slack/commands", "command=%2Fatdr&text=status"), context)
    help_result = handler.lambda_handler(_signed_event("/slack/commands", "command=%2Fatdr&text=help"), context)
    unknown = handler.lambda_handler(_signed_event("/slack/commands", "command=%2Fother&text=status"), context)

    assert json.loads(status["body"])["text"] == "ATDR is operational."
    assert "ATDR Commands" in json.loads(help_result["body"])["text"]
    assert json.loads(unknown["body"])["text"] == "Unknown command: /other"


def test_lambda_handler_decodes_base64_body_after_verification(aws_mocks, context):
    plain_body = json.dumps({"type": "event_callback"})
    encoded_body = base64.b64encode(plain_body.encode()).decode()
    timestamp = str(int(time.time()))
    event = {
        "rawPath": "/slack/events",
        "body": encoded_body,
        "isBase64Encoded": True,
        "headers": {"x-slack-request-timestamp": timestamp, "x-slack-signature": _signature(encoded_body, timestamp)},
    }

    result = handler.lambda_handler(event, context)

    assert result == {"statusCode": 200, "body": "ok"}


def test_lambda_handler_unknown_path_returns_not_found(aws_mocks, context):
    result = handler.lambda_handler(_signed_event("/slack/unknown", "{}"), context)

    assert result == {"statusCode": 404, "body": "Not found"}
