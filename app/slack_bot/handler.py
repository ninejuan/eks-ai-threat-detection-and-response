import base64
import hashlib
import hmac
import logging
import os
import time

from app.shared.config import Config
from app.shared.secrets import get_secret
from app.slack_bot.commands import handle_commands
from app.slack_bot.events import handle_events
from app.slack_bot.interactions import handle_interactions

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
        logger.warning("Invalid Slack signature for path %s", path)
        return {"statusCode": 401, "body": "Invalid signature"}

    if path.endswith("/events"):
        return handle_events(body, config)
    if path.endswith("/interactions"):
        return handle_interactions(body, config)
    if path.endswith("/commands"):
        return handle_commands(body, config)

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
