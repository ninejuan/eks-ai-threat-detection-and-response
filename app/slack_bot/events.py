import json
import logging
import os

from app.shared.config import Config
from app.slack_bot.blocks import help_blocks, message_response_blocks, status_blocks
from app.slack_bot.home import publish_home

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def handle_events(body: str, config: Config) -> dict:
    payload = json.loads(body)
    event_type = payload.get("type", "")

    if event_type == "url_verification":
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "text/plain"},
            "body": payload["challenge"],
        }

    if event_type == "event_callback":
        return _handle_event_callback(payload, config)

    return {"statusCode": 200, "body": "ok"}


def _handle_event_callback(payload: dict, config: Config) -> dict:
    event = payload.get("event", {})
    event_type = event.get("type", "")

    if event_type in {"app_mention", "message"}:
        if event.get("subtype") == "bot_message" or event.get("bot_id"):
            return {"statusCode": 200, "body": "ok"}
        return _handle_message(event, config)

    if event_type == "app_home_opened":
        user_id = event.get("user", "")
        if user_id:
            publish_home(user_id, config)
        return {"statusCode": 200, "body": "ok"}

    return {"statusCode": 200, "body": "ok"}


def _handle_message(event: dict, config: Config) -> dict:
    text = event.get("text", "").lower().strip()
    channel = event.get("channel", "")

    if not channel:
        return {"statusCode": 200, "body": "ok"}

    if any(keyword in text for keyword in ["status", "상태"]):
        blocks = status_blocks(config.eks_cluster_name)
    elif any(keyword in text for keyword in ["incident", "인시던트", "사건"]):
        blocks = message_response_blocks(
            "Use `/atdr incidents` to view recent incidents, or check the Grafana dashboard for real-time monitoring."
        )
    elif any(keyword in text for keyword in ["help", "도움", "도와"]):
        blocks = help_blocks()
    else:
        blocks = message_response_blocks(
            "👋 Hi! I'm the ATDR security bot.\n\n"
            "I can help with:\n"
            "• *status* — Check system health\n"
            "• *incidents* — View recent threats\n"
            "• *help* — Show all commands\n\n"
            "Or use `/atdr <command>` for slash commands."
        )

    _post_message(channel, blocks, config)
    return {"statusCode": 200, "body": "ok"}


def _post_message(channel: str, blocks: list[dict], config: Config) -> None:
    from urllib.error import URLError
    from urllib.request import Request, urlopen

    from app.shared.secrets import get_secret

    secret = get_secret(f"{config.project}/slack/bot-token")
    bot_token = secret.get("token", "")
    if not bot_token:
        logger.warning("Slack bot token not configured")
        return

    payload = json.dumps({"channel": channel, "blocks": blocks}).encode()
    request = Request(
        "https://slack.com/api/chat.postMessage",
        data=payload,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {bot_token}",
        },
    )

    try:
        with urlopen(request, timeout=10) as response:  # noqa: S310
            result = json.loads(response.read().decode())
            if not result.get("ok"):
                logger.warning("Slack API error: %s", result.get("error"))
    except URLError as error:
        logger.warning("Failed to post Slack message: %s", error)
