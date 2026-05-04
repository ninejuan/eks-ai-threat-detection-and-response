import json
import logging
import os

from app.shared.config import Config
from app.shared.slack_notifier import SlackNotifier

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    notifier = SlackNotifier(project=config.project)

    error_info = event.get("error", {})
    raw_event = event.get("raw_event", {})
    source = event.get("source", "unknown")

    incident = {
        "source": source,
        "raw_event": raw_event,
        "error": error_info,
        "mode": "DEGRADED",
    }

    notifier.send_incident(incident, mode="degraded")

    logger.info(
        "Sent degraded notification for %s event, error: %s",
        source,
        json.dumps(error_info, default=str)[:200],
    )

    return {"status": "degraded_notification_sent", "source": source}
