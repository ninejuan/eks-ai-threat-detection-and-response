import logging
import os
from urllib.parse import parse_qs

from app.shared.config import Config
from app.shared.dynamodb import IncidentStore
from app.slack_bot.blocks import (
    blocks_response,
    help_blocks,
    incidents_blocks,
    status_blocks,
    unknown_command_blocks,
)

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def handle_commands(body: str, config: Config) -> dict:
    parsed = parse_qs(body)
    command = parsed.get("command", [""])[0]
    text = parsed.get("text", [""])[0]

    if command == "/atdr":
        return _dispatch_atdr(text, config)

    return blocks_response(unknown_command_blocks(command))


def _dispatch_atdr(text: str, config: Config) -> dict:
    parts = text.strip().split(maxsplit=1)
    subcommand = parts[0].lower() if parts else "help"

    if subcommand == "status":
        return blocks_response(status_blocks(config.eks_cluster_name))
    if subcommand == "incidents":
        return _incidents_response(config)
    if subcommand == "help":
        return blocks_response(help_blocks())

    return blocks_response(unknown_command_blocks(subcommand))


def _incidents_response(config: Config) -> dict:
    try:
        store = IncidentStore(config.dynamodb_table_name)
        incidents = store.recent(limit=10)
    except Exception as error:
        logger.warning("Failed to fetch incidents: %s", error)
        incidents = None

    return blocks_response(incidents_blocks(incidents))
