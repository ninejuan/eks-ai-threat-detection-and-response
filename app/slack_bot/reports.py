import logging
from datetime import UTC, datetime, timedelta

from app.shared.config import Config
from app.shared.dynamodb import IncidentStore
from app.slack_bot.blocks import blocks_response, build_stats_from_incidents, error_blocks, report_summary_blocks

logger = logging.getLogger(__name__)


def report_response(config: Config, period: str) -> dict:
    period = period.lower()
    if period not in {"daily", "weekly"}:
        return blocks_response(
            error_blocks("Unknown report", "Use `/atdr report daily` or `/atdr report weekly`."), ephemeral=True
        )
    try:
        report = build_report(config, period)
        return blocks_response(report_summary_blocks(report, period))
    except Exception as error:
        logger.warning("Failed to build %s report: %s", period, error)
        return blocks_response(
            error_blocks("Report unavailable", "DynamoDB is unavailable. Try again later."), ephemeral=True
        )


def build_report(config: Config, period: str = "daily") -> dict:
    days = 7 if period == "weekly" else 1
    store = IncidentStore(config.dynamodb_table_name)
    try:
        stats = store.get_stats(days=days)
        incidents = store.recent(limit=100)
    except AttributeError:
        incidents = store.recent(limit=100)
        stats = build_stats_from_incidents(incidents)
    report = {"stats": stats, "window": _window_label(days)}
    if period == "weekly":
        report["trend"] = _trend_lines(incidents)
    return report


def daily_report_blocks(config: Config) -> list[dict]:
    return report_summary_blocks(build_report(config, "daily"), "daily")


def _window_label(days: int) -> str:
    end = datetime.now(tz=UTC)
    start = end - timedelta(days=days)
    return f"{start:%Y-%m-%d} → {end:%Y-%m-%d} UTC"


def _trend_lines(incidents: list[dict]) -> list[str]:
    today = datetime.now(tz=UTC).date()
    counts = {(today - timedelta(days=i)).isoformat(): 0 for i in range(6, -1, -1)}
    for incident in incidents:
        created = str(incident.get("created_at", ""))[:10]
        if created in counts:
            counts[created] += 1
    return [f"• `{day}` — {'▮' * min(count, 12) or '·'} {count}" for day, count in counts.items()]
