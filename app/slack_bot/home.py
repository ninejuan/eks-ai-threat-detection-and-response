import logging
import os
from typing import Any

from app.shared.config import Config
from app.shared.dynamodb import IncidentStore
from app.shared.slack_notifier import slack_api_call
from app.slack_bot.blocks import severity_emoji, slack_date

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

ACTIVE_STATUSES = {"detected", "acknowledged", "investigating", "open", "triaged"}
Block = dict[str, Any]


def publish_home(user_id: str, config: Config) -> dict[str, Any]:
    view = build_home_view(config)
    return _slack_api_call("views.publish", {"user_id": user_id, "view": view}, config)


def build_home_view(config: Config) -> dict[str, Any]:
    incidents, stats, data_error = _load_home_data(config)
    blocks: list[Block] = [
        {"type": "header", "text": {"type": "plain_text", "text": "🛡️ ATDR Security Operations Center", "emoji": True}},
        {"type": "divider"},
        _system_status_section(config, data_error),
        _stats_section(stats, data_error),
        {"type": "divider"},
        _active_incidents_section(incidents, data_error),
        _home_actions(),
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": "Fresh data is loaded every time this Home tab opens."}],
        },
    ]
    return {"type": "home", "blocks": blocks[:50]}


def _slack_api_call(method: str, payload: dict[str, Any], config: Config) -> dict[str, Any]:
    return slack_api_call(method, payload, config)


def _load_home_data(config: Config) -> tuple[list[dict[str, Any]], dict[str, Any], str | None]:
    try:
        store = IncidentStore(config.dynamodb_table_name)
        incidents = _active_incidents(store.recent(limit=25))[:5]
        stats = store.get_stats()
        return incidents, stats, None
    except Exception as error:
        logger.warning("Home data unavailable: %s", error)
        return [], {}, "Data unavailable"


def _active_incidents(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [incident for incident in incidents if str(incident.get("status", "detected")).lower() in ACTIVE_STATUSES]


def _system_status_section(config: Config, data_error: str | None) -> Block:
    ddb_status = "⚠️ Data unavailable" if data_error else "✅ DynamoDB incident ledger"
    return {
        "type": "section",
        "fields": [
            {"type": "mrkdwn", "text": f"*Cluster:*\n`{config.eks_cluster_name}`"},
            {"type": "mrkdwn", "text": "*Detection:*\n✅ Falco + Tetragon + GuardDuty"},
            {"type": "mrkdwn", "text": "*Remediation:*\n✅ EKS MCP Server"},
            {"type": "mrkdwn", "text": f"*Incident data:*\n{ddb_status}"},
        ],
    }


def _stats_section(stats: dict[str, Any], data_error: str | None) -> Block:
    if data_error:
        fields = [
            ("Total open", "Data unavailable"),
            ("P1 count", "Data unavailable"),
            ("MTTA", "Data unavailable"),
            ("MTTR", "Data unavailable"),
        ]
    else:
        fields = [
            ("Total open", str(stats.get("active", 0))),
            ("P1 count", str(stats.get("by_severity", {}).get("P1", 0))),
            ("MTTA", _duration(stats.get("mean_time_to_acknowledge_seconds"))),
            ("MTTR", _duration(stats.get("mean_time_to_resolve_seconds"))),
        ]
    return {
        "type": "section",
        "fields": [{"type": "mrkdwn", "text": f"*{label}:*\n{value}"} for label, value in fields],
    }


def _active_incidents_section(incidents: list[dict[str, Any]], data_error: str | None) -> Block:
    if data_error:
        text = "*Active incidents*\n_Data unavailable. Try reopening the Home tab._"
    elif not incidents:
        text = "*Active incidents*\n_No active incidents._ 🎉"
    else:
        lines = []
        for incident in incidents[:5]:
            severity = str(incident.get("severity", "UNKNOWN")).upper()
            title = str(incident.get("title") or incident.get("summary") or "Security incident")
            created = slack_date(incident.get("created_at"), "created")
            incident_id = str(incident.get("incident_id", "unknown"))
            lines.append(f"{severity_emoji(severity)} *{severity}* — *{title}*\n`{incident_id}` • {created}")
        text = "*Active incidents*\n" + "\n".join(lines)
    return {"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}}


def _home_actions() -> Block:
    return {
        "type": "actions",
        "elements": [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "View All Incidents"},
                "action_id": "view_all_incidents",
                "value": "all",
            },
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Generate Report"},
                "action_id": "generate_report",
                "value": "report",
            },
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "View On-Call"},
                "action_id": "view_oncall",
                "value": "oncall",
            },
        ],
    }


def _duration(seconds: object) -> str:
    if seconds is None:
        return "n/a"
    seconds = int(seconds) if isinstance(seconds, int | float | str) else 0
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
