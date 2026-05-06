import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

from app.shared.config import Config
from app.shared.dynamodb import IncidentStore
from app.shared.slack_notifier import slack_api_call
from app.slack_bot.blocks import (
    error_blocks,
    incident_detail_blocks,
    incidents_blocks,
    oncall_blocks,
    report_summary_blocks,
    status_blocks,
)
from app.slack_bot.reports import build_report

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
Block = dict[str, Any]


def open_incident_filter_modal(
    trigger_id: str, config: Config, channel_id: str = "", user_id: str = ""
) -> dict[str, Any]:
    view = {
        "type": "modal",
        "callback_id": "incident_filter_submit",
        "title": {"type": "plain_text", "text": "ATDR Incidents"},
        "submit": {"type": "plain_text", "text": "Search"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "private_metadata": _metadata(channel_id, user_id),
        "blocks": [
            _static_select_input(
                "severity_filter",
                "severity",
                "Severity",
                "Any severity",
                ["P1", "P2", "P3", "P4"],
            ),
            _static_select_input(
                "status_filter",
                "status",
                "Status",
                "Any status",
                ["open", "detected", "acknowledged", "investigating", "triaged", "resolved", "closed"],
            ),
            _date_input("start_date", "start", "Start date"),
            _date_input("end_date", "end", "End date"),
        ],
    }
    return slack_api_call("views.open", {"trigger_id": trigger_id, "view": view}, config)


def open_report_modal(trigger_id: str, config: Config, channel_id: str = "", user_id: str = "") -> dict[str, Any]:
    view = {
        "type": "modal",
        "callback_id": "report_generation_submit",
        "title": {"type": "plain_text", "text": "ATDR Report"},
        "submit": {"type": "plain_text", "text": "Generate"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "private_metadata": _metadata(channel_id, user_id),
        "blocks": [
            _static_select_input("report_type", "type", "Report type", "Daily", ["daily", "weekly"]),
            _date_input("report_start_date", "start", "Start date"),
            _date_input("report_end_date", "end", "End date"),
        ],
    }
    return slack_api_call("views.open", {"trigger_id": trigger_id, "view": view}, config)


def open_incident_detail_modal(trigger_id: str, config: Config, incident_id: str) -> dict[str, Any]:
    try:
        incident = IncidentStore(config.dynamodb_table_name).get_incident(incident_id)
        blocks = _modal_safe_blocks(incident_detail_blocks(incident))
    except Exception as error:
        logger.warning("Failed to open incident detail modal for %s: %s", incident_id, error)
        blocks = error_blocks("Incident detail unavailable", "DynamoDB is unavailable. Try again later.")
    view = {
        "type": "modal",
        "callback_id": "incident_detail_view",
        "title": {"type": "plain_text", "text": "Incident Detail"},
        "close": {"type": "plain_text", "text": "Close"},
        "blocks": blocks[:50],
    }
    return slack_api_call("views.open", {"trigger_id": trigger_id, "view": view}, config)


def open_status_modal(trigger_id: str, config: Config) -> dict[str, Any]:
    view = {
        "type": "modal",
        "callback_id": "status_view",
        "title": {"type": "plain_text", "text": "ATDR Status"},
        "close": {"type": "plain_text", "text": "Close"},
        "blocks": status_blocks(config.eks_cluster_name),
    }
    return slack_api_call("views.open", {"trigger_id": trigger_id, "view": view}, config)


def open_ack_incident_modal(trigger_id: str, config: Config, channel_id: str = "", user_id: str = "") -> dict[str, Any]:
    view = {
        "type": "modal",
        "callback_id": "ack_incident_submit",
        "title": {"type": "plain_text", "text": "Acknowledge"},
        "submit": {"type": "plain_text", "text": "Acknowledge"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "private_metadata": _metadata(channel_id, user_id),
        "blocks": [
            {
                "type": "input",
                "block_id": "incident_id_input",
                "label": {"type": "plain_text", "text": "Incident ID"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "incident_id",
                    "placeholder": {"type": "plain_text", "text": "inc-..."},
                },
            }
        ],
    }
    return slack_api_call("views.open", {"trigger_id": trigger_id, "view": view}, config)


def post_oncall_status(config: Config, user_id: str, channel_id: str = "") -> dict[str, Any]:
    return _post_user_blocks(config, user_id, channel_id, oncall_blocks(config.oncall_user, config.oncall_channel))


def handle_view_submission(payload: dict[str, Any], config: Config) -> dict[str, Any]:
    view = payload.get("view", {})
    callback_id = view.get("callback_id", "")
    user_id = payload.get("user", {}).get("id", "")
    metadata = _parse_metadata(view.get("private_metadata", ""), fallback_user=user_id)

    if callback_id == "incident_filter_submit":
        blocks = _filtered_incident_blocks(config, view)
        _post_user_blocks(config, metadata["user_id"], metadata["channel_id"], blocks)
    elif callback_id == "report_generation_submit":
        blocks = _generated_report_blocks(config, view)
        _post_user_blocks(config, metadata["user_id"], metadata["channel_id"], blocks)
    elif callback_id == "ack_incident_submit":
        blocks = _ack_incident_from_view(config, view, metadata["user_id"])
        _post_user_blocks(config, metadata["user_id"], metadata["channel_id"], blocks)

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"response_action": "clear"}),
    }


def _filtered_incident_blocks(config: Config, view: dict[str, Any]) -> list[Block]:
    severity = _selected_value(view, "severity_filter", "severity")
    status = _selected_value(view, "status_filter", "status")
    start_date = _date_value(view, "start_date", "start")
    end_date = _date_value(view, "end_date", "end")
    try:
        incidents = IncidentStore(config.dynamodb_table_name).recent(limit=100)
    except Exception as error:
        logger.warning("Failed to filter incidents: %s", error)
        return error_blocks("Incident filter unavailable", "DynamoDB is unavailable. Try again later.")

    filtered = [
        incident for incident in incidents if _matches_filters(incident, severity, status, start_date, end_date)
    ]
    title_parts = [part for part in [severity.upper() if severity else "", status.title() if status else ""] if part]
    title = "🚨 Filtered Incidents" + (f" ({', '.join(title_parts)})" if title_parts else "")
    return incidents_blocks(filtered[:10], title=title)


def _generated_report_blocks(config: Config, view: dict[str, Any]) -> list[Block]:
    report_type = _selected_value(view, "report_type", "type") or "daily"
    if report_type not in {"daily", "weekly"}:
        report_type = "daily"
    try:
        report = build_report(config, report_type)
    except Exception as error:
        logger.warning("Failed to generate modal report: %s", error)
        return error_blocks("Report unavailable", "DynamoDB is unavailable. Try again later.")
    start_date = _date_value(view, "report_start_date", "start")
    end_date = _date_value(view, "report_end_date", "end")
    if start_date or end_date:
        report["window"] = f"{start_date or 'beginning'} → {end_date or 'now'} UTC"
    return report_summary_blocks(report, report_type)


def _ack_incident_from_view(config: Config, view: dict[str, Any], user_id: str) -> list[Block]:
    incident_id = _plain_text_value(view, "incident_id_input", "incident_id").strip()
    if not incident_id:
        return error_blocks("Acknowledge failed", "Provide an incident ID.")
    try:
        IncidentStore(config.dynamodb_table_name).update_incident(
            incident_id,
            {
                "status": "acknowledged",
                "acknowledged_by": f"<@{user_id}>",
                "acknowledged_at": datetime.now(tz=UTC).isoformat(),
            },
        )
    except Exception as error:
        logger.warning("Failed to acknowledge incident %s: %s", incident_id, error)
        return error_blocks("Acknowledge failed", "DynamoDB is unavailable. Try again later.")
    return [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"✅ Incident acknowledged: `{incident_id}` by <@{user_id}>"},
        }
    ]


def _post_user_blocks(config: Config, user_id: str, channel_id: str, blocks: list[Block]) -> dict[str, Any]:
    if channel_id:
        return slack_api_call(
            "chat.postEphemeral", {"channel": channel_id, "user": user_id, "blocks": blocks[:50]}, config
        )
    return slack_api_call("chat.postMessage", {"channel": user_id, "blocks": blocks[:50]}, config)


def _static_select_input(block_id: str, action_id: str, label: str, placeholder: str, options: list[str]) -> Block:
    return {
        "type": "input",
        "block_id": block_id,
        "optional": True,
        "label": {"type": "plain_text", "text": label},
        "element": {
            "type": "static_select",
            "action_id": action_id,
            "placeholder": {"type": "plain_text", "text": placeholder},
            "options": [
                {"text": {"type": "plain_text", "text": option}, "value": option.lower()} for option in options
            ],
        },
    }


def _date_input(block_id: str, action_id: str, label: str) -> Block:
    return {
        "type": "input",
        "block_id": block_id,
        "optional": True,
        "label": {"type": "plain_text", "text": label},
        "element": {"type": "datepicker", "action_id": action_id},
    }


def _metadata(channel_id: str, user_id: str) -> str:
    return json.dumps({"channel_id": channel_id, "user_id": user_id})


def _parse_metadata(value: str, fallback_user: str) -> dict[str, str]:
    try:
        metadata = json.loads(value or "{}")
    except json.JSONDecodeError:
        metadata = {}
    return {"channel_id": metadata.get("channel_id", ""), "user_id": metadata.get("user_id") or fallback_user}


def _state_value(view: dict[str, Any], block_id: str, action_id: str) -> dict[str, Any]:
    return view.get("state", {}).get("values", {}).get(block_id, {}).get(action_id, {})


def _selected_value(view: dict[str, Any], block_id: str, action_id: str) -> str:
    selected = _state_value(view, block_id, action_id).get("selected_option") or {}
    return str(selected.get("value", ""))


def _date_value(view: dict[str, Any], block_id: str, action_id: str) -> str:
    return str(_state_value(view, block_id, action_id).get("selected_date") or "")


def _plain_text_value(view: dict[str, Any], block_id: str, action_id: str) -> str:
    return str(_state_value(view, block_id, action_id).get("value") or "")


def _matches_filters(incident: dict[str, Any], severity: str, status: str, start_date: str, end_date: str) -> bool:
    created = str(incident.get("created_at", ""))[:10]
    if severity and str(incident.get("severity", "")).lower() != severity.lower():
        return False
    if status and str(incident.get("status", "")).lower() != status.lower():
        return False
    if start_date and created and created < start_date:
        return False
    return not (end_date and created and created > end_date)


def _modal_safe_blocks(blocks: list[Block]) -> list[Block]:
    return [block for block in blocks if block.get("type") != "actions"]
