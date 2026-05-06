import logging
import time
from collections import Counter
from datetime import UTC, datetime
from typing import Any

import boto3

logger = logging.getLogger(__name__)


class IncidentStore:
    def __init__(self, table_name: str):
        self._table = boto3.resource("dynamodb").Table(table_name)

    def put_incident(self, incident_id: str, data: dict[str, Any]) -> None:
        item = {
            "incident_id": incident_id,
            "created_at": datetime.now(tz=UTC).isoformat(),
            **data,
        }
        self._table.put_item(Item=item)
        logger.info("Stored incident %s", incident_id)

    def update_incident(self, incident_id: str, updates: dict[str, Any]) -> None:
        expression_parts = []
        attribute_names = {}
        attribute_values = {}

        for i, (key, value) in enumerate(updates.items()):
            placeholder_name = f"#k{i}"
            placeholder_value = f":v{i}"
            expression_parts.append(f"{placeholder_name} = {placeholder_value}")
            attribute_names[placeholder_name] = key
            attribute_values[placeholder_value] = value

        expression_parts.append("#updated = :updated_at")
        attribute_names["#updated"] = "updated_at"
        attribute_values[":updated_at"] = datetime.now(tz=UTC).isoformat()

        self._table.update_item(
            Key={"incident_id": incident_id},
            UpdateExpression="SET " + ", ".join(expression_parts),
            ExpressionAttributeNames=attribute_names,
            ExpressionAttributeValues=attribute_values,
        )
        logger.info("Updated incident %s", incident_id)

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        response = self._table.get_item(Key={"incident_id": incident_id})
        return response.get("Item")

    def recent(self, limit: int = 10) -> list[dict[str, Any]]:
        response = self._table.scan(Limit=limit)
        items = response.get("Items", [])
        items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return items[:limit]

    def get_by_status(self, status: str, limit: int = 20) -> list[dict[str, Any]]:
        return self._scan_filter("status", status, limit)

    def get_by_severity(self, severity: str, limit: int = 20) -> list[dict[str, Any]]:
        return self._scan_filter("severity", severity.upper(), limit)

    def get_stats(self, days: int = 1) -> dict[str, Any]:
        response = self._table.scan()
        items = response.get("Items", [])
        cutoff = time.time() - (days * 86400)
        filtered = [
            item
            for item in items
            if _epoch_seconds(item.get("created_at")) is None or _epoch_seconds(item.get("created_at")) >= cutoff
        ]
        by_severity = Counter(str(item.get("severity", "UNKNOWN")).upper() for item in filtered)
        active_statuses = {"detected", "acknowledged", "investigating", "open", "triaged"}
        resolved_statuses = {"resolved", "remediated", "closed"}
        top_mitre = Counter(_first_mitre(item) for item in filtered if _first_mitre(item)).most_common(5)
        return {
            "total": len(filtered),
            "by_severity": dict(by_severity),
            "active": sum(1 for item in filtered if str(item.get("status", "detected")).lower() in active_statuses),
            "resolved": sum(1 for item in filtered if str(item.get("status", "")).lower() in resolved_statuses),
            "top_mitre": top_mitre,
            "mean_time_to_acknowledge_seconds": _mean_transition(filtered, "created_at", "acknowledged_at"),
            "mean_time_to_resolve_seconds": _mean_transition(filtered, "created_at", "resolved_at"),
        }

    def _scan_filter(self, key: str, value: str, limit: int) -> list[dict[str, Any]]:
        response = self._table.scan(
            FilterExpression=f"#{key} = :value",
            ExpressionAttributeNames={f"#{key}": key},
            ExpressionAttributeValues={":value": value},
            Limit=limit,
        )
        items = response.get("Items", [])
        items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return items[:limit]


def _epoch_seconds(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int | float):
        return int(value)
    if isinstance(value, datetime):
        return int(value.timestamp())
    text = str(value).replace("Z", "+00:00")
    try:
        return int(float(text))
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return int(parsed.timestamp())
    except ValueError:
        return None


def _mean_transition(items: list[dict[str, Any]], start_key: str, end_key: str) -> int | None:
    durations = []
    for item in items:
        start = _epoch_seconds(item.get(start_key))
        end = _epoch_seconds(item.get(end_key))
        if start and end and end >= start:
            durations.append(end - start)
    return int(sum(durations) / len(durations)) if durations else None


def _first_mitre(item: dict[str, Any]) -> str:
    value = item.get("mitre") or item.get("mitre_attack") or item.get("technique") or item.get("technique_id") or ""
    if isinstance(value, dict):
        value = " ".join(str(v) for v in value.values())
    if isinstance(value, list):
        value = " ".join(str(v) for v in value)
    for token in str(value).replace(",", " ").split():
        if token.startswith("T"):
            return token
    return ""
