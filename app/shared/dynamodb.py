import logging
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
