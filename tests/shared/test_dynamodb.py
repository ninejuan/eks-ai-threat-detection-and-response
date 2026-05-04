from app.shared.dynamodb import IncidentStore


def test_put_incident_writes_incident_with_created_timestamp(aws_mocks, dynamodb_table):
    store = IncidentStore("incidents")

    store.put_incident("inc-1", {"severity": "P1", "source": "falco"})

    aws_mocks["resources"]["dynamodb"].Table.assert_called_once_with("incidents")
    item = dynamodb_table.put_item.call_args.kwargs["Item"]
    assert item["incident_id"] == "inc-1"
    assert item["severity"] == "P1"
    assert item["source"] == "falco"
    assert "created_at" in item


def test_update_incident_builds_update_expression(aws_mocks, dynamodb_table):
    store = IncidentStore("incidents")

    store.update_incident("inc-2", {"severity": "P2", "status": "open"})

    kwargs = dynamodb_table.update_item.call_args.kwargs
    assert kwargs["Key"] == {"incident_id": "inc-2"}
    assert kwargs["UpdateExpression"].startswith("SET ")
    assert kwargs["ExpressionAttributeNames"]["#k0"] == "severity"
    assert kwargs["ExpressionAttributeNames"]["#k1"] == "status"
    assert kwargs["ExpressionAttributeNames"]["#updated"] == "updated_at"
    assert kwargs["ExpressionAttributeValues"][":v0"] == "P2"
    assert kwargs["ExpressionAttributeValues"][":v1"] == "open"


def test_get_incident_returns_item(aws_mocks, dynamodb_table):
    store = IncidentStore("incidents")

    result = store.get_incident("inc-1")

    assert result == {"incident_id": "inc-1", "severity": "P2"}
    dynamodb_table.get_item.assert_called_once_with(Key={"incident_id": "inc-1"})


def test_get_incident_returns_none_when_missing(aws_mocks, dynamodb_table):
    dynamodb_table.get_item.return_value = {}
    store = IncidentStore("incidents")

    assert store.get_incident("missing") is None
