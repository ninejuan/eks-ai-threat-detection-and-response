import json
from unittest.mock import MagicMock, patch

from app.agents.triage import handler


def test_lambda_handler_returns_parsed_triage(monkeypatch, context):
    client = MagicMock()
    triage = {
        "severity": "P1",
        "confidence": 0.9,
        "category": "cryptomining",
        "reasoning": "Confirmed mining",
        "auto_remediate": False,
        "requires_approval": True,
    }
    client.invoke.return_value = json.dumps(triage)
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    with patch.object(handler, "_notify_slack"):
        result = handler.lambda_handler({"summary": {"body": {"summary": "miner"}}}, context)

    assert result == triage
    assert "Triage this security incident" in client.invoke.call_args.kwargs["user_message"]


def test_lambda_handler_json_parse_failure_fallback(monkeypatch, context):
    client = MagicMock()
    client.invoke.return_value = "not-json"
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    with patch.object(handler, "_notify_slack"):
        result = handler.lambda_handler({"summary": {"body": {"title": "bad"}}}, context)

    assert result["severity"] == "P2"
    assert result["confidence"] == 0.5
    assert result["category"] == "unknown"
    assert result["reasoning"] == "not-json"
    assert result["requires_approval"] is True


def test_lambda_handler_uses_event_when_summary_missing(monkeypatch, context):
    client = MagicMock()
    client.invoke.return_value = json.dumps({"severity": "P4"})
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    with patch.object(handler, "_notify_slack"):
        result = handler.lambda_handler({"raw_event": {"rule": "scan"}}, context)

    assert result == {"severity": "P4"}
    user_message = client.invoke.call_args.kwargs["user_message"]
    assert "raw_event" in user_message
