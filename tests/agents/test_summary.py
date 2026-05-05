import json
from unittest.mock import MagicMock, patch

from app.agents.summary import handler


def test_lambda_handler_returns_parsed_summary(monkeypatch, context):
    client = MagicMock()
    client.invoke.return_value = json.dumps({"incident_id": "inc-1", "source": "falco", "summary": "Process exec"})
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    with patch.object(handler, "_store_incident"):
        result = handler.lambda_handler({"raw_event": {"rule": "exec", "output": "sh"}}, context)

    assert result["incident_id"] == "inc-1"
    assert result["raw_event"] == {"rule": "exec", "output": "sh"}
    client.invoke.assert_called_once()
    assert "Summarize this security event" in client.invoke.call_args.kwargs["user_message"]


def test_lambda_handler_wraps_json_parse_failure(monkeypatch, context):
    client = MagicMock()
    client.invoke.return_value = "plain text summary"
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    with patch.object(handler, "_store_incident"):
        result = handler.lambda_handler({"detail": "guardduty"}, context)

    assert result["summary"] == "plain text summary"
    assert result["parse_error"] is True
    assert result["raw_event"] == {"detail": "guardduty"}


def test_lambda_handler_uses_event_as_raw_event_when_missing_key(monkeypatch, context):
    client = MagicMock()
    client.invoke.return_value = json.dumps({"title": "Unknown", "source": "guardduty"})
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    event = {"source": "aws.guardduty"}
    with patch.object(handler, "_store_incident"):
        result = handler.lambda_handler(event, context)

    assert result["raw_event"] == event
    assert result["title"] == "Unknown"
