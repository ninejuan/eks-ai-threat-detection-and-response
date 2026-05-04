from unittest.mock import MagicMock

from app.degraded_notifier import handler


def test_lambda_handler_sends_degraded_notification(monkeypatch, context):
    notifier = MagicMock()
    monkeypatch.setattr(handler, "SlackNotifier", lambda project: notifier)
    event = {"source": "falco", "raw_event": {"rule": "x"}, "error": {"Cause": "ai failed"}}

    result = handler.lambda_handler(event, context)

    assert result == {"status": "degraded_notification_sent", "source": "falco"}
    notifier.send_incident.assert_called_once_with(
        {"source": "falco", "raw_event": {"rule": "x"}, "error": {"Cause": "ai failed"}, "mode": "DEGRADED"},
        mode="degraded",
    )


def test_lambda_handler_defaults_missing_fields(monkeypatch, context):
    notifier = MagicMock()
    monkeypatch.setattr(handler, "SlackNotifier", lambda project: notifier)

    result = handler.lambda_handler({}, context)

    assert result["source"] == "unknown"
    incident = notifier.send_incident.call_args.args[0]
    assert incident["raw_event"] == {}
    assert incident["error"] == {}


def test_lambda_handler_uses_project_from_config(monkeypatch, context):
    created = {}

    def make_notifier(project):
        created["project"] = project
        return MagicMock()

    monkeypatch.setattr(handler, "SlackNotifier", make_notifier)

    handler.lambda_handler({"source": "guardduty"}, context)

    assert created["project"] == "test-atdr"
