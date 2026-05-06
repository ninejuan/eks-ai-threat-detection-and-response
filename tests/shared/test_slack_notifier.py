import json
from unittest.mock import MagicMock

from app.shared.slack_notifier import SLACK_MAX_TEXT_LENGTH, SlackNotifier


def test_send_incident_posts_normal_blocks(monkeypatch):
    sent = {}
    response = MagicMock()
    response.status = 200
    response.__enter__.return_value = response
    response.__exit__.return_value = None

    def fake_urlopen(req, timeout):
        sent["req"] = req
        sent["timeout"] = timeout
        return response

    monkeypatch.setattr("app.shared.slack_notifier.get_secret", lambda secret_id: {"webhook_url": "https://hook"})
    monkeypatch.setattr("app.shared.slack_notifier.urlopen", fake_urlopen)

    SlackNotifier("proj").send_incident({"incident_id": "inc-1", "severity": "P1", "source": "falco", "summary": "bad"})

    payload = json.loads(sent["req"].data.decode())
    assert sent["timeout"] == 10
    assert payload["attachments"][0]["blocks"][0]["text"]["text"] == "ATDR Incident: inc-1"
    assert "*Severity:* P1" in payload["attachments"][0]["blocks"][1]["fields"][0]["text"]


def test_send_incident_posts_degraded_blocks(monkeypatch):
    sent = {}
    response = MagicMock()
    response.status = 200
    response.__enter__.return_value = response
    response.__exit__.return_value = None

    def fake_urlopen(req, timeout):
        sent["req"] = req
        sent["timeout"] = timeout
        return response

    monkeypatch.setattr("app.shared.slack_notifier.get_secret", lambda secret_id: {"webhook_url": "https://hook"})
    monkeypatch.setattr("app.shared.slack_notifier.urlopen", fake_urlopen)

    incident = {"source": "guardduty", "error": {"Cause": "bedrock down"}, "raw_event": {"detail": "x"}}
    SlackNotifier("proj").send_incident(incident, mode="degraded")

    payload = json.loads(sent["req"].data.decode())
    assert payload["blocks"][0]["text"]["text"] == "ATDR Degraded Alert"
    assert "bedrock down" in payload["blocks"][2]["text"]["text"]
    assert "guardduty" in payload["blocks"][1]["fields"][0]["text"]


def test_send_incident_skips_when_webhook_missing(monkeypatch):
    urlopen = MagicMock()
    monkeypatch.setattr("app.shared.slack_notifier.get_secret", lambda secret_id: {})
    monkeypatch.setattr("app.shared.slack_notifier.urlopen", urlopen)

    SlackNotifier("proj").send_incident({"incident_id": "inc-1"})

    urlopen.assert_not_called()


def test_degraded_blocks_truncate_large_raw_event():
    blocks = SlackNotifier("proj")._build_degraded_blocks({"raw_event": {"payload": "x" * 4000}})

    raw_block = blocks[3]["text"]["text"]
    assert len(raw_block) < SLACK_MAX_TEXT_LENGTH + 30
    assert raw_block.endswith("...```")
