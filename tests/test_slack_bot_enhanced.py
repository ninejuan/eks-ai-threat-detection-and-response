import json
from urllib.parse import quote_plus

from app.shared.config import Config
from app.shared.dynamodb import IncidentStore
from app.shared.slack_notifier import SlackNotifier, slack_api_call
from app.slack_bot.commands import _dispatch_atdr
from app.slack_bot.events import handle_events
from app.slack_bot.home import build_home_view
from app.slack_bot.interactions import handle_interactions


def _body(result):
    return json.loads(result["body"])


def test_incident_detail_command_shows_security_context(aws_mocks, dynamodb_table):
    dynamodb_table.get_item.return_value = {
        "Item": {
            "incident_id": "inc-1",
            "severity": "P1",
            "status": "detected",
            "title": "Reverse shell",
            "created_at": "2026-05-06T01:00:00Z",
            "triaged_at": "2026-05-06T01:01:00Z",
            "raw_indicators": {"ip": "10.0.0.8", "domain": "evil.example.com", "sha256": "a" * 64},
            "mitre": "T1611",
            "affected_resources": ["pod/default/shell", "node/ip-10-0-0-1"],
            "execution_log": [{"tool": "checkpoint_pod", "status": "success", "target": "pod/default/shell"}],
            "forensics": {"checkpoint_pod": "s3://bucket/inc-1/checkpoint.tar"},
        }
    }

    result = _dispatch_atdr("incident inc-1", Config())

    blocks_text = json.dumps(_body(result)["blocks"])
    assert "Incident Detail" in blocks_text
    assert "T1611" in blocks_text
    assert "10.0.0.8" in blocks_text
    assert "checkpoint_pod" in blocks_text
    assert "s3://bucket/inc-1/checkpoint.tar" in blocks_text


def test_incidents_filters_by_status_and_severity(aws_mocks, dynamodb_table):
    dynamodb_table.scan.return_value = {
        "Items": [{"incident_id": "inc-2", "severity": "P2", "status": "open", "created_at": "2026-05-06T01:00:00Z"}]
    }

    status_result = _dispatch_atdr("incidents open", Config())
    severity_result = _dispatch_atdr("incidents P2", Config())

    assert "Open Incidents" in json.dumps(_body(status_result)["blocks"])
    assert "P2 Incidents" in json.dumps(_body(severity_result)["blocks"])
    assert dynamodb_table.scan.call_args.kwargs["ExpressionAttributeValues"][":value"] == "P2"


def test_oncall_ack_assign_resolve_commands_update_incident(aws_mocks, dynamodb_table):
    ack = _dispatch_atdr("ack inc-1", Config())
    assign = _dispatch_atdr("assign inc-1 <@U2>", Config())
    resolve = _dispatch_atdr("resolve inc-1 contained", Config())

    assert "Incident Acknowledged" in json.dumps(_body(ack)["blocks"])
    assert "Incident Assigned" in json.dumps(_body(assign)["blocks"])
    assert "contained" in json.dumps(_body(resolve)["blocks"])
    assert dynamodb_table.update_item.call_count == 3


def test_ioc_evidence_timeline_and_guide_commands(aws_mocks, dynamodb_table, s3_client):
    dynamodb_table.get_item.return_value = {
        "Item": {
            "incident_id": "inc-3",
            "created_at": "2026-05-06T01:00:00Z",
            "acknowledged_at": "2026-05-06T01:02:00Z",
            "raw_indicators": "8.8.8.8 bad.example cafebabecafebabecafebabecafebabe",
            "evidence": "s3://bucket/inc-3/flows.json",
        }
    }

    ioc = _dispatch_atdr("ioc inc-3", Config())
    evidence = _dispatch_atdr("evidence inc-3", Config())
    timeline = _dispatch_atdr("timeline inc-3", Config())
    guide = _dispatch_atdr("guide dns", Config())

    assert "8.8.8.8" in json.dumps(_body(ioc)["blocks"])
    assert "Open evidence" in json.dumps(_body(evidence)["blocks"])
    assert s3_client.generate_presigned_url.called
    assert "Acknowledged" in json.dumps(_body(timeline)["blocks"])
    assert "Capture Hubble flows" in json.dumps(_body(guide)["blocks"])


def test_report_daily_uses_store_stats(aws_mocks, dynamodb_table):
    dynamodb_table.scan.return_value = {
        "Items": [
            {
                "incident_id": "a",
                "severity": "P1",
                "status": "resolved",
                "created_at": "2999-01-01T00:00:00Z",
                "mitre": "T1496",
            },
            {
                "incident_id": "b",
                "severity": "P3",
                "status": "detected",
                "created_at": "2999-01-01T00:00:00Z",
                "mitre": "T1611",
            },
        ]
    }

    result = _dispatch_atdr("report daily", Config())

    blocks_text = json.dumps(_body(result)["blocks"])
    assert "Daily Security Report" in blocks_text
    assert "Total incidents" in blocks_text
    assert "T1496" in blocks_text


def test_slack_notifier_enhanced_alert_contains_actions_and_escalation():
    blocks = SlackNotifier("proj")._build_normal_blocks(
        {
            "incident_id": "inc-p1",
            "severity": "P1",
            "source": "falco",
            "title": "Runtime threat",
            "summary": "Container escape attempt",
            "mitre": "T1611",
            "affected_resources": ["pod/default/a"],
        }
    )

    text = json.dumps(blocks, ensure_ascii=False)
    assert "🔴" in text
    assert "T1611" in text
    assert "<!channel>" in text
    assert "ack_incident" in text
    assert "escalate_incident" in text


def test_incident_store_new_scan_methods(aws_mocks, dynamodb_table):
    dynamodb_table.scan.return_value = {"Items": [{"incident_id": "inc", "severity": "P1", "status": "open"}]}
    store = IncidentStore("incidents")

    assert store.get_by_status("open")[0]["incident_id"] == "inc"
    assert store.get_by_severity("P1")[0]["incident_id"] == "inc"
    assert store.get_stats(days=7)["total"] == 1


def test_home_view_shows_soc_dashboard(aws_mocks, dynamodb_table):
    dynamodb_table.scan.return_value = {
        "Items": [
            {
                "incident_id": "inc-home",
                "severity": "P1",
                "status": "open",
                "title": "Container escape",
                "created_at": "2999-01-01T00:00:00Z",
            }
        ]
    }

    view = build_home_view(Config())

    text = json.dumps(view, ensure_ascii=False)
    assert view["type"] == "home"
    assert "ATDR Security Operations Center" in text
    assert "inc-home" in text
    assert "View All Incidents" in text
    assert "Generate Report" in text


def test_app_home_opened_event_publishes_home(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.slack_bot.events.publish_home", lambda user_id, config: calls.append((user_id, config.project))
    )

    result = handle_events(
        json.dumps({"type": "event_callback", "event": {"type": "app_home_opened", "user": "U1"}}), Config()
    )

    assert result["statusCode"] == 200
    assert calls == [("U1", "test-atdr")]


def test_home_buttons_open_modals_and_post_oncall(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.slack_bot.modals.slack_api_call",
        lambda method, payload, config: calls.append((method, payload)) or {"ok": True},
    )

    payload = {
        "type": "block_actions",
        "trigger_id": "trig-1",
        "user": {"id": "U1"},
        "channel": {"id": "C1"},
        "actions": [{"action_id": "view_all_incidents", "value": "all"}],
    }
    result = handle_interactions("payload=" + quote_plus(json.dumps(payload)), Config())

    payload["actions"] = [{"action_id": "generate_report", "value": "report"}]
    handle_interactions("payload=" + quote_plus(json.dumps(payload)), Config())
    payload["actions"] = [{"action_id": "view_oncall", "value": "oncall"}]
    handle_interactions("payload=" + quote_plus(json.dumps(payload)), Config())

    assert result["statusCode"] == 200
    assert calls[0][0] == "views.open"
    assert calls[0][1]["trigger_id"] == "trig-1"
    assert calls[0][1]["view"]["callback_id"] == "incident_filter_submit"
    assert calls[1][1]["view"]["callback_id"] == "report_generation_submit"
    assert calls[2][0] == "chat.postEphemeral"


def test_view_submission_filters_incidents_to_ephemeral(monkeypatch, aws_mocks, dynamodb_table):
    calls = []
    monkeypatch.setattr(
        "app.slack_bot.modals.slack_api_call",
        lambda method, payload, config: calls.append((method, payload)) or {"ok": True},
    )
    dynamodb_table.scan.return_value = {
        "Items": [
            {"incident_id": "inc-p1", "severity": "P1", "status": "open", "created_at": "2026-05-06T01:00:00Z"},
            {"incident_id": "inc-p3", "severity": "P3", "status": "closed", "created_at": "2026-05-06T01:00:00Z"},
        ]
    }
    payload = {
        "type": "view_submission",
        "user": {"id": "U1"},
        "view": {
            "callback_id": "incident_filter_submit",
            "private_metadata": json.dumps({"channel_id": "C1", "user_id": "U1"}),
            "state": {
                "values": {
                    "severity_filter": {"severity": {"selected_option": {"value": "p1"}}},
                    "status_filter": {"status": {"selected_option": {"value": "open"}}},
                    "start_date": {"start": {"selected_date": "2026-05-01"}},
                    "end_date": {"end": {"selected_date": "2026-05-31"}},
                }
            },
        },
    }

    result = handle_interactions("payload=" + quote_plus(json.dumps(payload)), Config())

    assert json.loads(result["body"])["response_action"] == "clear"
    assert calls[0][0] == "chat.postEphemeral"
    text = json.dumps(calls[0][1]["blocks"])
    assert "inc-p1" in text
    assert "inc-p3" not in text


def test_shortcuts_open_status_and_ack_modals(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.slack_bot.modals.slack_api_call",
        lambda method, payload, config: calls.append((method, payload)) or {"ok": True},
    )

    status_payload = {"type": "shortcut", "callback_id": "atdr_view_status", "trigger_id": "ts", "user": {"id": "U1"}}
    ack_payload = {"type": "shortcut", "callback_id": "atdr_ack_incident", "trigger_id": "ta", "user": {"id": "U1"}}
    handle_interactions("payload=" + quote_plus(json.dumps(status_payload)), Config())
    handle_interactions("payload=" + quote_plus(json.dumps(ack_payload)), Config())

    assert calls[0][1]["view"]["callback_id"] == "status_view"
    assert calls[1][1]["view"]["callback_id"] == "ack_incident_submit"


def test_slack_api_call_uses_bot_token(monkeypatch):
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps({"ok": True}).encode()

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["headers"] = request.headers
        captured["body"] = json.loads(request.data.decode())
        return Response()

    monkeypatch.setattr("app.shared.slack_notifier.get_secret", lambda secret_id: {"token": "xoxb-test"})
    monkeypatch.setattr("app.shared.slack_notifier.urlopen", fake_urlopen)

    result = slack_api_call("views.open", {"trigger_id": "t", "view": {"type": "modal"}}, Config())

    assert result["ok"] is True
    assert captured["url"] == "https://slack.com/api/views.open"
    assert captured["headers"]["Authorization"] == "Bearer xoxb-test"
    assert captured["body"]["trigger_id"] == "t"
