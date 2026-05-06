import json

from app.shared.config import Config
from app.shared.dynamodb import IncidentStore
from app.shared.slack_notifier import SlackNotifier
from app.slack_bot.commands import _dispatch_atdr


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
