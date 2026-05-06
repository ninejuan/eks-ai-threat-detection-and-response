import json
from unittest.mock import MagicMock, patch

import pytest

from app.agents.forensic_synthesis import handler


@pytest.fixture
def bedrock_patch(monkeypatch):
    def factory(response_text):
        client = MagicMock()
        client.invoke.return_value = response_text
        monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)
        return client

    return factory


@pytest.fixture
def s3_put_capture(monkeypatch):
    put_calls = []

    def fake_client(service_name, *_args, **_kwargs):
        if service_name != "s3":
            raise AssertionError(f"unexpected boto3.client({service_name!r}) in synthesis")

        class S3:
            def put_object(self, **kwargs):
                put_calls.append(kwargs)

        return S3()

    monkeypatch.setattr("boto3.client", fake_client)
    return put_calls


def _incident_event():
    return {
        "summary": {
            "body": {
                "incident_id": "inc-2026-synth-1",
                "title": "cat /etc/shadow",
                "source": "tetragon",
            }
        },
        "triage": {"body": {"severity": "P2", "confidence": 0.92, "category": "privilege_escalation"}},
        "solution": {"body": {"recommended_actions": []}},
        "remediation": {
            "body": {
                "status": "completed",
                "execution_log": [
                    {
                        "tool": "checkpoint_pod",
                        "input": {"pod_name": "attacker", "namespace": "atdr-test"},
                        "result": {
                            "status": "success",
                            "action": "checkpoint_pod",
                            "evidence_uri": "s3://atdr-forensics-test/incidents/inc-2026-synth-1/checkpoints/attacker/2026/evidence.json",
                            "evidence_sha256": "a" * 64,
                        },
                    },
                    {
                        "tool": "delete_pod",
                        "input": {"pod_name": "attacker", "namespace": "atdr-test"},
                        "result": {"status": "success", "action": "delete_pod"},
                    },
                    {"type": "completion", "text": "done"},
                ],
                "actions_taken": 2,
            }
        },
    }


def test_lambda_handler_persists_parsed_synthesis(bedrock_patch, s3_put_capture, context, monkeypatch):
    monkeypatch.setenv("FORENSICS_BUCKET", "atdr-forensics-test")
    monkeypatch.setattr(handler, "_update_incident", lambda *args, **kwargs: None)

    synthesis_payload = {
        "executive_summary": "Compromised pod read /etc/shadow and was isolated.",
        "timeline": [
            {
                "timestamp": "2026-05-06T19:16:03Z",
                "event": "cat /etc/shadow",
                "source": "tetragon",
                "evidence_ref": "evidence_uri:s3://...",
                "confidence": "high",
            }
        ],
        "iocs": [{"type": "file", "value": "/etc/shadow", "source": "tetragon", "confidence": "high"}],
        "ttps": [
            {
                "framework": "MITRE ATT&CK",
                "technique_id": "T1552",
                "name": "Unsecured Credentials",
                "evidence_refs": ["..."],
            }
        ],
        "blast_radius": {
            "affected_namespaces": ["atdr-test"],
            "affected_pods": ["attacker"],
            "lateral_movement_observed": False,
            "privilege_escalation_observed": True,
        },
        "root_cause_hypothesis": "Standalone attacker pod reading credentials.",
        "remediation_assessment": {
            "actions_attempted": ["checkpoint_pod", "delete_pod"],
            "actions_succeeded": ["checkpoint_pod", "delete_pod"],
            "actions_failed": [],
            "residual_risk": "low",
            "residual_risk_reason": "attacker pod deleted",
        },
        "hardening_recommendations": [
            {"priority": 1, "recommendation": "Add admission deny for /etc/shadow reads", "rationale": "..."}
        ],
        "open_questions": [],
        "confidence_overall": "high",
    }
    bedrock = bedrock_patch(json.dumps(synthesis_payload))

    result = handler.lambda_handler(_incident_event(), context)

    assert result["status"] == "completed"
    assert result["parse_error"] is None
    assert result["incident_id"] == "inc-2026-synth-1"
    assert result["synthesis_uris"]["report_uri"].endswith("/synthesis-report.md")
    assert result["synthesis_uris"]["synthesis_uri"].endswith("/synthesis.json")

    bedrock.invoke.assert_called_once()
    system_prompt = bedrock.invoke.call_args.kwargs["system_prompt"]
    assert "Forensic Synthesis" in system_prompt
    user_message = bedrock.invoke.call_args.kwargs["user_message"]
    assert "inc-2026-synth-1" in user_message
    assert "s3://atdr-forensics-test" in user_message

    kinds = {call["Key"].rsplit("/", 1)[-1] for call in s3_put_capture}
    assert kinds == {"synthesis-report.md", "synthesis.json", "timeline.json", "iocs.json", "ttps.json"}

    markdown_call = next(call for call in s3_put_capture if call["Key"].endswith("/synthesis-report.md"))
    assert b"Forensic Synthesis" in markdown_call["Body"]
    assert b"T1552" in markdown_call["Body"]


def test_lambda_handler_records_parse_error_on_invalid_json(bedrock_patch, s3_put_capture, context, monkeypatch):
    monkeypatch.setenv("FORENSICS_BUCKET", "atdr-forensics-test")
    monkeypatch.setattr(handler, "_update_incident", lambda *args, **kwargs: None)
    bedrock_patch("this is not json at all")

    result = handler.lambda_handler(_incident_event(), context)

    assert result["status"] == "completed_with_parse_error"
    assert "invalid_json_response" in result["parse_error"]
    synthesis_call = next(call for call in s3_put_capture if call["Key"].endswith("/synthesis.json"))
    payload = json.loads(synthesis_call["Body"])
    assert payload["_fallback"] is True
    assert "invalid_json_response" in payload["_fallback_reason"]


def test_lambda_handler_tolerates_bedrock_failure(bedrock_patch, s3_put_capture, context, monkeypatch):
    monkeypatch.setenv("FORENSICS_BUCKET", "atdr-forensics-test")
    monkeypatch.setattr(handler, "_update_incident", lambda *args, **kwargs: None)

    client = MagicMock()
    client.invoke.side_effect = RuntimeError("bedrock unavailable")
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    result = handler.lambda_handler(_incident_event(), context)

    assert result["status"] == "completed_with_parse_error"
    assert "bedrock_invoke_failed" in result["parse_error"]

    synthesis_call = next(call for call in s3_put_capture if call["Key"].endswith("/synthesis.json"))
    payload = json.loads(synthesis_call["Body"])
    assert payload["_fallback"] is True


def test_lambda_handler_strips_markdown_fences(bedrock_patch, s3_put_capture, context, monkeypatch):
    monkeypatch.setenv("FORENSICS_BUCKET", "atdr-forensics-test")
    monkeypatch.setattr(handler, "_update_incident", lambda *args, **kwargs: None)

    synthesis_payload = {
        "executive_summary": "fenced",
        "timeline": [],
        "iocs": [],
        "ttps": [],
        "blast_radius": {
            "affected_namespaces": [],
            "affected_pods": [],
            "lateral_movement_observed": False,
            "privilege_escalation_observed": False,
        },
        "root_cause_hypothesis": "",
        "remediation_assessment": {
            "actions_attempted": [],
            "actions_succeeded": [],
            "actions_failed": [],
            "residual_risk": "low",
            "residual_risk_reason": "",
        },
        "hardening_recommendations": [],
        "open_questions": [],
        "confidence_overall": "medium",
    }
    fenced = f"```json\n{json.dumps(synthesis_payload)}\n```"
    bedrock_patch(fenced)

    result = handler.lambda_handler(_incident_event(), context)

    assert result["parse_error"] is None
    synthesis_call = next(call for call in s3_put_capture if call["Key"].endswith("/synthesis.json"))
    payload = json.loads(synthesis_call["Body"])
    assert payload["executive_summary"] == "fenced"
    assert "_fallback" not in payload


def test_lambda_handler_skips_s3_when_bucket_missing(bedrock_patch, context, monkeypatch):
    monkeypatch.delenv("FORENSICS_BUCKET", raising=False)
    monkeypatch.setattr(handler, "_update_incident", lambda *args, **kwargs: None)
    bedrock_patch('{"executive_summary": "..."}')

    with patch("boto3.client") as mock_boto:
        result = handler.lambda_handler(_incident_event(), context)

    assert result["synthesis_uris"] == {}
    mock_boto.assert_not_called()


def test_extract_evidence_uris_pulls_from_execution_log():
    log = [
        {
            "tool": "checkpoint_pod",
            "result": {"status": "success", "evidence_uri": "s3://a/b.json", "evidence_sha256": "f" * 64},
        },
        {
            "tool": "delete_pod",
            "result": {"status": "success"},
        },
        {"type": "completion", "text": "done"},
    ]
    uris = handler._extract_evidence_uris(log, extra=["s3://extra/key"])
    assert uris[0]["uri"] == "s3://a/b.json"
    assert uris[0]["sha256"] == "f" * 64
    assert uris[1]["uri"] == "s3://extra/key"


def test_render_markdown_handles_empty_sections():
    synthesis = {
        "executive_summary": "",
        "timeline": [],
        "iocs": [],
        "ttps": [],
        "blast_radius": {},
        "root_cause_hypothesis": "",
        "remediation_assessment": {},
        "hardening_recommendations": [],
        "open_questions": [],
        "confidence_overall": "",
    }
    md = handler._render_markdown(synthesis, incident_id="inc-x")
    assert "Forensic Synthesis" in md
    assert "inc-x" in md
    assert "_(none)_" in md or "_(no events recorded)_" in md


def test_strip_json_fences_strips_triple_backticks():
    assert handler._strip_json_fences('```json\n{"a":1}\n```') == '{"a":1}'
    assert handler._strip_json_fences('```\n{"a":1}\n```') == '{"a":1}'
    assert handler._strip_json_fences('{"a":1}') == '{"a":1}'
