import json
from unittest.mock import MagicMock

from app.agents.solution import handler


def test_lambda_handler_returns_parsed_solution(monkeypatch, context):
    client = MagicMock()
    solution = {
        "recommended_actions": [{"action": "checkpoint_pod", "target": "pod-a", "namespace": "default"}],
        "runbook_match": "pod-isolation",
        "estimated_impact": "pod restart",
        "rollback_steps": ["remove policy"],
    }
    client.invoke.return_value = json.dumps(solution)
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    result = handler.lambda_handler(
        {"summary": {"body": {"title": "bad"}}, "triage": {"body": {"severity": "P2"}}}, context
    )

    assert result == solution
    assert "Recommend remediation" in client.invoke.call_args.kwargs["user_message"]


def test_lambda_handler_parse_failure_returns_safe_empty_solution(monkeypatch, context):
    client = MagicMock()
    client.invoke.return_value = "broken"
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    result = handler.lambda_handler({}, context)

    assert result["recommended_actions"] == []
    assert result["runbook_match"] is None
    assert result["parse_error"] is True
    assert result["raw_response"] == "broken"


def test_lambda_handler_handles_missing_nested_fields(monkeypatch, context):
    client = MagicMock()
    client.invoke.return_value = json.dumps({"recommended_actions": []})
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    result = handler.lambda_handler({"summary": {}, "triage": {}}, context)

    assert result == {"recommended_actions": []}
    assert "{}" in client.invoke.call_args.kwargs["user_message"]


def test_lambda_handler_includes_knowledge_base_context(monkeypatch, context):
    client = MagicMock()
    client.invoke.return_value = json.dumps({"recommended_actions": []})
    kb = MagicMock()
    kb.retrieve.return_value = [
        {"content": "Use checkpoint_pod before isolation", "source": "s3://runbooks/reverse-shell.md", "score": 0.91}
    ]

    monkeypatch.setenv("KNOWLEDGE_BASE_ID", "kb-test")
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)
    monkeypatch.setattr("app.shared.knowledge_base.KnowledgeBaseClient", lambda knowledge_base_id, region: kb)

    handler.lambda_handler(
        {"summary": {"body": {"title": "reverse shell"}}, "triage": {"body": {"severity": "P1"}}}, context
    )

    user_message = client.invoke.call_args.kwargs["user_message"]
    assert "Relevant runbook context" in user_message
    assert "Use checkpoint_pod before isolation" in user_message
    assert "s3://runbooks/reverse-shell.md" in user_message


def test_lambda_handler_skips_knowledge_base_without_id(monkeypatch, context):
    client = MagicMock()
    client.invoke.return_value = json.dumps({"recommended_actions": []})

    monkeypatch.setenv("KNOWLEDGE_BASE_ID", "")
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    handler.lambda_handler({"summary": {"body": {"title": "bad"}}, "triage": {"body": {"severity": "P2"}}}, context)

    assert "Relevant runbook context" not in client.invoke.call_args.kwargs["user_message"]
