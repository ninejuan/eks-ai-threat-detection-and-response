from unittest.mock import MagicMock, patch

from app.agents.remediation import handler


def test_lambda_handler_executes_tool_use_loop(monkeypatch, context):
    client = MagicMock()
    client.invoke_with_tools.side_effect = [
        {
            "stop_reason": "tool_use",
            "content": [
                {
                    "type": "tool_use",
                    "name": "checkpoint_pod",
                    "input": {"pod_name": "pod-a", "namespace": "default"},
                    "id": "tool-1",
                }
            ],
        },
        {"stop_reason": "end_turn", "content": [{"type": "text", "text": "done"}]},
    ]
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    with patch(
        "app.agents.remediation.tools.execute_tool", return_value={"status": "success", "action": "checkpoint_pod"}
    ):
        result = handler.lambda_handler({"solution": {"body": {"recommended_actions": []}}}, context)

    assert result["status"] == "completed"
    assert result["actions_taken"] == 1
    assert result["execution_log"][0]["tool"] == "checkpoint_pod"
    assert result["execution_log"][1] == {"type": "completion", "text": "done"}
    assert client.invoke_with_tools.call_count == 2


def test_lambda_handler_completes_without_tool_use(monkeypatch, context):
    client = MagicMock()
    client.invoke_with_tools.return_value = {
        "stop_reason": "end_turn",
        "content": [{"type": "text", "text": "nothing"}],
    }
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    result = handler.lambda_handler({}, context)

    assert result["actions_taken"] == 0
    assert result["execution_log"] == [{"type": "completion", "text": "nothing"}]


def test_execute_tool_calls_real_tools():
    with patch(
        "app.agents.remediation.tools.execute_tool", return_value={"status": "success", "action": "label_pod"}
    ) as mock_exec:
        result = handler._execute_tool(
            "label_pod", {"pod_name": "pod-a", "namespace": "default", "labels": {"x": "y"}}, []
        )

    mock_exec.assert_called_once_with("label_pod", {"pod_name": "pod-a", "namespace": "default", "labels": {"x": "y"}})
    assert result["status"] == "success"


def test_lambda_handler_stops_after_max_iterations(monkeypatch, context):
    client = MagicMock()
    client.invoke_with_tools.return_value = {
        "stop_reason": "tool_use",
        "content": [
            {
                "type": "tool_use",
                "name": "label_pod",
                "input": {"pod_name": "p", "namespace": "n", "labels": {}},
                "id": "tool",
            }
        ],
    }
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    with patch("app.agents.remediation.tools.execute_tool", return_value={"status": "success", "action": "label_pod"}):
        result = handler.lambda_handler({}, context)

    assert result["actions_taken"] == 10
    assert client.invoke_with_tools.call_count == 10


def test_destructive_tool_blocked_without_checkpoint(monkeypatch, context):
    client = MagicMock()
    client.invoke_with_tools.side_effect = [
        {
            "stop_reason": "tool_use",
            "content": [
                {
                    "type": "tool_use",
                    "name": "delete_pod",
                    "input": {"pod_name": "pod-a", "namespace": "default", "force": True},
                    "id": "tool-destructive",
                }
            ],
        },
        {"stop_reason": "end_turn", "content": [{"type": "text", "text": "aborted"}]},
    ]
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    with patch("app.agents.remediation.tools.execute_tool") as mock_exec:
        result = handler.lambda_handler({}, context)

    mock_exec.assert_not_called()
    first = result["execution_log"][0]
    assert first["tool"] == "delete_pod"
    assert first["result"]["status"] == "blocked"
    assert "forensic_precondition_not_met" in first["result"]["error"]
    assert first["result"]["required_forensic_tools"] == ["checkpoint_pod"]


def test_destructive_tool_allowed_after_successful_checkpoint(monkeypatch, context):
    client = MagicMock()
    client.invoke_with_tools.side_effect = [
        {
            "stop_reason": "tool_use",
            "content": [
                {
                    "type": "tool_use",
                    "name": "checkpoint_pod",
                    "input": {"pod_name": "pod-a", "namespace": "default"},
                    "id": "tool-1",
                }
            ],
        },
        {
            "stop_reason": "tool_use",
            "content": [
                {
                    "type": "tool_use",
                    "name": "apply_cilium_network_policy",
                    "input": {"policy_name": "deny-all", "namespace": "default", "deny_all": True},
                    "id": "tool-2",
                },
                {
                    "type": "tool_use",
                    "name": "delete_pod",
                    "input": {"pod_name": "pod-a", "namespace": "default"},
                    "id": "tool-3",
                },
            ],
        },
        {"stop_reason": "end_turn", "content": [{"type": "text", "text": "done"}]},
    ]
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    tool_responses = {
        "checkpoint_pod": {"status": "success", "action": "checkpoint_pod", "evidence_uri": "s3://e/1"},
        "apply_cilium_network_policy": {"status": "success", "action": "apply_cilium_network_policy"},
        "delete_pod": {"status": "success", "action": "delete_pod"},
    }

    def fake_execute(tool_name, _tool_input):
        return tool_responses[tool_name]

    with patch("app.agents.remediation.tools.execute_tool", side_effect=fake_execute):
        result = handler.lambda_handler({}, context)

    tools_run = [e["tool"] for e in result["execution_log"] if "tool" in e]
    assert tools_run == ["checkpoint_pod", "apply_cilium_network_policy", "delete_pod"]
    for entry in result["execution_log"]:
        if "tool" in entry:
            assert entry["result"]["status"] == "success"


def test_destructive_tool_blocked_when_checkpoint_failed(monkeypatch, context):
    client = MagicMock()
    client.invoke_with_tools.side_effect = [
        {
            "stop_reason": "tool_use",
            "content": [
                {
                    "type": "tool_use",
                    "name": "checkpoint_pod",
                    "input": {"pod_name": "pod-a", "namespace": "default"},
                    "id": "tool-1",
                }
            ],
        },
        {
            "stop_reason": "tool_use",
            "content": [
                {
                    "type": "tool_use",
                    "name": "drain_node",
                    "input": {"node_name": "node-a"},
                    "id": "tool-2",
                }
            ],
        },
        {"stop_reason": "end_turn", "content": [{"type": "text", "text": "halt"}]},
    ]
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    tool_responses = {
        "checkpoint_pod": {"status": "failed", "action": "checkpoint_pod", "error": "NoSuchBucket"},
    }

    def fake_execute(tool_name, _tool_input):
        return tool_responses[tool_name]

    with patch("app.agents.remediation.tools.execute_tool", side_effect=fake_execute) as mock_exec:
        result = handler.lambda_handler({}, context)

    mock_exec.assert_called_once_with("checkpoint_pod", {"pod_name": "pod-a", "namespace": "default"})
    drain_entry = next(e for e in result["execution_log"] if e.get("tool") == "drain_node")
    assert drain_entry["result"]["status"] == "blocked"


def test_patch_deployment_scaledown_blocked_without_checkpoint(monkeypatch, context):
    client = MagicMock()
    client.invoke_with_tools.side_effect = [
        {
            "stop_reason": "tool_use",
            "content": [
                {
                    "type": "tool_use",
                    "name": "patch_deployment",
                    "input": {"deployment_name": "app", "namespace": "default", "replicas": 0},
                    "id": "tool-1",
                }
            ],
        },
        {"stop_reason": "end_turn", "content": [{"type": "text", "text": "halt"}]},
    ]
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    with patch("app.agents.remediation.tools.execute_tool") as mock_exec:
        result = handler.lambda_handler({}, context)

    mock_exec.assert_not_called()
    entry = result["execution_log"][0]
    assert entry["tool"] == "patch_deployment"
    assert entry["result"]["status"] == "blocked"


def test_patch_deployment_scaleup_not_blocked(monkeypatch, context):
    client = MagicMock()
    client.invoke_with_tools.side_effect = [
        {
            "stop_reason": "tool_use",
            "content": [
                {
                    "type": "tool_use",
                    "name": "patch_deployment",
                    "input": {"deployment_name": "app", "namespace": "default", "replicas": 3},
                    "id": "tool-1",
                }
            ],
        },
        {"stop_reason": "end_turn", "content": [{"type": "text", "text": "done"}]},
    ]
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    with patch(
        "app.agents.remediation.tools.execute_tool",
        return_value={"status": "success", "action": "patch_deployment"},
    ) as mock_exec:
        result = handler.lambda_handler({}, context)

    mock_exec.assert_called_once()
    entry = result["execution_log"][0]
    assert entry["result"]["status"] == "success"


def test_label_pod_not_blocked_even_without_checkpoint(monkeypatch, context):
    client = MagicMock()
    client.invoke_with_tools.side_effect = [
        {
            "stop_reason": "tool_use",
            "content": [
                {
                    "type": "tool_use",
                    "name": "label_pod",
                    "input": {
                        "pod_name": "pod-a",
                        "namespace": "default",
                        "labels": {"security.incident/compromised": "true"},
                    },
                    "id": "tool-1",
                }
            ],
        },
        {"stop_reason": "end_turn", "content": [{"type": "text", "text": "labeled"}]},
    ]
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    with patch(
        "app.agents.remediation.tools.execute_tool",
        return_value={"status": "success", "action": "label_pod"},
    ) as mock_exec:
        result = handler.lambda_handler({}, context)

    mock_exec.assert_called_once()
    assert result["execution_log"][0]["result"]["status"] == "success"


def test_forensic_precondition_met_helper():
    assert handler._forensic_precondition_met([]) == ["checkpoint_pod"]
    assert handler._forensic_precondition_met([{"tool": "checkpoint_pod", "result": {"status": "failed"}}]) == [
        "checkpoint_pod"
    ]
    assert handler._forensic_precondition_met([{"tool": "checkpoint_pod", "result": {"status": "success"}}]) == []
    assert (
        handler._forensic_precondition_met(
            [
                {"tool": "label_pod", "result": {"status": "success"}},
                {"tool": "checkpoint_pod", "result": {"status": "success"}},
            ]
        )
        == []
    )
    assert handler._forensic_precondition_met([{"type": "completion", "text": "..."}]) == ["checkpoint_pod"]
