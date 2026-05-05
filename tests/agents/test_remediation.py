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
        result = handler._execute_tool("label_pod", {"pod_name": "pod-a", "namespace": "default", "labels": {"x": "y"}})

    mock_exec.assert_called_once_with("label_pod", {"pod_name": "pod-a", "namespace": "default", "labels": {"x": "y"}})
    assert result["status"] == "success"


def test_lambda_handler_stops_after_max_iterations(monkeypatch, context):
    client = MagicMock()
    client.invoke_with_tools.return_value = {
        "stop_reason": "tool_use",
        "content": [
            {"type": "tool_use", "name": "delete_pod", "input": {"pod_name": "p", "namespace": "n"}, "id": "tool"}
        ],
    }
    monkeypatch.setattr(handler, "BedrockClient", lambda model_id, region: client)

    with patch("app.agents.remediation.tools.execute_tool", return_value={"status": "success", "action": "delete_pod"}):
        result = handler.lambda_handler({}, context)

    assert result["actions_taken"] == 10
    assert client.invoke_with_tools.call_count == 10
