import json

from app.ingestor import handler


def test_lambda_handler_starts_execution_for_sqs_records(aws_mocks, context):
    event = {"Records": [{"body": json.dumps({"source": "aws.guardduty", "detail": {"id": "finding"}})}]}

    result = handler.lambda_handler(event, context)

    assert result["processed"] == 1
    assert result["executions"][0]["source"] == "guardduty"
    sfn = aws_mocks["clients"]["stepfunctions"]
    kwargs = sfn.start_execution.call_args.kwargs
    assert kwargs["stateMachineArn"].endswith("stateMachine:test")
    assert kwargs["name"].startswith("guardduty-")
    assert json.loads(kwargs["input"])["source"] == "guardduty"


def test_lambda_handler_unwraps_sns_message(aws_mocks, context):
    body = {"Message": json.dumps({"rule": "Terminal shell", "output": "shell spawned"})}

    result = handler.lambda_handler({"Records": [{"body": json.dumps(body)}]}, context)

    assert result["processed"] == 1
    assert result["executions"][0]["source"] == "falco"
    workflow_input = json.loads(aws_mocks["clients"]["stepfunctions"].start_execution.call_args.kwargs["input"])
    assert workflow_input["raw_event"] == {"rule": "Terminal shell", "output": "shell spawned"}


def test_lambda_handler_empty_event_processes_zero_records(aws_mocks, context):
    result = handler.lambda_handler({}, context)

    assert result == {"processed": 0, "executions": []}
    aws_mocks["clients"]["stepfunctions"].start_execution.assert_not_called()


def test_detect_source_handles_all_supported_sources():
    assert handler._detect_source({"detail-type": "GuardDuty Finding"}) == "guardduty"
    assert handler._detect_source({"source": "aws.guardduty"}) == "guardduty"
    assert handler._detect_source({"rule": "r", "output": "o"}) == "falco"
    assert handler._detect_source({"process_kprobe": {}}) == "tetragon"
    assert handler._detect_source({"process_exec": {}}) == "tetragon"
    assert handler._detect_source({"message": "unknown"}) == "unknown"


def test_lambda_handler_retains_tetragon_event_in_timeline_table(aws_mocks, context, monkeypatch):
    monkeypatch.setattr(handler, "TETRAGON_TABLE", "atdr-tetragon-events")

    tetragon_event = {
        "process_kprobe": {
            "process": {
                "exec_id": "exec-abc",
                "binary": "/bin/cat",
                "arguments": "/etc/shadow",
                "pod": {
                    "uid": "pod-uid-1",
                    "namespace": "atdr-test",
                    "name": "attacker",
                    "container": {"name": "attacker"},
                },
            },
            "policy_name": "detect-sensitive-file-access",
            "function_name": "security_file_open",
            "time": "2026-05-06T19:16:03Z",
        },
    }
    event = {"Records": [{"body": json.dumps(tetragon_event)}]}

    handler.lambda_handler(event, context)

    dynamodb_resource = aws_mocks["resources"]["dynamodb"]
    table_calls = [call.args[0] for call in dynamodb_resource.Table.call_args_list]
    assert "atdr-tetragon-events" in table_calls
    assert "atdr-event-dedup" in table_calls

    table = dynamodb_resource.Table.return_value
    put_calls = [call for call in table.put_item.call_args_list if "Item" in call.kwargs]
    retained = [call for call in put_calls if call.kwargs["Item"].get("pod_uid") == "pod-uid-1"]
    assert len(retained) == 1
    item = retained[0].kwargs["Item"]
    assert item["pod_uid"] == "pod-uid-1"
    assert item["sk"].startswith("2026-05-06T19:16:03Z#")
    assert item["sk"].endswith("exec-abc")
    assert item["policy_name"] == "detect-sensitive-file-access"
    assert item["binary"] == "/bin/cat"
    assert item["ttl"] > 0


def test_lambda_handler_skips_retention_when_pod_uid_missing(aws_mocks, context, monkeypatch):
    monkeypatch.setattr(handler, "TETRAGON_TABLE", "atdr-tetragon-events")

    tetragon_event = {
        "process_kprobe": {
            "process": {
                "binary": "/bin/ls",
                "pod": {"namespace": "atdr-test", "name": "no-uid"},
            },
            "policy_name": "detect-sensitive-file-access",
        },
    }
    handler.lambda_handler({"Records": [{"body": json.dumps(tetragon_event)}]}, context)

    dynamodb_resource = aws_mocks["resources"]["dynamodb"]
    table = dynamodb_resource.Table.return_value
    retained = [call for call in table.put_item.call_args_list if call.kwargs.get("Item", {}).get("pod_uid")]
    assert retained == []


def test_lambda_handler_does_not_retain_non_tetragon_event(aws_mocks, context, monkeypatch):
    monkeypatch.setattr(handler, "TETRAGON_TABLE", "atdr-tetragon-events")

    falco_event = {"rule": "Credential file access", "output": "cat /etc/shadow"}
    handler.lambda_handler({"Records": [{"body": json.dumps(falco_event)}]}, context)

    dynamodb_resource = aws_mocks["resources"]["dynamodb"]
    table = dynamodb_resource.Table.return_value
    retained = [call for call in table.put_item.call_args_list if call.kwargs.get("Item", {}).get("pod_uid")]
    assert retained == []
