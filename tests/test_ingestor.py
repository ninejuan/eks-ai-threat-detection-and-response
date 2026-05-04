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
