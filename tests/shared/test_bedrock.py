import json
from io import BytesIO

from app.shared.bedrock import BedrockClient


def test_invoke_returns_text_from_bedrock_response(aws_mocks):
    client = BedrockClient(model_id="model-1", region="eu-central-1")

    result = client.invoke("system", "user", max_tokens=123)

    assert result == '{"ok": true}'
    bedrock = aws_mocks["clients"]["bedrock-runtime"]
    bedrock.invoke_model.assert_called_once()
    kwargs = bedrock.invoke_model.call_args.kwargs
    body = json.loads(kwargs["body"])
    assert kwargs["modelId"] == "model-1"
    assert body["system"] == "system"
    assert body["messages"] == [{"role": "user", "content": "user"}]
    assert body["max_tokens"] == 123


def test_invoke_with_tools_returns_decoded_dict(aws_mocks):
    bedrock = aws_mocks["clients"]["bedrock-runtime"]
    bedrock.invoke_model.return_value = {"body": BytesIO(json.dumps({"stop_reason": "end_turn"}).encode())}
    client = BedrockClient(model_id="model-2", region="ap-south-1")

    result = client.invoke_with_tools("system", [{"role": "user", "content": "hi"}], [{"name": "tool"}], 55)

    assert result == {"stop_reason": "end_turn"}
    kwargs = bedrock.invoke_model.call_args.kwargs
    body = json.loads(kwargs["body"])
    assert body["tools"] == [{"name": "tool"}]
    assert body["messages"] == [{"role": "user", "content": "hi"}]
    assert body["max_tokens"] == 55


def test_constructor_uses_bedrock_runtime_region(aws_mocks):
    BedrockClient(model_id="model-3", region="us-east-1")

    assert aws_mocks["clients"]["bedrock-runtime"] is not None
