import json
from io import BytesIO
from unittest.mock import MagicMock

import pytest

from app.shared import secrets


@pytest.fixture(autouse=True)
def mock_env(monkeypatch):
    monkeypatch.setenv("PROJECT", "test-atdr")
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("AGENT_TYPE", "summary")
    monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.test-model")
    monkeypatch.setenv("OPENSEARCH_ENDPOINT", "https://opensearch.test")
    monkeypatch.setenv("KNOWLEDGE_BASE_ID", "kb-test")
    monkeypatch.setenv("STATE_MACHINE_ARN", "arn:aws:states:us-west-2:123456789012:stateMachine:test")
    monkeypatch.setenv("DYNAMODB_TABLE_NAME", "test-incidents")


@pytest.fixture(autouse=True)
def clear_secret_cache():
    secrets._get_secrets_client.cache_clear()
    yield
    secrets._get_secrets_client.cache_clear()


@pytest.fixture
def bedrock_runtime_client():
    client = MagicMock()
    client.invoke_model.return_value = {"body": BytesIO(json.dumps({"content": [{"text": '{"ok": true}'}]}).encode())}
    return client


@pytest.fixture
def dynamodb_table():
    table = MagicMock()
    table.get_item.return_value = {"Item": {"incident_id": "inc-1", "severity": "P2"}}
    return table


@pytest.fixture
def dynamodb_resource(dynamodb_table):
    resource = MagicMock()
    resource.Table.return_value = dynamodb_table
    return resource


@pytest.fixture
def secretsmanager_client():
    client = MagicMock()
    client.get_secret_value.return_value = {
        "SecretString": json.dumps(
            {
                "secret": "slack-signing-secret",
                "webhook_url": "https://hooks.slack.test/services/test",
            }
        )
    }
    return client


@pytest.fixture
def stepfunctions_client():
    client = MagicMock()
    client.start_execution.return_value = {"executionArn": "arn:aws:states:us-west-2:123456789012:execution:test:run"}
    return client


@pytest.fixture
def sqs_client():
    return MagicMock()


@pytest.fixture
def boto3_clients(monkeypatch, bedrock_runtime_client, secretsmanager_client, stepfunctions_client):
    clients = {
        "bedrock-runtime": bedrock_runtime_client,
        "secretsmanager": secretsmanager_client,
        "stepfunctions": stepfunctions_client,
        "sqs": MagicMock(),
    }

    def client(service_name, *args, **kwargs):
        return clients[service_name]

    monkeypatch.setattr("boto3.client", client)
    return clients


@pytest.fixture
def boto3_resources(monkeypatch, dynamodb_resource):
    resources = {"dynamodb": dynamodb_resource}

    def resource(service_name, *args, **kwargs):
        return resources[service_name]

    monkeypatch.setattr("boto3.resource", resource)
    return resources


@pytest.fixture
def aws_mocks(boto3_clients, boto3_resources):
    return {"clients": boto3_clients, "resources": boto3_resources}


@pytest.fixture
def context():
    ctx = MagicMock()
    ctx.aws_request_id = "request-1"
    return ctx
