from dataclasses import FrozenInstanceError

import pytest

from app.shared.config import Config


def test_config_reads_environment_variables():
    config = Config()

    assert config.project == "test-atdr"
    assert config.region == "us-west-2"
    assert config.log_level == "DEBUG"
    assert config.agent_type == "summary"
    assert config.bedrock_model_id == "anthropic.test-model"
    assert config.state_machine_arn.endswith("stateMachine:test")


def test_config_uses_defaults_when_env_missing(monkeypatch):
    for key in ("PROJECT", "AWS_REGION", "LOG_LEVEL", "AGENT_TYPE", "BEDROCK_MODEL_ID"):
        monkeypatch.delenv(key, raising=False)

    config = Config()

    assert config.project == "atdr"
    assert config.region == "ap-northeast-2"
    assert config.log_level == "INFO"
    assert config.agent_type == ""
    assert config.bedrock_model_id == ""


def test_config_is_frozen():
    config = Config()

    with pytest.raises(FrozenInstanceError):
        config.project = "changed"


def test_config_reads_optional_env_values():
    config = Config()

    assert config.opensearch_endpoint == "https://opensearch.test"
    assert config.knowledge_base_id == "kb-test"
    assert config.dynamodb_table_name == "test-incidents"
    assert config.mcp_server_url == "http://mcp.internal/mcp"
    assert config.mcp_auth_secret_id == "test/mcp/auth-token"
    assert config.mcp_server_url_secret_id == "test/mcp/server-url"
    assert config.mcp_timeout_seconds == 3
