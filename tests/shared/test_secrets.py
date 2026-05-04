import json

from app.shared.secrets import _get_secrets_client, get_secret


def test_get_secret_returns_decoded_secret(aws_mocks):
    result = get_secret("test-atdr/slack/signing-secret")

    assert result["secret"] == "slack-signing-secret"
    aws_mocks["clients"]["secretsmanager"].get_secret_value.assert_called_once_with(
        SecretId="test-atdr/slack/signing-secret"
    )


def test_get_secret_handles_webhook_secret(aws_mocks):
    aws_mocks["clients"]["secretsmanager"].get_secret_value.return_value = {
        "SecretString": json.dumps({"webhook_url": "https://hook"})
    }

    assert get_secret("test-atdr/slack/bot-token") == {"webhook_url": "https://hook"}


def test_get_secrets_client_is_cached(aws_mocks):
    first = _get_secrets_client()
    second = _get_secrets_client()

    assert first is second
    assert aws_mocks["clients"]["secretsmanager"] is first
