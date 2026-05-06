import json
import logging

import boto3

logger = logging.getLogger(__name__)

FAST_MODEL_CHAIN = [
    "global.anthropic.claude-haiku-4-5-20251001-v1:0",
    "apac.anthropic.claude-3-5-sonnet-20241022-v2:0",
    "anthropic.claude-3-5-sonnet-20240620-v1:0",
]

SMART_MODEL_CHAIN = [
    "apac.anthropic.claude-sonnet-4-20250514-v1:0",
    "global.anthropic.claude-sonnet-4-6",
    "apac.anthropic.claude-3-5-sonnet-20241022-v2:0",
]


class BedrockClient:
    def __init__(self, model_id: str, region: str = "ap-northeast-2"):
        self._client = boto3.client("bedrock-runtime", region_name=region)
        self._model_id = model_id

    def invoke(self, system_prompt: str, user_message: str, max_tokens: int = 4096) -> str:
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_message}],
        }

        response = self._invoke_with_fallback(body)
        result = json.loads(response["body"].read())
        return result["content"][0]["text"]

    def invoke_with_tools(
        self,
        system_prompt: str,
        messages: list[dict],
        tools: list[dict],
        max_tokens: int = 4096,
    ) -> dict:
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "system": system_prompt,
            "messages": messages,
            "tools": tools,
        }

        response = self._invoke_with_fallback(body)
        return json.loads(response["body"].read())

    def _invoke_with_fallback(self, body: dict) -> dict:
        models = [self._model_id] if self._model_id else []
        if not models:
            models = SMART_MODEL_CHAIN

        last_error = None
        for model_id in models:
            try:
                return self._client.invoke_model(
                    modelId=model_id,
                    contentType="application/json",
                    accept="application/json",
                    body=json.dumps(body),
                )
            except self._client.exceptions.AccessDeniedException as error:
                logger.warning("Model %s access denied, trying next: %s", model_id, error)
                last_error = error
            except self._client.exceptions.ValidationException as error:
                logger.warning("Model %s validation error, trying next: %s", model_id, error)
                last_error = error

        raise last_error
