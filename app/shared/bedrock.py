import json
import logging

import boto3

logger = logging.getLogger(__name__)


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

        response = self._client.invoke_model(
            modelId=self._model_id,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(body),
        )

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

        response = self._client.invoke_model(
            modelId=self._model_id,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(body),
        )

        return json.loads(response["body"].read())
