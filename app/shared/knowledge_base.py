import logging

import boto3

logger = logging.getLogger(__name__)


class KnowledgeBaseClient:
    def __init__(self, knowledge_base_id: str, region: str = "ap-northeast-2"):
        self._client = boto3.client("bedrock-agent-runtime", region_name=region)
        self._kb_id = knowledge_base_id

    def retrieve(self, query: str, max_results: int = 5) -> list[dict]:
        if not self._kb_id:
            logger.warning("Knowledge Base ID not configured, skipping retrieval")
            return []

        try:
            response = self._client.retrieve(
                knowledgeBaseId=self._kb_id,
                retrievalQuery={"text": query},
                retrievalConfiguration={
                    "vectorSearchConfiguration": {
                        "numberOfResults": max_results,
                    }
                },
            )

            results = []
            for result in response.get("retrievalResults", []):
                results.append(
                    {
                        "content": result.get("content", {}).get("text", ""),
                        "source": result.get("location", {}).get("s3Location", {}).get("uri", ""),
                        "score": result.get("score", 0.0),
                    }
                )

            return results
        except Exception:
            logger.exception("Knowledge Base retrieval failed")
            return []

    def retrieve_and_generate(self, query: str, model_arn: str) -> str:
        if not self._kb_id:
            return ""

        try:
            response = self._client.retrieve_and_generate(
                input={"text": query},
                retrieveAndGenerateConfiguration={
                    "type": "KNOWLEDGE_BASE",
                    "knowledgeBaseConfiguration": {
                        "knowledgeBaseId": self._kb_id,
                        "modelArn": model_arn,
                    },
                },
            )

            return response.get("output", {}).get("text", "")
        except Exception:
            logger.exception("RetrieveAndGenerate failed")
            return ""
