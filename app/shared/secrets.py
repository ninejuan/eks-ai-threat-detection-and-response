import json
import logging
from functools import lru_cache

import boto3

logger = logging.getLogger(__name__)


@lru_cache(maxsize=8)
def _get_secrets_client():
    return boto3.client("secretsmanager")


def get_secret(secret_id: str) -> dict:
    client = _get_secrets_client()
    response = client.get_secret_value(SecretId=secret_id)
    return json.loads(response["SecretString"])
