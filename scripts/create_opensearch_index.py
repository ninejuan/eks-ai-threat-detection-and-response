import os
import sys
import time

import boto3
import requests
from requests_aws4auth import AWS4Auth


def main() -> int:
    endpoint = os.environ["OPENSEARCH_ENDPOINT"]
    index_name = os.environ["OPENSEARCH_INDEX_NAME"]
    region = os.environ.get("AWS_REGION", "ap-northeast-2")

    session = boto3.Session(region_name=region)
    credentials = session.get_credentials().get_frozen_credentials()
    auth = AWS4Auth(
        credentials.access_key,
        credentials.secret_key,
        region,
        "aoss",
        session_token=credentials.token,
    )

    body = {
        "settings": {"index": {"knn": True}},
        "mappings": {
            "properties": {
                "bedrock-vector": {
                    "type": "knn_vector",
                    "dimension": 1024,
                    "method": {"name": "hnsw", "engine": "faiss", "space_type": "l2"},
                },
                "AMAZON_BEDROCK_TEXT_CHUNK": {"type": "text"},
                "AMAZON_BEDROCK_METADATA": {"type": "text", "index": False},
            }
        },
    }

    url = f"{endpoint}/{index_name}"

    for attempt in range(1, 25):
        response = requests.put(url, json=body, auth=auth, timeout=30)

        if response.status_code in {200, 201}:
            print(response.text)
            return 0
        if response.status_code == 400 and "resource_already_exists_exception" in response.text:
            print(response.text)
            return 0
        if response.status_code == 403 and attempt < 24:
            print(f"OpenSearch access policy not propagated yet; retrying ({attempt}/24)", file=sys.stderr)
            time.sleep(15)
            continue

        print(response.text, file=sys.stderr)
        return 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
