import base64
import logging
from functools import lru_cache

import boto3
from botocore.signers import RequestSigner

from kubernetes import client as k8s_client

logger = logging.getLogger(__name__)

STS_TOKEN_EXPIRES_IN = 60
CLUSTER_CACHE_KEY = "cluster_info"


@lru_cache(maxsize=1)
def _get_cluster_info(cluster_name: str, region: str) -> dict:
    eks = boto3.client("eks", region_name=region)
    response = eks.describe_cluster(name=cluster_name)
    cluster = response["cluster"]
    return {
        "endpoint": cluster["endpoint"],
        "ca_data": cluster["certificateAuthority"]["data"],
    }


def _get_bearer_token(cluster_name: str, region: str) -> str:
    session = boto3.Session()
    sts = session.client("sts", region_name=region)
    service_id = sts.meta.service_model.service_id

    signer = RequestSigner(service_id, region, "sts", "v4", session.get_credentials(), session.events)

    params = {
        "method": "GET",
        "url": f"https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
        "body": {},
        "headers": {"x-k8s-aws-id": cluster_name},
        "context": {},
    }

    signed_url = signer.generate_presigned_url(
        params,
        region_name=region,
        expires_in=STS_TOKEN_EXPIRES_IN,
        operation_name="",
    )

    return "k8s-aws-v1." + base64.urlsafe_b64encode(signed_url.encode("utf-8")).decode("utf-8").rstrip("=")


def get_k8s_client(cluster_name: str, region: str) -> k8s_client.ApiClient:
    cluster_info = _get_cluster_info(cluster_name, region)

    configuration = k8s_client.Configuration()
    configuration.host = cluster_info["endpoint"]
    configuration.api_key["authorization"] = _get_bearer_token(cluster_name, region)
    configuration.api_key_prefix["authorization"] = "Bearer"

    ca_cert_path = "/tmp/eks-ca.crt"  # noqa: S108
    with open(ca_cert_path, "w") as f:
        f.write(base64.b64decode(cluster_info["ca_data"]).decode("utf-8"))
    configuration.ssl_ca_cert = ca_cert_path

    return k8s_client.ApiClient(configuration)


def get_core_v1(cluster_name: str, region: str) -> k8s_client.CoreV1Api:
    return k8s_client.CoreV1Api(get_k8s_client(cluster_name, region))


def get_apps_v1(cluster_name: str, region: str) -> k8s_client.AppsV1Api:
    return k8s_client.AppsV1Api(get_k8s_client(cluster_name, region))


def get_custom_objects(cluster_name: str, region: str) -> k8s_client.CustomObjectsApi:
    return k8s_client.CustomObjectsApi(get_k8s_client(cluster_name, region))
