import json
import logging
import os
import secrets
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

import boto3
from kubernetes.client.rest import ApiException

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("atdr-remediation-mcp")

AUTH_TOKEN = os.environ["MCP_AUTH_TOKEN"]
PORT = int(os.environ.get("MCP_PORT", "8080"))
FORENSICS_BUCKET = os.environ["FORENSICS_BUCKET"]

k8s_config.load_incluster_config()
CORE = k8s_client.CoreV1Api()
APPS = k8s_client.AppsV1Api()
CUSTOM = k8s_client.CustomObjectsApi()
S3 = boto3.client("s3")


def _success(action: str, **values) -> dict:
    return {"status": "success", "action": action, **values}


def _failure(action: str, error: str) -> dict:
    return {"status": "failed", "action": action, "error": error}


def _forensics_destination(prefix: str, resource_name: str, requested_destination: str = "") -> tuple[str, str]:
    if requested_destination:
        parsed = urlparse(requested_destination)
        if parsed.scheme != "s3" or not parsed.netloc:
            raise ValueError("s3_destination must be an s3://bucket/key-prefix URI")
        bucket = parsed.netloc
        key_prefix = parsed.path.strip("/")
    else:
        bucket = FORENSICS_BUCKET
        key_prefix = f"{prefix}/{resource_name}/{datetime.now(tz=UTC).strftime('%Y%m%d-%H%M%S')}"
    return bucket, str(PurePosixPath(key_prefix) / "evidence.json")


def _put_forensics_json(bucket: str, key: str, payload: dict) -> str:
    S3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"),
        ContentType="application/json",
    )
    return f"s3://{bucket}/{key}"


def _sanitize_k8s_object(value: object) -> object:
    return k8s_client.ApiClient().sanitize_for_serialization(value)


def label_pod(pod_name: str, namespace: str, labels: dict) -> dict:
    CORE.patch_namespaced_pod(name=pod_name, namespace=namespace, body={"metadata": {"labels": labels}})
    return _success("label_pod", pod=pod_name, namespace=namespace, labels=labels)


def delete_pod(pod_name: str, namespace: str, force: bool = True, grace_period_seconds: int = 0) -> dict:
    CORE.delete_namespaced_pod(
        name=pod_name,
        namespace=namespace,
        grace_period_seconds=grace_period_seconds if force else None,
    )
    return _success("delete_pod", pod=pod_name, namespace=namespace)


def apply_cilium_network_policy(
    policy_name: str,
    namespace: str,
    pod_selector: dict | None = None,
    deny_all: bool = True,
) -> dict:
    policy_body = {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": policy_name,
            "namespace": namespace,
            "labels": {
                "atdr.juany.dev/managed": "true",
                "atdr.juany.dev/created-at": datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S"),
            },
        },
        "spec": {
            "endpointSelector": {"matchLabels": pod_selector or {"security.incident/compromised": "true"}},
        },
    }

    if deny_all:
        policy_body["spec"]["ingressDeny"] = [{"fromEndpoints": [{"matchLabels": {}}]}]
        policy_body["spec"]["egressDeny"] = [{"toEndpoints": [{"matchLabels": {}}]}]

    try:
        CUSTOM.create_namespaced_custom_object(
            group="cilium.io",
            version="v2",
            namespace=namespace,
            plural="ciliumnetworkpolicies",
            body=policy_body,
        )
        return _success("apply_cilium_network_policy", policy=policy_name, namespace=namespace)
    except ApiException as error:
        if error.status != 409:
            raise
        CUSTOM.patch_namespaced_custom_object(
            group="cilium.io",
            version="v2",
            namespace=namespace,
            plural="ciliumnetworkpolicies",
            name=policy_name,
            body=policy_body,
        )
        return _success("apply_cilium_network_policy", policy=policy_name, namespace=namespace, updated=True)


def patch_deployment(deployment_name: str, namespace: str, replicas: int) -> dict:
    APPS.patch_namespaced_deployment(name=deployment_name, namespace=namespace, body={"spec": {"replicas": replicas}})
    return _success("patch_deployment", deployment=deployment_name, namespace=namespace, replicas=replicas)


def cordon_node(node_name: str) -> dict:
    CORE.patch_node(name=node_name, body={"spec": {"unschedulable": True}})
    return _success("cordon_node", node=node_name)


def drain_node(node_name: str, ignore_daemonsets: bool = True) -> dict:
    CORE.patch_node(name=node_name, body={"spec": {"unschedulable": True}})
    pods = CORE.list_pod_for_all_namespaces(field_selector=f"spec.nodeName={node_name}")
    evicted = []

    for pod in pods.items:
        if (
            ignore_daemonsets
            and pod.metadata.owner_references
            and any(ref.kind == "DaemonSet" for ref in pod.metadata.owner_references)
        ):
            continue

        eviction = k8s_client.V1Eviction(
            metadata=k8s_client.V1ObjectMeta(name=pod.metadata.name, namespace=pod.metadata.namespace),
            delete_options=k8s_client.V1DeleteOptions(grace_period_seconds=30),
        )
        try:
            CORE.create_namespaced_pod_eviction(
                name=pod.metadata.name,
                namespace=pod.metadata.namespace,
                body=eviction,
            )
            evicted.append(f"{pod.metadata.namespace}/{pod.metadata.name}")
        except ApiException as error:
            logger.warning("Skipping eviction for %s/%s: %s", pod.metadata.namespace, pod.metadata.name, error.reason)

    return _success("drain_node", node=node_name, evicted_pods=len(evicted))


def checkpoint_pod(pod_name: str, namespace: str, container_name: str | None = None, s3_destination: str = "") -> dict:
    pod = CORE.read_namespaced_pod(name=pod_name, namespace=namespace)
    selected_container = container_name or pod.spec.containers[0].name
    logs = {}
    for container in pod.spec.containers:
        try:
            logs[container.name] = CORE.read_namespaced_pod_log(
                name=pod_name,
                namespace=namespace,
                container=container.name,
                tail_lines=500,
                timestamps=True,
            )
        except ApiException as error:
            logs[container.name] = f"log capture failed: {error.reason}"

    bucket, key = _forensics_destination("checkpoints", pod_name, s3_destination)
    evidence_uri = _put_forensics_json(
        bucket,
        key,
        {
            "captured_at": datetime.now(tz=UTC).isoformat(),
            "kind": "pod_forensics_checkpoint",
            "pod": _sanitize_k8s_object(pod),
            "selected_container": selected_container,
            "logs": logs,
        },
    )
    return _success(
        "checkpoint_pod",
        pod=pod_name,
        namespace=namespace,
        container=selected_container,
        node=pod.spec.node_name,
        uid=pod.metadata.uid,
        evidence_uri=evidence_uri,
    )


def capture_hubble_flows(pod_name: str, namespace: str, s3_destination: str = "") -> dict:
    pod = CORE.read_namespaced_pod(name=pod_name, namespace=namespace)
    pod_ip = pod.status.pod_ip or "unknown"
    host_ip = pod.status.host_ip or "unknown"
    node_name = pod.spec.node_name or "unknown"

    endpoints = {}
    try:
        endpoints = CUSTOM.list_namespaced_custom_object(
            group="cilium.io",
            version="v2",
            namespace=namespace,
            plural="ciliumendpoints",
            label_selector=f"io.kubernetes.pod.name={pod_name}",
        )
    except ApiException:
        endpoints = {"items": [], "note": "CiliumEndpoints not available (ENI mode)"}

    bucket, key = _forensics_destination("network-evidence", pod_name, s3_destination)
    evidence_uri = _put_forensics_json(
        bucket,
        key,
        {
            "captured_at": datetime.now(tz=UTC).isoformat(),
            "kind": "network_flow_snapshot",
            "pod_name": pod_name,
            "namespace": namespace,
            "pod_ip": pod_ip,
            "host_ip": host_ip,
            "node_name": node_name,
            "cilium_endpoints": endpoints,
            "pod_labels": pod.metadata.labels or {},
        },
    )
    return _success(
        "capture_hubble_flows",
        pod=pod_name,
        namespace=namespace,
        pod_ip=pod_ip,
        node_name=node_name,
        endpoints_found=len(endpoints.get("items", [])),
        evidence_uri=evidence_uri,
    )


TOOLS = {
    "label_pod": label_pod,
    "delete_pod": delete_pod,
    "apply_cilium_network_policy": apply_cilium_network_policy,
    "patch_deployment": patch_deployment,
    "cordon_node": cordon_node,
    "drain_node": drain_node,
    "checkpoint_pod": checkpoint_pod,
    "capture_hubble_flows": capture_hubble_flows,
}


class McpHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send_json(200, {"status": "ok"})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/mcp":
            self._send_json(404, {"error": "not found"})
            return
        if not self._authorized():
            self._send_json(401, {"error": "unauthorized"})
            return

        try:
            request = self._read_json()
            response = self._handle_jsonrpc(request)
        except json.JSONDecodeError:
            self._send_json(400, self._error_response(None, -32700, "Parse error"))
            return
        except (TypeError, ValueError) as error:
            self._send_json(400, self._error_response(None, -32600, str(error)))
            return

        self._send_json(200, response)

    def _authorized(self) -> bool:
        value = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not value.startswith(prefix):
            return False
        return secrets.compare_digest(value.removeprefix(prefix), AUTH_TOKEN)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        data = json.loads(body)
        if not isinstance(data, dict):
            raise TypeError("JSON-RPC request must be an object")
        return data

    def _handle_jsonrpc(self, request: dict) -> dict:
        request_id = request.get("id")
        method = request.get("method")

        if method == "initialize":
            return self._initialize_response(request_id)

        if method == "tools/list":
            return self._tools_list_response(request_id)

        if method != "tools/call":
            return self._error_response(request_id, -32601, f"Unsupported method: {method}")

        return self._tools_call_response(request_id, request.get("params"))

    @staticmethod
    def _initialize_response(request_id: object) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "atdr-remediation-mcp", "version": "1.0.0"},
                "capabilities": {"tools": {}},
            },
        }

    @staticmethod
    def _tools_list_response(request_id: object) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"tools": [{"name": name} for name in sorted(TOOLS)]},
        }

    def _tools_call_response(self, request_id: object, params: Any) -> dict:
        if not isinstance(params, dict):
            return self._error_response(request_id, -32602, "params must be an object")

        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(tool_name, str) or tool_name not in TOOLS:
            return self._error_response(request_id, -32602, f"Unknown tool: {tool_name}")
        if not isinstance(arguments, dict):
            return self._error_response(request_id, -32602, "arguments must be an object")

        try:
            result = TOOLS[tool_name](**arguments)
        except ApiException as error:
            result = _failure(tool_name, error.reason or str(error))
        except TypeError as error:
            return self._error_response(request_id, -32602, str(error))

        logger.info("MCP tool executed: %s status=%s", tool_name, result.get("status"))
        return {"jsonrpc": "2.0", "id": request_id, "result": {"structuredContent": result}}

    @staticmethod
    def _error_response(request_id: object, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}

    def _send_json(self, status_code: int, payload: dict) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, message_format: str, *args) -> None:
        logger.info(message_format, *args)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), McpHandler)  # noqa: S104
    logger.info("ATDR remediation MCP server listening on port %s", PORT)
    server.serve_forever()
