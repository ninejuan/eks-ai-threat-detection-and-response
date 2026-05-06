import hashlib
import json
import logging
import os
import re
import secrets
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import PurePosixPath
from typing import Any

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


_INCIDENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _sanitize_incident_id(incident_id: str | None) -> str:
    if incident_id and _INCIDENT_ID_RE.match(incident_id):
        return incident_id
    return "adhoc"


def _forensics_destination(prefix: str, resource_name: str, incident_id: str | None = None) -> tuple[str, str]:
    timestamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
    bundle_id = _sanitize_incident_id(incident_id)
    key_prefix = f"incidents/{bundle_id}/{prefix}/{resource_name}/{timestamp}"
    return FORENSICS_BUCKET, str(PurePosixPath(key_prefix) / "evidence.json")


_LABEL_VALUE_INVALID = re.compile(r"[^A-Za-z0-9._-]")


def _sanitize_label_value(value: object) -> str:
    text = str(value) if value is not None else ""
    cleaned = _LABEL_VALUE_INVALID.sub("-", text).strip("-._")[:63].strip("-._")
    return cleaned or "unknown"


def _put_forensics_object(bucket: str, key: str, body: bytes, content_type: str) -> tuple[str, str, int]:
    sha256 = hashlib.sha256(body).hexdigest()
    S3.put_object(
        Bucket=bucket,
        Key=key,
        Body=body,
        ContentType=content_type,
        Metadata={"sha256": sha256},
    )
    return f"s3://{bucket}/{key}", sha256, len(body)


def _put_forensics_json(
    bucket: str, key: str, payload: dict, incident_id: str | None = None, kind: str | None = None
) -> dict:
    body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    uri, sha256, size = _put_forensics_object(bucket, key, body, "application/json")
    _append_evidence_manifest(
        bucket=bucket,
        incident_id=_sanitize_incident_id(incident_id),
        item={
            "uri": uri,
            "key": key,
            "kind": kind or payload.get("kind", "unknown"),
            "sha256": sha256,
            "size_bytes": size,
            "captured_at": datetime.now(tz=UTC).isoformat(),
        },
    )
    return {"uri": uri, "sha256": sha256, "size_bytes": size}


def _append_evidence_manifest(bucket: str, incident_id: str, item: dict) -> None:
    timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%S%fZ")
    manifest_key = f"incidents/{incident_id}/manifest/{timestamp}.json"
    entry = {
        "incident_id": incident_id,
        "forensics_bucket": bucket,
        "recorded_at": datetime.now(tz=UTC).isoformat(),
        "evidence": [item],
    }
    body = json.dumps(entry, ensure_ascii=False).encode("utf-8")
    S3.put_object(
        Bucket=bucket,
        Key=manifest_key,
        Body=body,
        ContentType="application/json",
        Metadata={"incident-id": incident_id, "kind": "evidence-manifest-entry"},
    )


def _sanitize_k8s_object(value: object) -> object:
    return k8s_client.ApiClient().sanitize_for_serialization(value)


def label_pod(pod_name: str, namespace: str, labels: dict) -> dict:
    sanitized = {key: _sanitize_label_value(value) for key, value in labels.items()}
    CORE.patch_namespaced_pod(name=pod_name, namespace=namespace, body={"metadata": {"labels": sanitized}})
    return _success("label_pod", pod=pod_name, namespace=namespace, labels=sanitized)


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


def checkpoint_pod(
    pod_name: str, namespace: str, container_name: str | None = None, incident_id: str | None = None
) -> dict:
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

    bucket, key = _forensics_destination("checkpoints", pod_name, incident_id)
    evidence = _put_forensics_json(
        bucket,
        key,
        {
            "captured_at": datetime.now(tz=UTC).isoformat(),
            "kind": "pod_forensics_checkpoint",
            "incident_id": _sanitize_incident_id(incident_id),
            "pod": _sanitize_k8s_object(pod),
            "selected_container": selected_container,
            "logs": logs,
        },
        incident_id=incident_id,
        kind="pod_forensics_checkpoint",
    )
    return _success(
        "checkpoint_pod",
        pod=pod_name,
        namespace=namespace,
        container=selected_container,
        node=pod.spec.node_name,
        uid=pod.metadata.uid,
        evidence_uri=evidence["uri"],
        evidence_sha256=evidence["sha256"],
    )


def capture_hubble_flows(pod_name: str, namespace: str, incident_id: str | None = None) -> dict:
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

    bucket, key = _forensics_destination("network-evidence", pod_name, incident_id)
    evidence = _put_forensics_json(
        bucket,
        key,
        {
            "captured_at": datetime.now(tz=UTC).isoformat(),
            "kind": "network_flow_snapshot",
            "incident_id": _sanitize_incident_id(incident_id),
            "pod_name": pod_name,
            "namespace": namespace,
            "pod_ip": pod_ip,
            "host_ip": host_ip,
            "node_name": node_name,
            "cilium_endpoints": endpoints,
            "pod_labels": pod.metadata.labels or {},
        },
        incident_id=incident_id,
        kind="network_flow_snapshot",
    )
    return _success(
        "capture_hubble_flows",
        pod=pod_name,
        namespace=namespace,
        pod_ip=pod_ip,
        node_name=node_name,
        endpoints_found=len(endpoints.get("items", [])),
        evidence_uri=evidence["uri"],
        evidence_sha256=evidence["sha256"],
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
        except Exception as error:
            logger.exception("MCP tool %s raised an unexpected exception", tool_name)
            result = _failure(tool_name, f"{type(error).__name__}: {error}")

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
