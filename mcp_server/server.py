import hashlib
import json
import logging
import os
import re
import secrets
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import PurePosixPath
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
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


def capture_hubble_flows(
    pod_name: str,
    namespace: str,
    since_minutes: int = 5,
    max_flows: int = 2000,
    incident_id: str | None = None,
) -> dict:
    pod = CORE.read_namespaced_pod(name=pod_name, namespace=namespace)
    pod_ip = pod.status.pod_ip or "unknown"
    host_ip = pod.status.host_ip or "unknown"
    node_name = pod.spec.node_name or "unknown"

    endpoints: dict = {}
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

    flows_payload: dict | None = None
    flows_error: str | None = None
    try:
        flows_payload = _capture_hubble_flows(
            pod_namespace=namespace,
            pod_name=pod_name,
            since_minutes=int(since_minutes),
            max_flows=int(max_flows),
        )
    except Exception as error:
        flows_error = f"{type(error).__name__}: {error}"
        logger.warning("Hubble flow capture failed for %s/%s: %s", namespace, pod_name, flows_error)

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
            "hubble_flows": flows_payload,
            "hubble_error": flows_error,
        },
        incident_id=incident_id,
        kind="network_flow_snapshot",
    )
    flow_count = flows_payload.get("flow_count", 0) if isinstance(flows_payload, dict) else 0
    return _success(
        "capture_hubble_flows",
        pod=pod_name,
        namespace=namespace,
        pod_ip=pod_ip,
        node_name=node_name,
        endpoints_found=len(endpoints.get("items", [])),
        hubble_flow_count=flow_count,
        hubble_error=flows_error,
        evidence_uri=evidence["uri"],
        evidence_sha256=evidence["sha256"],
    )


def _capture_hubble_flows(pod_namespace: str, pod_name: str, since_minutes: int, max_flows: int) -> dict:
    from hubble_client import get_flows_for_pod

    return get_flows_for_pod(
        pod_namespace=pod_namespace,
        pod_name=pod_name,
        since_minutes=since_minutes,
        number=max_flows,
    )


DYNAMODB = boto3.resource("dynamodb", region_name=os.environ.get("AWS_REGION"))
LOGS = boto3.client("logs", region_name=os.environ.get("AWS_REGION"))
TETRAGON_EVENTS_TABLE = os.environ.get("TETRAGON_EVENTS_TABLE", "")
EKS_AUDIT_LOG_GROUP = os.environ.get("EKS_AUDIT_LOG_GROUP", "")


def collect_tetragon_timeline(
    pod_uid: str,
    since_minutes: int = 30,
    max_events: int = 500,
    incident_id: str | None = None,
) -> dict:
    if not TETRAGON_EVENTS_TABLE:
        return _failure("collect_tetragon_timeline", "TETRAGON_EVENTS_TABLE env not configured")

    table = DYNAMODB.Table(TETRAGON_EVENTS_TABLE)
    since = datetime.now(tz=UTC) - timedelta(minutes=int(since_minutes))
    since_iso = since.isoformat()

    events: list[dict] = []
    namespace = ""
    pod_name = ""
    last_key = None
    remaining = max(1, int(max_events))

    while True:
        kwargs = {
            "KeyConditionExpression": Key("pod_uid").eq(pod_uid) & Key("sk").gte(f"{since_iso}#"),
            "Limit": min(remaining, 100),
            "ScanIndexForward": True,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key

        page = table.query(**kwargs)
        for item in page.get("Items", []):
            namespace = namespace or item.get("namespace", "")
            pod_name = pod_name or item.get("pod_name", "")
            events.append(
                {
                    "recorded_at": item.get("recorded_at"),
                    "sort_key": item.get("sk"),
                    "namespace": item.get("namespace", ""),
                    "pod_name": item.get("pod_name", ""),
                    "container": item.get("container", ""),
                    "policy_name": item.get("policy_name", ""),
                    "function_name": item.get("function_name", ""),
                    "binary": item.get("binary", ""),
                    "arguments": item.get("arguments", ""),
                }
            )
        remaining = max(0, max_events - len(events))
        last_key = page.get("LastEvaluatedKey")
        if not last_key or remaining == 0:
            break

    payload = {
        "captured_at": datetime.now(tz=UTC).isoformat(),
        "kind": "tetragon_timeline",
        "incident_id": _sanitize_incident_id(incident_id),
        "pod_uid": pod_uid,
        "namespace": namespace,
        "pod_name": pod_name,
        "since": since_iso,
        "event_count": len(events),
        "events": events,
    }

    evidence: dict | None = None
    if incident_id:
        bucket, key = _forensics_destination("tetragon-timeline", pod_uid, incident_id)
        evidence = _put_forensics_json(
            bucket,
            key,
            payload,
            incident_id=incident_id,
            kind="tetragon_timeline",
        )

    return _success(
        "collect_tetragon_timeline",
        pod_uid=pod_uid,
        namespace=namespace,
        pod_name=pod_name,
        since=since_iso,
        event_count=len(events),
        evidence_uri=(evidence or {}).get("uri"),
        evidence_sha256=(evidence or {}).get("sha256"),
    )


_AUDIT_QUERY_TEMPLATE = (
    "fields @timestamp, @message, verb, objectRef.name, objectRef.namespace, "
    "objectRef.resource, user.username, sourceIPs.0, responseStatus.code\n"
    "| filter @logStream like /kube-apiserver-audit/\n"
    "| filter objectRef.namespace = '{namespace}' and objectRef.name = '{pod_name}'\n"
    "| sort @timestamp asc\n"
    "| limit {limit}"
)


def collect_audit_events(
    pod_name: str,
    namespace: str,
    since_minutes: int = 60,
    max_events: int = 500,
    incident_id: str | None = None,
    poll_timeout_seconds: int = 120,
) -> dict:
    if not EKS_AUDIT_LOG_GROUP:
        return _failure("collect_audit_events", "EKS_AUDIT_LOG_GROUP env not configured")

    safe_ns = _sanitize_audit_filter_value(namespace)
    safe_pod = _sanitize_audit_filter_value(pod_name)
    if not safe_ns or not safe_pod:
        return _failure("collect_audit_events", "namespace/pod_name contain unsafe characters")

    now = datetime.now(tz=UTC)
    since = now - timedelta(minutes=int(since_minutes))

    start_response = LOGS.start_query(
        logGroupName=EKS_AUDIT_LOG_GROUP,
        startTime=int(since.timestamp()),
        endTime=int(now.timestamp()),
        queryString=_AUDIT_QUERY_TEMPLATE.format(
            namespace=safe_ns,
            pod_name=safe_pod,
            limit=min(max(1, int(max_events)), 10000),
        ),
    )
    query_id = start_response["queryId"]

    final_status, results, statistics = _poll_logs_insights(query_id, poll_timeout_seconds)
    if final_status not in {"Complete"}:
        return _failure(
            "collect_audit_events",
            f"Logs Insights query ended with status {final_status}",
        )

    events = [{field["field"]: field["value"] for field in row if field.get("field") != "@ptr"} for row in results]

    payload = {
        "captured_at": now.isoformat(),
        "kind": "eks_audit_events",
        "incident_id": _sanitize_incident_id(incident_id),
        "namespace": namespace,
        "pod_name": pod_name,
        "log_group": EKS_AUDIT_LOG_GROUP,
        "since": since.isoformat(),
        "until": now.isoformat(),
        "event_count": len(events),
        "events": events,
        "statistics": statistics,
    }

    evidence: dict | None = None
    if incident_id:
        bucket, key = _forensics_destination("audit-events", pod_name, incident_id)
        evidence = _put_forensics_json(
            bucket,
            key,
            payload,
            incident_id=incident_id,
            kind="eks_audit_events",
        )

    return _success(
        "collect_audit_events",
        pod=pod_name,
        namespace=namespace,
        since=since.isoformat(),
        event_count=len(events),
        statistics=statistics,
        evidence_uri=(evidence or {}).get("uri"),
        evidence_sha256=(evidence or {}).get("sha256"),
    )


_AUDIT_FILTER_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")


def _sanitize_audit_filter_value(value: str) -> str:
    if value is None:
        return ""
    text = str(value)
    return text if _AUDIT_FILTER_SAFE.match(text) else ""


def _poll_logs_insights(query_id: str, timeout_seconds: int) -> tuple[str, list[list[dict]], dict]:
    import time as _time

    deadline = _time.time() + max(1, int(timeout_seconds))
    backoff = 0.5
    status = "Running"
    while _time.time() < deadline:
        resp = LOGS.get_query_results(queryId=query_id)
        status = resp.get("status", "Unknown")
        if status in {"Complete", "Failed", "Cancelled", "Timeout", "Unknown"}:
            return status, resp.get("results", []), resp.get("statistics", {})
        _time.sleep(backoff)
        backoff = min(backoff * 1.5, 5.0)

    try:
        LOGS.stop_query(queryId=query_id)
    except Exception as error:
        logger.warning("Failed to stop query %s after timeout: %s", query_id, error)
    return "Timeout", [], {}


LIVE_FORENSICS_PROFILES: dict[str, list[str]] = {
    "process_snapshot": [
        "sh",
        "-c",
        "ps auxf 2>/dev/null; echo ---; pstree -p 2>/dev/null; "
        "echo ---; ls -la /proc/1/fd 2>/dev/null; echo ---; cat /proc/1/status 2>/dev/null",
    ],
    "network_snapshot": [
        "sh",
        "-c",
        "ss -tunap 2>/dev/null; echo ---; ip route 2>/dev/null; "
        "echo ---; ip addr 2>/dev/null; echo ---; cat /proc/net/tcp 2>/dev/null | head -200",
    ],
    "filesystem_triage": [
        "sh",
        "-c",
        "ls -la / 2>/dev/null; echo ---; ls -la /tmp 2>/dev/null; "
        "echo ---; find /tmp -maxdepth 3 -type f -newer /etc/passwd 2>/dev/null | head -100; "
        "echo ---; find / -maxdepth 3 -perm -4000 -type f 2>/dev/null | head -50",
    ],
    "env_redacted": [
        "sh",
        "-c",
        "env 2>/dev/null | awk -F= 'BEGIN{IGNORECASE=1} "
        "{ key=$1; val=$2; if (key ~ /TOKEN|SECRET|PASSWORD|KEY|AUTH|CREDENTIAL/) "
        'print key"=[REDACTED]"; else print key"="val }\'',
    ],
}

LIVE_FORENSICS_IMAGE = os.environ.get("LIVE_FORENSICS_IMAGE", "busybox:1.37")
LIVE_FORENSICS_MAX_SECONDS = int(os.environ.get("LIVE_FORENSICS_MAX_SECONDS", "30"))

_K8S_DNS1123 = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


def _sanitize_k8s_dns_name(value: str) -> str:
    text = (value or "").lower()
    if not text or len(text) > 253 or not _K8S_DNS1123.match(text):
        return ""
    return text


def collect_live_pod_forensics(
    pod_name: str,
    namespace: str,
    profile: str = "process_snapshot",
    target_container: str | None = None,
    timeout_seconds: int | None = None,
    incident_id: str | None = None,
) -> dict:
    validation_error = _validate_live_forensics_inputs(pod_name, namespace, profile)
    if validation_error:
        return _failure("collect_live_pod_forensics", validation_error)

    safe_pod = _sanitize_k8s_dns_name(pod_name)
    safe_ns = _sanitize_k8s_dns_name(namespace)

    try:
        pod = CORE.read_namespaced_pod(name=safe_pod, namespace=safe_ns)
    except ApiException as error:
        return _failure("collect_live_pod_forensics", f"read_pod_failed: {error.reason}")

    selected_target = target_container or (pod.spec.containers[0].name if pod.spec.containers else "")
    if not selected_target:
        return _failure("collect_live_pod_forensics", "pod has no containers to target")

    debug_name = f"atdr-fx-{_hex_suffix()}"[:63]
    command = list(LIVE_FORENSICS_PROFILES[profile])
    max_secs = max(5, min(int(timeout_seconds or LIVE_FORENSICS_MAX_SECONDS), 120))

    inject_error = _inject_ephemeral_container(safe_pod, safe_ns, debug_name, command, selected_target)
    if inject_error:
        return _failure("collect_live_pod_forensics", inject_error)

    terminated, reason = _wait_for_ephemeral_container_exit(safe_pod, safe_ns, debug_name, max_secs)
    logs, logs_error = _read_ephemeral_container_logs(safe_pod, safe_ns, debug_name)

    payload = {
        "captured_at": datetime.now(tz=UTC).isoformat(),
        "kind": "live_pod_forensics",
        "incident_id": _sanitize_incident_id(incident_id),
        "pod_name": safe_pod,
        "namespace": safe_ns,
        "target_container": selected_target,
        "profile": profile,
        "debug_container_name": debug_name,
        "image": LIVE_FORENSICS_IMAGE,
        "command_sha256": hashlib.sha256(json.dumps(command).encode()).hexdigest(),
        "timeout_seconds": max_secs,
        "terminated": terminated,
        "exit_reason": reason,
        "logs_error": logs_error,
        "output": logs,
    }

    evidence: dict | None = None
    if incident_id:
        bucket, key = _forensics_destination(f"live-forensics/{profile}", safe_pod, incident_id)
        evidence = _put_forensics_json(
            bucket,
            key,
            payload,
            incident_id=incident_id,
            kind="live_pod_forensics",
        )

    return _success(
        "collect_live_pod_forensics",
        pod=safe_pod,
        namespace=safe_ns,
        target_container=selected_target,
        profile=profile,
        debug_container_name=debug_name,
        terminated=terminated,
        exit_reason=reason,
        output_bytes=len(logs),
        evidence_uri=(evidence or {}).get("uri"),
        evidence_sha256=(evidence or {}).get("sha256"),
    )


def _validate_live_forensics_inputs(pod_name: str, namespace: str, profile: str) -> str | None:
    if not _sanitize_k8s_dns_name(pod_name) or not _sanitize_k8s_dns_name(namespace):
        return "pod_name/namespace contain invalid K8s characters"
    if profile not in LIVE_FORENSICS_PROFILES:
        return f"unknown profile '{profile}'; allowed: {sorted(LIVE_FORENSICS_PROFILES)}"
    return None


def _inject_ephemeral_container(
    pod_name: str, namespace: str, debug_name: str, command: list[str], target_container: str
) -> str | None:
    ephemeral_container = {
        "name": debug_name,
        "image": LIVE_FORENSICS_IMAGE,
        "command": command,
        "targetContainerName": target_container,
        "imagePullPolicy": "IfNotPresent",
        "stdin": False,
        "tty": False,
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "runAsNonRoot": False,
            "capabilities": {"drop": ["ALL"]},
        },
    }
    try:
        CORE.patch_namespaced_pod_ephemeralcontainers(
            name=pod_name,
            namespace=namespace,
            body={"spec": {"ephemeralContainers": [ephemeral_container]}},
            _preload_content=False,
        )
    except ApiException as error:
        return f"inject_failed: {error.reason}"
    except AttributeError:
        return "ephemeral containers unsupported by this kubernetes client version"
    return None


def _read_ephemeral_container_logs(pod_name: str, namespace: str, container_name: str) -> tuple[str, str | None]:
    try:
        return CORE.read_namespaced_pod_log(name=pod_name, namespace=namespace, container=container_name), None
    except ApiException as error:
        logger.warning(
            "Failed to read logs for %s/%s container %s: %s", namespace, pod_name, container_name, error.reason
        )
        return "", f"log_fetch_failed: {error.reason}"


def _hex_suffix() -> str:
    return secrets.token_hex(6)


def _wait_for_ephemeral_container_exit(
    pod_name: str, namespace: str, container_name: str, timeout_seconds: int
) -> tuple[bool, str]:
    import time as _time

    deadline = _time.time() + timeout_seconds
    while _time.time() < deadline:
        try:
            pod = CORE.read_namespaced_pod(name=pod_name, namespace=namespace)
        except ApiException as error:
            return False, f"pod_read_failed:{error.reason}"

        statuses = pod.status.ephemeral_container_statuses or []
        for status in statuses:
            if status.name != container_name:
                continue
            state = status.state
            if state and getattr(state, "terminated", None):
                return True, getattr(state.terminated, "reason", "Completed") or "Completed"
        _time.sleep(0.5)

    return False, "watchdog_timeout"


TOOLS = {
    "label_pod": label_pod,
    "delete_pod": delete_pod,
    "apply_cilium_network_policy": apply_cilium_network_policy,
    "patch_deployment": patch_deployment,
    "cordon_node": cordon_node,
    "drain_node": drain_node,
    "checkpoint_pod": checkpoint_pod,
    "capture_hubble_flows": capture_hubble_flows,
    "collect_tetragon_timeline": collect_tetragon_timeline,
    "collect_audit_events": collect_audit_events,
    "collect_live_pod_forensics": collect_live_pod_forensics,
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
