import json
import logging
import os
from datetime import UTC, datetime

from kubernetes.client.rest import ApiException

from app.shared.kube_client import get_apps_v1, get_core_v1, get_custom_objects
from kubernetes import client as k8s_client

logger = logging.getLogger(__name__)

CLUSTER_NAME = os.environ.get("EKS_CLUSTER_NAME", "atdr-demo")
REGION = os.environ.get("AWS_REGION", "ap-northeast-2")


def label_pod(pod_name: str, namespace: str, labels: dict) -> dict:
    v1 = get_core_v1(CLUSTER_NAME, REGION)
    body = {"metadata": {"labels": labels}}

    try:
        v1.patch_namespaced_pod(name=pod_name, namespace=namespace, body=body)
        return {"status": "success", "action": "label_pod", "pod": pod_name, "labels": labels}
    except ApiException as e:
        logger.error("Failed to label pod %s: %s", pod_name, e.reason)
        return {"status": "failed", "action": "label_pod", "error": e.reason}


def delete_pod(pod_name: str, namespace: str, force: bool = True, grace_period_seconds: int = 0) -> dict:
    v1 = get_core_v1(CLUSTER_NAME, REGION)

    try:
        v1.delete_namespaced_pod(
            name=pod_name,
            namespace=namespace,
            grace_period_seconds=grace_period_seconds if force else None,
        )
        return {"status": "success", "action": "delete_pod", "pod": pod_name}
    except ApiException as e:
        logger.error("Failed to delete pod %s: %s", pod_name, e.reason)
        return {"status": "failed", "action": "delete_pod", "error": e.reason}


def apply_cilium_network_policy(
    policy_name: str,
    namespace: str,
    pod_selector: dict | None = None,
    deny_all: bool = True,
) -> dict:
    custom = get_custom_objects(CLUSTER_NAME, REGION)

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
        custom.create_namespaced_custom_object(
            group="cilium.io",
            version="v2",
            namespace=namespace,
            plural="ciliumnetworkpolicies",
            body=policy_body,
        )
        return {"status": "success", "action": "apply_cilium_network_policy", "policy": policy_name}
    except ApiException as e:
        if e.status == 409:
            custom.patch_namespaced_custom_object(
                group="cilium.io",
                version="v2",
                namespace=namespace,
                plural="ciliumnetworkpolicies",
                name=policy_name,
                body=policy_body,
            )
            return {
                "status": "success",
                "action": "apply_cilium_network_policy",
                "policy": policy_name,
                "updated": True,
            }
        logger.error("Failed to apply CNP %s: %s", policy_name, e.reason)
        return {"status": "failed", "action": "apply_cilium_network_policy", "error": e.reason}


def patch_deployment(deployment_name: str, namespace: str, replicas: int) -> dict:
    apps = get_apps_v1(CLUSTER_NAME, REGION)
    body = {"spec": {"replicas": replicas}}

    try:
        apps.patch_namespaced_deployment(name=deployment_name, namespace=namespace, body=body)
        return {"status": "success", "action": "patch_deployment", "deployment": deployment_name, "replicas": replicas}
    except ApiException as e:
        logger.error("Failed to patch deployment %s: %s", deployment_name, e.reason)
        return {"status": "failed", "action": "patch_deployment", "error": e.reason}


def cordon_node(node_name: str) -> dict:
    v1 = get_core_v1(CLUSTER_NAME, REGION)
    body = {"spec": {"unschedulable": True}}

    try:
        v1.patch_node(name=node_name, body=body)
        return {"status": "success", "action": "cordon_node", "node": node_name}
    except ApiException as e:
        logger.error("Failed to cordon node %s: %s", node_name, e.reason)
        return {"status": "failed", "action": "cordon_node", "error": e.reason}


def drain_node(node_name: str, ignore_daemonsets: bool = True) -> dict:
    v1 = get_core_v1(CLUSTER_NAME, REGION)

    try:
        v1.patch_node(name=node_name, body={"spec": {"unschedulable": True}})

        pods = v1.list_pod_for_all_namespaces(field_selector=f"spec.nodeName={node_name}")
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
                v1.create_namespaced_pod_eviction(
                    name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    body=eviction,
                )
                evicted.append(f"{pod.metadata.namespace}/{pod.metadata.name}")
            except ApiException:
                pass

        return {"status": "success", "action": "drain_node", "node": node_name, "evicted_pods": len(evicted)}
    except ApiException as e:
        logger.error("Failed to drain node %s: %s", node_name, e.reason)
        return {"status": "failed", "action": "drain_node", "error": e.reason}


def checkpoint_pod(pod_name: str, namespace: str, container_name: str | None = None, s3_destination: str = "") -> dict:
    v1 = get_core_v1(CLUSTER_NAME, REGION)

    try:
        pod = v1.read_namespaced_pod(name=pod_name, namespace=namespace)
        if not container_name:
            container_name = pod.spec.containers[0].name

        node_name = pod.spec.node_name
        pod_uid = pod.metadata.uid

        return {
            "status": "success",
            "action": "checkpoint_pod",
            "pod": pod_name,
            "container": container_name,
            "node": node_name,
            "uid": pod_uid,
            "s3_destination": s3_destination or f"s3://atdr-forensics/checkpoints/{pod_name}/{pod_uid}/",
            "note": "Checkpoint API requires kubelet direct access. Metadata captured for forensics.",
        }
    except ApiException as e:
        logger.error("Failed to checkpoint pod %s: %s", pod_name, e.reason)
        return {"status": "failed", "action": "checkpoint_pod", "error": e.reason}


def capture_hubble_flows(pod_name: str, namespace: str) -> dict:
    custom = get_custom_objects(CLUSTER_NAME, REGION)

    try:
        flows = custom.list_namespaced_custom_object(
            group="cilium.io",
            version="v1",
            namespace=namespace,
            plural="ciliumendpoints",
            label_selector=f"io.kubernetes.pod.name={pod_name}",
        )

        return {
            "status": "success",
            "action": "capture_hubble_flows",
            "pod": pod_name,
            "endpoints_found": len(flows.get("items", [])),
            "note": "Hubble flow capture requires Hubble Relay API. Endpoint metadata captured.",
        }
    except ApiException as e:
        logger.error("Failed to capture hubble flows for %s: %s", pod_name, e.reason)
        return {"status": "failed", "action": "capture_hubble_flows", "error": e.reason}


TOOL_REGISTRY = {
    "label_pod": label_pod,
    "delete_pod": delete_pod,
    "apply_cilium_network_policy": apply_cilium_network_policy,
    "patch_deployment": patch_deployment,
    "cordon_node": cordon_node,
    "drain_node": drain_node,
    "checkpoint_pod": checkpoint_pod,
    "capture_hubble_flows": capture_hubble_flows,
}


def execute_tool(tool_name: str, tool_input: dict) -> dict:
    tool_fn = TOOL_REGISTRY.get(tool_name)
    if not tool_fn:
        return {"status": "failed", "error": f"Unknown tool: {tool_name}"}

    logger.info("Executing tool: %s with input: %s", tool_name, json.dumps(tool_input))
    return tool_fn(**tool_input)
