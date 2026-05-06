import importlib
import json
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest


@pytest.fixture
def server_module(monkeypatch):
    monkeypatch.setenv("MCP_AUTH_TOKEN", "test-token")
    monkeypatch.setenv("FORENSICS_BUCKET", "atdr-forensics-test")
    sys.modules.pop("mcp_server.server", None)

    with (
        patch("kubernetes.config.load_incluster_config"),
        patch("kubernetes.client.CoreV1Api"),
        patch("kubernetes.client.AppsV1Api"),
        patch("kubernetes.client.CustomObjectsApi"),
        patch("boto3.client"),
    ):
        module = importlib.import_module("mcp_server.server")

    yield module
    sys.modules.pop("mcp_server.server", None)


def test_forensics_destination_uses_server_owned_bucket(server_module):
    bucket, key = server_module._forensics_destination("checkpoints", "pod-a")

    assert bucket == "atdr-forensics-test"
    assert key.startswith("checkpoints/pod-a/")
    assert key.endswith("/evidence.json")


def test_sanitize_label_value_replaces_invalid_chars(server_module):
    assert server_module._sanitize_label_value("2026-05-06T18:37:25Z") == "2026-05-06T18-37-25Z"
    assert server_module._sanitize_label_value("inc-20260506-183725-falco") == "inc-20260506-183725-falco"
    assert server_module._sanitize_label_value("") == "unknown"
    assert server_module._sanitize_label_value(None) == "unknown"
    assert server_module._sanitize_label_value("-.only-punct.-") == "only-punct"
    assert len(server_module._sanitize_label_value("x" * 200)) == 63


def test_label_pod_sanitizes_values_before_patch(server_module, monkeypatch):
    captured = {}

    class CoreApi:
        def patch_namespaced_pod(self, name, namespace, body):
            captured["name"] = name
            captured["namespace"] = namespace
            captured["body"] = body

    monkeypatch.setattr(server_module, "CORE", CoreApi())

    result = server_module.label_pod(
        "pod-a",
        "default",
        {
            "security.incident/id": "inc-20260506-183725-falco",
            "security.incident/compromised": "true",
            "security.incident/timestamp": "2026-05-06T18:37:25Z",
        },
    )

    assert result["status"] == "success"
    labels = captured["body"]["metadata"]["labels"]
    assert labels["security.incident/timestamp"] == "2026-05-06T18-37-25Z"
    assert labels["security.incident/id"] == "inc-20260506-183725-falco"
    assert ":" not in labels["security.incident/timestamp"]


def test_checkpoint_pod_writes_forensics_evidence(server_module, monkeypatch):
    pod = SimpleNamespace(
        spec=SimpleNamespace(containers=[SimpleNamespace(name="app")], node_name="node-a"),
        metadata=SimpleNamespace(uid="uid-123"),
    )
    captured = {}

    class CoreApi:
        def read_namespaced_pod(self, name, namespace):
            assert (name, namespace) == ("pod-a", "default")
            return pod

        def read_namespaced_pod_log(self, name, namespace, container, tail_lines, timestamps):
            assert (name, namespace, tail_lines, timestamps) == ("pod-a", "default", 500, True)
            return f"logs:{container}"

    class S3Client:
        def put_object(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(server_module, "CORE", CoreApi())
    monkeypatch.setattr(server_module, "S3", S3Client())
    monkeypatch.setattr(server_module, "_sanitize_k8s_object", lambda value: {"uid": value.metadata.uid})

    result = server_module.checkpoint_pod("pod-a", "default")

    assert result["status"] == "success"
    assert result["pod"] == "pod-a"
    assert result["evidence_uri"].startswith("s3://atdr-forensics-test/checkpoints/pod-a/")
    assert captured["Bucket"] == "atdr-forensics-test"
    assert captured["Key"].startswith("checkpoints/pod-a/")

    payload = json.loads(captured["Body"].decode("utf-8"))
    assert payload["kind"] == "pod_forensics_checkpoint"
    assert payload["pod"] == {"uid": "uid-123"}
    assert payload["logs"] == {"app": "logs:app"}


def test_capture_hubble_flows_writes_forensics_evidence(server_module, monkeypatch):
    pod = SimpleNamespace(
        spec=SimpleNamespace(node_name="node-a"),
        status=SimpleNamespace(pod_ip="10.0.0.5", host_ip="10.0.0.1"),
        metadata=SimpleNamespace(labels={"run": "attacker"}),
    )
    captured = {}

    class CoreApi:
        def read_namespaced_pod(self, name, namespace):
            assert (name, namespace) == ("pod-a", "default")
            return pod

    class CustomApi:
        def list_namespaced_custom_object(self, **kwargs):
            assert kwargs["namespace"] == "default"
            assert kwargs["label_selector"] == "io.kubernetes.pod.name=pod-a"
            return {"items": [{"metadata": {"name": "endpoint-a"}}]}

    class S3Client:
        def put_object(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(server_module, "CORE", CoreApi())
    monkeypatch.setattr(server_module, "CUSTOM", CustomApi())
    monkeypatch.setattr(server_module, "S3", S3Client())

    result = server_module.capture_hubble_flows("pod-a", "default")

    assert result["status"] == "success"
    assert result["endpoints_found"] == 1
    assert result["evidence_uri"].startswith("s3://atdr-forensics-test/network-evidence/pod-a/")
    assert captured["Bucket"] == "atdr-forensics-test"
    assert captured["Key"].startswith("network-evidence/pod-a/")

    payload = json.loads(captured["Body"].decode("utf-8"))
    assert payload["kind"] == "network_flow_snapshot"
    assert payload["pod_name"] == "pod-a"
    assert payload["pod_ip"] == "10.0.0.5"
    assert payload["cilium_endpoints"]["items"][0]["metadata"]["name"] == "endpoint-a"
