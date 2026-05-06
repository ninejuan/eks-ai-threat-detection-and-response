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
    assert key.startswith("incidents/adhoc/checkpoints/pod-a/")
    assert key.endswith("/evidence.json")


def test_forensics_destination_uses_sanitized_incident_id(server_module):
    bucket, key = server_module._forensics_destination("checkpoints", "pod-a", "inc-2026-05-07-falco")

    assert bucket == "atdr-forensics-test"
    assert key.startswith("incidents/inc-2026-05-07-falco/checkpoints/pod-a/")


def test_forensics_destination_rejects_unsafe_incident_id(server_module):
    _, key = server_module._forensics_destination("checkpoints", "pod-a", "../../evil")
    assert key.startswith("incidents/adhoc/")
    _, key2 = server_module._forensics_destination("checkpoints", "pod-a", "")
    assert key2.startswith("incidents/adhoc/")


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
    put_calls = []

    class CoreApi:
        def read_namespaced_pod(self, name, namespace):
            assert (name, namespace) == ("pod-a", "default")
            return pod

        def read_namespaced_pod_log(self, name, namespace, container, tail_lines, timestamps):
            assert (name, namespace, tail_lines, timestamps) == ("pod-a", "default", 500, True)
            return f"logs:{container}"

    class S3Client:
        def put_object(self, **kwargs):
            put_calls.append(kwargs)

    monkeypatch.setattr(server_module, "CORE", CoreApi())
    monkeypatch.setattr(server_module, "S3", S3Client())
    monkeypatch.setattr(server_module, "_sanitize_k8s_object", lambda value: {"uid": value.metadata.uid})

    result = server_module.checkpoint_pod("pod-a", "default", incident_id="inc-2026-abc")

    assert result["status"] == "success"
    assert result["pod"] == "pod-a"
    assert result["evidence_uri"].startswith("s3://atdr-forensics-test/incidents/inc-2026-abc/checkpoints/pod-a/")
    assert "evidence_sha256" in result
    assert len(result["evidence_sha256"]) == 64

    evidence_call = next(call for call in put_calls if "/evidence.json" in call["Key"])
    manifest_call = next(call for call in put_calls if "/manifest/" in call["Key"])
    assert evidence_call["Bucket"] == "atdr-forensics-test"
    assert evidence_call["Metadata"]["sha256"] == result["evidence_sha256"]
    assert manifest_call["Bucket"] == "atdr-forensics-test"
    assert manifest_call["Metadata"]["incident-id"] == "inc-2026-abc"

    payload = json.loads(evidence_call["Body"].decode("utf-8"))
    assert payload["kind"] == "pod_forensics_checkpoint"
    assert payload["incident_id"] == "inc-2026-abc"
    assert payload["pod"] == {"uid": "uid-123"}
    assert payload["logs"] == {"app": "logs:app"}

    manifest_entry = json.loads(manifest_call["Body"].decode("utf-8"))
    assert manifest_entry["incident_id"] == "inc-2026-abc"
    assert manifest_entry["evidence"][0]["kind"] == "pod_forensics_checkpoint"
    assert manifest_entry["evidence"][0]["sha256"] == result["evidence_sha256"]
    assert manifest_entry["evidence"][0]["uri"] == result["evidence_uri"]


def test_capture_hubble_flows_writes_forensics_evidence(server_module, monkeypatch):
    pod = SimpleNamespace(
        spec=SimpleNamespace(node_name="node-a"),
        status=SimpleNamespace(pod_ip="10.0.0.5", host_ip="10.0.0.1"),
        metadata=SimpleNamespace(labels={"run": "attacker"}),
    )
    put_calls = []

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
            put_calls.append(kwargs)

    monkeypatch.setattr(server_module, "CORE", CoreApi())
    monkeypatch.setattr(server_module, "CUSTOM", CustomApi())
    monkeypatch.setattr(server_module, "S3", S3Client())

    result = server_module.capture_hubble_flows("pod-a", "default", incident_id="inc-2026-xyz")

    assert result["status"] == "success"
    assert result["endpoints_found"] == 1
    assert result["evidence_uri"].startswith("s3://atdr-forensics-test/incidents/inc-2026-xyz/network-evidence/pod-a/")
    assert "evidence_sha256" in result

    evidence_call = next(call for call in put_calls if "/evidence.json" in call["Key"])
    manifest_call = next(call for call in put_calls if "/manifest/" in call["Key"])

    payload = json.loads(evidence_call["Body"].decode("utf-8"))
    assert payload["kind"] == "network_flow_snapshot"
    assert payload["incident_id"] == "inc-2026-xyz"
    assert payload["pod_name"] == "pod-a"
    assert payload["pod_ip"] == "10.0.0.5"
    assert payload["cilium_endpoints"]["items"][0]["metadata"]["name"] == "endpoint-a"

    manifest_entry = json.loads(manifest_call["Body"].decode("utf-8"))
    assert manifest_entry["evidence"][0]["kind"] == "network_flow_snapshot"
    assert manifest_entry["evidence"][0]["sha256"] == result["evidence_sha256"]


def test_put_forensics_object_returns_sha256(server_module, monkeypatch):
    put_calls = []

    class S3Client:
        def put_object(self, **kwargs):
            put_calls.append(kwargs)

    monkeypatch.setattr(server_module, "S3", S3Client())

    payload = b"hello forensic world"
    uri, sha256, size = server_module._put_forensics_object(
        "atdr-forensics-test", "some/key.bin", payload, "application/octet-stream"
    )
    assert uri == "s3://atdr-forensics-test/some/key.bin"
    assert size == len(payload)
    assert sha256 == "9836e30efa1910f25dffa2908852fd823db8a2d557c2320f76ea66d3909b14ce"
    assert put_calls[0]["Metadata"] == {"sha256": sha256}
