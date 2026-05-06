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
    monkeypatch.setenv("TETRAGON_EVENTS_TABLE", "atdr-tetragon-events-test")
    monkeypatch.setenv("EKS_AUDIT_LOG_GROUP", "/aws/eks/atdr-demo/cluster")
    sys.modules.pop("mcp_server.server", None)

    with (
        patch("kubernetes.config.load_incluster_config"),
        patch("kubernetes.client.CoreV1Api"),
        patch("kubernetes.client.AppsV1Api"),
        patch("kubernetes.client.CustomObjectsApi"),
        patch("boto3.client"),
        patch("boto3.resource"),
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
    fake_flows = {
        "target": "hubble-relay.kube-system.svc.cluster.local:4245",
        "selector": "default/pod-a",
        "since": "2026-05-07T00:00:00+00:00",
        "until": "2026-05-07T00:05:00+00:00",
        "flow_count": 2,
        "lost_events": [],
        "flows": [
            {"uuid": "f-1", "verdict": "FORWARDED", "source": {"pod_name": "pod-a"}},
            {"uuid": "f-2", "verdict": "DROPPED", "destination": {"pod_name": "pod-a"}},
        ],
    }
    monkeypatch.setattr(server_module, "_capture_hubble_flows", lambda **_kwargs: fake_flows)

    result = server_module.capture_hubble_flows("pod-a", "default", incident_id="inc-2026-xyz")

    assert result["status"] == "success"
    assert result["endpoints_found"] == 1
    assert result["hubble_flow_count"] == 2
    assert result["hubble_error"] is None
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
    assert payload["hubble_flows"]["flow_count"] == 2
    assert payload["hubble_error"] is None

    manifest_entry = json.loads(manifest_call["Body"].decode("utf-8"))
    assert manifest_entry["evidence"][0]["kind"] == "network_flow_snapshot"
    assert manifest_entry["evidence"][0]["sha256"] == result["evidence_sha256"]


def test_capture_hubble_flows_records_relay_failure(server_module, monkeypatch):
    pod = SimpleNamespace(
        spec=SimpleNamespace(node_name="node-a"),
        status=SimpleNamespace(pod_ip="10.0.0.5", host_ip="10.0.0.1"),
        metadata=SimpleNamespace(labels={}),
    )

    class CoreApi:
        def read_namespaced_pod(self, name, namespace):
            return pod

    class CustomApi:
        def list_namespaced_custom_object(self, **kwargs):
            return {"items": []}

    put_calls = []

    class S3Client:
        def put_object(self, **kwargs):
            put_calls.append(kwargs)

    def raising_flow_fetch(**_kwargs):
        raise RuntimeError("relay unreachable: connection refused")

    monkeypatch.setattr(server_module, "CORE", CoreApi())
    monkeypatch.setattr(server_module, "CUSTOM", CustomApi())
    monkeypatch.setattr(server_module, "S3", S3Client())
    monkeypatch.setattr(server_module, "_capture_hubble_flows", raising_flow_fetch)

    result = server_module.capture_hubble_flows("pod-a", "default")

    assert result["status"] == "success"
    assert result["hubble_flow_count"] == 0
    assert "relay unreachable" in result["hubble_error"]

    evidence_call = next(call for call in put_calls if "/evidence.json" in call["Key"])
    payload = json.loads(evidence_call["Body"].decode("utf-8"))
    assert payload["hubble_flows"] is None
    assert "relay unreachable" in payload["hubble_error"]


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


def test_collect_tetragon_timeline_returns_events(server_module, monkeypatch):
    captured_queries = []

    def fake_query(**kwargs):
        captured_queries.append(kwargs)
        return {
            "Items": [
                {
                    "sk": "2026-05-06T19:16:03Z#execA",
                    "recorded_at": "2026-05-06T19:16:05Z",
                    "namespace": "atdr-test",
                    "pod_name": "attacker",
                    "container": "attacker",
                    "policy_name": "detect-sensitive-file-access",
                    "function_name": "security_file_open",
                    "binary": "/bin/cat",
                    "arguments": "/etc/shadow",
                },
                {
                    "sk": "2026-05-06T19:16:10Z#execB",
                    "recorded_at": "2026-05-06T19:16:12Z",
                    "namespace": "atdr-test",
                    "pod_name": "attacker",
                    "container": "attacker",
                    "policy_name": "detect-privilege-escalation",
                    "function_name": "__x64_sys_setuid",
                    "binary": "/bin/su",
                    "arguments": "",
                },
            ],
        }

    fake_table = SimpleNamespace(query=fake_query)
    monkeypatch.setattr(server_module.DYNAMODB, "Table", lambda name: fake_table)

    result = server_module.collect_tetragon_timeline(pod_uid="uid-1", since_minutes=15)

    assert result["status"] == "success"
    assert result["pod_uid"] == "uid-1"
    assert result["event_count"] == 2
    assert result["namespace"] == "atdr-test"
    assert result["pod_name"] == "attacker"
    assert result["evidence_uri"] is None

    assert len(captured_queries) == 1
    assert "KeyConditionExpression" in captured_queries[0]
    assert captured_queries[0]["ScanIndexForward"] is True


def test_collect_tetragon_timeline_writes_forensics_when_incident_id(server_module, monkeypatch):
    def fake_query(**_kwargs):
        return {
            "Items": [
                {
                    "sk": "2026-05-06T19:16:03Z#execA",
                    "recorded_at": "2026-05-06T19:16:05Z",
                    "namespace": "atdr-test",
                    "pod_name": "attacker",
                    "container": "attacker",
                    "policy_name": "detect-sensitive-file-access",
                    "function_name": "security_file_open",
                    "binary": "/bin/cat",
                    "arguments": "/etc/shadow",
                },
            ],
        }

    fake_table = SimpleNamespace(query=fake_query)
    monkeypatch.setattr(server_module.DYNAMODB, "Table", lambda name: fake_table)

    put_calls = []

    class S3Client:
        def put_object(self, **kwargs):
            put_calls.append(kwargs)

    monkeypatch.setattr(server_module, "S3", S3Client())

    result = server_module.collect_tetragon_timeline(pod_uid="uid-2", since_minutes=10, incident_id="inc-2026-tl")

    assert result["status"] == "success"
    assert result["evidence_uri"].startswith("s3://atdr-forensics-test/incidents/inc-2026-tl/tetragon-timeline/uid-2/")
    assert "evidence_sha256" in result

    evidence_call = next(call for call in put_calls if "/evidence.json" in call["Key"])
    payload = json.loads(evidence_call["Body"].decode("utf-8"))
    assert payload["kind"] == "tetragon_timeline"
    assert payload["incident_id"] == "inc-2026-tl"
    assert payload["event_count"] == 1
    assert payload["events"][0]["binary"] == "/bin/cat"


def test_collect_tetragon_timeline_reports_missing_env(server_module, monkeypatch):
    monkeypatch.setattr(server_module, "TETRAGON_EVENTS_TABLE", "")
    result = server_module.collect_tetragon_timeline(pod_uid="uid-x")
    assert result["status"] == "failed"
    assert "TETRAGON_EVENTS_TABLE" in result["error"]


def test_collect_audit_events_returns_normalized_rows(server_module, monkeypatch):
    start_calls = []

    class FakeLogs:
        def start_query(self, **kwargs):
            start_calls.append(kwargs)
            return {"queryId": "q-123"}

        def get_query_results(self, **_kwargs):
            return {
                "status": "Complete",
                "results": [
                    [
                        {"field": "@timestamp", "value": "2026-05-06 19:16:03.000"},
                        {"field": "verb", "value": "create"},
                        {"field": "objectRef.namespace", "value": "atdr-test"},
                        {"field": "objectRef.name", "value": "attacker"},
                        {"field": "user.username", "value": "system:admin"},
                        {"field": "@ptr", "value": "ignored"},
                    ],
                ],
                "statistics": {"recordsMatched": 1.0, "recordsScanned": 10.0, "bytesScanned": 1024.0},
            }

        def stop_query(self, **_kwargs):
            pass

    monkeypatch.setattr(server_module, "LOGS", FakeLogs())

    result = server_module.collect_audit_events(pod_name="attacker", namespace="atdr-test", since_minutes=15)

    assert result["status"] == "success"
    assert result["event_count"] == 1
    assert result["statistics"]["recordsMatched"] == 1.0
    assert result["evidence_uri"] is None

    assert start_calls[0]["logGroupName"] == "/aws/eks/atdr-demo/cluster"
    assert "atdr-test" in start_calls[0]["queryString"]
    assert "attacker" in start_calls[0]["queryString"]
    assert start_calls[0]["endTime"] > start_calls[0]["startTime"]


def test_collect_audit_events_writes_forensics_when_incident_id(server_module, monkeypatch):
    class FakeLogs:
        def start_query(self, **_kwargs):
            return {"queryId": "q-456"}

        def get_query_results(self, **_kwargs):
            return {
                "status": "Complete",
                "results": [
                    [
                        {"field": "@timestamp", "value": "2026-05-06 19:16:03.000"},
                        {"field": "verb", "value": "exec"},
                        {"field": "objectRef.namespace", "value": "atdr-test"},
                        {"field": "objectRef.name", "value": "attacker"},
                    ],
                ],
                "statistics": {},
            }

        def stop_query(self, **_kwargs):
            pass

    put_calls = []

    class S3Client:
        def put_object(self, **kwargs):
            put_calls.append(kwargs)

    monkeypatch.setattr(server_module, "LOGS", FakeLogs())
    monkeypatch.setattr(server_module, "S3", S3Client())

    result = server_module.collect_audit_events(
        pod_name="attacker",
        namespace="atdr-test",
        since_minutes=15,
        incident_id="inc-2026-aud",
    )

    assert result["status"] == "success"
    assert result["evidence_uri"].startswith("s3://atdr-forensics-test/incidents/inc-2026-aud/audit-events/attacker/")
    assert "evidence_sha256" in result

    evidence_call = next(call for call in put_calls if "/evidence.json" in call["Key"])
    payload = json.loads(evidence_call["Body"].decode("utf-8"))
    assert payload["kind"] == "eks_audit_events"
    assert payload["incident_id"] == "inc-2026-aud"
    assert payload["events"][0]["objectRef.name"] == "attacker"


def test_collect_audit_events_rejects_unsafe_namespace(server_module):
    result = server_module.collect_audit_events(pod_name="attacker", namespace="atdr'; DROP /*")
    assert result["status"] == "failed"
    assert "unsafe characters" in result["error"]


def test_collect_audit_events_reports_missing_env(server_module, monkeypatch):
    monkeypatch.setattr(server_module, "EKS_AUDIT_LOG_GROUP", "")
    result = server_module.collect_audit_events(pod_name="attacker", namespace="atdr-test")
    assert result["status"] == "failed"
    assert "EKS_AUDIT_LOG_GROUP" in result["error"]


def test_collect_audit_events_stops_on_timeout(server_module, monkeypatch):
    class FakeLogs:
        def __init__(self):
            self.stopped = []

        def start_query(self, **_kwargs):
            return {"queryId": "q-timeout"}

        def get_query_results(self, **_kwargs):
            return {"status": "Running", "results": [], "statistics": {}}

        def stop_query(self, **kwargs):
            self.stopped.append(kwargs)

    fake = FakeLogs()
    monkeypatch.setattr(server_module, "LOGS", fake)

    result = server_module.collect_audit_events(
        pod_name="attacker",
        namespace="atdr-test",
        poll_timeout_seconds=0,
    )

    assert result["status"] == "failed"
    assert "Timeout" in result["error"]
    assert fake.stopped == [{"queryId": "q-timeout"}]


def test_collect_live_pod_forensics_injects_ephemeral_container(server_module, monkeypatch):
    pod_reads = {"count": 0}

    terminated_state = SimpleNamespace(
        state=SimpleNamespace(terminated=SimpleNamespace(reason="Completed"), running=None)
    )

    running_state = SimpleNamespace(state=SimpleNamespace(terminated=None, running=SimpleNamespace(started_at=None)))

    def _pod_with_status(include_terminated: bool):
        statuses = [
            SimpleNamespace(
                name="atdr-fx-abc", **(terminated_state.__dict__ if include_terminated else running_state.__dict__)
            )
        ]
        return SimpleNamespace(
            spec=SimpleNamespace(containers=[SimpleNamespace(name="app")]),
            status=SimpleNamespace(ephemeral_container_statuses=statuses),
        )

    patch_calls = []

    class CoreApi:
        def read_namespaced_pod(self, name, namespace):
            pod_reads["count"] += 1
            if pod_reads["count"] == 1:
                return SimpleNamespace(
                    spec=SimpleNamespace(containers=[SimpleNamespace(name="app")]),
                    status=SimpleNamespace(ephemeral_container_statuses=[]),
                )
            return _pod_with_status(include_terminated=True)

        def patch_namespaced_pod_ephemeralcontainers(self, name, namespace, body, _preload_content):
            patch_calls.append({"name": name, "namespace": namespace, "body": body})

        def read_namespaced_pod_log(self, name, namespace, container):
            return f"stdout of {container}"

    monkeypatch.setattr(server_module, "CORE", CoreApi())
    monkeypatch.setattr(server_module, "_hex_suffix", lambda: "abc")

    put_calls = []

    class S3Client:
        def put_object(self, **kwargs):
            put_calls.append(kwargs)

    monkeypatch.setattr(server_module, "S3", S3Client())

    result = server_module.collect_live_pod_forensics(
        pod_name="attacker",
        namespace="atdr-test",
        profile="process_snapshot",
        incident_id="inc-2026-live",
    )

    assert result["status"] == "success"
    assert result["profile"] == "process_snapshot"
    assert result["debug_container_name"] == "atdr-fx-abc"
    assert result["terminated"] is True
    assert result["exit_reason"] == "Completed"
    assert result["evidence_uri"].startswith(
        "s3://atdr-forensics-test/incidents/inc-2026-live/live-forensics/process_snapshot/attacker/"
    )

    assert patch_calls[0]["name"] == "attacker"
    ephemeral = patch_calls[0]["body"]["spec"]["ephemeralContainers"][0]
    assert ephemeral["targetContainerName"] == "app"
    assert ephemeral["command"][0] == "sh"
    assert ephemeral["securityContext"]["allowPrivilegeEscalation"] is False

    evidence_call = next(call for call in put_calls if "/evidence.json" in call["Key"])
    payload = json.loads(evidence_call["Body"].decode("utf-8"))
    assert payload["kind"] == "live_pod_forensics"
    assert payload["profile"] == "process_snapshot"
    assert payload["output"].startswith("stdout of atdr-fx-abc")
    assert payload["terminated"] is True


def test_collect_live_pod_forensics_rejects_unknown_profile(server_module, monkeypatch):
    class CoreApi:
        def read_namespaced_pod(self, name, namespace):
            return SimpleNamespace(
                spec=SimpleNamespace(containers=[SimpleNamespace(name="app")]),
                status=SimpleNamespace(ephemeral_container_statuses=[]),
            )

    monkeypatch.setattr(server_module, "CORE", CoreApi())
    result = server_module.collect_live_pod_forensics(
        pod_name="attacker",
        namespace="atdr-test",
        profile="rce_shell",
    )
    assert result["status"] == "failed"
    assert "unknown profile" in result["error"]


def test_collect_live_pod_forensics_rejects_invalid_pod_name(server_module):
    result = server_module.collect_live_pod_forensics(
        pod_name="attacker; rm -rf /",
        namespace="atdr-test",
        profile="process_snapshot",
    )
    assert result["status"] == "failed"
    assert "invalid K8s characters" in result["error"]


def test_collect_live_pod_forensics_reports_watchdog_timeout(server_module, monkeypatch):
    class CoreApi:
        def read_namespaced_pod(self, name, namespace):
            return SimpleNamespace(
                spec=SimpleNamespace(containers=[SimpleNamespace(name="app")]),
                status=SimpleNamespace(
                    ephemeral_container_statuses=[
                        SimpleNamespace(
                            name="atdr-fx-abc",
                            state=SimpleNamespace(terminated=None, running=SimpleNamespace(started_at=None)),
                        )
                    ]
                ),
            )

        def patch_namespaced_pod_ephemeralcontainers(self, name, namespace, body, _preload_content):
            pass

        def read_namespaced_pod_log(self, name, namespace, container):
            return ""

    monkeypatch.setattr(server_module, "CORE", CoreApi())
    monkeypatch.setattr(server_module, "_hex_suffix", lambda: "abc")

    result = server_module.collect_live_pod_forensics(
        pod_name="attacker",
        namespace="atdr-test",
        profile="network_snapshot",
        timeout_seconds=5,
    )

    assert result["status"] == "success"
    assert result["terminated"] is False
    assert result["exit_reason"] == "watchdog_timeout"


def test_checkpoint_container_experimental_success(server_module, monkeypatch):
    node_addr = SimpleNamespace(type="InternalIP", address="10.0.1.50")
    pod = SimpleNamespace(
        spec=SimpleNamespace(
            containers=[SimpleNamespace(name="app")],
            node_name="node-a",
        ),
    )
    node = SimpleNamespace(status=SimpleNamespace(addresses=[node_addr]))

    class CoreApi:
        def read_namespaced_pod(self, name, namespace):
            return pod

        def read_node(self, name):
            return node

    monkeypatch.setattr(server_module, "CORE", CoreApi())
    monkeypatch.setattr(
        server_module,
        "_kubelet_checkpoint_request",
        lambda **_kwargs: ("success", "checkpoint_created", "/var/lib/kubelet/checkpoints/checkpoint.tar", 200),
    )

    put_calls = []

    class S3Client:
        def put_object(self, **kwargs):
            put_calls.append(kwargs)

    monkeypatch.setattr(server_module, "S3", S3Client())

    result = server_module.checkpoint_container_experimental(
        pod_name="attacker", namespace="atdr-test", incident_id="inc-2026-criu"
    )
    assert result["status"] == "success"
    assert result["archive_path_on_node"] == "/var/lib/kubelet/checkpoints/checkpoint.tar"
    assert result["node_ip"] == "10.0.1.50"
    assert result["fallback_recommendation"] is None

    evidence_call = next(call for call in put_calls if "/evidence.json" in call["Key"])
    payload = json.loads(evidence_call["Body"].decode("utf-8"))
    assert payload["attempt_status"] == "success"
    assert payload["kubelet_http_status"] == 200


def test_checkpoint_container_experimental_reports_unsupported(server_module, monkeypatch):
    node_addr = SimpleNamespace(type="InternalIP", address="10.0.1.50")
    pod = SimpleNamespace(
        spec=SimpleNamespace(
            containers=[SimpleNamespace(name="app")],
            node_name="node-a",
        ),
    )
    node = SimpleNamespace(status=SimpleNamespace(addresses=[node_addr]))

    class CoreApi:
        def read_namespaced_pod(self, name, namespace):
            return pod

        def read_node(self, name):
            return node

    monkeypatch.setattr(server_module, "CORE", CoreApi())
    monkeypatch.setattr(
        server_module,
        "_kubelet_checkpoint_request",
        lambda **_kwargs: ("unsupported", "checkpoint_feature_gate_disabled_or_not_found", None, 404),
    )

    result = server_module.checkpoint_container_experimental(pod_name="attacker", namespace="atdr-test")

    assert result["status"] == "unsupported"
    assert "checkpoint_feature_gate_disabled_or_not_found" in result["error"]
    assert result["kubelet_http_status"] == 404
    assert result["fallback_recommendation"] == "collect_live_pod_forensics"


def test_checkpoint_container_experimental_handles_unscheduled_pod(server_module, monkeypatch):
    pod = SimpleNamespace(spec=SimpleNamespace(containers=[SimpleNamespace(name="app")], node_name=""))

    class CoreApi:
        def read_namespaced_pod(self, name, namespace):
            return pod

    monkeypatch.setattr(server_module, "CORE", CoreApi())

    result = server_module.checkpoint_container_experimental(pod_name="attacker", namespace="atdr-test")

    assert result["status"] == "unsupported"
    assert "pod_not_scheduled_or_has_no_containers" in result["error"]


def test_interpret_kubelet_checkpoint_response_maps_statuses(server_module):
    cases = [
        (200, '{"items":["/path/a.tar"]}', ("success", "checkpoint_created", "/path/a.tar")),
        (401, "", ("unsupported", "kubelet_unauthorized_missing_checkpoint_rbac", None)),
        (403, "", ("unsupported", "kubelet_forbidden_checkpoint_rbac", None)),
        (404, "", ("unsupported", "checkpoint_feature_gate_disabled_or_not_found", None)),
        (502, "", ("unsupported", "unexpected_status:502", None)),
        (None, None, ("unsupported", "kubelet_no_response", None)),
    ]
    for status_code, body, expected in cases:
        assert server_module._interpret_kubelet_checkpoint_response(status_code, body) == expected
