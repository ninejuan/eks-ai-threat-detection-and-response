import importlib
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

MCP_SERVER_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "mcp_server")
GENERATED_DIR = os.path.join(MCP_SERVER_DIR, "_generated")


@pytest.fixture
def hubble_client(monkeypatch):
    for path in (GENERATED_DIR, MCP_SERVER_DIR):
        if path not in sys.path:
            sys.path.insert(0, path)

    monkeypatch.delenv("HUBBLE_TLS_ENABLED", raising=False)
    monkeypatch.delenv("HUBBLE_CA_CERT_PATH", raising=False)
    monkeypatch.delenv("HUBBLE_CLIENT_CERT_PATH", raising=False)
    monkeypatch.delenv("HUBBLE_CLIENT_KEY_PATH", raising=False)
    monkeypatch.delenv("HUBBLE_RELAY_TARGET", raising=False)

    sys.modules.pop("hubble_client", None)
    module = importlib.import_module("hubble_client")
    yield module
    sys.modules.pop("hubble_client", None)


def _make_flow_response(flow_pb2, uuid, source_pod=None, destination_pod=None, verdict="FORWARDED"):
    from google.protobuf.timestamp_pb2 import Timestamp

    flow = flow_pb2.Flow(
        uuid=uuid,
        verdict=getattr(flow_pb2.Verdict, verdict),
        traffic_direction=flow_pb2.INGRESS,
    )
    ts = Timestamp()
    ts.GetCurrentTime()
    flow.time.CopyFrom(ts)
    if source_pod:
        ns, name = source_pod.split("/", 1)
        flow.source.namespace = ns
        flow.source.pod_name = name
    if destination_pod:
        ns, name = destination_pod.split("/", 1)
        flow.destination.namespace = ns
        flow.destination.pod_name = name
    flow.l4.TCP.source_port = 12345
    flow.l4.TCP.destination_port = 80
    return flow


def test_get_flows_for_pod_returns_flow_list(hubble_client):
    from flow import flow_pb2
    from observer import observer_pb2

    flow_a = _make_flow_response(flow_pb2, "flow-a", source_pod="default/pod-a")
    flow_b = _make_flow_response(flow_pb2, "flow-b", destination_pod="default/pod-a", verdict="DROPPED")

    responses = [
        observer_pb2.GetFlowsResponse(flow=flow_a, node_name="node-1"),
        observer_pb2.GetFlowsResponse(flow=flow_b, node_name="node-2"),
    ]

    fake_stub = MagicMock()
    fake_stub.GetFlows.return_value = iter(responses)
    fake_channel = MagicMock()

    with (
        patch.object(hubble_client, "_build_channel", return_value=fake_channel),
        patch.object(hubble_client.observer_pb2_grpc, "ObserverStub", return_value=fake_stub),
    ):
        result = hubble_client.get_flows_for_pod(
            pod_namespace="default",
            pod_name="pod-a",
            since_minutes=5,
            number=10,
        )

    assert result["selector"] == "default/pod-a"
    assert result["flow_count"] == 2
    assert result["lost_events"] == []
    assert result["flows"][0]["uuid"] == "flow-a"
    assert result["flows"][0]["verdict"] == "FORWARDED"
    assert result["flows"][1]["verdict"] == "DROPPED"
    assert result["flows"][0]["l4"] == {"protocol": "TCP", "source_port": 12345, "destination_port": 80}
    fake_channel.close.assert_called_once()

    args, _ = fake_stub.GetFlows.call_args
    request = args[0]
    assert request.whitelist[0].source_pod == ["default/pod-a"]
    assert request.whitelist[1].destination_pod == ["default/pod-a"]
    assert request.number == 10
    assert request.follow is False


def test_get_flows_for_pod_captures_lost_events(hubble_client):
    from flow import flow_pb2
    from observer import observer_pb2

    flow_ok = _make_flow_response(flow_pb2, "f-ok", source_pod="default/pod-a")
    lost = flow_pb2.LostEvent(
        source=flow_pb2.UNKNOWN_LOST_EVENT_SOURCE,
        num_events_lost=42,
    )
    responses = [
        observer_pb2.GetFlowsResponse(flow=flow_ok, node_name="node-1"),
        observer_pb2.GetFlowsResponse(lost_events=lost, node_name="node-1"),
    ]

    fake_stub = MagicMock()
    fake_stub.GetFlows.return_value = iter(responses)
    fake_channel = MagicMock()

    with (
        patch.object(hubble_client, "_build_channel", return_value=fake_channel),
        patch.object(hubble_client.observer_pb2_grpc, "ObserverStub", return_value=fake_stub),
    ):
        result = hubble_client.get_flows_for_pod(pod_namespace="default", pod_name="pod-a")

    assert result["flow_count"] == 1
    assert result["lost_events"] == [{"source": flow_pb2.UNKNOWN_LOST_EVENT_SOURCE, "num_events_lost": 42}]


def test_get_flows_for_pod_raises_on_grpc_failure(hubble_client):
    import grpc

    fake_stub = MagicMock()

    class FakeRpcError(grpc.RpcError):
        def code(self):
            return grpc.StatusCode.UNAVAILABLE

        def details(self):
            return "relay not reachable"

    fake_stub.GetFlows.side_effect = FakeRpcError()
    fake_channel = MagicMock()

    with (
        patch.object(hubble_client, "_build_channel", return_value=fake_channel),
        patch.object(hubble_client.observer_pb2_grpc, "ObserverStub", return_value=fake_stub),
        pytest.raises(hubble_client.HubbleConnectError) as excinfo,
    ):
        hubble_client.get_flows_for_pod(pod_namespace="default", pod_name="pod-a")

    assert "UNAVAILABLE" in str(excinfo.value)
    assert "relay not reachable" in str(excinfo.value)
    fake_channel.close.assert_called_once()


def test_build_channel_insecure_by_default(hubble_client):
    with patch.object(hubble_client, "grpc") as grpc_mod:
        hubble_client._build_channel("localhost:4245")
        grpc_mod.insecure_channel.assert_called_once()
        grpc_mod.secure_channel.assert_not_called()


def test_build_channel_requires_ca_when_tls_enabled(hubble_client, monkeypatch):
    monkeypatch.setenv("HUBBLE_TLS_ENABLED", "true")
    with pytest.raises(hubble_client.HubbleConnectError) as excinfo:
        hubble_client._build_channel("localhost:4245")
    assert "HUBBLE_CA_CERT_PATH" in str(excinfo.value)


def test_build_channel_uses_tls_when_enabled(hubble_client, monkeypatch, tmp_path):
    ca = tmp_path / "ca.pem"
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    ca.write_bytes(b"CA DATA")
    cert.write_bytes(b"CERT DATA")
    key.write_bytes(b"KEY DATA")

    monkeypatch.setenv("HUBBLE_TLS_ENABLED", "true")
    monkeypatch.setenv("HUBBLE_CA_CERT_PATH", str(ca))
    monkeypatch.setenv("HUBBLE_CLIENT_CERT_PATH", str(cert))
    monkeypatch.setenv("HUBBLE_CLIENT_KEY_PATH", str(key))

    with patch.object(hubble_client, "grpc") as grpc_mod:
        hubble_client._build_channel("relay.example:443")

        grpc_mod.ssl_channel_credentials.assert_called_once_with(
            root_certificates=b"CA DATA",
            private_key=b"KEY DATA",
            certificate_chain=b"CERT DATA",
        )
        grpc_mod.secure_channel.assert_called_once()
        grpc_mod.insecure_channel.assert_not_called()
