import logging
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import grpc
from flow import flow_pb2
from google.protobuf.timestamp_pb2 import Timestamp
from observer import observer_pb2, observer_pb2_grpc

logger = logging.getLogger("atdr-remediation-mcp.hubble")

DEFAULT_RELAY_TARGET = "hubble-relay.kube-system.svc.cluster.local:4245"
DEFAULT_MAX_MESSAGE_SIZE = 50 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 30


class HubbleConnectError(RuntimeError):
    pass


def _channel_options() -> list[tuple[str, int]]:
    return [
        ("grpc.max_send_message_length", DEFAULT_MAX_MESSAGE_SIZE),
        ("grpc.max_receive_message_length", DEFAULT_MAX_MESSAGE_SIZE),
    ]


def _load_tls_credentials() -> grpc.ChannelCredentials:
    ca_path = os.environ.get("HUBBLE_CA_CERT_PATH")
    cert_path = os.environ.get("HUBBLE_CLIENT_CERT_PATH")
    key_path = os.environ.get("HUBBLE_CLIENT_KEY_PATH")
    if not ca_path:
        raise HubbleConnectError("HUBBLE_CA_CERT_PATH is required when HUBBLE_TLS_ENABLED=true")

    with open(ca_path, "rb") as handle:
        ca_cert = handle.read()
    client_cert = None
    client_key = None
    if cert_path and key_path:
        with open(cert_path, "rb") as handle:
            client_cert = handle.read()
        with open(key_path, "rb") as handle:
            client_key = handle.read()

    return grpc.ssl_channel_credentials(
        root_certificates=ca_cert,
        private_key=client_key,
        certificate_chain=client_cert,
    )


def _build_channel(target: str) -> grpc.Channel:
    tls_enabled = os.environ.get("HUBBLE_TLS_ENABLED", "false").lower() == "true"
    if not tls_enabled:
        return grpc.insecure_channel(target, options=_channel_options())
    credentials = _load_tls_credentials()
    return grpc.secure_channel(target, credentials, options=_channel_options())


def _ts_from_datetime(value: datetime) -> Timestamp:
    ts = Timestamp()
    ts.FromDatetime(value)
    return ts


def _flow_to_dict(flow: Any) -> dict:
    return {
        "uuid": flow.uuid,
        "time": flow.time.ToJsonString() if flow.HasField("time") else None,
        "verdict": flow_pb2.Verdict.Name(flow.verdict),
        "traffic_direction": flow_pb2.TrafficDirection.Name(flow.traffic_direction),
        "source": {
            "namespace": flow.source.namespace,
            "pod_name": flow.source.pod_name,
            "identity": flow.source.identity,
            "labels": list(flow.source.labels),
        },
        "destination": {
            "namespace": flow.destination.namespace,
            "pod_name": flow.destination.pod_name,
            "identity": flow.destination.identity,
            "labels": list(flow.destination.labels),
        },
        "node_name": flow.node_name,
        "l4": _l4_to_dict(flow.l4) if flow.HasField("l4") else None,
        "ip": _ip_to_dict(flow.IP) if flow.HasField("IP") else None,
        "drop_reason_desc": (flow_pb2.DropReason.Name(flow.drop_reason_desc) if flow.drop_reason_desc != 0 else None),
    }


def _l4_to_dict(l4: Any) -> dict:
    if l4.HasField("TCP"):
        return {
            "protocol": "TCP",
            "source_port": l4.TCP.source_port,
            "destination_port": l4.TCP.destination_port,
        }
    if l4.HasField("UDP"):
        return {
            "protocol": "UDP",
            "source_port": l4.UDP.source_port,
            "destination_port": l4.UDP.destination_port,
        }
    if l4.HasField("ICMPv4"):
        return {"protocol": "ICMPv4"}
    if l4.HasField("ICMPv6"):
        return {"protocol": "ICMPv6"}
    return {"protocol": "UNKNOWN"}


def _ip_to_dict(ip: Any) -> dict:
    return {"source": ip.source, "destination": ip.destination, "ip_version": flow_pb2.IPVersion.Name(ip.ipVersion)}


def get_flows_for_pod(
    pod_namespace: str,
    pod_name: str,
    since_minutes: int = 5,
    number: int = 1000,
    target: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    selector = f"{pod_namespace}/{pod_name}"
    since = datetime.now(tz=UTC) - timedelta(minutes=since_minutes)
    until = datetime.now(tz=UTC)

    whitelist = [
        flow_pb2.FlowFilter(source_pod=[selector]),
        flow_pb2.FlowFilter(destination_pod=[selector]),
    ]
    request = observer_pb2.GetFlowsRequest(
        since=_ts_from_datetime(since),
        until=_ts_from_datetime(until),
        whitelist=whitelist,
        follow=False,
        number=number,
    )

    effective_target = target or os.environ.get("HUBBLE_RELAY_TARGET", DEFAULT_RELAY_TARGET)
    flows: list[dict] = []
    lost: list[dict] = []
    channel = _build_channel(effective_target)
    try:
        stub = observer_pb2_grpc.ObserverStub(channel)
        for response in stub.GetFlows(request, timeout=timeout_seconds):
            if response.HasField("flow"):
                flows.append(_flow_to_dict(response.flow))
            elif response.HasField("lost_events"):
                lost.append(
                    {
                        "source": response.lost_events.source,
                        "num_events_lost": response.lost_events.num_events_lost,
                    }
                )
    except grpc.RpcError as error:
        raise HubbleConnectError(f"Hubble Relay gRPC failed: {error.code().name}: {error.details()}") from error
    finally:
        channel.close()

    return {
        "target": effective_target,
        "selector": selector,
        "since": since.isoformat(),
        "until": until.isoformat(),
        "flow_count": len(flows),
        "lost_events": lost,
        "flows": flows,
    }
