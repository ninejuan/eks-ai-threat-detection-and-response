import http.client
import json
import logging
from urllib.parse import urlparse

from app.shared.config import Config
from app.shared.mcp_client import McpClient, McpClientError
from app.shared.secrets import get_secret

logger = logging.getLogger(__name__)

ALLOWED_TOOLS = {
    "label_pod",
    "delete_pod",
    "apply_cilium_network_policy",
    "patch_deployment",
    "cordon_node",
    "drain_node",
    "checkpoint_pod",
    "capture_hubble_flows",
    "collect_tetragon_timeline",
    "collect_audit_events",
    "collect_live_pod_forensics",
}

_warmed_up = False


def _mcp_server_url(config: Config) -> str:
    if config.mcp_server_url:
        return config.mcp_server_url

    secret = get_secret(config.mcp_server_url_secret_id)
    url = secret.get("url")
    if not isinstance(url, str) or not url:
        raise McpClientError("MCP server URL secret does not contain url")
    return url


def _client() -> McpClient:
    global _warmed_up  # noqa: PLW0603

    config = Config()
    url = _mcp_server_url(config)

    if not _warmed_up:
        _warmup(url)
        _warmed_up = True

    return McpClient(
        server_url=url,
        auth_secret_id=config.mcp_auth_secret_id,
        timeout_seconds=config.mcp_timeout_seconds,
    )


def _warmup(server_url: str) -> None:
    parsed = urlparse(server_url)
    try:
        conn = http.client.HTTPConnection(parsed.netloc, timeout=10)
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        resp.read()
        conn.close()
        logger.info("MCP warmup: %s", resp.status)
    except Exception as error:
        logger.warning("MCP warmup failed (non-fatal): %s", error)


INCIDENT_AWARE_TOOLS = frozenset(
    {
        "checkpoint_pod",
        "capture_hubble_flows",
        "collect_tetragon_timeline",
        "collect_audit_events",
        "collect_live_pod_forensics",
    }
)


def execute_tool(tool_name: str, tool_input: dict, *, incident_id: str | None = None) -> dict:
    if tool_name not in ALLOWED_TOOLS:
        return {"status": "failed", "error": f"Unknown tool: {tool_name}"}

    effective_input = dict(tool_input)
    if incident_id and tool_name in INCIDENT_AWARE_TOOLS:
        effective_input["incident_id"] = incident_id

    logger.info("Executing MCP tool: %s with input: %s", tool_name, json.dumps(effective_input))
    try:
        result = _client().call_tool(tool_name, effective_input)
    except McpClientError as error:
        logger.error("MCP tool %s failed: %s", tool_name, error)
        return {"status": "failed", "action": tool_name, "error": str(error)}

    if "action" not in result:
        result["action"] = tool_name
    if "status" not in result:
        result["status"] = "success"
    return result
