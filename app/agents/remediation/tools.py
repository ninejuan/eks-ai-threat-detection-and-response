import json
import logging

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
}


def _mcp_server_url(config: Config) -> str:
    if config.mcp_server_url:
        return config.mcp_server_url

    secret = get_secret(config.mcp_server_url_secret_id)
    url = secret.get("url")
    if not isinstance(url, str) or not url:
        raise McpClientError("MCP server URL secret does not contain url")
    return url


def _client() -> McpClient:
    config = Config()
    return McpClient(
        server_url=_mcp_server_url(config),
        auth_secret_id=config.mcp_auth_secret_id,
        timeout_seconds=config.mcp_timeout_seconds,
    )


def execute_tool(tool_name: str, tool_input: dict) -> dict:
    if tool_name not in ALLOWED_TOOLS:
        return {"status": "failed", "error": f"Unknown tool: {tool_name}"}

    logger.info("Executing MCP tool: %s with input: %s", tool_name, json.dumps(tool_input))
    try:
        result = _client().call_tool(tool_name, tool_input)
    except McpClientError as error:
        logger.error("MCP tool %s failed: %s", tool_name, error)
        return {"status": "failed", "action": tool_name, "error": str(error)}

    if "action" not in result:
        result["action"] = tool_name
    if "status" not in result:
        result["status"] = "success"
    return result
