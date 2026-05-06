import http.client
import json
import logging
from dataclasses import dataclass
from urllib.parse import urlparse

from app.shared.secrets import get_secret

logger = logging.getLogger(__name__)

MCP_PROTOCOL_VERSION = "2025-06-18"


class McpClientError(RuntimeError):
    pass


@dataclass(frozen=True)
class McpClient:
    server_url: str
    auth_secret_id: str
    timeout_seconds: int = 30

    def call_tool(self, tool_name: str, tool_input: dict) -> dict:
        if not self.server_url:
            raise McpClientError("MCP server URL is not configured")

        payload = {
            "jsonrpc": "2.0",
            "id": f"atdr-{tool_name}",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": tool_input,
            },
        }
        response = self._post(payload)

        if "error" in response:
            error = response["error"]
            message = error.get("message", "MCP tool call failed") if isinstance(error, dict) else str(error)
            raise McpClientError(message)

        result = response.get("result", {})
        if isinstance(result, dict) and "structuredContent" in result:
            structured = result["structuredContent"]
            if isinstance(structured, dict):
                return structured
        if isinstance(result, dict) and "content" in result:
            return self._parse_content(result["content"])
        if isinstance(result, dict):
            return result
        return {"status": "success", "result": result}

    def _post(self, payload: dict) -> dict:
        data = json.dumps(payload).encode("utf-8")
        parsed = urlparse(self.server_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise McpClientError("MCP server URL must be an HTTP(S) URL")

        connection_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        path = parsed.path or "/mcp"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        headers = {
            "Authorization": f"Bearer {self._auth_token()}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
        }

        last_error = None
        for attempt in range(3):
            connection = connection_cls(parsed.netloc, timeout=self.timeout_seconds)
            try:
                connection.request("POST", path, body=data, headers=headers)
                response = connection.getresponse()
                body = response.read().decode("utf-8")
                last_error = None
                break
            except OSError as error:
                last_error = error
                logger.warning("MCP connection attempt %d failed: %s", attempt + 1, error)
                import time

                time.sleep(1)
            finally:
                connection.close()

        if last_error:
            raise McpClientError(f"MCP server connection failed: {last_error}") from last_error

        if response.status >= 400:
            logger.warning("MCP server returned HTTP %s: %s", response.status, body)
            raise McpClientError(f"MCP server returned HTTP {response.status}")

        try:
            decoded = json.loads(body)
        except json.JSONDecodeError as error:
            raise McpClientError("MCP server returned invalid JSON") from error

        if not isinstance(decoded, dict):
            raise McpClientError("MCP server returned a non-object JSON response")
        return decoded

    def _auth_token(self) -> str:
        secret = get_secret(self.auth_secret_id)
        token = secret.get("token")
        if not isinstance(token, str) or not token:
            raise McpClientError("MCP auth token secret does not contain token")
        return token

    @staticmethod
    def _parse_content(content: object) -> dict:
        if not isinstance(content, list) or not content:
            return {"status": "success", "content": content}

        first = content[0]
        if not isinstance(first, dict):
            return {"status": "success", "content": content}

        text = first.get("text")
        if not isinstance(text, str):
            return {"status": "success", "content": content}

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {"status": "success", "text": text}

        if isinstance(parsed, dict):
            return parsed
        return {"status": "success", "result": parsed}
