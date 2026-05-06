import pytest

from app.shared.mcp_client import McpClient, McpClientError


class Response:
    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body

    def read(self):
        return self.body.encode("utf-8")


class Connection:
    def __init__(
        self, captured: dict, status: int = 200, body: str = '{"result":{"structuredContent":{"status":"success"}}}'
    ):
        self.captured = captured
        self.response = Response(status, body)

    def request(self, method, path, body, headers):
        self.captured["method"] = method
        self.captured["path"] = path
        self.captured["body"] = body
        self.captured["headers"] = headers

    def getresponse(self):
        return self.response

    def close(self):
        self.captured["closed"] = True


def test_mcp_client_calls_tool_with_bearer_token(monkeypatch):
    captured = {}

    monkeypatch.setattr("app.shared.mcp_client.get_secret", lambda secret_id: {"token": "secret-token"})

    def fake_connection(netloc, timeout):
        captured["netloc"] = netloc
        captured["timeout"] = timeout
        return Connection(captured)

    monkeypatch.setattr("app.shared.mcp_client.http.client.HTTPConnection", fake_connection)

    result = McpClient("http://mcp.internal/mcp", "atdr/mcp/auth-token", 7).call_tool("delete_pod", {"pod_name": "p"})

    assert result == {"status": "success"}
    assert captured["netloc"] == "mcp.internal"
    assert captured["method"] == "POST"
    assert captured["path"] == "/mcp"
    assert captured["headers"]["Authorization"] == "Bearer secret-token"
    assert captured["headers"]["MCP-Protocol-Version"] == "2025-06-18"
    assert captured["timeout"] == 7
    assert b'"method": "tools/call"' in captured["body"]
    assert b'"name": "delete_pod"' in captured["body"]


def test_mcp_client_raises_on_jsonrpc_error(monkeypatch):
    monkeypatch.setattr("app.shared.mcp_client.get_secret", lambda secret_id: {"token": "secret-token"})

    def fake_connection(netloc, timeout):
        return Connection({}, body='{"error":{"message":"denied"}}')

    monkeypatch.setattr("app.shared.mcp_client.http.client.HTTPConnection", fake_connection)

    with pytest.raises(McpClientError, match="denied"):
        McpClient("http://mcp.internal/mcp", "atdr/mcp/auth-token").call_tool("delete_pod", {})


def test_mcp_client_raises_on_http_error(monkeypatch):
    monkeypatch.setattr("app.shared.mcp_client.get_secret", lambda secret_id: {"token": "secret-token"})

    def fake_connection(netloc, timeout):
        return Connection({}, status=401, body='{"error":"unauthorized"}')

    monkeypatch.setattr("app.shared.mcp_client.http.client.HTTPConnection", fake_connection)

    with pytest.raises(McpClientError, match="HTTP 401"):
        McpClient("http://mcp.internal/mcp", "atdr/mcp/auth-token").call_tool("delete_pod", {})


def test_mcp_client_raises_on_connection_error(monkeypatch):
    monkeypatch.setattr("app.shared.mcp_client.get_secret", lambda secret_id: {"token": "secret-token"})

    class BrokenConnection:
        def request(self, _method, _path, body, headers):
            _ = (body, headers)
            raise OSError("network down")

        def close(self):
            pass

    def fake_connection(netloc, timeout):
        return BrokenConnection()

    monkeypatch.setattr("app.shared.mcp_client.http.client.HTTPConnection", fake_connection)

    with pytest.raises(McpClientError, match="connection failed"):
        McpClient("http://mcp.internal/mcp", "atdr/mcp/auth-token").call_tool("delete_pod", {})
