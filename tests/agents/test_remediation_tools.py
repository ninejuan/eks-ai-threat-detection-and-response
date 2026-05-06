from app.agents.remediation import tools


def test_execute_tool_delegates_to_mcp(monkeypatch):
    class Client:
        def call_tool(self, tool_name, tool_input):
            assert tool_name == "label_pod"
            assert tool_input == {"pod_name": "pod-a", "namespace": "default", "labels": {"x": "y"}}
            return {"status": "success"}

    def client_factory():
        return Client()

    monkeypatch.setattr(tools, "_client", client_factory)

    result = tools.execute_tool("label_pod", {"pod_name": "pod-a", "namespace": "default", "labels": {"x": "y"}})

    assert result == {"status": "success", "action": "label_pod"}


def test_execute_tool_rejects_unknown_tool():
    assert tools.execute_tool("kubectl_apply", {}) == {"status": "failed", "error": "Unknown tool: kubectl_apply"}


def test_remediation_tools_do_not_import_kubernetes_client():
    assert "kubernetes" not in tools.__dict__
    assert "get_core_v1" not in tools.__dict__
