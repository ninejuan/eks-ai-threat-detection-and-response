import json
import logging
import os

from app.shared.bedrock import BedrockClient
from app.shared.config import Config

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

SYSTEM_PROMPT = """You are a security remediation executor for ATDR (AI Threat Detection and Response).
You receive a list of recommended remediation actions and execute them against an EKS cluster
using the available MCP tools.

You MUST follow this execution order for pod isolation:
1. checkpoint_pod (preserve forensic evidence)
2. capture_hubble_flows (capture network flows)
3. label_pod with security.incident/compromised=true (triggers Tetragon SIGKILL)
4. apply_cilium_network_policy deny-all
5. delete_pod with --force --grace-period=0
6. patch_deployment to scale replicas=0

For each action, report:
- action: what was executed
- status: success or failed
- details: execution output or error message
- timestamp: when the action was executed

If an action fails, continue with remaining actions unless it's a critical dependency.
Never skip checkpoint_pod before isolation."""

REMEDIATION_TOOLS = [
    {
        "name": "label_pod",
        "description": "Add or update labels on a pod",
        "input_schema": {
            "type": "object",
            "properties": {
                "pod_name": {"type": "string"},
                "namespace": {"type": "string"},
                "labels": {"type": "object"},
            },
            "required": ["pod_name", "namespace", "labels"],
        },
    },
    {
        "name": "apply_cilium_network_policy",
        "description": "Apply a CiliumNetworkPolicy to isolate a pod or namespace",
        "input_schema": {
            "type": "object",
            "properties": {
                "policy_name": {"type": "string"},
                "namespace": {"type": "string"},
                "pod_selector": {"type": "object"},
                "deny_all": {"type": "boolean"},
            },
            "required": ["policy_name", "namespace"],
        },
    },
    {
        "name": "delete_pod",
        "description": "Delete a pod, optionally with force",
        "input_schema": {
            "type": "object",
            "properties": {
                "pod_name": {"type": "string"},
                "namespace": {"type": "string"},
                "force": {"type": "boolean"},
                "grace_period_seconds": {"type": "integer"},
            },
            "required": ["pod_name", "namespace"],
        },
    },
    {
        "name": "patch_deployment",
        "description": "Patch a deployment (e.g., scale replicas)",
        "input_schema": {
            "type": "object",
            "properties": {
                "deployment_name": {"type": "string"},
                "namespace": {"type": "string"},
                "replicas": {"type": "integer"},
            },
            "required": ["deployment_name", "namespace"],
        },
    },
    {
        "name": "checkpoint_pod",
        "description": "Create a container checkpoint and export to S3",
        "input_schema": {
            "type": "object",
            "properties": {
                "pod_name": {"type": "string"},
                "namespace": {"type": "string"},
                "container_name": {"type": "string"},
                "s3_destination": {"type": "string"},
            },
            "required": ["pod_name", "namespace"],
        },
    },
    {
        "name": "cordon_node",
        "description": "Mark a node as unschedulable",
        "input_schema": {
            "type": "object",
            "properties": {
                "node_name": {"type": "string"},
            },
            "required": ["node_name"],
        },
    },
    {
        "name": "drain_node",
        "description": "Drain all pods from a node",
        "input_schema": {
            "type": "object",
            "properties": {
                "node_name": {"type": "string"},
                "ignore_daemonsets": {"type": "boolean"},
            },
            "required": ["node_name"],
        },
    },
]


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    client = BedrockClient(model_id=config.bedrock_model_id, region=config.region)

    summary = event.get("summary", {}).get("body", {})
    triage = event.get("triage", {}).get("body", {})
    solution = event.get("solution", {}).get("body", {})

    context_json = json.dumps(
        {"summary": summary, "triage": triage, "solution": solution},
        indent=2,
        ensure_ascii=False,
    )

    messages = [
        {
            "role": "user",
            "content": f"Execute the recommended remediation actions:\n\n{context_json}",
        }
    ]

    execution_log = []
    max_iterations = 10

    for _ in range(max_iterations):
        response = client.invoke_with_tools(
            system_prompt=SYSTEM_PROMPT,
            messages=messages,
            tools=REMEDIATION_TOOLS,
            max_tokens=4096,
        )

        stop_reason = response.get("stop_reason", "end_turn")

        if stop_reason != "tool_use":
            final_text = ""
            for block in response.get("content", []):
                if block.get("type") == "text":
                    final_text = block["text"]
            execution_log.append({"type": "completion", "text": final_text})
            break

        messages.append({"role": "assistant", "content": response["content"]})

        tool_results = []
        for block in response.get("content", []):
            if block.get("type") == "tool_use":
                tool_name = block["name"]
                tool_input = block["input"]
                tool_id = block["id"]

                result = _execute_tool(tool_name, tool_input)
                execution_log.append({"tool": tool_name, "input": tool_input, "result": result})

                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": json.dumps(result),
                    }
                )

        messages.append({"role": "user", "content": tool_results})

    return {
        "status": "completed",
        "execution_log": execution_log,
        "actions_taken": len([e for e in execution_log if "tool" in e]),
    }


def _execute_tool(tool_name: str, tool_input: dict) -> dict:
    logger.info("Executing tool: %s with input: %s", tool_name, json.dumps(tool_input))
    return {
        "status": "success",
        "message": f"Tool {tool_name} executed successfully (MCP integration pending)",
        "input": tool_input,
    }
