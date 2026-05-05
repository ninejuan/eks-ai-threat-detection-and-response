import json
import logging
import os

from app.shared.bedrock import BedrockClient
from app.shared.config import Config

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

SYSTEM_PROMPT = """You are a security solution architect for ATDR (AI Threat Detection and Response).
Given a triaged security incident, recommend specific remediation actions for an EKS cluster.

Available remediation actions:
1. isolate_pod: Apply CiliumNetworkPolicy deny-all + Tetragon SIGKILL label + delete pod
2. scale_deployment: Scale a deployment to 0 replicas
3. cordon_node: Prevent new pods from scheduling on a node
4. drain_node: Evict all pods from a node
5. delete_cluster_role_binding: Remove excessive RBAC permissions
6. rotate_secret: Rotate a compromised secret
7. block_ip: Add IP to deny list via CiliumNetworkPolicy
8. checkpoint_pod: Create container checkpoint before isolation (for forensics)

Output a JSON object with:
- recommended_actions: ordered list of action objects, each with:
  - action: one of the actions above
  - target: specific resource (pod name, deployment name, node name, etc.)
  - namespace: kubernetes namespace
  - priority: 1 (immediate) to 5 (can wait)
  - reason: why this action is recommended
- runbook_match: name of matching runbook if found, null otherwise
- estimated_impact: description of service impact from remediation
- rollback_steps: list of steps to undo the remediation if needed

Always recommend checkpoint_pod before isolate_pod for forensic evidence preservation.
Be specific about targets. Never recommend actions without clear justification."""


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    client = BedrockClient(model_id=config.bedrock_model_id, region=config.region)

    summary = event.get("summary", {}).get("body", {})
    triage = event.get("triage", {}).get("body", {})

    kb_context = _retrieve_runbook_context(config, summary, triage)

    context_json = json.dumps(
        {"summary": summary, "triage": triage},
        indent=2,
        ensure_ascii=False,
    )

    user_message = f"Recommend remediation for this incident:\n\n{context_json}"
    if kb_context:
        user_message += f"\n\nRelevant runbook context from Knowledge Base:\n{kb_context}"

    response_text = client.invoke(
        system_prompt=SYSTEM_PROMPT,
        user_message=user_message,
        max_tokens=4096,
    )

    try:
        solution = json.loads(response_text)
    except json.JSONDecodeError:
        logger.warning("Failed to parse solution as JSON")
        solution = {
            "recommended_actions": [],
            "runbook_match": None,
            "estimated_impact": "Unable to determine",
            "rollback_steps": [],
            "parse_error": True,
            "raw_response": response_text,
        }

    return solution


def _retrieve_runbook_context(config: Config, summary: dict, triage: dict) -> str:
    from app.shared.knowledge_base import KnowledgeBaseClient

    if not config.knowledge_base_id:
        return ""

    kb = KnowledgeBaseClient(knowledge_base_id=config.knowledge_base_id, region=config.region)

    query = (
        f"Security incident: {summary.get('title', '')}. "
        f"Category: {triage.get('category', 'unknown')}. "
        f"Severity: {triage.get('severity', 'unknown')}. "
        f"What is the recommended remediation procedure?"
    )

    results = kb.retrieve(query, max_results=3)
    if not results:
        return ""

    context_parts = []
    for r in results:
        source = r.get("source", "unknown")
        content = r.get("content", "")
        context_parts.append(f"[Source: {source}]\n{content}")

    return "\n---\n".join(context_parts)
