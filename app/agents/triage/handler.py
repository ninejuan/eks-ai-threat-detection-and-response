import json
import logging
import os

from app.shared.bedrock import BedrockClient
from app.shared.config import Config
from app.shared.json_extract import extract_json

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

SYSTEM_PROMPT = """You are a security incident triage agent for ATDR (AI Threat Detection and Response).
Given a structured security event summary, determine the severity and priority.

Severity levels:
- P1 (Critical): Active data exfiltration, container escape, crypto mining confirmed
- P2 (High): Privilege escalation attempt, suspicious lateral movement, C2 communication
- P3 (Medium): Anomalous DNS queries, unusual process execution, policy violations
- P4 (Low): Informational alerts, minor policy deviations, scan activity

Output ONLY a valid JSON object with these fields (no markdown, no explanation, no text before or after):
- severity: P1, P2, P3, or P4
- confidence: 0.0 to 1.0
- category: one of [cryptomining, container_escape, privilege_escalation, data_exfiltration,
  lateral_movement, c2_communication, dns_anomaly, policy_violation, reconnaissance, unknown]
- reasoning: 1-2 sentences explaining the severity decision
- auto_remediate: boolean, true if severity is P3 or P4
- requires_approval: boolean, true if severity is P1 or P2

Rules:
- Output ONLY the JSON object. No markdown fences, no notes, no explanations.
- Be decisive. When in doubt, err on the side of higher severity."""


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    client = BedrockClient(model_id=config.bedrock_model_id, region=config.region)

    summary = event.get("summary", {}).get("body", event)
    summary_json = json.dumps(summary, indent=2, ensure_ascii=False)

    response_text = client.invoke(
        system_prompt=SYSTEM_PROMPT,
        user_message=f"Triage this security incident:\n\n{summary_json}",
        max_tokens=1024,
    )

    try:
        triage = extract_json(response_text)
    except json.JSONDecodeError:
        logger.warning("Failed to parse triage as JSON, defaulting to P2")
        triage = {
            "severity": "P2",
            "confidence": 0.5,
            "category": "unknown",
            "reasoning": response_text,
            "auto_remediate": False,
            "requires_approval": True,
        }

    _update_incident(triage, summary)
    _notify_slack(triage, summary)
    return triage


def _update_incident(triage: dict, summary: dict) -> None:
    from app.shared.dynamodb import IncidentStore

    config = Config()
    if not config.dynamodb_table_name:
        return

    incident_id = summary.get("incident_id", "")
    if not incident_id:
        return

    store = IncidentStore(table_name=config.dynamodb_table_name)
    store.update_incident(
        incident_id=incident_id,
        updates={
            "severity": triage.get("severity", "UNKNOWN"),
            "confidence": str(triage.get("confidence", 0)),
            "category": triage.get("category", "unknown"),
            "triage_reasoning": triage.get("reasoning", ""),
            "auto_remediate": triage.get("auto_remediate", False),
            "requires_approval": triage.get("requires_approval", True),
            "status": "triaged",
        },
    )


def _notify_slack(triage: dict, summary: dict) -> None:
    from app.shared.slack_notifier import SlackNotifier

    config = Config()
    notifier = SlackNotifier(project=config.project)

    incident = {
        "incident_id": summary.get("incident_id", "unknown"),
        "severity": triage.get("severity", "UNKNOWN"),
        "source": summary.get("source", "unknown"),
        "summary": summary.get("summary", "No summary"),
        "category": triage.get("category", "unknown"),
        "reasoning": triage.get("reasoning", ""),
        "requires_approval": triage.get("requires_approval", True),
    }

    notifier.send_incident(incident)
