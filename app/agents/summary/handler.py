import json
import logging
import os

from app.shared.bedrock import BedrockClient
from app.shared.config import Config

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

SYSTEM_PROMPT = """You are a security event summarizer for an EKS-based threat detection system (ATDR).
Your job is to take raw security events from GuardDuty or Falco and produce a structured summary.

Output a JSON object with these fields:
- incident_id: generated from source and timestamp (format: inc-YYYYMMDD-HHMMSS-SOURCE)
- source: "guardduty" or "falco"
- timestamp: ISO 8601 timestamp of the event
- title: one-line description of the event
- summary: 2-3 sentence description of what happened
- affected_resources: list of affected pods, nodes, namespaces, or AWS resources
- raw_indicators: list of IPs, domains, file paths, or process names involved
- mitre_technique: MITRE ATT&CK technique ID if identifiable (e.g. T1496)

Be concise and factual. Do not speculate."""


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    client = BedrockClient(model_id=config.bedrock_model_id, region=config.region)

    raw_event = event.get("raw_event") or event
    raw_json = json.dumps(raw_event, indent=2, ensure_ascii=False)

    response_text = client.invoke(
        system_prompt=SYSTEM_PROMPT,
        user_message=f"Summarize this security event:\n\n{raw_json}",
        max_tokens=2048,
    )

    try:
        summary = json.loads(response_text)
    except json.JSONDecodeError:
        logger.warning("Failed to parse summary as JSON, wrapping as text")
        summary = {"summary": response_text, "parse_error": True}

    summary["raw_event"] = raw_event

    _store_incident(config, summary)
    return summary


def _store_incident(config: Config, summary: dict) -> None:
    from app.shared.dynamodb import IncidentStore

    if not config.dynamodb_table_name:
        return

    store = IncidentStore(table_name=config.dynamodb_table_name)
    incident_id = summary.get("incident_id", f"inc-{int(__import__('time').time())}")

    store.put_incident(
        incident_id=incident_id,
        data={
            "source": summary.get("source", "unknown"),
            "title": summary.get("title", ""),
            "summary": summary.get("summary", ""),
            "status": "detected",
            "mitre_technique": summary.get("mitre_technique", ""),
        },
    )
