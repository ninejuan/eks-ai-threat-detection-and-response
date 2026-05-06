import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

import boto3

from app.shared.bedrock import BedrockClient
from app.shared.config import Config

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

SYSTEM_PROMPT = """You are ATDR's Forensic Synthesis Analyst.

You receive the full incident context for a Kubernetes security event:
- Original detection (Falco / Tetragon / GuardDuty)
- Summary, triage, and solution agent outputs
- Remediation execution log with S3 evidence URIs

Your job is to produce a grounded, citation-bearing forensic report.

Every claim you make MUST be backed by a reference to one of:
- A remediation execution_log entry ("execution_log[<index>].<tool>")
- An evidence S3 URI already present in the context ("evidence_uri:<s3://...>")
- A field of summary/triage/solution output ("summary.<field>", etc.)

You MUST respond with ONLY valid minified JSON. No prose, no markdown code fences.
Use this exact schema:

{
  "executive_summary": "1-2 sentence analyst-grade description of what happened.",
  "timeline": [
    {
      "timestamp": "ISO-8601 or best-effort string",
      "event": "What happened at this moment",
      "source": "falco|tetragon|guardduty|remediation|inferred",
      "evidence_ref": "citation as described above",
      "confidence": "high|medium|low"
    }
  ],
  "iocs": [
    {"type": "pod|ip|domain|file|binary|uid|image|hash", "value": "...",
     "source": "...", "confidence": "high|medium|low"}
  ],
  "ttps": [
    {"framework": "MITRE ATT&CK", "technique_id": "Txxxx", "name": "...", "evidence_refs": ["..."]}
  ],
  "blast_radius": {
    "affected_namespaces": ["..."],
    "affected_pods": ["..."],
    "lateral_movement_observed": true,
    "privilege_escalation_observed": true
  },
  "root_cause_hypothesis": "Grounded hypothesis citing evidence.",
  "remediation_assessment": {
    "actions_attempted": ["..."],
    "actions_succeeded": ["..."],
    "actions_failed": ["..."],
    "residual_risk": "high|medium|low",
    "residual_risk_reason": "..."
  },
  "hardening_recommendations": [
    {"priority": 1, "recommendation": "...", "rationale": "..."}
  ],
  "open_questions": ["..."],
  "confidence_overall": "high|medium|low"
}

If an input section is missing, write an empty array or an empty string, never invent data.
"""


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    client = BedrockClient(model_id=config.bedrock_model_id, region=config.region)

    summary = _safe_body(event.get("summary"))
    triage = _safe_body(event.get("triage"))
    solution = _safe_body(event.get("solution"))
    remediation = _safe_body(event.get("remediation"))

    incident_id = summary.get("incident_id") or "adhoc"
    execution_log = remediation.get("execution_log", []) if isinstance(remediation, dict) else []
    evidence_uris = _extract_evidence_uris(execution_log, extra=remediation.get("evidence_uris", []))

    user_message = json.dumps(
        {
            "incident_id": incident_id,
            "summary": summary,
            "triage": triage,
            "solution": solution,
            "remediation_execution_log": execution_log,
            "evidence_uris": evidence_uris,
        },
        default=str,
        ensure_ascii=False,
    )

    raw_text: str = ""
    synthesis: dict[str, Any] | None = None
    parse_error: str | None = None

    try:
        raw_text = client.invoke(
            system_prompt=SYSTEM_PROMPT,
            user_message=user_message,
            max_tokens=8192,
        )
    except Exception as error:
        logger.exception("Bedrock invocation failed for synthesis")
        parse_error = f"bedrock_invoke_failed: {type(error).__name__}: {error}"

    if raw_text:
        try:
            synthesis = json.loads(_strip_json_fences(raw_text))
        except json.JSONDecodeError as error:
            parse_error = f"invalid_json_response: {error}"

    if synthesis is None:
        synthesis = _fallback_synthesis(incident_id=incident_id, reason=parse_error, evidence_uris=evidence_uris)

    report_md = _render_markdown(synthesis, incident_id=incident_id)
    s3_uris = _persist_artifacts(
        config=config,
        incident_id=incident_id,
        synthesis=synthesis,
        report_md=report_md,
    )

    _update_incident(config, incident_id, synthesis, s3_uris, parse_error)

    return {
        "status": "completed" if parse_error is None else "completed_with_parse_error",
        "incident_id": incident_id,
        "synthesis_uris": s3_uris,
        "parse_error": parse_error,
    }


def _safe_body(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    body = value.get("body", value)
    return body if isinstance(body, dict) else {}


def _extract_evidence_uris(execution_log: list, extra: list | None = None) -> list[dict]:
    uris: list[dict] = []
    for entry in execution_log:
        if not isinstance(entry, dict):
            continue
        result = entry.get("result", {})
        if not isinstance(result, dict):
            continue
        uri = result.get("evidence_uri")
        if uri:
            uris.append(
                {
                    "uri": uri,
                    "tool": entry.get("tool"),
                    "sha256": result.get("evidence_sha256"),
                    "kind": result.get("kind") or entry.get("tool"),
                }
            )
    for uri in extra or []:
        if isinstance(uri, str):
            uris.append({"uri": uri, "tool": None, "sha256": None, "kind": None})
    return uris


def _fallback_synthesis(incident_id: str, reason: str | None, evidence_uris: list) -> dict:
    return {
        "executive_summary": ("Forensic synthesis could not be generated by the LLM. See parse_error for details."),
        "timeline": [],
        "iocs": [],
        "ttps": [],
        "blast_radius": {
            "affected_namespaces": [],
            "affected_pods": [],
            "lateral_movement_observed": False,
            "privilege_escalation_observed": False,
        },
        "root_cause_hypothesis": "",
        "remediation_assessment": {
            "actions_attempted": [],
            "actions_succeeded": [],
            "actions_failed": [],
            "residual_risk": "medium",
            "residual_risk_reason": f"synthesis unavailable: {reason}" if reason else "",
        },
        "hardening_recommendations": [],
        "open_questions": ["Re-run synthesis after investigating why the LLM output could not be parsed."],
        "confidence_overall": "low",
        "_fallback": True,
        "_fallback_reason": reason,
        "_incident_id": incident_id,
        "_evidence_uris": evidence_uris,
    }


def _strip_json_fences(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        first_newline = stripped.find("\n")
        stripped = stripped[first_newline + 1 :] if first_newline != -1 else stripped[3:]
    if stripped.endswith("```"):
        stripped = stripped[:-3]
    return stripped.strip()


def _render_markdown(synthesis: dict, incident_id: str) -> str:
    def bullet(items: list[str]) -> str:
        return "\n".join(f"- {item}" for item in items) if items else "_(none recorded)_"

    timeline_md = (
        "\n".join(
            f"- `{event.get('timestamp', '')}` ({event.get('source', '?')}, {event.get('confidence', '?')}): "
            f"{event.get('event', '')} [{event.get('evidence_ref', '')}]"
            for event in synthesis.get("timeline", [])
        )
        or "_(no events recorded)_"
    )

    ioc_md = (
        "\n".join(
            f"- {ioc.get('type', '')}: `{ioc.get('value', '')}` (conf={ioc.get('confidence', '?')}, "
            f"source={ioc.get('source', '?')})"
            for ioc in synthesis.get("iocs", [])
        )
        or "_(none)_"
    )

    ttp_md = (
        "\n".join(
            f"- {ttp.get('framework', '')} / {ttp.get('technique_id', '')} - {ttp.get('name', '')} "
            f"({', '.join(ttp.get('evidence_refs', []) or [])})"
            for ttp in synthesis.get("ttps", [])
        )
        or "_(none)_"
    )

    hardening_md = (
        "\n".join(
            f"{item.get('priority', '?')}. {item.get('recommendation', '')} — {item.get('rationale', '')}"
            for item in synthesis.get("hardening_recommendations", [])
        )
        or "_(none)_"
    )

    blast = synthesis.get("blast_radius", {}) or {}
    remediation = synthesis.get("remediation_assessment", {}) or {}

    return (
        f"# Forensic Synthesis — {incident_id}\n\n"
        f"**Executive summary:** {synthesis.get('executive_summary', '')}\n\n"
        f"**Overall confidence:** {synthesis.get('confidence_overall', '')}\n\n"
        f"## Timeline\n{timeline_md}\n\n"
        f"## Indicators of Compromise\n{ioc_md}\n\n"
        f"## MITRE ATT&CK Techniques\n{ttp_md}\n\n"
        f"## Blast Radius\n"
        f"- Namespaces: {', '.join(blast.get('affected_namespaces') or []) or '_(none)_'}\n"
        f"- Pods: {', '.join(blast.get('affected_pods') or []) or '_(none)_'}\n"
        f"- Lateral movement observed: {blast.get('lateral_movement_observed', False)}\n"
        f"- Privilege escalation observed: {blast.get('privilege_escalation_observed', False)}\n\n"
        f"## Root Cause Hypothesis\n{synthesis.get('root_cause_hypothesis', '') or '_(none)_'}\n\n"
        f"## Remediation Assessment\n"
        f"- Attempted: {bullet(remediation.get('actions_attempted') or [])}\n"
        f"- Succeeded: {bullet(remediation.get('actions_succeeded') or [])}\n"
        f"- Failed: {bullet(remediation.get('actions_failed') or [])}\n"
        f"- Residual risk: {remediation.get('residual_risk', '')} — "
        f"{remediation.get('residual_risk_reason', '')}\n\n"
        f"## Hardening Recommendations\n{hardening_md}\n\n"
        f"## Open Questions\n{bullet(synthesis.get('open_questions') or [])}\n"
    )


def _persist_artifacts(config: Config, incident_id: str, synthesis: dict, report_md: str) -> dict[str, str]:
    bucket = os.environ.get("FORENSICS_BUCKET") or ""
    if not bucket:
        logger.warning("FORENSICS_BUCKET not configured; skipping synthesis S3 write")
        return {}

    s3 = boto3.client("s3", region_name=config.region)
    timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
    prefix = f"incidents/{incident_id}/ai/{timestamp}"

    artifacts = {
        "report_uri": (f"{prefix}/synthesis-report.md", "text/markdown", report_md.encode("utf-8")),
        "synthesis_uri": (
            f"{prefix}/synthesis.json",
            "application/json",
            json.dumps(synthesis, ensure_ascii=False, default=str).encode("utf-8"),
        ),
        "timeline_uri": (
            f"{prefix}/timeline.json",
            "application/json",
            json.dumps(synthesis.get("timeline", []), ensure_ascii=False, default=str).encode("utf-8"),
        ),
        "iocs_uri": (
            f"{prefix}/iocs.json",
            "application/json",
            json.dumps(synthesis.get("iocs", []), ensure_ascii=False, default=str).encode("utf-8"),
        ),
        "ttps_uri": (
            f"{prefix}/ttps.json",
            "application/json",
            json.dumps(synthesis.get("ttps", []), ensure_ascii=False, default=str).encode("utf-8"),
        ),
    }

    uris: dict[str, str] = {}
    for name, (key, content_type, body) in artifacts.items():
        s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType=content_type)
        uris[name] = f"s3://{bucket}/{key}"

    return uris


def _update_incident(
    config: Config,
    incident_id: str,
    synthesis: dict,
    s3_uris: dict[str, str],
    parse_error: str | None,
) -> None:
    from app.shared.dynamodb import IncidentStore

    if not config.dynamodb_table_name or incident_id == "adhoc":
        return

    store = IncidentStore(table_name=config.dynamodb_table_name)
    store.update_incident(
        incident_id=incident_id,
        updates={
            "forensic_synthesis_status": "completed" if parse_error is None else "parse_error",
            "forensic_synthesis_uris": s3_uris,
            "forensic_synthesis_summary": synthesis.get("executive_summary", "")[:500],
            "forensic_synthesis_error": parse_error or "",
        },
    )
