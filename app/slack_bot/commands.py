import json
import logging
import os
from urllib.parse import parse_qs

import boto3

from app.shared.config import Config
from app.shared.dynamodb import IncidentStore
from app.slack_bot.blocks import (
    blocks_response,
    error_blocks,
    evidence_blocks,
    help_blocks,
    incident_detail_blocks,
    incidents_blocks,
    ioc_blocks,
    status_blocks,
    timeline_blocks,
    unknown_command_blocks,
)
from app.slack_bot.oncall import (
    ack_response,
    assign_response,
    escalate_response,
    oncall_response,
    resolve_response,
)
from app.slack_bot.reports import report_response

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def handle_commands(body: str, config: Config) -> dict:
    parsed = parse_qs(body)
    command = parsed.get("command", [""])[0]
    text = parsed.get("text", [""])[0]

    if command == "/atdr":
        return _dispatch_atdr(text, config)

    return blocks_response(unknown_command_blocks(command))


def _dispatch_atdr(text: str, config: Config) -> dict:  # noqa: PLR0911, PLR0912
    parts = text.strip().split(maxsplit=1)
    subcommand = parts[0].lower() if parts else "help"
    rest = parts[1] if len(parts) > 1 else ""

    if subcommand == "status":
        return blocks_response(status_blocks(config.eks_cluster_name))
    if subcommand == "incidents":
        return _incidents_response(config, rest)
    if subcommand == "incident":
        return _incident_detail_response(config, rest)
    if subcommand == "oncall":
        return oncall_response(config)
    if subcommand == "ack":
        return ack_response(config, rest.strip())
    if subcommand == "resolve":
        incident_id, note = _split_id_and_rest(rest)
        return resolve_response(config, incident_id, note)
    if subcommand == "assign":
        incident_id, assignee = _split_id_and_rest(rest)
        return assign_response(config, incident_id, assignee)
    if subcommand == "escalate":
        return escalate_response(config, rest.strip())
    if subcommand == "remediate":
        return _remediate_response(config, rest.strip())
    if subcommand == "report":
        return report_response(config, rest.strip() or "daily")
    if subcommand == "ioc":
        return _ioc_response(config, rest)
    if subcommand == "evidence":
        return _evidence_response(config, rest)
    if subcommand == "timeline":
        return _timeline_response(config, rest)
    if subcommand == "guide":
        return _guide_response(rest)
    if subcommand == "help":
        return blocks_response(help_blocks())

    return blocks_response(unknown_command_blocks(subcommand))


def _incidents_response(config: Config, filter_text: str = "") -> dict:
    try:
        store = IncidentStore(config.dynamodb_table_name)
        filter_value = filter_text.strip()
        if filter_value.upper() in {"P1", "P2", "P3", "P4"}:
            incidents = store.get_by_severity(filter_value, limit=10)
            title = f"🚨 {filter_value.upper()} Incidents"
        elif filter_value:
            incidents = store.get_by_status(filter_value.lower(), limit=10)
            title = f"🚨 {filter_value.title()} Incidents"
        else:
            incidents = store.recent(limit=10)
            title = "🚨 Recent Incidents"
    except Exception as error:
        logger.warning("Failed to fetch incidents: %s", error)
        incidents = None
        title = "🚨 Recent Incidents"

    return blocks_response(incidents_blocks(incidents, title=title))


def _incident_detail_response(config: Config, incident_id: str) -> dict:
    incident, error = _get_incident(config, incident_id.strip())
    return blocks_response(incident_detail_blocks(incident, error), ephemeral=bool(error))


def _ioc_response(config: Config, incident_id: str) -> dict:
    incident, error = _get_incident(config, incident_id.strip())
    if error:
        return blocks_response(error_blocks("IOC lookup failed", error), ephemeral=True)
    return blocks_response(ioc_blocks(incident or {}))


def _evidence_response(config: Config, incident_id: str) -> dict:
    incident, error = _get_incident(config, incident_id.strip())
    if error:
        return blocks_response(error_blocks("Evidence lookup failed", error), ephemeral=True)
    signed = _presign_evidence(incident or {})
    return blocks_response(evidence_blocks(incident or {}, signed_urls=signed))


def _timeline_response(config: Config, incident_id: str) -> dict:
    incident, error = _get_incident(config, incident_id.strip())
    if error:
        return blocks_response(error_blocks("Timeline lookup failed", error), ephemeral=True)
    return blocks_response(timeline_blocks(incident or {}))


def _guide_response(category: str) -> dict:
    guides = {
        "cryptomining": (
            "Validate CPU/network spikes, quarantine pod via approved remediation, preserve process snapshot, "
            "then rotate exposed credentials."
        ),
        "privilege": (
            "Preserve checkpoint evidence, inspect hostPath/capabilities, isolate workload, "
            "and review admission policy gaps."
        ),
        "secrets": (
            "Identify accessed secrets, revoke tokens, rotate credentials, and audit pod/service account permissions."
        ),
        "dns": "Capture Hubble flows, block egress, inspect domains, and add IOC domains to DNS controls.",
        "lateral": (
            "Map source and target services, isolate source namespace, review network policies, "
            "and hunt for reused credentials."
        ),
    }
    key = category.strip().lower()
    text = guides.get(key) or "Available categories: `cryptomining`, `privilege`, `secrets`, `dns`, `lateral`."
    return blocks_response(error_blocks(f"Runbook: {key or 'category'}", text))


def _get_incident(config: Config, incident_id: str) -> tuple[dict | None, str | None]:
    if not incident_id:
        return None, "Provide an incident ID."
    try:
        incident = IncidentStore(config.dynamodb_table_name).get_incident(incident_id)
    except Exception as error:
        logger.warning("Failed to fetch incident %s: %s", incident_id, error)
        return None, "DynamoDB is unavailable. Try again later."
    if not incident:
        return None, "No incident matched that ID."
    return incident, None


def _presign_evidence(incident: dict) -> list[str]:
    from app.slack_bot.blocks import extract_evidence_uris

    uris = extract_evidence_uris(incident)
    if not uris:
        return []
    try:
        s3 = boto3.client("s3")
        signed = []
        for uri in uris[:10]:
            bucket_key = uri.removeprefix("s3://").split("/", 1)
            if len(bucket_key) != 2:
                signed.append(uri)
                continue
            signed.append(
                s3.generate_presigned_url(
                    "get_object", Params={"Bucket": bucket_key[0], "Key": bucket_key[1]}, ExpiresIn=900
                )
            )
        return signed
    except Exception as error:
        logger.warning("Failed to presign evidence URLs: %s", error)
        return uris


def _split_id_and_rest(text: str) -> tuple[str, str]:
    parts = text.strip().split(maxsplit=1)
    return (parts[0], parts[1] if len(parts) > 1 else "") if parts else ("", "")


def _remediate_response(config: Config, incident_id: str) -> dict:
    if not incident_id:
        return blocks_response(
            [{"type": "section", "text": {"type": "mrkdwn", "text": "❌ Usage: `/atdr remediate <incident_id>`"}}],
            ephemeral=True,
        )

    try:
        store = IncidentStore(config.dynamodb_table_name)
        incident = store.get_incident(incident_id)
    except Exception:
        return blocks_response(
            [{"type": "section", "text": {"type": "mrkdwn", "text": "❌ Could not fetch incident from DynamoDB."}}],
            ephemeral=True,
        )

    if not incident:
        return blocks_response(
            [{"type": "section", "text": {"type": "mrkdwn", "text": f"❌ Incident `{incident_id}` not found."}}],
            ephemeral=True,
        )

    task_token = incident.get("task_token", "")

    if task_token:
        try:
            import boto3

            sfn = boto3.client("stepfunctions")
            sfn.send_task_success(
                taskToken=task_token,
                output=json.dumps(
                    {"decision": "approved", "approved_by": "manual_remediate", "source": "/atdr remediate"}
                ),
            )
            store.update_incident(incident_id, {"status": "remediation_approved"})
            return blocks_response(
                [
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"✅ Remediation approved for `{incident_id}`"},
                    },
                    {
                        "type": "context",
                        "elements": [{"type": "mrkdwn", "text": "Step Functions pipeline will execute remediation."}],
                    },
                ]
            )
        except Exception as error:
            logger.warning("SendTaskSuccess failed for %s: %s", incident_id, error)
            return _invoke_remediation_directly(config, incident_id, incident)
    else:
        return _invoke_remediation_directly(config, incident_id, incident)


def _invoke_remediation_directly(config: Config, incident_id: str, incident: dict) -> dict:
    try:
        import boto3

        lambda_client = boto3.client("lambda")
        payload = json.dumps(
            {
                "incident_id": incident_id,
                "summary": incident,
                "source": "manual_remediate",
            },
            default=str,
        )
        lambda_client.invoke(
            FunctionName=f"{config.project}-remediation-agent",
            InvocationType="Event",
            Payload=payload.encode(),
        )
        from app.shared.dynamodb import IncidentStore

        IncidentStore(config.dynamodb_table_name).update_incident(incident_id, {"status": "remediation_triggered"})
        return blocks_response(
            [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"⚡ Remediation triggered directly for `{incident_id}`"},
                },
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": "Task token expired. Remediation Agent invoked directly."}],
                },
            ]
        )
    except Exception as error:
        logger.warning("Direct remediation invoke failed for %s: %s", incident_id, error)
        return blocks_response(
            [{"type": "section", "text": {"type": "mrkdwn", "text": f"❌ Failed to trigger remediation: {error}"}}],
            ephemeral=True,
        )
