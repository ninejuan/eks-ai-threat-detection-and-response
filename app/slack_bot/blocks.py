import json
from datetime import UTC, datetime


def status_blocks(cluster_name: str = "atdr-demo") -> list[dict]:
    now = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🛡️ ATDR System Status", "emoji": True},
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Cluster:*\n`{cluster_name}`"},
                {"type": "mrkdwn", "text": f"*Checked:*\n{now}"},
            ],
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": "*Detection:*\n✅ Falco + Tetragon"},
                {"type": "mrkdwn", "text": "*Remediation:*\n✅ MCP Server"},
            ],
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": "*RAG Knowledge Base:*\n✅ Active"},
                {"type": "mrkdwn", "text": "*Step Functions:*\n✅ Pipeline Ready"},
            ],
        },
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": "Use `/atdr incidents` to view recent security events."}],
        },
    ]


def incidents_blocks(incidents: list[dict] | None = None) -> list[dict]:
    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🚨 Recent Incidents", "emoji": True},
        },
        {"type": "divider"},
    ]

    if not incidents:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "_No incidents in the last 24 hours._ 🎉"},
            }
        )
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": "Incidents are created when Falco or GuardDuty detects a threat."}
                ],
            }
        )
        return blocks

    for inc in incidents[:10]:
        severity = inc.get("severity", "UNKNOWN")
        severity_emoji = {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "⚪"}.get(severity, "⚪")
        title = inc.get("title", "Untitled")
        incident_id = inc.get("incident_id", "?")
        status = inc.get("status", "open")
        created = inc.get("created_at", "?")

        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{severity_emoji} *{severity}* — {title}\n`{incident_id}` | Status: *{status}* | {created}"
                    ),
                },
            }
        )

    blocks.append({"type": "divider"})
    blocks.append(
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"Showing {len(incidents[:10])} most recent incidents."}],
        }
    )
    return blocks


def help_blocks() -> list[dict]:
    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🛡️ ATDR Bot", "emoji": True},
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    "*AI Threat Detection & Response for EKS*\n\n"
                    "ATDR monitors your EKS cluster for security threats using Falco, Tetragon, and GuardDuty. "
                    "When a threat is detected, AI agents analyze, triage, and recommend remediation actions — "
                    "with human approval before execution."
                ),
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    "*Commands:*\n"
                    "• `/atdr status` — System health check\n"
                    "• `/atdr incidents` — Recent security incidents\n"
                    "• `/atdr help` — This message"
                ),
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    "*DM & Mentions:*\n"
                    "You can also DM me or mention `@ATDR Bot` in a channel to ask about system status or incidents."
                ),
            },
        },
        {"type": "divider"},
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": "Powered by Bedrock Claude • MCP Remediation • EKS Pod Identity"}],
        },
    ]


def unknown_command_blocks(subcommand: str) -> list[dict]:
    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"❓ Unknown subcommand: `{subcommand}`\n\nTry `/atdr help` to see available commands.",
            },
        },
    ]


def message_response_blocks(text: str) -> list[dict]:
    return [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": text},
        },
    ]


def blocks_response(blocks: list[dict], ephemeral: bool = False) -> dict:
    body: dict = {"blocks": blocks}
    if ephemeral:
        body["response_type"] = "ephemeral"
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }
