import json
import re
import time
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from app.shared.slack_notifier import to_slack_mrkdwn

SEVERITY_META = {
    "P1": {"emoji": "🔴", "color": "danger", "label": "Critical"},
    "P2": {"emoji": "🟠", "color": "warning", "label": "High"},
    "P3": {"emoji": "🟡", "color": "warning", "label": "Medium"},
    "P4": {"emoji": "⚪", "color": "#9CA3AF", "label": "Low"},
}

MITRE_DESCRIPTIONS = {
    "T1496": "Resource Hijacking — adversaries abuse compute for mining or other resource-intensive tasks.",
    "T1611": "Escape to Host — adversaries break out of a container to access the host system.",
    "T1552.007": "Container and Resource Discovery — adversaries search containers for credentials and secrets.",
    "T1071.004": "DNS — adversaries communicate using DNS application-layer protocols.",
    "T1210": "Exploitation of Remote Services — adversaries exploit services for lateral movement.",
}

TIMELINE_STEPS = ["detected", "acknowledged", "triaged", "solution", "approved", "remediated", "resolved"]


def severity_emoji(severity: str | None) -> str:
    return SEVERITY_META.get((severity or "").upper(), {"emoji": "⚪"})["emoji"]


def severity_color(severity: str | None) -> str:
    return SEVERITY_META.get((severity or "").upper(), {"color": "#9CA3AF"})["color"]


def slack_date(value: Any, fallback: str = "unknown") -> str:
    timestamp = _epoch_seconds(value)
    if timestamp is None:
        return fallback
    return f"<!date^{timestamp}^{{date_short_pretty}} {{time}}|{fallback}>"


def status_blocks(cluster_name: str = "atdr-demo") -> list[dict]:
    now = slack_date(int(time.time()), "now")
    return [
        _header("🛡️ ATDR System Status"),
        {"type": "divider"},
        _fields_section(
            [
                ("Cluster", f"`{cluster_name}`"),
                ("Checked", now),
                ("Detection", "✅ Falco + Tetragon + GuardDuty"),
                ("Remediation", "✅ EKS MCP Server"),
                ("Workflow", "✅ Step Functions + Slack approval"),
                ("Storage", "✅ DynamoDB incident ledger"),
            ]
        ),
        _context("Use `/atdr incidents`, `/atdr report daily`, or `/atdr help` for operations."),
    ]


def incidents_blocks(incidents: list[dict] | None = None, title: str = "🚨 Recent Incidents") -> list[dict]:
    blocks: list[dict] = [_header(title), {"type": "divider"}]
    if not incidents:
        blocks.extend(
            [_section("_No matching incidents._ 🎉"), _context("Incidents appear after detection events land in ATDR.")]
        )
        return blocks

    for incident in incidents[:10]:
        blocks.extend(incident_card_blocks(incident, include_actions=True, compact=True))

    blocks.append(_context(f"Showing {len(incidents[:10])} incident(s). Use `/atdr incident <id>` for full details."))
    return _trim_blocks(blocks)


def incident_card_blocks(incident: dict, include_actions: bool = True, compact: bool = False) -> list[dict]:
    incident_id = str(incident.get("incident_id", "unknown"))
    severity = str(incident.get("severity", "UNKNOWN")).upper()
    title = to_slack_mrkdwn(str(incident.get("title") or incident.get("summary") or "Security incident"))
    status = str(incident.get("status", "detected"))
    source = str(incident.get("source", "unknown"))
    created = slack_date(incident.get("created_at"), "created")
    mitre = _mitre_text(incident)
    resources = _resource_summary(incident)

    text = (
        f"{severity_emoji(severity)} *{severity}* — *{title}*\n"
        f"`{incident_id}` | Status: *{status}* | Source: `{source}` | {created}"
    )
    blocks = [_section(text)]
    fields = [("MITRE ATT&CK", mitre), ("Affected resources", resources)]
    if not compact:
        fields.extend(
            [("Summary", _truncate(to_slack_mrkdwn(str(incident.get("summary", "No summary available"))), 500))]
        )
    blocks.append(_fields_section(fields))
    if include_actions:
        blocks.append(_incident_actions(incident_id))
    blocks.append({"type": "divider"})
    return blocks


def incident_detail_blocks(incident: dict | None, error: str | None = None) -> list[dict]:
    if error:
        return error_blocks("Incident detail unavailable", error)
    if not incident:
        return error_blocks("Incident not found", "No incident matched that ID.")

    blocks = [_header(f"{severity_emoji(incident.get('severity'))} Incident Detail"), {"type": "divider"}]
    blocks.extend(incident_card_blocks(incident, include_actions=True, compact=False))
    blocks.extend(timeline_blocks(incident, title="Timeline"))
    blocks.extend(ioc_blocks(incident, title="Indicators of Compromise"))
    blocks.extend(evidence_blocks(incident, title="Forensic Evidence"))
    blocks.extend(remediation_log_blocks(incident))
    return _trim_blocks(blocks)


def timeline_blocks(incident: dict, title: str = "Incident Timeline") -> list[dict]:
    events = _timeline_events(incident)
    blocks = [_header(f"🕒 {title}")]
    if not events:
        blocks.append(_section("_No timeline events recorded yet._"))
        return blocks

    lines = []
    for name, when, actor in events:
        marker = "✅" if when else "⬜"
        label = name.replace("_", " ").title()
        suffix = f" — {slack_date(when, label)}" if when else ""
        if actor:
            suffix += f" by {actor}"
        lines.append(f"{marker} *{label}*{suffix}")
    blocks.append(_section("\n".join(lines)))
    return blocks


def ioc_blocks(incident: dict, title: str = "IOCs") -> list[dict]:
    indicators = extract_iocs(incident)
    blocks = [_header(f"🧬 {title}")]
    if not any(indicators.values()):
        blocks.append(_section("_No IOCs captured for this incident._"))
        return blocks

    fields = []
    for label, values in indicators.items():
        if values:
            fields.append((label.replace("_", " ").title(), "\n".join(f"`{value}`" for value in values[:8])))
    blocks.append(_fields_section(fields))
    blocks.append(_context("Share IOCs with `/atdr ioc <id>` when coordinating containment."))
    return blocks


def evidence_blocks(incident: dict, signed_urls: list[str] | None = None, title: str = "Evidence") -> list[dict]:
    evidence = signed_urls or extract_evidence_uris(incident)
    blocks = [_header(f"📦 {title}")]
    if not evidence:
        blocks.append(_section("_No forensic S3 evidence recorded yet._"))
        return blocks
    lines = []
    for uri in evidence[:10]:
        display = _truncate(str(uri), 120)
        lines.append(f"• `{display}`" if str(uri).startswith("s3://") else f"• <{uri}|Open evidence>")
    blocks.append(_section("\n".join(lines)))
    return blocks


def remediation_log_blocks(incident: dict) -> list[dict]:
    logs = (
        incident.get("execution_log")
        or incident.get("remediation_log")
        or incident.get("remediation", {}).get("execution_log")
        or []
    )
    blocks = [_header("🛠️ Remediation Execution Log")]
    if not logs:
        blocks.append(_section("_No remediation tools have run yet._"))
        return blocks
    lines = []
    for entry in logs[:10]:
        tool = entry.get("tool") or entry.get("name") or entry.get("action") or "unknown_tool"
        status = entry.get("status") or entry.get("result") or "unknown"
        marker = "✅" if str(status).lower() in {"success", "succeeded", "ok"} else "❌"
        detail = entry.get("error") or entry.get("message") or entry.get("target") or ""
        lines.append(f"{marker} `{tool}` — *{status}* {to_slack_mrkdwn(str(detail))}".strip())
    blocks.append(_section("\n".join(lines)))
    return blocks


def report_summary_blocks(report: dict, period: str) -> list[dict]:
    stats = report.get("stats", {})
    severity_counts = stats.get("by_severity", {})
    techniques = stats.get("top_mitre", [])
    blocks = [_header(f"📊 ATDR {period.title()} Security Report"), {"type": "divider"}]
    blocks.append(
        _fields_section(
            [
                ("Total incidents", str(stats.get("total", 0))),
                ("Active", str(stats.get("active", 0))),
                ("Resolved", str(stats.get("resolved", 0))),
                ("Mean TTA", _duration(stats.get("mean_time_to_acknowledge_seconds"))),
                ("Mean TTR", _duration(stats.get("mean_time_to_resolve_seconds"))),
                ("Window", report.get("window", period)),
            ]
        )
    )
    severity_text = "\n".join(
        f"{severity_emoji(sev)} *{sev}:* {severity_counts.get(sev, 0)}" for sev in ["P1", "P2", "P3", "P4"]
    )
    technique_text = "\n".join(f"• `{tech}` — {count}" for tech, count in techniques[:5]) or "_No techniques observed._"
    blocks.extend(
        [_section(f"*Severity breakdown*\n{severity_text}"), _section(f"*Top MITRE techniques*\n{technique_text}")]
    )
    if report.get("trend"):
        blocks.append(_section("*7-day trend*\n" + "\n".join(report["trend"][:7])))
    blocks.append(_context(f"Generated {slack_date(int(time.time()), 'now')}."))
    return _trim_blocks(blocks)


def oncall_blocks(oncall: str, channel: str) -> list[dict]:
    return [
        _header("📟 ATDR On-call"),
        _fields_section([("Primary", oncall or "Not configured"), ("Channel", channel or "Not configured")]),
    ]


def action_result_blocks(title: str, incident_id: str, message: str) -> list[dict]:
    return [
        _header(title),
        _section(f"`{incident_id}`\n{to_slack_mrkdwn(message)}"),
        _context(f"Recorded {slack_date(int(time.time()), 'now')}."),
    ]


def help_blocks() -> list[dict]:
    return [
        _header("🛡️ ATDR Bot"),
        {"type": "divider"},
        _section(
            "*AI Threat Detection & Response for EKS*\n"
            "ATDR supports SOC triage, on-call workflow, evidence sharing, and MCP-backed remediation approvals."
        ),
        _section(
            "*Core*\n"
            "• `/atdr status` — System health\n"
            "• `/atdr incidents [open|P1|P2|P3|P4]` — Incident queue\n"
            "• `/atdr incident <id>` — Full incident detail\n"
            "• `/atdr help` — This guide"
        ),
        _section(
            "*On-call*\n"
            "• `/atdr oncall` — Current responder\n"
            "• `/atdr ack <id>` — Acknowledge\n"
            "• `/atdr assign <id> @user` — Assign owner\n"
            "• `/atdr escalate <id>` — Escalate\n"
            "• `/atdr resolve <id> [note]` — Resolve with note"
        ),
        _section(
            "*Security support*\n"
            "• `/atdr ioc <id>` — Extract IOCs\n"
            "• `/atdr evidence <id>` — Forensic S3 evidence links\n"
            "• `/atdr timeline <id>` — Incident timeline\n"
            "• `/atdr guide <category>` — Runbook summary\n"
            "• `/atdr report daily|weekly` — Security report"
        ),
        _context("Powered by Bedrock Claude • EKS MCP • EKS Pod Identity"),
    ]


def unknown_command_blocks(subcommand: str) -> list[dict]:
    return [
        _section(f"❓ Unknown subcommand: `{subcommand}`\n\nTry `/atdr help` to see available commands."),
    ]


def message_response_blocks(text: str) -> list[dict]:
    return [_section(to_slack_mrkdwn(text))]


def error_blocks(title: str, detail: str) -> list[dict]:
    return [_header(f"⚠️ {title}"), _section(to_slack_mrkdwn(detail))]


def blocks_response(blocks: list[dict], ephemeral: bool = False) -> dict:
    body: dict = {"blocks": _trim_blocks(blocks)}
    if ephemeral:
        body["response_type"] = "ephemeral"
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"}, "body": json.dumps(body)}


def extract_iocs(incident: dict) -> dict[str, list[str]]:
    raw = incident.get("raw_indicators") or incident.get("indicators") or {}
    text = json.dumps(raw, ensure_ascii=False) if isinstance(raw, (dict, list)) else str(raw)
    return {
        "ips": sorted(set(re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", text))),
        "domains": sorted(set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text))),
        "file_hashes": sorted(set(re.findall(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b", text))),
    }


def extract_evidence_uris(incident: dict) -> list[str]:
    text = json.dumps(incident, ensure_ascii=False)
    uris = set(re.findall(r"s3://[^\s\"'<>]+", text))
    for key in ["evidence_uris", "forensic_evidence", "checkpoint_pod", "capture_hubble_flows"]:
        value = incident.get(key)
        if isinstance(value, str) and value.startswith("s3://"):
            uris.add(value)
        elif isinstance(value, list):
            uris.update(str(item) for item in value if str(item).startswith("s3://"))
        elif isinstance(value, dict):
            uris.update(extract_evidence_uris(value))
    return sorted(uris)


def build_stats_from_incidents(incidents: list[dict]) -> dict:
    by_severity = Counter(str(inc.get("severity", "UNKNOWN")).upper() for inc in incidents)
    active_statuses = {"detected", "acknowledged", "investigating", "open", "triaged"}
    resolved_statuses = {"resolved", "remediated", "closed"}
    active = sum(1 for inc in incidents if str(inc.get("status", "detected")).lower() in active_statuses)
    resolved = sum(1 for inc in incidents if str(inc.get("status", "")).lower() in resolved_statuses)
    top_mitre = Counter(_mitre_ids(inc)[0] for inc in incidents if _mitre_ids(inc)).most_common(5)
    return {
        "total": len(incidents),
        "by_severity": dict(by_severity),
        "active": active,
        "resolved": resolved,
        "top_mitre": top_mitre,
        "mean_time_to_acknowledge_seconds": _mean_transition(incidents, "created_at", "acknowledged_at"),
        "mean_time_to_resolve_seconds": _mean_transition(incidents, "created_at", "resolved_at"),
    }


def _header(text: str) -> dict:
    return {"type": "header", "text": {"type": "plain_text", "text": text[:150], "emoji": True}}


def _section(text: str) -> dict:
    return {"type": "section", "text": {"type": "mrkdwn", "text": _truncate(to_slack_mrkdwn(text), 2900)}}


def _fields_section(fields: list[tuple[str, Any]]) -> dict:
    return {
        "type": "section",
        "fields": [
            {
                "type": "mrkdwn",
                "text": f"*{to_slack_mrkdwn(str(label))}:*\n{_truncate(to_slack_mrkdwn(str(value)), 1900)}",
            }
            for label, value in fields[:10]
        ],
    }


def _context(text: str) -> dict:
    return {"type": "context", "elements": [{"type": "mrkdwn", "text": _truncate(to_slack_mrkdwn(text), 1900)}]}


def _incident_actions(incident_id: str) -> dict:
    return {
        "type": "actions",
        "elements": [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Acknowledge"},
                "action_id": "ack_incident",
                "value": incident_id,
                "style": "primary",
            },
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Investigate"},
                "action_id": "investigate_incident",
                "value": incident_id,
            },
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Escalate"},
                "action_id": "escalate_incident",
                "value": incident_id,
                "style": "danger",
            },
        ],
    }


def _resource_summary(incident: dict) -> str:
    resources = incident.get("affected_resources") or incident.get("resources") or []
    if not resources:
        pod = incident.get("pod") or incident.get("pod_name")
        node = incident.get("node") or incident.get("node_name")
        namespace = incident.get("namespace")
        resources = [
            value
            for value in [
                f"pod/{pod}" if pod else None,
                f"node/{node}" if node else None,
                f"ns/{namespace}" if namespace else None,
            ]
            if value
        ]
    if isinstance(resources, str):
        return f"`{resources}`"
    return "\n".join(f"`{item}`" for item in resources[:6]) or "Not recorded"


def _mitre_text(incident: dict) -> str:
    ids = _mitre_ids(incident)
    if not ids:
        return "Not mapped"
    return "\n".join(f"`{tech}` — {MITRE_DESCRIPTIONS.get(tech, 'Technique details unavailable')}" for tech in ids[:3])


def _mitre_ids(incident: dict) -> list[str]:
    candidates = (
        incident.get("mitre")
        or incident.get("mitre_attack")
        or incident.get("technique")
        or incident.get("technique_id")
        or []
    )
    if isinstance(candidates, dict):
        candidates = list(candidates.values())
    if isinstance(candidates, str):
        candidates = [candidates]
    text = " ".join(str(item) for item in candidates)
    return sorted(set(re.findall(r"T\d{4}(?:\.\d{3})?", text)))


def _timeline_events(incident: dict) -> list[tuple[str, Any, str]]:
    explicit = incident.get("timeline") or []
    events = []
    if isinstance(explicit, list):
        for event in explicit:
            if isinstance(event, dict):
                events.append(
                    (
                        str(event.get("step") or event.get("status") or "event"),
                        event.get("at") or event.get("timestamp"),
                        str(event.get("actor", "")),
                    )
                )
    for step in TIMELINE_STEPS:
        when = incident.get(f"{step}_at") or (incident.get("created_at") if step == "detected" else None)
        actor = str(incident.get(f"{step}_by", ""))
        if when or not events:
            events.append((step, when, actor))
    return events


def _epoch_seconds(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int | float):
        return int(value)
    if isinstance(value, datetime):
        return int(value.timestamp())
    text = str(value).replace("Z", "+00:00")
    try:
        return int(float(text))
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return int(parsed.timestamp())
    except ValueError:
        return None


def _mean_transition(incidents: list[dict], start_key: str, end_key: str) -> int | None:
    durations = []
    for inc in incidents:
        start = _epoch_seconds(inc.get(start_key))
        end = _epoch_seconds(inc.get(end_key))
        if start and end and end >= start:
            durations.append(end - start)
    return int(sum(durations) / len(durations)) if durations else None


def _duration(seconds: Any) -> str:
    if seconds is None:
        return "n/a"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _trim_blocks(blocks: list[dict]) -> list[dict]:
    return blocks[:50]
