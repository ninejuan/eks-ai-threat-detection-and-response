import hashlib
import json
import logging
import os
import time
from datetime import UTC, datetime

import boto3
from botocore.exceptions import ClientError

from app.shared.config import Config

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

DEDUP_WINDOW_SECONDS = 300
DEDUP_TABLE = os.environ.get("DEDUP_TABLE_NAME", "atdr-event-dedup")


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    sfn_client = boto3.client("stepfunctions")
    dedup_table = boto3.resource("dynamodb").Table(DEDUP_TABLE)

    records = event.get("Records", [])
    results = []

    for record in records:
        raw_body = record.get("body", "{}")
        body = json.loads(raw_body)

        sns_message = body.get("Message")
        if sns_message:
            if isinstance(sns_message, str):
                try:
                    body = json.loads(sns_message)
                except json.JSONDecodeError:
                    logger.warning("SNS message not valid JSON: %s", sns_message[:200])
                    body = {"raw": sns_message, "source": "unknown"}
            elif isinstance(sns_message, dict):
                body = sns_message

        source = _detect_source(body)
        dedup_key = _dedup_key(body, source)

        if _is_duplicate(dedup_table, dedup_key):
            logger.info("Deduplicated event: %s", dedup_key[:80])
            results.append({"source": source, "status": "deduplicated"})
            continue

        execution_name = f"{source}-{datetime.now(tz=UTC).strftime('%Y%m%d-%H%M%S-%f')}"

        workflow_input = {
            "raw_event": body,
            "source": source,
            "received_at": datetime.now(tz=UTC).isoformat(),
        }

        response = sfn_client.start_execution(
            stateMachineArn=config.state_machine_arn,
            name=execution_name[:80],
            input=json.dumps(workflow_input, default=str),
        )

        logger.info("Started execution %s for %s event", response["executionArn"], source)
        results.append({"source": source, "execution_arn": response["executionArn"], "status": "started"})

    return {"processed": len(results), "executions": results}


def _dedup_key(event: dict, source: str) -> str:
    if source == "tetragon":
        kprobe = event.get("process_kprobe", {})
        proc = kprobe.get("process", {})
        pod = proc.get("pod", {})
        policy = kprobe.get("policy_name", "unknown")
        pod_name = pod.get("name", "")
        ns = pod.get("namespace", "")
    elif source == "falco":
        policy = event.get("rule", "unknown")
        pod_name = event.get("output_fields", {}).get("k8s.pod.name", "")
        ns = event.get("output_fields", {}).get("k8s.ns.name", "")
    else:
        policy = event.get("detail", {}).get("type", "unknown")
        pod_name = ""
        ns = ""

    window = int(time.time()) // DEDUP_WINDOW_SECONDS
    raw = f"{source}|{policy}|{ns}|{pod_name}|{window}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _is_duplicate(table, dedup_key: str) -> bool:
    now = int(time.time())
    ttl = now + DEDUP_WINDOW_SECONDS * 2

    try:
        table.put_item(
            Item={"dedup_key": dedup_key, "ttl": ttl, "created_at": now},
            ConditionExpression="attribute_not_exists(dedup_key)",
        )
        return False
    except ClientError as error:
        if error.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return True
        raise


def _detect_source(event: dict) -> str:
    if "detail-type" in event and "GuardDuty" in event.get("detail-type", ""):
        return "guardduty"

    if event.get("source") == "aws.guardduty":
        return "guardduty"

    if "rule" in event and "output" in event:
        return "falco"

    if "process_kprobe" in event or "process_exec" in event:
        return "tetragon"

    return "unknown"
