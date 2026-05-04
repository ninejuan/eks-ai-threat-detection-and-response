import json
import logging
import os
from datetime import UTC, datetime

import boto3

from app.shared.config import Config

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    sfn_client = boto3.client("stepfunctions")

    records = event.get("Records", [])
    results = []

    for record in records:
        body = json.loads(record.get("body", "{}"))

        sns_message = body.get("Message")
        if sns_message:
            body = json.loads(sns_message)

        source = _detect_source(body)
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

        logger.info(
            "Started execution %s for %s event",
            response["executionArn"],
            source,
        )

        results.append(
            {
                "source": source,
                "execution_arn": response["executionArn"],
                "status": "started",
            }
        )

    return {"processed": len(results), "executions": results}


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
