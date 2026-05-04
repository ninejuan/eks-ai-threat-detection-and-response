resource "aws_sns_topic" "falco_events" {
  name              = "${var.project}-falco-events"
  kms_master_key_id = var.kms_key_id
}

resource "aws_sqs_queue" "agent_dlq" {
  name                      = "${var.project}-agent-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue" "agent" {
  name                       = "${var.project}-agent"
  visibility_timeout_seconds = 360
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.agent_dlq.arn
    maxReceiveCount     = 3
  })
}

resource "aws_sns_topic_subscription" "agent" {
  topic_arn = aws_sns_topic.falco_events.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.agent.arn
}

data "aws_iam_policy_document" "agent_queue" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.agent.arn]
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_sns_topic.falco_events.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "agent" {
  queue_url = aws_sqs_queue.agent.id
  policy    = data.aws_iam_policy_document.agent_queue.json
}

resource "aws_cloudwatch_metric_alarm" "dlq_not_empty" {
  alarm_name          = "${var.project}-agent-dlq-not-empty"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.agent_dlq.name
  }
}
