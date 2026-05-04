output "sns_topic_arn" {
  value = aws_sns_topic.falco_events.arn
}

output "sqs_queue_arn" {
  value = aws_sqs_queue.agent.arn
}

output "sqs_queue_url" {
  value = aws_sqs_queue.agent.id
}

output "dlq_arn" {
  value = aws_sqs_queue.agent_dlq.arn
}
