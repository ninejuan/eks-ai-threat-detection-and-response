output "detector_id" {
  value = aws_guardduty_detector.this.id
}

output "event_rule_arn" {
  value = aws_cloudwatch_event_rule.guardduty_severity.arn
}
