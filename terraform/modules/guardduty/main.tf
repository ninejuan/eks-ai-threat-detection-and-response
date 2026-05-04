locals {
  detector_name = "${var.project}-guardduty"
}

resource "aws_guardduty_detector" "this" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_guardduty_detector_feature" "eks_runtime_monitoring" {
  detector_id = aws_guardduty_detector.this.id
  name        = "EKS_RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = "ENABLED"
  }
}

resource "aws_guardduty_detector_feature" "kubernetes_audit_logs" {
  detector_id = aws_guardduty_detector.this.id
  name        = "EKS_AUDIT_LOGS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "malware_protection" {
  detector_id = aws_guardduty_detector.this.id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "ENABLED"
}

resource "aws_securityhub_account" "this" {
}

resource "aws_securityhub_finding_aggregator" "this" {
  linking_mode = "ALL_REGIONS"
}

resource "aws_cloudwatch_event_rule" "guardduty_severity" {
  name        = "${var.project}-guardduty-severity"
  description = "Forward GuardDuty findings with severity at or above 7"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_severity.name
  target_id = "${var.project}-guardduty-target"
  arn       = var.lambda_arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "${var.project}-guardduty-eventbridge"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_severity.arn
}
