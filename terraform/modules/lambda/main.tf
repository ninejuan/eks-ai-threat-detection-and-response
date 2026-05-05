locals {
  agents = {
    summary = {
      memory_size = 512
      timeout     = 30
      model_id    = "anthropic.claude-haiku-4.5-20250404-v1:0"
    }
    triage = {
      memory_size = 512
      timeout     = 30
      model_id    = "anthropic.claude-haiku-4.5-20250404-v1:0"
    }
    solution = {
      memory_size = 1024
      timeout     = 120
      model_id    = "anthropic.claude-sonnet-4-20250514-v1:0"
    }
    remediation = {
      memory_size = 1024
      timeout     = 180
      model_id    = "anthropic.claude-sonnet-4-20250514-v1:0"
    }
  }
}

resource "aws_security_group" "lambda" {
  name        = "${var.project}-sg-lambda"
  description = "Lambda agent security group"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.project}-sg-lambda"
  }
}

resource "aws_security_group_rule" "lambda_egress_https" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "HTTPS outbound for Bedrock, OpenSearch, AWS APIs"
  security_group_id = aws_security_group.lambda.id
}

resource "aws_lambda_layer_version" "dependencies" {
  layer_name          = "${var.project}-dependencies"
  filename            = "${path.module}/layer.zip"
  compatible_runtimes = ["python3.12"]

  lifecycle {
    ignore_changes = [filename, source_code_hash]
  }
}

resource "aws_lambda_function" "agent" {
  for_each = local.agents

  function_name = "${var.project}-${each.key}-agent"
  role          = var.execution_role_arn
  runtime       = "python3.12"
  handler       = "handler.lambda_handler"
  filename      = "${path.module}/placeholder.zip"
  timeout       = each.value.timeout
  memory_size   = each.value.memory_size
  layers        = [aws_lambda_layer_version.dependencies.arn]

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      AGENT_TYPE          = each.key
      BEDROCK_MODEL_ID    = each.value.model_id
      OPENSEARCH_ENDPOINT = var.opensearch_endpoint
      KNOWLEDGE_BASE_ID   = var.knowledge_base_id
      EKS_CLUSTER_NAME    = var.eks_cluster_name
      DYNAMODB_TABLE_NAME = var.dynamodb_table_name
      PROJECT             = var.project
      LOG_LEVEL           = "INFO"
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Name  = "${var.project}-${each.key}-agent"
    Agent = each.key
  }

  lifecycle {
    ignore_changes = [filename, source_code_hash]
  }
}

resource "aws_lambda_function" "ingestor" {
  function_name = "${var.project}-ingestor"
  role          = var.execution_role_arn
  runtime       = "python3.12"
  handler       = "handler.lambda_handler"
  filename      = "${path.module}/placeholder.zip"
  timeout       = 60
  memory_size   = 256
  layers        = [aws_lambda_layer_version.dependencies.arn]

  reserved_concurrent_executions = 2

  environment {
    variables = {
      STATE_MACHINE_ARN = aws_sfn_state_machine.agent_pipeline.arn
      PROJECT           = var.project
      LOG_LEVEL         = "INFO"
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Name = "${var.project}-ingestor"
  }

  lifecycle {
    ignore_changes = [filename, source_code_hash]
  }
}

resource "aws_lambda_function" "degraded_notifier" {
  function_name = "${var.project}-degraded-notifier"
  role          = var.execution_role_arn
  runtime       = "python3.12"
  handler       = "handler.lambda_handler"
  filename      = "${path.module}/placeholder.zip"
  timeout       = 30
  memory_size   = 256
  layers        = [aws_lambda_layer_version.dependencies.arn]

  environment {
    variables = {
      PROJECT   = var.project
      LOG_LEVEL = "INFO"
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Name = "${var.project}-degraded-notifier"
  }

  lifecycle {
    ignore_changes = [filename, source_code_hash]
  }
}

resource "aws_lambda_function" "approval_notifier" {
  function_name = "${var.project}-approval-notifier"
  role          = var.execution_role_arn
  runtime       = "python3.12"
  handler       = "handler.lambda_handler"
  filename      = "${path.module}/placeholder.zip"
  timeout       = 30
  memory_size   = 256
  layers        = [aws_lambda_layer_version.dependencies.arn]

  environment {
    variables = {
      PROJECT   = var.project
      LOG_LEVEL = "INFO"
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Name = "${var.project}-approval-notifier"
  }

  lifecycle {
    ignore_changes = [filename, source_code_hash]
  }
}

resource "aws_lambda_event_source_mapping" "sqs_ingestor" {
  event_source_arn = var.sqs_queue_arn
  function_name    = aws_lambda_function.ingestor.arn
  batch_size       = 1
  enabled          = true

  scaling_config {
    maximum_concurrency = 2
  }
}

resource "aws_sfn_state_machine" "agent_pipeline" {
  name     = "${var.project}-agent-pipeline"
  role_arn = var.step_functions_role_arn
  type     = "STANDARD"

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.step_functions.arn}:*"
    include_execution_data = true
    level                  = "ERROR"
  }

  tracing_configuration {
    enabled = true
  }

  definition = jsonencode({
    Comment = "ATDR AI Agent Pipeline"
    StartAt = "SummaryAgent"

    States = {
      SummaryAgent = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.agent["summary"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = {
          "body.$" = "$.Payload"
        }
        ResultPath = "$.summary"
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException", "Lambda.TooManyRequestsException", "States.Timeout"]
          IntervalSeconds = 2
          BackoffRate     = 2
          MaxAttempts     = 3
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "DegradedNotify"
          ResultPath  = "$.error"
        }]
        Next = "TriageAgent"
      }

      TriageAgent = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.agent["triage"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = {
          "body.$" = "$.Payload"
        }
        ResultPath = "$.triage"
        Retry = [{
          ErrorEquals     = ["States.ALL"]
          IntervalSeconds = 2
          BackoffRate     = 2
          MaxAttempts     = 2
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "DegradedNotify"
          ResultPath  = "$.error"
        }]
        Next = "CheckSeverity"
      }

      CheckSeverity = {
        Type = "Choice"
        Choices = [
          {
            Variable     = "$.triage.body.severity"
            StringEquals = "P4"
            Next         = "LogOnly"
          },
          {
            Variable     = "$.triage.body.severity"
            StringEquals = "P3"
            Next         = "SolutionAgent"
          }
        ]
        Default = "SolutionAgentWithApproval"
      }

      SolutionAgent = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.agent["solution"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = {
          "body.$" = "$.Payload"
        }
        ResultPath = "$.solution"
        Retry = [{
          ErrorEquals     = ["States.ALL"]
          IntervalSeconds = 5
          BackoffRate     = 2
          MaxAttempts     = 3
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "DegradedNotify"
          ResultPath  = "$.error"
        }]
        Next = "RemediationAgent"
      }

      SolutionAgentWithApproval = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.agent["solution"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = {
          "body.$" = "$.Payload"
        }
        ResultPath = "$.solution"
        Retry = [{
          ErrorEquals     = ["States.ALL"]
          IntervalSeconds = 5
          BackoffRate     = 2
          MaxAttempts     = 3
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "DegradedNotify"
          ResultPath  = "$.error"
        }]
        Next = "WaitForApproval"
      }

      WaitForApproval = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke.waitForTaskToken"
        Parameters = {
          FunctionName = aws_lambda_function.approval_notifier.arn
          Payload = {
            "execution.$"  = "$"
            "task_token.$" = "$$.Task.Token"
          }
        }
        TimeoutSeconds = 3600
        ResultPath     = "$.approval"
        Catch = [{
          ErrorEquals = ["States.Timeout"]
          Next        = "ApprovalTimeout"
          ResultPath  = "$.error"
        }]
        Next = "CheckApproval"
      }

      CheckApproval = {
        Type = "Choice"
        Choices = [{
          Variable     = "$.approval.decision"
          StringEquals = "approved"
          Next         = "RemediationAgent"
        }]
        Default = "RejectedEnd"
      }

      RemediationAgent = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.agent["remediation"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = {
          "body.$" = "$.Payload"
        }
        ResultPath = "$.remediation"
        Retry = [{
          ErrorEquals     = ["States.ALL"]
          IntervalSeconds = 5
          BackoffRate     = 2
          MaxAttempts     = 1
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "DegradedNotify"
          ResultPath  = "$.error"
        }]
        End = true
      }

      LogOnly = {
        Type = "Pass"
        End  = true
      }

      RejectedEnd = {
        Type = "Pass"
        End  = true
      }

      ApprovalTimeout = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.degraded_notifier.arn
          Payload = {
            "source.$"    = "$.source"
            "raw_event.$" = "$.raw_event"
            "error"       = { "Cause" = "Approval timed out after 1 hour" }
          }
        }
        End = true
      }

      DegradedNotify = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.degraded_notifier.arn
          "Payload.$"  = "$"
        }
        End = true
      }
    }
  })

  tags = {
    Name = "${var.project}-agent-pipeline"
  }
}

resource "aws_cloudwatch_log_group" "step_functions" {
  name              = "/aws/states/${var.project}-agent-pipeline"
  retention_in_days = 30

  tags = {
    Name = "${var.project}-sfn-logs"
  }
}
