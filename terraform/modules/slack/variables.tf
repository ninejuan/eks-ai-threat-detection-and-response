variable "project" {
  description = "Project name for resource naming"
  type        = string
}

variable "execution_role_arn" {
  description = "IAM role ARN for Slack bot Lambda"
  type        = string
}

variable "dynamodb_table_name" {
  description = "DynamoDB table name for incident/approval state"
  type        = string
  default     = ""
}

variable "lambda_layer_arn" {
  description = "Lambda layer ARN for shared dependencies"
  type        = string
  default     = ""
}
