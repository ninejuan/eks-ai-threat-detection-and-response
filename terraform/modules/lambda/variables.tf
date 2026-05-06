variable "project" {
  description = "Project name for resource naming"
  type        = string
}

variable "region" {
  description = "AWS region"
  type        = string
}

variable "bedrock_fast_model_id" {
  description = "Bedrock model ID for fast/cheap agents (summary, triage)"
  type        = string
}

variable "bedrock_smart_model_id" {
  description = "Bedrock model ID for smart/expensive agents (solution, remediation)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for Lambda security group"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for Lambda VPC config"
  type        = list(string)
}

variable "execution_role_arn" {
  description = "IAM role ARN for Lambda execution"
  type        = string
}

variable "step_functions_role_arn" {
  description = "IAM role ARN for Step Functions"
  type        = string
}

variable "sqs_queue_arn" {
  description = "SQS queue ARN for event source mapping"
  type        = string
}

variable "sns_topic_arn" {
  description = "SNS topic ARN for Slack notifications"
  type        = string
  default     = ""
}

variable "opensearch_endpoint" {
  description = "OpenSearch Serverless endpoint"
  type        = string
  default     = ""
}

variable "knowledge_base_id" {
  description = "Bedrock Knowledge Base ID"
  type        = string
  default     = ""
}

variable "eks_cluster_name" {
  description = "EKS cluster name for Remediation Agent"
  type        = string
}

variable "dynamodb_table_name" {
  description = "DynamoDB table name for incident records"
  type        = string
}

variable "mcp_auth_secret_id" {
  description = "Secrets Manager secret ID for the EKS MCP bearer token"
  type        = string
  default     = "atdr/mcp/auth-token"
}

variable "mcp_server_url_secret_id" {
  description = "Secrets Manager secret ID containing the private EKS MCP server URL"
  type        = string
  default     = "atdr/mcp/server-url"
}

variable "forensics_bucket_name" {
  description = "Name of the forensics S3 bucket where evidence manifests and synthesis reports are written"
  type        = string
}
