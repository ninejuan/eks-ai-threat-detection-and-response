variable "project" {
  type = string
}

variable "region" {
  type = string
}

variable "bedrock_kb_role_arn" {
  type = string
}

variable "lambda_role_arn" {
  type = string
}

variable "admin_principal_arn" {
  description = "IAM principal ARN for OpenSearch index management (operator/admin)"
  type        = string
}

variable "embedding_model_arn" {
  type    = string
  default = null
}
