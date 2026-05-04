variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
}

variable "cluster_role_arn" {
  description = "IAM role ARN for EKS cluster"
  type        = string
}

variable "node_role_arn" {
  description = "IAM role ARN for EKS node groups"
  type        = string
}

variable "admin_role_arn" {
  description = "IAM role ARN for cluster admin access"
  type        = string
}

variable "falco_pod_role_arn" {
  description = "IAM role ARN for Falcosidekick Pod Identity"
  type        = string
}

variable "external_secrets_role_arn" {
  description = "IAM role ARN for External Secrets Operator Pod Identity"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for EKS"
  type        = list(string)
}
