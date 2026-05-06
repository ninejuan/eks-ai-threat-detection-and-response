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

variable "falco_k8saudit_role_arn" {
  description = "IAM role ARN for Falco k8saudit Pod Identity"
  type        = string
}

variable "external_secrets_role_arn" {
  description = "IAM role ARN for External Secrets Operator Pod Identity"
  type        = string
}

variable "mcp_server_role_arn" {
  description = "IAM role ARN for EKS MCP Server Pod Identity"
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

variable "aws_lb_controller_role_arn" {
  description = "IAM role ARN for AWS Load Balancer Controller Pod Identity"
  type        = string
}

variable "endpoint_public_access_cidrs" {
  description = "CIDR blocks allowed to access the EKS public endpoint"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "ebs_csi_role_arn" {
  description = "IAM role ARN for EBS CSI Driver Pod Identity"
  type        = string
}

variable "cilium_operator_role_arn" {
  description = "IAM role ARN for Cilium Operator Pod Identity (ENI mode)"
  type        = string
}

variable "tetragon_forwarder_role_arn" {
  description = "IAM role ARN for Tetragon SNS Forwarder Pod Identity"
  type        = string
}
