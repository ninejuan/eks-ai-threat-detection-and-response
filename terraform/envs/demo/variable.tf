variable "environment" {
  description = "Deployment environment (e.g. demo, dev, prod)"
  type        = string
  default     = "demo"
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "atdr"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "ap-northeast-2"
}

variable "endpoint_public_access_cidrs" {
  description = "CIDR blocks allowed to access the EKS public endpoint (e.g. team IPs)"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}
