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
