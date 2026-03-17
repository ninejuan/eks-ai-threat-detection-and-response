variable "environment" {
  description = "Deployment environment identifier (e.g. dev, staging, prod)."
  type        = string
}

variable "project_name" {
  description = "Human-friendly project name used for tagging."
  type        = string
}

variable "region" {
  description = "AWS region where the infrastructure is provisioned."
  type        = string
}

variable "prefix" {
  description = "Global resource prefix applied to all names."
  type        = string
}