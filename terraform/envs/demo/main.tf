data "aws_caller_identity" "current" {}

locals {
  common_tags = {
    Environment = var.environment
    Project     = var.project_name
    ManagedBy   = "Sigmoid"
  }
}

module "nested_module" {
  source = "../../modules/nested_module"
}