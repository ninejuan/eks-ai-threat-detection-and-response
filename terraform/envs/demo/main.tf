data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  common_tags = {
    Environment = var.environment
    Project     = var.project_name
    ManagedBy   = "terraform"
  }
}

module "kms" {
  source = "../../modules/kms"

  project         = var.project_name
  account_id      = local.account_id
  lambda_role_arn = module.iam.lambda_agent_role_arn
}

module "s3" {
  source = "../../modules/s3"

  project     = var.project_name
  account_id  = local.account_id
  kms_key_arn = module.kms.key_arn
}

module "vpc" {
  source = "../../modules/vpc"

  project            = var.project_name
  vpc_cidr           = "10.0.0.0/16"
  availability_zones = ["ap-northeast-2a", "ap-northeast-2c"]
  log_bucket_arn     = module.s3.logs_bucket_arn
}

module "iam" {
  source = "../../modules/iam"

  project = var.project_name
  region  = var.region
}

module "eks" {
  source = "../../modules/eks"

  cluster_name              = "${var.project_name}-${var.environment}"
  cluster_role_arn          = module.iam.eks_cluster_role_arn
  node_role_arn             = module.iam.eks_node_role_arn
  admin_role_arn            = module.iam.eks_cluster_role_arn
  falco_pod_role_arn        = module.iam.falco_pod_role_arn
  external_secrets_role_arn = module.iam.external_secrets_role_arn
  vpc_id                    = module.vpc.vpc_id
  private_subnet_ids        = module.vpc.private_subnet_ids
}

module "sns_sqs" {
  source = "../../modules/sns-sqs"

  project    = var.project_name
  kms_key_id = module.kms.key_id
}

module "guardduty" {
  source = "../../modules/guardduty"

  project              = var.project_name
  lambda_arn           = module.lambda.ingestor_function_arn
  lambda_function_name = module.lambda.ingestor_function_name
}

module "opensearch" {
  source = "../../modules/opensearch"

  project             = var.project_name
  bedrock_kb_role_arn = module.iam.bedrock_kb_role_arn
  lambda_role_arn     = module.iam.lambda_agent_role_arn
}

module "lambda" {
  source = "../../modules/lambda"

  project                 = var.project_name
  region                  = var.region
  vpc_id                  = module.vpc.vpc_id
  private_subnet_ids      = module.vpc.private_subnet_ids
  execution_role_arn      = module.iam.lambda_agent_role_arn
  step_functions_role_arn = module.iam.step_functions_role_arn
  sqs_queue_arn           = module.sns_sqs.sqs_queue_arn
  opensearch_endpoint     = module.opensearch.collection_endpoint
}

module "slack" {
  source = "../../modules/slack"

  project             = var.project_name
  execution_role_arn  = module.iam.lambda_agent_role_arn
  dynamodb_table_name = aws_dynamodb_table.incidents.name
}

resource "aws_dynamodb_table" "incidents" {
  name         = "${var.project_name}-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = module.kms.key_arn
  }

  tags = {
    Name = "${var.project_name}-incidents"
  }
}

resource "aws_dynamodb_table" "approval_audit" {
  name         = "${var.project_name}-approval-audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "approval_id"

  attribute {
    name = "approval_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = module.kms.key_arn
  }

  tags = {
    Name = "${var.project_name}-approval-audit"
  }
}

resource "aws_secretsmanager_secret" "slack_bot_token" {
  name = "${var.project_name}/slack/bot-token"

  tags = {
    Name = "${var.project_name}-slack-bot-token"
  }
}

resource "aws_secretsmanager_secret" "slack_signing_secret" {
  name = "${var.project_name}/slack/signing-secret"

  tags = {
    Name = "${var.project_name}-slack-signing-secret"
  }
}

resource "aws_secretsmanager_secret" "mcp_auth_token" {
  name = "${var.project_name}/mcp/auth-token"

  tags = {
    Name = "${var.project_name}-mcp-auth-token"
  }
}
