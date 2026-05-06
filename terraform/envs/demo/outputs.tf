output "account_id" {
  value = local.account_id
}

output "region" {
  value = var.region
}

output "vpc_id" {
  value = module.vpc.vpc_id
}

output "vpc_cidr" {
  value = module.vpc.vpc_cidr
}

output "eks_cluster_name" {
  value = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  value     = module.eks.cluster_endpoint
  sensitive = true
}

output "state_machine_arn" {
  value = module.lambda.state_machine_arn
}

output "slack_api_endpoint" {
  value = module.slack.api_endpoint
}

output "guardduty_detector_id" {
  value = module.guardduty.detector_id
}

output "opensearch_endpoint" {
  value = module.opensearch.collection_endpoint
}

output "sns_topic_arn" {
  value = module.sns_sqs.sns_topic_arn
}

output "forensics_bucket_id" {
  value = module.s3.forensics_bucket_id
}

output "mcp_server_repository_url" {
  value = aws_ecr_repository.mcp_server.repository_url
}

output "mcp_nlb_security_group_id" {
  value = aws_security_group.mcp_nlb.id
}
