output "eks_cluster_role_arn" {
  value = aws_iam_role.eks_cluster.arn
}

output "eks_node_role_arn" {
  value = aws_iam_role.eks_node.arn
}

output "lambda_agent_role_arn" {
  value = aws_iam_role.lambda_agent.arn
}

output "step_functions_role_arn" {
  value = aws_iam_role.step_functions.arn
}

output "falco_pod_role_arn" {
  value = aws_iam_role.falco_pod.arn
}

output "external_secrets_role_arn" {
  value = aws_iam_role.external_secrets.arn
}

output "bedrock_kb_role_arn" {
  value = aws_iam_role.bedrock_kb.arn
}

output "aws_lb_controller_role_arn" {
  value = aws_iam_role.aws_lb_controller.arn
}
