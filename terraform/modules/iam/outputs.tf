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

output "falco_k8saudit_role_arn" {
  value = aws_iam_role.falco_k8saudit.arn
}

output "external_secrets_role_arn" {
  value = aws_iam_role.external_secrets.arn
}

output "bedrock_kb_role_arn" {
  value = aws_iam_role.bedrock_kb.arn
}

output "opensearch_index_manager_role_arn" {
  value = aws_iam_role.opensearch_index_manager.arn
}

output "aws_lb_controller_role_arn" {
  value = aws_iam_role.aws_lb_controller.arn
}

output "ebs_csi_role_arn" {
  value = aws_iam_role.ebs_csi.arn
}

output "mcp_server_role_arn" {
  value = aws_iam_role.mcp_server.arn
}

output "cilium_operator_role_arn" {
  value = aws_iam_role.cilium_operator.arn
}

output "tetragon_forwarder_role_arn" {
  value = aws_iam_role.tetragon_forwarder.arn
}
