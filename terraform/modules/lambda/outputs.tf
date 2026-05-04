output "agent_function_arns" {
  value = { for k, v in aws_lambda_function.agent : k => v.arn }
}

output "agent_function_names" {
  value = { for k, v in aws_lambda_function.agent : k => v.function_name }
}

output "ingestor_function_arn" {
  value = aws_lambda_function.ingestor.arn
}

output "ingestor_function_name" {
  value = aws_lambda_function.ingestor.function_name
}

output "degraded_notifier_function_arn" {
  value = aws_lambda_function.degraded_notifier.arn
}

output "state_machine_arn" {
  value = aws_sfn_state_machine.agent_pipeline.arn
}

output "lambda_security_group_id" {
  value = aws_security_group.lambda.id
}
