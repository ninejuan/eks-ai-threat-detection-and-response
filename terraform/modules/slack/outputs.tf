output "api_endpoint" {
  value = aws_apigatewayv2_api.slack.api_endpoint
}

output "api_id" {
  value = aws_apigatewayv2_api.slack.id
}

output "slack_bot_function_arn" {
  value = aws_lambda_function.slack_bot.arn
}

output "slack_bot_function_name" {
  value = aws_lambda_function.slack_bot.function_name
}
