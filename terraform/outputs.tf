output "api_gateway_endpoint" {
  description = "Public API Gateway HTTP invoke endpoint for CloudSentinel."
  value       = aws_apigatewayv2_stage.default.invoke_url
}

output "lambda_function_arn" {
  description = "ARN of CloudSentinel Lambda scanner."
  value       = aws_lambda_function.cloudsentinel_scanner.arn
}

output "iam_role_arn" {
  description = "ARN of CloudSentinel strictly read-only execution IAM role."
  value       = aws_iam_role.scanner_role.arn
}
