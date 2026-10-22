output "version_arn" {
  description = "Numbered Lambda version ARN for a CloudFront viewer-request association."
  value       = aws_lambda_function.edge.qualified_arn
}

output "function_name" {
  description = "Deployed function name."
  value       = aws_lambda_function.edge.function_name
}
