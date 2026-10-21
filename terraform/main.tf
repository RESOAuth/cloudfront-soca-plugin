terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

data "aws_region" "current" {}
data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

resource "aws_iam_role" "edge" {
  description = "SOCA Lambda@Edge execution role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = ["lambda.amazonaws.com", "edgelambda.amazonaws.com"] }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "logs" {
  name = "function-logs"
  role = aws_iam_role.edge.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = [
        "arn:${data.aws_partition.current.partition}:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.function_name}",
        "arn:${data.aws_partition.current.partition}:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.function_name}:*",
        "arn:${data.aws_partition.current.partition}:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/us-east-1.${var.function_name}",
        "arn:${data.aws_partition.current.partition}:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/us-east-1.${var.function_name}:*"
      ]
    }]
  })
}

resource "aws_lambda_function" "edge" {
  function_name    = var.function_name
  description      = "SOCA stateless CloudFront authentication"
  role             = aws_iam_role.edge.arn
  filename         = var.zip_path
  source_code_hash = filebase64sha256(var.zip_path)
  runtime          = "nodejs24.x"
  handler          = "index.handler"
  architectures    = ["x86_64"]
  memory_size      = 128
  timeout          = var.timeout_seconds
  publish          = true
  tags             = var.tags

  depends_on = [aws_iam_role_policy.logs]

  lifecycle {
    precondition {
      condition     = data.aws_region.current.region == "us-east-1"
      error_message = "Lambda@Edge must be deployed using an AWS provider in us-east-1."
    }
  }
}
