# Package the CloudSentinel backend into a Lambda zip artifact
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../backend"
  output_path = "${path.module}/cloudsentinel_backend.zip"
  excludes    = ["tests", "__pycache__", ".pytest_cache", "*.pyc"]
}

# CloudWatch Log Group with 14-day retention to prevent credential or volume cost leaks
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.app_name}-api-${var.environment}"
  retention_in_days = 14
}

# CloudSentinel Lambda Function
resource "aws_lambda_function" "cloudsentinel_scanner" {
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  function_name    = "${var.app_name}-api-${var.environment}"
  role             = aws_iam_role.scanner_role.arn
  handler          = "lambda_handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      SCAN_MODE    = "auto"
      LOG_LEVEL    = "INFO"
      CORS_ENABLED = "true"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda_logs,
    aws_iam_role_policy_attachment.security_audit,
    aws_iam_role_policy_attachment.inspector_attachment,
  ]
}
