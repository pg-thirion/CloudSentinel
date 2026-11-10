# IAM Execution Role for CloudSentinel
# Strictly limited to Read-Only and Audit permissions.
# Absolutely zero write, delete, or mutation capabilities.

resource "aws_iam_role" "scanner_role" {
  name        = "${var.app_name}-execution-role-${var.environment}"
  description = "Strictly read-only execution role for CloudSentinel CSPM scanner"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Attach AWS managed SecurityAudit policy (standard read-only security posture auditing)
resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.scanner_role.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# Attach AWS Lambda Basic Execution Role for CloudWatch Logs
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.scanner_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Explicit Read-Only Policy for scanner check requirements
resource "aws_iam_policy" "read_only_inspector" {
  name        = "${var.app_name}-readonly-policy-${var.environment}"
  description = "Minimal read permissions for S3, IAM, EC2 SG and RDS security evaluation"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ReadOnlyInspection"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
          "s3:GetBucketPolicy",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketAcl",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetEncryptionConfiguration"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMReadOnlyInspection"
        Effect = "Allow"
        Action = [
          "iam:GetAccountAuthorizationDetails",
          "iam:ListPolicies",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListAttachedUserPolicies",
          "iam:ListAttachedRolePolicies"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2AndRDSReadOnlyInspection"
        Effect = "Allow"
        Action = [
          "ec2:DescribeRegions",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVolumes",
          "ec2:DescribeVolumesModifications",
          "rds:DescribeDBInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "inspector_attachment" {
  role       = aws_iam_role.scanner_role.name
  policy_arn = aws_iam_policy.read_only_inspector.arn
}
